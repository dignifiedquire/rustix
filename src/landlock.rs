//! Landlock — unprivileged filesystem access control.
//!
//! [Landlock] lets an unprivileged thread irreversibly restrict its own (and its
//! future children's) access to the filesystem. Build a ruleset describing which
//! access rights it will govern ([`create_ruleset`]), add the paths to allow
//! ([`add_path_beneath_rule`]), then enforce it ([`restrict_self`]). Enforcement
//! requires no-new-privs (see [`set_no_new_privs`]) and cannot be undone.
//!
//! [Landlock]: https://docs.kernel.org/userspace-api/landlock.html
//! [`set_no_new_privs`]: crate::thread::set_no_new_privs

#![allow(unsafe_code)]

use crate::backend::landlock::syscalls;
use crate::fd::{AsRawFd, BorrowedFd, OwnedFd};
use crate::io;
use bitflags::bitflags;
use linux_raw_sys::landlock::{landlock_path_beneath_attr, landlock_ruleset_attr};

bitflags! {
    /// `LANDLOCK_ACCESS_FS_*` — filesystem access rights a ruleset can govern.
    #[repr(transparent)]
    #[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
    pub struct AccessFs: u64 {
        /// `LANDLOCK_ACCESS_FS_EXECUTE`
        const EXECUTE = linux_raw_sys::landlock::LANDLOCK_ACCESS_FS_EXECUTE as u64;
        /// `LANDLOCK_ACCESS_FS_WRITE_FILE`
        const WRITE_FILE = linux_raw_sys::landlock::LANDLOCK_ACCESS_FS_WRITE_FILE as u64;
        /// `LANDLOCK_ACCESS_FS_READ_FILE`
        const READ_FILE = linux_raw_sys::landlock::LANDLOCK_ACCESS_FS_READ_FILE as u64;
        /// `LANDLOCK_ACCESS_FS_READ_DIR`
        const READ_DIR = linux_raw_sys::landlock::LANDLOCK_ACCESS_FS_READ_DIR as u64;
        /// `LANDLOCK_ACCESS_FS_REMOVE_DIR`
        const REMOVE_DIR = linux_raw_sys::landlock::LANDLOCK_ACCESS_FS_REMOVE_DIR as u64;
        /// `LANDLOCK_ACCESS_FS_REMOVE_FILE`
        const REMOVE_FILE = linux_raw_sys::landlock::LANDLOCK_ACCESS_FS_REMOVE_FILE as u64;
        /// `LANDLOCK_ACCESS_FS_MAKE_CHAR`
        const MAKE_CHAR = linux_raw_sys::landlock::LANDLOCK_ACCESS_FS_MAKE_CHAR as u64;
        /// `LANDLOCK_ACCESS_FS_MAKE_DIR`
        const MAKE_DIR = linux_raw_sys::landlock::LANDLOCK_ACCESS_FS_MAKE_DIR as u64;
        /// `LANDLOCK_ACCESS_FS_MAKE_REG`
        const MAKE_REG = linux_raw_sys::landlock::LANDLOCK_ACCESS_FS_MAKE_REG as u64;
        /// `LANDLOCK_ACCESS_FS_MAKE_SOCK`
        const MAKE_SOCK = linux_raw_sys::landlock::LANDLOCK_ACCESS_FS_MAKE_SOCK as u64;
        /// `LANDLOCK_ACCESS_FS_MAKE_FIFO`
        const MAKE_FIFO = linux_raw_sys::landlock::LANDLOCK_ACCESS_FS_MAKE_FIFO as u64;
        /// `LANDLOCK_ACCESS_FS_MAKE_BLOCK`
        const MAKE_BLOCK = linux_raw_sys::landlock::LANDLOCK_ACCESS_FS_MAKE_BLOCK as u64;
        /// `LANDLOCK_ACCESS_FS_MAKE_SYM`
        const MAKE_SYM = linux_raw_sys::landlock::LANDLOCK_ACCESS_FS_MAKE_SYM as u64;
        /// `LANDLOCK_ACCESS_FS_REFER`
        const REFER = linux_raw_sys::landlock::LANDLOCK_ACCESS_FS_REFER as u64;
        /// `LANDLOCK_ACCESS_FS_TRUNCATE`
        const TRUNCATE = linux_raw_sys::landlock::LANDLOCK_ACCESS_FS_TRUNCATE as u64;
        /// `LANDLOCK_ACCESS_FS_IOCTL_DEV`
        const IOCTL_DEV = linux_raw_sys::landlock::LANDLOCK_ACCESS_FS_IOCTL_DEV as u64;

        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;
    }
}

bitflags! {
    /// `LANDLOCK_SCOPE_*` — IPC a ruleset confines to its own domain (and domains
    /// nested in it). Needs Landlock ABI 6 (Linux 6.12).
    #[repr(transparent)]
    #[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
    pub struct Scope: u64 {
        /// `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` — connect only to abstract
        /// `unix(7)` sockets created in the same or a nested domain.
        const ABSTRACT_UNIX_SOCKET = linux_raw_sys::landlock::LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET as u64;
        /// `LANDLOCK_SCOPE_SIGNAL` — send signals only to processes in the same
        /// or a nested domain.
        const SIGNAL = linux_raw_sys::landlock::LANDLOCK_SCOPE_SIGNAL as u64;

        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;
    }
}

/// Query the kernel's supported Landlock ABI version (`>= 1`), via
/// `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`. Returns
/// `ENOSYS`/`EOPNOTSUPP` if Landlock is unavailable — use it to mask
/// [`AccessFs`] down to the rights the running kernel actually supports.
///
/// # References
///  - [`landlock_create_ruleset(2)`]
///
/// [`landlock_create_ruleset(2)`]: https://man7.org/linux/man-pages/man2/landlock_create_ruleset.2.html
#[inline]
pub fn abi_version() -> io::Result<i32> {
    syscalls::landlock_abi_version()
}

/// Create a Landlock ruleset governing `handled_access_fs` and confining the IPC
/// in `scoped` to its own domain, returning its file descriptor. Add rules to it
/// with [`add_path_beneath_rule`], then enforce it with [`restrict_self`]. A
/// non-empty `scoped` fails with `EINVAL` below Landlock ABI 6.
///
/// # References
///  - [`landlock_create_ruleset(2)`]
///
/// [`landlock_create_ruleset(2)`]: https://man7.org/linux/man-pages/man2/landlock_create_ruleset.2.html
#[inline]
pub fn create_ruleset(handled_access_fs: AccessFs, scoped: Scope) -> io::Result<OwnedFd> {
    let attr = landlock_ruleset_attr {
        handled_access_fs: handled_access_fs.bits(),
        handled_access_net: 0,
        scoped: scoped.bits(),
    };
    syscalls::landlock_create_ruleset(&attr, 0)
}

/// Add a "path beneath" rule to `ruleset`: allow `allowed_access` on the file
/// hierarchy beneath the already-open `parent` directory/file.
///
/// # References
///  - [`landlock_add_rule(2)`]
///
/// [`landlock_add_rule(2)`]: https://man7.org/linux/man-pages/man2/landlock_add_rule.2.html
#[inline]
pub fn add_path_beneath_rule(
    ruleset: BorrowedFd<'_>,
    allowed_access: AccessFs,
    parent: BorrowedFd<'_>,
) -> io::Result<()> {
    let attr = landlock_path_beneath_attr {
        allowed_access: allowed_access.bits(),
        parent_fd: parent.as_raw_fd(),
    };
    syscalls::landlock_add_path_beneath_rule(ruleset, &attr, 0)
}

/// Irreversibly enforce `ruleset` on the calling thread (and its future children).
/// The caller must have already set no-new-privs (see [`set_no_new_privs`]).
///
/// # References
///  - [`landlock_restrict_self(2)`]
///
/// [`set_no_new_privs`]: crate::thread::set_no_new_privs
/// [`landlock_restrict_self(2)`]: https://man7.org/linux/man-pages/man2/landlock_restrict_self.2.html
#[inline]
pub fn restrict_self(ruleset: BorrowedFd<'_>) -> io::Result<()> {
    syscalls::landlock_restrict_self(ruleset, 0)
}
