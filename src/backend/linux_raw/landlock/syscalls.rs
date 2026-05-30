//! linux_raw syscalls supporting `rustix::landlock`.
//!
//! # Safety
//!
//! See the `rustix::backend` module documentation for details.
#![allow(unsafe_code, clippy::undocumented_unsafe_blocks)]

use crate::backend::conv::{by_ref, c_uint, pass_usize, ret, ret_c_int, ret_owned_fd, zero};
use crate::fd::{BorrowedFd, OwnedFd};
use crate::io;
use core::mem::size_of;
use linux_raw_sys::landlock::{
    landlock_path_beneath_attr, landlock_rule_type, landlock_ruleset_attr,
    LANDLOCK_CREATE_RULESET_VERSION,
};

#[inline]
pub(crate) fn landlock_create_ruleset(
    attr: &landlock_ruleset_attr,
    flags: u32,
) -> io::Result<OwnedFd> {
    unsafe {
        ret_owned_fd(syscall!(
            __NR_landlock_create_ruleset,
            by_ref(attr),
            pass_usize(size_of::<landlock_ruleset_attr>()),
            c_uint(flags)
        ))
    }
}

/// `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)` — query the
/// kernel's supported ABI version rather than create a ruleset.
#[inline]
pub(crate) fn landlock_abi_version() -> io::Result<i32> {
    unsafe {
        ret_c_int(syscall!(
            __NR_landlock_create_ruleset,
            zero(),
            pass_usize(0),
            c_uint(LANDLOCK_CREATE_RULESET_VERSION)
        ))
    }
}

#[inline]
pub(crate) fn landlock_add_path_beneath_rule(
    ruleset: BorrowedFd<'_>,
    attr: &landlock_path_beneath_attr,
    flags: u32,
) -> io::Result<()> {
    unsafe {
        ret(syscall!(
            __NR_landlock_add_rule,
            ruleset,
            c_uint(landlock_rule_type::LANDLOCK_RULE_PATH_BENEATH as u32),
            by_ref(attr),
            c_uint(flags)
        ))
    }
}

#[inline]
pub(crate) fn landlock_restrict_self(ruleset: BorrowedFd<'_>, flags: u32) -> io::Result<()> {
    unsafe { ret(syscall!(__NR_landlock_restrict_self, ruleset, c_uint(flags))) }
}
