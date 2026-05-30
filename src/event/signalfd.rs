//! `signalfd`—Create a file descriptor for accepting signals.

use crate::fd::OwnedFd;
use crate::{backend, io};

pub use crate::kernel_sigset::KernelSigSet;
pub use backend::event::types::SignalfdFlags;

/// `signalfd4(fd, mask, flags)`—Create or update a signalfd.
///
/// Pass `-1` as `fd` to create a new signalfd, or an existing signalfd
/// file descriptor to update its signal mask.
///
/// # References
///  - [Linux]
///
/// [Linux]: https://man7.org/linux/man-pages/man2/signalfd.2.html
#[inline]
pub fn signalfd(mask: &KernelSigSet, flags: SignalfdFlags) -> io::Result<OwnedFd> {
    backend::event::syscalls::signalfd(-1, mask, flags)
}
