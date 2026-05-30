//! `swapon`/`swapoff` — Enable and disable swap devices.

use crate::ffi::CStr;
use crate::{backend, io};

pub use backend::mm::types::SwapFlags;

/// `swapon(path, swapflags)`—Enable a swap device.
///
/// # References
///  - [Linux]
///
/// [Linux]: https://man7.org/linux/man-pages/man2/swapon.2.html
#[inline]
pub fn swapon(path: &CStr, flags: SwapFlags) -> io::Result<()> {
    backend::mm::syscalls::swapon(path, flags)
}

/// `swapoff(path)`—Disable a swap device.
///
/// # References
///  - [Linux]
///
/// [Linux]: https://man7.org/linux/man-pages/man2/swapoff.2.html
#[inline]
pub fn swapoff(path: &CStr) -> io::Result<()> {
    backend::mm::syscalls::swapoff(path)
}
