use crate::ffi;
use bitflags::bitflags;

bitflags! {
    /// `EFD_*` flags for use with [`eventfd`].
    ///
    /// [`eventfd`]: crate::event::eventfd
    #[repr(transparent)]
    #[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
    pub struct EventfdFlags: ffi::c_uint {
        /// `EFD_CLOEXEC`
        const CLOEXEC = linux_raw_sys::general::EFD_CLOEXEC;
        /// `EFD_NONBLOCK`
        const NONBLOCK = linux_raw_sys::general::EFD_NONBLOCK;
        /// `EFD_SEMAPHORE`
        const SEMAPHORE = linux_raw_sys::general::EFD_SEMAPHORE;

        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;
    }
}

bitflags! {
    /// `SFD_*` flags for use with [`signalfd`].
    ///
    /// [`signalfd`]: crate::event::signalfd
    #[repr(transparent)]
    #[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
    pub struct SignalfdFlags: ffi::c_uint {
        /// `SFD_CLOEXEC`
        const CLOEXEC = linux_raw_sys::general::O_CLOEXEC as _;
        /// `SFD_NONBLOCK`
        const NONBLOCK = linux_raw_sys::general::O_NONBLOCK as _;

        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;
    }
}
