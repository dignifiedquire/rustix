#[cfg(any(linux_kernel, target_os = "freebsd", target_os = "illumos"))]
use crate::backend::c;
use bitflags::bitflags;

#[cfg(any(
    linux_kernel,
    target_os = "freebsd",
    target_os = "illumos",
    target_os = "espidf"
))]
bitflags! {
    /// `EFD_*` flags for use with [`eventfd`].
    ///
    /// [`eventfd`]: crate::event::eventfd
    #[repr(transparent)]
    #[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
    pub struct EventfdFlags: u32 {
        /// `EFD_CLOEXEC`
        #[cfg(not(target_os = "espidf"))]
        const CLOEXEC = bitcast!(c::EFD_CLOEXEC);
        /// `EFD_NONBLOCK`
        #[cfg(not(target_os = "espidf"))]
        const NONBLOCK = bitcast!(c::EFD_NONBLOCK);
        /// `EFD_SEMAPHORE`
        #[cfg(not(target_os = "espidf"))]
        const SEMAPHORE = bitcast!(c::EFD_SEMAPHORE);

        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;
    }
}

#[cfg(linux_kernel)]
bitflags! {
    /// `SFD_*` flags for use with [`signalfd`].
    ///
    /// [`signalfd`]: crate::event::signalfd
    #[repr(transparent)]
    #[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
    pub struct SignalfdFlags: u32 {
        /// `SFD_CLOEXEC`
        const CLOEXEC = bitcast!(c::SFD_CLOEXEC);
        /// `SFD_NONBLOCK`
        const NONBLOCK = bitcast!(c::SFD_NONBLOCK);

        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;
    }
}
