//! fscrypt `ioctl`s: add and remove v2 master keys, query a key's status, and set or read a v2
//! encryption policy.
//!
//! # References
//!  - [Linux]
//!
//! [Linux]: https://docs.kernel.org/filesystems/fscrypt.html

#![allow(unsafe_code)]

use crate::fd::AsFd;
use crate::{io, ioctl};
use bitflags::bitflags;
use core::mem::{size_of, zeroed};
use core::ptr::write_volatile;
use core::sync::atomic::{compiler_fence, Ordering};
use linux_raw_sys::general as g;
use linux_raw_sys::ioctl as op;

/// Size of a v2 master key identifier.
pub const KEY_IDENTIFIER_SIZE: usize = g::FSCRYPT_KEY_IDENTIFIER_SIZE as usize;
/// Largest raw master key.
pub const MAX_KEY_SIZE: usize = g::FSCRYPT_MAX_KEY_SIZE as usize;

/// A v2 master key identifier, derived by the kernel from the raw key.
pub type KeyIdentifier = [u8; KEY_IDENTIFIER_SIZE];

/// `fscrypt_add_key_arg` followed by room for the raw key (the uapi's flexible array member).
#[repr(C)]
struct AddKey {
    arg: g::fscrypt_add_key_arg,
    raw: [u8; MAX_KEY_SIZE],
}

const _: () = assert!(size_of::<g::fscrypt_add_key_arg>() == 80);
const _: () = assert!(size_of::<g::fscrypt_remove_key_arg>() == 64);
const _: () = assert!(size_of::<g::fscrypt_get_key_status_arg>() == 128);
const _: () = assert!(size_of::<g::fscrypt_policy_v2>() == 24);

/// Overwrite `bytes` with zeros in a way the optimizer may not remove.
fn wipe(bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        // SAFETY: `b` is a valid, exclusive reference to one byte.
        unsafe { write_volatile(b, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// A key specifier naming `id` (`FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER`).
fn identifier_spec(id: &KeyIdentifier) -> g::fscrypt_key_specifier {
    // SAFETY: the struct and its union are plain integers and byte arrays; all zeros is valid.
    let mut spec: g::fscrypt_key_specifier = unsafe { zeroed() };
    spec.type_ = g::FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;
    spec.u.identifier = *id;
    spec
}

/// `ioctl(fd, FS_IOC_ADD_ENCRYPTION_KEY)`—Add a raw v2 master key to the keyring of the filesystem
/// that contains `fd`, and return the identifier the kernel derived for it.
///
/// Adding the same raw key again returns the same identifier. The copy of `raw` handed to the kernel
/// is wiped before this returns; the caller owns `raw` itself.
#[doc(alias = "FS_IOC_ADD_ENCRYPTION_KEY")]
pub fn add_key<Fd: AsFd>(fd: Fd, raw: &[u8]) -> io::Result<KeyIdentifier> {
    if raw.is_empty() || raw.len() > MAX_KEY_SIZE {
        return Err(io::Errno::INVAL);
    }
    // SAFETY: plain integers and byte arrays; all zeros is valid.
    let mut arg: AddKey = unsafe { zeroed() };
    arg.arg.key_spec.type_ = g::FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;
    arg.arg.raw_size = raw.len() as u32;
    arg.raw[..raw.len()].copy_from_slice(raw);
    // SAFETY: FS_IOC_ADD_ENCRYPTION_KEY reads a `fscrypt_add_key_arg` followed by `raw_size` bytes of
    // key and writes the derived identifier into `key_spec.u`; `AddKey` is exactly that layout.
    let added = unsafe {
        let ctl = ioctl::Updater::<{ op::FS_IOC_ADD_ENCRYPTION_KEY as ioctl::Opcode }, AddKey>::new(
            &mut arg,
        );
        ioctl::ioctl(fd, ctl)
    };
    // SAFETY: `identifier` is the union member the kernel writes for a key added by identifier.
    let id = unsafe { arg.arg.key_spec.u.identifier };
    wipe(&mut arg.raw);
    added.map(|()| id)
}

bitflags! {
    /// What a key removal reported (`removal_status_flags`).
    #[repr(transparent)]
    #[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
    pub struct KeyRemovalStatus: u32 {
        /// Files were still in use: their inodes keep the key until closed
        /// (the key is incompletely removed).
        const FILES_BUSY = g::FSCRYPT_KEY_REMOVAL_STATUS_FLAG_FILES_BUSY;
        /// Other users still hold claims to the key, so it stays added.
        const OTHER_USERS = g::FSCRYPT_KEY_REMOVAL_STATUS_FLAG_OTHER_USERS;

        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;
    }
}

/// `ioctl(fd, FS_IOC_REMOVE_ENCRYPTION_KEY)`—Remove the calling user's claim to key `id` from the
/// filesystem that contains `fd`; with `all_users`, `FS_IOC_REMOVE_ENCRYPTION_KEY_ALL_USERS`
/// removes every user's claim (needs `CAP_SYS_ADMIN`).
///
/// Success does not mean the key is gone: check [`KeyRemovalStatus`] or [`key_status`].
#[doc(alias = "FS_IOC_REMOVE_ENCRYPTION_KEY")]
#[doc(alias = "FS_IOC_REMOVE_ENCRYPTION_KEY_ALL_USERS")]
pub fn remove_key<Fd: AsFd>(
    fd: Fd,
    id: &KeyIdentifier,
    all_users: bool,
) -> io::Result<KeyRemovalStatus> {
    // SAFETY: plain integers and byte arrays; all zeros is valid.
    let mut arg: g::fscrypt_remove_key_arg = unsafe { zeroed() };
    arg.key_spec = identifier_spec(id);
    // SAFETY: both opcodes read and write a `fscrypt_remove_key_arg`.
    unsafe {
        if all_users {
            let ctl = ioctl::Updater::<
                { op::FS_IOC_REMOVE_ENCRYPTION_KEY_ALL_USERS as ioctl::Opcode },
                g::fscrypt_remove_key_arg,
            >::new(&mut arg);
            ioctl::ioctl(fd, ctl)?;
        } else {
            let ctl = ioctl::Updater::<
                { op::FS_IOC_REMOVE_ENCRYPTION_KEY as ioctl::Opcode },
                g::fscrypt_remove_key_arg,
            >::new(&mut arg);
            ioctl::ioctl(fd, ctl)?;
        }
    }
    Ok(KeyRemovalStatus::from_bits_retain(arg.removal_status_flags))
}

/// Whether a master key is in a filesystem's keyring.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum KeyStatus {
    /// Not present: files under a policy using it cannot be read.
    Absent,
    /// Present.
    Present,
    /// Removed, but files still in use keep it alive until they are closed.
    IncompletelyRemoved,
}

/// `ioctl(fd, FS_IOC_GET_ENCRYPTION_KEY_STATUS)`—The status of key `id` in the keyring of the
/// filesystem that contains `fd`.
#[doc(alias = "FS_IOC_GET_ENCRYPTION_KEY_STATUS")]
pub fn key_status<Fd: AsFd>(fd: Fd, id: &KeyIdentifier) -> io::Result<KeyStatus> {
    // SAFETY: plain integers and byte arrays; all zeros is valid.
    let mut arg: g::fscrypt_get_key_status_arg = unsafe { zeroed() };
    arg.key_spec = identifier_spec(id);
    // SAFETY: FS_IOC_GET_ENCRYPTION_KEY_STATUS reads and writes a `fscrypt_get_key_status_arg`.
    unsafe {
        let ctl = ioctl::Updater::<
            { op::FS_IOC_GET_ENCRYPTION_KEY_STATUS as ioctl::Opcode },
            g::fscrypt_get_key_status_arg,
        >::new(&mut arg);
        ioctl::ioctl(fd, ctl)?;
    }
    match arg.status {
        g::FSCRYPT_KEY_STATUS_ABSENT => Ok(KeyStatus::Absent),
        g::FSCRYPT_KEY_STATUS_PRESENT => Ok(KeyStatus::Present),
        g::FSCRYPT_KEY_STATUS_INCOMPLETELY_REMOVED => Ok(KeyStatus::IncompletelyRemoved),
        _ => Err(io::Errno::INVAL),
    }
}

/// A v2 encryption policy.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PolicyV2 {
    /// `FSCRYPT_MODE_*` for file contents.
    pub contents_mode: u8,
    /// `FSCRYPT_MODE_*` for file names.
    pub filenames_mode: u8,
    /// `FSCRYPT_POLICY_FLAG*`.
    pub flags: u8,
    /// log2 of the data unit size, or 0 for the filesystem block size.
    pub log2_data_unit_size: u8,
    /// The master key the policy uses.
    pub key_identifier: KeyIdentifier,
}

/// A directory's encryption policy, as [`get_policy`] reads it.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Policy {
    /// A v1 policy (its details are not decoded here).
    V1,
    /// A v2 policy.
    V2(PolicyV2),
}

/// `ioctl(fd, FS_IOC_SET_ENCRYPTION_POLICY)`—Set a v2 policy on the empty directory `fd`.
#[doc(alias = "FS_IOC_SET_ENCRYPTION_POLICY")]
pub fn set_policy_v2<Fd: AsFd>(fd: Fd, policy: &PolicyV2) -> io::Result<()> {
    let raw = g::fscrypt_policy_v2 {
        version: g::FSCRYPT_POLICY_V2 as u8,
        contents_encryption_mode: policy.contents_mode,
        filenames_encryption_mode: policy.filenames_mode,
        flags: policy.flags,
        log2_data_unit_size: policy.log2_data_unit_size,
        __reserved: [0; 3],
        master_key_identifier: policy.key_identifier,
    };
    // SAFETY: FS_IOC_SET_ENCRYPTION_POLICY reads a policy whose first byte is its version; the kernel
    // copies the whole v2 struct when the version says v2.
    unsafe {
        let ctl = ioctl::Setter::<
            { op::FS_IOC_SET_ENCRYPTION_POLICY as ioctl::Opcode },
            g::fscrypt_policy_v2,
        >::new(raw);
        ioctl::ioctl(fd, ctl)
    }
}

/// `ioctl(fd, FS_IOC_GET_ENCRYPTION_POLICY_EX)`—The encryption policy of `fd`, or `None` when it
/// has none.
#[doc(alias = "FS_IOC_GET_ENCRYPTION_POLICY_EX")]
pub fn get_policy<Fd: AsFd>(fd: Fd) -> io::Result<Option<Policy>> {
    // SAFETY: plain integers and byte arrays; all zeros is valid.
    let mut arg: g::fscrypt_get_policy_ex_arg = unsafe { zeroed() };
    arg.policy_size = size_of::<g::fscrypt_get_policy_ex_arg__bindgen_ty_1>() as u64;
    // SAFETY: FS_IOC_GET_ENCRYPTION_POLICY_EX reads `policy_size` (the buffer's capacity) and writes
    // the policy and its size into a `fscrypt_get_policy_ex_arg`.
    let got = unsafe {
        let ctl = ioctl::Updater::<
            { op::FS_IOC_GET_ENCRYPTION_POLICY_EX as ioctl::Opcode },
            g::fscrypt_get_policy_ex_arg,
        >::new(&mut arg);
        ioctl::ioctl(fd, ctl)
    };
    match got {
        Err(io::Errno::NODATA) => return Ok(None),
        Err(e) => return Err(e),
        Ok(()) => {}
    }
    // SAFETY: `version` is the first byte of every policy variant, so it is always initialized.
    if unsafe { arg.policy.version } != g::FSCRYPT_POLICY_V2 as u8 {
        return Ok(Some(Policy::V1));
    }
    // SAFETY: the version says the kernel wrote a v2 policy.
    let v2 = unsafe { arg.policy.v2 };
    Ok(Some(Policy::V2(PolicyV2 {
        contents_mode: v2.contents_encryption_mode,
        filenames_mode: v2.filenames_encryption_mode,
        flags: v2.flags,
        log2_data_unit_size: v2.log2_data_unit_size,
        key_identifier: v2.master_key_identifier,
    })))
}
