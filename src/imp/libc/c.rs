//! Adapt the Winsock2 API to resemble a POSIX-style libc API.

#![allow(unused_imports)]

pub(crate) use winapi::shared::ws2def::{
    AF_DECnet, ADDRESS_FAMILY as sa_family_t, ADDRINFOA as addrinfo, AF_APPLETALK, AF_INET,
    AF_INET6, AF_IPX, AF_IRDA, AF_SNA, AF_UNIX, AF_UNSPEC, IPPROTO_AH, IPPROTO_EGP, IPPROTO_ESP,
    IPPROTO_FRAGMENT, IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_IDP, IPPROTO_IGMP, IPPROTO_IP,
    IPPROTO_IPV6, IPPROTO_PIM, IPPROTO_PUP, IPPROTO_RAW, IPPROTO_ROUTING, IPPROTO_SCTP,
    IPPROTO_TCP, IPPROTO_UDP, MSG_TRUNC, SOCKADDR as sockaddr, SOCKADDR_IN as sockaddr_in,
    SOCKADDR_STORAGE_LH as sockaddr_storage, TCP_NODELAY,
};

pub(crate) use winapi::shared::ws2ipdef::{
    IPV6_ADD_MEMBERSHIP, IPV6_DROP_MEMBERSHIP, IPV6_MREQ as ipv6_mreq, IPV6_MULTICAST_LOOP,
    IPV6_V6ONLY, IP_ADD_MEMBERSHIP, IP_DROP_MEMBERSHIP, IP_MREQ as ip_mreq, IP_MULTICAST_LOOP,
    IP_MULTICAST_TTL, IP_TTL, SOCKADDR_IN6_LH as sockaddr_in6,
};

pub(crate) use winapi::um::ws2tcpip::socklen_t;

pub(crate) use winapi::shared::in6addr::in6_addr;
pub(crate) use winapi::shared::inaddr::in_addr;

pub(crate) use winapi::ctypes::*;
pub(crate) use winapi::shared::basetsd::SSIZE_T as ssize_t;

pub(crate) use winapi::um::winsock2::{
    closesocket as close, ioctlsocket as ioctl, linger, SOL_SOCKET, SO_BROADCAST, SO_LINGER,
    SO_RCVTIMEO, SO_REUSEADDR, SO_SNDTIMEO, SO_TYPE, WSAEACCES as EACCES,
    WSAEADDRINUSE as EADDRINUSE, WSAEADDRNOTAVAIL as EADDRNOTAVAIL,
    WSAEAFNOSUPPORT as EAFNOSUPPORT, WSAEALREADY as EALREADY, WSAEBADF as EBADF,
    WSAECANCELLED as ECANCELED, WSAECONNABORTED as ECONNABORTED, WSAECONNREFUSED as ECONNREFUSED,
    WSAECONNRESET as ECONNRESET, WSAEDESTADDRREQ as EDESTADDRREQ, WSAEDISCON as EDISCON,
    WSAEDQUOT as EDQUOT, WSAEFAULT as EFAULT, WSAEHOSTDOWN as EHOSTDOWN,
    WSAEHOSTUNREACH as EHOSTUNREACH, WSAEINPROGRESS as EINPROGRESS, WSAEINTR as EINTR,
    WSAEINVAL as EINVAL, WSAEINVALIDPROCTABLE as EINVALIDPROCTABLE,
    WSAEINVALIDPROVIDER as EINVALIDPROVIDER, WSAEISCONN as EISCONN, WSAELOOP as ELOOP,
    WSAEMFILE as EMFILE, WSAEMSGSIZE as EMSGSIZE, WSAENAMETOOLONG as ENAMETOOLONG,
    WSAENETDOWN as ENETDOWN, WSAENETRESET as ENETRESET, WSAENETUNREACH as ENETUNREACH,
    WSAENOBUFS as ENOBUFS, WSAENOMORE as ENOMORE, WSAENOPROTOOPT as ENOPROTOOPT,
    WSAENOTCONN as ENOTCONN, WSAENOTEMPTY as ENOTEMPTY, WSAENOTSOCK as ENOTSOCK,
    WSAEOPNOTSUPP as EOPNOTSUPP, WSAEPFNOSUPPORT as EPFNOSUPPORT, WSAEPROCLIM as EPROCLIM,
    WSAEPROTONOSUPPORT as EPROTONOSUPPORT, WSAEPROTOTYPE as EPROTOTYPE,
    WSAEPROVIDERFAILEDINIT as EPROVIDERFAILEDINIT, WSAEREFUSED as EREFUSED, WSAEREMOTE as EREMOTE,
    WSAESHUTDOWN as ESHUTDOWN, WSAESOCKTNOSUPPORT as ESOCKTNOSUPPORT, WSAESTALE as ESTALE,
    WSAETIMEDOUT as ETIMEDOUT, WSAETOOMANYREFS as ETOOMANYREFS, WSAEUSERS as EUSERS,
    WSAEWOULDBLOCK as EWOULDBLOCK, WSAEWOULDBLOCK as EAGAIN, *,
};

// [Documented] values for the `how` argument to `shutdown`.
//
// [Documented]: https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-shutdown#parameters
const SD_RECEIVE: c_int = 0;
const SD_SEND: c_int = 1;
const SD_BOTH: c_int = 2;

pub(crate) const SHUT_WR: c_int = SD_SEND;
pub(crate) const SHUT_RD: c_int = SD_RECEIVE;
pub(crate) const SHUT_RDWR: c_int = SD_BOTH;

#[repr(C)]
pub(crate) struct msghdr {
    pub msg_name: *mut SOCKADDR,
    pub msg_namelen: c_int,
    pub msg_iov: LPWSABUF,
    pub msg_iovlen: c_ulong,
    #[allow(dead_code)]
    pub msg_control: *mut c_void,
    #[allow(dead_code)]
    pub msg_controllen: size_t,
    pub msg_flags: c_int,
}

pub(crate) unsafe fn sendmsg(fd: c_int, msg: *const msghdr, flags: c_int) -> c_int {
    let s = fd as SOCKET;

    let lpBuffers = (*msghdr).msg_iov;
    let dwBufferCount = (*msghdr).msg_iovlen;

    let mut lpNumberOfBytesSent: c_ulong = 0;
    let dwFlags = (*msghdr).msg_flags as c_ulong;
    let lpTo = (*msghdr).msg_name;
    let iToLen = (*msghdr).msg_namelen;

    // No overlapping IO support
    let lpOverlapped = core::ptr::null_mut();
    let lpCompletionRoutine = None;

    let res = WSASendTo(
        s,
        lpBuffers,
        dwBufferCount,
        &mut lpNumberOfBytesSent,
        dwFlags,
        lpTo,
        iToLen,
        lpOverlapped,
        lpCompletionRoutine,
    );

    if res == 0 {
        lpNumberOfBytesSent as c_int
    } else {
        -1
    }
}

pub(crate) unsafe fn recvmsg(fd: c_int, msg: *mut msghdr, flags: c_int) -> c_int {
    let s = fd as SOCKET;

    let lpBuffers = (*msghdr).msg_iov;
    let dwBufferCount = (*msghdr).msg_iovlen;

    let mut lpNumberOfBytesRecvd: c_ulong = 0;
    let lpFlags = (*msghdr).msg_flags as c_ulong;
    let lpFrom = (*msghdr).msg_name;
    let iFromLen = (*msghdr).msg_namelen;

    // No overlapping IO support
    let lpOverlapped = core::ptr::null_mut();
    let lpCompletionRoutine = None;

    let res = WSASendTo(
        s,
        lpBuffers,
        dwBufferCount,
        &mut lpNumberOfBytesRecvd,
        lpFlags,
        lpFrom,
        iFromLen,
        lpOverlapped,
        lpCompletionRoutine,
    );

    if res == 0 {
        lpNumberOfBytesRecvd
    } else {
        -1
    }
}
