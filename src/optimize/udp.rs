#![allow(unused_imports)]
#![allow(dead_code)]

use libc::{c_void, iovec, msghdr, sockaddr_storage, socklen_t};
use std::net::{SocketAddr, UdpSocket};
use std::os::unix::io::{AsRawFd, RawFd};

#[cfg(target_os = "macos")]
extern "C" {
    fn sendmsg_x(
        s: libc::c_int,
        msgp: *const libc::msghdr,
        cnt: libc::c_uint,
        flags: libc::c_int,
    ) -> libc::c_int;
}

// =========================================================================
// UDP GSO/GRO - Generic Segmentation/Receive Offload (Linux >= 4.18)
// =========================================================================

/// UDP GSO capability detection and configuration
pub struct UdpGsoConfig {
    pub enabled: bool,
    pub max_segments: u16,
    pub gso_size: u16,
}

#[cfg(target_arch = "aarch64")]
pub(crate) unsafe fn memcpy_non_temporal_arm(dst: &mut [u8], src: &[u8], len: usize) {
    use std::arch::aarch64::*;
    let mut i = 0usize;
    // Prefetch distance tuned conservatively
    const PF_DIST: usize = 256;

    while i + 64 <= len {
        // Prefetch ahead to reduce cache pollution
        if i + PF_DIST < len {
            core::arch::asm!(
                "prfm pldl1keep, [{ptr}]",
                ptr = in(reg) src.as_ptr().add(i + PF_DIST),
                options(nostack, preserves_flags)
            );
        }

        // Load 64 bytes and store
        let a0 = vld1q_u8(src.as_ptr().add(i));
        let a1 = vld1q_u8(src.as_ptr().add(i + 16));
        let a2 = vld1q_u8(src.as_ptr().add(i + 32));
        let a3 = vld1q_u8(src.as_ptr().add(i + 48));

        vst1q_u8(dst.as_mut_ptr().add(i), a0);
        vst1q_u8(dst.as_mut_ptr().add(i + 16), a1);
        vst1q_u8(dst.as_mut_ptr().add(i + 32), a2);
        vst1q_u8(dst.as_mut_ptr().add(i + 48), a3);

        i += 64;
    }

    // Remainder copy
    while i < len {
        *dst.get_unchecked_mut(i) = *src.get_unchecked(i);
        i += 1;
    }
}

#[cfg(not(target_arch = "aarch64"))]
pub(crate) unsafe fn memcpy_non_temporal_arm(dst: &mut [u8], src: &[u8], len: usize) {
    let len = len.min(dst.len()).min(src.len());
    if len == 0 {
        return;
    }
    core::ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr(), len);
}

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

impl UdpGsoConfig {
    /// Detect and enable UDP GSO on socket
    pub fn enable(sock: &UdpSocket) -> std::io::Result<Self> {
        let fd = sock.as_raw_fd();

        // Enable UDP_SEGMENT option (SOL_UDP = 17, UDP_SEGMENT = 103)
        const SOL_UDP: libc::c_int = 17;
        const UDP_SEGMENT: libc::c_int = 103;

        let enable: libc::c_int = 1;
        let ret = unsafe {
            libc::setsockopt(
                fd,
                SOL_UDP,
                UDP_SEGMENT,
                &enable as *const _ as *const c_void,
                std::mem::size_of_val(&enable) as socklen_t,
            )
        };

        if ret == 0 {
            Ok(Self { enabled: true, max_segments: 64, gso_size: 1472 })
        } else {
            Ok(Self { enabled: false, max_segments: 1, gso_size: 0 })
        }
    }
}

// =========================================================================
// sendmmsg/recvmmsg - Batched syscalls for reduced overhead
// =========================================================================

/// Batched UDP send with sendmmsg (Linux/BSD)
#[cfg(target_os = "linux")]
pub fn send_batch(sock: &UdpSocket, packets: &[(&[u8], SocketAddr)]) -> std::io::Result<usize> {
    use std::mem::MaybeUninit;

    let fd = sock.as_raw_fd();
    let mut messages: Vec<libc::mmsghdr> = Vec::with_capacity(packets.len());
    let mut iovecs: Vec<iovec> = Vec::with_capacity(packets.len());
    let mut addrs: Vec<sockaddr_storage> = Vec::with_capacity(packets.len());

    for (data, addr) in packets {
        let mut storage = MaybeUninit::<sockaddr_storage>::uninit();
        let len = match addr {
            SocketAddr::V4(v4) => {
                #[cfg(target_os = "macos")]
                let raw = libc::sockaddr_in {
                    sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    sin_port: v4.port().to_be(),
                    sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(v4.ip().octets()) },
                    sin_zero: [0; 8],
                };
                #[cfg(not(target_os = "macos"))]
                let raw = libc::sockaddr_in {
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    sin_port: v4.port().to_be(),
                    sin_addr: libc::in_addr {
                        s_addr: u32::from_ne_bytes(v4.ip().octets()).to_be(),
                    },
                    sin_zero: [0; 8],
                };
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        &raw as *const _ as *const u8,
                        storage.as_mut_ptr() as *mut u8,
                        std::mem::size_of_val(&raw),
                    );
                }
                std::mem::size_of::<libc::sockaddr_in>() as socklen_t
            }
            SocketAddr::V6(v6) => {
                #[cfg(target_os = "macos")]
                let raw = libc::sockaddr_in6 {
                    sin6_len: std::mem::size_of::<libc::sockaddr_in6>() as u8,
                    sin6_family: libc::AF_INET6 as libc::sa_family_t,
                    sin6_port: v6.port().to_be(),
                    sin6_flowinfo: v6.flowinfo(),
                    sin6_addr: libc::in6_addr { s6_addr: v6.ip().octets() },
                    sin6_scope_id: v6.scope_id(),
                };
                #[cfg(not(target_os = "macos"))]
                let raw = libc::sockaddr_in6 {
                    sin6_family: libc::AF_INET6 as libc::sa_family_t,
                    sin6_port: v6.port().to_be(),
                    sin6_flowinfo: v6.flowinfo(),
                    sin6_addr: libc::in6_addr { s6_addr: v6.ip().octets() },
                    sin6_scope_id: v6.scope_id(),
                };
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        &raw as *const _ as *const u8,
                        storage.as_mut_ptr() as *mut u8,
                        std::mem::size_of_val(&raw),
                    );
                }
                std::mem::size_of::<libc::sockaddr_in6>() as socklen_t
            }
        };

        let storage = unsafe { storage.assume_init() };
        addrs.push(storage);

        iovecs.push(iovec { iov_base: data.as_ptr() as *mut c_void, iov_len: data.len() });

        let msg_hdr = msghdr {
            msg_name: addrs.last_mut().unwrap() as *mut _ as *mut c_void,
            msg_namelen: len,
            msg_iov: iovecs.last_mut().unwrap() as *mut iovec,
            msg_iovlen: 1,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };

        messages.push(libc::mmsghdr { msg_hdr, msg_len: 0 });
    }

    let ret = unsafe {
        libc::sendmmsg(
            fd,
            messages.as_mut_ptr(),
            messages.len() as libc::c_uint,
            libc::MSG_DONTWAIT,
        )
    };

    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(ret as usize)
    }
}

/// Batched UDP send using sendmsg_x where available (macOS/iOS).
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub fn send_batch(sock: &UdpSocket, packets: &[(&[u8], SocketAddr)]) -> std::io::Result<usize> {
    if packets.is_empty() {
        return Ok(0);
    }

    use std::sync::atomic::Ordering;

    let fd = sock.as_raw_fd();
    let mut messages: Vec<msghdr> = Vec::with_capacity(packets.len());
    let mut iovecs: Vec<iovec> = Vec::with_capacity(packets.len());
    let mut addrs: Vec<sockaddr_storage> = Vec::with_capacity(packets.len());
    let mut addr_lens: Vec<socklen_t> = Vec::with_capacity(packets.len());

    for (data, addr) in packets {
        let mut storage: sockaddr_storage = unsafe { std::mem::zeroed() };
        let len = match addr {
            SocketAddr::V4(v4) => {
                #[cfg(target_os = "macos")]
                let raw = libc::sockaddr_in {
                    sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    sin_port: v4.port().to_be(),
                    sin_addr: libc::in_addr {
                        s_addr: u32::from_ne_bytes(v4.ip().octets()).to_be(),
                    },
                    sin_zero: [0; 8],
                };
                #[cfg(not(target_os = "macos"))]
                let raw = libc::sockaddr_in {
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    sin_port: v4.port().to_be(),
                    sin_addr: libc::in_addr {
                        s_addr: u32::from_ne_bytes(v4.ip().octets()).to_be(),
                    },
                    sin_zero: [0; 8],
                };
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        &raw as *const _ as *const u8,
                        &mut storage as *mut _ as *mut u8,
                        std::mem::size_of_val(&raw),
                    );
                }
                std::mem::size_of::<libc::sockaddr_in>() as socklen_t
            }
            SocketAddr::V6(v6) => {
                #[cfg(target_os = "macos")]
                let raw = libc::sockaddr_in6 {
                    sin6_len: std::mem::size_of::<libc::sockaddr_in6>() as u8,
                    sin6_family: libc::AF_INET6 as libc::sa_family_t,
                    sin6_port: v6.port().to_be(),
                    sin6_flowinfo: v6.flowinfo(),
                    sin6_addr: libc::in6_addr { s6_addr: v6.ip().octets() },
                    sin6_scope_id: v6.scope_id(),
                };
                #[cfg(not(target_os = "macos"))]
                let raw = libc::sockaddr_in6 {
                    sin6_family: libc::AF_INET6 as libc::sa_family_t,
                    sin6_port: v6.port().to_be(),
                    sin6_flowinfo: v6.flowinfo(),
                    sin6_addr: libc::in6_addr { s6_addr: v6.ip().octets() },
                    sin6_scope_id: v6.scope_id(),
                };
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        &raw as *const _ as *const u8,
                        &mut storage as *mut _ as *mut u8,
                        std::mem::size_of_val(&raw),
                    );
                }
                std::mem::size_of::<libc::sockaddr_in6>() as socklen_t
            }
        };

        addrs.push(storage);
        addr_lens.push(len);
        iovecs.push(iovec { iov_base: data.as_ptr() as *mut c_void, iov_len: data.len() });
    }

    for i in 0..packets.len() {
        messages.push(msghdr {
            msg_name: &mut addrs[i] as *mut _ as *mut c_void,
            msg_namelen: addr_lens[i],
            msg_iov: &mut iovecs[i] as *mut iovec,
            msg_iovlen: 1,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        });
    }

    let flags = libc::MSG_DONTWAIT;

    #[cfg(target_os = "macos")]
    {
        crate::optimize::telemetry::ZEROCOPY_SEND_CALLS.fetch_add(1, Ordering::Relaxed);
        let sent = unsafe { sendmsg_x(fd, messages.as_ptr(), messages.len() as u32, flags) };
        if sent >= 0 {
            return Ok(sent as usize);
        }

        let err = std::io::Error::last_os_error();
        if !matches!(
            err.raw_os_error(),
            Some(libc::ENOSYS)
                | Some(libc::EOPNOTSUPP)
                | Some(libc::ENOTSUP)
                | Some(libc::EINVAL)
                | Some(libc::EADDRNOTAVAIL)
        ) {
            return Err(err);
        }
        crate::optimize::telemetry::ZEROCOPY_SEND_FALLBACKS.fetch_add(1, Ordering::Relaxed);
    }

    let mut sent = 0usize;
    for msg in &messages {
        let rc = unsafe { libc::sendmsg(fd, msg as *const _ as *const _, flags) };
        if rc < 0 {
            return Err(std::io::Error::last_os_error());
        }
        sent += 1;
    }
    Ok(sent)
}

// =========================================================================
// MSG_ZEROCOPY - Zero-copy transmission for large buffers (Linux >= 4.14)
// =========================================================================

pub struct ZeroCopySocket {
    sock: UdpSocket,
    enabled: bool,
}

impl ZeroCopySocket {
    pub fn new(sock: UdpSocket) -> std::io::Result<Self> {
        let fd = sock.as_raw_fd();

        // Enable SO_ZEROCOPY (SOL_SOCKET = 1, SO_ZEROCOPY = 60)
        const SO_ZEROCOPY: libc::c_int = 60;
        let enable: libc::c_int = 1;

        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                SO_ZEROCOPY,
                &enable as *const _ as *const c_void,
                std::mem::size_of_val(&enable) as socklen_t,
            )
        };

        Ok(Self { sock, enabled: ret == 0 })
    }

    pub fn send_zerocopy(&self, data: &[u8], addr: SocketAddr) -> std::io::Result<usize> {
        const ZEROCOPY_THRESHOLD: usize = 10240;

        if !self.enabled || data.len() < ZEROCOPY_THRESHOLD {
            return self.sock.send_to(data, addr);
        }

        const MSG_ZEROCOPY: libc::c_int = 0x4000000;

        unsafe {
            let mut msg: libc::msghdr = std::mem::zeroed();
            let iov = libc::iovec { iov_base: data.as_ptr() as *mut _, iov_len: data.len() };

            // Convert SocketAddr to sockaddr in a storage that outlives sendmsg
            let mut storage: libc::sockaddr_storage = std::mem::zeroed();
            let addr_len: libc::socklen_t = match addr {
                SocketAddr::V4(v4) => {
                    #[cfg(target_os = "macos")]
                    let sa = libc::sockaddr_in {
                        sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
                        sin_family: libc::AF_INET as libc::sa_family_t,
                        sin_port: v4.port().to_be(),
                        sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(v4.ip().octets()) },
                        sin_zero: [0; 8],
                    };
                    #[cfg(not(target_os = "macos"))]
                    let sa = libc::sockaddr_in {
                        sin_family: libc::AF_INET as libc::sa_family_t,
                        sin_port: v4.port().to_be(),
                        sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(v4.ip().octets()) },
                        sin_zero: [0; 8],
                    };
                    std::ptr::copy_nonoverlapping(
                        &sa as *const _ as *const u8,
                        &mut storage as *mut _ as *mut u8,
                        std::mem::size_of::<libc::sockaddr_in>(),
                    );
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
                }
                SocketAddr::V6(v6) => {
                    #[cfg(target_os = "macos")]
                    let sa = libc::sockaddr_in6 {
                        sin6_len: std::mem::size_of::<libc::sockaddr_in6>() as u8,
                        sin6_family: libc::AF_INET6 as libc::sa_family_t,
                        sin6_port: v6.port().to_be(),
                        sin6_flowinfo: v6.flowinfo(),
                        sin6_addr: libc::in6_addr { s6_addr: v6.ip().octets() },
                        sin6_scope_id: v6.scope_id(),
                    };
                    #[cfg(not(target_os = "macos"))]
                    let sa = libc::sockaddr_in6 {
                        sin6_family: libc::AF_INET6 as libc::sa_family_t,
                        sin6_port: v6.port().to_be(),
                        sin6_flowinfo: v6.flowinfo(),
                        sin6_addr: libc::in6_addr { s6_addr: v6.ip().octets() },
                        sin6_scope_id: v6.scope_id(),
                    };
                    std::ptr::copy_nonoverlapping(
                        &sa as *const _ as *const u8,
                        &mut storage as *mut _ as *mut u8,
                        std::mem::size_of::<libc::sockaddr_in6>(),
                    );
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
                }
            };

            msg.msg_name = &mut storage as *mut _ as *mut _;
            msg.msg_namelen = addr_len;
            msg.msg_iov = &iov as *const _ as *mut _;
            msg.msg_iovlen = 1;

            // Control message for zerocopy notification (Linux-only UDP_SEGMENT)
            #[cfg(target_os = "linux")]
            {
                let mut control = [0u8; 64];
                let cmsg = control.as_mut_ptr() as *mut libc::cmsghdr;
                (*cmsg).cmsg_level = libc::SOL_UDP;
                (*cmsg).cmsg_type = libc::UDP_SEGMENT;
                (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<u16>() as u32) as usize;
                let gso_size: u16 = 1200; // QUIC packet size
                let data_ptr = libc::CMSG_DATA(cmsg) as *mut u16;
                *data_ptr = gso_size;
                msg.msg_control = control.as_mut_ptr() as *mut _;
                msg.msg_controllen = (*cmsg).cmsg_len;
            }

            // Send with MSG_ZEROCOPY flag
            let flags = MSG_ZEROCOPY | libc::MSG_DONTWAIT;
            let sent = libc::sendmsg(self.sock.as_raw_fd(), &msg, flags);

            if sent < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    return Ok(0);
                }
                return Err(err);
            }

            // Check for zerocopy completion notification
            if sent > 0 {
                #[cfg(target_os = "linux")]
                self.register_zerocopy_completion(self.sock.as_raw_fd(), sent as usize);
            }

            Ok(sent as usize)
        }
    }

    #[cfg(target_os = "linux")]
    fn register_zerocopy_completion(&self, _fd: RawFd, _bytes: usize) {
        // Forward MSG_ZEROCOPY completion into transport::uring inbox.
        // This keeps the producer (send path) decoupled from the consumer (CQ loop).
        // The consumer can periodically drain via try_drain_zerocopy_events().
        crate::transport::uring::notify_zerocopy_completion(_fd, _bytes);
    }
}

// =========================================================================
// SO_BUSY_POLL - Busy polling for ultra-low latency
// =========================================================================

pub struct BusyPollSocket {
    sock: UdpSocket,
}

impl BusyPollSocket {
    pub fn new(sock: UdpSocket, poll_usecs: u32) -> std::io::Result<Self> {
        let fd = sock.as_raw_fd();
        const SO_BUSY_POLL: libc::c_int = 46;

        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                SO_BUSY_POLL,
                &poll_usecs as *const _ as *const c_void,
                std::mem::size_of_val(&poll_usecs) as socklen_t,
            );
        }

        Ok(Self { sock })
    }
}

// =========================================================================
// NIC Parallelism - RSS/RPS/RFS configuration
// =========================================================================

#[cfg(target_os = "linux")]
pub struct NicParallelism;

#[cfg(target_os = "linux")]
impl NicParallelism {
    pub fn configure_rps(interface: &str) -> std::io::Result<()> {
        let mut sys = sysinfo::System::new();
        sys.refresh_cpu();
        let cpu_count = sys.cpus().len().max(1);
        let cpu_mask = (1u128 << cpu_count) - 1;
        let mask_str = format!("{:x}", cpu_mask);

        let base = format!("/sys/class/net/{}/queues", interface);
        for entry in std::fs::read_dir(&base)? {
            let entry = entry?;
            let name = entry.file_name();
            if name.to_string_lossy().starts_with("rx-") {
                let rps_cpus = entry.path().join("rps_cpus");
                if rps_cpus.exists() {
                    std::fs::write(&rps_cpus, &mask_str)?;
                }
            }
        }
        Ok(())
    }
}
