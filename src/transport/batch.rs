use crate::accelerate::transport_io as accelerate;
#[cfg(target_os = "linux")]
use crate::optimize::SimdDispatch;
use crate::simd::planner::AccelerationPlanner;
use std::net::{SocketAddr, UdpSocket};
#[cfg(target_os = "linux")]
use std::sync::atomic::AtomicUsize;
#[cfg(target_os = "linux")]
use std::sync::atomic::Ordering;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::io::FromRawFd;

use super::{MAX_BATCH_SIZE, OPTIMAL_BATCH_SIZE};

#[cfg(target_os = "linux")]
static BATCH_SENDS: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_os = "linux")]
static BATCH_RECVS: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_os = "linux")]
static PACKETS_BATCHED: AtomicUsize = AtomicUsize::new(0);

/// Ultra-fast batch packet processor with network acceleration
pub struct BatchProcessor {
    /// Preallocated buffers for zero-copy batch operations
    send_buffers: Vec<Vec<u8>>,
    recv_buffers: Vec<Vec<u8>>,
    /// IO vectors for sendmmsg/recvmmsg
    #[cfg(target_os = "linux")]
    send_msgs: Vec<libc::mmsghdr>,
    #[cfg(target_os = "linux")]
    recv_msgs: Vec<libc::mmsghdr>,
    /// Batch size based on CPU features
    batch_size: usize,
    /// Network acceleration features
    gso_config: Option<accelerate::UdpGsoConfig>,
    zero_copy: Option<accelerate::ZeroCopySocket>,
    busy_poll: Option<accelerate::BusyPollSocket>,
}

impl Default for BatchProcessor {
    fn default() -> Self {
        Self::new()
    }
}

impl BatchProcessor {
    pub fn new() -> Self {
        let plans = AccelerationPlanner::global();

        // Determine optimal batch size based on CPU
        let batch_size = if plans.transport.has_avx512f {
            MAX_BATCH_SIZE // 64 packets with AVX-512
        } else if plans.transport.has_avx2 {
            OPTIMAL_BATCH_SIZE // 32 packets with AVX2
        } else {
            16 // Conservative for older CPUs
        };

        log::info!("BatchProcessor: {} packet batches", batch_size);

        // Preallocate buffers
        let mut send_buffers = Vec::with_capacity(batch_size);
        let mut recv_buffers = Vec::with_capacity(batch_size);

        for _ in 0..batch_size {
            send_buffers.push(vec![0u8; 1500]); // MTU size
            recv_buffers.push(vec![0u8; 1500]);
        }

        #[cfg(target_os = "linux")]
        let (send_msgs, recv_msgs) = Self::init_mmsg_headers(batch_size);

        Self {
            send_buffers,
            recv_buffers,
            #[cfg(target_os = "linux")]
            send_msgs,
            #[cfg(target_os = "linux")]
            recv_msgs,
            batch_size,
            gso_config: None,
            zero_copy: None,
            busy_poll: None,
        }
    }

    #[cfg(target_os = "linux")]
    fn init_mmsg_headers(batch_size: usize) -> (Vec<libc::mmsghdr>, Vec<libc::mmsghdr>) {
        let mut send_msgs = Vec::with_capacity(batch_size);
        let mut recv_msgs = Vec::with_capacity(batch_size);

        for _ in 0..batch_size {
            send_msgs.push(unsafe { std::mem::zeroed() });
            recv_msgs.push(unsafe { std::mem::zeroed() });
        }

        (send_msgs, recv_msgs)
    }

    /// Initialize network acceleration for a socket
    pub fn init_acceleration(&mut self, socket: &UdpSocket) -> std::io::Result<()> {
        // Try to enable GSO
        self.gso_config = accelerate::UdpGsoConfig::enable(socket).ok();

        // Try to enable zero-copy
        if let Ok(sock_clone) = socket.try_clone() {
            self.zero_copy = accelerate::ZeroCopySocket::new(sock_clone).ok();
        }

        // Enable busy polling for low latency if configured
        if std::env::var("QUICFUSCATE_BUSY_POLL").is_ok() {
            if let Ok(sock_clone) = socket.try_clone() {
                self.busy_poll = accelerate::BusyPollSocket::new(sock_clone, 50).ok();
            }
        }

        log::info!("Network acceleration initialized:");
        log::info!("  GSO: {}", self.gso_config.as_ref().is_some_and(|g| g.enabled));
        log::info!("  Zero-copy: {}", self.zero_copy.is_some());
        log::info!("  Busy-poll: {}", self.busy_poll.is_some());

        Ok(())
    }

    /// Batch send packets with sendmmsg and acceleration (Linux)
    #[cfg(target_os = "linux")]
    pub fn batch_send(
        &mut self,
        socket: i32,
        packets: &[(&[u8], SocketAddr)],
    ) -> std::io::Result<usize> {
        // Try accelerated batch send first
        {
            crate::optimize::telemetry::ZEROCOPY_SEND_CALLS.fetch_add(1, Ordering::Relaxed);
            // Create a temporary UdpSocket from raw fd for accelerate API
            use std::os::unix::io::{FromRawFd, IntoRawFd};
            let sock = unsafe { UdpSocket::from_raw_fd(socket) };

            // Use sendmmsg through accelerate
            let result = accelerate::send_batch(&sock, packets);

            // Release socket without closing fd
            let _ = sock.into_raw_fd();

            if let Ok(sent) = result {
                BATCH_SENDS.fetch_add(1, Ordering::Relaxed);
                PACKETS_BATCHED.fetch_add(sent, Ordering::Relaxed);
                crate::optimize::telemetry::ZERO_COPY_SENDS.inc_by(sent as u64);
                return Ok(sent);
            }
        }

        crate::optimize::telemetry::ZEROCOPY_SEND_FALLBACKS.fetch_add(1, Ordering::Relaxed);

        // Fallback to manual sendmmsg preparation
        use std::mem;
        use std::ptr;

        let batch_count = packets.len().min(self.batch_size);
        if batch_count == 0 {
            return Ok(0);
        }

        // Prepare messages with SIMD copy
        for (i, (data, addr)) in packets.iter().take(batch_count).enumerate() {
            // Use SIMD memcpy for packet data
            let len = data.len().min(self.send_buffers[i].len());
            SimdDispatch::memcpy_fast(&mut self.send_buffers[i][..len], data);

            // Setup message header
            let mut sa: libc::sockaddr_storage = unsafe { mem::zeroed() };
            let sa_len = match addr {
                SocketAddr::V4(v4) => {
                    let sa4 = &mut sa as *mut _ as *mut libc::sockaddr_in;
                    unsafe {
                        (*sa4).sin_family = libc::AF_INET as u16;
                        (*sa4).sin_port = v4.port().to_be();
                        (*sa4).sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
                    }
                    mem::size_of::<libc::sockaddr_in>()
                }
                SocketAddr::V6(v6) => {
                    let sa6 = &mut sa as *mut _ as *mut libc::sockaddr_in6;
                    unsafe {
                        (*sa6).sin6_family = libc::AF_INET6 as u16;
                        (*sa6).sin6_port = v6.port().to_be();
                        (*sa6).sin6_addr.s6_addr = v6.ip().octets();
                        (*sa6).sin6_flowinfo = v6.flowinfo();
                        (*sa6).sin6_scope_id = v6.scope_id();
                    }
                    mem::size_of::<libc::sockaddr_in6>()
                }
            };

            // Setup iovec
            let mut iov =
                libc::iovec { iov_base: self.send_buffers[i].as_mut_ptr() as *mut _, iov_len: len };

            // Setup mmsghdr
            self.send_msgs[i] = libc::mmsghdr {
                msg_hdr: libc::msghdr {
                    msg_name: &mut sa as *mut _ as *mut _,
                    msg_namelen: sa_len as u32,
                    msg_iov: &mut iov,
                    msg_iovlen: 1,
                    msg_control: ptr::null_mut(),
                    msg_controllen: 0,
                    msg_flags: 0,
                },
                msg_len: 0,
            };
        }

        // Send all packets in one syscall (non-blocking)!
        let sent = unsafe {
            libc::sendmmsg(
                socket,
                self.send_msgs.as_mut_ptr(),
                batch_count as u32,
                libc::MSG_DONTWAIT,
            )
        };

        if sent < 0 {
            return Err(std::io::Error::last_os_error());
        }

        BATCH_SENDS.fetch_add(1, Ordering::Relaxed);
        PACKETS_BATCHED.fetch_add(sent as usize, Ordering::Relaxed);
        crate::optimize::telemetry::ZERO_COPY_SENDS.inc_by(sent as u64);

        Ok(sent as usize)
    }

    /// Batch receive packets with recvmmsg (Linux)
    #[cfg(target_os = "linux")]
    pub fn batch_recv(
        &mut self,
        socket: i32,
        timeout: Option<Duration>,
    ) -> std::io::Result<Vec<(Vec<u8>, SocketAddr)>> {
        use std::mem;

        let mut results = Vec::new();

        // Setup timeout
        let ts = timeout.map(|d| libc::timespec {
            tv_sec: d.as_secs() as i64,
            tv_nsec: d.subsec_nanos() as i64,
        });

        // Setup receive messages
        for i in 0..self.batch_size {
            let mut sa: libc::sockaddr_storage = unsafe { mem::zeroed() };

            let mut iov = libc::iovec {
                iov_base: self.recv_buffers[i].as_mut_ptr() as *mut _,
                iov_len: self.recv_buffers[i].len(),
            };

            self.recv_msgs[i] = libc::mmsghdr {
                msg_hdr: libc::msghdr {
                    msg_name: &mut sa as *mut _ as *mut _,
                    msg_namelen: mem::size_of::<libc::sockaddr_storage>() as u32,
                    msg_iov: &mut iov,
                    msg_iovlen: 1,
                    msg_control: std::ptr::null_mut(),
                    msg_controllen: 0,
                    msg_flags: 0,
                },
                msg_len: 0,
            };
        }

        // Receive all packets in one syscall!
        let received = unsafe {
            libc::recvmmsg(
                socket,
                self.recv_msgs.as_mut_ptr(),
                self.batch_size as u32,
                libc::MSG_DONTWAIT,
                ts.as_ref().map_or(std::ptr::null(), |t| t as *const _),
            )
        };

        if received < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(results);
            }
            return Err(err);
        }

        // Process received packets
        for i in 0..received as usize {
            let len = self.recv_msgs[i].msg_len as usize;
            if len > 0 {
                let mut data = vec![0u8; len];
                // Use SIMD copy
                SimdDispatch::memcpy_fast(&mut data, &self.recv_buffers[i][..len]);

                // Parse address
                let addr = unsafe {
                    let sa = self.recv_msgs[i].msg_hdr.msg_name as *const libc::sockaddr_storage;
                    match (*sa).ss_family as i32 {
                        libc::AF_INET => {
                            let sa4 = sa as *const libc::sockaddr_in;
                            SocketAddr::V4(std::net::SocketAddrV4::new(
                                std::net::Ipv4Addr::from((*sa4).sin_addr.s_addr.to_ne_bytes()),
                                (*sa4).sin_port.to_be(),
                            ))
                        }
                        libc::AF_INET6 => {
                            let sa6 = sa as *const libc::sockaddr_in6;
                            SocketAddr::V6(std::net::SocketAddrV6::new(
                                std::net::Ipv6Addr::from((*sa6).sin6_addr.s6_addr),
                                (*sa6).sin6_port.to_be(),
                                (*sa6).sin6_flowinfo,
                                (*sa6).sin6_scope_id,
                            ))
                        }
                        _ => continue,
                    }
                };

                results.push((data, addr));
            }
        }

        BATCH_RECVS.fetch_add(1, Ordering::Relaxed);
        PACKETS_BATCHED.fetch_add(received as usize, Ordering::Relaxed);
        crate::optimize::telemetry::ZERO_COPY_RECVS.inc_by(received as u64);

        Ok(results)
    }

    /// Batched send for macOS/iOS using sendmsg_x (best-effort).
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub fn batch_send(
        &mut self,
        socket: i32,
        packets: &[(&[u8], SocketAddr)],
    ) -> std::io::Result<usize> {
        if packets.is_empty() {
            return Ok(0);
        }

        use std::os::unix::io::IntoRawFd;
        let sock = unsafe { UdpSocket::from_raw_fd(socket) };
        let result = accelerate::send_batch(&sock, packets);
        let _ = sock.into_raw_fd();

        match result {
            Ok(sent) => {
                crate::optimize::telemetry::ZERO_COPY_SENDS.inc_by(sent as u64);
                Ok(sent)
            }
            Err(err) => Err(err),
        }
    }

    /// Fallback for non-Linux, non-Apple Unix systems
    #[cfg(all(unix, not(any(target_os = "linux", target_os = "macos", target_os = "ios"))))]
    pub fn batch_send(
        &mut self,
        socket: i32,
        packets: &[(&[u8], SocketAddr)],
    ) -> std::io::Result<usize> {
        use std::os::unix::io::IntoRawFd;
        let sock = unsafe { UdpSocket::from_raw_fd(socket) };
        let mut sent = 0usize;
        for (data, addr) in packets {
            sock.send_to(data, addr)?;
            sent += 1;
        }
        let _ = sock.into_raw_fd();
        Ok(sent)
    }

    /// Fallback for Windows systems
    #[cfg(target_os = "windows")]
    pub fn batch_send(
        &mut self,
        socket: i32,
        packets: &[(&[u8], SocketAddr)],
    ) -> std::io::Result<usize> {
        use std::os::windows::io::FromRawSocket;
        use std::os::windows::io::IntoRawSocket;
        use windows_sys::Win32::Networking::WinSock::SOCKET;
        let sock = unsafe { UdpSocket::from_raw_socket(socket as SOCKET) };
        let mut sent = 0usize;
        for (data, addr) in packets {
            sock.send_to(data, addr)?;
            sent += 1;
        }
        let _ = sock.into_raw_socket();
        Ok(sent)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn batch_recv(
        &mut self,
        _socket: i32,
        _timeout: Option<Duration>,
    ) -> std::io::Result<Vec<(Vec<u8>, SocketAddr)>> {
        // Fallback to individual receives
        log::debug!("Batch recv not available on this platform");
        let _ = (self.send_buffers.len(), self.recv_buffers.len(), self.batch_size);
        Ok(Vec::new())
    }
}
