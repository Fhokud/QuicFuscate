#![cfg(feature = "rust-tests")]

#[cfg(target_os = "linux")]
use std::collections::HashSet;
#[cfg(target_os = "linux")]
use std::net::UdpSocket;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
use quicfuscate::optimize::zc_batch;

#[test]
#[cfg(not(target_os = "linux"))]
fn io_hotpath_kernel_integration_is_linux_only() {}

#[test]
#[cfg(target_os = "linux")]
fn zc_batch_sendmmsg_kernel_path_sends_all_datagrams() {
    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    receiver.set_read_timeout(Some(Duration::from_secs(1))).expect("set read timeout");
    let recv_addr = receiver.local_addr().expect("receiver addr");

    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    sender.connect(recv_addr).expect("connect sender");

    let payloads: Vec<&[u8]> = vec![b"kernel-alpha", b"kernel-beta", b"kernel-gamma"];
    let sent = zc_batch::sendmmsg(sender.as_raw_fd(), &payloads).expect("sendmmsg");
    assert_eq!(sent, payloads.len(), "sendmmsg should send full batch");

    let mut received = Vec::with_capacity(sent);
    for _ in 0..sent {
        let mut buf = [0u8; 256];
        let (len, _from) = receiver.recv_from(&mut buf).expect("recv datagram");
        received.push(buf[..len].to_vec());
    }

    let expected: HashSet<Vec<u8>> = payloads.iter().map(|p| p.to_vec()).collect();
    let actual: HashSet<Vec<u8>> = received.into_iter().collect();
    assert_eq!(actual, expected, "received datagrams mismatch");
}

#[test]
#[cfg(all(target_os = "linux", feature = "uring_sys"))]
fn uring_try_send_connected_kernel_smoke() {
    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    receiver.set_read_timeout(Some(Duration::from_millis(500))).expect("set read timeout");
    let recv_addr = receiver.local_addr().expect("receiver addr");

    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    sender.connect(recv_addr).expect("connect sender");
    let payload = b"uring-kernel-smoke";

    match quicfuscate::transport::uring::try_send_connected(sender.as_raw_fd(), payload) {
        Ok(Some(n)) => {
            assert_eq!(n, payload.len(), "uring send length mismatch");
            let mut buf = [0u8; 128];
            let (len, _from) = receiver.recv_from(&mut buf).expect("recv datagram");
            assert_eq!(&buf[..len], payload);
        }
        Ok(None) => {
            // Valid on systems where io_uring is unavailable or deliberately disabled.
        }
        Err(e) => {
            // Also acceptable for this smoke test; runtime code falls back to socket path.
            let kind = e.kind();
            assert!(
                matches!(
                    kind,
                    std::io::ErrorKind::Unsupported
                        | std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::Other
                ),
                "unexpected io_uring error kind: {kind:?}"
            );
        }
    }
}
