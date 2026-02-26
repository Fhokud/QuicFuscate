#![cfg(feature = "rust-tests")]

use std::env;
use std::net::TcpListener as StdTcpListener;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::sleep;

static ENV_LOCK: Mutex<()> = Mutex::const_new(());

fn reserve_port() -> u16 {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = listener.local_addr().expect("local_addr").port();
    drop(listener);
    port
}

async fn request(addr: &str, path: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let req = format!("GET {} HTTP/1.1\r\nHost: {}\r\n\r\n", path, addr);
    stream.write_all(req.as_bytes()).await.expect("write");
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.expect("read");
    String::from_utf8_lossy(&buf).to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn telemetry_http_endpoint_responds() {
    let _guard = ENV_LOCK.lock().await;
    let port = reserve_port();
    let addr = format!("127.0.0.1:{}", port);
    let prev = env::var("QUICFUSCATE_METRICS_ADDR").ok();
    env::set_var("QUICFUSCATE_METRICS_ADDR", &addr);

    quicfuscate::metrics::spawn_telemetry_server();

    let mut last_err = None;
    let mut ready = false;
    for _ in 0..20 {
        match TcpStream::connect(&addr).await {
            Ok(_) => {
                ready = true;
                break;
            }
            Err(e) => {
                last_err = Some(e);
                sleep(Duration::from_millis(25)).await;
            }
        }
    }
    if !ready {
        panic!("telemetry server not reachable on {}: {:?}", addr, last_err);
    }

    let ok_resp = request(&addr, "/telemetry").await;
    let (ok_head, ok_body) = ok_resp.split_once("\r\n\r\n").unwrap_or((&ok_resp, ""));
    assert!(ok_head.starts_with("HTTP/1.1 200"), "expected 200 OK, got: {}", ok_head);
    assert!(
        ok_head.contains("Content-Type: text/plain"),
        "expected text/plain response, got: {}",
        ok_head
    );
    assert!(!ok_body.is_empty(), "telemetry body must not be empty");
    assert!(
        ok_body.contains("quicfuscate_mem_pool_capacity"),
        "telemetry body missing expected counter"
    );

    let miss_resp = request(&addr, "/not-found").await;
    let (miss_head, _miss_body) = miss_resp.split_once("\r\n\r\n").unwrap_or((&miss_resp, ""));
    assert!(
        miss_head.starts_with("HTTP/1.1 404"),
        "expected 404 for non-telemetry path, got: {}",
        miss_head
    );

    if let Some(prev) = prev {
        env::set_var("QUICFUSCATE_METRICS_ADDR", prev);
    } else {
        env::remove_var("QUICFUSCATE_METRICS_ADDR");
    }
}
