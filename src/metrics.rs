use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn handle_connection(mut stream: TcpStream) {
    let mut buf = [0u8; 1024];
    // Read a single request (very small parser sufficient for /telemetry)
    let n = match stream.read(&mut buf).await {
        Ok(0) => return,
        Ok(n) => n,
        Err(_) => return,
    };
    let req = &buf[..n];
    let is_telemetry = req.starts_with(b"GET /telemetry") || req.starts_with(b"GET /telemetry ");

    if is_telemetry {
        let body = crate::telemetry::export_telemetry_text();
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n\r\n{}",
            body.len(), body
        );
        let _ = stream.write_all(resp.as_bytes()).await;
    } else {
        let body = "Not Found";
        let resp = format!(
            "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n\r\n{}",
            body.len(), body
        );
        let _ = stream.write_all(resp.as_bytes()).await;
    }
    let _ = stream.shutdown().await;
}

/// Spawn a minimal HTTP server that exposes a telemetry snapshot on /telemetry.
/// Address is taken from QUICFUSCATE_METRICS_ADDR (default 127.0.0.1:9898).
pub fn spawn_telemetry_server() {
    let addr =
        std::env::var("QUICFUSCATE_METRICS_ADDR").unwrap_or_else(|_| "127.0.0.1:9898".into());
    tokio::spawn(async move {
        match TcpListener::bind(&addr).await {
            Ok(listener) => {
                log::info!("Telemetry server listening on {} at /telemetry", addr);
                loop {
                    match listener.accept().await {
                        Ok((stream, _peer)) => {
                            tokio::spawn(handle_connection(stream));
                        }
                        Err(e) => {
                            log::warn!("Metrics accept error: {}", e);
                            break;
                        }
                    }
                }
            }
            Err(e) => {
                log::warn!("Failed to bind metrics server on {}: {}", addr, e);
            }
        }
    });
}
