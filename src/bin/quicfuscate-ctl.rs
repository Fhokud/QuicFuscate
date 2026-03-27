//! QuicFuscate Admin CLI (quicfuscate-ctl)
//!
//! Command-line interface for managing the QuicFuscate server.

use std::io::{BufRead, Write};
use std::os::unix::net::UnixStream;

const DEFAULT_SOCKET: &str = "/var/run/quicfuscate/ctl.sock";

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_usage();
        std::process::exit(1);
    }

    let socket_path =
        std::env::var("QUICFUSCATE_CTL_SOCKET").unwrap_or_else(|_| DEFAULT_SOCKET.to_string());

    let cmd = &args[1];

    let result = match cmd.as_str() {
        "status" => send_command(&socket_path, r#"{"cmd":"status"}"#),
        "clients" => send_command(&socket_path, r#"{"cmd":"clients"}"#),
        "kick" => {
            if args.len() < 3 {
                eprintln!("Usage: quicfuscate-ctl kick <client_id>");
                std::process::exit(1);
            }
            send_command(&socket_path, &format!(r#"{{"cmd":"kick","id":"{}"}}"#, args[2]))
        }
        "block" => {
            if args.len() < 3 {
                eprintln!("Usage: quicfuscate-ctl block <ip>");
                std::process::exit(1);
            }
            send_command(&socket_path, &format!(r#"{{"cmd":"block","ip":"{}"}}"#, args[2]))
        }
        "unblock" => {
            if args.len() < 3 {
                eprintln!("Usage: quicfuscate-ctl unblock <ip>");
                std::process::exit(1);
            }
            send_command(&socket_path, &format!(r#"{{"cmd":"unblock","ip":"{}"}}"#, args[2]))
        }
        "reload" => send_command(&socket_path, r#"{"cmd":"reload"}"#),
        "qkey" => send_command(&socket_path, r#"{"cmd":"qkey"}"#),
        "shutdown" => send_command(&socket_path, r#"{"cmd":"shutdown"}"#),
        "help" | "--help" | "-h" => {
            print_usage();
            Ok(())
        }
        _ => {
            eprintln!("Unknown command: {}", cmd);
            print_usage();
            std::process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn print_usage() {
    println!("QuicFuscate Control CLI");
    println!();
    println!("Usage: quicfuscate-ctl <command> [options]");
    println!();
    println!("Commands:");
    println!("  status              Show server status");
    println!("  clients             List connected clients");
    println!("  kick <id>           Disconnect a client");
    println!("  block <ip>          Block an IP address");
    println!("  unblock <ip>        Unblock an IP address");
    println!("  reload              Reload configuration");
    println!("  qkey                Generate client QKey");
    println!("  shutdown            Shutdown the server");
    println!();
    println!("Environment:");
    println!("  QUICFUSCATE_CTL_SOCKET    Control socket path (default: {})", DEFAULT_SOCKET);
}

fn send_command(socket_path: &str, cmd: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = UnixStream::connect(socket_path)
        .map_err(|e| format!("Cannot connect to server: {} (is it running?)", e))?;

    // Send command
    writeln!(stream, "{}", cmd)?;
    stream.flush()?;

    // Read response
    let mut reader = std::io::BufReader::new(&stream);
    let mut response = String::new();
    reader.read_line(&mut response)?;

    // Parse and format response
    let resp: serde_json::Value = serde_json::from_str(&response)
        .map_err(|e| format!("Malformed server response (not valid JSON): {}", e))?;

    if resp["success"].as_bool().unwrap_or(false) {
        if let Some(data) = resp.get("data") {
            format_output(data);
        } else if let Some(msg) = resp["message"].as_str() {
            println!("{}", msg);
        } else {
            println!("OK");
        }
    } else {
        let msg = resp["message"].as_str().unwrap_or("Unknown error");
        eprintln!("Error: {}", msg);
        std::process::exit(1);
    }

    Ok(())
}

fn format_output(data: &serde_json::Value) {
    // Special handling for status
    if data.get("version").is_some() {
        println!("QuicFuscate Server v{}", data["version"].as_str().unwrap_or("?"));
        println!("Status: Running");
        println!("Uptime: {}", format_duration(data["uptime_secs"].as_u64().unwrap_or(0)));
        println!(
            "Clients: {}/{}",
            data["clients_active"].as_u64().unwrap_or(0),
            data["clients_total"].as_u64().unwrap_or(0)
        );
        println!(
            "Traffic: {} down / {} up",
            format_bytes(data["bytes_in"].as_u64().unwrap_or(0)),
            format_bytes(data["bytes_out"].as_u64().unwrap_or(0))
        );
        if let Some(stealth) = data.get("stealth") {
            println!(
                "Stealth: {} HTTP/3, {} TLS 1.3",
                stealth["http3"].as_u64().unwrap_or(0),
                stealth["tls13"].as_u64().unwrap_or(0)
            );
        }
        if let Some(fec) = data.get("fec_recovered") {
            println!("FEC Recovered: {} packets", fec.as_u64().unwrap_or(0));
        }
        return;
    }

    // Special handling for qkey
    if let Some(qkey) = data.get("qkey") {
        println!("{}", qkey.as_str().unwrap_or(""));
        return;
    }

    // Special handling for clients list
    if let Some(clients) = data.as_array() {
        if clients.is_empty() {
            println!("No clients connected");
            return;
        }
        println!("{:<12} {:<15} {:<12} {:<12}", "ID", "IP", "Connected", "Traffic");
        println!("{}", "-".repeat(55));
        for client in clients {
            println!(
                "{:<12} {:<15} {:<12} {:<12}",
                client["id"].as_str().unwrap_or("?"),
                client["ip"].as_str().unwrap_or("?"),
                format_duration(client["connected_secs"].as_u64().unwrap_or(0)),
                format_bytes(
                    client["bytes_in"].as_u64().unwrap_or(0)
                        + client["bytes_out"].as_u64().unwrap_or(0)
                )
            );
        }
        return;
    }

    // Default: pretty print JSON
    match serde_json::to_string_pretty(data) {
        Ok(json) => println!("{}", json),
        Err(e) => eprintln!("Warning: could not serialize response data: {}", e),
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

fn format_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else if secs < 86400 {
        let hours = secs / 3600;
        let mins = (secs % 3600) / 60;
        format!("{}h {}m", hours, mins)
    } else {
        let days = secs / 86400;
        let hours = (secs % 86400) / 3600;
        format!("{}d {}h", days, hours)
    }
}
