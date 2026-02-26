//! Windows platform implementation.

use super::traits::*;
use std::net::IpAddr;
use std::process::Command;

/// Windows platform backend.
pub struct WindowsPlatform;

impl WindowsPlatform {
    pub fn new() -> Self {
        Self
    }

    /// Run netsh command.
    fn run_netsh(&self, args: &[&str]) -> Result<(), PlatformError> {
        let status = Command::new("netsh")
            .args(args)
            .status()
            .map_err(|e| PlatformError::CommandFailed(e.to_string()))?;

        if !status.success() {
            return Err(PlatformError::CommandFailed(format!("netsh {} failed", args.join(" "))));
        }
        Ok(())
    }

    /// Run route command.
    fn run_route(&self, args: &[&str]) -> Result<(), PlatformError> {
        let status = Command::new("route")
            .args(args)
            .status()
            .map_err(|e| PlatformError::CommandFailed(e.to_string()))?;

        if !status.success() {
            return Err(PlatformError::CommandFailed(format!("route {} failed", args.join(" "))));
        }
        Ok(())
    }
}

impl Default for WindowsPlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl PlatformBackend for WindowsPlatform {
    fn name(&self) -> &'static str {
        "Windows"
    }

    fn is_elevated(&self) -> bool {
        // Check if running as Administrator
        // Simplified check - real impl uses Windows API
        let output = Command::new("net").args(["session"]).output();

        match output {
            Ok(o) => o.status.success(),
            Err(_) => false,
        }
    }

    fn request_elevation(&self) -> Result<(), PlatformError> {
        if self.is_elevated() {
            return Ok(());
        }
        Err(PlatformError::PermissionDenied("Please run as Administrator".to_string()))
    }

    fn create_tun(&self, config: &TunDeviceConfig) -> Result<TunHandle, PlatformError> {
        // Windows uses WinTUN driver
        // The wintun crate provides the interface

        let name = config.name.clone().unwrap_or_else(|| "QuicFuscate".to_string());

        // In production, we'd use the wintun crate here
        // For now, we simulate with netsh

        log::info!("Creating WinTUN adapter: {}", name);

        // Configure IP address via netsh
        self.run_netsh(&[
            "interface",
            "ip",
            "set",
            "address",
            &format!("name=\"{}\"", name),
            "static",
            &config.address.to_string(),
            "255.255.255.0", // Simplified
        ])?;

        log::info!("Created TUN device {} with IP {}", name, config.address);

        Ok(TunHandle {
            name,
            id: 0,
            handle: 0, // Would be actual HANDLE
        })
    }

    fn destroy_tun(&self, handle: TunHandle) -> Result<(), PlatformError> {
        // Disable the adapter
        self.run_netsh(&["interface", "set", "interface", &handle.name, "admin=disabled"])?;

        log::info!("Destroyed TUN device {}", handle.name);
        Ok(())
    }

    fn add_route(&self, route: &RouteConfig) -> Result<(), PlatformError> {
        // Calculate netmask from prefix length
        let netmask = prefix_to_netmask(route.prefix_len);

        self.run_route(&[
            "add",
            &route.destination.to_string(),
            "mask",
            &netmask,
            &route.gateway.to_string(),
            "metric",
            &route.metric.to_string(),
        ])
    }

    fn remove_route(&self, route: &RouteConfig) -> Result<(), PlatformError> {
        let _ = self.run_route(&["delete", &route.destination.to_string()]);
        Ok(())
    }

    fn set_dns(&self, config: &DnsConfig) -> Result<(), PlatformError> {
        // Get interface name (simplified)
        let interface = "QuicFuscate";

        // Set primary DNS
        if let Some(primary) = config.servers.first() {
            self.run_netsh(&[
                "interface",
                "ip",
                "set",
                "dns",
                &format!("name=\"{}\"", interface),
                "static",
                &primary.to_string(),
            ])?;
        }

        // Add secondary DNS servers
        for dns in config.servers.iter().skip(1) {
            let _ = self.run_netsh(&[
                "interface",
                "ip",
                "add",
                "dns",
                &format!("name=\"{}\"", interface),
                &dns.to_string(),
                "index=2",
            ]);
        }

        log::info!("DNS configured: {:?}", config.servers);
        Ok(())
    }

    fn restore_dns(&self) -> Result<(), PlatformError> {
        // Reset DNS to DHCP
        let interface = "QuicFuscate";
        let _ = self.run_netsh(&[
            "interface",
            "ip",
            "set",
            "dns",
            &format!("name=\"{}\"", interface),
            "dhcp",
        ]);

        log::info!("DNS restored to DHCP");
        Ok(())
    }

    fn default_gateway(&self) -> Result<IpAddr, PlatformError> {
        let output = Command::new("route")
            .args(["print", "0.0.0.0"])
            .output()
            .map_err(|e| PlatformError::CommandFailed(e.to_string()))?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse Windows route table output
        for line in stdout.lines() {
            if line.contains("0.0.0.0") && !line.contains("On-link") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    if let Ok(ip) = parts[2].parse() {
                        return Ok(ip);
                    }
                }
            }
        }

        Err(PlatformError::RoutingError("Could not detect default gateway".to_string()))
    }
}

/// Convert CIDR prefix length to dotted netmask.
fn prefix_to_netmask(prefix: u8) -> String {
    let mask: u32 = !((1u32 << (32 - prefix)) - 1);
    format!(
        "{}.{}.{}.{}",
        (mask >> 24) & 0xFF,
        (mask >> 16) & 0xFF,
        (mask >> 8) & 0xFF,
        mask & 0xFF
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_windows_platform_name() {
        let platform = WindowsPlatform::new();
        assert_eq!(platform.name(), "Windows");
    }

    #[test]
    fn test_prefix_to_netmask() {
        assert_eq!(prefix_to_netmask(24), "255.255.255.0");
        assert_eq!(prefix_to_netmask(16), "255.255.0.0");
        assert_eq!(prefix_to_netmask(8), "255.0.0.0");
        assert_eq!(prefix_to_netmask(32), "255.255.255.255");
    }
}
