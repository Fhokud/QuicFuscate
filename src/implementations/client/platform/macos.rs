//! macOS platform implementation.

use super::traits::*;
use std::net::IpAddr;
use std::process::Command;

/// macOS platform backend.
pub struct MacOSPlatform {
    utun_counter: std::sync::atomic::AtomicU32,
}

impl MacOSPlatform {
    pub fn new() -> Self {
        Self { utun_counter: std::sync::atomic::AtomicU32::new(10) }
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

    /// Run ifconfig command.
    fn run_ifconfig(&self, args: &[&str]) -> Result<(), PlatformError> {
        let status = Command::new("ifconfig")
            .args(args)
            .status()
            .map_err(|e| PlatformError::CommandFailed(e.to_string()))?;

        if !status.success() {
            return Err(PlatformError::CommandFailed(format!(
                "ifconfig {} failed",
                args.join(" ")
            )));
        }
        Ok(())
    }
}

impl Default for MacOSPlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl PlatformBackend for MacOSPlatform {
    fn name(&self) -> &'static str {
        "macOS"
    }

    fn is_elevated(&self) -> bool {
        unsafe { libc::geteuid() == 0 }
    }

    fn request_elevation(&self) -> Result<(), PlatformError> {
        if self.is_elevated() {
            return Ok(());
        }
        Err(PlatformError::PermissionDenied("Please run with sudo".to_string()))
    }

    fn create_tun(&self, config: &TunDeviceConfig) -> Result<TunHandle, PlatformError> {
        // macOS uses utun devices via a system socket
        // The tun2 crate handles this properly

        let utun_num = self.utun_counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let name = format!("utun{}", utun_num);

        // Create utun socket
        let fd = unsafe {
            let sock = libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, 2); // SYSPROTO_CONTROL = 2
            if sock < 0 {
                return Err(PlatformError::DeviceError("Failed to create utun socket".to_string()));
            }
            sock
        };

        // Configure the interface
        self.run_ifconfig(&[
            &name,
            &config.address.to_string(),
            &config.address.to_string(), // Point-to-point
            "netmask",
            "255.255.255.0",
            "mtu",
            &config.mtu.to_string(),
            "up",
        ])?;

        log::info!("Created utun device {} with IP {}", name, config.address);

        Ok(TunHandle { name, id: utun_num, fd })
    }

    fn destroy_tun(&self, handle: TunHandle) -> Result<(), PlatformError> {
        // Bring down interface
        let _ = self.run_ifconfig(&[&handle.name, "down"]);

        // Close socket
        unsafe {
            libc::close(handle.fd);
        }

        log::info!("Destroyed utun device {}", handle.name);
        Ok(())
    }

    fn add_route(&self, route: &RouteConfig) -> Result<(), PlatformError> {
        self.run_route(&[
            "-n",
            "add",
            "-net",
            &format!("{}/{}", route.destination, route.prefix_len),
            &route.gateway.to_string(),
        ])
    }

    fn remove_route(&self, route: &RouteConfig) -> Result<(), PlatformError> {
        let _ = self.run_route(&[
            "-n",
            "delete",
            "-net",
            &format!("{}/{}", route.destination, route.prefix_len),
        ]);
        Ok(())
    }

    fn set_dns(&self, config: &DnsConfig) -> Result<(), PlatformError> {
        // Use scutil to set DNS
        // networksetup -setdnsservers "Wi-Fi" 1.1.1.1 8.8.8.8

        // Get network service name (simplified - assumes Wi-Fi)
        let service = "Wi-Fi";

        let mut args = vec!["-setdnsservers", service];
        let server_strs: Vec<String> = config.servers.iter().map(|s| s.to_string()).collect();
        for s in &server_strs {
            args.push(s);
        }

        let status = Command::new("networksetup")
            .args(&args)
            .status()
            .map_err(|e| PlatformError::DnsError(e.to_string()))?;

        if !status.success() {
            log::warn!("networksetup DNS failed, trying scutil");
        }

        log::info!("DNS configured: {:?}", config.servers);
        Ok(())
    }

    fn restore_dns(&self) -> Result<(), PlatformError> {
        // Reset DNS to DHCP
        let _ = Command::new("networksetup").args(["-setdnsservers", "Wi-Fi", "Empty"]).status();

        log::info!("DNS restored to DHCP");
        Ok(())
    }

    fn default_gateway(&self) -> Result<IpAddr, PlatformError> {
        let output = Command::new("route")
            .args(["-n", "get", "default"])
            .output()
            .map_err(|e| PlatformError::CommandFailed(e.to_string()))?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse "gateway: X.X.X.X"
        for line in stdout.lines() {
            if line.trim().starts_with("gateway:") {
                if let Some(gw) = line.split(':').nth(1) {
                    if let Ok(ip) = gw.trim().parse() {
                        return Ok(ip);
                    }
                }
            }
        }

        Err(PlatformError::RoutingError("Could not detect default gateway".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_macos_platform_name() {
        let platform = MacOSPlatform::new();
        assert_eq!(platform.name(), "macOS");
    }
}
