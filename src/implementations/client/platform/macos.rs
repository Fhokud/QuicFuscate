//! macOS platform implementation.

use super::traits::*;
use std::net::IpAddr;
use std::process::Command;
use std::sync::Mutex;

/// macOS platform backend.
pub struct MacOSPlatform {
    utun_counter: std::sync::atomic::AtomicU32,
    dns_service: Mutex<Option<String>>,
}

impl MacOSPlatform {
    pub fn new() -> Self {
        Self { utun_counter: std::sync::atomic::AtomicU32::new(10), dns_service: Mutex::new(None) }
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

    fn run_networksetup(&self, args: &[&str]) -> Result<(), PlatformError> {
        let status = Command::new("networksetup")
            .args(args)
            .status()
            .map_err(|e| PlatformError::DnsError(e.to_string()))?;
        if !status.success() {
            return Err(PlatformError::DnsError(format!("networksetup {} failed", args.join(" "))));
        }
        Ok(())
    }

    fn detect_default_interface(&self) -> Result<String, PlatformError> {
        let output = Command::new("route")
            .args(["-n", "get", "default"])
            .output()
            .map_err(|e| PlatformError::CommandFailed(e.to_string()))?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("interface:") {
                let iface = rest.trim();
                if !iface.is_empty() {
                    return Ok(iface.to_string());
                }
            }
        }
        Err(PlatformError::DnsError("Could not determine default network interface".to_string()))
    }

    fn resolve_network_service_for_device(&self, device: &str) -> Result<String, PlatformError> {
        let output = Command::new("networksetup")
            .args(["-listnetworkserviceorder"])
            .output()
            .map_err(|e| PlatformError::DnsError(e.to_string()))?;
        let stdout = String::from_utf8_lossy(&output.stdout);

        let mut current_service: Option<String> = None;
        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('(') && trimmed.contains("Hardware Port:") {
                if let Some(idx) = trimmed.find("Device:") {
                    let dev = trimmed[idx + "Device:".len()..].trim().trim_end_matches(')').trim();
                    if dev == device {
                        if let Some(service) = current_service {
                            return Ok(service);
                        }
                    }
                }
                continue;
            }

            if let Some(pos) = trimmed.find(')') {
                let service = trimmed[pos + 1..].trim().trim_start_matches('*').trim();
                if !service.is_empty() {
                    current_service = Some(service.to_string());
                }
            }
        }

        Err(PlatformError::DnsError(format!(
            "Could not map interface '{}' to a network service",
            device
        )))
    }

    fn dns_service_name(&self) -> Result<String, PlatformError> {
        if let Some(existing) = self.dns_service.lock().unwrap_or_else(|e| e.into_inner()).clone() {
            return Ok(existing);
        }
        let iface = self.detect_default_interface()?;
        let service = self.resolve_network_service_for_device(&iface)?;
        *self.dns_service.lock().unwrap_or_else(|e| e.into_inner()) = Some(service.clone());
        Ok(service)
    }

    fn prefix_to_netmask(prefix: u8) -> String {
        if prefix == 0 {
            return "0.0.0.0".to_string();
        }
        if prefix >= 32 {
            return "255.255.255.255".to_string();
        }
        let mask: u32 = !((1u32 << (32 - prefix)) - 1);
        format!(
            "{}.{}.{}.{}",
            (mask >> 24) & 0xFF,
            (mask >> 16) & 0xFF,
            (mask >> 8) & 0xFF,
            mask & 0xFF
        )
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
            &Self::prefix_to_netmask(config.netmask),
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
        let service = self.dns_service_name()?;
        let mut args = vec!["-setdnsservers".to_string(), service];
        args.extend(config.servers.iter().map(|s| s.to_string()));
        if config.servers.is_empty() {
            args.push("Empty".to_string());
        }
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        self.run_networksetup(&arg_refs)?;

        log::info!("DNS configured: {:?}", config.servers);
        Ok(())
    }

    fn restore_dns(&self) -> Result<(), PlatformError> {
        // Reset DNS to DHCP
        let service = self.dns_service_name()?;
        self.run_networksetup(&["-setdnsservers", &service, "Empty"])?;

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
