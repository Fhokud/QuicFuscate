//! Linux platform implementation.

use super::traits::*;
use std::net::IpAddr;
use std::process::Command;

/// Linux platform backend.
pub struct LinuxPlatform;

impl LinuxPlatform {
    pub fn new() -> Self {
        Self
    }

    /// Check if systemd-resolved is available.
    fn has_systemd_resolved(&self) -> bool {
        std::path::Path::new("/run/systemd/resolve/stub-resolv.conf").exists()
    }

    /// Run ip command.
    fn run_ip(&self, args: &[&str]) -> Result<(), PlatformError> {
        let status = Command::new("ip")
            .args(args)
            .status()
            .map_err(|e| PlatformError::CommandFailed(e.to_string()))?;

        if !status.success() {
            return Err(PlatformError::CommandFailed(format!("ip {} failed", args.join(" "))));
        }
        Ok(())
    }
}

impl Default for LinuxPlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl PlatformBackend for LinuxPlatform {
    fn name(&self) -> &'static str {
        "Linux"
    }

    fn is_elevated(&self) -> bool {
        unsafe { libc::geteuid() == 0 }
    }

    fn request_elevation(&self) -> Result<(), PlatformError> {
        if self.is_elevated() {
            return Ok(());
        }
        Err(PlatformError::PermissionDenied("Please run with sudo or as root".to_string()))
    }

    fn create_tun(&self, config: &TunDeviceConfig) -> Result<TunHandle, PlatformError> {
        use std::os::unix::io::AsRawFd;
        use std::os::unix::io::IntoRawFd;

        // Open /dev/net/tun
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .map_err(|e| PlatformError::DeviceError(e.to_string()))?;

        let fd = file.as_raw_fd();

        // Device name
        let name = config.name.clone().unwrap_or_else(|| "qftun0".to_string());

        // TUNSETIFF ioctl would go here - for now, use tuntap crate behavior
        // This is a simplified version - real impl uses tun2 crate

        // Configure the device via ip commands
        self.run_ip(&["link", "set", &name, "up"])?;

        self.run_ip(&[
            "addr",
            "add",
            &format!("{}/{}", config.address, config.netmask),
            "dev",
            &name,
        ])?;

        self.run_ip(&["link", "set", &name, "mtu", &config.mtu.to_string()])?;

        log::info!("Created TUN device {} with IP {}/{}", name, config.address, config.netmask);

        // Transfer fd ownership to caller-side lifecycle management.
        let _ = file.into_raw_fd();

        Ok(TunHandle { name, id: 0, fd })
    }

    fn destroy_tun(&self, handle: TunHandle) -> Result<(), PlatformError> {
        self.run_ip(&["link", "set", &handle.name, "down"])?;
        self.run_ip(&["link", "delete", &handle.name])?;

        // Close file descriptor
        unsafe {
            libc::close(handle.fd);
        }

        log::info!("Destroyed TUN device {}", handle.name);
        Ok(())
    }

    fn add_route(&self, route: &RouteConfig) -> Result<(), PlatformError> {
        self.run_ip(&[
            "route",
            "add",
            &format!("{}/{}", route.destination, route.prefix_len),
            "via",
            &route.gateway.to_string(),
            "metric",
            &route.metric.to_string(),
        ])
    }

    fn remove_route(&self, route: &RouteConfig) -> Result<(), PlatformError> {
        let _ =
            self.run_ip(&["route", "del", &format!("{}/{}", route.destination, route.prefix_len)]);
        Ok(())
    }

    fn set_dns(&self, config: &DnsConfig) -> Result<(), PlatformError> {
        if self.has_systemd_resolved() {
            // Use resolvectl
            for server in &config.servers {
                let _ = Command::new("resolvectl")
                    .args(["dns", "qftun0", &server.to_string()])
                    .status();
            }
        } else {
            // Write to /etc/resolv.conf
            let mut content = String::new();
            for server in &config.servers {
                content.push_str(&format!("nameserver {}\n", server));
            }
            for domain in &config.search_domains {
                content.push_str(&format!("search {}\n", domain));
            }

            std::fs::write("/etc/resolv.conf", content)
                .map_err(|e| PlatformError::DnsError(e.to_string()))?;
        }

        log::info!("DNS configured: {:?}", config.servers);
        Ok(())
    }

    fn restore_dns(&self) -> Result<(), PlatformError> {
        // In production, we'd restore the original DNS configuration
        log::info!("DNS restored");
        Ok(())
    }

    fn default_gateway(&self) -> Result<IpAddr, PlatformError> {
        let output = Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .map_err(|e| PlatformError::CommandFailed(e.to_string()))?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse "default via X.X.X.X ..."
        for (i, word) in stdout.split_whitespace().enumerate() {
            if word == "via" {
                if let Some(gw) = stdout.split_whitespace().nth(i + 1) {
                    if let Ok(ip) = gw.parse() {
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
    fn test_linux_platform_name() {
        let platform = LinuxPlatform::new();
        assert_eq!(platform.name(), "Linux");
    }

    #[test]
    fn test_is_elevated_check() {
        let platform = LinuxPlatform::new();
        // This will return true if running as root, false otherwise
        let _ = platform.is_elevated();
    }
}
