//! Kill switch implementation for QuicFuscate client.
//!
//! Blocks all network traffic when VPN is not connected.

use std::sync::atomic::{AtomicBool, Ordering};

/// Kill switch manager.
pub struct KillSwitch {
    /// Whether kill switch is enabled
    enabled: AtomicBool,
    /// Whether VPN is currently connected
    vpn_connected: AtomicBool,
    /// Platform-specific implementation
    #[cfg(target_os = "linux")]
    backend: LinuxKillSwitch,
    #[cfg(target_os = "macos")]
    backend: MacOSKillSwitch,
    #[cfg(target_os = "windows")]
    backend: WindowsKillSwitch,
}

impl KillSwitch {
    /// Create a new kill switch.
    pub fn new() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            vpn_connected: AtomicBool::new(false),
            #[cfg(target_os = "linux")]
            backend: LinuxKillSwitch::new(),
            #[cfg(target_os = "macos")]
            backend: MacOSKillSwitch::new(),
            #[cfg(target_os = "windows")]
            backend: WindowsKillSwitch::new(),
        }
    }

    /// Enable the kill switch.
    pub fn enable(&self) -> Result<(), KillSwitchError> {
        self.enabled.store(true, Ordering::SeqCst);

        // If VPN is not connected, activate blocking
        if !self.vpn_connected.load(Ordering::SeqCst) {
            self.backend.block_traffic()?;
        }

        log::info!("Kill switch enabled");
        Ok(())
    }

    /// Disable the kill switch.
    pub fn disable(&self) -> Result<(), KillSwitchError> {
        self.enabled.store(false, Ordering::SeqCst);
        self.backend.allow_traffic()?;
        log::info!("Kill switch disabled");
        Ok(())
    }

    /// Check if enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::SeqCst)
    }

    /// Notify that VPN connected.
    pub fn on_vpn_connected(&self, tun_name: &str, server_ip: &str) -> Result<(), KillSwitchError> {
        self.vpn_connected.store(true, Ordering::SeqCst);

        if self.enabled.load(Ordering::SeqCst) {
            self.backend.allow_vpn_traffic(tun_name, server_ip)?;
        }

        Ok(())
    }

    /// Notify that VPN disconnected.
    pub fn on_vpn_disconnected(&self) -> Result<(), KillSwitchError> {
        self.vpn_connected.store(false, Ordering::SeqCst);

        if self.enabled.load(Ordering::SeqCst) {
            self.backend.block_traffic()?;
        }

        Ok(())
    }
}

impl Default for KillSwitch {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for KillSwitch {
    fn drop(&mut self) {
        // Always clean up on drop
        let _ = self.backend.cleanup();
    }
}

/// Kill switch errors.
#[derive(Debug)]
pub enum KillSwitchError {
    CommandFailed(String),
    PermissionDenied,
    NotSupported,
}

impl std::fmt::Display for KillSwitchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CommandFailed(s) => write!(f, "Command failed: {}", s),
            Self::PermissionDenied => write!(f, "Permission denied"),
            Self::NotSupported => write!(f, "Kill switch not supported on this platform"),
        }
    }
}

impl std::error::Error for KillSwitchError {}

// ============================================================================
// Linux Implementation (iptables)
// ============================================================================

#[cfg(target_os = "linux")]
struct LinuxKillSwitch {
    rules_active: AtomicBool,
}

#[cfg(target_os = "linux")]
impl LinuxKillSwitch {
    fn new() -> Self {
        Self { rules_active: AtomicBool::new(false) }
    }

    fn block_traffic(&self) -> Result<(), KillSwitchError> {
        use std::process::Command;

        // Block all outgoing except localhost
        let rules = [
            // Allow loopback
            ["-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
            // Block everything else
            ["-A", "OUTPUT", "-j", "DROP"],
        ];

        for rule in &rules {
            Command::new("iptables")
                .args(*rule)
                .status()
                .map_err(|e| KillSwitchError::CommandFailed(e.to_string()))?;
        }

        self.rules_active.store(true, Ordering::SeqCst);
        log::debug!("Kill switch: traffic blocked");
        Ok(())
    }

    fn allow_traffic(&self) -> Result<(), KillSwitchError> {
        self.cleanup()
    }

    fn allow_vpn_traffic(&self, tun_name: &str, server_ip: &str) -> Result<(), KillSwitchError> {
        use std::process::Command;

        // First clean up any existing rules
        self.cleanup()?;

        // Allow traffic to VPN server
        Command::new("iptables")
            .args(["-A", "OUTPUT", "-d", server_ip, "-j", "ACCEPT"])
            .status()
            .map_err(|e| KillSwitchError::CommandFailed(e.to_string()))?;

        // Allow traffic through TUN
        Command::new("iptables")
            .args(["-A", "OUTPUT", "-o", tun_name, "-j", "ACCEPT"])
            .status()
            .map_err(|e| KillSwitchError::CommandFailed(e.to_string()))?;

        // Allow loopback
        Command::new("iptables")
            .args(["-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])
            .status()
            .map_err(|e| KillSwitchError::CommandFailed(e.to_string()))?;

        // Block everything else
        Command::new("iptables")
            .args(["-A", "OUTPUT", "-j", "DROP"])
            .status()
            .map_err(|e| KillSwitchError::CommandFailed(e.to_string()))?;

        self.rules_active.store(true, Ordering::SeqCst);
        log::debug!("Kill switch: VPN traffic allowed, rest blocked");
        Ok(())
    }

    fn cleanup(&self) -> Result<(), KillSwitchError> {
        use std::process::Command;

        if !self.rules_active.load(Ordering::SeqCst) {
            return Ok(());
        }

        // Flush OUTPUT chain
        let _ = Command::new("iptables").args(["-F", "OUTPUT"]).status();

        self.rules_active.store(false, Ordering::SeqCst);
        log::debug!("Kill switch: rules cleaned up");
        Ok(())
    }
}

// ============================================================================
// macOS Implementation (pf)
// ============================================================================

#[cfg(target_os = "macos")]
struct MacOSKillSwitch {
    rules_active: AtomicBool,
    anchor_name: String,
}

#[cfg(target_os = "macos")]
impl MacOSKillSwitch {
    fn new() -> Self {
        Self {
            rules_active: AtomicBool::new(false),
            anchor_name: "com.quicfuscate.killswitch".to_string(),
        }
    }

    fn block_traffic(&self) -> Result<(), KillSwitchError> {
        use std::process::Command;

        // Create pf rules
        let rules = "block out all\npass out on lo0\n".to_string();

        // Write to temp file
        let path = "/tmp/quicfuscate_killswitch.conf";
        std::fs::write(path, rules).map_err(|e| KillSwitchError::CommandFailed(e.to_string()))?;

        // Load rules
        Command::new("pfctl")
            .args(["-a", &self.anchor_name, "-f", path])
            .status()
            .map_err(|e| KillSwitchError::CommandFailed(e.to_string()))?;

        // Enable pf
        Command::new("pfctl")
            .args(["-e"])
            .status()
            .map_err(|e| KillSwitchError::CommandFailed(e.to_string()))?;

        self.rules_active.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn allow_traffic(&self) -> Result<(), KillSwitchError> {
        self.cleanup()
    }

    fn allow_vpn_traffic(&self, tun_name: &str, server_ip: &str) -> Result<(), KillSwitchError> {
        use std::process::Command;

        let rules = format!(
            "pass out on {}\n\
             pass out to {}\n\
             pass out on lo0\n\
             block out all\n",
            tun_name, server_ip
        );

        let path = "/tmp/quicfuscate_killswitch.conf";
        std::fs::write(path, rules).map_err(|e| KillSwitchError::CommandFailed(e.to_string()))?;

        Command::new("pfctl")
            .args(["-a", &self.anchor_name, "-f", path])
            .status()
            .map_err(|e| KillSwitchError::CommandFailed(e.to_string()))?;

        self.rules_active.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn cleanup(&self) -> Result<(), KillSwitchError> {
        use std::process::Command;

        if !self.rules_active.load(Ordering::SeqCst) {
            return Ok(());
        }

        // Flush anchor
        let _ = Command::new("pfctl").args(["-a", &self.anchor_name, "-F", "all"]).status();

        self.rules_active.store(false, Ordering::SeqCst);
        Ok(())
    }
}

// ============================================================================
// Windows Implementation (Windows Firewall)
// ============================================================================

#[cfg(target_os = "windows")]
struct WindowsKillSwitch {
    rules_active: AtomicBool,
}

#[cfg(target_os = "windows")]
impl WindowsKillSwitch {
    fn new() -> Self {
        Self { rules_active: AtomicBool::new(false) }
    }

    fn block_traffic(&self) -> Result<(), KillSwitchError> {
        use std::process::Command;

        // Add blocking rule
        Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=QuicFuscate-KillSwitch-Block",
                "dir=out",
                "action=block",
            ])
            .status()
            .map_err(|e| KillSwitchError::CommandFailed(e.to_string()))?;

        self.rules_active.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn allow_traffic(&self) -> Result<(), KillSwitchError> {
        self.cleanup()
    }

    fn allow_vpn_traffic(&self, _tun_name: &str, server_ip: &str) -> Result<(), KillSwitchError> {
        use std::process::Command;

        self.cleanup()?;

        // Allow VPN server
        Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=QuicFuscate-KillSwitch-VPN",
                "dir=out",
                "action=allow",
                &format!("remoteip={}", server_ip),
            ])
            .status()
            .map_err(|e| KillSwitchError::CommandFailed(e.to_string()))?;

        // Block rest
        Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=QuicFuscate-KillSwitch-Block",
                "dir=out",
                "action=block",
            ])
            .status()
            .map_err(|e| KillSwitchError::CommandFailed(e.to_string()))?;

        self.rules_active.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn cleanup(&self) -> Result<(), KillSwitchError> {
        use std::process::Command;

        if !self.rules_active.load(Ordering::SeqCst) {
            return Ok(());
        }

        // Remove our rules
        let _ = Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                "name=QuicFuscate-KillSwitch-Block",
            ])
            .status();

        let _ = Command::new("netsh")
            .args(["advfirewall", "firewall", "delete", "rule", "name=QuicFuscate-KillSwitch-VPN"])
            .status();

        self.rules_active.store(false, Ordering::SeqCst);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kill_switch_new() {
        let ks = KillSwitch::new();
        assert!(!ks.is_enabled());
    }
}
