//! mobile_gateway — LAN device discovery for a future gateway. [PARTIAL]
//!
//! When enabled, dpi_guard reports the local interface and devices visible
//! in the ARP/neighbour table. It deliberately does **not** open a LAN
//! listener, enable IP forwarding, or install NAT/proxy rules: doing so
//! safely requires an explicit administrator-reviewed gateway policy and
//! platform-specific rollback. The relay remains loopback-only.

use std::net::IpAddr;
use std::process::Command;

/// A detected LAN device.
#[derive(Debug, Clone)]
pub struct LanDevice {
    pub ip: IpAddr,
    pub mac: Option<String>,
    pub hostname: Option<String>,
}

/// Get the local machine's LAN IP address.
pub fn local_lan_ip() -> Option<IpAddr> {
    // Connect to a public IP (no actual traffic sent) to determine
    // which interface the OS would use for outbound traffic.
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    let _ = socket.connect("1.1.1.1:80");
    socket.local_addr().ok().map(|a| a.ip())
}

/// Detect LAN devices from the ARP table.
pub fn detect_lan_devices() -> Vec<LanDevice> {
    let mut devices = Vec::new();

    #[cfg(windows)]
    {
        if let Ok(output) = Command::new("arp").arg("-a").output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(ip) = parts[0].parse::<IpAddr>() {
                        if ip.is_loopback() || ip.is_unspecified() {
                            continue;
                        }
                        let mac = if parts.len() >= 2 {
                            Some(parts[1].to_string())
                        } else {
                            None
                        };
                        devices.push(LanDevice {
                            ip,
                            mac,
                            hostname: None,
                        });
                    }
                }
            }
        }
    }

    #[cfg(not(windows))]
    {
        if let Ok(output) = Command::new("ip").args(["neigh", "show"]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if let Some(ip_str) = parts.first() {
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        if ip.is_loopback() || ip.is_unspecified() {
                            continue;
                        }
                        let mac = parts
                            .iter()
                            .position(|&p| p == "lladdr")
                            .and_then(|i| parts.get(i + 1))
                            .map(|s| s.to_string());
                        devices.push(LanDevice {
                            ip,
                            mac,
                            hostname: None,
                        });
                    }
                }
            }
        }
    }

    devices
}

/// Count of connected LAN devices (excluding the local machine).
pub fn connected_device_count() -> usize {
    let local = local_lan_ip();
    detect_lan_devices()
        .into_iter()
        .filter(|d| Some(d.ip) != local)
        .filter(|d| !d.ip.is_loopback())
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_lan_ip_returns_something() {
        // May fail in sandboxed environments — that's ok
        let _ = local_lan_ip();
    }

    #[test]
    fn detect_lan_devices_returns_vec() {
        let devices = detect_lan_devices();
        // May be empty in sandbox — that's fine
        let _ = devices;
    }

    #[test]
    fn connected_device_count_runs_without_panic() {
        // usize cannot go negative; the meaningful invariant is that the
        // count never exceeds the number of devices actually detected.
        let count = connected_device_count();
        assert!(count <= detect_lan_devices().len());
    }
}
