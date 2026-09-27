//! client_detect — auto-detect running proxy clients. [UNTESTED]
//!
//! Scans for known processes (v2rayN, Xray, sing-box) and optionally
//! patches their configuration to point at the dpi_guard relay.

use std::process::Command;

/// Known proxy client processes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyClient {
    V2rayN,
    V2ray,
    Xray,
    SingBox,
    Clash,
}

impl ProxyClient {
    pub fn process_names(&self) -> &[&str] {
        match self {
            ProxyClient::V2rayN => &["v2rayN.exe", "v2rayN"],
            ProxyClient::V2ray => &["v2ray.exe", "v2ray"],
            ProxyClient::Xray => &["xray.exe", "xray"],
            ProxyClient::SingBox => &["sing-box.exe", "sing-box"],
            ProxyClient::Clash => &["clash.exe", "clash", "clash-verge.exe"],
        }
    }

    /// Default SOCKS port for this client.
    pub fn default_socks_port(&self) -> u16 {
        match self {
            ProxyClient::V2rayN | ProxyClient::V2ray | ProxyClient::Xray => 10808,
            ProxyClient::SingBox => 2080,
            ProxyClient::Clash => 7890,
        }
    }
}

/// Detection result.
#[derive(Debug, Clone)]
pub struct DetectionResult {
    pub client: ProxyClient,
    pub pid: Option<u32>,
    pub running: bool,
}

/// Check if a process with the given name is running.
/// Returns Some(pid) if found, None otherwise.
pub fn find_process(name: &str) -> Option<u32> {
    #[cfg(windows)]
    {
        let output = Command::new("tasklist")
            .args(&["/FI", &format!("IMAGENAME eq {name}"), "/FO", "CSV", "/NH"])
            .output()
            .ok()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Parse CSV: "name.exe","pid","session","session#","mem"
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split('"').collect();
            if parts.len() >= 4 {
                if let Ok(pid) = parts[3].parse::<u32>() {
                    return Some(pid);
                }
            }
        }
        None
    }
    #[cfg(not(windows))]
    {
        let output = Command::new("pgrep").args(["-f", name]).output().ok()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout.lines().next()?.trim().parse().ok()
    }
}

/// Scan for all known proxy clients and return which are running.
pub fn detect_all() -> Vec<DetectionResult> {
    let clients = [
        ProxyClient::V2rayN,
        ProxyClient::V2ray,
        ProxyClient::Xray,
        ProxyClient::SingBox,
        ProxyClient::Clash,
    ];

    let mut results = Vec::new();
    for client in &clients {
        let mut found = DetectionResult {
            client: *client,
            pid: None,
            running: false,
        };
        for name in client.process_names() {
            if let Some(pid) = find_process(name) {
                found.pid = Some(pid);
                found.running = true;
                break;
            }
        }
        results.push(found);
    }
    results
}

/// Check if any proxy client is running.
pub fn any_running() -> bool {
    detect_all().iter().any(|d| d.running)
}

/// Get the first running proxy client, if any.
pub fn first_running() -> Option<DetectionResult> {
    detect_all().into_iter().find(|d| d.running)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_names_not_empty() {
        for client in [
            ProxyClient::V2rayN,
            ProxyClient::V2ray,
            ProxyClient::Xray,
            ProxyClient::SingBox,
            ProxyClient::Clash,
        ] {
            assert!(!client.process_names().is_empty());
        }
    }

    #[test]
    fn default_socks_ports_reasonable() {
        assert_eq!(ProxyClient::V2rayN.default_socks_port(), 10808);
        assert_eq!(ProxyClient::Xray.default_socks_port(), 10808);
        assert_eq!(ProxyClient::SingBox.default_socks_port(), 2080);
        assert_eq!(ProxyClient::Clash.default_socks_port(), 7890);
    }

    #[test]
    fn detect_all_returns_results_for_all_clients() {
        let results = detect_all();
        assert_eq!(results.len(), 5);
    }

    #[test]
    fn any_running_returns_boolean() {
        let _ = any_running();
    }

    #[test]
    fn first_running_matches_any_running() {
        let any = any_running();
        let first = first_running();
        assert_eq!(any, first.is_some());
    }
}
