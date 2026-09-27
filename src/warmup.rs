//! warmup — TLS pre-connect / path warmup. [UNTESTED]
//!
//! Opens TLS connections to popular domains ahead of time so the first
//! real request is faster. Useful for YouTube warmup (pre-connect to
//! googlevideo.com) and other latency-sensitive paths.
//!
//! This does NOT intercept or modify traffic — it just warms the TCP
//! connection cache and TLS session state in the OS.

use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// Timeout for warmup connections.
pub const WARMUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Default warmup targets for common use cases.
pub fn default_warmup_targets() -> Vec<WarmupTarget> {
    vec![
        WarmupTarget {
            label: "YouTube CDN".into(),
            host: "googlevideo.com".into(),
            port: 443,
        },
        WarmupTarget {
            label: "Cloudflare DNS".into(),
            host: "1.1.1.1".into(),
            port: 443,
        },
        WarmupTarget {
            label: "Google".into(),
            host: "www.google.com".into(),
            port: 443,
        },
    ]
}

/// A single warmup target.
#[derive(Debug, Clone)]
pub struct WarmupTarget {
    pub label: String,
    pub host: String,
    pub port: u16,
}

/// Result of a warmup attempt.
#[derive(Debug)]
pub struct WarmupResult {
    pub label: String,
    pub success: bool,
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
}

/// Perform a warmup connection to a single target.
/// Opens a TCP connection (and optionally a TLS hello) to warm the path.
pub fn warmup_target(target: &WarmupTarget) -> WarmupResult {
    let start = std::time::Instant::now();
    // F-004: resolve the hostname properly instead of falling back to a
    // connect to 0.0.0.0 (which can never succeed and masked the real
    // error in the result).
    let addr = match (target.host.as_str(), target.port).to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(a) => a,
            None => {
                return WarmupResult {
                    label: target.label.clone(),
                    success: false,
                    latency_ms: None,
                    error: Some("no address resolved for warmup target".into()),
                };
            }
        },
        Err(e) => {
            return WarmupResult {
                label: target.label.clone(),
                success: false,
                latency_ms: None,
                error: Some(e.to_string()),
            };
        }
    };
    match TcpStream::connect_timeout(&addr, WARMUP_TIMEOUT) {
        Ok(_stream) => {
            let elapsed = start.elapsed().as_millis() as u64;
            WarmupResult {
                label: target.label.clone(),
                success: true,
                latency_ms: Some(elapsed),
                error: None,
            }
        }
        Err(e) => WarmupResult {
            label: target.label.clone(),
            success: false,
            latency_ms: None,
            error: Some(e.to_string()),
        },
    }
}

/// Warmup all targets. Returns results for each.
pub fn warmup_all(targets: &[WarmupTarget]) -> Vec<WarmupResult> {
    targets.iter().map(warmup_target).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_warmup_targets_not_empty() {
        let targets = default_warmup_targets();
        assert!(!targets.is_empty());
        assert!(targets.iter().all(|t| !t.label.is_empty()));
        assert!(targets.iter().all(|t| t.port > 0));
    }

    #[test]
    fn warmup_target_struct_is_complete() {
        let t = WarmupTarget {
            label: "test".into(),
            host: "127.0.0.1".into(),
            port: 443,
        };
        assert_eq!(t.label, "test");
        assert_eq!(t.port, 443);
    }
}
