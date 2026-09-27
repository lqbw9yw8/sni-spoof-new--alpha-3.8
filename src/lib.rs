//! dpi_guard
//!
//! Modular DPI-evasion engine. Pure-logic modules build and test on any
//! OS. Packet capture/injection needs Windows + WinDivert and only
//! compiles on `cfg(windows)`.
//!
//! STATUS LEGEND used in doc comments (these are labels, not current test
//! results):
//!   `DONE`    - implemented and unit tested in a verified build.
//!   `PARTIAL` - implemented, with documented limits.
//!   `STUB`    - compiles, returns a typed error, needs Windows/WFP FFI.
//!   `UNTESTED` - implementation present; current tests were not executed.
//! # dpi_guard
//!
//! A patterniha-style local SNI-spoofing relay and DPI-evasion engine.
//! There is no Xray/v2ray/sing-box core here and no VPN: the destination IP
//! is still visible on the wire (that is inherent to this class of tool).
//! Packet capture/injection is Windows-only (WinDivert); all pure-logic
//! modules build and unit-test on Linux/macOS/CI.
//!
//! `#![deny(unsafe_code)]` applies crate-wide. The FFI boundary is confined
//! to `engine.rs` (WinDivert), `dns_guard.rs` (WFP), and `singleton.rs`
//! (`flock`/`CreateFileW`).
#![deny(unsafe_code)]

pub mod autottl;
pub mod config;
pub mod connection;
pub mod dns_cache;
pub mod dns_guard;
pub mod doh;
pub mod ech;
pub mod error;
pub mod fail_open;
pub mod fooling;
pub mod fragmentation;
pub mod geedge;
pub mod handle_retire;
pub mod hpke;
pub mod http_host;
pub mod integrity;
pub mod native_gui;
pub mod netguard;
pub mod observability;
pub mod packet;
pub mod pipeline;
pub mod quic;
pub mod relay;
pub mod sequence;
pub mod singleton;
pub mod sni_mutations;
pub mod stealth;
pub mod strategy;
pub mod utls;
pub mod webui;
// ── 25 new feature modules (2026 upgrade) ──
pub mod anti_fingerprint;
pub mod client_detect;
pub mod isp_profiles;
pub mod mobile_gateway;
pub mod proxy_cleanup;
pub mod scanner;
pub mod self_update;
pub mod warmup;

#[cfg(windows)]
pub mod engine;
#[cfg(not(windows))]
pub mod engine_stub;
#[cfg(not(windows))]
pub use engine_stub as engine;

pub use error::DpiGuardError;

/// The compiled-in WinDivert filter diverts **all** TCP and UDP ports in
/// both directions, excludes loopback, and never touches SSH (22), DNS (53),
/// or RDP (3389). Windows' separate WFP guard handles outbound plaintext DNS;
/// this filter only controls packet diversion. This matches the "all ports
/// minus never-touch" default the operator expects from a patterniha-style
/// relay; narrow it down via
/// `intercept_ports` in `dpi_guard.toml` if needed.
pub const DEFAULT_FILTER: &str = "!loopback and (\
     (tcp and tcp.DstPort != 22 and tcp.SrcPort != 22 and tcp.DstPort != 53 and tcp.SrcPort != 53 and tcp.DstPort != 3389 and tcp.SrcPort != 3389) \
     or \
     (udp and udp.DstPort != 22 and udp.SrcPort != 22 and udp.DstPort != 53 and udp.SrcPort != 53 and udp.DstPort != 3389 and udp.SrcPort != 3389)\
 )";

/// Build the WinDivert filter from settings. Both protocols are always
/// written out (never a bare `tcp or udp`). By default (when
/// `intercept_all_tcp`/`intercept_all_udp` are true, as in `Default`), the
/// filter covers every port except the never-intercept set (SSH 22, DNS 53,
/// RDP 3389) so "all ports" cannot cut the operator's own remote access or
/// plaintext DNS. Setting both wildcards to false falls back to the
/// explicit `intercept_ports` list.
///
/// When relay mode is on, the relay's destination port is guaranteed to be
/// in the filter (to observe the handshake for fake-SNI injection).
pub fn build_filter(settings: &config::Settings) -> String {
    // The explicit list is only consumed by the *non*-wildcard clause, and
    // `tcp_clause`/`udp_clause` each ignore it when their own wildcard is
    // on. So it must be built whenever *either* protocol still needs it —
    // testing `||` here used to blank the list for the non-wildcard side
    // too, which compiled that clause down to `false` and silently dropped
    // all traffic for that protocol.
    let mut ports = if settings.intercept_all_tcp && settings.intercept_all_udp {
        Vec::new()
    } else {
        settings.explicit_port_list()
    };
    if settings.relay_enabled {
        ports.push(settings.relay_connect_port);
        ports.retain(|p| !config::NEVER_INTERCEPT_PORTS.contains(p));
        ports.sort_unstable();
        ports.dedup();
    }
    let tcp = tcp_clause(settings, &ports);
    let udp = udp_clause(settings, &ports);
    format!("!loopback and ({tcp} or {udp})")
}

/// Exclusions expressed per protocol: in WinDivert a protocol field read
/// against the wrong transport is meaningless, so each clause is guarded
/// by `{proto} and ...`.
fn never_clause(proto: &str) -> String {
    config::NEVER_INTERCEPT_PORTS
        .iter()
        .map(|p| format!("{proto}.DstPort != {p} and {proto}.SrcPort != {p}"))
        .collect::<Vec<String>>()
        .join(" and ")
}

fn tcp_clause(settings: &config::Settings, ports: &[u16]) -> String {
    if settings.intercept_all_tcp {
        return format!("(tcp and {})", never_clause("tcp"));
    }
    if ports.is_empty() {
        // Every configured port was a never-intercept port.
        return "false".to_string();
    }
    let conds = ports
        .iter()
        .map(|p| format!("tcp.DstPort == {p} or tcp.SrcPort == {p}"))
        .collect::<Vec<String>>()
        .join(" or ");
    format!("(tcp and ({conds}))")
}

fn udp_clause(settings: &config::Settings, ports: &[u16]) -> String {
    if settings.intercept_all_udp {
        return format!("(udp and {})", never_clause("udp"));
    }
    if ports.is_empty() {
        return "false".to_string();
    }
    let conds = ports
        .iter()
        .map(|p| format!("udp.DstPort == {p} or udp.SrcPort == {p}"))
        .collect::<Vec<String>>()
        .join(" or ");
    format!("(udp and ({conds}))")
}

/// `RUST_LOG` controls verbosity; default `dpi_guard=info`.
pub fn init_logging() {
    let _ = env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("dpi_guard=info"),
    )
    .is_test(false)
    .try_init();
    if let Err(e) = observability::init() {
        log::warn!("bounded JSON-lines observability log unavailable: {e}");
    }
}

/// Recover a `Mutex` after a panic in another thread. Poisoning must not
/// take the packet path down — fail-open prefers a possibly-stale
/// pipeline over black-holing every subsequent packet.
pub fn recover_mutex<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match m.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_filter_is_all_ports_minus_never() {
        // Default intercept_all_tcp/intercept_all_udp are true -> every port
        // except 22/53/3389, both protocols, both directions.
        let s = config::Settings::default();
        assert!(s.intercept_all_tcp);
        assert!(s.intercept_all_udp);
        let f = build_filter(&s);
        assert!(f.contains("!loopback"));
        assert!(f.contains("(tcp and"));
        assert!(f.contains("(udp and"));
        for p in config::NEVER_INTERCEPT_PORTS {
            assert!(f.contains(&format!("tcp.DstPort != {p}")));
            assert!(f.contains(&format!("tcp.SrcPort != {p}")));
            assert!(f.contains(&format!("udp.DstPort != {p}")));
            assert!(f.contains(&format!("udp.SrcPort != {p}")));
        }
        // It must not hard-code 443 any more.
        assert!(!f.contains("tcp.DstPort == 443"));
    }

    #[test]
    fn all_ports_filter_excludes_never_ports() {
        let s = config::Settings::default();
        let f = build_filter(&s);
        for p in config::NEVER_INTERCEPT_PORTS {
            assert!(f.contains(&format!("tcp.DstPort != {p}")));
            assert!(f.contains(&format!("udp.SrcPort != {p}")));
        }
    }

    #[test]
    fn explicit_ports_used_when_wildcards_off() {
        let s = config::Settings {
            intercept_all_tcp: false,
            intercept_all_udp: false,
            intercept_ports: vec![443, 8443, 53],
            ..config::Settings::default()
        };
        let f = build_filter(&s);
        assert!(f.contains("tcp.DstPort == 443"));
        assert!(f.contains("tcp.DstPort == 8443"));
        // never ports dropped from the explicit list
        assert!(!f.contains("tcp.DstPort == 53"));
    }

    #[test]
    fn relay_port_included_when_relay_enabled() {
        let s = config::Settings {
            intercept_all_tcp: false,
            intercept_all_udp: false,
            intercept_ports: vec![443],
            relay_enabled: true,
            relay_connect_port: 8443,
            ..config::Settings::default()
        };
        let f = build_filter(&s);
        assert!(f.contains("tcp.DstPort == 8443"));
    }

    #[test]
    fn custom_ports_filter_contains_all() {
        let s = config::Settings {
            intercept_all_tcp: false,
            intercept_all_udp: false,
            intercept_ports: vec![443, 8443, 8080],
            ..config::Settings::default()
        };
        let f = build_filter(&s);
        assert!(f.contains("443"));
        assert!(f.contains("8443"));
        assert!(f.contains("8080"));
    }

    /// Regression: one wildcard on must not blank the explicit port list
    /// that the *other* protocol's clause still depends on. Before the fix
    /// `build_filter` tested `intercept_all_tcp || intercept_all_udp`, so
    /// the UDP clause collapsed to `false` and every QUIC packet escaped
    /// the filter even though the operator had listed port 443.
    #[test]
    fn one_wildcard_keeps_explicit_ports_for_the_other_protocol() {
        let s = config::Settings {
            intercept_all_tcp: true,
            intercept_all_udp: false,
            intercept_ports: vec![443, 8443],
            ..config::Settings::default()
        };
        let f = build_filter(&s);
        // TCP side is the wildcard-minus-never form.
        assert!(f.contains("(tcp and"));
        assert!(f.contains("tcp.DstPort != 22"));
        // UDP side must be the explicit list, not the dead `false` clause.
        assert!(f.contains("udp.DstPort == 443"), "filter was: {f}");
        assert!(f.contains("udp.DstPort == 8443"), "filter was: {f}");
        assert!(!f.contains("(udp and (false"), "filter was: {f}");

        // Mirror case: UDP wildcard on, TCP explicit.
        let s2 = config::Settings {
            intercept_all_tcp: false,
            intercept_all_udp: true,
            intercept_ports: vec![8443],
            ..config::Settings::default()
        };
        let f2 = build_filter(&s2);
        assert!(f2.contains("tcp.DstPort == 8443"), "filter was: {f2}");
        assert!(f2.contains("udp.DstPort != 22"), "filter was: {f2}");
    }

    /// Both wildcards on is the documented "all ports" default and is the
    /// only case where the explicit list is genuinely unused.
    #[test]
    fn both_wildcards_ignore_the_explicit_list() {
        let s = config::Settings {
            intercept_ports: vec![8443],
            ..config::Settings::default()
        };
        let f = build_filter(&s);
        assert!(!f.contains("== 8443"));
    }
}
