//! config — TOML settings + mtime hot-reload. [UNTESTED]
//! `HotReloadWatcher::new` snapshots the current mtime so the first
//! `reload_if_changed` is a no-op unless the file actually changes.

use crate::error::DpiGuardError;
use crate::sni_mutations::MutationProfile;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::SystemTime;

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    #[serde(default = "default_profile")]
    pub mutation_profile: String,
    #[serde(default = "default_ttl")]
    pub decoy_ttl: u8,
    #[serde(default = "default_idle_secs")]
    pub idle_timeout_secs: u64,
    /// Legacy DNS redirect target. It is retained only so old configuration
    /// files can be diagnosed and removed without an unknown-key error.
    ///
    /// A user-mode WFP filter can block plaintext DNS, but redirecting it to
    /// this address requires a signed kernel callout that is not shipped by
    /// this project. Non-empty values are therefore rejected fail-closed;
    /// `None` is the only supported value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_dns: Option<String>,
    /// 0 = do not TCP-segment ClientHello. Default 64 (never 1).
    #[serde(default = "default_fragment_chunk")]
    pub fragment_chunk_size: usize,
    #[serde(default = "default_true")]
    pub enable_decoys: bool,
    #[serde(default = "default_true")]
    pub enable_sni_fragmentation: bool,
    #[serde(default)]
    pub enable_swap_foolers: bool,
    #[serde(default)]
    pub enable_kill_switch: bool,
    #[serde(default)]
    pub kill_switch_adapter: String,
    /// Optional relay-mode destination rotation. Each new local relay
    /// connection selects the next validated IP; transparent WinDivert flows
    /// keep their established destination and are never rewritten mid-flow.
    #[serde(default)]
    pub rotate_ips: Vec<String>,
    #[serde(default)]
    pub win_divert_sha256: Vec<String>,
    #[serde(default)]
    pub enable_web_ui: bool,
    #[serde(default = "default_web_ui_port")]
    pub web_ui_port: u16,
    #[serde(default)]
    pub web_ui_token: String,
    // --- 2025-2026 extensions ---
    #[serde(default)]
    pub enable_quic_port_bypass: bool,
    #[serde(default)]
    pub quic_bypass_use_low_port: bool,
    #[serde(default)]
    pub enable_sni_disguise: bool,
    #[serde(default)]
    pub fronting_benign_sni: String,
    #[serde(default = "default_true")]
    pub enable_combined_fragmentation: bool,
    // --- ALL PORTS upgrade ---
    /// List of TCP/UDP ports to intercept. Empty = default [443].
    /// Example: [443, 8443, 2053, 2083, 2087, 2096, 8080, 80]
    #[serde(default)]
    pub intercept_ports: Vec<u16>,
    /// If true, intercept ALL TCP ports except NEVER_INTERCEPT. Default true
    /// (same as [`Settings::default`] and `dpi_guard.toml.example`).
    #[serde(default = "default_true")]
    pub intercept_all_tcp: bool,
    /// If true, intercept ALL UDP ports except NEVER_INTERCEPT. Default true.
    #[serde(default = "default_true")]
    pub intercept_all_udp: bool,
    /// Enable uTLS/JA3/JA4 fingerprint rotation (browser profile)
    #[serde(default)]
    pub enable_utls_fingerprint: bool,
    /// Browser to mimic: chrome, firefox, safari, edge, random
    #[serde(default = "default_browser")]
    pub utls_browser: String,
    /// Enable ECH (Encrypted Client Hello) GREASE and outer SNI
    #[serde(default)]
    pub enable_ech_grease: bool,
    /// Enable MD5SIG fooling (adds TCP option 19) - breaks some servers, only for zapret-style evasion
    #[serde(default)]
    pub enable_md5sig_fooling: bool,
    /// Enable Geedge-style evasion: extra padding, SNI with IP literal, etc.
    #[serde(default = "default_true")]
    pub enable_geedge_evasion: bool,
    // --- Relay mode (patterniha-style local relay) ---
    /// Bind 127.0.0.1:<relay_listen_port> and relay to a fixed destination.
    #[serde(default)]
    pub relay_enabled: bool,
    /// Local port v2rayN connects to (default 40443).
    #[serde(default = "default_relay_listen_port")]
    pub relay_listen_port: u16,
    /// Real destination host (domain or IP literal). Domain = resolved via DoH.
    #[serde(default)]
    pub relay_connect_host: String,
    /// Real destination port (default 443).
    #[serde(default = "default_relay_connect_port")]
    pub relay_connect_port: u16,
    /// Benign SNI shown to the DPI in the injected fake ClientHello.
    #[serde(default)]
    pub relay_fake_sni: String,
    /// Resolve `relay_connect_host` via DoH (no plaintext DNS). IP literals
    /// skip DNS entirely.
    #[serde(default = "default_true")]
    pub relay_resolve_doh: bool,
    /// After the fake handshake, also run the relay flow's real ClientHello
    /// through the normal SNI-mutation pipeline (item 1).
    #[serde(default)]
    pub relay_mutate_real_sni: bool,
    /// At injection time, also emit a TTL-limited wrong-checksum decoy of the
    /// fake ClientHello (item 2).
    #[serde(default)]
    pub relay_emit_decoy: bool,
    /// DoH endpoint URL.
    #[serde(default = "default_doh_url")]
    pub doh_server: String,

    // --- 2026 hardening: filter lists, TLS/HTTP desync knobs, fail-closed relay ---
    /// If non-empty, SNI evasion / fake injection applies ONLY to SNIs that
    /// match one of these patterns (exact or `*.example.com`).
    #[serde(default)]
    pub sni_only: Vec<String>,
    /// SNIs that must never be mutated / relayed through the fake injection
    /// (exact or `*.example.com`). Deny wins over allow.
    #[serde(default)]
    pub sni_except: Vec<String>,
    /// Split ClientHello into multiple 0x16 TLS records.
    /// Wired in `pipeline::apply_client_hello`: re-frames the ClientHello as
    /// a run of valid 0x16 records instead of cutting the TCP payload at
    /// arbitrary byte offsets.
    ///
    /// Defaults to **false**. It used to default to true while doing nothing
    /// at all; now that it is wired, leaving it true would silently swap the
    /// wire format every TLS flow has always used for a different one that
    /// has never been tested against a real DPI. Opt in explicitly.
    #[serde(default)]
    pub enable_tls_record_fragmentation: bool,
    /// Max bytes per fragmented TLS record (0 = use fragment_chunk_size).
    /// Wired in `pipeline::apply_client_hello`. 0 falls back to
    /// `fragment_chunk_size`.
    #[serde(default)]
    pub tls_record_chunk_size: usize,
    /// Split a TLS record immediately before the SNI name.
    /// Wired in `pipeline::apply_client_hello`: places the TLS-record
    /// boundary immediately before the SNI name.
    #[serde(default)]
    pub enable_frag_by_sni: bool,
    /// Learn decoy TTL from the inbound hop count to this host.
    #[serde(default)]
    pub enable_autottl: bool,
    /// Delta added to the learned TTL (-32..=32).
    /// Positive = reach one hop further, negative = die earlier.
    #[serde(default)]
    pub autottl_delta: i8,
    /// Apply the HTTP `Host:`-line split trick to plaintext HTTP flows.
    #[serde(default)]
    pub enable_http_host_tricks: bool,
    /// Pick a desync mode per-flow from strategy scores (tls-record /
    /// frag-by-sni / disorder / decoy).
    /// Wired in `pipeline::apply_client_hello`: when on, the desync mode is
    /// chosen per domain from the learned strategy scores
    /// (`strategy::DesyncMode`) instead of the fixed flags alone.
    #[serde(default)]
    pub enable_adaptive_desync: bool,
    // --- 2026 roadmap upgrades (NestedCloak era) ---
    /// Split the ClientHello's TLS record *inside* the SNI name (the name
    /// straddles the record boundary) instead of before it. Roadmap #1.
    #[serde(default)]
    pub enable_frag_mid_sni: bool,
    /// Inflate the ClientHello with a random-length TLS padding extension
    /// (RFC 7685) per connection, breaking fixed-size fingerprints and
    /// offset-based SNI extractors. Roadmap #2.
    #[serde(default)]
    pub enable_padding_inflation: bool,
    /// Per-connection strategy rotation + escalation (roadmap #4 + #6):
    /// weighted-random pick among techniques that already scored positively
    /// for a domain, and ladder-climb when the configured profile scores
    /// negative. Off = the previous deterministic selection.
    #[serde(default)]
    pub enable_strategy_rotation: bool,
    /// Real ECH (roadmap #5): seal the real SNI inside an inner
    /// ClientHello (HPKE: X25519 + HKDF-SHA256 + ChaCha20Poly1305); the
    /// outer hello shows the ECHConfig's `public_name`. Requires
    /// `real_ech_config_hex`; the destination server must support ECH.
    #[serde(default)]
    pub enable_real_ech: bool,
    /// Hex of the ECHConfigList — the `ech` SvcParamValue of the target's
    /// DNS HTTPS record (e.g. from `dig HTTPS example.com`). Only read when
    /// `enable_real_ech = true`.
    #[serde(default)]
    pub real_ech_config_hex: String,
    /// Fail-closed: if the fake ClientHello is not ACKed (injection not
    /// confirmed) within the wait window, the relay drops the connection so
    /// the real ClientHello is never sent. Default true.
    #[serde(default = "default_true")]
    pub relay_require_inject: bool,

    // ─── 25 new features (2026 upgrade) ────────────────────────────
    // #1 #2 — Scanner / Edge ranker
    /// main.rs probes the candidate pool with REAL TLS handshakes at
    /// startup (probe_and_rank_spoof_pairs) and the dashboard exposes the
    /// same probe via /api/scanner/probe; results are ranked by RTT.
    #[serde(default)]
    pub enable_sni_scanner: bool,
    #[serde(default)]
    pub sni_candidates: Vec<String>,
    #[serde(default)]
    pub edge_candidates: Vec<String>,
    /// ISP profile: mci, irancell, auto, russia, china, generic
    #[serde(default = "default_isp_profile")]
    pub isp_profile: String,
    /// #4 — SNI pool rotation: round_robin, weighted_random, lru
    #[serde(default = "default_rotation_mode")]
    pub sni_rotation_mode: String,
    /// #5-7 — Anti-fingerprint
    #[serde(default)]
    pub enable_anti_fingerprint: bool,
    #[serde(default = "default_delay_min")]
    pub injection_delay_min_ms: u64,
    #[serde(default = "default_delay_max")]
    pub injection_delay_max_ms: u64,
    #[serde(default = "default_max_padding")]
    pub max_packet_padding: usize,
    #[serde(default)]
    pub randomize_ip_id: bool,
    #[serde(default)]
    pub randomize_packet_size: bool,
    /// #8 — Fake-with-SNI (realistic browser-mimic ClientHello)
    #[serde(default)]
    pub enable_fake_with_sni: bool,
    #[serde(default = "default_fake_browser")]
    pub fake_browser: String,
    /// #11 — Reverse fragmentation (GoodbyeDPI / zapret)
    #[serde(default)]
    pub enable_reverse_frag: bool,
    /// Wired in `pipeline::build_decoy` and the relay fake-SNI path.
    /// Defaults to TRUE because that is what the wire has always done: a
    /// decoy that carries a valid checksum and an in-window sequence number
    /// is a real packet, not a decoy. Turn it off only if you want that.
    #[serde(default = "default_true")]
    pub enable_wrong_seq: bool,
    /// See `enable_wrong_seq`.
    #[serde(default = "default_true")]
    pub enable_wrong_checksum: bool,
    /// #12 — OOB data injection (zapret)
    #[serde(default)]
    pub enable_oob_injection: bool,
    /// #13 — Host dot (zapret — dot after hostname in HTTP Host)
    #[serde(default)]
    pub enable_hostdot: bool,
    /// #14 — Max payload cap (skip large payloads)
    #[serde(default = "default_max_payload")]
    pub max_payload_size: usize,
    /// #15 — Fake resend count
    #[serde(default = "default_fake_resend")]
    pub fake_resend_count: u32,
    /// #16 — Self-update
    /// Wired in main.rs: one GitHub-release API query at startup, logged.
    /// It never downloads or replaces the binary.
    #[serde(default)]
    pub enable_self_update: bool,
    /// `owner/repo` used by the update check.
    #[serde(default = "default_update_repo")]
    pub update_repo: String,
    /// #17 — Auto-detect proxy clients (v2rayN, Xray, sing-box)
    /// Wired in main.rs: logs the known proxy clients that are running and
    /// warns when their default ports collide with ours.
    #[serde(default)]
    pub enable_client_detect: bool,
    /// #19 — Graceful proxy cleanup on exit
    #[serde(default = "default_true")]
    pub enable_proxy_cleanup: bool,
    /// #20 — YouTube warmup (pre-connect)
    /// Wired in main.rs: warms the YouTube endpoints on a startup thread.
    #[serde(default)]
    pub enable_youtube_warmup: bool,
    /// #22 — Mobile gateway (LAN sharing)
    /// PARTIAL (audit F-003): main.rs reports the LAN interface and device
    /// count, but the relay still binds 127.0.0.1 only — no LAN listener.
    #[serde(default)]
    pub enable_mobile_gateway: bool,
    /// #25 — ipset/hostname filtering (zapret-style)
    #[serde(default)]
    pub ipset_hostlist: Vec<String>,
    /// AutoTTL scale (GoodbyeDPI: a1-a2-m)
    /// Wired in `pipeline::autottl_ttl_for`. a1 == 0 (the default) keeps the
    /// plain learn-and-reuse behaviour; any other value switches to
    /// `autottl::suggest_ttl_scaled`.
    #[serde(default)]
    pub autottl_scale_a1: u8,
    #[serde(default = "default_autottl_a2")]
    pub autottl_scale_a2: u8,
    #[serde(default = "default_autottl_m")]
    pub autottl_scale_max: u8,
}

/// Maximum accepted size of a `dpi_guard.toml` file. A larger config is
/// rejected outright (resource-exhaustion / disk-filling defence).
pub const MAX_CONFIG_BYTES: usize = 256 * 1024;

/// Ports never intercepted, even by the `intercept_all_tcp` /
/// `intercept_all_udp` wildcards: SSH (22), DNS (53), RDP (3389). Diverting
/// these would cut the operator's own remote access or plaintext DNS — the
/// exact leaks this tool is meant to avoid.
pub const NEVER_INTERCEPT_PORTS: [u16; 3] = [22, 53, 3389];

/// Well-known **local inbound** ports used by v2rayN / v2ray / Xray clients
/// (SOCKS 10808, HTTP 10809, DNS 10853). Nothing here refuses them — the
/// relay is allowed to listen anywhere — but binding the relay on one of
/// them means one of the two programs fails to start, and the failure looks
/// like a dpi_guard bug rather than a port clash. `Settings::validate`
/// warns so the operator sees the real cause.
pub const KNOWN_V2RAY_LOCAL_PORTS: [u16; 3] = [10808, 10809, 10853];

fn default_profile() -> String {
    "Stealth".to_string()
}
fn default_ttl() -> u8 {
    8
}
fn default_idle_secs() -> u64 {
    120
}
fn default_fragment_chunk() -> usize {
    64
}
fn default_web_ui_port() -> u16 {
    9090
}
fn default_true() -> bool {
    true
}
fn default_browser() -> String {
    "chrome".to_string()
}
fn default_relay_listen_port() -> u16 {
    40443
}
fn default_relay_connect_port() -> u16 {
    443
}
fn default_doh_url() -> String {
    crate::doh::DEFAULT_DOH_URL.to_string()
}
fn default_isp_profile() -> String {
    "auto".to_string()
}
fn default_rotation_mode() -> String {
    "round_robin".to_string()
}
fn default_delay_min() -> u64 {
    1
}
fn default_delay_max() -> u64 {
    10
}
fn default_max_padding() -> usize {
    0
}
fn default_fake_browser() -> String {
    "firefox".to_string()
}
fn default_max_payload() -> usize {
    1200
}
fn default_fake_resend() -> u32 {
    1
}
fn default_update_repo() -> String {
    crate::self_update::DEFAULT_UPDATE_REPO.to_string()
}
fn default_autottl_a2() -> u8 {
    4
}
fn default_autottl_m() -> u8 {
    10
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            mutation_profile: default_profile(),
            decoy_ttl: default_ttl(),
            idle_timeout_secs: default_idle_secs(),
            trusted_dns: None,
            fragment_chunk_size: default_fragment_chunk(),
            enable_decoys: true,
            enable_sni_fragmentation: true,
            enable_swap_foolers: false,
            enable_kill_switch: false,
            kill_switch_adapter: String::new(),
            rotate_ips: Vec::new(),
            win_divert_sha256: Vec::new(),
            enable_web_ui: false,
            web_ui_port: default_web_ui_port(),
            web_ui_token: String::new(),
            enable_quic_port_bypass: false,
            quic_bypass_use_low_port: false,
            enable_sni_disguise: false,
            fronting_benign_sni: String::new(),
            enable_combined_fragmentation: true,
            intercept_ports: Vec::new(),
            // Default: intercept ALL TCP/UDP ports except the never-touch
            // set (22/53/3389). This is the patterniha-style "all ports"
            // default; narrow via intercept_ports if needed.
            intercept_all_tcp: true,
            intercept_all_udp: true,
            enable_utls_fingerprint: false,
            utls_browser: default_browser(),
            enable_ech_grease: false,
            enable_md5sig_fooling: false,
            enable_geedge_evasion: true,
            relay_enabled: false,
            relay_listen_port: default_relay_listen_port(),
            relay_connect_host: String::new(),
            relay_connect_port: default_relay_connect_port(),
            relay_fake_sni: String::new(),
            relay_resolve_doh: true,
            relay_mutate_real_sni: false,
            relay_emit_decoy: false,
            doh_server: default_doh_url(),
            sni_only: Vec::new(),
            sni_except: Vec::new(),
            enable_tls_record_fragmentation: false,
            tls_record_chunk_size: 0,
            enable_frag_by_sni: false,
            enable_autottl: false,
            autottl_delta: 0,
            enable_http_host_tricks: false,
            enable_adaptive_desync: false,
            // 2026 roadmap upgrades — all off by default: each one changes
            // the wire shape, so they are opt-in like the other desync flags.
            enable_frag_mid_sni: false,
            enable_padding_inflation: false,
            enable_strategy_rotation: false,
            enable_real_ech: false,
            real_ech_config_hex: String::new(),
            // MUST be true by default (fail-closed). If you flip this off, a
            // failed fake injection falls through to relaying the real
            // ClientHello, which defeats the whole point of the relay.
            relay_require_inject: true,
            // 25 new features defaults
            enable_sni_scanner: false,
            sni_candidates: Vec::new(),
            edge_candidates: Vec::new(),
            isp_profile: default_isp_profile(),
            sni_rotation_mode: default_rotation_mode(),
            enable_anti_fingerprint: false,
            injection_delay_min_ms: default_delay_min(),
            injection_delay_max_ms: default_delay_max(),
            max_packet_padding: default_max_padding(),
            randomize_ip_id: false,
            randomize_packet_size: false,
            enable_fake_with_sni: false,
            fake_browser: default_fake_browser(),
            enable_reverse_frag: false,
            enable_wrong_seq: true,
            enable_wrong_checksum: true,
            enable_oob_injection: false,
            enable_hostdot: false,
            max_payload_size: default_max_payload(),
            fake_resend_count: default_fake_resend(),
            enable_self_update: false,
            update_repo: default_update_repo(),
            enable_client_detect: false,
            enable_proxy_cleanup: true,
            enable_youtube_warmup: false,
            enable_mobile_gateway: false,
            ipset_hostlist: Vec::new(),
            autottl_scale_a1: 0,
            autottl_scale_a2: default_autottl_a2(),
            autottl_scale_max: default_autottl_m(),
        }
    }
}

impl fmt::Debug for Settings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Settings")
            .field("mutation_profile", &self.mutation_profile)
            .field("decoy_ttl", &self.decoy_ttl)
            .field("idle_timeout_secs", &self.idle_timeout_secs)
            .field("trusted_dns", &self.trusted_dns)
            .field("fragment_chunk_size", &self.fragment_chunk_size)
            .field("enable_decoys", &self.enable_decoys)
            .field("enable_sni_fragmentation", &self.enable_sni_fragmentation)
            .field("enable_swap_foolers", &self.enable_swap_foolers)
            .field("enable_kill_switch", &self.enable_kill_switch)
            .field("kill_switch_adapter", &self.kill_switch_adapter)
            .field("rotate_ips", &self.rotate_ips)
            .field(
                "win_divert_sha256",
                &format!("{} pin(s)", self.win_divert_sha256.len()),
            )
            .field("enable_web_ui", &self.enable_web_ui)
            .field("web_ui_port", &self.web_ui_port)
            .field(
                "web_ui_token",
                &if self.web_ui_token.is_empty() {
                    "<empty>"
                } else {
                    "<redacted>"
                },
            )
            .field("enable_quic_port_bypass", &self.enable_quic_port_bypass)
            .field("quic_bypass_use_low_port", &self.quic_bypass_use_low_port)
            .field("enable_sni_disguise", &self.enable_sni_disguise)
            .field("fronting_benign_sni", &self.fronting_benign_sni)
            .field(
                "enable_combined_fragmentation",
                &self.enable_combined_fragmentation,
            )
            .field("intercept_ports", &self.intercept_ports)
            .field("intercept_all_tcp", &self.intercept_all_tcp)
            .field("intercept_all_udp", &self.intercept_all_udp)
            .field("enable_utls_fingerprint", &self.enable_utls_fingerprint)
            .field("utls_browser", &self.utls_browser)
            .field("enable_ech_grease", &self.enable_ech_grease)
            .field("enable_md5sig_fooling", &self.enable_md5sig_fooling)
            .field("enable_geedge_evasion", &self.enable_geedge_evasion)
            .field("relay_enabled", &self.relay_enabled)
            .field("relay_listen_port", &self.relay_listen_port)
            .field(
                "relay_connect_host",
                &if self.relay_connect_host.is_empty() {
                    "<empty>".to_string()
                } else {
                    crate::stealth::redact_endpoint(&self.relay_connect_host)
                },
            )
            .field("relay_connect_port", &self.relay_connect_port)
            .field("relay_fake_sni", &self.relay_fake_sni)
            .field("relay_resolve_doh", &self.relay_resolve_doh)
            .field("relay_mutate_real_sni", &self.relay_mutate_real_sni)
            .field("relay_emit_decoy", &self.relay_emit_decoy)
            .field("doh_server", &self.doh_server)
            .field("sni_only", &self.sni_only)
            .field("sni_except", &self.sni_except)
            .field(
                "enable_tls_record_fragmentation",
                &self.enable_tls_record_fragmentation,
            )
            .field("tls_record_chunk_size", &self.tls_record_chunk_size)
            .field("enable_frag_by_sni", &self.enable_frag_by_sni)
            .field("enable_autottl", &self.enable_autottl)
            .field("autottl_delta", &self.autottl_delta)
            .field("enable_http_host_tricks", &self.enable_http_host_tricks)
            .field("enable_adaptive_desync", &self.enable_adaptive_desync)
            .field("enable_frag_mid_sni", &self.enable_frag_mid_sni)
            .field("enable_padding_inflation", &self.enable_padding_inflation)
            .field("enable_strategy_rotation", &self.enable_strategy_rotation)
            .field("enable_real_ech", &self.enable_real_ech)
            .field(
                "real_ech_config_hex",
                &format!("{} hex byte(s)", self.real_ech_config_hex.len() / 2),
            )
            .field("relay_require_inject", &self.relay_require_inject)
            .finish()
    }
}

impl Settings {
    /// Configured interception ports, independent of the all-* wildcards:
    /// `intercept_ports` minus the never-intercept ports, or `[443]` when
    /// empty. Used by the filter builder and by `is_target_port` on the
    /// non-wildcard path.
    pub fn explicit_port_list(&self) -> Vec<u16> {
        let mut v: Vec<u16> = if self.intercept_ports.is_empty() {
            vec![443]
        } else {
            self.intercept_ports.clone()
        };
        v.retain(|p| !NEVER_INTERCEPT_PORTS.contains(p));
        v.sort_unstable();
        v.dedup();
        v
    }

    /// Display view for logs / dashboard: the sorted explicit list, or
    /// `[]` to mean "all ports" when a wildcard flag is on.
    pub fn effective_ports(&self) -> Vec<u16> {
        if self.intercept_all_tcp || self.intercept_all_udp {
            return vec![]; // meaning all, handled by the filter builder
        }
        self.explicit_port_list()
    }

    pub fn is_target_port(&self, port: u16, is_udp: bool) -> bool {
        if NEVER_INTERCEPT_PORTS.contains(&port) {
            return false;
        }
        if is_udp {
            if self.intercept_all_udp {
                return true;
            }
        } else if self.intercept_all_tcp {
            return true;
        }
        self.explicit_port_list().contains(&port)
    }

    pub fn validate(&mut self) -> Result<(), DpiGuardError> {
        MutationProfile::from_str(&self.mutation_profile)?;
        if self.enable_real_ech {
            // Fail early on a broken ECH config: sealing fails per-hello
            // otherwise, which would log-spam and silently disable ECH.
            let bytes = crate::hpke::decode_hex(&self.real_ech_config_hex).map_err(|_| {
                DpiGuardError::Config("real_ech_config_hex is not valid hex".into())
            })?;
            crate::ech::parse_ech_config_detailed(&bytes)
                .map_err(|e| DpiGuardError::Config(format!("real_ech_config_hex: {e}")))?;
        }
        if self.decoy_ttl == 0 || self.decoy_ttl > 64 {
            return Err(DpiGuardError::Config("decoy_ttl must be 1..=64".into()));
        }
        if self.idle_timeout_secs == 0 {
            return Err(DpiGuardError::Config(
                "idle_timeout_secs must be > 0".into(),
            ));
        }
        if self.fragment_chunk_size == 1 {
            return Err(DpiGuardError::Config(
                "fragment_chunk_size=1 is rejected; use 0 or >=8".into(),
            ));
        }
        if self.fragment_chunk_size > 0 && self.fragment_chunk_size < 8 {
            return Err(DpiGuardError::Config(
                "fragment_chunk_size must be 0 or >=8".into(),
            ));
        }
        if self.fragment_chunk_size > 16384 {
            return Err(DpiGuardError::Config(
                "fragment_chunk_size must be <=16384".into(),
            ));
        }
        if self.idle_timeout_secs > 86_400 {
            return Err(DpiGuardError::Config(
                "idle_timeout_secs must be <=86400".into(),
            ));
        }
        if self.enable_kill_switch {
            crate::stealth::sanitize_adapter_name(&self.kill_switch_adapter)?;
        }
        if self.trusted_dns.is_some() {
            return Err(DpiGuardError::Config(
                "trusted_dns is unsupported: DNS redirection requires a signed WFP kernel callout; remove this legacy setting and use doh_server/relay_resolve_doh".into(),
            ));
        }
        for ip in &self.rotate_ips {
            let parsed = ip
                .parse::<IpAddr>()
                .map_err(|_| DpiGuardError::Config(format!("rotate_ips {ip:?} invalid")))?;
            crate::netguard::validate_relay_ip(parsed).map_err(|e| {
                DpiGuardError::Config(format!("rotate_ips {ip:?} is forbidden: {e}"))
            })?;
        }
        if !self.win_divert_sha256.is_empty() && self.win_divert_sha256.len() != 2 {
            return Err(DpiGuardError::Config(
                "win_divert_sha256 must contain exactly two pins in order: WinDivert.dll, WinDivert64.sys".into(),
            ));
        }
        for h in &self.win_divert_sha256 {
            let h = h.trim();
            if h.len() != 64 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(DpiGuardError::Config(
                    "win_divert_sha256 must be 64 hex".into(),
                ));
            }
        }
        if self.web_ui_port == 0 {
            return Err(DpiGuardError::Config("web_ui_port must be >0".into()));
        }
        if !self.web_ui_token.is_empty() {
            if self.web_ui_token.len() < 16 {
                return Err(DpiGuardError::Config("web_ui_token must be >=16".into()));
            }
            if !self
                .web_ui_token
                .chars()
                .all(|c| c.is_ascii_graphic() && c != '"' && c != '\\')
            {
                return Err(DpiGuardError::Config(
                    "web_ui_token must be printable ASCII without quotes".into(),
                ));
            }
        }
        if !self.fronting_benign_sni.is_empty() {
            if self.fronting_benign_sni.len() > 253 {
                return Err(DpiGuardError::Config("fronting_benign_sni too long".into()));
            }
            if !self
                .fronting_benign_sni
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
            {
                return Err(DpiGuardError::Config(
                    "fronting_benign_sni must be valid hostname".into(),
                ));
            }
        }
        if !self.intercept_ports.is_empty() {
            for &p in &self.intercept_ports {
                if p == 0 {
                    return Err(DpiGuardError::Config(
                        "intercept_ports cannot contain 0".into(),
                    ));
                }
                if NEVER_INTERCEPT_PORTS.contains(&p) {
                    log::warn!(
                        "intercept_ports contains {p}, which is never intercepted by design \
                         (SSH/DNS/RDP) — it will be ignored"
                    );
                }
            }
            if self.intercept_ports.len() > 100 {
                return Err(DpiGuardError::Config(
                    "intercept_ports max 100 entries".into(),
                ));
            }
        }
        let valid_browsers = ["chrome", "firefox", "safari", "edge", "random"];
        if !valid_browsers.contains(&self.utls_browser.to_ascii_lowercase().as_str()) {
            return Err(DpiGuardError::Config(format!(
                "utls_browser must be one of {:?}",
                valid_browsers
            )));
        }
        if self.relay_enabled {
            if self.relay_listen_port == 0 {
                return Err(DpiGuardError::Config(
                    "relay_listen_port must be > 0".into(),
                ));
            }
            if KNOWN_V2RAY_LOCAL_PORTS.contains(&self.relay_listen_port) {
                log::warn!(
                    "relay_listen_port {} is a well-known v2rayN/v2ray local port \
                     (SOCKS 10808 / HTTP 10809 / DNS 10853). If that client is running, \
                     one of the two will fail to bind — pick another port.",
                    self.relay_listen_port
                );
            }
            if self.relay_connect_port == 0 {
                return Err(DpiGuardError::Config(
                    "relay_connect_port must be > 0".into(),
                ));
            }
            let host = self.relay_connect_host.trim();
            if host.is_empty() {
                return Err(DpiGuardError::Config(
                    "relay_connect_host is required when relay_enabled".into(),
                ));
            }
            if host.parse::<IpAddr>().is_err()
                && !host
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
            {
                return Err(DpiGuardError::Config(
                    "relay_connect_host must be an IP or a valid hostname".into(),
                ));
            }
            // Forbidden destinations (loopback/link-local/multicast/metadata)
            // are refused for both IP literals and hostnames.
            if crate::netguard::is_forbidden_hostname(host) {
                return Err(DpiGuardError::Config(format!(
                    "relay_connect_host {host:?} is forbidden (loopback/link-local/multicast/metadata)"
                )));
            }
            // An IP literal is preferred: it skips DNS entirely and cannot be
            // rebounded. A hostname is allowed but warned about.
            if host.parse::<IpAddr>().is_err() {
                log::warn!(
                    "relay_connect_host is a domain name; using an IP literal avoids \
                     DNS resolution and is recommended (zero leak)."
                );
            } else if let Ok(ip) = host.parse::<IpAddr>() {
                crate::netguard::validate_relay_ip(ip)?;
            }
            if self.relay_fake_sni.is_empty() {
                return Err(DpiGuardError::Config(
                    "relay_fake_sni is required when relay_enabled".into(),
                ));
            }
            if !self
                .relay_fake_sni
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
            {
                return Err(DpiGuardError::Config(
                    "relay_fake_sni must be a valid hostname".into(),
                ));
            }
            // F-007: same cap the dashboard enforces (max DNS hostname length).
            if self.relay_fake_sni.len() > 253 {
                return Err(DpiGuardError::Config(
                    "relay_fake_sni exceeds 253 chars (max hostname length)".into(),
                ));
            }
            if self.enable_web_ui && self.relay_listen_port == self.web_ui_port {
                return Err(DpiGuardError::Config(format!(
                    "relay_listen_port {} collides with web_ui_port",
                    self.relay_listen_port
                )));
            }
        }
        // Validate + normalize the DoH URL unconditionally (even when relay
        // is off) so a bad endpoint fails fast.
        self.doh_server = crate::netguard::validate_doh_url(&self.doh_server)?;
        // SNI filter lists must be valid host patterns (letters/digits/.-_*).
        for list in [&self.sni_only, &self.sni_except] {
            for pat in list {
                if pat.len() > 253 {
                    return Err(DpiGuardError::Config("SNI filter pattern too long".into()));
                }
                if !pat.chars().all(|c| {
                    c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' || c == '*'
                }) {
                    return Err(DpiGuardError::Config(format!(
                        "SNI filter pattern {pat:?} contains invalid characters"
                    )));
                }
            }
        }
        if self.tls_record_chunk_size > 16384 {
            return Err(DpiGuardError::Config(
                "tls_record_chunk_size must be <= 16384".into(),
            ));
        }
        if !(-32..=32).contains(&self.autottl_delta) {
            return Err(DpiGuardError::Config(
                "autottl_delta must be between -32 and 32".into(),
            ));
        }
        if self.intercept_all_tcp && self.intercept_all_udp {
            log::warn!("intercept_all_tcp AND intercept_all_udp both ON - will intercept ALL traffic except 22/53/3389");
        }
        // ── New 25-feature validation ──
        // ISP profile
        let _ = crate::isp_profiles::IspProfile::from_str(&self.isp_profile)?;
        // SNI rotation mode
        let valid_modes = ["round_robin", "weighted_random", "lru"];
        if !valid_modes.contains(&self.sni_rotation_mode.to_lowercase().as_str()) {
            return Err(DpiGuardError::Config(format!(
                "sni_rotation_mode must be one of {:?}",
                valid_modes
            )));
        }
        // Anti-fingerprint delay bounds
        if self.enable_anti_fingerprint && self.injection_delay_min_ms > self.injection_delay_max_ms
        {
            return Err(DpiGuardError::Config(
                "injection_delay_min_ms must be <= injection_delay_max_ms".into(),
            ));
        }
        // Fake browser
        let valid_browsers_fp = ["firefox", "chrome", "safari", "edge", "random"];
        if !valid_browsers_fp.contains(&self.fake_browser.to_lowercase().as_str()) {
            return Err(DpiGuardError::Config(format!(
                "fake_browser must be one of {:?}",
                valid_browsers_fp
            )));
        }
        // Max payload
        if self.max_payload_size > 65535 {
            return Err(DpiGuardError::Config(
                "max_payload_size must be <= 65535".into(),
            ));
        }
        // Fake resend
        if self.fake_resend_count > 10 {
            return Err(DpiGuardError::Config(
                "fake_resend_count must be <= 10".into(),
            ));
        }
        // AutoTTL scale
        if self.autottl_scale_a2 > 64 {
            return Err(DpiGuardError::Config(
                "autottl_scale_a2 must be <= 64".into(),
            ));
        }
        if self.autottl_scale_max > 64 {
            return Err(DpiGuardError::Config(
                "autottl_scale_max must be <= 64".into(),
            ));
        }
        // IPset hostlist validation
        for host in &self.ipset_hostlist {
            if host.len() > 253 {
                return Err(DpiGuardError::Config(
                    "ipset_hostlist entry too long".into(),
                ));
            }
        }
        // The update check formats this straight into the GitHub API URL,
        // so it must be a bare owner/repo slug — never a URL and never
        // anything that can add path segments or a query string.
        crate::self_update::validate_repo_slug(&self.update_repo)?;
        Ok(())
    }

    pub fn profile(&self) -> MutationProfile {
        MutationProfile::from_str(&self.mutation_profile).unwrap_or(MutationProfile::Stealth)
    }
}

pub fn parse(toml_text: &str) -> Result<Settings, DpiGuardError> {
    let mut s: Settings =
        toml::from_str(toml_text).map_err(|e| DpiGuardError::Config(e.to_string()))?;
    s.validate()?;
    Ok(s)
}

pub fn load_from_file(path: &Path) -> Result<Settings, DpiGuardError> {
    let meta = std::fs::metadata(path)?;
    if meta.len() > MAX_CONFIG_BYTES as u64 {
        return Err(DpiGuardError::Config(format!(
            "config file {} is {} bytes, over the {MAX_CONFIG_BYTES} byte cap",
            path.display(),
            meta.len()
        )));
    }
    let text = std::fs::read_to_string(path)?;
    parse(&text)
}

/// Merge a *partial* TOML document over `base`, producing validated
/// `Settings`. Used by the web UI: the dashboard POSTs only the fields the
/// user changed; everything else is inherited from the currently running
/// settings. Unknown keys are still rejected (deny_unknown_fields applies to
/// the final deserialization).
pub fn merge_partial(base: &Settings, partial_toml: &str) -> Result<Settings, DpiGuardError> {
    let partial: toml::Value =
        toml::from_str(partial_toml).map_err(|e| DpiGuardError::Config(e.to_string()))?;
    let overrides = match partial {
        toml::Value::Table(t) => t,
        _ => return Err(DpiGuardError::Config("config must be a TOML table".into())),
    };
    let base_str = toml::to_string(base).map_err(|e| DpiGuardError::Config(e.to_string()))?;
    let mut base_value: toml::Value =
        toml::from_str(&base_str).map_err(|e| DpiGuardError::Config(e.to_string()))?;
    let base_table = base_value
        .as_table_mut()
        .ok_or_else(|| DpiGuardError::Config("base config is not a table".into()))?;
    for (k, v) in overrides {
        // The dashboard's redacted form sends web_ui_token = "" and
        // win_divert_sha256 = []. If we applied those, "Save" would wipe
        // the operator's token and pins. Treat empty values as "leave as-is".
        if k == "web_ui_token" {
            if let Some(s) = v.as_str() {
                if s.is_empty() {
                    continue;
                }
            }
        }
        if k == "win_divert_sha256" {
            if let Some(arr) = v.as_array() {
                if arr.is_empty() {
                    continue;
                }
            }
        }
        // `trusted_dns` is `Option<String>`. An empty string means "turn the
        // feature off": remove the key so it deserializes back to `None`
        // (an empty value cannot be stored — `validate` rejects a non-IP).
        // Without this the field would be write-once from the dashboard.
        if k == "trusted_dns" {
            if let Some(s) = v.as_str() {
                if s.is_empty() {
                    base_table.remove("trusted_dns");
                    continue;
                }
            }
        }
        base_table.insert(k, v);
    }
    let merged_str =
        toml::to_string(&base_value).map_err(|e| DpiGuardError::Config(e.to_string()))?;
    let mut merged: Settings =
        toml::from_str(&merged_str).map_err(|e| DpiGuardError::Config(e.to_string()))?;
    merged.validate()?;
    Ok(merged)
}

/// Serialize settings to TOML for the dashboard's advanced editor, with the
/// web-UI bearer token and driver pins redacted. Saving that text back via
/// `merge_partial` leaves the real token/pins in place (they are simply not
/// overridden).
pub fn redacted_toml(s: &Settings) -> Result<String, DpiGuardError> {
    let mut copy = s.clone();
    copy.web_ui_token = String::new();
    copy.win_divert_sha256 = Vec::new();
    toml::to_string(&copy).map_err(|e| DpiGuardError::Config(e.to_string()))
}

pub struct HotReloadWatcher {
    path: PathBuf,
    last_mtime: Option<SystemTime>,
}

impl HotReloadWatcher {
    pub fn new(path: PathBuf) -> Self {
        let last_mtime = std::fs::metadata(&path)
            .ok()
            .and_then(|m| m.modified().ok());
        Self { path, last_mtime }
    }
    pub fn reload_if_changed(&mut self) -> Result<Option<Settings>, DpiGuardError> {
        let meta = match std::fs::metadata(&self.path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let mtime = meta.modified()?;
        let changed = self.last_mtime.map(|prev| mtime > prev).unwrap_or(true);
        if !changed {
            return Ok(None);
        }
        let settings = load_from_file(&self.path)?;
        self.last_mtime = Some(mtime);
        Ok(Some(settings))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_when_fields_missing() {
        let s = parse("").unwrap();
        assert_eq!(s, Settings::default());
        assert_eq!(s.fragment_chunk_size, 64);
        assert!(s.enable_decoys);
        assert!(!s.enable_swap_foolers);
        assert!(!s.enable_quic_port_bypass);
        // Default is ALL ports (minus never-touch).
        assert!(s.intercept_all_tcp);
        assert!(s.intercept_all_udp);
        assert!(s.is_target_port(443, false));
        assert!(s.is_target_port(80, false));
        assert!(!s.is_target_port(22, false));
        assert!(!s.is_target_port(53, true));
        assert!(!s.is_target_port(3389, false));
        // Fail-closed relay default.
        assert!(s.relay_require_inject);
    }

    #[test]
    fn parses_overrides_and_rejects_legacy_dns_redirect() {
        let toml = r#"
            mutation_profile = "Aggressive"
            decoy_ttl = 5
            idle_timeout_secs = 60
            fragment_chunk_size = 32
            enable_decoys = false
        "#;
        let s = parse(toml).unwrap();
        assert_eq!(s.mutation_profile, "Aggressive");
        assert_eq!(s.decoy_ttl, 5);
        assert_eq!(s.trusted_dns, None);
        assert_eq!(s.fragment_chunk_size, 32);
        assert!(!s.enable_decoys);

        let err = parse("trusted_dns = \"1.1.1.1\"\n").unwrap_err();
        assert!(err.to_string().contains("signed WFP kernel callout"));
    }

    #[test]
    fn rejects_malformed_toml() {
        assert!(parse("not = [valid").is_err());
    }

    #[test]
    fn rotate_ips_accepts_approved_addresses_and_rejects_forbidden_targets() {
        let parsed = parse("rotate_ips = [\"1.1.1.1\", \"1.0.0.1\"]").unwrap();
        assert_eq!(
            parsed.rotate_ips,
            vec!["1.1.1.1".to_string(), "1.0.0.1".to_string()]
        );
        for raw in ["not-an-ip", "127.0.0.1", "169.254.169.254", "::1"] {
            assert!(
                parse(&format!("rotate_ips = [\"{raw}\"]")).is_err(),
                "forbidden rotation target {raw} must fail validation"
            );
        }
    }

    /// Audit F-04 regression: the shipped example must stay parseable by
    /// `parse()` (which validates) and must document every Settings field
    /// that has no documented reason to be absent — `rotate_ips` and
    /// `trusted_dns` were missing entirely while both having dashboard
    /// controls and mock entries.
    #[test]
    fn shipped_toml_example_parses_and_documents_partial_fields() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("dpi_guard.toml.example");
        let text = std::fs::read_to_string(&path)
            .expect("dpi_guard.toml.example must ship with the crate");
        let s = parse(&text).expect("example config must parse AND validate");
        assert_eq!(s.rotate_ips, Vec::<String>::new());
        assert!(s.trusted_dns.is_none());
        // The partial/limited fields stay documented in the file body.
        assert!(text.contains("rotate_ips ="));
        assert!(text.contains("trusted_dns ="));
    }

    #[test]
    fn rejects_unknown_profile_and_chunk_size_one() {
        assert!(parse("mutation_profile = \"Nope\"\n").is_err());
        assert!(parse("fragment_chunk_size = 1\n").is_err());
        assert!(parse("decoy_ttl = 0\n").is_err());
    }

    #[test]
    fn web_ui_defaults_off_and_port_9090() {
        let s = Settings::default();
        assert!(!s.enable_web_ui);
        assert_eq!(s.web_ui_port, 9090);
        assert!(s.web_ui_token.is_empty());
        assert!(parse("web_ui_port = 0\n").is_err());
        assert!(parse(
            "enable_web_ui = true\nweb_ui_port = 9091\nweb_ui_token = \"0123456789abcdef\"\n"
        )
        .is_ok());
    }

    #[test]
    fn win_divert_pins_must_be_64_hex_chars() {
        let good = "a".repeat(64);
        assert!(parse(&format!("win_divert_sha256 = [\"{good}\", \"{good}\"]\n")).is_ok());
        assert!(parse(&format!("win_divert_sha256 = [\"{good}\"]\n")).is_err());
        assert!(parse("win_divert_sha256 = [\"abcd\"]\n").is_err());
    }

    #[test]
    fn rejects_unknown_fields() {
        assert!(parse("not_a_real_key = 1\n").is_err());
    }

    #[test]
    fn new_quic_and_fronting_options_parse() {
        let toml = r#"
            enable_quic_port_bypass = true
            quic_bypass_use_low_port = true
            enable_sni_disguise = true
            fronting_benign_sni = "www.microsoft.com"
            enable_combined_fragmentation = true
            mutation_profile = "Henan"
        "#;
        let s = parse(toml).unwrap();
        assert!(s.enable_quic_port_bypass);
        assert!(s.enable_sni_disguise);
        assert_eq!(s.mutation_profile, "Henan");
    }

    #[test]
    fn all_ports_upgrade_parses() {
        let toml = r#"
            intercept_ports = [443, 8443, 2053, 2083, 8080, 80]
            intercept_all_tcp = false
            intercept_all_udp = false
            enable_utls_fingerprint = true
            utls_browser = "firefox"
            enable_ech_grease = true
            enable_md5sig_fooling = true
        "#;
        let s = parse(toml).unwrap();
        assert_eq!(s.effective_ports(), vec![80, 443, 2053, 2083, 8080, 8443]);
        assert!(s.is_target_port(8443, false));
        assert!(s.is_target_port(80, false));
        assert!(!s.is_target_port(22, false));
        assert!(s.enable_utls_fingerprint);
        assert!(s.enable_ech_grease);
    }

    #[test]
    fn intercept_all_flags_exclude_never_ports() {
        let s = Settings::default();
        // Never-intercept ports stay off-limits even in "all" mode.
        assert!(!s.is_target_port(22, false));
        assert!(!s.is_target_port(53, true));
        assert!(!s.is_target_port(3389, false));
        assert!(!s.is_target_port(3389, true));
        // Ordinary ports are intercepted.
        assert!(s.is_target_port(12345, true));
        assert!(s.is_target_port(12345, false));
    }

    #[test]
    fn new_desync_fields_parse() {
        let toml = r#"
            sni_only = ["*.example.com", "keep.org"]
            sni_except = ["blocked.example.com"]
            enable_tls_record_fragmentation = true
            tls_record_chunk_size = 128
            enable_frag_by_sni = true
            enable_autottl = true
            autottl_delta = 2
            enable_http_host_tricks = true
            enable_adaptive_desync = true
            relay_require_inject = false
        "#;
        let s = parse(toml).unwrap();
        assert_eq!(s.sni_only, vec!["*.example.com", "keep.org"]);
        assert_eq!(s.sni_except, vec!["blocked.example.com"]);
        assert!(s.enable_tls_record_fragmentation);
        assert_eq!(s.tls_record_chunk_size, 128);
        assert!(s.enable_frag_by_sni);
        assert!(s.enable_autottl);
        assert_eq!(s.autottl_delta, 2);
        assert!(s.enable_http_host_tricks);
        assert!(s.enable_adaptive_desync);
        assert!(!s.relay_require_inject);
    }

    #[test]
    fn relay_loopback_dest_is_rejected() {
        assert!(parse(
            "relay_enabled = true\nrelay_connect_host = \"127.0.0.1\"\nrelay_fake_sni = \"a.com\"\n"
        ).is_err());
        assert!(parse(
            "relay_enabled = true\nrelay_connect_host = \"localhost\"\nrelay_fake_sni = \"a.com\"\n"
        ).is_err());
        assert!(parse(
            "relay_enabled = true\nrelay_connect_host = \"169.254.169.254\"\nrelay_fake_sni = \"a.com\"\n"
        ).is_err());
        // RFC1918 is allowed.
        assert!(parse(
            "relay_enabled = true\nrelay_connect_host = \"10.0.0.5\"\nrelay_fake_sni = \"a.com\"\n"
        )
        .is_ok());
    }

    #[test]
    fn doh_loopback_is_rejected() {
        assert!(parse(
            "relay_enabled = true\nrelay_connect_host = \"1.1.1.1\"\nrelay_fake_sni = \"a.com\"\ndoh_server = \"https://127.0.0.1/dns-query\"\n"
        ).is_err());
        assert!(parse(
            "relay_enabled = true\nrelay_connect_host = \"1.1.1.1\"\nrelay_fake_sni = \"a.com\"\ndoh_server = \"https://user:pass@1.1.1.1/dns-query\"\n"
        ).is_err());
    }

    #[test]
    fn never_ports_are_ignored_in_explicit_list() {
        let s = parse("intercept_ports = [443, 53, 22]\n").unwrap();
        assert!(!s.is_target_port(53, true));
        assert!(!s.is_target_port(22, false));
        assert!(s.is_target_port(443, false));
        assert_eq!(s.explicit_port_list(), vec![443]);
    }

    #[test]
    fn rejects_invalid_ports_and_browser() {
        assert!(parse("intercept_ports = [0]\n").is_err());
        assert!(parse("utls_browser = \"opera\"\n").is_err());
        assert!(parse("utls_browser = \"chrome\"\n").is_ok());
    }

    #[test]
    fn relay_config_parses_and_validates() {
        let toml = r#"
            relay_enabled = true
            relay_listen_port = 40555
            relay_connect_host = "speedtest.example.com"
            relay_connect_port = 443
            relay_fake_sni = "www.microsoft.com"
            relay_resolve_doh = true
        "#;
        let s = parse(toml).unwrap();
        assert!(s.relay_enabled);
        assert_eq!(s.relay_listen_port, 40555);
        assert_eq!(s.relay_fake_sni, "www.microsoft.com");
        assert_eq!(s.doh_server, crate::doh::DEFAULT_DOH_URL);

        // Missing fake SNI -> error
        assert!(parse("relay_enabled = true\nrelay_connect_host = \"1.1.1.1\"\n").is_err());
        // Non-https DoH endpoint -> error
        assert!(parse("relay_enabled = true\nrelay_connect_host = \"1.1.1.1\"\nrelay_fake_sni = \"a.com\"\ndoh_server = \"http://x\"\n").is_err());
        // Invalid hostname -> error
        assert!(parse(
            "relay_enabled = true\nrelay_connect_host = \"bad host\"\nrelay_fake_sni = \"a.com\"\n"
        )
        .is_err());
    }

    #[test]
    fn merge_partial_overrides_and_preserves_base() {
        let base = Settings::default();
        let merged = merge_partial(&base, "mutation_profile = \"Henan\"\nrelay_enabled = true\nrelay_connect_host = \"1.1.1.1\"\nrelay_fake_sni = \"a.com\"\n").unwrap();
        assert_eq!(merged.mutation_profile, "Henan");
        assert!(merged.relay_enabled);
        // Untouched fields keep their base values.
        assert_eq!(merged.decoy_ttl, base.decoy_ttl);
        assert_eq!(merged.fragment_chunk_size, base.fragment_chunk_size);
        assert_eq!(merged.intercept_ports, base.intercept_ports);
    }

    #[test]
    fn merge_partial_rejects_unknown_key_and_bad_value() {
        let base = Settings::default();
        assert!(merge_partial(&base, "not_a_real_key = 1\n").is_err());
        assert!(merge_partial(&base, "decoy_ttl = 0\n").is_err());
        assert!(merge_partial(&base, "relay_enabled = true\n").is_err()); // missing fake_sni
    }

    #[test]
    fn merge_partial_new_relay_flags_parse() {
        let base = Settings::default();
        let merged = merge_partial(
            &base,
            "relay_enabled = true\nrelay_connect_host = \"1.1.1.1\"\nrelay_fake_sni = \"a.com\"\nrelay_mutate_real_sni = true\nrelay_emit_decoy = true\n",
        )
        .unwrap();
        assert!(merged.relay_mutate_real_sni);
        assert!(merged.relay_emit_decoy);
    }

    #[test]
    fn redacted_toml_hides_token_and_pins() {
        let s = Settings {
            web_ui_token: "secret-secret-secret".into(),
            win_divert_sha256: vec!["a".repeat(64), "b".repeat(64)],
            ..Settings::default()
        };
        let toml = redacted_toml(&s).unwrap();
        assert!(!toml.contains("secret-secret-secret"));
        assert!(!toml.contains(&"a".repeat(64)));
        // And merging it back keeps the original token/pins untouched. The
        // pin list is an ordered two-element gate (WinDivert.dll, then
        // WinDivert64.sys — see `validate` and `engine::version_check`), so
        // a round-trip must preserve BOTH entries in order.
        let merged = merge_partial(&s, &toml).unwrap();
        assert_eq!(merged.web_ui_token, "secret-secret-secret");
        assert_eq!(
            merged.win_divert_sha256,
            vec!["a".repeat(64), "b".repeat(64)]
        );
    }

    /// A default config has `trusted_dns = None`. The dashboard's save and
    /// advanced-editor paths both round-trip the struct through
    /// `toml::to_string`, which must not fail on a `None` field.
    #[test]
    fn default_settings_round_trip_through_toml() {
        let s = Settings::default();
        assert_eq!(s.trusted_dns, None);
        let text =
            toml::to_string(&s).expect("defaults must serialize (Option::None must be skipped)");
        assert!(
            !text.contains("trusted_dns"),
            "None must be skipped, not emitted"
        );
        let back: Settings = toml::from_str(&text).unwrap();
        assert_eq!(back, s);
        // The dashboard save path depends on exactly this.
        assert_eq!(merge_partial(&s, "decoy_ttl = 9\n").unwrap().decoy_ttl, 9);
        assert!(redacted_toml(&s).is_ok());
    }

    /// The dashboard must not turn the legacy `trusted_dns` field into a
    /// false promise: non-empty values fail closed, while an empty value is
    /// treated as removal for backwards-compatible cleanup.
    #[test]
    fn trusted_dns_redirect_is_rejected_and_can_be_cleared() {
        let base = Settings::default();
        let err = merge_partial(&base, "trusted_dns = \"1.1.1.1\"\n").unwrap_err();
        assert!(err.to_string().contains("signed WFP kernel callout"));
        let cleared = merge_partial(&base, "trusted_dns = \"\"\n").unwrap();
        assert_eq!(cleared.trusted_dns, None);
    }

    /// Every Settings field must survive a partial merge that only touches
    /// unrelated keys (the dashboard sends only what the operator changed).
    #[test]
    fn merge_partial_preserves_every_untouched_field() {
        let base = Settings {
            web_ui_token: "0123456789abcdef".into(),
            win_divert_sha256: vec!["b".repeat(64), "c".repeat(64)],
            intercept_ports: vec![443, 8443],
            sni_except: vec!["bank.example.com".into()],
            ..Settings::default()
        };
        let merged = merge_partial(&base, "enable_autottl = true\n").unwrap();
        assert!(merged.enable_autottl);
        assert_eq!(merged.trusted_dns, None);
        assert_eq!(merged.web_ui_token, "0123456789abcdef");
        // Untouched fields are preserved verbatim — including the full
        // ordered two-pin driver gate (validate requires exactly 2 or 0).
        assert_eq!(
            merged.win_divert_sha256,
            vec!["b".repeat(64), "c".repeat(64)]
        );
        assert_eq!(merged.intercept_ports, vec![443, 8443]);
        assert_eq!(merged.sni_except, vec!["bank.example.com".to_string()]);
    }

    #[test]
    fn relay_disabled_by_default_and_port_collision_rejected() {
        assert!(!Settings::default().relay_enabled);
        assert_eq!(Settings::default().relay_listen_port, 40443);
        // web_ui (9090) + relay on the same port -> error
        let toml = r#"
            enable_web_ui = true
            relay_enabled = true
            relay_listen_port = 9090
            relay_connect_host = "1.1.1.1"
            relay_fake_sni = "a.com"
        "#;
        assert!(parse(toml).is_err());
    }

    /// Coexistence with v2rayN / v2ray running on the same machine.
    ///
    /// The intended topology is: browser/app -> v2rayN (SOCKS 10808 /
    /// HTTP 10809) -> dpi_guard relay (127.0.0.1:40443) -> real server.
    /// Nothing here may reject that layout, and the relay's default port
    /// must not sit on one of v2rayN's local ports.
    #[test]
    fn coexists_with_v2rayn_default_local_ports() {
        // The documented setup must validate.
        let toml = r#"
            enable_web_ui = true
            web_ui_port   = 9090
            relay_enabled = true
            relay_listen_port = 40443
            relay_connect_host = "1.1.1.1"
            relay_connect_port = 443
            relay_fake_sni = "www.microsoft.com"
        "#;
        assert!(parse(toml).is_ok());

        // The default relay port is none of v2rayN's local ports.
        assert!(!KNOWN_V2RAY_LOCAL_PORTS.contains(&default_relay_listen_port()));
        assert!(!KNOWN_V2RAY_LOCAL_PORTS.contains(&default_web_ui_port()));
        // Nor is it a never-intercept port (22/53/3389).
        assert!(!NEVER_INTERCEPT_PORTS.contains(&default_relay_listen_port()));

        // Binding the relay on a v2rayN port is only a warning, not an
        // error: the operator may deliberately have stopped v2rayN.
        let clash = parse(
            "relay_enabled = true\nrelay_listen_port = 10808\n\
             relay_connect_host = \"1.1.1.1\"\nrelay_fake_sni = \"a.com\"\n",
        );
        assert!(clash.is_ok(), "port clash must warn, not refuse");
        assert_eq!(clash.unwrap().relay_listen_port, 10808);

        // A relay/web-UI collision is still a hard error.
        assert!(parse(
            "enable_web_ui = true\nrelay_enabled = true\nrelay_listen_port = 10808\n\
             web_ui_port = 10808\nrelay_connect_host = \"1.1.1.1\"\nrelay_fake_sni = \"a.com\"\n"
        )
        .is_err());
    }

    /// v2rayN -> relay is loopback and must never be intercepted; the
    /// relay -> server leg is the one dpi_guard has to see. The filter
    /// therefore has to keep `!loopback` while still covering the relay's
    /// destination port.
    #[test]
    fn filter_keeps_loopback_excluded_for_the_v2rayn_leg() {
        let s = parse(
            "relay_enabled = true\nrelay_listen_port = 40443\n\
             relay_connect_host = \"1.1.1.1\"\nrelay_connect_port = 443\n\
             relay_fake_sni = \"a.com\"\n",
        )
        .unwrap();
        let f = crate::build_filter(&s);
        assert!(
            f.contains("!loopback"),
            "v2rayN -> relay must stay untouched"
        );
        assert!(f.contains("tcp.DstPort == 443") || s.intercept_all_tcp);
        // The relay's own listen port is never a divert target.
        assert!(!f.contains("tcp.DstPort == 40443"));
    }

    #[test]
    fn hot_reload_detects_change() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("dpi_guard_test_{}.toml", std::process::id()));
        std::fs::write(&path, "decoy_ttl = 1\n").unwrap();
        let mut watcher = HotReloadWatcher::new(path.clone());
        assert!(watcher.reload_if_changed().unwrap().is_none());
        let mut seen = None;
        for _ in 0..40 {
            std::thread::sleep(std::time::Duration::from_millis(50));
            std::fs::write(&path, "decoy_ttl = 2\n").unwrap();
            if let Some(s) = watcher.reload_if_changed().unwrap() {
                seen = Some(s);
                break;
            }
        }
        assert_eq!(seen.unwrap().decoy_ttl, 2);
        let _ = std::fs::remove_file(&path);
    }

    /// 2026 roadmap flags: off by default, parseable, and nested-cloak
    /// profile accepted as a mutation_profile value.
    #[test]
    fn roadmap_2026_flags_default_off_and_parse() {
        let s = Settings::default();
        assert!(!s.enable_frag_mid_sni);
        assert!(!s.enable_padding_inflation);
        assert!(!s.enable_strategy_rotation);
        assert!(!s.enable_real_ech);
        let parsed = parse(
            "enable_frag_mid_sni = true\n\
             enable_padding_inflation = true\n\
             enable_strategy_rotation = true\n\
             mutation_profile = \"NestedCloak\"\n",
        )
        .unwrap();
        assert!(parsed.enable_frag_mid_sni);
        assert!(parsed.enable_padding_inflation);
        assert!(parsed.enable_strategy_rotation);
        assert_eq!(parsed.mutation_profile, "NestedCloak");
    }

    #[test]
    fn real_ech_requires_valid_config_hex() {
        // enable_real_ech with non-hex garbage is rejected at load.
        let mut s = Settings {
            enable_real_ech: true,
            real_ech_config_hex: "zz".into(),
            ..Settings::default()
        };
        assert!(s.validate().is_err());
        // Valid hex that is not an ECHConfigList is rejected too.
        let mut s = Settings {
            enable_real_ech: true,
            real_ech_config_hex: "0001020304".into(),
            ..Settings::default()
        };
        assert!(s.validate().is_err());
        // Flag off: nothing to validate.
        let mut s = Settings::default();
        assert!(s.validate().is_ok());
    }
}
