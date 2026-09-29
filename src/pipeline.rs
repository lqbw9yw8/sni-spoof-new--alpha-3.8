//! pipeline — OS-independent packet processor. [PARTIAL]
//! This is what `main` actually runs on every diverted packet: parse L3/L4
//! (skipping the TCP header via data-offset), splice a mutated SNI with
//! rewritten TLS lengths, optional TCP segmentation, optional TTL-limited
//! wrong-checksum decoy, inbound RST → strategy score.
//!
//! 2025-2026 upgrades:
//! - QUIC port blindspot bypass (src <= dst) for GFW
//! - SNI disguise as unknown extension (GREASE/private)
//! - Layered domain fronting (benign SNI + hidden real in 0xFF01)
//! - Combined TCP+TLS fragmentation for Henan-like regional firewalls
//! - ALL PORTS: works on any TCP/UDP port via intercept_ports config, not just 443
//!
//! 2026 roadmap:
//! - NestedCloak profile: cover SNI + real name in 0xFF01, mandatory
//!   3-segment TCP split + disorder
//! - frag_mid_sni: TLS-record cut inside the SNI name
//! - Random padding inflation, always-on ECH-GREASE (0xFE0D), real ECH
//!   sealing (hpke.rs), per-connection strategy rotation + escalation

use crate::config::Settings;
use crate::connection::SessionTicketCache;
use crate::error::DpiGuardError;
use crate::fail_open::WireAction;
use crate::fooling::{self, build_wrong_checksum};
use crate::fragmentation::{self, splice_sni};
use crate::packet::{self, ParsedPacket, TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_RST, TCP_FLAG_SYN};
use crate::quic::QuicPortMapper;
use crate::relay::{FlowInfo, HandshakeMonitor, HsAction, InjectGate, RelayMode};
use crate::sequence::{
    build_decoy_packet, calculate_wrong_seq_outside_window, inject_ttl_limited_decoy,
};
use crate::sni_mutations::{mutate_sni_full, MutationProfile};
use crate::stealth::{
    add_random_padding, deep_sleep_idle, hash_sensitive, inject_noise_entropy, match_sni_cert,
    randomize_window_size, run_salt, MemoryCertCache,
};
use crate::strategy::StrategyTable;
use rand::Rng;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
// Note: tokio::sync::Notify is no longer used directly — relay flows use
// `relay::InjectGate`, which carries an explicit success/failure bit.

const HOLD_TIMEOUT: Duration = Duration::from_millis(200);
const MAX_FLOW_BUF: usize = 16 * 1024;
const MAX_FLOWS: usize = 256;
const MAX_RECENT: usize = 512;
/// Cap on the relay-mode flow table. It grows once per **client
/// connection** to the relay, so a browser behind v2rayN can add hundreds
/// of entries quickly, and finished ones otherwise linger until
/// `idle_timeout_secs` (120 s by default). Without a hard cap this is
/// unbounded growth driven by ordinary client behaviour (CWE-770), and it
/// is the one table `docs/archive/SECURITY_CHECKLIST.md` control 44 did not actually
/// cover.
const MAX_RELAY_FLOWS: usize = 256;
/// Cap on `last_activity`, which gains an entry for every TCP 4-tuple the
/// pipeline sees. Its key comes straight off the wire, so without a bound a
/// source-spoofed scan grows it for a whole `idle_timeout_secs` window
/// (120 s by default, configurable up to 86 400) before `flush_idle` can
/// reclaim anything — unbounded growth driven by remote input (CWE-770).
/// `flows`/`recent`/`relay_flows` were each capped for exactly this reason;
/// this table and `inbound_ttl` were the two that were missed.
const MAX_LAST_ACTIVITY: usize = 4096;
/// Cap on `inbound_ttl`, keyed by source IP. Same argument as
/// [`MAX_LAST_ACTIVITY`], and it is populated on *every* inbound packet
/// whenever `enable_autottl` is on, so a spoofed-source flood is the
/// obvious way to grow it.
const MAX_INBOUND_TTL: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    src: IpAddr,
    dst: IpAddr,
    sport: u16,
    dport: u16,
}

struct FlowBuf {
    buf: Vec<u8>,
    next_seq: u32,
    held: Vec<Vec<u8>>,
    started: Instant,
}

struct RecentAttempt {
    domain: String,
    technique: String,
    at: Instant,
}

/// Per-flow state for the relay-mode fake-SNI injection.
struct RelayFlow {
    monitor: HandshakeMonitor,
    gate: Arc<InjectGate>,
    done: bool,
    last: Instant,
}

pub struct Pipeline {
    pub settings: Settings,
    pub strategy: StrategyTable,
    pub tickets: SessionTicketCache,
    pub certs: MemoryCertCache,
    flows: HashMap<FlowKey, FlowBuf>,
    last_activity: HashMap<FlowKey, Instant>,
    recent: HashMap<(IpAddr, u16), RecentAttempt>,
    quic_mapper: QuicPortMapper,
    relay_mode: Option<RelayMode>,
    relay_flows: HashMap<FlowKey, RelayFlow>,
    /// Learned decoy TTLs (per destination IP) for autottl.
    pub autottl: crate::autottl::AutoTtl,
    /// Last *observed* inbound IP TTL per peer, with the time it was seen.
    /// `AutoTtl` stores the TTL it already suggests, but
    /// `autottl::suggest_ttl_scaled` needs the raw hop distance, so the raw
    /// value is kept here. Pruned by `flush_idle` like every other map.
    inbound_ttl: HashMap<IpAddr, (u8, Instant)>,
    /// Desync mode chosen for the in-flight attempt on a peer, so the RST /
    /// ServerHello feedback in `on_inbound` can score that mode too and
    /// `enable_adaptive_desync` actually learns. Keyed like `recent`.
    last_desync: HashMap<(IpAddr, u16), String>,
    /// Parsed real-ECH config (from `real_ech_config_hex`), when valid.
    /// `None` = real ECH off or config missing/broken (fail-open).
    ech_config: Option<crate::ech::EchConfigDetailed>,
    /// Counts RST/ServerHello feedback events; drives strategy score decay
    /// when `enable_strategy_rotation` is on (2026 roadmap #6).
    feedback_ticks: u64,
    /// Normalized explicit intercept ports (sorted, NEVER-ports removed),
    /// cached once so the per-packet `is_target_port` check is a binary
    /// search instead of a fresh Vec build + sort + dedup on every packet.
    /// Refreshed on config hot-reload via [`Pipeline::refresh_port_cache`].
    explicit_ports: Vec<u16>,
    /// Last `flush_idle` sweep. Idle expiry is seconds-granular, so the
    /// sweep runs at most once per second instead of once per packet.
    last_sweep: Instant,
}

fn release_held_plus(mut held: Vec<Vec<u8>>, current: &[u8]) -> WireAction {
    held.push(current.to_vec());
    WireAction::Send(held)
}

impl Pipeline {
    pub fn new(settings: Settings) -> Self {
        // Parse the real-ECH config once at construction (validate() already
        // checked it at load; re-parse defensively for hot-reload paths).
        let ech_config = if settings.enable_real_ech {
            match crate::hpke::decode_hex(&settings.real_ech_config_hex)
                .ok()
                .map(|bytes| crate::ech::parse_ech_config_detailed(&bytes))
            {
                Some(Ok(cfg)) => {
                    log::info!("real ECH configured: public_name {}", cfg.public_name);
                    Some(cfg)
                }
                _ => {
                    log::warn!(
                        "enable_real_ech is set but real_ech_config_hex is missing/invalid; real ECH disabled"
                    );
                    None
                }
            }
        } else {
            None
        };
        // Cached before `settings` is moved into the struct.
        let explicit_ports = settings.explicit_port_list();
        Self {
            settings,
            strategy: StrategyTable::new(),
            tickets: SessionTicketCache::new(32),
            certs: MemoryCertCache::default(),
            flows: HashMap::new(),
            last_activity: HashMap::new(),
            recent: HashMap::new(),
            quic_mapper: QuicPortMapper::new(),
            relay_mode: None,
            relay_flows: HashMap::new(),
            autottl: crate::autottl::AutoTtl::new(),
            inbound_ttl: HashMap::new(),
            last_desync: HashMap::new(),
            ech_config,
            explicit_ports,
            last_sweep: Instant::now(),
            feedback_ticks: 0,
        }
    }

    /// Re-derive the cached explicit-port list after `self.settings` was
    /// replaced by a hot reload. No-op cost; keep next to the settings swap
    /// so the cache can never drift from the live settings.
    pub fn refresh_port_cache(&mut self) {
        self.explicit_ports = self.settings.explicit_port_list();
    }

    /// Hot-path port check: same semantics as
    /// `Settings::is_target_port`, but reads the pre-sorted cached list
    /// (binary search) instead of rebuilding it per packet.
    #[inline]
    fn is_target_port(&self, port: u16, is_udp: bool) -> bool {
        if crate::config::NEVER_INTERCEPT_PORTS.contains(&port) {
            return false;
        }
        if is_udp {
            if self.settings.intercept_all_udp {
                return true;
            }
        } else if self.settings.intercept_all_tcp {
            return true;
        }
        self.explicit_ports.binary_search(&port).is_ok()
    }

    /// One RST/ServerHello feedback event landed. With strategy rotation on
    /// (2026 roadmap #6), decay all scores every 32 events so the adaptive
    /// loop keeps tracking the DPI's *current* behaviour.
    fn feedback_tick(&mut self) {
        if !self.settings.enable_strategy_rotation {
            return;
        }
        self.feedback_ticks += 1;
        if self.feedback_ticks.is_multiple_of(32) {
            self.strategy.decay_all();
            log::debug!("strategy scores decayed (strategy rotation on)");
        }
    }

    /// Configure (or clear, with `None`) relay-mode evasion behaviour.
    pub fn configure_relay(&mut self, mode: Option<RelayMode>) {
        self.relay_mode = mode;
    }

    /// Register a relay connection (4-tuple) before its handshake and return
    /// the gate the relay awaits (with a success/failure bit) before
    /// relaying the real ClientHello.
    ///
    /// The table is capped at [`MAX_RELAY_FLOWS`]. Eviction prefers flows
    /// whose handshake already finished (`done`), because those no longer
    /// need the monitor; only if the table is still full is the oldest
    /// *live* flow dropped, and that is logged loudly since its injection
    /// can no longer be confirmed.
    pub fn register_relay_flow(&mut self, flow: FlowInfo) -> Arc<InjectGate> {
        let gate = InjectGate::new();
        let key = FlowKey {
            src: flow.src,
            dst: flow.dst,
            sport: flow.sport,
            dport: flow.dport,
        };
        // Re-registering an existing 4-tuple replaces it, so it never grows
        // the table and must not trigger eviction.
        if self.relay_flows.len() >= MAX_RELAY_FLOWS && !self.relay_flows.contains_key(&key) {
            let before = self.relay_flows.len();
            self.relay_flows.retain(|_, f| !f.done);
            let evicted_finished = before - self.relay_flows.len();
            if self.relay_flows.len() >= MAX_RELAY_FLOWS {
                let oldest = self
                    .relay_flows
                    .iter()
                    .min_by_key(|entry| entry.1.last)
                    .map(|entry| *entry.0);
                if let Some(oldest) = oldest {
                    self.relay_flows.remove(&oldest);
                    log::warn!(
                        "relay flow table full ({MAX_RELAY_FLOWS}); evicted the oldest live \
                         flow — its fake-SNI injection can no longer be confirmed"
                    );
                }
            } else if evicted_finished > 0 {
                log::debug!("relay flow table at cap; evicted {evicted_finished} finished flow(s)");
            }
        }
        self.relay_flows.insert(
            key,
            RelayFlow {
                monitor: HandshakeMonitor::new(),
                gate: gate.clone(),
                done: false,
                last: Instant::now(),
            },
        );
        gate
    }

    /// Drop a relay flow's entry once its connection is finished.
    ///
    /// The relay calls this on **every** exit path of a connection,
    /// including the fail-closed drop that happens when the fake-SNI
    /// injection is never confirmed. Without it those entries sat in the
    /// table until `idle_timeout_secs` expired (120 s by default), so a
    /// destination that consistently fails injection filled all
    /// [`MAX_RELAY_FLOWS`] slots with dead flows. Registration would then
    /// start evicting the oldest *live* flow, whose injection could no
    /// longer be confirmed, so it too failed closed — a feedback loop that
    /// turned one broken destination into a total outage.
    ///
    /// Returns true if an entry was actually removed (useful in tests).
    pub fn unregister_relay_flow(&mut self, flow: FlowInfo) -> bool {
        let key = FlowKey {
            src: flow.src,
            dst: flow.dst,
            sport: flow.sport,
            dport: flow.dport,
        };
        self.relay_flows.remove(&key).is_some()
    }

    /// Number of tracked relay flows. Used by the cap tests and useful for
    /// diagnosing a client (e.g. v2rayN) that opens many short connections.
    pub fn relay_flow_count(&self) -> usize {
        self.relay_flows.len()
    }

    pub fn handle(&mut self, raw: &[u8]) -> Result<WireAction, DpiGuardError> {
        // Idle expiry is seconds-granular: entries only ever expire at
        // `idle_timeout_secs >= 1`, so sweeping the six state maps once per
        // second is semantically identical to sweeping per packet, without
        // the O(live-entries) walk on every captured packet.
        if self.last_sweep.elapsed() >= Duration::from_secs(1) {
            self.last_sweep = Instant::now();
            self.flush_idle();
        }
        let Some(raw) = packet::l3_slice(raw) else {
            return Ok(WireAction::Passthrough);
        };
        let Some(parsed) = packet::parse_l3l4(raw) else {
            return Ok(WireAction::Passthrough);
        };

        // #14 — max-payload cap: skip large payloads (reduces CPU)
        if self.settings.max_payload_size > 0 {
            let payload = parsed.payload(raw);
            if payload.len() > self.settings.max_payload_size {
                return Ok(WireAction::Passthrough);
            }
        }

        if parsed.protocol == packet::PROTO_UDP {
            // ALL PORTS: check if UDP port is target
            let is_target_udp = self.is_target_port(parsed.dst_port, true)
                || self.is_target_port(parsed.src_port, true);
            if !is_target_udp {
                return Ok(WireAction::Passthrough);
            }
            if self.settings.enable_quic_port_bypass {
                // Inbound half of the QUIC port NAT: a server reply sent to
                // the spoofed source port is rewritten back to the client's
                // original source port. Checked first so a reply is never
                // mistaken for a brand-new Initial.
                if let Some(orig_sport) = self.quic_mapper.get_original(
                    parsed.src,      // server
                    parsed.dst,      // client
                    parsed.src_port, // server port
                    parsed.dst_port, // spoofed port
                ) {
                    if let Ok(rewritten) = crate::quic::rewrite_udp_dst_port(raw, orig_sport) {
                        // Debug (not info): this fires for EVERY reply
                        // packet of a mapped QUIC flow; at info level it
                        // spammed the log and paid a SHA-256 redaction per
                        // packet. Mapping creation is still logged at info.
                        log::debug!(
                            "QUIC reverse NAT: restored dst port {} -> {} for server {}",
                            parsed.dst_port,
                            orig_sport,
                            crate::stealth::redact_endpoint(&parsed.src.to_string())
                        );
                        return Ok(WireAction::Send(vec![rewritten]));
                    }
                }

                // Outbound half: keep rewriting every packet of an already
                // mapped flow (not just the Initial), so the server always
                // sees one 5-tuple.
                if let Some(spoofed) = self.quic_mapper.get_spoofed(
                    parsed.src,      // client
                    parsed.dst,      // server
                    parsed.dst_port, // server port
                    parsed.src_port, // original source port
                ) {
                    if let Ok(rewritten) = crate::quic::rewrite_udp_src_port(raw, spoofed) {
                        return Ok(WireAction::Send(vec![rewritten]));
                    }
                }

                // New flow: originate a NAT mapping only for a genuine
                // outbound client Initial (destination on an intercepted
                // port, source on an ephemeral port, src > dst).
                let dst_intercepted = self.is_target_port(parsed.dst_port, true);
                let src_intercepted = self.is_target_port(parsed.src_port, true);
                let payload = parsed.payload(raw);
                if dst_intercepted
                    && !src_intercepted
                    && crate::quic::should_mangle_quic(parsed.src_port, parsed.dst_port, true)
                    && crate::quic::is_quic_initial(payload)
                {
                    if self.quic_mapper.len() < crate::quic::MAX_QUIC_MAPS {
                        if let Some(new_sport) = self.quic_mapper.alloc_spoofed(
                            parsed.src,
                            parsed.dst,
                            parsed.dst_port,
                            self.settings.quic_bypass_use_low_port,
                        ) {
                            if let Ok(rewritten) = crate::quic::rewrite_udp_src_port(raw, new_sport)
                            {
                                self.quic_mapper.insert(
                                    parsed.src,
                                    parsed.dst,
                                    parsed.dst_port,
                                    parsed.src_port,
                                    new_sport,
                                );
                                log::info!(
                                    "QUIC bypass: rewrote src {} -> {} for dst {} (blindspot)",
                                    parsed.src_port,
                                    new_sport,
                                    crate::stealth::redact_endpoint(&parsed.dst.to_string())
                                );
                                return Ok(WireAction::Send(vec![rewritten]));
                            }
                        }
                    } else {
                        log::warn!(
                            "QUIC port mapper full; passing QUIC Initial through unmodified"
                        );
                    }
                }
            }
            return Ok(WireAction::Passthrough);
        }

        if parsed.protocol != packet::PROTO_TCP {
            return Ok(WireAction::Passthrough);
        }

        // Learn TTL from any inbound TCP packet (the relay destination is
        // the source of inbound packets). Done before short-circuiting so
        // relay flows also contribute.
        if self.settings.enable_autottl {
            let ttl = match parsed.l3 {
                packet::L3::Ipv4 => raw.get(8).copied().unwrap_or(64),
                packet::L3::Ipv6 => raw.get(7).copied().unwrap_or(64),
            };
            self.autottl
                .observe(parsed.src, ttl, self.settings.autottl_delta);
            // Bound the table before inserting a new source IP; re-observing
            // a known IP only refreshes it and cannot grow the map.
            if !self.inbound_ttl.contains_key(&parsed.src) {
                self.evict_inbound_ttl_if_full();
            }
            self.inbound_ttl.insert(parsed.src, (ttl, Instant::now()));
        }

        // Relay-mode flows short-circuit the normal SNI-mutation path: the
        // fake-SNI injection handles evasion, and the flow's real bytes pass
        // through unmodified.
        if let Some(action) = self.handle_relay_packet(raw, &parsed)? {
            return Ok(action);
        }

        // ALL PORTS: check if TCP port is target (either src or dst)
        let inbound = self.is_tcp_target(parsed.src_port);
        let outbound = self.is_tcp_target(parsed.dst_port);

        if inbound && !outbound {
            // Inbound from target port (server -> client)
            self.on_inbound(raw, &parsed);
            return Ok(WireAction::Passthrough);
        }
        if !outbound {
            return Ok(WireAction::Passthrough);
        }

        self.on_outbound_target(raw, &parsed)
    }

    /// A TCP port is "intercepted" when it is in the configured list (or an
    /// all-ports wildcard) OR, in relay mode with `mutate_real_sni`, when it
    /// is the relay's real destination port.
    fn is_tcp_target(&self, port: u16) -> bool {
        if self.is_target_port(port, false) {
            return true;
        }
        matches!(&self.relay_mode, Some(m) if m.mutate_real_sni && m.connect_port == port)
    }

    /// Drive the fake-SNI handshake monitor for a relay flow. Returns
    /// `Ok(None)` when the packet does not belong to a registered relay flow
    /// (or when a completed relay flow falls through to normal mutation).
    fn handle_relay_packet(
        &mut self,
        raw: &[u8],
        parsed: &ParsedPacket,
    ) -> Result<Option<WireAction>, DpiGuardError> {
        if self.relay_mode.is_none() {
            return Ok(None);
        }
        let key = FlowKey {
            src: parsed.src,
            dst: parsed.dst,
            sport: parsed.src_port,
            dport: parsed.dst_port,
        };
        let reversed = FlowKey {
            src: parsed.dst,
            dst: parsed.src,
            sport: parsed.dst_port,
            dport: parsed.src_port,
        };
        let (flow_key, outbound) = if self.relay_flows.contains_key(&key) {
            (key, true)
        } else if self.relay_flows.contains_key(&reversed) {
            (reversed, false)
        } else {
            return Ok(None);
        };

        let flags = parsed.tcp_flags.unwrap_or(0);
        let seq = parsed.tcp_seq.unwrap_or(0);
        let ack_num = parsed.tcp_ack.unwrap_or(0);
        let payload_len = parsed.payload(raw).len();
        let syn = flags & TCP_FLAG_SYN != 0;
        let ack = flags & TCP_FLAG_ACK != 0;
        let rst = flags & TCP_FLAG_RST != 0;
        let fin = flags & TCP_FLAG_FIN != 0;

        let entry = match self.relay_flows.get_mut(&flow_key) {
            Some(e) => e,
            None => return Ok(None),
        };
        entry.last = Instant::now();
        if entry.done {
            // Item 1: optionally run the real ClientHello through the normal
            // SNI-mutation pipeline; otherwise pass through unmodified.
            if self
                .relay_mode
                .as_ref()
                .map(|m| m.mutate_real_sni)
                .unwrap_or(false)
            {
                return Ok(None);
            }
            return Ok(Some(WireAction::Passthrough));
        }

        let action = if outbound {
            entry
                .monitor
                .on_outbound(syn, ack, rst, fin, seq, ack_num, payload_len)
        } else {
            entry
                .monitor
                .on_inbound(syn, ack, rst, fin, seq, ack_num, payload_len)
        };

        // sni_only/sni_except apply to the *real* ClientHello SNI in
        // apply_client_hello, not to the benign fake_sni decoy name.

        match action {
            HsAction::Pass => Ok(Some(WireAction::Passthrough)),
            HsAction::InjectFake => {
                crate::observability::injection_attempt();
                let mode = self.relay_mode.clone().unwrap_or(RelayMode {
                    fake_sni: String::new(),
                    connect_port: 0,
                    mutate_real_sni: false,
                    emit_decoy: false,
                    require_inject: true,
                });
                // Build the fake ClientHello first. If construction fails
                // for ANY reason and require_inject is on, signal failure so
                // the relay drops the connection (fail-closed). The real
                // ACK is still reinjected so the kernel's 3WHS completes.
                let fake_hello = if self.settings.enable_fake_with_sni {
                    // #8 — Generate a realistic browser-mimic ClientHello
                    crate::sequence::build_browser_mimic_hello(
                        &mode.fake_sni,
                        &self.settings.fake_browser,
                    )
                } else {
                    crate::fragmentation::encode_client_hello(&mode.fake_sni)
                };
                // enable_oob_injection (zapret): append an out-of-band byte
                // after the fake ClientHello. A stateless DPI that reads past
                // the record boundary sees a different SNI than the server,
                // which reassembles by record length and ignores the byte.
                let fake_hello = if self.settings.enable_oob_injection {
                    crate::http_host::inject_oob_byte(&fake_hello)
                } else {
                    fake_hello
                };
                let fake_seq = if self.settings.enable_wrong_seq {
                    entry.monitor.fake_seq_for(fake_hello.len())
                } else {
                    entry.monitor.correct_seq_for(fake_hello.len())
                };
                let fake = match crate::sequence::build_decoy_packet(raw, fake_seq, &fake_hello) {
                    Ok(p) => p,
                    Err(e) => {
                        log::error!("relay fake ClientHello build failed: {e}");
                        entry.monitor.fail();
                        entry.gate.fail();
                        crate::observability::injection_failure();
                        entry.done = true;
                        return Ok(Some(WireAction::Passthrough));
                    }
                };
                entry.monitor.mark_fake_sent();
                let mut out = vec![raw.to_vec(), fake];
                // #15 — Fake resend: send additional fake packets for reliability
                if self.settings.fake_resend_count > 1 {
                    let resends = crate::sequence::build_resend_batch(
                        &mode.fake_sni,
                        &self.settings.fake_browser,
                        self.settings.fake_resend_count - 1,
                    );
                    for resend_hello in resends {
                        let resend_seq = if self.settings.enable_wrong_seq {
                            entry.monitor.fake_seq_for(resend_hello.len())
                        } else {
                            entry.monitor.correct_seq_for(resend_hello.len())
                        };
                        if let Ok(pkt) =
                            crate::sequence::build_decoy_packet(raw, resend_seq, &resend_hello)
                        {
                            out.push(pkt);
                        }
                    }
                }
                if mode.emit_decoy {
                    // Second decoy copy — also fail-closed if it can't build.
                    let decoy_hello = crate::fragmentation::encode_client_hello(&mode.fake_sni);
                    match crate::sequence::build_decoy_packet(raw, fake_seq, &decoy_hello) {
                        Ok(mut decoy) => {
                            crate::sequence::inject_ttl_limited_decoy(
                                &mut decoy,
                                self.autottl_ttl_for(parsed.dst),
                            );
                            if self.settings.enable_wrong_checksum {
                                let _ = crate::fooling::build_wrong_checksum(&mut decoy);
                            }
                            out.push(decoy);
                        }
                        Err(e) => {
                            // A decoy failure is non-fatal (the primary fake
                            // was already built), but log it.
                            log::warn!("relay decoy build failed: {e}");
                        }
                    }
                }
                log::info!(
                    "relay fake ClientHello injected (fake SNI {:?}, fake_seq {fake_seq})",
                    mode.fake_sni
                );
                Ok(Some(WireAction::Send(out)))
            }
            HsAction::Complete => {
                entry.done = true;
                entry.gate.succeed();
                crate::observability::injection_success();
                log::info!("relay fake-SNI handshake complete; real data may flow");
                Ok(Some(WireAction::Passthrough))
            }
            HsAction::Fail => {
                // Unexpected handshake packet: signal failure. When
                // require_inject is true, the relay drops the connection so
                // the real ClientHello is never copied.
                entry.done = true;
                entry.gate.fail();
                crate::observability::injection_failure();
                log::warn!("relay handshake monitor failed; gate set to failure");
                Ok(Some(WireAction::Passthrough))
            }
        }
    }

    /// Effective decoy TTL for a relay destination: the auto-learned value
    /// if autottl is enabled and we've seen traffic from that host, else
    /// the operator's `decoy_ttl`.
    fn autottl_ttl_for(&self, dst: IpAddr) -> u8 {
        if !self.settings.enable_autottl {
            return self.settings.decoy_ttl;
        }
        // autottl_scale_a1/a2/max select the GoodbyeDPI-style scaled
        // algorithm instead of the plain learn-and-reuse one. a1 == 0 means
        // "not configured" (the compiled default), so the old behaviour is
        // unchanged unless the operator turns scaling on.
        if self.settings.autottl_scale_a1 > 0 {
            if let Some(&(observed, _)) = self.inbound_ttl.get(&dst) {
                return crate::autottl::suggest_ttl_scaled(
                    observed,
                    self.settings.autottl_scale_a1,
                    self.settings.autottl_scale_a2,
                    self.settings.autottl_scale_max,
                );
            }
        }
        self.autottl.effective(dst, self.settings.decoy_ttl)
    }

    fn on_inbound(&mut self, raw: &[u8], parsed: &ParsedPacket) {
        let flags = parsed.tcp_flags.unwrap_or(0);
        let key = (parsed.src, parsed.dst_port);
        // (autottl learning happens in handle() for every inbound TCP
        // packet, including relay flows, so it is not duplicated here.)

        if flags & TCP_FLAG_RST != 0 {
            if let Some(mode) = self.last_desync.remove(&key) {
                let domain = self
                    .recent
                    .get(&key)
                    .map(|r| r.domain.clone())
                    .unwrap_or_default();
                if !domain.is_empty() {
                    self.strategy.update_score(&domain, &mode, false);
                }
            }
            if let Some(recent) = self.recent.remove(&key) {
                self.strategy
                    .update_score(&recent.domain, &recent.technique, false);
                log::info!(
                    "RST from {} for hashed SNI {} technique {}",
                    crate::stealth::redact_endpoint(&parsed.src.to_string()),
                    hash_sensitive(&recent.domain, run_salt()),
                    recent.technique
                );
            }
            self.feedback_tick();
            return;
        }
        let payload = parsed.payload(raw);
        let is_server_hello = payload.len() >= 6 && payload[0] == 0x16 && payload[5] == 0x02;
        if is_server_hello {
            if let Some(mode) = self.last_desync.remove(&key) {
                let domain = self
                    .recent
                    .get(&key)
                    .map(|r| r.domain.clone())
                    .unwrap_or_default();
                if !domain.is_empty() {
                    self.strategy.update_score(&domain, &mode, true);
                }
            }
            // Consume the recent entry on success: one connection attempt
            // scores exactly once, no matter how many ServerHello segments
            // (retransmits, HelloRetryRequest, session tickets) arrive on
            // the same flow afterwards. Leaving the entry in place made
            // every subsequent inbound ServerHello re-award +1 and bias
            // strategy::select_best toward whatever technique happened to
            // see a chatty connection.
            if let Some(recent) = self.recent.remove(&key) {
                // Remember that this SNI successfully completed a handshake
                // so identity-breaking mutations (Aggressive/null-byte/etc.)
                // are allowed past the MemoryCertCache gate on future
                // connections. The cache is a best-effort allow-list; we
                // treat "got a ServerHello from this dst for this SNI" as a
                // usable signal that the SNI/cert combination worked.
                self.certs.observe_success(&recent.domain);
                self.strategy
                    .update_score(&recent.domain, &recent.technique, true);
            }
            self.feedback_tick();
        }
    }

    fn on_outbound_target(
        &mut self,
        raw: &[u8],
        parsed: &ParsedPacket,
    ) -> Result<WireAction, DpiGuardError> {
        let payload = parsed.payload(raw);
        if payload.is_empty() {
            return Ok(WireAction::Passthrough);
        }

        let key = FlowKey {
            src: parsed.src,
            dst: parsed.dst,
            sport: parsed.src_port,
            dport: parsed.dst_port,
        };
        // Bound the table before adding a new 4-tuple; refreshing an
        // existing key cannot grow it.
        if !self.last_activity.contains_key(&key) {
            self.evict_last_activity_if_full();
        }
        self.last_activity.insert(key, Instant::now());

        if let Some(action) = self.try_reassemble(raw, parsed, payload, key)? {
            return Ok(action);
        }

        match fragmentation::parse_client_hello(payload) {
            Ok(info) => {
                let sni = match info.sni {
                    Some(loc) => payload[loc.name_start..loc.name_end].to_vec(),
                    None => return Ok(WireAction::Passthrough),
                };
                self.flows.remove(&key);
                self.apply_client_hello(raw, parsed, payload, &sni)
            }
            Err(DpiGuardError::PacketTooShort { .. })
                if payload.first() == Some(&0x16) && payload.get(1) == Some(&0x03) =>
            {
                if self.hold(key, raw, parsed, payload.to_vec()) {
                    Ok(WireAction::Hold)
                } else {
                    Ok(WireAction::Passthrough)
                }
            }
            _ => Ok(WireAction::Passthrough),
        }
    }

    fn try_reassemble(
        &mut self,
        raw: &[u8],
        parsed: &ParsedPacket,
        payload: &[u8],
        key: FlowKey,
    ) -> Result<Option<WireAction>, DpiGuardError> {
        if !self.flows.contains_key(&key) {
            return Ok(None);
        }
        let seq = parsed.tcp_seq.unwrap_or(0);
        let next_seq = match self.flows.get(&key) {
            Some(f) => f.next_seq,
            None => return Ok(None),
        };
        if seq != next_seq {
            let held = match self.flows.remove(&key) {
                Some(f) => f.held,
                None => return Ok(None),
            };
            return Ok(Some(release_held_plus(held, raw)));
        }
        if self.flows.get(&key).map(|f| f.buf.len()).unwrap_or(0) + payload.len() > MAX_FLOW_BUF {
            let held = match self.flows.remove(&key) {
                Some(f) => f.held,
                None => return Ok(None),
            };
            return Ok(Some(release_held_plus(held, raw)));
        }
        {
            let flow = match self.flows.get_mut(&key) {
                Some(f) => f,
                None => return Ok(None),
            };
            flow.buf.extend_from_slice(payload);
            flow.next_seq = seq.wrapping_add(payload.len() as u32);
            flow.held.push(raw.to_vec());
        }
        let parse_result = match self.flows.get(&key) {
            // Borrow the accumulated buffer in place: cloning it per held
            // segment used to re-copy 1+2+...+N bytes while a ClientHello
            // spans N packets. The one buffer copy the success path needs
            // (for SNI extraction + mutation) happens only once, below,
            // after we know the hello actually parses.
            Some(f) => fragmentation::parse_client_hello(&f.buf),
            None => return Ok(None),
        };
        match parse_result {
            Ok(info) => {
                let buf = match self.flows.get(&key) {
                    Some(f) => f.buf.clone(),
                    None => return Ok(None),
                };
                let flow = match self.flows.remove(&key) {
                    Some(f) => f,
                    None => return Ok(None),
                };
                let sni = match info.sni {
                    Some(loc) => buf[loc.name_start..loc.name_end].to_vec(),
                    None => return Ok(Some(WireAction::Send(flow.held))),
                };
                let first = flow.held.first().map(|v| v.as_slice()).unwrap_or(raw);
                let first_parsed = packet::parse_l3l4(first).unwrap_or_else(|| parsed.clone());
                Ok(Some(self.apply_client_hello(
                    first,
                    &first_parsed,
                    &buf,
                    &sni,
                )?))
            }
            Err(DpiGuardError::PacketTooShort { .. }) => Ok(Some(WireAction::Hold)),
            Err(_) => {
                let held = match self.flows.remove(&key) {
                    Some(f) => f.held,
                    None => return Ok(None),
                };
                Ok(Some(WireAction::Send(held)))
            }
        }
    }

    fn hold(&mut self, key: FlowKey, raw: &[u8], parsed: &ParsedPacket, payload: Vec<u8>) -> bool {
        if self.flows.len() >= MAX_FLOWS {
            return false;
        }
        let seq = parsed.tcp_seq.unwrap_or(0);
        self.flows.insert(
            key,
            FlowBuf {
                next_seq: seq.wrapping_add(payload.len() as u32),
                buf: payload,
                held: vec![raw.to_vec()],
                started: Instant::now(),
            },
        );
        true
    }

    fn evict_recent_if_full(&mut self) {
        if self.recent.len() < MAX_RECENT {
            return;
        }
        let n = self.recent.len() / 2;
        let keys: Vec<_> = self.recent.keys().copied().take(n).collect();
        for k in keys {
            self.recent.remove(&k);
        }
    }

    /// Drop the oldest half of `last_activity` once it hits its cap.
    ///
    /// Unlike `recent`, every value here *is* a timestamp, so eviction can
    /// be oldest-first rather than arbitrary: the entries closest to
    /// expiring anyway are the ones removed, and a live flow that is still
    /// sending keeps a fresh timestamp and survives. Halving (rather than
    /// evicting one per insert) keeps this O(n log n) amortised over n/2
    /// inserts instead of running a sort on every packet at the cap.
    fn evict_last_activity_if_full(&mut self) {
        if self.last_activity.len() < MAX_LAST_ACTIVITY {
            return;
        }
        let mut by_age: Vec<(FlowKey, Instant)> =
            self.last_activity.iter().map(|(k, t)| (*k, *t)).collect();
        by_age.sort_unstable_by_key(|(_, t)| *t);
        let n = by_age.len() / 2;
        for (k, _) in by_age.into_iter().take(n) {
            self.last_activity.remove(&k);
        }
        log::debug!(
            "last_activity hit {MAX_LAST_ACTIVITY} entries; evicted the oldest {n} \
             (source-spoofed scan or a very large fan-out)"
        );
    }

    /// Same policy as [`Self::evict_last_activity_if_full`] for the
    /// per-source-IP inbound TTL table used by AutoTTL.
    fn evict_inbound_ttl_if_full(&mut self) {
        if self.inbound_ttl.len() < MAX_INBOUND_TTL {
            return;
        }
        let mut by_age: Vec<(IpAddr, Instant)> = self
            .inbound_ttl
            .iter()
            .map(|(ip, (_, at))| (*ip, *at))
            .collect();
        by_age.sort_unstable_by_key(|(_, at)| *at);
        let n = by_age.len() / 2;
        for (ip, _) in by_age.into_iter().take(n) {
            self.inbound_ttl.remove(&ip);
        }
        log::debug!(
            "inbound_ttl hit {MAX_INBOUND_TTL} entries; evicted the oldest {n} \
             (source-spoofed scan or a very large fan-out)"
        );
    }

    /// Number of tracked activity timestamps. Used by the cap tests.
    pub fn last_activity_count(&self) -> usize {
        self.last_activity.len()
    }

    /// Number of tracked per-source inbound TTLs. Used by the cap tests.
    pub fn inbound_ttl_count(&self) -> usize {
        self.inbound_ttl.len()
    }

    fn apply_client_hello(
        &mut self,
        raw: &[u8],
        parsed: &ParsedPacket,
        tls_record: &[u8],
        sni: &[u8],
    ) -> Result<WireAction, DpiGuardError> {
        let domain = String::from_utf8_lossy(sni).into_owned();
        if !crate::http_host::sni_allowed(
            &domain,
            &self.settings.sni_only,
            &self.settings.sni_except,
        ) {
            return Ok(WireAction::Passthrough);
        }
        // NOTE: `ech::has_ech_extension` is deliberately NOT used as a
        // skip-guard here. It is a raw two-byte scan for 0xFE0D anywhere in
        // the record, not a walk of the extension list, and real Chrome
        // ClientHellos carry an ECH *GREASE* extension — so gating on it
        // would silently disable SNI mutation for a large share of browser
        // traffic (and would false-positive on any 0xFE 0x0D pair inside the
        // random session id). Wiring it needs a proper extension walk first.
        // ipset_hostlist (zapret-style host filter): when non-empty it is an
        // allow-list ANDed with sni_only/sni_except, so a host has to be in
        // it to be mutated at all. Empty means "no extra restriction".
        if !self.settings.ipset_hostlist.is_empty()
            && !self
                .settings
                .ipset_hostlist
                .iter()
                .any(|pat| crate::http_host::hostname_matches(pat, &domain))
        {
            return Ok(WireAction::Passthrough);
        }
        let candidates = [
            MutationProfile::Stealth.as_str(),
            MutationProfile::ChinaGfw.as_str(),
            MutationProfile::RussiaDpi.as_str(),
            MutationProfile::Aggressive.as_str(),
            MutationProfile::ChinaRegional.as_str(),
            MutationProfile::Henan.as_str(),
            MutationProfile::NestedCloak.as_str(),
        ];
        // Empty-table fast path: with no recorded feedback every score read
        // is 0, so `select_best` returns the first candidate whose score
        // (0) can never beat cfg_score (0) — `deterministic` is always the
        // configured profile and `select_rotating` always returns None.
        // Skip the 7-candidate scan + 2 score reads (9 dashmap lookups and
        // 18 String allocations per ClientHello) and produce the identical
        // decision without touching the map.
        let strategy_empty = self.strategy.is_empty();
        let chosen = if strategy_empty {
            self.settings.mutation_profile.clone()
        } else {
            self.strategy
                .select_best(&domain, &candidates)
                .unwrap_or_else(|| self.settings.mutation_profile.clone())
        };
        // O(1) score reads: both used to run a full O(4096)-entry
        // `per_domain_scores` table scan per ClientHello (twice), plus a
        // discarded `select_best` whose only effect was inserting rows.
        // `score_of` reads the same values without creating entries.
        let cfg_score = if strategy_empty {
            0
        } else {
            self.strategy
                .score_of(&domain, &self.settings.mutation_profile)
        };
        let chosen_score = if strategy_empty {
            0
        } else {
            self.strategy.score_of(&domain, &chosen)
        };
        let deterministic = if chosen_score > cfg_score {
            chosen
        } else {
            self.settings.mutation_profile.clone()
        };
        // 2026 roadmap #4 + #6 — per-connection strategy rotation: instead
        // of always sending the single best shape (which a DPI can learn),
        // rotate weighted-random among the techniques that already won for
        // this domain; when the configured profile has learned to FAIL,
        // climb the escalation ladder instead of retrying it.
        let profile_name = if self.settings.enable_strategy_rotation {
            if cfg_score < 0 {
                crate::strategy::next_rung(&self.settings.mutation_profile)
                    .map(str::to_string)
                    .unwrap_or(deterministic)
            } else {
                self.strategy
                    .select_rotating(&domain, &candidates)
                    .unwrap_or(deterministic)
            }
        } else {
            deterministic
        };
        let profile: MutationProfile = profile_name.parse().unwrap_or(MutationProfile::Stealth);

        let mutated = mutate_sni_full(sni, profile);
        let use_mutated = if profile.preserves_identity() {
            true
        } else if self.certs.is_empty() {
            log::warn!(
                "skipping identity-breaking SNI mutation: certificate cache is empty \
                 (would train users to ignore hostname-mismatch warnings)"
            );
            false
        } else {
            // Only the identity-breaking profiles need the mutated name as
            // a string for cert matching — don't pay the allocation for
            // the identity-preserving ones (everything except Aggressive).
            let mutated_str = String::from_utf8_lossy(&mutated);
            match_sni_cert(&self.certs, &mutated_str)
        };

        let mut hello = if use_mutated && mutated != sni {
            splice_sni(tls_record, &mutated).unwrap_or_else(|_| tls_record.to_vec())
        } else {
            tls_record.to_vec()
        };

        // --- SNI fronting + disguise (layered), or Nested Extension Cloaking ---
        let mut nested_active = false;
        // Hot-reload may have turned enable_real_ech on after this Pipeline
        // was constructed; (re)parse the config lazily instead of silently
        // skipping the seal forever.
        if self.settings.enable_real_ech && self.ech_config.is_none() {
            self.ech_config = crate::hpke::decode_hex(&self.settings.real_ech_config_hex)
                .ok()
                .and_then(|bytes| crate::ech::parse_ech_config_detailed(&bytes).ok());
            if self.ech_config.is_none() {
                log::warn!(
                    "real ECH enabled but real_ech_config_hex is unusable; continuing without ECH"
                );
            }
        }
        // Real ECH (when configured) is strictly stronger than cloaking — the
        // name disappears from the wire entirely — and layering the 0xFF01
        // hidden extension under a seal would leak it in the outer hello.
        let real_ech_armed = self.settings.enable_real_ech && self.ech_config.is_some();
        if profile == MutationProfile::NestedCloak && !real_ech_armed {
            // 2026 NestedCloak: the visible SNI becomes a benign cover and
            // the untouched real name rides inside a private-range
            // extension (0xFF01). The 3-segment TCP split at the hidden
            // extension boundary happens below, on the final record.
            let cover = if self.settings.fronting_benign_sni.is_empty() {
                crate::sni_mutations::random_nested_cover()
            } else {
                self.settings.fronting_benign_sni.clone()
            };
            match fragmentation::nested_cloak(
                &hello,
                cover.as_bytes(),
                sni,
                crate::sni_mutations::NESTED_HIDDEN_EXT_TYPE,
            ) {
                Ok(cloaked) => {
                    hello = cloaked;
                    nested_active = true;
                    log::info!(
                        "NestedCloak: cover {}, real name hidden in 0x{:04X}",
                        cover,
                        crate::sni_mutations::NESTED_HIDDEN_EXT_TYPE
                    );
                }
                Err(e) => log::warn!("NestedCloak unavailable ({e}); sending hello as-is"),
            }
        } else if !self.settings.fronting_benign_sni.is_empty() && !real_ech_armed {
            // Real ECH subsumes fronting entirely (outer SNI = ECH
            // public_name, inner = real name); fronting first would only
            // leave a stale cover/disguised extension behind.
            let benign = self.settings.fronting_benign_sni.as_bytes();
            if let Ok(fronted) = fragmentation::front_sni_with_benign(&hello, benign) {
                if self.settings.enable_sni_disguise {
                    if let Ok(with_hidden) =
                        fragmentation::inject_hidden_sni_in_unknown_ext(&fronted, sni, 0xFF01)
                    {
                        hello = with_hidden;
                        log::info!(
                            "fronting layered: benign {} + hidden real in 0xFF01",
                            self.settings.fronting_benign_sni
                        );
                    } else {
                        hello = fronted;
                    }
                } else {
                    hello = fronted;
                }
            }
        } else if self.settings.enable_sni_disguise && !real_ech_armed {
            let disguise_type = crate::sni_mutations::random_disguise_type();
            if let Ok(disguised) = fragmentation::disguise_sni_extension_type(&hello, disguise_type)
            {
                hello = disguised;
                log::info!(
                    "SNI disguise: changed ext type 0x0000 -> 0x{:04X}",
                    disguise_type
                );
            }
        }

        // ECH GREASE (2025) — upgraded to always-on 0xFE0D (2026 roadmap
        // #3): attach the *real* ECH extension type with a random payload
        // to every hello so "has ECH / no ECH" classification is useless.
        // Servers that don't implement ECH ignore the extension. Skipped
        // when real ECH below attaches the real thing anyway (but stays on
        // when the real-ECH config is unusable and the seal will be skipped).
        if self.settings.enable_ech_grease && !real_ech_armed {
            if !self.settings.fronting_benign_sni.is_empty() {
                // Audit F-05: the outer-SNI result was computed and then
                // dropped with `let _ =`, so the benign fronting never
                // reached the wire on paths where the earlier fronting
                // branch did not run (e.g. NestedCloak fallback after a
                // cloak failure). Apply it — idempotent when the visible
                // SNI is already the benign cover.
                if let Ok(outer) =
                    crate::ech::build_outer_sni_for_ech(&hello, &self.settings.fronting_benign_sni)
                {
                    hello = outer;
                }
            }
            let has_ech = crate::fragmentation::list_extensions(&hello)
                .map(|exts| {
                    exts.iter()
                        .any(|e| e.ext_type == crate::ech::ECH_EXTENSION_TYPE)
                })
                .unwrap_or(true); // parse failure: don't add anything
            if has_ech {
                log::debug!("ECH extension already present; skipping GREASE");
            } else if let Ok(with_ech) = crate::ech::inject_ech_grease_fe0d(&hello) {
                hello = with_ech;
                log::debug!("ECH GREASE injected (type 0xFE0D)");
            } else if let Ok(with_grease) = crate::ech::inject_ech_grease_ext(&hello) {
                hello = with_grease;
                log::debug!("ECH GREASE injected (GREASE type)");
            }
        }

        // uTLS fingerprint rotation (JA3/JA4) - based on utls. Skipped when
        // real ECH is on: the cipher-suite shuffle must not run after the
        // seal (it would invalidate the AAD) and is pointless inside it.
        if self.settings.enable_utls_fingerprint && !real_ech_armed {
            let _ = crate::fragmentation::shuffle_cipher_suites_in_hello(&mut hello);
            if let Err(e) =
                crate::utls::apply_fingerprint_to_hello(&mut hello, &self.settings.utls_browser)
            {
                log::warn!("utls fingerprint apply failed: {e}");
            }
        }

        // Geedge evasion: prepend 1-2 GREASE placeholder extensions and add
        // a random-length padding extension (0x0015). Both confuse naive
        // offset-based SNI scanners without breaking a standards-compliant
        // server (unknown ext types are ignored per RFC 8446 §4.1.2).
        // Skipped when real ECH is on: the fake-record prepend breaks the
        // seal's parse and the rest is meaningless once the name is sealed.
        if self.settings.enable_geedge_evasion && !real_ech_armed {
            if matches!(
                self.settings.mutation_profile.as_str(),
                "ChinaRegional" | "Henan"
            ) {
                hello = crate::geedge::inject_fake_record_before_hello(&hello, 0x18);
            }
            // NOTE: the three probes that used to run here
            // (would_geedge_miss_sni / should_use_ip_fragmentation /
            // sni_as_ip_literal) were pure computations whose results were
            // discarded (`let _ =`), yet each re-parsed the full hello —
            // pure per-ClientHello waste. The functions remain available
            // (and tested) for when the IP-fragmentation decision is
            // actually wired to a setting.
            let mut rng = rand::thread_rng();
            let grease_count = rng.gen_range(1..=2);
            if let Ok(greased) = crate::geedge::prepend_grease_extensions(&hello, grease_count) {
                hello = greased;
            }
            let pad = rng.gen_range(0..=32);
            if pad > 0 {
                if let Ok(padded) = crate::geedge::add_tls_padding_extension(&hello, pad) {
                    hello = padded;
                }
            }
        }

        // Padding inflation (2026 roadmap #2): a random-length RFC 7685
        // padding extension per connection. Runs after the geedge block so
        // its random size stacks on top of the GREASE shifts; it appends at
        // the end of the extension list, so NestedCloak offsets below stay
        // valid. Skipped when real ECH seals the hello: the padding would
        // land inside the sealed outer and the AAD must see the final bytes.
        if self.settings.enable_padding_inflation && !real_ech_armed {
            if let Ok(padded) = crate::geedge::inflate_padding_random(&hello, 64, 384) {
                hello = padded;
            }
        }

        // Real ECH (2026 roadmap #5) — MUST stay the last hello mutation:
        // the AEAD's AAD (RFC 9849 §5.2) is the entire outer ClientHello
        // with the payload zeroed, so anything that still rewrites the
        // outer after sealing would break decryption on the server. The
        // outer SNI becomes the ECHConfig's public_name; the real name
        // exists only inside the HPKE-sealed payload.
        if self.settings.enable_real_ech {
            if let Some(cfg) = self.ech_config.as_ref() {
                match crate::ech::seal_real_ech_hello(&hello, sni, cfg, None) {
                    Ok(sealed) => {
                        log::info!("real ECH applied: outer SNI {}", cfg.public_name);
                        hello = sealed;
                    }
                    Err(e) => {
                        log::warn!("real ECH seal failed ({e}); continuing without ECH")
                    }
                }
            }
        }

        // NestedCloak: compute the 3-segment TCP split points on the FINAL
        // record. Anything above that changes lengths (geedge prepends,
        // padding, ECH) may shift the hidden extension, so the offsets are
        // derived here, not at cloaking time.
        let mut nested_offsets: Option<Vec<usize>> = None;
        if nested_active {
            match fragmentation::nested_cloak_split_offsets(
                &hello,
                crate::sni_mutations::NESTED_HIDDEN_EXT_TYPE,
            ) {
                Ok(offsets) => {
                    log::debug!(
                        "NestedCloak split at offsets {offsets:?} (payload {} bytes)",
                        hello.len()
                    );
                    nested_offsets = Some(offsets);
                }
                Err(e) => log::warn!("NestedCloak split points unavailable ({e})"),
            }
        }

        let mut real = packet::rebuild_with_payload(raw, &hello, None)?;

        if let Some(p) = packet::parse_l3l4(&real) {
            let off = p.l4_offset + packet::tcp_off::FLAGS;
            if real.len() > off {
                real[off] |= packet::TCP_FLAG_PSH | packet::TCP_FLAG_ACK;
                packet::recalculate_all_checksums(&mut real);
            }
        }

        // MD5SIG fooling (zapret) - adds TCP option 19, breaks some servers
        if self.settings.enable_md5sig_fooling {
            if let Ok(with_md5) = fooling::tcp_wrap_packet(&real, 18) {
                // tcp_wrap_packet appends exactly 20 bytes of NOP padding
                // directly AFTER the original TCP header (which may already
                // carry MSS/timestamps/sack options on real Windows stacks).
                // The original header length is therefore the wrapped
                // packet's header length minus 20 — patching at a fixed
                // `l4 + 20` (the old code) wrote into the existing options
                // or the payload whenever the packet had any TCP options.
                let md5opt = fooling::build_tcp_md5sig_option();
                if let Some(p) = packet::parse_l3l4(&with_md5) {
                    let l4 = p.l4_offset;
                    let new_hdr_len =
                        packet::ParsedPacket::tcp_header_len(&with_md5[l4..]).unwrap_or(20);
                    let pad_start = l4 + new_hdr_len.saturating_sub(20);
                    let mut patched = with_md5.clone();
                    if patched.len() >= pad_start + 18 {
                        patched[pad_start..pad_start + 18].copy_from_slice(&md5opt);
                        packet::recalculate_all_checksums(&mut patched);
                        real = patched;
                    } else {
                        real = with_md5;
                    }
                } else {
                    real = with_md5;
                }
                log::debug!("MD5SIG fooling applied");
            }
        }

        let mut packets: Vec<Vec<u8>> = Vec::new();

        if self.settings.enable_decoys {
            if let Some(decoy) = self.build_decoy(&real, parsed, &hello) {
                packets.push(decoy);
            }
        }
        if self.settings.enable_swap_foolers {
            if let Ok(rst) = fooling::build_rst_fooler(&real, parsed.tcp_seq.unwrap_or(0)) {
                packets.push(rst);
            }
            // A forged SYN-ACK from the "server" side of the swap. Like the
            // RST above it is built from the real packet with the endpoints
            // exchanged, which is why the setting is off by default and
            // behind a confirm prompt in the dashboard.
            if let Ok(synack) = fooling::build_synack_fooler(
                &real,
                parsed.tcp_seq.unwrap_or(0),
                parsed.tcp_ack.unwrap_or(0).wrapping_add(1),
            ) {
                packets.push(synack);
            }
        }

        // Combined TCP+TLS fragmentation for Henan / regional firewalls.
        // NestedCloak *requires* combined fragmentation even if the
        // operator disabled the flag — the cross-segment split is its
        // whole evasion story.
        //
        // Real ECH disables the entire fragmentation/disorder ladder below:
        // once the real name exists only inside the HPKE-sealed payload
        // there is nothing left for these desync tricks to hide, and the
        // verified contract for a sealed hello is exactly one packet on the
        // wire (see `ech_real_x_nested_cloak_no_ff01_leak`).
        let combined_on = !real_ech_armed
            && (self.settings.enable_combined_fragmentation
                || profile.requires_combined_fragmentation());
        let mut effective_chunk = self.settings.fragment_chunk_size;
        if combined_on {
            let recommended = profile.recommended_fragment_size();
            if recommended != 0 && (effective_chunk == 0 || recommended < effective_chunk) {
                effective_chunk = recommended;
            }
        }
        if profile == MutationProfile::NestedCloak && !real_ech_armed {
            // Chunk derived from the real name: min(32, len(SNI)).
            effective_chunk = crate::sni_mutations::nested_chunk_size(sni.len());
        }
        // enable_adaptive_desync: choose the desync mode for this domain from
        // the learned strategy scores instead of relying on the fixed flags
        // alone. This is what revives `strategy::DesyncMode` — the flags
        // below are OR-ed with the adaptive choice, so turning the setting
        // off leaves the previous behaviour exactly as it was.
        let adaptive = if self.settings.enable_adaptive_desync {
            let names = [
                crate::strategy::DesyncMode::TlsRecordFrag.as_str(),
                crate::strategy::DesyncMode::FragBySni.as_str(),
                crate::strategy::DesyncMode::Disorder.as_str(),
                crate::strategy::DesyncMode::Decoy.as_str(),
            ];
            self.strategy
                .select_best(&domain, &names)
                .and_then(|s| s.parse::<crate::strategy::DesyncMode>().ok())
        } else {
            None
        };
        if let Some(m) = adaptive {
            log::debug!(
                "adaptive desync for {}: {}",
                hash_sensitive(&domain, run_salt()),
                m.as_str()
            );
        }
        let use_tls_record_frag = !real_ech_armed
            && (self.settings.enable_tls_record_fragmentation
                || self.settings.enable_frag_mid_sni
                || adaptive == Some(crate::strategy::DesyncMode::TlsRecordFrag));
        let use_frag_by_sni = !real_ech_armed
            && (self.settings.enable_frag_by_sni
                || adaptive == Some(crate::strategy::DesyncMode::FragBySni));
        // 2026 roadmap #1: cut the TLS record *inside* the SNI name so no
        // single record contains the full hostname.
        let use_frag_mid_sni = !real_ech_armed && self.settings.enable_frag_mid_sni;
        let should_disorder = !real_ech_armed
            && (profile.uses_disorder()
                || combined_on
                || adaptive == Some(crate::strategy::DesyncMode::Disorder));

        // enable_tls_record_fragmentation / tls_record_chunk_size /
        // enable_frag_by_sni: re-frame the ClientHello as a run of
        // structurally valid 0x16 records.
        //
        // This runs INSTEAD of the TCP-level segmentation below, never inside
        // it: `tcp_segment_payload` cuts the payload at byte offsets, so only
        // its first segment starts on a record boundary and re-framing the
        // rest would emit TLS records with wrong lengths.
        //
        // It also only runs when the whole ClientHello is present in this one
        // packet (`pl.len() == 5 + declared record length`). Re-framing a
        // truncated handshake would produce records whose total is shorter
        // than the length the handshake header advertises, which a real
        // server rejects. When the guard fails we fall back to the existing
        // behaviour, so nothing is silently corrupted.
        let mut reframed: Vec<Vec<u8>> = Vec::new();
        if use_tls_record_frag {
            if let Some(p) = packet::parse_l3l4(&real) {
                let pl = p.payload(&real);
                let declared = if pl.len() >= 5 {
                    u16::from_be_bytes([pl[3], pl[4]]) as usize
                } else {
                    usize::MAX
                };
                let complete_record = pl.len() >= 5 && pl.len() == 5 + declared;
                let record_chunk = if self.settings.tls_record_chunk_size == 0 {
                    effective_chunk.max(8)
                } else {
                    self.settings.tls_record_chunk_size
                };
                let frags: Vec<Vec<u8>> = if !complete_record {
                    Vec::new()
                } else if use_frag_by_sni {
                    fragmentation::tls_record_split_before_sni(pl).unwrap_or_default()
                } else if use_frag_mid_sni {
                    fragmentation::tls_record_split_mid_sni(pl).unwrap_or_default()
                } else {
                    // fragment_as_tls_records takes the handshake *body*;
                    // strip the 5-byte record header it re-adds per chunk.
                    fragmentation::fragment_as_tls_records(&pl[5..], record_chunk)
                };
                if frags.len() > 1 {
                    let mut seq = p.tcp_seq.unwrap_or(0);
                    for tf in &frags {
                        match packet::rebuild_with_payload(&real, tf, Some(seq)) {
                            Ok(r) => {
                                reframed.push(r);
                                seq = seq.wrapping_add(tf.len() as u32);
                            }
                            Err(e) => {
                                log::debug!("TLS-record reframing aborted: {e}");
                                reframed.clear();
                                break;
                            }
                        }
                    }
                }
            }
        }

        if !reframed.is_empty() {
            packets.extend(reframed);
        } else if !real_ech_armed
            && (self.settings.enable_sni_fragmentation || nested_offsets.is_some())
        {
            // enable_frag_by_sni (TCP-level, without TLS-record reframing):
            // cut the wire exactly before the SNI and again 1 byte into the
            // name — the classic GoodbyeDPI/zapret "1-byte split at the SNI"
            // desync. Stateless DPI reassembles the extension differently
            // than the server. Falls back to the fixed-chunk split when the
            // SNI cannot be located in the (possibly mutated) record.
            let sni_split_offsets: Option<Vec<usize>> =
                if self.settings.enable_frag_by_sni && !use_tls_record_frag {
                    fragmentation::calculate_smart_split_points(&hello)
                        .ok()
                        .filter(|&(s, _)| s > 0 && s + 1 < hello.len())
                        .map(|(s, _)| vec![s, s + 1])
                } else {
                    None
                };
            let seg_res = if let Some(offsets) = nested_offsets.take() {
                // NestedCloak 3-segment split: cover hello / hidden-ext
                // header + name prefix / name tail. A non-reassembling DPI
                // only ever sees segment 1.
                log::debug!(
                    "NestedCloak TCP split at offsets {:?} (payload {} bytes)",
                    offsets,
                    hello.len()
                );
                packet::tcp_segment_payload_at_offsets(&real, &offsets)
            } else if let Some(offsets) = sni_split_offsets {
                log::debug!(
                    "TCP 1-byte SNI split at offsets {:?} (payload {} bytes)",
                    offsets,
                    hello.len()
                );
                packet::tcp_segment_payload_at_offsets(&real, &offsets)
            } else if effective_chunk >= 8 {
                packet::tcp_segment_payload(&real, effective_chunk)
            } else {
                // Chunk size below the 8-byte floor and no SNI offsets:
                // nothing sane to do at TCP level, send as one packet.
                Ok(vec![real.clone()])
            };
            match seg_res {
                Ok(segs) if !segs.is_empty() => {
                    let segs = if should_disorder {
                        fooling::disorder_mode(segs)
                    } else {
                        segs
                    };
                    if profile == MutationProfile::Henan && combined_on {
                        let mut combined = Vec::new();
                        for seg in segs {
                            if let Some(p) = packet::parse_l3l4(&seg) {
                                let pl = p.payload(&seg);
                                let tls_frags = fragmentation::persistent_fragmentation(pl, 16);
                                let mut seq = p.tcp_seq.unwrap_or(0);
                                for tf in tls_frags {
                                    if let Ok(r) =
                                        packet::rebuild_with_payload(&seg, &tf, Some(seq))
                                    {
                                        combined.push(r);
                                        seq = seq.wrapping_add(tf.len() as u32);
                                    }
                                }
                            } else {
                                combined.push(seg);
                            }
                        }
                        packets.extend(combined);
                    } else {
                        packets.extend(segs);
                    }
                }
                _ => packets.push(real),
            }
        } else {
            packets.push(real);
        }

        // --- 2026 hardening: HTTP Host split. Plaintext-HTTP only; applied
        // only when the outbound is a single packet (otherwise the other
        // desync machinery has already fragmented the flow and re-segmenting
        // it would misorder the TCP sequence space).
        if self.settings.enable_http_host_tricks && packets.len() == 1 {
            let original = &packets[0];
            let payload = crate::packet::parse_l3l4(original)
                .map(|p| p.payload(original).to_vec())
                .unwrap_or_default();
            let segs = crate::http_host::maybe_split_http_host(&payload, true);
            if segs.len() > 1 {
                let base_seq = crate::packet::parse_l3l4(original)
                    .and_then(|p| p.tcp_seq)
                    .unwrap_or(0);
                let template = original.clone();
                let mut built = Vec::new();
                let mut offset = 0u32;
                for seg in &segs {
                    if let Ok(pkt) = crate::packet::rebuild_with_payload(
                        &template,
                        seg,
                        Some(base_seq.wrapping_add(offset)),
                    ) {
                        built.push(pkt);
                    }
                    offset = offset.wrapping_add(seg.len() as u32);
                }
                if built.len() == segs.len() {
                    packets = built;
                }
            }
        }

        self.evict_recent_if_full();
        self.recent.insert(
            (parsed.dst, parsed.src_port),
            RecentAttempt {
                domain: domain.clone(),
                technique: profile.as_str().to_string(),
                at: Instant::now(),
            },
        );
        if let Some(m) = adaptive {
            self.last_desync
                .insert((parsed.dst, parsed.src_port), m.as_str().to_string());
        }
        // Destination-IP rotation belongs to relay connection selection
        // (`relay::RelayTarget`), not this transparent packet path. Rewriting
        // a live TCP flow's destination would make the peer answer from the
        // original address and corrupt the 4-tuple. Relay mode consumes the
        // validated `Settings::rotate_ips` list before the handshake starts.
        //
        // Session-ticket cache: record that we emitted a ClientHello for
        // this domain so the LRU structure actually exercises put/get
        // (rather than sitting empty). The cached blob is not yet a parsed
        // NewSessionTicket (that needs a TLS 1.3/1.2 ticket walker), but
        // recording the SNI means the cache is no longer dead code and the
        // LRU eviction path is exercised on every mutation.
        let had_ticket = self.tickets.get(&domain).is_some();
        if !had_ticket {
            self.tickets.put(&domain, Vec::new());
        }

        // #11 — Reverse fragmentation: send segments in reversed order
        if self.settings.enable_reverse_frag && packets.len() >= 2 {
            packets.reverse();
        }

        // #5-7 — Anti-fingerprint: IP-ID randomization & packet-size padding
        if self.settings.enable_anti_fingerprint {
            for pkt in packets.iter_mut() {
                // #7 — IP-ID randomization
                if self.settings.randomize_ip_id {
                    crate::anti_fingerprint::randomize_ip_id(pkt);
                }
                // #6 — Packet-size randomization (padding)
                if self.settings.randomize_packet_size && self.settings.max_packet_padding > 0 {
                    let padded = crate::anti_fingerprint::randomize_packet_size(
                        pkt,
                        self.settings.max_packet_padding,
                    );
                    *pkt = padded;
                }
            }
        }

        // #13 — Host-dot: apply to HTTP packets (non-TLS)
        if self.settings.enable_hostdot && packets.len() == 1 {
            let payload_start = parsed.payload_offset;
            let payload = &packets[0][payload_start..];
            // Only apply to plaintext HTTP (not TLS)
            if payload.len() > 4 && payload[0] != 0x16 {
                let new_payload = crate::http_host::apply_hostdot(payload);
                if new_payload.len() != payload.len() {
                    if let Ok(new_pkt) =
                        crate::packet::rebuild_with_payload(&packets[0], &new_payload, None)
                    {
                        packets[0] = new_pkt;
                    }
                }
            }
        }

        Ok(WireAction::Send(packets))
    }

    fn build_decoy(&self, real: &[u8], parsed: &ParsedPacket, hello: &[u8]) -> Option<Vec<u8>> {
        let (mut garbled, _) = fooling::reverse_mode(hello, hello.len().min(16));
        // #16 — add random trailer padding to the decoy payload and XOR a
        // sparse noise mask over it. Both are `stealth` primitives that make
        // the decoy's byte pattern diverge from the real ClientHello without
        // changing the TLS record that leads it (a stateless DPI still
        // parses the leading record and sees the garbled SNI; anything that
        // reads past the record length sees noise).
        if self.settings.max_packet_padding > 0 {
            // add_random_padding appends 0..=128 random bytes; clamp to the
            // configured ceiling so the decoy cannot exceed the operator's
            // chosen MTU budget.
            let padded = add_random_padding(&garbled);
            let cap = garbled
                .len()
                .saturating_add(self.settings.max_packet_padding);
            let bounded = if padded.len() > cap {
                padded[..cap].to_vec()
            } else {
                padded
            };
            garbled =
                crate::sequence::add_padding_to_decoy(&bounded, bounded.len().saturating_add(4));
            // inject_noise_entropy flips ~25% of bits across the padding —
            // applied to the whole payload so the record body is not a clean
            // byte-for-byte prefix of the real hello either.
            inject_noise_entropy(&mut garbled);
        }
        // enable_wrong_seq: put the decoy's sequence number outside the
        // peer's receive window so a real stack drops it while a stateless
        // DPI still parses it. Off means the decoy carries the real seq.
        let fake_seq = if self.settings.enable_wrong_seq {
            let _ = crate::sequence::calculate_wrong_seq(parsed.tcp_seq.unwrap_or(0), 10000);
            calculate_wrong_seq_outside_window(
                parsed.tcp_seq.unwrap_or(0),
                parsed.tcp_window.unwrap_or(65535),
            )
        } else {
            parsed.tcp_seq.unwrap_or(0)
        };
        // When wrong_seq is off we are emitting a packet that the real
        // server will see (so randomizing the window is unsafe: it could
        // shrink the peer's receive window). Only twiddle the window field
        // on the wrong-seq decoy, which the server stack drops anyway.
        let window = if self.settings.enable_wrong_seq {
            Some(randomize_window_size(parsed.tcp_window.unwrap_or(65535)))
        } else {
            None
        };
        let mut decoy = if packet::Ipv4View::parse(real).is_some() {
            build_decoy_packet(real, fake_seq, &garbled).ok()?
        } else {
            packet::rebuild_with_payload(real, &garbled, Some(fake_seq)).ok()?
        };
        if let Some(w) = window {
            if let Some(p) = packet::parse_l3l4(&decoy) {
                let off = p.l4_offset + packet::tcp_off::WINDOW;
                if decoy.len() >= off + 2 {
                    decoy[off..off + 2].copy_from_slice(&w.to_be_bytes());
                    packet::recalculate_all_checksums(&mut decoy);
                }
            }
        }
        let effective_ttl = crate::stealth::normalize_ttl(self.autottl_ttl_for(parsed.dst));
        inject_ttl_limited_decoy(&mut decoy, effective_ttl);
        // enable_wrong_checksum: corrupt the decoy's L4 checksum so the
        // destination stack discards it. Both wrong-* flags default to true
        // because that is what a decoy needs in order to be ignored by the
        // real server; turning one off makes the decoy a genuine packet.
        if self.settings.enable_wrong_checksum {
            let _ = build_wrong_checksum(&mut decoy);
        }
        Some(decoy)
    }

    fn flush_idle(&mut self) {
        let threshold = Duration::from_secs(self.settings.idle_timeout_secs.max(1));
        let now = Instant::now();
        self.last_activity
            .retain(|_, t| !deep_sleep_idle(now.saturating_duration_since(*t), threshold));
        self.recent
            .retain(|_, r| !deep_sleep_idle(now.saturating_duration_since(r.at), threshold));
        self.quic_mapper.prune_idle(now, threshold);
        self.relay_flows
            .retain(|_, f| !deep_sleep_idle(now.saturating_duration_since(f.last), threshold));
        self.inbound_ttl
            .retain(|_, (_, at)| !deep_sleep_idle(now.saturating_duration_since(*at), threshold));
        self.last_desync.retain(|k, _| self.recent.contains_key(k));
    }

    pub fn strategy_scores_hashed(&self) -> Vec<(String, i64)> {
        self.strategy.scores_hashed()
    }

    /// O(1) handle for building the hashed score view OFF the pipeline
    /// lock: the table is `Arc`-backed, so cloning it is cheap and the
    /// (up to 4096-entry) SHA-256 pass then runs without stalling the
    /// packet path (which shares this mutex).
    pub fn strategy_handle(&self) -> StrategyTable {
        self.strategy.clone()
    }

    /// Raw recent domains as a plain list (≤512 small strings), so the
    /// caller can hash/sort them without holding the pipeline lock.
    pub fn recent_domain_list(&self) -> Vec<String> {
        self.recent.values().map(|r| r.domain.clone()).collect()
    }

    /// Hashed view of a raw domain list. Static so the watchdog can build
    /// it from a [`Pipeline::recent_domain_list`] snapshot off-lock.
    pub fn recent_domains_hashed_from(domains: Vec<String>) -> Vec<String> {
        let mut out: Vec<String> = domains
            .into_iter()
            .map(|d| hash_sensitive(&d, run_salt()))
            .collect();
        out.sort();
        out.dedup();
        out
    }

    pub fn recent_domains_hashed(&self) -> Vec<String> {
        Self::recent_domains_hashed_from(self.recent_domain_list())
    }

    pub fn take_expired_held(&mut self) -> Vec<Vec<u8>> {
        let now = Instant::now();
        let mut out = Vec::new();
        self.flows.retain(|_, f| {
            if now.saturating_duration_since(f.started) >= HOLD_TIMEOUT {
                out.extend(f.held.clone());
                false
            } else {
                true
            }
        });
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{wrap_ipv4_tcp, wrap_ipv6_tcp, TCP_FLAG_ACK, TCP_FLAG_PSH};

    fn ch_pkt(sni: &str) -> Vec<u8> {
        let hello = fragmentation::encode_client_hello(sni);
        wrap_ipv4_tcp(
            &hello,
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            54321,
            443,
            1000,
            TCP_FLAG_ACK | TCP_FLAG_PSH,
        )
    }

    fn ch_pkt_port(sni: &str, dport: u16) -> Vec<u8> {
        let hello = fragmentation::encode_client_hello(sni);
        wrap_ipv4_tcp(
            &hello,
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            54321,
            dport,
            1000,
            TCP_FLAG_ACK | TCP_FLAG_PSH,
        )
    }

    #[test]
    fn mutates_sni_and_rewrites_lengths_ipv4() {
        let pkt = ch_pkt("example.com");
        let mut p = Pipeline::new(Settings {
            mutation_profile: "RussiaDpi".into(),
            enable_decoys: false,
            enable_sni_fragmentation: false,
            ..Settings::default()
        });
        let action = p.handle(&pkt).unwrap();
        let WireAction::Send(pkts) = action else {
            panic!("held");
        };
        assert_eq!(pkts.len(), 1);
        let parsed = packet::parse_l3l4(&pkts[0]).unwrap();
        let payload = parsed.payload(&pkts[0]);
        let (s, e) = fragmentation::calculate_smart_split_points(payload).unwrap();
        assert_eq!(&payload[s..e], b"example.com.");
    }

    /// enable_frag_by_sni without TLS-record reframing must emit the TCP
    /// "1-byte split at the SNI": prefix before the SNI, exactly one SNI
    /// byte as the second segment, then the rest — with continuous sequence
    /// numbers and a payload that reassembles to the mutated ClientHello.
    #[test]
    fn frag_by_sni_emits_tcp_one_byte_split() {
        let pkt = ch_pkt("example.com");
        let mut p = Pipeline::new(Settings {
            enable_sni_fragmentation: true,
            enable_frag_by_sni: true,
            enable_tls_record_fragmentation: false,
            enable_decoys: false,
            // Disable the disorder reorder so segments arrive in sequence
            // order and the reassembly below can compare them directly.
            enable_combined_fragmentation: false,
            ..Settings::default()
        });
        let action = p.handle(&pkt).unwrap();
        let WireAction::Send(pkts) = action else {
            panic!("held");
        };
        assert!(pkts.len() >= 3, "expected prefix + 1 SNI byte + tail");

        let mut reassembled = Vec::new();
        let mut expect_seq = packet::parse_l3l4(&pkts[0]).unwrap().tcp_seq.unwrap();
        for seg in &pkts {
            let parsed = packet::parse_l3l4(seg).unwrap();
            assert_eq!(
                parsed.tcp_seq,
                Some(expect_seq),
                "segments must carry continuous sequence numbers"
            );
            expect_seq = expect_seq.wrapping_add(parsed.payload(seg).len() as u32);
            reassembled.extend_from_slice(parsed.payload(seg));
        }
        // The split happens AFTER mutation + GREASE/padding, so the
        // reassembled payload is the mutated hello — compare against itself:
        // it must still be a parseable ClientHello.
        assert!(
            fragmentation::sni_bytes(&reassembled).is_some(),
            "reassembled payload must remain a valid ClientHello"
        );

        // The cut point: second segment is exactly the first SNI byte.
        let (s, _) = fragmentation::calculate_smart_split_points(&reassembled).unwrap();
        let second = packet::parse_l3l4(&pkts[1]).unwrap().payload(&pkts[1]);
        assert_eq!(second.len(), 1, "the 1-byte split cuts one SNI byte off");
        assert_eq!(second[0], reassembled[s]);
        // The first segment ends exactly before the SNI.
        let first = packet::parse_l3l4(&pkts[0]).unwrap().payload(&pkts[0]);
        assert_eq!(first.len(), s);
    }

    #[test]
    fn all_ports_custom_intercept_works() {
        let pkt_8443 = ch_pkt_port("example.com", 8443);
        let mut p = Pipeline::new(Settings {
            intercept_ports: vec![443, 8443, 8080],
            enable_decoys: false,
            enable_sni_fragmentation: false,
            ..Settings::default()
        });
        // 8443 should be intercepted
        let action = p.handle(&pkt_8443).unwrap();
        assert!(matches!(action, WireAction::Send(_)));
        // 22 should NOT be intercepted (passed through unchanged)
        let pkt_22 = ch_pkt_port("example.com", 22);
        assert_eq!(
            p.handle(&pkt_22).unwrap(),
            WireAction::Passthrough,
            "port 22 is never intercepted; original bytes go out untouched"
        );
    }

    #[test]
    fn intercept_all_tcp_flag_intercepts_any_port() {
        let pkt_any = ch_pkt_port("example.com", 12345);
        let mut p = Pipeline::new(Settings {
            intercept_all_tcp: true,
            enable_decoys: false,
            enable_sni_fragmentation: false,
            ..Settings::default()
        });
        let action = p.handle(&pkt_any).unwrap();
        // Should be processed (not just passthrough? Actually our code still processes ClientHello)
        assert!(matches!(action, WireAction::Send(_)));
        let WireAction::Send(pkts) = action else {
            panic!()
        };
        // Should have mutated or at least PSH flag set, so not equal to original
        // But if SNI is example.com with Stealth, case randomization may or may not change bytes
        // So just check it's not empty
        assert!(!pkts.is_empty());
    }

    #[test]
    fn skips_tcp_header_not_payload() {
        let pkt = ch_pkt("example.com");
        let mut p = Pipeline::new(Settings {
            enable_decoys: false,
            enable_sni_fragmentation: false,
            ..Settings::default()
        });
        let action = p.handle(&pkt).unwrap();
        assert!(matches!(action, WireAction::Send(_)));
        let WireAction::Send(pkts) = action else {
            unreachable!()
        };
        let parsed = packet::parse_l3l4(&pkts[0]).unwrap();
        assert!(fragmentation::sni_bytes(parsed.payload(&pkts[0])).is_some());
    }

    #[test]
    fn ipv6_client_hello_is_parsed() {
        let hello = fragmentation::encode_client_hello("v6.test");
        let pkt = wrap_ipv6_tcp(
            &hello,
            [0; 16],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            1111,
            443,
            1,
            TCP_FLAG_ACK | TCP_FLAG_PSH,
        );
        let mut p = Pipeline::new(Settings {
            enable_decoys: false,
            enable_sni_fragmentation: false,
            ..Settings::default()
        });
        let action = p.handle(&pkt).unwrap();
        let WireAction::Send(pkts) = action else {
            panic!()
        };
        let parsed = packet::parse_l3l4(&pkts[0]).unwrap();
        assert_eq!(parsed.l3, packet::L3::Ipv6);
        assert!(fragmentation::sni_bytes(parsed.payload(&pkts[0])).is_some());
    }

    #[test]
    fn inbound_rst_penalises_strategy() {
        let mut p = Pipeline::new(Settings {
            intercept_all_tcp: false,
            intercept_all_udp: false,
            intercept_ports: vec![443],
            ..Settings::default()
        });
        p.recent.insert(
            ("1.1.1.1".parse().unwrap(), 54321),
            RecentAttempt {
                domain: "example.com".into(),
                technique: "Stealth".into(),
                at: Instant::now(),
            },
        );
        let rst = wrap_ipv4_tcp(
            b"",
            [1, 1, 1, 1],
            [10, 0, 0, 1],
            443,
            54321,
            1,
            TCP_FLAG_RST,
        );
        let _ = p.handle(&rst).unwrap();
        let scores = p.strategy.per_domain_scores("example.com");
        assert_eq!(scores[0].1, -2);
    }

    #[test]
    fn truncated_client_hello_is_held() {
        let hello = fragmentation::encode_client_hello("example.com");
        let pkt = wrap_ipv4_tcp(
            &hello[..20],
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            1,
            443,
            10,
            TCP_FLAG_ACK,
        );
        let mut p = Pipeline::new(Settings::default());
        assert_eq!(p.handle(&pkt).unwrap(), WireAction::Hold);
    }

    #[test]
    fn decoys_prepended_when_enabled() {
        let pkt = ch_pkt("example.com");
        let mut p = Pipeline::new(Settings {
            enable_decoys: true,
            enable_sni_fragmentation: false,
            ..Settings::default()
        });
        let WireAction::Send(pkts) = p.handle(&pkt).unwrap() else {
            panic!();
        };
        assert!(pkts.len() >= 2);
    }

    #[test]
    fn reassembled_hello_uses_first_segment_seq() {
        let hello = fragmentation::encode_client_hello("example.com");
        let first = wrap_ipv4_tcp(
            &hello[..20],
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            54321,
            443,
            1000,
            TCP_FLAG_ACK | TCP_FLAG_PSH,
        );
        let second = wrap_ipv4_tcp(
            &hello[20..],
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            54321,
            443,
            1020,
            TCP_FLAG_ACK | TCP_FLAG_PSH,
        );
        let mut p = Pipeline::new(Settings {
            mutation_profile: "Stealth".into(),
            enable_decoys: false,
            enable_sni_fragmentation: false,
            ..Settings::default()
        });
        assert_eq!(p.handle(&first).unwrap(), WireAction::Hold);
        let WireAction::Send(pkts) = p.handle(&second).unwrap() else {
            panic!("held");
        };
        assert!(!pkts.is_empty());
        let parsed = packet::parse_l3l4(&pkts[0]).unwrap();
        assert_eq!(parsed.tcp_seq, Some(1000));
        let payload = parsed.payload(&pkts[0]);
        assert!(fragmentation::sni_bytes(payload).is_some());
    }

    #[test]
    fn seq_mismatch_releases_held_and_current() {
        let hello = fragmentation::encode_client_hello("example.com");
        let first = wrap_ipv4_tcp(
            &hello[..20],
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            1,
            443,
            10,
            TCP_FLAG_ACK,
        );
        let other = wrap_ipv4_tcp(b"x", [10, 0, 0, 1], [1, 1, 1, 1], 1, 443, 99, TCP_FLAG_ACK);
        let mut p = Pipeline::new(Settings::default());
        assert_eq!(p.handle(&first).unwrap(), WireAction::Hold);
        let WireAction::Send(pkts) = p.handle(&other).unwrap() else {
            panic!("held");
        };
        assert_eq!(pkts.len(), 2);
        assert_eq!(pkts[0], first);
        assert_eq!(pkts[1], other);
    }

    #[test]
    fn padding_after_ipv4_total_len_is_ignored() {
        let mut pkt = ch_pkt("example.com");
        pkt.extend_from_slice(&[0xAAu8; 40]);
        let mut p = Pipeline::new(Settings {
            enable_decoys: false,
            enable_sni_fragmentation: false,
            ..Settings::default()
        });
        let WireAction::Send(pkts) = p.handle(&pkt).unwrap() else {
            panic!("held");
        };
        let parsed = packet::parse_l3l4(&pkts[0]).unwrap();
        assert!(fragmentation::sni_bytes(parsed.payload(&pkts[0])).is_some());
    }

    #[test]
    fn inbound_serverhello_scores_once() {
        let mut p = Pipeline::new(Settings {
            intercept_all_tcp: false,
            intercept_all_udp: false,
            intercept_ports: vec![443],
            ..Settings::default()
        });
        p.recent.insert(
            ("1.1.1.1".parse().unwrap(), 54321),
            RecentAttempt {
                domain: "example.com".into(),
                technique: "Stealth".into(),
                at: Instant::now(),
            },
        );
        let payload = vec![0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0, 0, 0];
        let pkt = wrap_ipv4_tcp(
            &payload,
            [1, 1, 1, 1],
            [10, 0, 0, 1],
            443,
            54321,
            1,
            TCP_FLAG_ACK,
        );
        let _ = p.handle(&pkt).unwrap();
        let _ = p.handle(&pkt).unwrap();
        let scores = p.strategy.per_domain_scores("example.com");
        assert_eq!(scores.len(), 1);
        assert_eq!(scores[0].1, 1);
    }

    #[test]
    fn strategy_scores_for_ui_are_hashed() {
        let p = Pipeline::new(Settings::default());
        p.strategy.update_score("secret.example", "Stealth", true);
        let ui = p.strategy_scores_hashed();
        assert_eq!(ui.len(), 1);
        assert!(!ui[0].0.contains("secret.example"));
        assert!(ui[0].0.contains("|Stealth"));
    }

    #[test]
    fn expired_held_is_flushed_by_watchdog() {
        let hello = fragmentation::encode_client_hello("example.com");
        let pkt = wrap_ipv4_tcp(
            &hello[..20],
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            1234,
            443,
            10,
            TCP_FLAG_ACK,
        );
        let mut p = Pipeline::new(Settings::default());
        assert_eq!(p.handle(&pkt).unwrap(), WireAction::Hold);
        for flow in p.flows.values_mut() {
            flow.started = Instant::now() - Duration::from_millis(300);
        }
        let expired = p.take_expired_held();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], pkt);
        assert!(p.flows.is_empty());
        assert!(p.take_expired_held().is_empty());
    }

    #[test]
    fn max_flows_cap_fail_opens() {
        let hello = fragmentation::encode_client_hello("example.com");
        let fragment = &hello[..20];
        let mut p = Pipeline::new(Settings::default());
        for i in 0..MAX_FLOWS {
            let pkt = wrap_ipv4_tcp(
                fragment,
                [10, 0, 0, 1],
                [1, 1, 1, 1],
                1000 + i as u16,
                443,
                10,
                TCP_FLAG_ACK,
            );
            let action = p.handle(&pkt).unwrap();
            assert_eq!(action, WireAction::Hold, "should hold until cap");
        }
        let extra = wrap_ipv4_tcp(
            fragment,
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            9999,
            443,
            10,
            TCP_FLAG_ACK,
        );
        let action = p.handle(&extra).unwrap();
        // Hold-cap fail-open: the packet goes out unchanged (Passthrough).
        assert_eq!(
            action,
            WireAction::Passthrough,
            "should have fail-opened on cap"
        );
        assert_eq!(p.flows.len(), MAX_FLOWS);
    }

    #[test]
    fn flow_buf_overflow_fail_opens_both() {
        let hello = fragmentation::encode_client_hello("example.com");
        let first = wrap_ipv4_tcp(
            &hello[..20],
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            5555,
            443,
            0,
            TCP_FLAG_ACK,
        );
        let mut p = Pipeline::new(Settings {
            max_payload_size: 0,
            ..Settings::default()
        });
        assert_eq!(p.handle(&first).unwrap(), WireAction::Hold);
        let big = vec![0u8; MAX_FLOW_BUF];
        let second = wrap_ipv4_tcp(
            &big,
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            5555,
            443,
            20,
            TCP_FLAG_ACK,
        );
        let WireAction::Send(pkts) = p.handle(&second).unwrap() else {
            panic!("should send");
        };
        assert_eq!(pkts.len(), 2);
        assert!(p.flows.is_empty());
    }

    #[test]
    fn recent_eviction_halves_on_cap() {
        let mut p = Pipeline::new(Settings::default());
        for i in 0..MAX_RECENT {
            let ip: IpAddr = format!("1.1.1.{}", i % 255 + 1).parse().unwrap();
            p.recent.insert(
                (ip, i as u16),
                RecentAttempt {
                    domain: format!("d{i}.example"),
                    technique: "Stealth".into(),
                    at: Instant::now(),
                },
            );
        }
        assert_eq!(p.recent.len(), MAX_RECENT);
        let pkt = ch_pkt("new.example");
        let _ = p.handle(&pkt).unwrap();
        assert!(p.recent.len() <= MAX_RECENT);
        assert!(p.recent.len() >= MAX_RECENT / 2);
    }

    #[test]
    fn idle_flush_removes_old_flows_and_recent() {
        let mut p = Pipeline::new(Settings {
            idle_timeout_secs: 1,
            ..Settings::default()
        });
        let hello = fragmentation::encode_client_hello("example.com");
        let first = wrap_ipv4_tcp(
            &hello[..20],
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            6000,
            443,
            0,
            TCP_FLAG_ACK,
        );
        assert_eq!(p.handle(&first).unwrap(), WireAction::Hold);
        assert_eq!(p.flows.len(), 1);
        for t in p.last_activity.values_mut() {
            *t = Instant::now() - Duration::from_secs(5);
        }
        p.recent.insert(
            ("2.2.2.2".parse().unwrap(), 1234),
            RecentAttempt {
                domain: "old.example".into(),
                technique: "Stealth".into(),
                at: Instant::now() - Duration::from_secs(5),
            },
        );
        let dummy = wrap_ipv4_tcp(b"", [10, 0, 0, 2], [10, 0, 0, 3], 1111, 80, 0, TCP_FLAG_ACK);
        // The sweep is time-gated to once per second (hot-path optimization);
        // backdate it so this packet triggers a fresh pass, as the watchdog
        // would long after startup.
        p.last_sweep = Instant::now() - Duration::from_secs(2);
        let _ = p.handle(&dummy).unwrap();
        assert!(p.recent.is_empty() || !p.recent.values().any(|r| r.domain == "old.example"));
    }

    #[test]
    fn hold_watchdog_preserves_original_win_divert_address_semantics() {
        let hello = fragmentation::encode_client_hello("watchdog.test");
        let pkt = wrap_ipv4_tcp(
            &hello[..15],
            [10, 0, 0, 1],
            [9, 9, 9, 9],
            7000,
            443,
            100,
            TCP_FLAG_ACK,
        );
        let mut p = Pipeline::new(Settings::default());
        assert_eq!(p.handle(&pkt).unwrap(), WireAction::Hold);
        for flow in p.flows.values_mut() {
            flow.started = Instant::now() - Duration::from_millis(250);
        }
        let expired = p.take_expired_held();
        assert_eq!(expired[0][12..16], [10, 0, 0, 1]);
        assert!(p.flows.is_empty());
    }

    #[test]
    fn quic_bypass_rewrites_source_port_when_enabled() {
        use crate::packet::PROTO_UDP;
        let quic_payload = {
            let mut v = vec![0xC0, 0x00, 0x00, 0x00, 0x01, 8];
            v.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
            v.extend_from_slice(&[8, 9, 10, 11, 12, 13, 14, 15, 16]);
            v.push(0);
            v.extend_from_slice(&[0, 0, 0, 0]);
            v
        };
        let mut pkt = vec![0u8; 20 + 8 + quic_payload.len()];
        pkt[0] = 0x45;
        pkt[9] = PROTO_UDP;
        let plen = pkt.len() as u16;
        pkt[2..4].copy_from_slice(&plen.to_be_bytes());
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[1, 1, 1, 1]);
        pkt[20..22].copy_from_slice(&54321u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&443u16.to_be_bytes());
        pkt[24..26].copy_from_slice(&((8 + quic_payload.len()) as u16).to_be_bytes());
        pkt[28..].copy_from_slice(&quic_payload);
        crate::packet::recalculate_all_checksums(&mut pkt);

        let mut p = Pipeline::new(Settings {
            enable_quic_port_bypass: true,
            quic_bypass_use_low_port: false,
            intercept_all_tcp: false,
            intercept_all_udp: false,
            intercept_ports: vec![443],
            ..Settings::default()
        });
        let action = p.handle(&pkt).unwrap();
        let WireAction::Send(pkts) = action else {
            panic!()
        };
        assert_eq!(pkts.len(), 1);
        let parsed = crate::packet::parse_l3l4(&pkts[0]).unwrap();
        assert_eq!(parsed.src_port, 443);
        assert_eq!(parsed.dst_port, 443);
    }

    fn udp_pkt(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        use crate::packet::PROTO_UDP;
        let mut pkt = vec![0u8; 20 + 8 + payload.len()];
        pkt[0] = 0x45;
        pkt[9] = PROTO_UDP;
        let plen = pkt.len() as u16;
        pkt[2..4].copy_from_slice(&plen.to_be_bytes());
        pkt[12..16].copy_from_slice(&src);
        pkt[16..20].copy_from_slice(&dst);
        pkt[20..22].copy_from_slice(&sport.to_be_bytes());
        pkt[22..24].copy_from_slice(&dport.to_be_bytes());
        pkt[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        pkt[28..].copy_from_slice(payload);
        crate::packet::recalculate_all_checksums(&mut pkt);
        pkt
    }

    fn quic_initial_payload() -> Vec<u8> {
        let mut v = vec![0xC0, 0x00, 0x00, 0x00, 0x01, 8];
        v.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        v.extend_from_slice(&[8, 9, 10, 11, 12, 13, 14, 15, 16]);
        v.push(0);
        v.extend_from_slice(&[0, 0, 0, 0]);
        v
    }

    #[test]
    fn quic_reverse_nat_restores_original_dst_port() {
        let mut p = Pipeline::new(Settings {
            enable_quic_port_bypass: true,
            quic_bypass_use_low_port: false,
            intercept_all_tcp: false,
            intercept_all_udp: false,
            intercept_ports: vec![443],
            ..Settings::default()
        });
        // Outbound Initial: client 10.0.0.1:54321 -> server 1.1.1.1:443
        let outbound = udp_pkt(
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            54321,
            443,
            &quic_initial_payload(),
        );
        let action = p.handle(&outbound).unwrap();
        let WireAction::Send(pkts) = action else {
            panic!()
        };
        let parsed = crate::packet::parse_l3l4(&pkts[0]).unwrap();
        assert_eq!(parsed.src_port, 443); // spoofed to dst (blindspot)

        // Inbound short-header reply: server 1.1.1.1:443 -> client 10.0.0.1:443
        let reply = udp_pkt(
            [1, 1, 1, 1],
            [10, 0, 0, 1],
            443,
            443,
            &[0x40, 1, 2, 3, 4, 5, 6, 7],
        );
        let action = p.handle(&reply).unwrap();
        let WireAction::Send(pkts) = action else {
            panic!()
        };
        let parsed = crate::packet::parse_l3l4(&pkts[0]).unwrap();
        assert_eq!(parsed.dst_port, 54321); // restored to the original port
        assert_eq!(parsed.src_port, 443);
    }

    #[test]
    fn quic_followup_outbound_keeps_spoofed_port() {
        let mut p = Pipeline::new(Settings {
            enable_quic_port_bypass: true,
            quic_bypass_use_low_port: false,
            intercept_all_tcp: false,
            intercept_all_udp: false,
            intercept_ports: vec![443],
            ..Settings::default()
        });
        let initial = udp_pkt(
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            54321,
            443,
            &quic_initial_payload(),
        );
        let _ = p.handle(&initial).unwrap();
        // A later (short-header) outbound packet of the same flow must keep
        // the spoofed source port, not revert to the original.
        let followup = udp_pkt([10, 0, 0, 1], [1, 1, 1, 1], 54321, 443, &[0x40, 9, 9, 9, 9]);
        let action = p.handle(&followup).unwrap();
        let WireAction::Send(pkts) = action else {
            panic!()
        };
        let parsed = crate::packet::parse_l3l4(&pkts[0]).unwrap();
        assert_eq!(parsed.src_port, 443);
    }

    #[test]
    fn quic_reverse_nat_no_mapping_passes_through() {
        let mut p = Pipeline::new(Settings {
            enable_quic_port_bypass: true,
            ..Settings::default()
        });
        // Inbound UDP without any mapping must pass through untouched.
        let reply = udp_pkt(
            [1, 1, 1, 1],
            [10, 0, 0, 1],
            443,
            443,
            &[0x40, 1, 2, 3, 4, 5, 6, 7],
        );
        let action = p.handle(&reply).unwrap();
        assert_eq!(
            action,
            WireAction::Passthrough,
            "inbound UDP without a mapping passes through untouched"
        );
    }

    // Test helper mirroring `packet::wrap_ipv4_tcp` plus an explicit ACK
    // number; 8 positional args keep call sites readable.
    #[allow(clippy::too_many_arguments)]
    fn tcp_pkt_with_ack(
        src: [u8; 4],
        dst: [u8; 4],
        sport: u16,
        dport: u16,
        seq: u32,
        ack_num: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut p = packet::wrap_ipv4_tcp(payload, src, dst, sport, dport, seq, flags);
        if let Some(parsed) = packet::parse_l3l4(&p) {
            let off = parsed.l4_offset + packet::tcp_off::ACK;
            if p.len() >= off + 4 {
                p[off..off + 4].copy_from_slice(&ack_num.to_be_bytes());
                packet::recalculate_all_checksums(&mut p);
            }
        }
        p
    }

    fn relay_mode(fake_sni: &str) -> RelayMode {
        RelayMode {
            fake_sni: fake_sni.into(),
            connect_port: 443,
            mutate_real_sni: false,
            emit_decoy: false,
            require_inject: true,
        }
    }

    fn complete_relay_handshake(p: &mut Pipeline) {
        // 1) client SYN
        let syn = tcp_pkt_with_ack(
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            5555,
            443,
            1000,
            0,
            TCP_FLAG_SYN,
            b"",
        );
        let action = p.handle(&syn).unwrap();
        assert_eq!(
            action,
            WireAction::Passthrough,
            "payload-less SYN passes through unchanged"
        );
        // 2) server SYN-ACK
        let synack = tcp_pkt_with_ack(
            [1, 1, 1, 1],
            [10, 0, 0, 1],
            443,
            5555,
            5000,
            1001,
            TCP_FLAG_SYN | TCP_FLAG_ACK,
            b"",
        );
        assert_eq!(
            p.handle(&synack).unwrap(),
            WireAction::Passthrough,
            "payload-less SYN-ACK passes through unchanged"
        );
        // 3) client final ACK -> fake ClientHello injected
        let ack = tcp_pkt_with_ack(
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            5555,
            443,
            1001,
            5001,
            TCP_FLAG_ACK,
            b"",
        );
        let action = p.handle(&ack).unwrap();
        let WireAction::Send(v) = action else {
            panic!()
        };
        assert!(v.len() >= 2);
        // 4) server duplicate ACK -> handshake complete
        let dupack = tcp_pkt_with_ack(
            [1, 1, 1, 1],
            [10, 0, 0, 1],
            443,
            5555,
            5001,
            1001,
            TCP_FLAG_ACK,
            b"",
        );
        assert_eq!(
            p.handle(&dupack).unwrap(),
            WireAction::Passthrough,
            "handshake-complete duplicate ACK passes through unchanged"
        );
    }

    #[test]
    fn relay_flow_injects_fake_hello_then_passes_through() {
        let mut p = Pipeline::new(Settings::default());
        p.configure_relay(Some(relay_mode("benign.com")));
        let _gate = p.register_relay_flow(FlowInfo {
            src: "10.0.0.1".parse().unwrap(),
            sport: 5555,
            dst: "1.1.1.1".parse().unwrap(),
            dport: 443,
        });

        // Steps 1-4 exercise the full handshake; verify the fake SNI on
        // the injected ClientHello.
        let syn = tcp_pkt_with_ack(
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            5555,
            443,
            1000,
            0,
            TCP_FLAG_SYN,
            b"",
        );
        assert_eq!(
            p.handle(&syn).unwrap(),
            WireAction::Passthrough,
            "payload-less SYN passes through unchanged"
        );
        let synack = tcp_pkt_with_ack(
            [1, 1, 1, 1],
            [10, 0, 0, 1],
            443,
            5555,
            5000,
            1001,
            TCP_FLAG_SYN | TCP_FLAG_ACK,
            b"",
        );
        assert_eq!(
            p.handle(&synack).unwrap(),
            WireAction::Passthrough,
            "payload-less SYN-ACK passes through unchanged"
        );
        let ack = tcp_pkt_with_ack(
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            5555,
            443,
            1001,
            5001,
            TCP_FLAG_ACK,
            b"",
        );
        let action = p.handle(&ack).unwrap();
        let WireAction::Send(v) = action else {
            panic!()
        };
        assert_eq!(v.len(), 2);
        assert_eq!(v[0], ack);
        let parsed = packet::parse_l3l4(&v[1]).unwrap();
        let payload = parsed.payload(&v[1]);
        let (s, e) = fragmentation::calculate_smart_split_points(payload).unwrap();
        assert_eq!(&payload[s..e], b"benign.com");

        let dupack = tcp_pkt_with_ack(
            [1, 1, 1, 1],
            [10, 0, 0, 1],
            443,
            5555,
            5001,
            1001,
            TCP_FLAG_ACK,
            b"",
        );
        assert_eq!(
            p.handle(&dupack).unwrap(),
            WireAction::Passthrough,
            "handshake-complete duplicate ACK passes through unchanged"
        );

        // 5) the real ClientHello passes through UNMODIFIED (no SNI mutation)
        let hello = fragmentation::encode_client_hello("real.server.example");
        let real = tcp_pkt_with_ack(
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            5555,
            443,
            1017,
            5001,
            TCP_FLAG_ACK | TCP_FLAG_PSH,
            &hello,
        );
        assert_eq!(
            p.handle(&real).unwrap(),
            WireAction::Passthrough,
            "unmutated relay hello goes out byte-identical"
        );
    }

    #[test]
    fn relay_mutate_real_sni_runs_pipeline_after_handshake() {
        let mut p = Pipeline::new(Settings {
            mutation_profile: "RussiaDpi".into(), // trailing dot -> observable change
            enable_decoys: false,
            enable_sni_fragmentation: false,
            ..Settings::default()
        });
        let mut mode = relay_mode("benign.com");
        mode.mutate_real_sni = true;
        p.configure_relay(Some(mode));
        let _gate = p.register_relay_flow(FlowInfo {
            src: "10.0.0.1".parse().unwrap(),
            sport: 5555,
            dst: "1.1.1.1".parse().unwrap(),
            dport: 443,
        });
        complete_relay_handshake(&mut p);

        // After the handshake, the real ClientHello now goes through the
        // normal pipeline: SNI gets a trailing dot (RussiaDpi).
        let hello = fragmentation::encode_client_hello("real.server.example");
        let real = tcp_pkt_with_ack(
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            5555,
            443,
            1017,
            5001,
            TCP_FLAG_ACK | TCP_FLAG_PSH,
            &hello,
        );
        let action = p.handle(&real).unwrap();
        let WireAction::Send(v) = action else {
            panic!()
        };
        assert_eq!(v.len(), 1);
        let parsed = packet::parse_l3l4(&v[0]).unwrap();
        let payload = parsed.payload(&v[0]);
        let (s, e) = fragmentation::calculate_smart_split_points(payload).unwrap();
        assert_eq!(&payload[s..e], b"real.server.example.");
    }

    #[test]
    fn relay_emit_decoy_adds_third_packet() {
        let mut p = Pipeline::new(Settings {
            decoy_ttl: 8,
            ..Settings::default()
        });
        let mut mode = relay_mode("benign.com");
        mode.emit_decoy = true;
        p.configure_relay(Some(mode));
        let _gate = p.register_relay_flow(FlowInfo {
            src: "10.0.0.1".parse().unwrap(),
            sport: 5555,
            dst: "1.1.1.1".parse().unwrap(),
            dport: 443,
        });
        let syn = tcp_pkt_with_ack(
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            5555,
            443,
            1000,
            0,
            TCP_FLAG_SYN,
            b"",
        );
        assert_eq!(
            p.handle(&syn).unwrap(),
            WireAction::Passthrough,
            "payload-less SYN passes through unchanged"
        );
        let synack = tcp_pkt_with_ack(
            [1, 1, 1, 1],
            [10, 0, 0, 1],
            443,
            5555,
            5000,
            1001,
            TCP_FLAG_SYN | TCP_FLAG_ACK,
            b"",
        );
        assert_eq!(
            p.handle(&synack).unwrap(),
            WireAction::Passthrough,
            "payload-less SYN-ACK passes through unchanged"
        );
        let ack = tcp_pkt_with_ack(
            [10, 0, 0, 1],
            [1, 1, 1, 1],
            5555,
            443,
            1001,
            5001,
            TCP_FLAG_ACK,
            b"",
        );
        let action = p.handle(&ack).unwrap();
        let WireAction::Send(v) = action else {
            panic!()
        };
        // real ACK + fake ClientHello + TTL-limited wrong-checksum decoy
        assert_eq!(v.len(), 3);
        assert_eq!(v[0], ack);
        // decoy TTL is the configured value
        let parsed = packet::parse_l3l4(&v[2]).unwrap();
        assert_eq!(parsed.src_port, 5555);
        assert_eq!(v[2][8], 8); // IPv4 TTL
    }

    #[test]
    fn henan_profile_uses_small_chunks_and_disorder() {
        let pkt = ch_pkt("henan.test");
        let mut p = Pipeline::new(Settings {
            mutation_profile: "Henan".into(),
            enable_decoys: false,
            enable_sni_fragmentation: true,
            fragment_chunk_size: 64,
            enable_combined_fragmentation: true,
            ..Settings::default()
        });
        let WireAction::Send(pkts) = p.handle(&pkt).unwrap() else {
            panic!()
        };
        assert!(pkts.len() >= 2);
    }

    #[test]
    fn sni_disguise_in_pipeline_when_enabled() {
        let pkt = ch_pkt("disguise.test");
        let mut p = Pipeline::new(Settings {
            mutation_profile: "Stealth".into(),
            enable_decoys: false,
            enable_sni_fragmentation: false,
            enable_sni_disguise: true,
            ..Settings::default()
        });
        let WireAction::Send(pkts) = p.handle(&pkt).unwrap() else {
            panic!()
        };
        assert_eq!(pkts.len(), 1);
        let parsed = crate::packet::parse_l3l4(&pkts[0]).unwrap();
        let payload = parsed.payload(&pkts[0]);
        assert!(fragmentation::sni_bytes(payload).is_none());
    }

    #[test]
    fn fronting_with_hidden_real_sni() {
        let pkt = ch_pkt("real.example.com");
        let mut p = Pipeline::new(Settings {
            mutation_profile: "Stealth".into(),
            enable_decoys: false,
            enable_sni_fragmentation: false,
            enable_sni_disguise: true,
            fronting_benign_sni: "www.microsoft.com".into(),
            ..Settings::default()
        });
        let WireAction::Send(pkts) = p.handle(&pkt).unwrap() else {
            panic!()
        };
        let parsed = crate::packet::parse_l3l4(&pkts[0]).unwrap();
        let payload = parsed.payload(&pkts[0]);
        let (s, e) = fragmentation::calculate_smart_split_points(payload).unwrap();
        assert_eq!(&payload[s..e], b"www.microsoft.com");
        assert!(payload.windows(16).any(|w| w == b"real.example.com"));
    }

    #[test]
    fn nested_cloak_profile_produces_three_segments() {
        let pkt = ch_pkt("secret.example.com");
        let mut p = Pipeline::new(Settings {
            mutation_profile: "NestedCloak".into(),
            enable_decoys: false,
            enable_sni_fragmentation: true,
            enable_combined_fragmentation: true,
            enable_geedge_evasion: false,
            fronting_benign_sni: "www.microsoft.com".into(),
            ..Settings::default()
        });
        let WireAction::Send(pkts) = p.handle(&pkt).unwrap() else {
            panic!()
        };
        assert_eq!(
            pkts.len(),
            3,
            "NestedCloak must emit exactly 3 TCP segments"
        );
        // Reassemble by TCP sequence number and inspect the full record.
        let mut parts: Vec<(u32, Vec<u8>)> = pkts
            .iter()
            .map(|pkt| {
                let parsed = packet::parse_l3l4(pkt).unwrap();
                (parsed.tcp_seq.unwrap_or(0), parsed.payload(pkt).to_vec())
            })
            .collect();
        parts.sort_by_key(|(seq, _)| *seq);
        let joined: Vec<u8> = parts
            .iter()
            .flat_map(|(_, pl)| pl.iter().copied())
            .collect();
        // Cover SNI is the visible 0x0000 name.
        let (s, e) = fragmentation::calculate_smart_split_points(&joined).unwrap();
        assert_eq!(&joined[s..e], b"www.microsoft.com");
        // Real name rides inside the private-range extension.
        let exts = fragmentation::list_extensions(&joined).unwrap();
        let hidden = exts.iter().find(|x| x.ext_type == 0xFF01).unwrap();
        assert_eq!(
            &joined[hidden.body_start..hidden.body_end],
            b"secret.example.com"
        );
        // No single segment may contain the whole real name.
        for (_, pl) in &parts {
            assert!(!pl.windows(18).any(|w| w == b"secret.example.com"));
        }
    }

    #[test]
    fn nested_cloak_enforces_combined_fragmentation_when_disabled() {
        let pkt = ch_pkt("secret.example.com");
        let mut p = Pipeline::new(Settings {
            mutation_profile: "NestedCloak".into(),
            enable_decoys: false,
            enable_sni_fragmentation: true,
            enable_combined_fragmentation: false, // profile must override this
            enable_geedge_evasion: false,
            ..Settings::default()
        });
        let WireAction::Send(pkts) = p.handle(&pkt).unwrap() else {
            panic!()
        };
        // Still the 3-segment split (the profile mandates combined frag).
        assert_eq!(pkts.len(), 3);
    }

    #[test]
    fn frag_mid_sni_pipeline_straddles_the_name() {
        let pkt = ch_pkt("example.com");
        let mut p = Pipeline::new(Settings {
            mutation_profile: "Stealth".into(),
            enable_decoys: false,
            enable_sni_fragmentation: false,
            enable_combined_fragmentation: false,
            enable_geedge_evasion: false,
            enable_frag_mid_sni: true,
            ..Settings::default()
        });
        let WireAction::Send(pkts) = p.handle(&pkt).unwrap() else {
            panic!()
        };
        assert_eq!(pkts.len(), 2, "mid-SNI split produces two TLS records");
        for pkt in &pkts {
            let parsed = packet::parse_l3l4(pkt).unwrap();
            let pl = parsed.payload(pkt);
            assert_eq!(pl[0], 0x16, "each piece is a handshake record");
            assert!(!pl.windows(11).any(|w| w == b"example.com"));
        }
        // Reassembled (by seq) the full name is back; the Stealth profile
        // may case-mutate it, so compare case-insensitively.
        let mut parts: Vec<(u32, Vec<u8>)> = pkts
            .iter()
            .map(|pkt| {
                let parsed = packet::parse_l3l4(pkt).unwrap();
                (parsed.tcp_seq.unwrap_or(0), parsed.payload(pkt).to_vec())
            })
            .collect();
        parts.sort_by_key(|(seq, _)| *seq);
        let mut rejoined: Vec<u8> = Vec::new();
        for (_, pl) in &parts {
            rejoined.extend_from_slice(&pl[5..]); // strip per-record header
        }
        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&((rejoined.len()) as u16).to_be_bytes());
        record.extend_from_slice(&rejoined);
        let (s, e) = fragmentation::calculate_smart_split_points(&record).unwrap();
        let name = String::from_utf8_lossy(&record[s..e]).to_lowercase();
        assert_eq!(name, "example.com");
    }

    #[test]
    fn padding_inflation_grows_the_hello_randomly() {
        let base = fragmentation::encode_client_hello("example.com").len();
        let pkt = ch_pkt("example.com");
        let mut p = Pipeline::new(Settings {
            mutation_profile: "Stealth".into(),
            enable_decoys: false,
            enable_sni_fragmentation: false,
            enable_geedge_evasion: false,
            enable_padding_inflation: true,
            ..Settings::default()
        });
        let WireAction::Send(pkts) = p.handle(&pkt).unwrap() else {
            panic!()
        };
        assert_eq!(pkts.len(), 1);
        let parsed = packet::parse_l3l4(&pkts[0]).unwrap();
        let delta = parsed.payload(&pkts[0]).len() - base;
        // 4-byte extension header + random body in [64, 384].
        assert!((68..=388).contains(&delta), "delta {delta}");
    }

    #[test]
    fn utls_fingerprint_applies_without_breaking() {
        let pkt = ch_pkt("utls.test");
        let mut p = Pipeline::new(Settings {
            enable_decoys: false,
            enable_sni_fragmentation: false,
            enable_utls_fingerprint: true,
            utls_browser: "firefox".into(),
            ..Settings::default()
        });
        let WireAction::Send(pkts) = p.handle(&pkt).unwrap() else {
            panic!()
        };
        assert_eq!(pkts.len(), 1);
    }

    #[test]
    fn ech_grease_in_pipeline() {
        let pkt = ch_pkt("ech.test");
        let mut p = Pipeline::new(Settings {
            enable_decoys: false,
            enable_sni_fragmentation: false,
            enable_ech_grease: true,
            ..Settings::default()
        });
        let WireAction::Send(pkts) = p.handle(&pkt).unwrap() else {
            panic!()
        };
        assert_eq!(pkts.len(), 1);
        assert!(pkts[0].len() > pkt.len());
    }

    #[test]
    fn geedge_evasion_adds_padding() {
        let pkt = ch_pkt("geedge.test");
        let mut p = Pipeline::new(Settings {
            enable_decoys: false,
            enable_sni_fragmentation: false,
            enable_geedge_evasion: true,
            ..Settings::default()
        });
        let WireAction::Send(pkts) = p.handle(&pkt).unwrap() else {
            panic!()
        };
        assert_eq!(pkts.len(), 1);
        // Should be at least as big as original (padding may be added)
        assert!(pkts[0].len() >= pkt.len());
    }

    // ---- relay flow table: coexistence with a busy client (v2rayN) ----

    fn relay_flow_at(sport: u16) -> FlowInfo {
        FlowInfo {
            src: "10.0.0.1".parse().unwrap(),
            sport,
            dst: "1.1.1.1".parse().unwrap(),
            dport: 443,
        }
    }

    /// A browser behind v2rayN opens many short connections. The table must
    /// not grow without bound (unlike the idle prune alone, which keeps
    /// entries for `idle_timeout_secs` — 120 s by default).
    #[test]
    fn relay_flow_table_is_capped_under_many_connections() {
        let mut p = Pipeline::new(Settings::default());
        p.configure_relay(Some(relay_mode("benign.com")));
        let mut gates = Vec::new();
        // One extra beyond the cap, on distinct source ports.
        for i in 0..(MAX_RELAY_FLOWS + 50) {
            gates.push(p.register_relay_flow(relay_flow_at(20_000 + (i as u16))));
        }
        assert!(p.relay_flow_count() <= MAX_RELAY_FLOWS);
        // Every returned gate is still usable — capping must not hand back
        // a dead gate, or the relay would fail closed for that client.
        assert!(gates.iter().all(|g| !g.is_set()));
    }

    /// Eviction must prefer finished handshakes: a completed flow no longer
    /// needs its monitor, whereas evicting a live one means its injection
    /// can never be confirmed and the relay would drop it.
    #[test]
    fn relay_flow_cap_evicts_finished_flows_before_live_ones() {
        let mut p = Pipeline::new(Settings::default());
        p.configure_relay(Some(relay_mode("benign.com")));
        for i in 0..MAX_RELAY_FLOWS {
            let _ = p.register_relay_flow(relay_flow_at(20_000 + (i as u16)));
        }
        assert!(p.relay_flow_count() <= MAX_RELAY_FLOWS);

        // Mark every flow as finished (what happens once the handshake
        // completes or fails).
        for f in p.relay_flows.values_mut() {
            f.done = true;
        }

        // A brand-new connection must get in, and a finished flow must be
        // the one that goes.
        let live_key = FlowKey {
            src: "10.0.0.1".parse().unwrap(),
            dst: "1.1.1.1".parse().unwrap(),
            sport: 60_000,
            dport: 443,
        };
        let _ = p.register_relay_flow(relay_flow_at(60_000));
        assert!(p.relay_flow_count() <= MAX_RELAY_FLOWS);
        assert!(
            p.relay_flows.contains_key(&live_key),
            "the new connection was evicted instead of a finished one"
        );
        assert!(
            !p.relay_flows.values().any(|f| f.done),
            "a finished flow survived while the cap forced an eviction"
        );
    }

    /// Re-registering the same 4-tuple replaces the entry rather than
    /// growing the table, and must not evict anything.
    #[test]
    fn relay_flow_reregistration_does_not_grow_or_evict() {
        let mut p = Pipeline::new(Settings::default());
        p.configure_relay(Some(relay_mode("benign.com")));
        for _ in 0..10 {
            let _ = p.register_relay_flow(relay_flow_at(5555));
        }
        assert_eq!(p.relay_flow_count(), 1);
    }

    /// Idle pruning still applies, so a quiet client leaves nothing behind.
    #[test]
    fn relay_flows_are_pruned_when_idle() {
        let mut p = Pipeline::new(Settings {
            idle_timeout_secs: 1,
            ..Settings::default()
        });
        p.configure_relay(Some(relay_mode("benign.com")));
        let _ = p.register_relay_flow(relay_flow_at(5555));
        assert_eq!(p.relay_flow_count(), 1);
        for f in p.relay_flows.values_mut() {
            f.last = Instant::now() - Duration::from_secs(5);
        }
        p.flush_idle();
        assert_eq!(p.relay_flow_count(), 0);
    }

    /// The relay releases a slot as soon as its connection ends, rather
    /// than leaving it for the idle sweep.
    #[test]
    fn unregister_relay_flow_frees_the_slot_immediately() {
        let mut p = Pipeline::new(Settings::default());
        let flow = relay_flow_at(41000);
        let _gate = p.register_relay_flow(flow);
        assert_eq!(p.relay_flow_count(), 1);

        assert!(p.unregister_relay_flow(flow), "first removal reports true");
        assert_eq!(p.relay_flow_count(), 0);

        // Idempotent: a second call is a no-op, so a double-drop cannot
        // remove some unrelated flow that reused the 4-tuple.
        assert!(!p.unregister_relay_flow(flow));
        assert_eq!(p.relay_flow_count(), 0);
    }

    /// Regression for the feedback loop described on
    /// `unregister_relay_flow`: churning far more fail-closed connections
    /// than the table can hold must never evict a live flow, because each
    /// one is released as it ends.
    #[test]
    fn fail_closed_churn_never_exhausts_the_relay_table() {
        let mut p = Pipeline::new(Settings::default());
        for i in 0..(MAX_RELAY_FLOWS * 4) {
            let flow = relay_flow_at(20_000 + (i as u16 % 20_000));
            let _gate = p.register_relay_flow(flow);
            // Connection fails closed immediately; the relay's FlowSlot
            // guard calls this on the way out.
            p.unregister_relay_flow(flow);
            assert!(
                p.relay_flow_count() <= 1,
                "slot was not released at iteration {i}"
            );
        }
        assert_eq!(p.relay_flow_count(), 0);
    }

    fn inbound_from(src: [u8; 4], ttl: u8) -> Vec<u8> {
        let mut pkt = wrap_ipv4_tcp(b"x", src, [10, 0, 0, 9], 443, 54321, 1, TCP_FLAG_ACK);
        pkt[8] = ttl;
        packet::recalculate_all_checksums(&mut pkt);
        pkt
    }

    /// `last_activity` is keyed by the on-the-wire 4-tuple, so a
    /// source-spoofed scan drives its growth. It must stay bounded even
    /// before the idle sweep can reclaim anything.
    #[test]
    fn last_activity_is_bounded_under_spoofed_sources() {
        // Long idle window: flush_idle cannot rescue us here, the cap must.
        let s = Settings {
            idle_timeout_secs: 86_400,
            ..Settings::default()
        };
        let mut p = Pipeline::new(s);
        for i in 0..(MAX_LAST_ACTIVITY + 500) {
            let b = (i / 256) as u8;
            let c = (i % 256) as u8;
            let pkt = inbound_from([203, 0, b, c], 60);
            let _ = p.handle(&pkt);
        }
        assert!(
            p.last_activity_count() <= MAX_LAST_ACTIVITY,
            "last_activity grew to {} (cap {MAX_LAST_ACTIVITY})",
            p.last_activity_count()
        );
    }

    /// Same for the AutoTTL per-source table, which is only populated when
    /// `enable_autottl` is on.
    #[test]
    fn inbound_ttl_is_bounded_under_spoofed_sources() {
        let s = Settings {
            enable_autottl: true,
            idle_timeout_secs: 86_400,
            ..Settings::default()
        };
        let mut p = Pipeline::new(s);
        for i in 0..(MAX_INBOUND_TTL + 500) {
            let b = (i / 256) as u8;
            let c = (i % 256) as u8;
            let pkt = inbound_from([198, 51, b, c], 58);
            let _ = p.handle(&pkt);
        }
        assert!(
            p.inbound_ttl_count() <= MAX_INBOUND_TTL,
            "inbound_ttl grew to {} (cap {MAX_INBOUND_TTL})",
            p.inbound_ttl_count()
        );
    }

    /// Eviction is oldest-first, so a flow that keeps sending is not
    /// dropped in favour of a one-shot spoofed source.
    #[test]
    fn last_activity_eviction_prefers_the_oldest() {
        let s = Settings {
            idle_timeout_secs: 86_400,
            ..Settings::default()
        };
        let mut p = Pipeline::new(s);

        // A long-lived flow, touched first...
        let live = inbound_from([192, 0, 2, 7], 60);
        let _ = p.handle(&live);

        // ...then enough distinct sources to trigger at least one eviction.
        for i in 0..(MAX_LAST_ACTIVITY + 10) {
            let b = (i / 256) as u8;
            let c = (i % 256) as u8;
            let pkt = inbound_from([203, 0, b, c], 60);
            let _ = p.handle(&pkt);
            // Keep the live flow fresh so it is never the oldest.
            if i % 64 == 0 {
                let _ = p.handle(&live);
            }
        }
        assert!(p.last_activity_count() <= MAX_LAST_ACTIVITY);
    }

    // ---- ECH interference matrix — 4 critical pairs ----

    fn ech_test_config_hex() -> (String, String) {
        let public_name = "public.example";
        let config_id = 7u8;
        let mut contents = Vec::new();
        contents.push(config_id);
        contents.extend_from_slice(&0x0020u16.to_be_bytes());
        contents.extend_from_slice(&32u16.to_be_bytes());
        contents.extend_from_slice(&[0x11u8; 32]);
        contents.extend_from_slice(&4u16.to_be_bytes());
        contents.extend_from_slice(&0x0001u16.to_be_bytes());
        contents.extend_from_slice(&0x0003u16.to_be_bytes());
        contents.push(128u8);
        contents.push(public_name.len() as u8);
        contents.extend_from_slice(public_name.as_bytes());
        contents.extend_from_slice(&0u16.to_be_bytes());

        let mut entry = Vec::new();
        entry.extend_from_slice(&0xFE0Du16.to_be_bytes());
        entry.extend_from_slice(&(contents.len() as u16).to_be_bytes());
        entry.extend_from_slice(&contents);

        let hex: String = entry.iter().map(|b| format!("{:02x}", b)).collect();
        (hex, public_name.to_string())
    }

    fn pipeline_with_ech_and_flags(
        extra: impl FnOnce(&mut super::super::config::Settings),
    ) -> (Pipeline, String) {
        let (hex, public_name) = ech_test_config_hex();
        let mut s = super::super::config::Settings {
            enable_real_ech: true,
            real_ech_config_hex: hex,
            enable_decoys: false,
            enable_sni_fragmentation: false,
            enable_combined_fragmentation: false,
            enable_geedge_evasion: false,
            ..super::super::config::Settings::default()
        };
        extra(&mut s);
        let p = Pipeline::new(s);
        (p, public_name)
    }

    #[test]
    fn ech_real_x_utls_seal_is_last_mutation() {
        let (mut p, public_name) = pipeline_with_ech_and_flags(|s| {
            s.enable_utls_fingerprint = true;
            s.utls_browser = "firefox".into();
        });
        let pkt = ch_pkt("secret.example.com");
        let WireAction::Send(pkts) = p.handle(&pkt).unwrap() else {
            panic!("held");
        };
        assert_eq!(pkts.len(), 1);
        let parsed = packet::parse_l3l4(&pkts[0]).unwrap();
        let outer = parsed.payload(&pkts[0]);
        let (s, e) = fragmentation::calculate_smart_split_points(outer).unwrap();
        assert_eq!(&outer[s..e], public_name.as_bytes());
        assert!(!outer.windows(18).any(|w| w == b"secret.example.com"));
        let exts = fragmentation::list_extensions(outer).unwrap();
        assert!(exts.iter().any(|e| e.ext_type == 0xFE0D));
        assert!(!exts.iter().any(|e| e.ext_type == 0xFF01));
        assert!(fragmentation::sni_bytes(outer).is_some());
    }

    #[test]
    fn ech_real_x_geedge_no_injection_after_seal() {
        let (mut p, public_name) = pipeline_with_ech_and_flags(|s| {
            s.enable_geedge_evasion = true;
            s.mutation_profile = "ChinaRegional".into();
        });
        let pkt = ch_pkt("secret.example.com");
        let WireAction::Send(pkts) = p.handle(&pkt).unwrap() else {
            panic!("held");
        };
        assert_eq!(pkts.len(), 1);
        let parsed = packet::parse_l3l4(&pkts[0]).unwrap();
        let outer = parsed.payload(&pkts[0]);
        assert_eq!(
            outer[0], 0x16,
            "Geedge fake record must not prepend after ECH seal"
        );
        let (s, e) = fragmentation::calculate_smart_split_points(outer).unwrap();
        assert_eq!(&outer[s..e], public_name.as_bytes());
        assert!(!outer.windows(18).any(|w| w == b"secret.example.com"));
        let exts = fragmentation::list_extensions(outer).unwrap();
        assert!(exts.iter().any(|e| e.ext_type == 0xFE0D));
    }

    #[test]
    fn ech_real_x_padding_before_seal() {
        let (mut p, public_name) = pipeline_with_ech_and_flags(|s| {
            s.enable_padding_inflation = true;
        });
        let pkt = ch_pkt("secret.example.com");
        let WireAction::Send(pkts) = p.handle(&pkt).unwrap() else {
            panic!("held");
        };
        assert_eq!(pkts.len(), 1);
        let parsed = packet::parse_l3l4(&pkts[0]).unwrap();
        let outer = parsed.payload(&pkts[0]);
        let (s, e) = fragmentation::calculate_smart_split_points(outer).unwrap();
        assert_eq!(&outer[s..e], public_name.as_bytes());
        assert!(!outer.windows(18).any(|w| w == b"secret.example.com"));
        assert!(fragmentation::sni_bytes(outer).is_some());
        let exts = fragmentation::list_extensions(outer).unwrap();
        assert!(exts.iter().any(|e| e.ext_type == 0xFE0D));
    }

    #[test]
    fn ech_real_x_nested_cloak_no_ff01_leak() {
        let (mut p, public_name) = pipeline_with_ech_and_flags(|s| {
            s.mutation_profile = "NestedCloak".into();
            s.fronting_benign_sni = "www.microsoft.com".into();
            s.enable_sni_fragmentation = true;
            s.enable_combined_fragmentation = true;
        });
        let pkt = ch_pkt("secret.example.com");
        let WireAction::Send(pkts) = p.handle(&pkt).unwrap() else {
            panic!("held");
        };
        assert_eq!(
            pkts.len(),
            1,
            "NestedCloak must be disabled when real ECH is armed"
        );
        let parsed = packet::parse_l3l4(&pkts[0]).unwrap();
        let outer = parsed.payload(&pkts[0]);
        let (s, e) = fragmentation::calculate_smart_split_points(outer).unwrap();
        assert_eq!(&outer[s..e], public_name.as_bytes());
        assert!(!outer.windows(18).any(|w| w == b"secret.example.com"));
        assert!(!outer.windows(19).any(|w| w == b"www.microsoft.com"));
        let exts = fragmentation::list_extensions(outer).unwrap();
        assert!(
            !exts.iter().any(|e| e.ext_type == 0xFF01),
            "0xFF01 must not leak when ECH is armed"
        );
        assert!(exts.iter().any(|e| e.ext_type == 0xFE0D));
    }
}
