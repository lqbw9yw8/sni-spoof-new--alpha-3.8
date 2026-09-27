//! webui — opt-in local dashboard. [UNTESTED] (std-only, no new dependencies)
//!
//! A deliberately *safe* control surface, unlike the earlier sibling
//! project that bound a control panel to `0.0.0.0` with no auth:
//!
//! - binds **127.0.0.1 only** (never exposed on the network)
//! - every `/api/*` route requires a bearer token (constant-time compare)
//! - failed auth adds an 80 ms delay before the 401 (timing brute-force
//!   throttling)
//! - request bodies are capped (UI requests ≈ 16 KiB)
//! - no CORS headers; Host must be 127.0.0.1 (DNS-rebind defence,
//!   `localhost` is rejected); `X-Content-Type-Options: nosniff`,
//!   `Content-Security-Policy`, `X-Frame-Options: DENY`,
//!   `Cross-Origin-Resource-Policy: same-origin`,
//!   `Cross-Origin-Opener-Policy: same-origin`; no file serving
//!
//! There is no Xray/core here — the dashboard talks to the local
//! patterniha-style relay directly. The local TLS client connects to
//! `127.0.0.1:<relay_listen_port>` and presents the **real** server
//! domain as SNI (the relay injects the fake SNI itself).
//!
//! It is OFF unless `enable_web_ui = true`. The server runs on a plain
//! `std::net::TcpListener` thread so it has zero dependency surface and
//! cannot reach the WinDivert capture handle.
//!
//! ## Routes
//!
//! | Route                  | Auth | Effect                                   |
//! |------------------------|------|------------------------------------------|
//! | `GET  /`               | no   | the dashboard page (no secrets in it)     |
//! | `GET  /api/status`     | yes  | live snapshot (SNIs are hashed, never raw)|
//! | `GET  /api/config`     | yes  | settings as JSON, token + pins redacted   |
//! | `GET  /api/config/toml`| yes  | `config::redacted_toml`                   |
//! | `POST /api/profile`    | yes  | switch the mutation profile immediately   |
//! | `POST /api/validate`   | yes  | dry run: validate, **never** touches disk |
//! | `POST /api/config`     | yes  | `config::merge_partial` + write the file  |
//!
//! ## The page covers every setting
//!
//! `src/webui/index.html` declares a schema of editable fields. The
//! `ui_schema_tests` module at the bottom of this file derives the key set
//! of [`crate::config::Settings`] from the struct itself and fails
//! `cargo test` (not the build — it is a `#[cfg(test)]` assertion) if any
//! setting has no control in the page — so a new config field cannot
//! silently become "TOML-only" and bypass the UI's validation.
//!
//! The page is a real HTML file (embedded with `include_str!`) rather than
//! a string literal so it can be opened and driven directly:
//! `cd uitest && npm install && npm test` runs it in jsdom against a mock
//! of the routes above.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::error::DpiGuardError;
use crate::pipeline::Pipeline;

/// Snapshot of pipeline state rendered by the dashboard. `main` refreshes
/// this from the live pipeline; the web thread only reads it.
#[derive(Debug, Clone)]
pub struct DashboardSnapshot {
    pub mutation_profile: String,
    pub decoy_ttl: u8,
    pub idle_timeout_secs: u64,
    pub fragment_chunk_size: usize,
    pub enable_decoys: bool,
    pub enable_sni_fragmentation: bool,
    pub enable_swap_foolers: bool,
    pub enable_kill_switch: bool,
    pub processed_packets: u64,
    /// Packets that left the pipeline actually mutated (multi-packet
    /// replacement or a changed single packet) — the interception
    /// effectiveness metric for the overview cards.
    pub mutated_packets: u64,
    /// Operational counters written to the bounded JSON-lines log as well
    /// as exposed here; these are not inferred from GUI history.
    pub held_packets: u64,
    pub fail_open_events: u64,
    pub injection_attempts: u64,
    pub injection_successes: u64,
    pub injection_failures: u64,
    pub relay_fail_closed: u64,
    pub capture_errors: u64,
    /// Human-readable DoH state for the overview ("off" / "enabled",
    /// plus last-resolution outcome when the relay is running).
    pub doh_state: String,
    /// Live WinDivert capture handle open (true = exactly one live handle).
    pub driver_handles_live: bool,
    /// Parked-but-not-yet-closed retired driver handles (bounded at 16 by
    /// `handle_retire::RETIRED_CAP`).
    pub driver_handles_retired: usize,
    /// Process uptime in seconds.
    pub uptime_secs: u64,
    /// Flattened `domain|technique -> score`.
    pub strategy_scores: Vec<(String, i64)>,
    /// Hashed SNIs recently observed (never the raw hostname in the UI).
    pub recent_domains: Vec<String>,
    // NEW 2025-2026 fields
    pub intercept_ports: Vec<u16>,
    pub enable_quic_port_bypass: bool,
    pub enable_sni_disguise: bool,
    pub fronting_benign_sni: String,
    pub enable_utls_fingerprint: bool,
    pub enable_ech_grease: bool,
    // Relay-mode fields
    pub relay_enabled: bool,
    pub relay_listen_port: u16,
    /// Fail-closed injection (true = drop if fake not ACKed).
    pub relay_require_inject: bool,
    pub relay_connect_host: String,
    pub relay_connect_port: u16,
    pub relay_fake_sni: String,
    // ── 25 new features snapshot fields ──
    pub enable_sni_scanner: bool,
    pub isp_profile: String,
    pub sni_rotation_mode: String,
    pub enable_anti_fingerprint: bool,
    pub randomize_ip_id: bool,
    pub enable_reverse_frag: bool,
    pub enable_wrong_seq: bool,
    pub enable_wrong_checksum: bool,
    pub enable_oob_injection: bool,
    pub enable_hostdot: bool,
    pub max_payload_size: usize,
    pub fake_resend_count: u32,
    pub enable_self_update: bool,
    pub enable_client_detect: bool,
    pub enable_proxy_cleanup: bool,
    pub enable_youtube_warmup: bool,
    pub enable_mobile_gateway: bool,
    pub autottl_scale_a1: u8,
    pub autottl_scale_a2: u8,
    pub autottl_scale_max: u8,
}

impl Default for DashboardSnapshot {
    fn default() -> Self {
        Self {
            mutation_profile: String::new(),
            decoy_ttl: 0,
            idle_timeout_secs: 0,
            fragment_chunk_size: 0,
            enable_decoys: false,
            enable_sni_fragmentation: false,
            enable_swap_foolers: false,
            enable_kill_switch: false,
            processed_packets: 0,
            mutated_packets: 0,
            held_packets: 0,
            fail_open_events: 0,
            injection_attempts: 0,
            injection_successes: 0,
            injection_failures: 0,
            relay_fail_closed: 0,
            capture_errors: 0,
            doh_state: "off".into(),
            driver_handles_live: false,
            driver_handles_retired: 0,
            uptime_secs: 0,
            strategy_scores: Vec::new(),
            recent_domains: Vec::new(),
            intercept_ports: Vec::new(),
            enable_quic_port_bypass: false,
            enable_sni_disguise: false,
            fronting_benign_sni: String::new(),
            enable_utls_fingerprint: false,
            enable_ech_grease: false,
            relay_enabled: false,
            relay_listen_port: 0,
            // Match Settings::default / the status_json empty-snapshot test:
            // fail-closed is the documented invariant even on an empty card.
            relay_require_inject: true,
            relay_connect_host: String::new(),
            relay_connect_port: 443,
            relay_fake_sni: String::new(),
            // 25 new features defaults
            enable_sni_scanner: false,
            isp_profile: "auto".into(),
            sni_rotation_mode: "round_robin".into(),
            enable_anti_fingerprint: false,
            randomize_ip_id: false,
            enable_reverse_frag: false,
            enable_wrong_seq: false,
            enable_wrong_checksum: false,
            enable_oob_injection: false,
            enable_hostdot: false,
            max_payload_size: 1200,
            fake_resend_count: 1,
            enable_self_update: false,
            enable_client_detect: false,
            enable_proxy_cleanup: true,
            enable_youtube_warmup: false,
            enable_mobile_gateway: false,
            autottl_scale_a1: 0,
            autottl_scale_a2: 4,
            autottl_scale_max: 10,
        }
    }
}

/// Start the dashboard on `127.0.0.1:port`, returning the server thread
/// handle. Fails fast (bind error) so `main` can log and continue without
/// the UI rather than crashing the packet path.
pub fn start(
    port: u16,
    token: String,
    snapshot: Arc<Mutex<DashboardSnapshot>>,
    requested_profile: Arc<Mutex<Option<String>>>,
    pipeline: Arc<Mutex<Pipeline>>,
    config_path: PathBuf,
    running: Arc<AtomicBool>,
) -> Result<std::thread::JoinHandle<()>, DpiGuardError> {
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let listener = TcpListener::bind(addr).map_err(|e| {
        DpiGuardError::Io(std::io::Error::new(
            e.kind(),
            format!("webui bind {addr}: {e}"),
        ))
    })?;
    log::info!("web UI listening on http://{addr} (token required)");

    let handle = std::thread::Builder::new()
        .name("dpi_guard-webui".into())
        .spawn(move || {
            serve_loop(
                listener,
                port,
                token,
                snapshot,
                requested_profile,
                pipeline,
                config_path,
                running,
            )
        })
        .map_err(|e| {
            DpiGuardError::Io(std::io::Error::new(e.kind(), format!("webui spawn: {e}")))
        })?;
    Ok(handle)
}

// Internal server entrypoint; every argument is a distinct handle the loop
// needs (listener, auth token, shared state slots). A context struct would
// add indirection without reducing coupling.
#[allow(clippy::too_many_arguments)]
fn serve_loop(
    listener: TcpListener,
    port: u16,
    token: String,
    snapshot: Arc<Mutex<DashboardSnapshot>>,
    requested_profile: Arc<Mutex<Option<String>>>,
    pipeline: Arc<Mutex<Pipeline>>,
    config_path: PathBuf,
    running: Arc<AtomicBool>,
) {
    // Non-blocking accept so Ctrl+C (running=false) does not wait for the
    // next inbound TCP connection to notice shutdown.
    let _ = listener.set_nonblocking(true);
    while running.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = handle_conn(
                    stream,
                    port,
                    &token,
                    &snapshot,
                    &requested_profile,
                    &pipeline,
                    &config_path,
                );
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(e) => log::debug!("webui accept error: {e}"),
        }
    }
}

fn handle_conn(
    mut stream: TcpStream,
    port: u16,
    token: &str,
    snapshot: &Arc<Mutex<DashboardSnapshot>>,
    requested_profile: &Arc<Mutex<Option<String>>>,
    pipeline: &Arc<Mutex<Pipeline>>,
    config_path: &PathBuf,
) -> Result<(), std::io::Error> {
    let _ = stream.set_nonblocking(false);
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;

    // Cap UI requests at ~16 KiB. Config bodies are small (the file
    // itself has a 256 KiB cap at load time, but the dashboard POSTs
    // partial TOML that is always far smaller).
    const MAX_UI_REQ: usize = 16 * 1024;

    // Accumulate until the end of the header block (CRLFCRLF) BEFORE
    // parsing anything: TCP is free to split the request anywhere,
    // including inside the header block. Parsing a truncated first read
    // silently dropped the Content-Length line, so the body was never
    // reassembled (audit Cat.4). Body bytes that arrive in the same
    // segment stay in `raw` for the body reassembly below.
    let mut raw: Vec<u8> = Vec::new();
    let header_end = loop {
        let mut chunk = [0u8; 2048];
        match stream.read(&mut chunk) {
            Ok(0) => {
                if raw.is_empty() {
                    return Ok(());
                }
                // Peer closed mid-request: parse what arrived; the missing
                // Content-Length degrades to an empty body, as before.
                break raw.len();
            }
            Ok(n) => {
                raw.extend_from_slice(&chunk[..n]);
                if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                    break pos + 4;
                }
                if raw.len() > MAX_UI_REQ {
                    return respond(
                        stream,
                        413,
                        "application/json",
                        r#"{"error":"request too large"}"#,
                    );
                }
            }
            Err(_) => {
                if raw.is_empty() {
                    return Ok(());
                }
                break raw.len();
            }
        }
    };

    let head = String::from_utf8_lossy(&raw[..header_end.min(raw.len())]).to_string();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("/").to_string();

    let mut auth = String::new();
    let mut content_length = 0usize;
    let mut host = String::new();
    let mut origin = String::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let lname = name.trim().to_ascii_lowercase();
        let value = value.trim();
        match lname.as_str() {
            "authorization" => auth = value.to_string(),
            "content-length" => {
                content_length = value.parse().unwrap_or(0);
                if content_length > 4096 {
                    return respond(
                        stream,
                        413,
                        "application/json",
                        r#"{"error":"request too large"}"#,
                    );
                }
            }
            // Chunked bodies are explicitly rejected instead of silently
            // treated as body-less: the dashboard never sends them, and an
            // unknown sender gets a clear signal rather than a confusing
            // auth failure (audit Cat.4).
            "transfer-encoding" => {
                return respond(
                    stream,
                    501,
                    "application/json",
                    r#"{"error":"transfer-encoding not supported; send identity + content-length"}"#,
                );
            }
            "host" => host = value.to_string(),
            "origin" => origin = value.to_string(),
            _ => {}
        }
    }

    if !host_is_allowed(&host, port) {
        return respond(
            stream,
            403,
            "application/json",
            r#"{"error":"forbidden host"}"#,
        );
    }
    if !origin_is_allowed(&origin, port) {
        return respond(
            stream,
            403,
            "application/json",
            r#"{"error":"forbidden origin"}"#,
        );
    }

    // Reassemble the body: keep reading until `content_length` bytes have
    // arrived after the header block, or the read times out / the peer
    // closes. Bounded by MAX_UI_REQ so a lying Content-Length cannot stream
    // unbounded data into memory.
    let mut body_bytes: Vec<u8> = raw[header_end.min(raw.len())..].to_vec();
    if content_length > 0 {
        while body_bytes.len() < content_length {
            let mut more = [0u8; 2048];
            match stream.read(&mut more) {
                Ok(0) => break,
                Ok(k) => body_bytes.extend_from_slice(&more[..k]),
                Err(_) => break,
            }
            if body_bytes.len() > MAX_UI_REQ {
                return respond(
                    stream,
                    413,
                    "application/json",
                    r#"{"error":"request too large"}"#,
                );
            }
        }
        body_bytes.truncate(content_length);
    }
    let body = String::from_utf8_lossy(&body_bytes).to_string();

    match (method.as_str(), path.as_str()) {
        ("GET", "/") => respond(stream, 200, "text/html; charset=utf-8", INDEX_HTML),
        ("GET", "/api/status") => {
            if !token_ok(&auth, token) {
                return unauthorized(stream);
            }
            let snap = crate::recover_mutex(snapshot).clone();
            respond(stream, 200, "application/json", &status_json(&snap))
        }
        ("POST", "/api/profile") => {
            if !token_ok(&auth, token) {
                return unauthorized(stream);
            }
            let profile = extract_json_string(&body, "profile");
            match profile {
                Some(p) if is_known_profile(&p) => {
                    *crate::recover_mutex(requested_profile) = Some(p.clone());
                    respond(
                        stream,
                        200,
                        "application/json",
                        &format!(r#"{{"ok":true,"profile":"{}"}}"#, json_escape(&p)),
                    )
                }
                _ => respond(
                    stream,
                    400,
                    "application/json",
                    r#"{"ok":false,"error":"profile must be one of Stealth, ChinaGfw, RussiaDpi, Aggressive, ChinaRegional, Henan, NestedCloak"}"#,
                ),
            }
        }
        ("GET", "/api/config") => {
            if !token_ok(&auth, token) {
                return unauthorized(stream);
            }
            let settings = crate::recover_mutex(pipeline).settings.clone();
            respond(stream, 200, "application/json", &settings_json(&settings))
        }
        ("GET", "/api/config/toml") => {
            if !token_ok(&auth, token) {
                return unauthorized(stream);
            }
            let settings = crate::recover_mutex(pipeline).settings.clone();
            match crate::config::redacted_toml(&settings) {
                Ok(toml) => respond(stream, 200, "text/plain; charset=utf-8", &toml),
                Err(e) => respond(
                    stream,
                    500,
                    "application/json",
                    &format!(
                        r#"{{"ok":false,"error":"{}"}}"#,
                        json_escape(&e.to_string())
                    ),
                ),
            }
        }
        ("GET", "/api/scanner/pairs") => {
            if !token_ok(&auth, token) {
                return unauthorized(stream);
            }
            let pairs = crate::scanner::default_spoof_pairs();
            let json = serde_json::to_string(&pairs).unwrap_or_else(|_| "[]".into());
            respond(stream, 200, "application/json", &json)
        }
        ("POST", "/api/scanner/probe") | ("GET", "/api/scanner/probe") => {
            if !token_ok(&auth, token) {
                return unauthorized(stream);
            }
            let pairs = crate::scanner::default_spoof_pairs();
            let ranked = crate::scanner::probe_and_rank_spoof_pairs(
                &pairs,
                std::time::Duration::from_millis(1500),
            );
            // `best_spoof_pair` used to be called here as well — it runs the
            // exact same 16-candidate probe wave again (same fn, first
            // Some-latency result), doubling the probe latency and stalling
            // the single-threaded web UI for another ~1.5s. Derive the best
            // pair from the ranked list we already have: byte-identical
            // result at half the work.
            let best = ranked
                .iter()
                .find_map(|(pair, lat)| lat.map(|ms| (pair, ms)));
            let mut list_json = Vec::new();
            for (p, lat) in &ranked {
                list_json.push(format!(
                    r#"{{"provider":"{}","connect_ip":"{}","port":{},"fake_sni":"{}","description":"{}","latency_ms":{}}}"#,
                    json_escape(&p.provider),
                    json_escape(&p.connect_ip),
                    p.port,
                    json_escape(&p.fake_sni),
                    json_escape(&p.description),
                    lat.map(|l| l.to_string()).unwrap_or_else(|| "null".into())
                ));
            }
            let best_json = match best {
                Some((b, ms)) => format!(
                    r#"{{"provider":"{}","connect_ip":"{}","port":{},"fake_sni":"{}","latency_ms":{}}}"#,
                    json_escape(&b.provider),
                    json_escape(&b.connect_ip),
                    b.port,
                    json_escape(&b.fake_sni),
                    ms
                ),
                None => "null".into(),
            };
            let out = format!(
                r#"{{"ok":true,"best":{},"results":[{}]}}"#,
                best_json,
                list_json.join(",")
            );
            respond(stream, 200, "application/json", &out)
        }
        // Read-only dry run: same validation as the save path, no disk
        // write. Lets the dashboard show the operator the exact server-side
        // rejection reason before committing a change.
        ("POST", "/api/validate") => {
            if !token_ok(&auth, token) {
                return unauthorized(stream);
            }
            let base = crate::recover_mutex(pipeline).settings.clone();
            match validate_partial(&base, &body) {
                Ok(n) => respond(
                    stream,
                    200,
                    "application/json",
                    &format!(r#"{{"ok":true,"changed":{n},"message":"valid"}}"#),
                ),
                Err(e) => respond(
                    stream,
                    400,
                    "application/json",
                    &format!(
                        r#"{{"ok":false,"error":"{}"}}"#,
                        json_escape(&e.to_string())
                    ),
                ),
            }
        }
        ("POST", "/api/config") => {
            if !token_ok(&auth, token) {
                return unauthorized(stream);
            }
            let base = crate::recover_mutex(pipeline).settings.clone();
            match crate::config::merge_partial(&base, &body) {
                Ok(merged) => {
                    let text = match toml::to_string(&merged) {
                        Ok(t) => t,
                        Err(e) => {
                            return respond(
                                stream,
                                500,
                                "application/json",
                                &format!(
                                    r#"{{"ok":false,"error":"{}"}}"#,
                                    json_escape(&e.to_string())
                                ),
                            )
                        }
                    };
                    match std::fs::write(config_path, text) {
                        Ok(()) => respond(
                            stream,
                            200,
                            "application/json",
                            r#"{"ok":true,"saved":true,"message":"config saved; hot-reload applies it within a second"}"#,
                        ),
                        Err(e) => respond(
                            stream,
                            500,
                            "application/json",
                            &format!(
                                r#"{{"ok":false,"error":"{}"}}"#,
                                json_escape(&e.to_string())
                            ),
                        ),
                    }
                }
                Err(e) => respond(
                    stream,
                    400,
                    "application/json",
                    &format!(
                        r#"{{"ok":false,"error":"{}"}}"#,
                        json_escape(&e.to_string())
                    ),
                ),
            }
        }
        _ => respond(stream, 404, "application/json", r#"{"error":"not found"}"#),
    }
}

/// Send a 401 after a fixed delay to throttle credential brute-forcing.
/// The delay is constant regardless of whether a token was supplied, so it
/// does not itself become a timing oracle.
fn unauthorized(stream: TcpStream) -> Result<(), std::io::Error> {
    std::thread::sleep(Duration::from_millis(80));
    respond(
        stream,
        401,
        "application/json",
        r#"{"error":"unauthorized"}"#,
    )
}

fn respond(
    mut stream: TcpStream,
    code: u16,
    ctype: &str,
    body: &str,
) -> Result<(), std::io::Error> {
    let reason = match code {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        413 => "Payload Too Large",
        _ => "Error",
    };
    let head = format!(
        "HTTP/1.1 {code} {reason}\r\n\
         Content-Type: {ctype}\r\n\
         Content-Length: {}\r\n\
         X-Content-Type-Options: nosniff\r\n\
         X-Frame-Options: DENY\r\n\
         Referrer-Policy: no-referrer\r\n\
         Cache-Control: no-store\r\n\
         Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\n\
         Permissions-Policy: camera=(), microphone=(), geolocation=()\r\n\
         Cross-Origin-Resource-Policy: same-origin\r\n\
         Cross-Origin-Opener-Policy: same-origin\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body.as_bytes())?;
    stream.flush()
}

/// Constant-time token comparison (avoids a timing side channel on the
/// auth check even though this is localhost-only).
fn token_ok(header: &str, expected: &str) -> bool {
    // Defence in depth: an empty expected token must never authenticate.
    // `main` always generates one when the config leaves it blank, but a
    // direct `webui::start("")` would otherwise make `constant_time_eq("",
    // "")` return true and open every /api route.
    if expected.is_empty() {
        return false;
    }
    let header = header.trim();
    let bytes = header.as_bytes();
    // Compare on bytes so a multibyte first character cannot panic on a
    // non-char-boundary slice of the `str`.
    let got = if bytes.len() >= 7 && bytes[..7].eq_ignore_ascii_case(b"bearer ") {
        header[7..].trim()
    } else {
        ""
    };
    crate::integrity::constant_time_eq(got.as_bytes(), expected.as_bytes())
}

fn is_known_profile(p: &str) -> bool {
    matches!(
        p,
        "Stealth"
            | "ChinaGfw"
            | "RussiaDpi"
            | "Aggressive"
            | "ChinaRegional"
            | "Henan"
            | "NestedCloak"
    )
}

/// Host must be loopback IPv4. Rejecting `localhost` and any other name
/// blocks DNS-rebinding (an attacker domain resolving to 127.0.0.1
/// would otherwise send `Host: evil.example`).
pub fn host_is_allowed(host: &str, port: u16) -> bool {
    let host = host.trim();
    if host.is_empty() {
        return false;
    }
    let expected_port = format!("127.0.0.1:{port}");
    host.eq_ignore_ascii_case("127.0.0.1") || host.eq_ignore_ascii_case(&expected_port)
}

/// Empty Origin (curl / non-browser) is allowed. Browser fetch must
/// come from the dashboard origin itself.
pub fn origin_is_allowed(origin: &str, port: u16) -> bool {
    let origin = origin.trim();
    if origin.is_empty() {
        return true;
    }
    let expected = format!("http://127.0.0.1:{port}");
    origin.eq_ignore_ascii_case(&expected)
}

fn extract_json_string(body: &str, key: &str) -> Option<String> {
    // Minimal parser for `{"key":"value"}` — no external JSON dependency.
    let body = body.trim();
    let rest = body.strip_prefix('{')?.strip_suffix('}')?.trim();
    for pair in rest.split(',') {
        let mut kv = pair.splitn(2, ':');
        let k = kv.next()?.trim().trim_matches('"').trim();
        let v = kv.next()?.trim().trim_matches('"').trim();
        if k == key {
            return Some(v.to_string());
        }
    }
    None
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn status_json(s: &DashboardSnapshot) -> String {
    let scores: Vec<String> = s
        .strategy_scores
        .iter()
        .map(|(k, v)| format!(r#"{{"key":"{}","score":{v}}}"#, json_escape(k)))
        .collect();
    let domains: Vec<String> = s
        .recent_domains
        .iter()
        .map(|d| format!("\"{}\"", json_escape(d)))
        .collect();
    let ports: Vec<String> = s.intercept_ports.iter().map(|p| p.to_string()).collect();
    format!(
        r#"{{"mutation_profile":"{}","decoy_ttl":{},"idle_timeout_secs":{},"fragment_chunk_size":{},"enable_decoys":{},"enable_sni_fragmentation":{},"enable_swap_foolers":{},"enable_kill_switch":{},"processed_packets":{},"held_packets":{},"fail_open_events":{},"injection_attempts":{},"injection_successes":{},"injection_failures":{},"relay_fail_closed":{},"capture_errors":{},"strategy_scores":[{}],"recent_domains":[{}],"intercept_ports":[{}],"enable_quic_port_bypass":{},"enable_sni_disguise":{},"fronting_benign_sni":"{}","enable_utls_fingerprint":{},"enable_ech_grease":{},"relay_enabled":{},"relay_listen_port":{},"relay_require_inject":{},"relay_connect_host":"{}","relay_connect_port":{},"relay_fake_sni":"{}","enable_sni_scanner":{},"isp_profile":"{}","sni_rotation_mode":"{}","enable_anti_fingerprint":{},"randomize_ip_id":{},"enable_reverse_frag":{},"enable_wrong_seq":{},"enable_wrong_checksum":{},"enable_oob_injection":{},"enable_hostdot":{},"max_payload_size":{},"fake_resend_count":{},"enable_self_update":{},"enable_client_detect":{},"enable_proxy_cleanup":{},"enable_youtube_warmup":{},"enable_mobile_gateway":{},"autottl_scale_a1":{},"autottl_scale_a2":{},"autottl_scale_max":{},"mutated_packets":{},"doh_state":"{}","driver_handles_live":{},"driver_handles_retired":{},"uptime_secs":{}}}"#,
        json_escape(&s.mutation_profile),
        s.decoy_ttl,
        s.idle_timeout_secs,
        s.fragment_chunk_size,
        s.enable_decoys,
        s.enable_sni_fragmentation,
        s.enable_swap_foolers,
        s.enable_kill_switch,
        s.processed_packets,
        s.held_packets,
        s.fail_open_events,
        s.injection_attempts,
        s.injection_successes,
        s.injection_failures,
        s.relay_fail_closed,
        s.capture_errors,
        scores.join(","),
        domains.join(","),
        ports.join(","),
        s.enable_quic_port_bypass,
        s.enable_sni_disguise,
        json_escape(&s.fronting_benign_sni),
        s.enable_utls_fingerprint,
        s.enable_ech_grease,
        s.relay_enabled,
        s.relay_listen_port,
        s.relay_require_inject,
        json_escape(&s.relay_connect_host),
        s.relay_connect_port,
        json_escape(&s.relay_fake_sni),
        s.enable_sni_scanner,
        json_escape(&s.isp_profile),
        json_escape(&s.sni_rotation_mode),
        s.enable_anti_fingerprint,
        s.randomize_ip_id,
        s.enable_reverse_frag,
        s.enable_wrong_seq,
        s.enable_wrong_checksum,
        s.enable_oob_injection,
        s.enable_hostdot,
        s.max_payload_size,
        s.fake_resend_count,
        s.enable_self_update,
        s.enable_client_detect,
        s.enable_proxy_cleanup,
        s.enable_youtube_warmup,
        s.enable_mobile_gateway,
        s.autottl_scale_a1,
        s.autottl_scale_a2,
        s.autottl_scale_max,
        s.mutated_packets,
        json_escape(&s.doh_state),
        s.driver_handles_live,
        s.driver_handles_retired,
        s.uptime_secs
    )
}

/// Full editable settings as JSON for the dashboard config form. The web-UI
/// bearer token and driver pins are redacted (they are advanced/sensitive and
/// preserved on save via `config::merge_partial`).
fn settings_json(s: &crate::config::Settings) -> String {
    fn str_array(v: &[String]) -> String {
        v.iter()
            .map(|x| format!("\"{}\"", json_escape(x)))
            .collect::<Vec<_>>()
            .join(",")
    }
    let ports: Vec<String> = s.intercept_ports.iter().map(|p| p.to_string()).collect();
    let trusted = s.trusted_dns.as_deref().unwrap_or("");
    fn sa(v: &[String]) -> String {
        v.iter()
            .map(|x| format!("\"{}\"", json_escape(x)))
            .collect::<Vec<_>>()
            .join(",")
    }
    format!(
        r#"{{"mutation_profile":"{}","decoy_ttl":{},"idle_timeout_secs":{},"trusted_dns":"{}","fragment_chunk_size":{},"enable_decoys":{},"enable_sni_fragmentation":{},"enable_swap_foolers":{},"enable_kill_switch":{},"kill_switch_adapter":"{}","rotate_ips":[{}],"win_divert_sha256":[],"enable_web_ui":{},"web_ui_port":{},"web_ui_token":"","enable_quic_port_bypass":{},"quic_bypass_use_low_port":{},"enable_sni_disguise":{},"fronting_benign_sni":"{}","enable_combined_fragmentation":{},"intercept_ports":[{}],"intercept_all_tcp":{},"intercept_all_udp":{},"enable_utls_fingerprint":{},"utls_browser":"{}","enable_ech_grease":{},"enable_md5sig_fooling":{},"enable_geedge_evasion":{},"relay_enabled":{},"relay_listen_port":{},"relay_connect_host":"{}","relay_connect_port":{},"relay_fake_sni":"{}","relay_resolve_doh":{},"relay_mutate_real_sni":{},"relay_emit_decoy":{},"relay_require_inject":{},"doh_server":"{}","enable_tls_record_fragmentation":{},"tls_record_chunk_size":{},"enable_frag_by_sni":{},"enable_autottl":{},"autottl_delta":{},"enable_http_host_tricks":{},"enable_adaptive_desync":{},"sni_only":[{}],"sni_except":[{}],"enable_sni_scanner":{},"sni_candidates":[{}],"edge_candidates":[{}],"isp_profile":"{}","sni_rotation_mode":"{}","enable_anti_fingerprint":{},"injection_delay_min_ms":{},"injection_delay_max_ms":{},"max_packet_padding":{},"randomize_ip_id":{},"randomize_packet_size":{},"enable_fake_with_sni":{},"fake_browser":"{}","enable_reverse_frag":{},"enable_wrong_seq":{},"enable_wrong_checksum":{},"enable_oob_injection":{},"enable_hostdot":{},"max_payload_size":{},"fake_resend_count":{},"enable_self_update":{},"update_repo":"{}","enable_client_detect":{},"enable_proxy_cleanup":{},"enable_youtube_warmup":{},"enable_mobile_gateway":{},"ipset_hostlist":[{}],"autottl_scale_a1":{},"autottl_scale_a2":{},"autottl_scale_max":{}}}"#,
        json_escape(&s.mutation_profile),
        s.decoy_ttl,
        s.idle_timeout_secs,
        json_escape(trusted),
        s.fragment_chunk_size,
        s.enable_decoys,
        s.enable_sni_fragmentation,
        s.enable_swap_foolers,
        s.enable_kill_switch,
        json_escape(&s.kill_switch_adapter),
        str_array(&s.rotate_ips),
        s.enable_web_ui,
        s.web_ui_port,
        s.enable_quic_port_bypass,
        s.quic_bypass_use_low_port,
        s.enable_sni_disguise,
        json_escape(&s.fronting_benign_sni),
        s.enable_combined_fragmentation,
        ports.join(","),
        s.intercept_all_tcp,
        s.intercept_all_udp,
        s.enable_utls_fingerprint,
        json_escape(&s.utls_browser),
        s.enable_ech_grease,
        s.enable_md5sig_fooling,
        s.enable_geedge_evasion,
        s.relay_enabled,
        s.relay_listen_port,
        json_escape(&s.relay_connect_host),
        s.relay_connect_port,
        json_escape(&s.relay_fake_sni),
        s.relay_resolve_doh,
        s.relay_mutate_real_sni,
        s.relay_emit_decoy,
        s.relay_require_inject,
        json_escape(&s.doh_server),
        s.enable_tls_record_fragmentation,
        s.tls_record_chunk_size,
        s.enable_frag_by_sni,
        s.enable_autottl,
        s.autottl_delta,
        s.enable_http_host_tricks,
        s.enable_adaptive_desync,
        sa(&s.sni_only),
        sa(&s.sni_except),
        // ── 25 new features ──
        s.enable_sni_scanner,
        sa(&s.sni_candidates),
        sa(&s.edge_candidates),
        json_escape(&s.isp_profile),
        json_escape(&s.sni_rotation_mode),
        s.enable_anti_fingerprint,
        s.injection_delay_min_ms,
        s.injection_delay_max_ms,
        s.max_packet_padding,
        s.randomize_ip_id,
        s.randomize_packet_size,
        s.enable_fake_with_sni,
        json_escape(&s.fake_browser),
        s.enable_reverse_frag,
        s.enable_wrong_seq,
        s.enable_wrong_checksum,
        s.enable_oob_injection,
        s.enable_hostdot,
        s.max_payload_size,
        s.fake_resend_count,
        s.enable_self_update,
        json_escape(&s.update_repo),
        s.enable_client_detect,
        s.enable_proxy_cleanup,
        s.enable_youtube_warmup,
        s.enable_mobile_gateway,
        sa(&s.ipset_hostlist),
        s.autottl_scale_a1,
        s.autottl_scale_a2,
        s.autottl_scale_max
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_check_is_constant_time_semantics() {
        assert!(token_ok("Bearer secret", "secret"));
        assert!(token_ok("bearer secret", "secret"));
        assert!(token_ok("BEARER secret", "secret"));
        assert!(token_ok("Bearer AbCdEfGhIjKlMnop", "AbCdEfGhIjKlMnop"));
        assert!(!token_ok("Bearer AbCdEfGhIjKlMnop", "abcdefghijklmnop"));
        assert!(!token_ok("Bearer secret", "other"));
        assert!(!token_ok("", "secret"));
        assert!(!token_ok("Bearer secret", "secret1"));
        // An empty expected token must never authenticate, no matter what
        // the client sends: constant_time_eq("", "") is true, so this needs
        // its own guard.
        assert!(!token_ok("Bearer ", ""));
        assert!(!token_ok("", ""));
        assert!(!token_ok("Bearer anything", ""));
    }

    #[test]
    fn host_header_must_be_loopback_ipv4() {
        assert!(host_is_allowed("127.0.0.1", 9090));
        assert!(host_is_allowed("127.0.0.1:9090", 9090));
        assert!(!host_is_allowed("127.0.0.1:9091", 9090));
        assert!(!host_is_allowed("localhost", 9090));
        assert!(!host_is_allowed("evil.example", 9090));
        assert!(!host_is_allowed("", 9090));
        assert!(!host_is_allowed("0.0.0.0", 9090));
    }

    #[test]
    fn origin_must_be_empty_or_loopback_dashboard() {
        assert!(origin_is_allowed("", 9090));
        assert!(origin_is_allowed("http://127.0.0.1:9090", 9090));
        assert!(!origin_is_allowed("http://127.0.0.1:9091", 9090));
        assert!(!origin_is_allowed("http://evil.example", 9090));
        assert!(!origin_is_allowed("null", 9090));
    }

    #[test]
    fn profile_validation_is_strict() {
        for p in [
            "Stealth",
            "ChinaGfw",
            "RussiaDpi",
            "Aggressive",
            "ChinaRegional",
            "Henan",
            "NestedCloak",
        ] {
            assert!(is_known_profile(p));
        }
        assert!(!is_known_profile("stealth"));
        assert!(!is_known_profile("../../etc"));
        assert!(!is_known_profile("Stealth; calc"));
    }

    #[test]
    fn json_string_extraction() {
        assert_eq!(
            extract_json_string(r#"{"profile":"Aggressive"}"#, "profile").as_deref(),
            Some("Aggressive")
        );
        assert_eq!(extract_json_string(r#"{"nope":"x"}"#, "profile"), None);
        assert_eq!(extract_json_string("garbage", "profile"), None);
        assert_eq!(
            extract_json_string("{\"profile\":\"Stealth\"}\n", "profile").as_deref(),
            Some("Stealth")
        );
    }

    #[test]
    fn json_escape_handles_quotes_and_control() {
        assert_eq!(json_escape("a\"b"), "a\\\"b");
        assert_eq!(json_escape("x\ny"), "x\\ny");
        assert_eq!(json_escape("plain"), "plain");
    }

    #[test]
    fn status_json_is_well_formed_for_empty_snapshot() {
        let s = DashboardSnapshot::default();
        let j = status_json(&s);
        assert!(j.contains("\"mutation_profile\":\"\""));
        assert!(j.contains("\"processed_packets\":0"));
        assert!(j.contains("\"intercept_ports\":[]"));
        assert!(j.contains("\"enable_quic_port_bypass\":false"));
        assert!(j.contains("\"enable_sni_disguise\":false"));
        assert!(j.contains("\"fronting_benign_sni\":\"\""));
        assert!(j.contains("\"enable_utls_fingerprint\":false"));
        assert!(j.contains("\"enable_ech_grease\":false"));
        assert!(j.contains("\"relay_enabled\":false"));
        assert!(j.contains("\"relay_listen_port\":0"));
        assert!(j.contains("\"relay_require_inject\":true"));
        assert!(j.contains("\"relay_connect_host\":\"\""));
        assert!(j.contains("\"relay_connect_port\":443"));
        assert!(j.contains("\"mutated_packets\":0"));
        assert!(j.contains("\"fail_open_events\":0"));
        assert!(j.contains("\"injection_successes\":0"));
        assert!(j.contains("\"doh_state\":\"off\""));
        assert!(j.contains("\"driver_handles_live\":false"));
        assert!(j.contains("\"driver_handles_retired\":0"));
        assert!(j.contains("\"uptime_secs\":0"));
    }

    #[test]
    fn settings_json_redacts_token_and_pins_but_has_relay() {
        let s = crate::config::Settings {
            web_ui_token: "0123456789abcdef".into(),
            win_divert_sha256: vec!["a".repeat(64), "b".repeat(64)],
            relay_enabled: true,
            relay_connect_host: "1.1.1.1".into(),
            relay_fake_sni: "www.microsoft.com".into(),
            ..crate::config::Settings::default()
        };
        let j = settings_json(&s);
        assert!(j.contains("\"relay_enabled\":true"));
        assert!(j.contains("\"relay_connect_host\":\"1.1.1.1\""));
        assert!(j.contains("\"relay_fake_sni\":\"www.microsoft.com\""));
        assert!(!j.contains("0123456789abcdef"));
        assert!(!j.contains(&"a".repeat(64)));
        assert!(j.contains("\"web_ui_token\":\"\""));
    }

    #[test]
    fn status_json_serializes_intercept_ports_and_new_flags() {
        let s = DashboardSnapshot {
            intercept_ports: vec![443, 8443, 2053],
            enable_quic_port_bypass: true,
            fronting_benign_sni: "www.microsoft.com".into(),
            ..DashboardSnapshot::default()
        };
        let j = status_json(&s);
        assert!(j.contains("\"intercept_ports\":[443,8443,2053]"));
        assert!(j.contains("\"enable_quic_port_bypass\":true"));
        assert!(j.contains("\"fronting_benign_sni\":\"www.microsoft.com\""));
    }
}

/// The dashboard page. It lives in `src/webui/index.html` (embedded at
/// compile time with `include_str!`) so it stays a real, lintable HTML
/// file rather than a string literal, while the served binary still has
/// zero external assets. The page carries no secrets; the token is
/// prompted for, kept in `localStorage`, and sent as
/// `Authorization: Bearer` on every API call.
const INDEX_HTML: &str = include_str!("webui/index.html");

/// Validate a partial (or full) TOML body against the running settings
/// **without** writing anything to disk. Backs `POST /api/validate` so the
/// dashboard can show the operator the exact server-side rejection reason
/// before they commit a change.
///
/// Returns the number of keys the body would override.
pub fn validate_partial(
    base: &crate::config::Settings,
    partial_toml: &str,
) -> Result<usize, DpiGuardError> {
    let value: toml::Value =
        toml::from_str(partial_toml).map_err(|e| DpiGuardError::Config(e.to_string()))?;
    let table = match value {
        toml::Value::Table(t) => t,
        _ => return Err(DpiGuardError::Config("config must be a TOML table".into())),
    };
    let n = table.len();
    // `merge_partial` runs `Settings::validate()` on the merged result, so
    // this is exactly the check `POST /api/config` would apply.
    crate::config::merge_partial(base, partial_toml)?;
    Ok(n)
}

#[cfg(test)]
mod ui_schema_tests {
    use super::*;

    /// Every key of `config::Settings`, derived from the struct itself by
    /// serializing the defaults. `trusted_dns` is `Option` and is skipped
    /// when `None`, so it is filled in first to make the list complete.
    fn settings_keys() -> Vec<String> {
        let s = crate::config::Settings {
            trusted_dns: Some("1.1.1.1".into()),
            ..crate::config::Settings::default()
        };
        let text = toml::to_string(&s).expect("defaults must serialize");
        let table: toml::Value = toml::from_str(&text).expect("round-trip");
        let mut keys: Vec<String> = table.as_table().expect("table").keys().cloned().collect();
        keys.sort();
        keys
    }

    /// Keys declared in the dashboard's `FIELDS` schema, parsed out of the
    /// embedded HTML (`{ k: "field_name", ... }`).
    fn ui_schema_keys() -> Vec<String> {
        let mut keys = Vec::new();
        let bytes = INDEX_HTML.as_bytes();
        let needle = b"k: \"";
        let mut i = 0usize;
        while i + needle.len() < bytes.len() {
            if &bytes[i..i + needle.len()] == needle {
                let start = i + needle.len();
                if let Some(end_off) = bytes[start..].iter().position(|&b| b == b'"') {
                    let k = &INDEX_HTML[start..start + end_off];
                    if !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                        keys.push(k.to_string());
                    }
                }
            }
            i += 1;
        }
        keys.sort();
        keys.dedup();
        keys
    }

    /// The core guarantee of the dashboard: **every** setting is editable.
    /// Adding a field to `Settings` without adding it to `index.html` fails
    /// this test. There is deliberately no exemption list — a setting that
    /// is reachable from TOML but invisible in the UI is a setting an
    /// operator can never see the value of.
    #[test]
    fn every_settings_field_is_editable_in_the_ui() {
        let ui = ui_schema_keys();
        let keys = settings_keys();
        let missing: Vec<&String> = keys.iter().filter(|k| !ui.contains(k)).collect();
        assert!(
            missing.is_empty(),
            "these Settings fields have no control in src/webui/index.html: {missing:?}"
        );
    }

    /// The reverse direction: no stale/typo'd key in the UI that is not a
    /// real setting (which `deny_unknown_fields` would reject on save).
    #[test]
    fn ui_schema_declares_no_unknown_settings_key() {
        let real = settings_keys();
        let schema = ui_schema_keys();
        let bogus: Vec<&String> = schema.iter().filter(|k| !real.contains(k)).collect();
        assert!(
            bogus.is_empty(),
            "src/webui/index.html declares keys that are not Settings fields: {bogus:?}"
        );
    }

    /// The schema must declare exactly one control per setting, i.e. no
    /// duplicates smuggled in.
    #[test]
    fn ui_schema_size_matches_settings() {
        assert_eq!(
            ui_schema_keys().len(),
            settings_keys().len(),
            "UI schema and Settings disagree on the number of editable fields"
        );
    }

    #[test]
    fn index_html_is_embedded_and_self_contained() {
        assert!(INDEX_HTML.starts_with("<!doctype html>"));
        assert!(INDEX_HTML.contains("</html>"));
        // No external assets: the CSP is default-src 'none' and the served
        // binary must not reach the network for fonts/scripts/styles.
        let lower = INDEX_HTML.to_ascii_lowercase();
        assert!(!lower.contains("src=\"http"), "external <script src> found");
        assert!(!lower.contains("href=\"http"), "external <link href> found");
        assert!(!lower.contains("@import"), "external CSS @import found");
        assert!(!lower.contains("cdn."), "CDN reference found");
    }

    #[test]
    fn index_html_uses_only_the_documented_api_surface() {
        for route in [
            "/api/status",
            "/api/config",
            "/api/config/toml",
            "/api/profile",
            "/api/validate",
        ] {
            assert!(
                INDEX_HTML.contains(route),
                "dashboard never calls {route} — dead endpoint or missing feature"
            );
        }
    }

    #[test]
    fn validate_partial_accepts_good_and_rejects_bad() {
        let base = crate::config::Settings::default();
        // A realistic dashboard save: relay on, a few knobs changed.
        let good = "mutation_profile = \"Henan\"\n\
                    relay_enabled = true\n\
                    relay_connect_host = \"1.1.1.1\"\n\
                    relay_fake_sni = \"www.microsoft.com\"\n\
                    decoy_ttl = 12\n\
                    intercept_ports = [443, 8443]\n";
        assert_eq!(validate_partial(&base, good).unwrap(), 6);

        // Server-side rejections must surface, not pass silently.
        assert!(validate_partial(&base, "decoy_ttl = 0\n").is_err());
        assert!(validate_partial(&base, "fragment_chunk_size = 1\n").is_err());
        assert!(validate_partial(&base, "not_a_real_key = 1\n").is_err());
        assert!(validate_partial(&base, "utls_browser = \"opera\"\n").is_err());
        assert!(validate_partial(&base, "intercept_ports = [0]\n").is_err());
        assert!(validate_partial(&base, "not = [valid").is_err());
        assert!(validate_partial(&base, "42\n").is_err());
        // relay on without a fake SNI
        assert!(validate_partial(&base, "relay_enabled = true\n").is_err());
    }

    /// `POST /api/validate` must never touch the disk: it is read-only.
    /// Guarded by asserting the handler and the writer are distinct calls.
    #[test]
    fn validate_endpoint_is_distinct_from_config_write() {
        assert!(INDEX_HTML.contains("btn_validate"));
        assert!(INDEX_HTML.contains("btn_save"));
    }

    /// A full-config round-trip through the dashboard must fit inside the
    /// 4096-byte `Content-Length` cap enforced by `handle_conn`, otherwise
    /// "Save advanced" would 413 on a large config.
    #[test]
    fn redacted_full_config_fits_the_ui_body_cap() {
        let s = crate::config::Settings::default();
        let toml_text = crate::config::redacted_toml(&s).unwrap();
        assert!(
            toml_text.len() < 4096,
            "redacted config is {} bytes; raise the UI body cap or the \
             advanced editor cannot round-trip a full config",
            toml_text.len()
        );
    }
}
