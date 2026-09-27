/*
 * Mock of dpi_guard's dashboard HTTP API, used to exercise the REAL
 * src/webui/index.html in a browser / jsdom without a Windows host.
 *
 * It ports the server-side contract of src/webui.rs:
 *   GET  /                 -> index.html
 *   GET  /api/status       -> DashboardSnapshot
 *   GET  /api/config       -> Settings as JSON (token + pins redacted)
 *   GET  /api/config/toml  -> redacted_toml(Settings)
 *   POST /api/profile      -> {profile}
 *   POST /api/config       -> merge_partial + validate, then "save"
 *   POST /api/validate     -> merge_partial + validate, no save
 * plus a faithful port of Settings::default() / Settings::validate() /
 * merge_partial() from src/config.rs so UI errors are real errors.
 *
 * Deviations from the shipped server (mock only): no Host/Origin allowlist
 * (so the sandbox preview proxy can reach it) and a fixed token.
 */
import http from "node:http";
import TOML from "@iarna/toml";
import fs from "node:fs";
import path from "node:path";

const TOKEN = "dev-token-dev-token";
const REPO = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const HTML_PATH = path.join(REPO, "src/webui/index.html");

const NEVER_INTERCEPT = [22, 53, 3389];

export const DEFAULTS = {
  mutation_profile: "Stealth",
  decoy_ttl: 8,
  idle_timeout_secs: 120,
  fragment_chunk_size: 64,
  enable_decoys: true,
  enable_sni_fragmentation: true,
  enable_swap_foolers: false,
  enable_kill_switch: false,
  kill_switch_adapter: "",
  rotate_ips: [],
  win_divert_sha256: [],
  enable_web_ui: false,
  web_ui_port: 9090,
  web_ui_token: "",
  enable_quic_port_bypass: false,
  quic_bypass_use_low_port: false,
  enable_sni_disguise: false,
  fronting_benign_sni: "",
  enable_combined_fragmentation: true,
  intercept_ports: [],
  intercept_all_tcp: true,
  intercept_all_udp: true,
  enable_utls_fingerprint: false,
  utls_browser: "chrome",
  enable_ech_grease: false,
  enable_md5sig_fooling: false,
  enable_geedge_evasion: true,
  relay_enabled: false,
  relay_listen_port: 40443,
  relay_connect_host: "",
  relay_connect_port: 443,
  relay_fake_sni: "",
  relay_resolve_doh: true,
  relay_mutate_real_sni: false,
  relay_emit_decoy: false,
  doh_server: "https://cloudflare-dns.com/dns-query",
  sni_only: [],
  sni_except: [],
  enable_tls_record_fragmentation: false,
  tls_record_chunk_size: 0,
  enable_frag_by_sni: false,
  enable_autottl: false,
  autottl_delta: 0,
  enable_http_host_tricks: false,
  enable_adaptive_desync: false,
  // 2026 roadmap upgrades (NestedCloak era)
  enable_frag_mid_sni: false,
  enable_padding_inflation: false,
  enable_strategy_rotation: false,
  enable_real_ech: false,
  real_ech_config_hex: "",
  relay_require_inject: true,
  // 25 new features defaults
  enable_sni_scanner: false,
  sni_candidates: [],
  edge_candidates: [],
  isp_profile: "auto",
  sni_rotation_mode: "round_robin",
  enable_anti_fingerprint: false,
  injection_delay_min_ms: 1,
  injection_delay_max_ms: 10,
  max_packet_padding: 0,
  randomize_ip_id: false,
  randomize_packet_size: false,
  enable_fake_with_sni: false,
  fake_browser: "firefox",
  enable_reverse_frag: false,
  enable_wrong_seq: true,
  enable_wrong_checksum: true,
  enable_oob_injection: false,
  enable_hostdot: false,
  max_payload_size: 1200,
  fake_resend_count: 1,
  enable_self_update: false,
  update_repo: "lqbw9yw8/sni-spoof-new--alpha-3.6",
  enable_client_detect: false,
  enable_proxy_cleanup: true,
  enable_youtube_warmup: false,
  enable_mobile_gateway: false,
  ipset_hostlist: [],
  autottl_scale_a1: 0,
  autottl_scale_a2: 4,
  autottl_scale_max: 10,
  // trusted_dns: Option<String> — absent means None
};

const PROFILES = ["Stealth", "ChinaGfw", "RussiaDpi", "Aggressive", "ChinaRegional", "Henan", "NestedCloak"];
const BROWSERS = ["chrome", "firefox", "safari", "edge", "random"];

let settings = JSON.parse(JSON.stringify(DEFAULTS));
let processed = 128741;
let statusOverrides = {};

const isIP = (s) => {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return s.split(".").every((p) => +p <= 255);
  return /^[0-9a-fA-F:]+$/.test(s) && s.includes(":");
};
const forbiddenIP = (s) =>
  /^127\./.test(s) || s === "::1" || /^169\.254\./.test(s) || /^2[2-3]\d\./.test(s) || s === "0.0.0.0";
const forbiddenHost = (h) => {
  const x = h.toLowerCase().replace(/\.+$/, "");
  if (isIP(x)) return forbiddenIP(x);
  return x === "localhost" || x.endsWith(".localhost") || x.endsWith(".local") ||
    x.endsWith(".internal") || x === "metadata.google.internal";
};

/**
 * Faithful port of Settings::validate(). Returns error string or null.
 *
 * Missing keys take their compiled default first, exactly like serde's
 * `#[serde(default)]` does — so a hand-written or partial TOML document
 * validates the same way the Rust side would validate it.
 */
export function validate(raw) {
  const s = Object.assign({}, DEFAULTS, raw);
  if (!PROFILES.includes(s.mutation_profile)) return "unknown mutation_profile";
  if (s.decoy_ttl === 0 || s.decoy_ttl > 64) return "decoy_ttl must be 1..=64";
  if (s.idle_timeout_secs === 0) return "idle_timeout_secs must be > 0";
  if (s.idle_timeout_secs > 86400) return "idle_timeout_secs must be <=86400";
  if (s.fragment_chunk_size === 1) return "fragment_chunk_size=1 is rejected; use 0 or >=8";
  if (s.fragment_chunk_size > 0 && s.fragment_chunk_size < 8) return "fragment_chunk_size must be 0 or >=8";
  if (s.fragment_chunk_size > 16384) return "fragment_chunk_size must be <=16384";
  if (s.enable_kill_switch && !/^[A-Za-z0-9 _-]+$/.test(s.kill_switch_adapter))
    return "kill-switch adapter name must be [A-Za-z0-9 _-]+";
  if (s.trusted_dns !== undefined && s.trusted_dns !== null && !isIP(s.trusted_dns))
    return "trusted_dns must be valid IP";
  for (const ip of s.rotate_ips) if (!isIP(ip)) return `rotate_ips ${ip} invalid`;
  if (s.win_divert_sha256.length !== 0 && s.win_divert_sha256.length !== 2)
    return "win_divert_sha256 must contain exactly two pins in DLL, SYS order";
  for (const h of s.win_divert_sha256) if (!/^[0-9a-fA-F]{64}$/.test(h.trim()))
    return "win_divert_sha256 must be 64 hex";
  if (s.web_ui_port === 0) return "web_ui_port must be >0";
  if (s.web_ui_token) {
    if (s.web_ui_token.length < 16) return "web_ui_token must be >=16";
    if (!/^[\x21-\x7e]+$/.test(s.web_ui_token) || s.web_ui_token.includes('"') || s.web_ui_token.includes("\\"))
      return "web_ui_token must be printable ASCII without quotes";
  }
  if (s.fronting_benign_sni) {
    if (s.fronting_benign_sni.length > 253) return "fronting_benign_sni too long";
    if (!/^[A-Za-z0-9._-]+$/.test(s.fronting_benign_sni)) return "fronting_benign_sni must be valid hostname";
  }
  for (const p of s.intercept_ports) if (p === 0) return "intercept_ports cannot contain 0";
  if (s.intercept_ports.length > 100) return "intercept_ports max 100 entries";
  if (!BROWSERS.includes(s.utls_browser.toLowerCase())) return "utls_browser must be one of chrome/firefox/safari/edge/random";
  if (s.relay_enabled) {
    if (s.relay_listen_port === 0) return "relay_listen_port must be > 0";
    if (s.relay_connect_port === 0) return "relay_connect_port must be > 0";
    const host = (s.relay_connect_host || "").trim();
    if (!host) return "relay_connect_host is required when relay_enabled";
    if (!isIP(host) && !/^[A-Za-z0-9.-]+$/.test(host)) return "relay_connect_host must be an IP or a valid hostname";
    if (forbiddenHost(host)) return `relay_connect_host ${host} is forbidden (loopback/link-local/multicast/metadata)`;
    if (!s.relay_fake_sni) return "relay_fake_sni is required when relay_enabled";
    if (!/^[A-Za-z0-9._-]+$/.test(s.relay_fake_sni)) return "relay_fake_sni must be a valid hostname";
    if (s.enable_web_ui && s.relay_listen_port === s.web_ui_port)
      return `relay_listen_port ${s.relay_listen_port} collides with web_ui_port`;
  }
  const d = (s.doh_server || "").trim();
  if (!d.startsWith("https://")) return "doh_server must be an https:// URL";
  const auth = d.slice(8).split(/[/?#]/)[0];
  if (auth.includes("@")) return "doh_server must not contain userinfo (user:password@)";
  if (forbiddenHost(auth.replace(/^\[|\]$/g, "").split(":")[0])) return "doh_server host is forbidden";
  for (const list of [s.sni_only, s.sni_except]) {
    for (const pat of list) {
      if (pat.length > 253) return "SNI filter pattern too long";
      if (!/^[A-Za-z0-9._*-]+$/.test(pat)) return `SNI filter pattern ${pat} contains invalid characters`;
    }
  }
  if (s.tls_record_chunk_size > 16384) return "tls_record_chunk_size must be <= 16384";
  if (!(s.autottl_delta >= 0 && s.autottl_delta <= 32)) return "autottl_delta must be between 0 and 32";
  // Port of self_update::validate_repo_slug — update_repo is formatted
  // straight into the GitHub API URL, so it must be a bare owner/repo pair
  // with no path segments, query, fragment, scheme, or userinfo.
  {
    const r = (s.update_repo || "").trim();
    if (!r) return "update_repo must not be empty";
    if (r.length > 201) return `update_repo is ${r.length} chars, over the 201 cap`;
    const slash = r.indexOf("/");
    if (slash < 0) return "update_repo must be an owner/repo pair, not a URL";
    const halves = [["owner", r.slice(0, slash)], ["repo", r.slice(slash + 1)]];
    for (const [label, part] of halves) {
      if (!part) return `update_repo ${label} half is empty`;
      if (part === "." || part === "..") return `update_repo ${label} half ${part} is a path traversal`;
      if (!/^[A-Za-z0-9._-]+$/.test(part))
        return `update_repo ${label} half ${part} has characters outside [A-Za-z0-9._-]`;
    }
  }
  return null;
}

/** Faithful port of config::merge_partial(), including the redaction rules. */
export function mergePartial(base, partialText) {
  let overrides;
  try { overrides = parseTomlTable(partialText); }
  catch (e) { return { error: "config error: " + e.message }; }
  const out = JSON.parse(JSON.stringify(base));
  for (const [k, v] of Object.entries(overrides)) {
    if (k === "web_ui_token" && typeof v === "string" && v === "") continue;
    if (k === "win_divert_sha256" && Array.isArray(v) && v.length === 0) continue;
    if (k === "trusted_dns" && typeof v === "string" && v === "") { delete out.trusted_dns; continue; }
    if (!(k in DEFAULTS) && k !== "trusted_dns") return { error: `config error: unknown field \`${k}\`` };
    out[k] = v;
  }
  const err = validate(out);
  if (err) return { error: "config error: " + err };
  return { settings: out, changed: Object.keys(overrides).length };
}

/*
 * TOML parsing uses a real parser (@iarna/toml), not a hand-rolled subset:
 * if the dashboard emits something that is not valid TOML, the save must
 * fail here rather than silently succeeding in the mock.
 */
export function parseTomlTable(text) {
  const src = String(text);
  if (!src.trim()) return {};
  return TOML.parse(src);
}

function toToml(s) {
  const lines = [];
  for (const [k, v] of Object.entries(s)) {
    if (v === null || v === undefined) continue;               // Option::None skipped
    if (typeof v === "boolean" || typeof v === "number") lines.push(`${k} = ${v}`);
    else if (Array.isArray(v)) {
      lines.push(`${k} = [${v.map((x) => (typeof x === "number" ? x : JSON.stringify(String(x)))).join(", ")}]`);
    } else lines.push(`${k} = ${JSON.stringify(String(v))}`);
  }
  return lines.join("\n") + "\n";
}

function redacted(s) {
  const c = JSON.parse(JSON.stringify(s));
  c.web_ui_token = "";
  c.win_divert_sha256 = [];
  return c;
}

function statusJson() {
  // Mirrors `status_json()` in src/webui.rs FIELD FOR FIELD, so the UI under
  // test reads the same names it will read in production. The mock used to
  // emit 28 of the 56 fields plus three stale names (`enable_quic_bypass`,
  // `enable_utls`, `fronting_benign`) that the real endpoint no longer sends
  // — every card/chip bound to them silently read `undefined` and the tests
  // passed while proving nothing about them.
  const flags = (names) => Object.fromEntries(names.map((n) => [n, !!settings[n]]));
  return Object.assign(
    {
      mutation_profile: settings.mutation_profile,
      decoy_ttl: settings.decoy_ttl,
      idle_timeout_secs: settings.idle_timeout_secs,
      fragment_chunk_size: settings.fragment_chunk_size,
      processed_packets: processed,
      mutated_packets: Math.floor(processed / 3),
      held_packets: 0,
      fail_open_events: 0,
      injection_attempts: processed,
      injection_successes: Math.floor(processed / 2),
      injection_failures: 0,
      relay_fail_closed: 0,
      capture_errors: 0,
      strategy_scores: [
        { key: "a91c…|tls_record_frag", score: 42 },
        { key: "b7fe…|frag_by_sni", score: 17 },
        { key: "c123…|disorder", score: -5 },
      ],
      recent_domains: ["3f2a91cbe7d04a15", "88d0c2a41b9f7e33"],
      intercept_ports:
        settings.intercept_all_tcp || settings.intercept_all_udp
          ? []
          : settings.intercept_ports.length
            ? settings.intercept_ports
            : [443],
      fronting_benign_sni: settings.fronting_benign_sni,
      relay_enabled: settings.relay_enabled,
      relay_listen_port: settings.relay_listen_port,
      relay_require_inject: settings.relay_require_inject,
      relay_connect_host: settings.relay_connect_host,
      relay_connect_port: settings.relay_connect_port,
      relay_fake_sni: settings.relay_fake_sni,
      isp_profile: settings.isp_profile,
      sni_rotation_mode: settings.sni_rotation_mode,
      max_payload_size: settings.max_payload_size,
      fake_resend_count: settings.fake_resend_count,
      autottl_scale_a1: settings.autottl_scale_a1,
      autottl_scale_a2: settings.autottl_scale_a2,
      autottl_scale_max: settings.autottl_scale_max,
      doh_state: settings.relay_enabled && settings.relay_resolve_doh ? "enabled" : "off",
      driver_handles_live: true,
      driver_handles_retired: 2,
      uptime_secs: 3725,
    },
    flags([
      "enable_decoys",
      "enable_sni_fragmentation",
      "enable_swap_foolers",
      "enable_kill_switch",
      "enable_quic_port_bypass",
      "enable_sni_disguise",
      "enable_utls_fingerprint",
      "enable_ech_grease",
      "enable_sni_scanner",
      "enable_anti_fingerprint",
      "randomize_ip_id",
      "enable_reverse_frag",
      "enable_wrong_seq",
      "enable_wrong_checksum",
      "enable_oob_injection",
      "enable_hostdot",
      "enable_self_update",
      "enable_client_detect",
      "enable_proxy_cleanup",
      "enable_youtube_warmup",
      "enable_mobile_gateway",
    ]),
    statusOverrides,
  );
}


const HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Cache-Control": "no-store",
};

function send(res, code, ctype, body, extra) {
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(String(body), "utf8");
  res.writeHead(code, Object.assign({
    "Content-Type": ctype, "Content-Length": buf.length, Connection: "close",
  }, HEADERS, extra || {}));
  res.end(buf);
}

function authed(req) {
  const h = (req.headers.authorization || "").trim();
  const got = /^bearer\s+/i.test(h) ? h.slice(7).trim() : "";
  if (got.length !== TOKEN.length) return false;
  let diff = 0;
  for (let i = 0; i < TOKEN.length; i++) diff |= got.charCodeAt(i) ^ TOKEN.charCodeAt(i);
  return diff === 0;
}

export function createServer() {
  return http.createServer((req, res) => {
    const url = (req.url || "/").split("?")[0];
    if (req.method === "GET" && url === "/") {
      return send(res, 200, "text/html; charset=utf-8", fs.readFileSync(HTML_PATH));
    }
    if (req.method === "GET" && url === "/healthz") {
      return send(res, 200, "application/json", JSON.stringify({ ok: true }));
    }
    if (!url.startsWith("/api/")) {
      return send(res, 404, "application/json", '{"error":"not found"}');
    }
    if (!authed(req)) {
      setTimeout(() => send(res, 401, "application/json", '{"error":"unauthorized"}'), 80);
      return;
    }
    if (req.method === "GET" && url === "/api/status") {
      processed += 137;
      return send(res, 200, "application/json", JSON.stringify(statusJson()));
    }
    if (req.method === "GET" && url === "/api/config") {
      return send(res, 200, "application/json", JSON.stringify(redacted(settings)));
    }
    if (req.method === "GET" && url === "/api/config/toml") {
      return send(res, 200, "text/plain; charset=utf-8", toToml(redacted(settings)));
    }
    if (req.method === "POST" && (url === "/api/config" || url === "/api/validate")) {
      const chunks = [];
      let n = 0;
      req.on("data", (c) => { n += c.length; if (n > 4096) { req.destroy(); } else chunks.push(c); });
      req.on("end", () => {
        if (n > 4096) return send(res, 413, "application/json", '{"error":"request too large"}');
        const body = Buffer.concat(chunks).toString("utf8");
        const r = mergePartial(settings, body);
        if (r.error) return send(res, 400, "application/json", JSON.stringify({ ok: false, error: r.error }));
        if (url === "/api/validate") {
          return send(res, 200, "application/json",
            JSON.stringify({ ok: true, changed: r.changed, message: "valid" }));
        }
        settings = r.settings;
        return send(res, 200, "application/json", JSON.stringify({
          ok: true, saved: true,
          message: "config saved; hot-reload applies it within a second",
        }));
      });
      return;
    }
    if (req.method === "POST" && url === "/api/profile") {
      const chunks = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => {
        const body = Buffer.concat(chunks).toString("utf8");
        const m = body.match(/"profile"\s*:\s*"([^"]*)"/);
        const p = m && m[1];
        if (!p || !PROFILES.includes(p)) {
          return send(res, 400, "application/json",
            '{"ok":false,"error":"profile must be one of ' + PROFILES.join(", ") + '"}');
        }
        settings.mutation_profile = p;
        return send(res, 200, "application/json", JSON.stringify({ ok: true, profile: p }));
      });
      return;
    }
    return send(res, 404, "application/json", '{"error":"not found"}');
  });
}

export function resetForTests() {
  settings = JSON.parse(JSON.stringify(DEFAULTS));
  processed = 0;
  statusOverrides = {};
}
export function setStatusForTests(overrides) {
  statusOverrides = { ...overrides };
}
export function getSettings() { return settings; }

// Run standalone: node uitest/mock-server.js [port]
if (process.argv[1] && process.argv[1].includes("mock-server")) {
  const port = Number(process.argv[2] || 8787);
  createServer().listen(port, "0.0.0.0", () => {
    console.log(`dpi_guard UI mock on http://0.0.0.0:${port}`);
    console.log(`token: ${TOKEN}`);
  });
}
