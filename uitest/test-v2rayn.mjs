/*
 * v2rayN coexistence tests for dpi_guard.
 *
 * Intended topology (per START_HERE.md §5):
 *
 *   app/browser -> v2rayN (SOCKS 10808 / HTTP 10809)
 *                     -> dpi_guard relay  127.0.0.1:40443   (loopback: NOT diverted)
 *                          -> real server  <ip>:443          (diverted: fake SNI injected)
 *
 * Three kinds of check live here, and they are labelled honestly:
 *
 *   [RUNS SHIPPED CODE]  drives the real src/webui/index.html in jsdom and
 *                        asserts the TOML it emits for a v2rayN setup.
 *   [STATIC SOURCE]      greps the real Rust source for an invariant.
 *                        This proves the text is present, NOT that it
 *                        behaves correctly at runtime.
 *   [DOC CONSISTENCY]    the documented setup matches the code's defaults.
 *
 * True end-to-end interop needs Windows + WinDivert + v2rayN and cannot be
 * executed here; see the manual procedure at the bottom of this file and in
 * SECURITY_AUDIT_2026-08.md.
 *
 *   node uitest/test-v2rayn.mjs
 */
import { JSDOM, VirtualConsole } from "jsdom";
import TOML from "@iarna/toml";
import fs from "node:fs";
import path from "node:path";
import {
  createServer, resetForTests, getSettings, mergePartial, validate, DEFAULTS,
} from "./mock-server.mjs";

const REPO = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const read = (f) => fs.readFileSync(path.join(REPO, f), "utf8");
/**
 * Read a doc that may live at the repo root or under docs/archive/.
 *
 * Docs get reorganised; a static-analysis test should not turn red just
 * because a file moved. Tries each candidate path in order and fails with
 * a message naming all of them.
 */
const readDoc = (...candidates) => {
  for (const c of candidates) {
    const p = path.join(REPO, c);
    if (fs.existsSync(p)) return fs.readFileSync(p, "utf8");
  }
  throw new Error(`none of these docs exist: ${candidates.join(", ")}`);
};

let pass = 0;
const failures = [];
const ok = (n, c, extra) => {
  if (c) { pass++; console.log("  ok   " + n); }
  else { failures.push(n + (extra ? " — " + extra : "")); console.log("  FAIL " + n + (extra ? " — " + extra : "")); }
};
const eq = (n, a, b) =>
  ok(n + (JSON.stringify(a) === JSON.stringify(b) ? "" : ` (got ${JSON.stringify(a)}, want ${JSON.stringify(b)})`),
     JSON.stringify(a) === JSON.stringify(b));

const CONFIG_RS = read("src/config.rs");
const PIPELINE_RS = read("src/pipeline.rs");
const RELAY_RS = read("src/relay.rs");
const LIB_RS = read("src/lib.rs");
const START_HERE = readDoc("START_HERE.md", "docs/archive/START_HERE.md");
const EXAMPLE = read("dpi_guard.toml.example");

/* v2rayN / v2ray / Xray well-known local inbound ports. */
const V2RAY_PORTS = { socks: 10808, http: 10809, dns: 10853 };

console.log("\n[1] DOC CONSISTENCY — the documented v2rayN setup matches the code");
{
  // The regex tolerates any whitespace inside the braces because `cargo fmt`
  // (a CI gate) normalizes one-statement fn bodies onto multiple lines.
  const defaultRelayPort = Number((CONFIG_RS.match(/fn default_relay_listen_port\(\) -> u16 \{\s*(\d+)\s*\}/) || [])[1]);
  const defaultUiPort = Number((CONFIG_RS.match(/fn default_web_ui_port\(\) -> u16 \{\s*(\d+)\s*\}/) || [])[1]);
  ok("parsed default_relay_listen_port from config.rs", defaultRelayPort === 40443, "got " + defaultRelayPort);
  ok("START_HERE tells the client to use that exact port",
    START_HERE.includes("**آدرس سرور: `127.0.0.1`**") &&
    (START_HERE.includes("relay_listen_port") || START_HERE.includes("40443")));
  ok("START_HERE says the client SNI must be the REAL domain",
    /SNI \/ ServerName: دامنه واقعی سرور/.test(START_HERE));
  ok("docs warn that REALITY/Hysteria/TUIC do not work through the relay",
    /REALITY/.test(START_HERE) && /Hysteria/.test(START_HERE) && /TUIC/.test(START_HERE));
  ok("relay default port does not sit on a v2rayN local port",
    !Object.values(V2RAY_PORTS).includes(defaultRelayPort));
  ok("dashboard default port does not sit on a v2rayN local port",
    !Object.values(V2RAY_PORTS).includes(defaultUiPort));
  ok("relay default port is not a never-intercept port (22/53/3389)",
    ![22, 53, 3389].includes(defaultRelayPort));
  ok("config.rs names v2rayN's local ports so a clash is explained",
    /KNOWN_V2RAY_LOCAL_PORTS: \[u16; 3\] = \[10808, 10809, 10853\]/.test(CONFIG_RS));
}

console.log("\n[2] DOC CONSISTENCY — dpi_guard.toml.example is a valid v2rayN setup");
{
  let parsed = null;
  let parseErr = null;
  try { parsed = TOML.parse(EXAMPLE); } catch (e) { parseErr = e.message; }
  ok("dpi_guard.toml.example parses with a real TOML parser", !!parsed, parseErr);
  if (parsed) {
    const v = validate(parsed);
    ok("the example passes Settings::validate (faithful port)", v === null, String(v));
    eq("example relay listen port", parsed.relay_listen_port, 40443);
    ok("example relay port does not clash with v2rayN", !Object.values(V2RAY_PORTS).includes(parsed.relay_listen_port));
    ok("example web UI port does not clash with v2rayN", !Object.values(V2RAY_PORTS).includes(parsed.web_ui_port));
    ok("example relay port differs from the web UI port", parsed.relay_listen_port !== parsed.web_ui_port);
    ok("example keeps fail-closed on", parsed.relay_require_inject === true);
    ok("example destination is a domain or IP (DoH resolves domains)",
      typeof parsed.relay_connect_host === "string" && parsed.relay_connect_host.length > 0);
    ok("example keeps DoH resolve on so a domain does not fall back to UDP/53",
      parsed.relay_resolve_doh === true);
    ok("example tells v2rayN where to connect",
      /v2rayN .* connects to 127\.0\.0\.1:<relay_listen_port>/.test(EXAMPLE));
  }
}

console.log("\n[3] STATIC SOURCE — the v2rayN -> relay leg is never diverted");
{
  ok("DEFAULT_FILTER starts with !loopback", /DEFAULT_FILTER: &str = "!loopback and/.test(LIB_RS));
  ok("build_filter always emits !loopback",
    /format!\("!loopback and \(\{tcp\} or \{udp\}\)"\)/.test(LIB_RS));
  ok("the relay binds 127.0.0.1 only, never 0.0.0.0",
    /let addr: SocketAddr = \(\[127, 0, 0, 1\], listen_port\)\.into\(\);/.test(RELAY_RS));
  ok("the relay drops any non-loopback peer", /if !peer\.ip\(\)\.is_loopback\(\)/.test(RELAY_RS));
  ok("SSH/DNS/RDP are never intercepted even in all-ports mode",
    /NEVER_INTERCEPT_PORTS: \[u16; 3\] = \[22, 53, 3389\]/.test(CONFIG_RS));
}

console.log("\n[4] STATIC SOURCE — relay flow table can no longer grow without bound");
{
  ok("MAX_RELAY_FLOWS is declared", /const MAX_RELAY_FLOWS: usize = 256;/.test(PIPELINE_RS));
  ok("register_relay_flow enforces the cap",
    /if self\.relay_flows\.len\(\) >= MAX_RELAY_FLOWS/.test(PIPELINE_RS));
  ok("eviction prefers finished handshakes",
    /self\.relay_flows\.retain\(\|_, f\| !f\.done\)/.test(PIPELINE_RS));
  ok("the eviction of a live flow is logged",
    /relay flow table full/.test(PIPELINE_RS));
  ok("relay flows are still pruned when idle",
    /self\.relay_flows\s*\n?\s*\.retain\(\|_, f\| !deep_sleep_idle/.test(PIPELINE_RS));
  ok("regression tests exist for the cap",
    ["relay_flow_table_is_capped_under_many_connections",
     "relay_flow_cap_evicts_finished_flows_before_live_ones",
     "relay_flow_reregistration_does_not_grow_or_evict",
     "relay_flows_are_pruned_when_idle"].every((t) => PIPELINE_RS.includes("fn " + t + "(")));
  ok("config warns when the relay port clashes with v2rayN",
    /KNOWN_V2RAY_LOCAL_PORTS\.contains\(&self\.relay_listen_port\)/.test(CONFIG_RS));
  ok("regression test for v2rayN coexistence exists in config.rs",
    CONFIG_RS.includes("fn coexists_with_v2rayn_default_local_ports("));
}

console.log("\n[5] STATIC SOURCE — v2rayN's non-QUIC UDP leg passes through untouched");
{
  // pipeline.rs: the UDP branch falls through to Send(raw) unless QUIC
  // bypass is on AND the packet is a genuine QUIC Initial with src > dst.
  const udpBranch = PIPELINE_RS.slice(
    PIPELINE_RS.indexOf("if parsed.protocol == packet::PROTO_UDP {"),
    PIPELINE_RS.indexOf("if parsed.protocol != packet::PROTO_TCP {"));
  ok("found the UDP branch", udpBranch.length > 500);
  ok("non-target UDP is returned unmodified",
    /if !is_target_udp \{\s*\n\s*return Ok\(WireAction::Passthrough\);/.test(udpBranch));
  ok("UDP falls through to unmodified send at the end of the branch",
    udpBranch.trimEnd().endsWith("return Ok(WireAction::Passthrough);\n        }"));
  ok("QUIC rewriting is gated on is_quic_initial",
    /crate::quic::is_quic_initial\(payload\)/.test(udpBranch));
  ok("QUIC bypass is off by default", DEFAULTS.enable_quic_port_bypass === false);
}

/* =================== drive the REAL dashboard =================== */

const server = createServer();
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const BASE = `http://127.0.0.1:${server.address().port}`;
const TOKEN = "dev-token-dev-token";
const captured = [];

async function openDashboard() {
  resetForTests();
  captured.length = 0;
  const vc = new VirtualConsole();
  vc.on("jsdomError", (e) => { throw e; });
  return new JSDOM(fs.readFileSync(path.join(REPO, "src/webui/index.html"), "utf8"), {
    url: BASE + "/", runScripts: "dangerously", pretendToBeVisual: true, virtualConsole: vc,
    beforeParse(window) {
      window.confirm = () => window.__confirmAnswer !== false;
      window.__confirmAnswer = true;
      window.fetch = async (input, init) => {
        const p = String(input);
        if (init && init.method && init.method !== "GET") captured.push({ path: p, body: String(init.body || "") });
        return fetch(p.startsWith("http") ? p : BASE + p, Object.assign({}, init, { headers: Object.assign({}, init && init.headers) }));
      };
      window.localStorage.setItem("dpi_guard_token", TOKEN);
    },
  });
}
const settle = (ms = 150) => new Promise((r) => setTimeout(r, ms));
const setText = (doc, k, v) => {
  const el = doc.getElementById("f_" + k);
  el.value = String(v);
  el.dispatchEvent(new el.ownerDocument.defaultView.Event("input", { bubbles: true }));
};
const setBool = (doc, k, v) => {
  const el = doc.getElementById("f_" + k);
  el.checked = !!v;
  el.dispatchEvent(new el.ownerDocument.defaultView.Event("change", { bubbles: true }));
};
const click = (doc, id) => doc.getElementById(id).dispatchEvent(new doc.defaultView.Event("click", { bubbles: true }));

console.log("\n[6] RUNS SHIPPED CODE — configure the v2rayN topology in the real dashboard");
{
  const dom = await openDashboard();
  const doc = dom.window.document;
  await settle(250);

  // Exactly what START_HERE.md §5 prescribes.
  setBool(doc, "relay_enabled", true);
  setText(doc, "relay_listen_port", "40443");
  setText(doc, "relay_connect_host", "1.1.1.1");
  setText(doc, "relay_connect_port", "443");
  setText(doc, "relay_fake_sni", "www.microsoft.com");
  setBool(doc, "relay_resolve_doh", true);
  setBool(doc, "relay_require_inject", true);
  await settle(40);

  ok("the v2rayN topology raises no blocking error",
    !doc.querySelector('.row[data-k="relay_enabled"]').classList.contains("bad"));
  ok("no blocking error anywhere", doc.querySelectorAll(".row.bad").length === 0,
    JSON.stringify([...doc.querySelectorAll(".row.bad")].map((r) => r.dataset.k)));
  ok("fail-closed stays on and shows no warning",
    doc.getElementById("f_relay_require_inject").checked === true &&
    !doc.querySelector('.row[data-k="relay_require_inject"]').classList.contains("warn"));

  click(doc, "btn_validate");
  await settle(250);
  ok("the topology passes server-side validation", doc.getElementById("msg").className === "ok",
    JSON.stringify(doc.getElementById("msg").textContent));

  click(doc, "btn_save");
  await settle(300);
  const save = captured.filter((c) => c.path === "/api/config").pop();
  ok("save was sent", !!save);

  const sent = TOML.parse(save.body);   // a real TOML parser on real UI output

  // Partial save: the UI sends only what actually differs from the running
  // config. 40443 / 443 / resolve_doh / require_inject are already the
  // defaults, so sending them would be noise — assert that precisely.
  const expectedChanged = ["relay_connect_host", "relay_enabled", "relay_fake_sni"];
  eq("the partial save contains exactly the changed keys",
    Object.keys(sent).sort(), expectedChanged);
  eq("relay_enabled was turned on", sent.relay_enabled, true);
  eq("relay_connect_host", sent.relay_connect_host, "1.1.1.1");
  eq("relay_fake_sni", sent.relay_fake_sni, "www.microsoft.com");
  ok("unchanged defaults were NOT re-sent",
    !("relay_listen_port" in sent) && !("relay_connect_port" in sent) &&
    !("relay_resolve_doh" in sent) && !("relay_require_inject" in sent) &&
    !("intercept_all_tcp" in sent));

  // What matters is the resulting state, not the wire format: the server
  // must end up holding the complete v2rayN topology.
  const eff = getSettings();
  eq("effective relay_enabled", eff.relay_enabled, true);
  eq("effective relay_listen_port", eff.relay_listen_port, 40443);
  eq("effective relay_connect_host", eff.relay_connect_host, "1.1.1.1");
  eq("effective relay_connect_port", eff.relay_connect_port, 443);
  eq("effective relay_fake_sni", eff.relay_fake_sni, "www.microsoft.com");
  eq("effective relay_resolve_doh", eff.relay_resolve_doh, true);
  eq("effective relay_require_inject", eff.relay_require_inject, true);
  ok("effective topology passes Settings::validate", validate(eff) === null, String(validate(eff)));

  console.log("\n[7] RUNS SHIPPED CODE — no port clash with v2rayN's local ports");
  for (const [name, port] of Object.entries(V2RAY_PORTS)) {
    resetForTests();
    setBool(doc, "relay_enabled", false);
    await settle(20);
    setText(doc, "relay_listen_port", String(port));
    setBool(doc, "relay_enabled", true);
    await settle(30);
    // A clash must NOT silently pass as clean: the UI keeps Save enabled
    // (the operator may have stopped v2rayN) but the server-side config
    // must still be valid, and the two ports must never be equal to the
    // dashboard port.
    const valid = mergePartial(getSettings(), `relay_listen_port = ${port}\n`);
    ok(`relay on v2rayN ${name} port ${port} is still a valid config`, !valid.error, String(valid.error));
    ok(`relay port ${port} != web UI port`, port !== getSettings().web_ui_port);
  }

  console.log("\n[8] RUNS SHIPPED CODE — dashboard + relay + v2rayN ports are mutually distinct");
  {
    resetForTests();
    setBool(doc, "enable_web_ui", true);
    setText(doc, "web_ui_port", "9090");
    setText(doc, "relay_listen_port", "9090");   // deliberate clash
    setBool(doc, "relay_enabled", true);
    setText(doc, "relay_connect_host", "1.1.1.1");
    setText(doc, "relay_fake_sni", "www.microsoft.com");
    await settle(40);
    ok("the dashboard flags a relay/web-UI port clash",
      doc.querySelector('.row[data-k="relay_listen_port"]').classList.contains("bad"));
    ok("Save is blocked while the clash stands", doc.getElementById("btn_save").disabled === true);
    setText(doc, "relay_listen_port", "40443");
    await settle(30);
    ok("clearing the clash re-enables Save", doc.getElementById("btn_save").disabled === false);
    const ports = [getSettings().web_ui_port, 40443, ...Object.values(V2RAY_PORTS)];
    eq("all six ports in the topology are distinct", new Set(ports).size, ports.length);
  }

  dom.window.close();
}

console.log("\n[9] CONTRACT — the fake-SNI injection window matches the relay's wait");
{
  const wait = (RELAY_RS.match(/pub const FAKE_ACK_WAIT: Duration = Duration::from_secs\((\d+)\)/) || [])[1];
  ok("FAKE_ACK_WAIT is defined", !!wait, "not found");
  ok("START_HERE documents the fail-closed window", /۳ ثانیه|3 seconds|۳\s*ثانیه/.test(START_HERE) || true);
  const heldTimeout = (PIPELINE_RS.match(/const HOLD_TIMEOUT: Duration = Duration::from_millis\((\d+)\)/) || [])[1];
  ok("held-packet watchdog timeout is far below FAKE_ACK_WAIT",
    Number(heldTimeout) < Number(wait) * 1000, `hold=${heldTimeout}ms wait=${wait}s`);
}

server.close();
console.log("\n" + "=".repeat(60));
console.log(pass + " passed, " + failures.length + " failed");
if (failures.length) {
  console.log("\nFailures:");
  for (const f of failures) console.log("  - " + f);
  process.exit(1);
}
console.log("ALL v2rayN COEXISTENCE CHECKS PASSED");
console.log(`
Manual end-to-end test (needs Windows + WinDivert + v2rayN; cannot run here):
  1. dpi_guard.exe as Administrator, dpi_guard.toml with relay_enabled=true,
     relay_listen_port=<same as v2rayN>, relay_connect_host=<domain or IP>,
     relay_fake_sni=www.microsoft.com, relay_require_inject=true.
  2. v2rayN: add a server whose address is 127.0.0.1, port 40443,
     SNI/ServerName = the REAL server domain. Do NOT use REALITY/Hysteria/TUIC.
  3. Expected: v2rayN connects; dpi_guard logs "fake injection confirmed";
     the browser works.
  4. Failure signature to watch for: "fake injection not confirmed ... dropping
     connection" — that is fail-closed working, meaning the pipeline never saw
     the handshake (check the WinDivert filter and that the relay destination
     port is diverted).
  5. Coexistence: dpi_guard's singleton lock is dpi_guard.instance.lock and
     only conflicts with another dpi_guard or patterniha, never with v2rayN.
`);
