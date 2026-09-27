/*
 * Settings-UI tests: quick-access toolbar, restart-required hints,
 * feature counter, and dirty-tracking of bulk toggles.
 *
 * Drives the REAL src/webui/index.html in jsdom against the mock API:
 *   node uitest/test-settings.mjs
 */
import { JSDOM, VirtualConsole } from "jsdom";
import fs from "node:fs";
import path from "node:path";
import { createServer, resetForTests, getSettings, DEFAULTS } from "./mock-server.mjs";

const REPO = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const HTML_PATH = path.join(REPO, "src/webui/index.html");
const TOKEN = "dev-token-dev-token";

let pass = 0;
const failures = [];
function ok(name, cond, extra) {
  if (cond) { pass++; console.log("  ok   " + name); }
  else { failures.push(name + (extra ? " — " + extra : "")); console.log("  FAIL " + name + (extra ? " — " + extra : "")); }
}
function eq(name, a, b) { ok(name + ` (got ${JSON.stringify(a)}, want ${JSON.stringify(b)})`, JSON.stringify(a) === JSON.stringify(b)); }

const server = createServer();
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const PORT = server.address().port;
const BASE = `http://127.0.0.1:${PORT}`;

const captured = [];

async function makeDom() {
  resetForTests();
  captured.length = 0;
  const vc = new VirtualConsole();
  vc.on("jsdomError", (e) => { throw e; });
  const dom = new JSDOM(fs.readFileSync(HTML_PATH, "utf8"), {
    url: BASE + "/",
    runScripts: "dangerously",
    pretendToBeVisual: true,
    virtualConsole: vc,
    beforeParse(window) {
      window.confirm = () => true;
      window.fetch = async (input, init) => {
        const p = String(input);
        const url = p.startsWith("http") ? p : BASE + p;
        if (init && init.method && init.method !== "GET") {
          captured.push({ path: p, body: String(init.body || "") });
        }
        return fetch(url, Object.assign({}, init, {
          headers: Object.assign({}, init && init.headers),
        }));
      };
      window.localStorage.setItem("dpi_guard_token", TOKEN);
    },
  });
  return dom;
}

const settle = (ms = 120) => new Promise((r) => setTimeout(r, ms));
const click = (doc, id) => doc.getElementById(id).dispatchEvent(
  new doc.defaultView.Event("click", { bubbles: true }));
function setBool(doc, key, value) {
  const el = doc.getElementById("f_" + key);
  el.checked = !!value;
  el.dispatchEvent(new el.ownerDocument.defaultView.Event("change", { bubbles: true }));
}

console.log("\n[S1] quick-access toolbar toggles mark rows dirty");
{
  const dom = await makeDom();
  const doc = dom.window.document;
  await settle(250);

  const features = ["enable_anti_fingerprint", "randomize_ip_id", "randomize_packet_size",
    "enable_reverse_frag", "enable_wrong_seq", "enable_wrong_checksum",
    "enable_oob_injection", "enable_hostdot", "enable_fake_with_sni"];
  // enable_wrong_seq / enable_wrong_checksum default to TRUE: a decoy that
  // carries a valid checksum and an in-window sequence number is a real
  // packet, not a decoy (see the doc comment in src/config.rs). Everything
  // else in the bundle starts off.
  const startsOn = new Set(["enable_wrong_seq", "enable_wrong_checksum"]);
  for (const f of features)
    eq("starts at its documented default: " + f,
       doc.getElementById("f_" + f).checked, startsOn.has(f));

  click(doc, "qa_all_on");
  await settle(30);
  for (const f of features) eq("qa_all_on enables " + f, doc.getElementById("f_" + f).checked, true);
  ok("Save enabled after bulk toggle", doc.getElementById("btn_save").disabled === false);
  // The two that were already on cannot become dirty.
  ok("dirty rows counted",
    doc.querySelectorAll(".row.dirty").length >= features.length - startsOn.size,
    "n=" + doc.querySelectorAll(".row.dirty").length);

  click(doc, "btn_save");
  await settle(250);
  const save = captured.find((c) => c.path === "/api/config");
  ok("bulk toggle POSTed a partial TOML", !!save);
  for (const f of features) ok("server applied " + f, getSettings()[f] === true);
  // This set does NOT include restart-flagged fields: the message must
  // stay the plain hot-reload one (no restart warning).
  ok("no restart warning for hot-reloadable keys", doc.getElementById("msg").className === "ok",
    JSON.stringify(doc.getElementById("msg").textContent));

  click(doc, "qa_all_off");
  await settle(30);
  click(doc, "btn_save");
  await settle(250);
  for (const f of features) ok("qa_all_off applied " + f, getSettings()[f] === false);
  dom.window.close();
}

console.log("\n[S2] profile shortcuts set the mutation profile + technique set");
{
  const dom = await makeDom();
  const doc = dom.window.document;
  await settle(250);

  click(doc, "qa_stealth");
  await settle(30);
  eq("stealth preset selects the Stealth profile", doc.getElementById("f_mutation_profile").value, "Stealth");
  eq("stealth keeps decoys on", doc.getElementById("f_enable_decoys").checked, true);
  eq("stealth keeps SNI fragmentation on", doc.getElementById("f_enable_sni_fragmentation").checked, true);
  eq("stealth turns reverse-frag off", doc.getElementById("f_enable_reverse_frag").checked, false);

  click(doc, "btn_save");
  await settle(250);
  eq("server profile saved", getSettings().mutation_profile, "Stealth");

  click(doc, "qa_aggressive");
  await settle(30);
  eq("aggressive preset selects the Aggressive profile", doc.getElementById("f_mutation_profile").value, "Aggressive");
  click(doc, "btn_save");
  await settle(250);
  eq("server profile saved (Aggressive)", getSettings().mutation_profile, "Aggressive");
  dom.window.close();
}

console.log("\n[S3] restart-required settings are tagged and warned");
{
  const dom = await makeDom();
  const doc = dom.window.document;
  await settle(250);

  // The schema flags exactly the startup-only settings (audit gap C110:
  // hot-reload cannot apply these; they are read once at boot). Sorted to
  // match Array.prototype.sort() order used above. The scanner quartet
  // (edge_candidates, enable_sni_scanner, sni_candidates, sni_rotation_mode)
  // is boot-only too: backend_main consumes them once when spawning the
  // SNI scanner thread, so the schema restart tag is correct.
  const tagged = [...doc.querySelectorAll('.row[data-k]')]
    .filter((r) => r.textContent.includes("نیاز به ری‌استارت"))
    .map((r) => r.dataset.k).sort();
  eq("restart-tagged fields are exactly the startup-only ones",
    tagged, ["edge_candidates", "enable_client_detect", "enable_kill_switch",
      "enable_mobile_gateway", "enable_proxy_cleanup", "enable_self_update",
      "enable_sni_scanner", "enable_web_ui", "enable_youtube_warmup",
      "injection_delay_max_ms", "injection_delay_min_ms", "isp_profile",
      "kill_switch_adapter", "sni_candidates", "sni_rotation_mode",
      "update_repo", "web_ui_port", "web_ui_token", "win_divert_sha256"]);

  // Saving a restart-flagged key shows the restart hint...
  setBool(doc, "enable_web_ui", !DEFAULTS.enable_web_ui);
  await settle(20);
  click(doc, "btn_save");
  await settle(250);
  ok("restart hint shown for enable_web_ui",
    /اجرای مجدد/.test(doc.getElementById("msg").textContent),
    JSON.stringify(doc.getElementById("msg").textContent));
  eq("server applied enable_web_ui", getSettings().enable_web_ui, !DEFAULTS.enable_web_ui);

  // ...but a plain hot-reloadable key never does.
  const el = doc.getElementById("f_decoy_ttl");
  el.value = String(DEFAULTS.decoy_ttl + 3);
  el.dispatchEvent(new dom.window.Event("input", { bubbles: true }));
  await settle(20);
  click(doc, "btn_save");
  await settle(250);
  ok("no restart warning for decoy_ttl",
    doc.getElementById("msg").className === "ok",
    JSON.stringify(doc.getElementById("msg").textContent));
  dom.window.close();
}

console.log("\n[S4] feature counter reflects the live state");
{
  const dom = await makeDom();
  const doc = dom.window.document;
  await settle(250);
  const before = doc.getElementById("feature_count").textContent;
  ok("counter renders at boot", /\d+ از \d+ قابلیت فعال/.test(before), before);

  click(doc, "qa_all_on");
  await settle(30);
  const after = doc.getElementById("feature_count").textContent;
  const nBefore = parseInt(before, 10);
  const nAfter = parseInt(after, 10);
  ok("counter increases after enabling techniques", nAfter > nBefore,
    `${before} -> ${after}`);
  dom.window.close();
}

console.log("\n[S5] revert also clears bulk quick-access changes");
{
  const dom = await makeDom();
  const doc = dom.window.document;
  await settle(250);
  click(doc, "qa_all_on");
  await settle(30);
  ok("dirty rows exist before revert", doc.querySelectorAll(".row.dirty").length > 0);
  click(doc, "btn_revert");
  await settle(50);
  eq("all bulk changes reverted", doc.querySelectorAll(".row.dirty").length, 0);
  eq("reverse-frag back to server value",
    doc.getElementById("f_enable_reverse_frag").checked,
    !!DEFAULTS.enable_reverse_frag);
  dom.window.close();
}

console.log("\n[S6] the mock's defaults ARE Settings::default()");
{
  /* Same class of drift as [O6] on /api/status, one level deeper: if a
   * default in the mock disagrees with `impl Default for Settings` in
   * src/config.rs, every UI assertion about that field tests a value the
   * real binary never produces. Two real drifts were found this way —
   * enable_tls_record_fragmentation (mock true vs Rust false) and
   * update_repo (mock pointed at a repo that is not DEFAULT_UPDATE_REPO). */
  const CFG = fs.readFileSync(path.join(REPO, "src", "config.rs"), "utf8");
  const at = CFG.indexOf("impl Default for Settings");
  if (at < 0) throw new Error("impl Default for Settings not found in src/config.rs");
  const body = CFG.slice(at, CFG.indexOf("\n}\n", at));

  // `fn default_xxx() -> T { VALUE }` helpers, and `crate::m::CONST` consts.
  const helpers = new Map();
  for (const m of CFG.matchAll(/^fn (default_[a-z_0-9]+)\(\)[^{]*\{\s*(.+?)\s*\}/gm)) {
    helpers.set(m[1], m[2]);
  }
  const constValue = (module, name) => {
    try {
      const src = fs.readFileSync(path.join(REPO, "src", module + ".rs"), "utf8");
      const m = src.match(new RegExp("pub const " + name + ": &str = \"([^\"]*)\""));
      return m ? m[1] : null;
    } catch {
      return null;
    }
  };

  const norm = (raw) => {
    let v = Array.isArray(raw) ? JSON.stringify(raw) : String(raw).trim();
    v = v.replace(/\.to_string\(\)/g, "").replace(/\.into\(\)$/, "");
    v = v.replace(/^vec!\[(.*)\]$/, "[$1]");
    if (/^\[.*\]$/.test(v)) return v.replace(/\s+/g, "");
    v = v.replace(/^"(.*)"$/, "$1").replace(/^'(.*)'$/, "$1");
    if (v === "Vec::new()" || v === "[]") return "[]";
    if (v === "String::new()") return "";
    if (/^\d+_u?\d*$/.test(v)) return v.replace(/_.*$/, "");
    if (/^-?\d+\.0$/.test(v)) return v.slice(0, -2);
    return v;
  };

  const resolve = (v) => {
    v = v.trim();
    const h = v.match(/^(default_[a-z_0-9]+)\(\)$/);
    if (h && helpers.has(h[1])) v = helpers.get(h[1]);
    const c = v.match(/^crate::([a-z_0-9]+)::([A-Z_0-9]+)\.to_string\(\)$/);
    if (c) v = '"' + constValue(c[1], c[2]) + '"';
    return norm(v);
  };

  const rust = new Map();
  for (const m of body.matchAll(/^\s+([a-z_0-9]+):\s*(.+?),\s*$/gm)) {
    rust.set(m[1], resolve(m[2]));
  }
  ok("parsed the real Default impl", rust.size >= 80, "n=" + rust.size);

  // trusted_dns is Option<String>: the real default is None, which the TOML
  // layer encodes as "absent" — the mock deliberately omits the key.
  rust.delete("trusted_dns");
  const mock = new Map(Object.entries(DEFAULTS).map(([k, v]) => [k, norm(v)]));

  const missing = [...rust.keys()].filter((k) => !mock.has(k));
  const extra = [...mock.keys()].filter((k) => !rust.has(k));
  const wrong = [...rust.keys()]
    .filter((k) => mock.has(k) && mock.get(k) !== rust.get(k))
    .map((k) => `${k}: rust=${rust.get(k)} mock=${mock.get(k)}`);

  ok("mock declares every field Settings::default() sets", missing.length === 0,
    "missing=" + JSON.stringify(missing));
  ok("mock declares no field Settings::default() lacks", extra.length === 0,
    "extra=" + JSON.stringify(extra));
  ok("every default value matches the Rust default", wrong.length === 0,
    "\n      " + wrong.join("\n      "));
  ok("the comparison is meaningful", rust.size > 75 && mock.size > 75,
    `rust=${rust.size} mock=${mock.size}`);

  // The dashboard must render the real default for a flag, not its own idea.
  const dom = await makeDom();
  const d = dom.window.document;
  await settle(250); // let boot() populate the form before the window closes
  const shown = d.getElementById("f_enable_tls_record_fragmentation");
  ok("default of enable_tls_record_fragmentation is off in the UI",
    !!shown && shown.checked === false,
    "checked=" + (shown ? shown.checked : "control missing"));
  dom.window.close();
}

server.close();
console.log("\n========================================================");
if (failures.length) {
  console.log(`${pass} passed, ${failures.length} FAILED`);
  process.exit(1);
} else {
  console.log(`${pass} passed, 0 failed`);
  console.log("ALL SETTINGS-UI TESTS PASSED");
}
