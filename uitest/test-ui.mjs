/*
 * Drives the REAL src/webui/index.html in jsdom against the mock API.
 * This executes the shipped UI code (not a reimplementation of it).
 *
 *   node uitest/test-ui.mjs
 */
import { JSDOM, VirtualConsole } from "jsdom";
import fs from "node:fs";
import path from "node:path";
import { createServer, resetForTests, setStatusForTests, getSettings, DEFAULTS } from "./mock-server.mjs";

const REPO = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const HTML_PATH = path.join(REPO, "src/webui/index.html");
const CONFIG_RS = path.join(REPO, "src/config.rs");
const TOKEN = "dev-token-dev-token";

let pass = 0;
const failures = [];
function ok(name, cond, extra) {
  if (cond) { pass++; console.log("  ok   " + name); }
  else { failures.push(name + (extra ? " — " + extra : "")); console.log("  FAIL " + name + (extra ? " — " + extra : "")); }
}
function eq(name, a, b) { ok(name + ` (got ${JSON.stringify(a)}, want ${JSON.stringify(b)})`, JSON.stringify(a) === JSON.stringify(b)); }

/* ---- Settings field names, parsed out of the real src/config.rs ---- */
function settingsFieldNames() {
  const src = fs.readFileSync(CONFIG_RS, "utf8");
  const start = src.indexOf("pub struct Settings {");
  if (start < 0) throw new Error("Settings struct not found");
  let depth = 0, i = src.indexOf("{", start), body = "";
  for (; i < src.length; i++) {
    if (src[i] === "{") depth++;
    else if (src[i] === "}") { depth--; if (depth === 0) break; }
    if (depth >= 1) body += src[i];
  }
  const names = [];
  for (const line of body.split("\n")) {
    const m = line.match(/^\s*pub\s+([a-z][a-z0-9_]*)\s*:/);
    if (m) names.push(m[1]);
  }
  return names.sort();
}

/* ---------------------------- harness ---------------------------- */

const server = createServer();
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const PORT = server.address().port;
const BASE = `http://127.0.0.1:${PORT}`;

const captured = [];   // every non-GET API request the UI made

async function makeDom({ token = TOKEN, status = null } = {}) {
  resetForTests();
  if (status) setStatusForTests(status);
  captured.length = 0;
  const vc = new VirtualConsole();
  vc.on("jsdomError", (e) => { throw e; });
  const dom = new JSDOM(fs.readFileSync(HTML_PATH, "utf8"), {
    url: BASE + "/",
    runScripts: "dangerously",
    pretendToBeVisual: true,
    virtualConsole: vc,
    // Must run BEFORE the inline script boots, otherwise the page's first
    // fetch uses jsdom's (absent) fetch and the dashboard never loads.
    beforeParse(window) {
      window.confirm = () => window.__confirmAnswer !== false;
      window.__confirmAnswer = true;
      window.fetch = async (input, init) => {
        const p = String(input);
        const url = p.startsWith("http") ? p : BASE + p;
        if (init && init.method && init.method !== "GET") {
          captured.push({ path: p, body: String(init.body || ""), headers: init.headers || {} });
        }
        return fetch(url, Object.assign({}, init, {
          headers: Object.assign({}, init && init.headers),
        }));
      };
      window.localStorage.setItem("dpi_guard_token", token);
    },
  });
  return dom;
}

/** Let pending promises + the boot sequence settle. */
const settle = (ms = 120) => new Promise((r) => setTimeout(r, ms));

/** Wait for a real DOM/API condition instead of relying on a cold-CPU sleep. */
async function waitFor(predicate, timeout = 2000, interval = 20) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (predicate()) return true;
    await settle(interval);
  }
  return !!predicate();
}

function setText(doc, key, value) {
  const el = doc.getElementById("f_" + key);
  if (!el) throw new Error("no control for " + key);
  el.value = String(value);
  el.dispatchEvent(new el.ownerDocument.defaultView.Event("input", { bubbles: true }));
}
function setBool(doc, key, value) {
  const el = doc.getElementById("f_" + key);
  if (!el) throw new Error("no control for " + key);
  el.checked = !!value;
  el.dispatchEvent(new el.ownerDocument.defaultView.Event("change", { bubbles: true }));
}
const click = (doc, id) => doc.getElementById(id).dispatchEvent(
  new doc.defaultView.Event("click", { bubbles: true }));

/* ============================== tests ============================== */

console.log("\n[1] schema coverage against src/config.rs");
const realFields = settingsFieldNames();
eq("Settings field count parsed from config.rs", realFields.length, 82);

{
  const dom = await makeDom();
  const doc = dom.window.document;
  const booted = await waitFor(() =>
    doc.getElementById("f_decoy_ttl")?.value === String(DEFAULTS.decoy_ttl) &&
    doc.querySelectorAll("#cards .card").length >= 10 &&
    doc.querySelectorAll("#profiles button").length === 7,
  );
  ok("dashboard boot completed before assertions", booted);

  console.log("\n[2] every Settings field renders a real, editable control");
  const missingCtl = [];
  const wrongType = [];
  for (const f of realFields) {
    const el = doc.getElementById("f_" + f);
    if (!el) { missingCtl.push(f); continue; }
    const tag = el.tagName.toLowerCase();
    if (!["input", "select", "textarea"].includes(tag)) wrongType.push(f + ":" + tag);
  }
  eq("controls rendered for every field", missingCtl, []);
  eq("all controls are form elements", wrongType, []);
  eq("total field rows rendered", doc.querySelectorAll('.row[data-k]').length, 82);

  console.log("\n[3] no stale keys in the schema (would hit deny_unknown_fields)");
  const uiKeys = [...doc.querySelectorAll('.row[data-k]')].map((r) => r.dataset.k).sort();
  eq("UI keys == Settings fields", uiKeys, realFields);

  console.log("\n[4] page is self-contained (CSP default-src 'none')");
  const html = fs.readFileSync(HTML_PATH, "utf8");
  ok("no external script/link/CDN", !/src="http|href="http|cdn\.|@import/i.test(html));
  ok("declares every API route it uses",
    ["/api/status", "/api/config", "/api/config/toml", "/api/profile", "/api/validate"]
      .every((r) => html.includes(r)));

  console.log("\n[5] baseline loaded from /api/config into the form");
  eq("decoy_ttl control shows server value", doc.getElementById("f_decoy_ttl").value, String(DEFAULTS.decoy_ttl));
  eq("mutation_profile select shows server value", doc.getElementById("f_mutation_profile").value, "Stealth");
  eq("bool control reflects server value", doc.getElementById("f_enable_decoys").checked, true);
  eq("secret token field is NOT pre-filled with a secret", doc.getElementById("f_web_ui_token").value, "");
  ok("status cards rendered", doc.querySelectorAll("#cards .card").length >= 10,
    "got " + doc.querySelectorAll("#cards .card").length);
  ok("strategy scores rendered", doc.querySelectorAll("#scores tr").length >= 3);
  ok("profile buttons rendered", doc.querySelectorAll("#profiles button").length === 7);

  console.log("\n[6] editing marks the row dirty and enables Save");
  ok("Save disabled when clean", doc.getElementById("btn_save").disabled === true);
  setText(doc, "decoy_ttl", 21);
  await settle(20);
  ok("Save enabled after a change", doc.getElementById("btn_save").disabled === false);
  ok("row marked dirty", doc.querySelector('.row[data-k="decoy_ttl"]').classList.contains("dirty"));
  ok("dirty pill shows 1", doc.getElementById("dirtypill").textContent.includes("1"));

  console.log("\n[7] Save POSTs partial TOML containing ONLY the changed key");
  click(doc, "btn_save");
  await settle(200);
  const save = captured.find((c) => c.path === "/api/config");
  ok("POST /api/config was sent", !!save);
  ok("body is exactly the changed key", save.body.trim() === "decoy_ttl = 21", JSON.stringify(save.body));
  eq("server applied it", getSettings().decoy_ttl, 21);
  ok("untouched field preserved on server", getSettings().fragment_chunk_size === DEFAULTS.fragment_chunk_size);

  console.log("\n[8] client-side validation mirrors Settings::validate");
  const cases = [
    ["decoy_ttl", "0", false],
    ["decoy_ttl", "65", false],
    ["decoy_ttl", "8", true],
    ["fragment_chunk_size", "1", false],
    ["fragment_chunk_size", "4", false],
    ["fragment_chunk_size", "0", true],
    ["fragment_chunk_size", "64", true],
    ["tls_record_chunk_size", "20000", false],
    ["autottl_delta", "33", false],
    ["autottl_delta", "32", true],
    ["web_ui_token", "short", false],
    ["web_ui_token", "0123456789abcdef", true],
    ["kill_switch_adapter", 'Wi-Fi; calc', false],
    ["kill_switch_adapter", "Wi-Fi 2", true],
    ["doh_server", "http://1.1.1.1/dns-query", false],
    ["doh_server", "https://user:pass@1.1.1.1/dns-query", false],
    ["doh_server", "https://cloudflare-dns.com/dns-query", true],
    ["trusted_dns", "not-an-ip", false],
    ["trusted_dns", "", true],
    ["relay_fake_sni", "bad host!", false],
    ["relay_fake_sni", "www.microsoft.com", true],
    ["intercept_ports", "0", false],
    ["intercept_ports", "443,8443", true],
    ["sni_only", "bad pat!tern", false],
    ["sni_only", "*.example.com,keep.org", true],
    ["utls_browser", "opera", false],
  ];
  for (const [key, val, wantValid] of cases) {
    setText(doc, key, val);
    await settle(5);
    const bad = doc.querySelector('.row[data-k="' + key + '"]').classList.contains("bad");
    ok(`${key}=${JSON.stringify(val)} -> ${wantValid ? "accepted" : "rejected"}`, bad === !wantValid);
  }
  // put the form back to something valid
  for (const [key, val] of [["decoy_ttl", "21"], ["fragment_chunk_size", "64"],
    ["tls_record_chunk_size", "0"], ["autottl_delta", "0"], ["web_ui_token", ""],
    ["kill_switch_adapter", ""], ["doh_server", DEFAULTS.doh_server], ["trusted_dns", ""],
    ["relay_fake_sni", ""], ["intercept_ports", ""], ["sni_only", ""], ["utls_browser", "chrome"]]) {
    setText(doc, key, val);
  }
  await settle(20);

  console.log("\n[9] cross-field rules");
  setBool(doc, "relay_enabled", true);
  await settle(20);
  ok("relay_enabled without host shows an error",
    doc.querySelector('.row[data-k="relay_connect_host"]').classList.contains("bad"));
  ok("relay_enabled without fake SNI shows an error",
    doc.querySelector('.row[data-k="relay_fake_sni"]').classList.contains("bad"));
  ok("Save blocked while cross-field errors exist", doc.getElementById("btn_save").disabled === true);
  setText(doc, "relay_connect_host", "1.1.1.1");
  setText(doc, "relay_fake_sni", "www.microsoft.com");
  await settle(20);
  ok("errors cleared once both are set",
    !doc.querySelector('.row[data-k="relay_connect_host"]').classList.contains("bad"));

  console.log("\n[10] dangerous toggles ask for confirmation");
  dom.window.__confirmAnswer = false;
  setBool(doc, "relay_require_inject", false);
  await settle(20);
  eq("fail-closed stays ON when the operator cancels", doc.getElementById("f_relay_require_inject").checked, true);
  setBool(doc, "intercept_all_tcp", false);
  await settle(10);
  dom.window.__confirmAnswer = true;
  setBool(doc, "intercept_all_tcp", true);
  await settle(20);
  ok("intercept_all_tcp accepted after confirmation", doc.getElementById("f_intercept_all_tcp").checked === true);

  console.log("\n[11] validate endpoint is a dry run (no save)");
  const before = JSON.parse(JSON.stringify(getSettings()));
  setText(doc, "decoy_ttl", 33);
  await settle(10);
  click(doc, "btn_validate");
  await settle(200);
  ok("POST /api/validate was sent", captured.some((c) => c.path === "/api/validate"));
  eq("server state unchanged by validate", JSON.stringify(getSettings()), JSON.stringify(before));
  ok("success message shown", doc.getElementById("msg").className === "ok");

  console.log("\n[12] server-side rejection surfaces in the UI");
  setText(doc, "decoy_ttl", "33");
  setText(doc, "utls_browser", "chrome");
  click(doc, "btn_save");
  await settle(200);
  ok("valid save succeeded", getSettings().decoy_ttl === 33);
  // A destination the client-side rule accepts but netguard refuses
  // (*.internal is on the server's forbidden-name list).
  setText(doc, "relay_connect_host", "printer.internal");
  await settle(20);
  ok("client-side check does not pre-empt this one",
    !doc.querySelector('.row[data-k="relay_connect_host"]').classList.contains("bad"));
  await settle(20);
  click(doc, "btn_save");
  await settle(250);
  ok("server rejection is displayed", /forbidden|config error/i.test(doc.getElementById("msg").textContent),
    JSON.stringify(doc.getElementById("msg").textContent));
  setText(doc, "relay_connect_host", "1.1.1.1");
  await settle(10);
  click(doc, "btn_save");
  await settle(250);

  console.log("\n[13] revert restores the baseline");
  setText(doc, "decoy_ttl", "45");
  setText(doc, "fronting_benign_sni", "cdn.example.net");
  await settle(30);
  const nDirtyBefore = dom.window.document.querySelectorAll(".row.dirty").length;
  click(doc, "btn_revert");
  await settle(50);
  ok("dirty rows existed before revert", nDirtyBefore > 0, "n=" + nDirtyBefore);
  ok("revert made a difference", nDirtyBefore >= 2, "n=" + nDirtyBefore);
  eq("no dirty rows after revert", doc.querySelectorAll(".row.dirty").length, 0);
  eq("control value restored", doc.getElementById("f_decoy_ttl").value, String(getSettings().decoy_ttl));

  console.log("\n[14] advanced TOML editor round-trip");
  click(doc, "btn_toml_load");
  await settle(200);
  const tomlText = doc.getElementById("toml").value;
  ok("TOML loaded from server", tomlText.includes("mutation_profile"));
  ok("token redacted in the served TOML", !/web_ui_token = "[^"]+"/.test(tomlText));
  ok("driver pins redacted in the served TOML", !/win_divert_sha256 = \[[^\]]/.test(tomlText));
  ok("full config fits the 4096-byte UI body cap", tomlText.length < 4096, "len=" + tomlText.length);
  click(doc, "btn_toml_validate");
  await settle(200);
  ok("advanced validate succeeded", doc.getElementById("msg").className === "ok",
    JSON.stringify(doc.getElementById("msg").textContent));
  doc.getElementById("toml").value = tomlText.replace(/decoy_ttl = \d+/, "decoy_ttl = 7");
  const requestsBeforeRawConfirm = captured.length;
  dom.window.__confirmAnswer = false;
  click(doc, "btn_toml_save");
  await settle(50);
  ok("raw TOML dangerous flags still require confirmation", captured.length === requestsBeforeRawConfirm);
  dom.window.__confirmAnswer = true;
  click(doc, "btn_toml_save");
  await settle(250);
  eq("advanced editor save applied", getSettings().decoy_ttl, 7);

  console.log("\n[15] search + only-changed filters");
  doc.getElementById("q").value = "sni";
  doc.getElementById("q").dispatchEvent(new dom.window.Event("input", { bubbles: true }));
  await settle(20);
  const visible = [...doc.querySelectorAll('.row[data-k]')].filter((r) => !r.classList.contains("hide"));
  ok("search narrows the list", visible.length > 0 && visible.length < 47, "visible=" + visible.length);
  ok("every visible row matches the query",
    visible.every((r) => (r.dataset.k + " " + r.textContent).toLowerCase().includes("sni")));
  doc.getElementById("q").value = "";
  doc.getElementById("q").dispatchEvent(new dom.window.Event("input", { bubbles: true }));
  await settle(20);
  eq("clearing the search shows all rows again",
    [...doc.querySelectorAll('.row[data-k]')].filter((r) => !r.classList.contains("hide")).length, 82);

  console.log("\n[16] mutation-profile shortcut posts /api/profile");
  const pbtn = [...doc.querySelectorAll("#profiles button")].find((b) => b.dataset.p === "Henan");
  pbtn.dispatchEvent(new dom.window.Event("click", { bubbles: true }));
  await settle(250);
  ok("POST /api/profile sent", captured.some((c) => c.path === "/api/profile"));
  eq("server profile updated", getSettings().mutation_profile, "Henan");

  console.log("\n[17] list + secret fields serialize as valid TOML");
  setText(doc, "intercept_ports", "443, 8443,2053");
  setText(doc, "sni_only", "*.example.com,keep.org");
  setText(doc, "rotate_ips", "1.2.3.4,5.6.7.8");
  setText(doc, "web_ui_token", "abcdefghijklmnop");
  setText(doc, "win_divert_sha256", "a".repeat(64) + "," + "b".repeat(64));
  setText(doc, "kill_switch_adapter", "Wi-Fi 2");
  setBool(doc, "intercept_all_tcp", false);
  setBool(doc, "intercept_all_udp", false);
  setBool(doc, "enable_kill_switch", true);
  await settle(30);
  click(doc, "btn_save");
  await settle(300);
  const last = captured.filter((c) => c.path === "/api/config").pop();
  ok("list save sent", !!last);
  ok("intercept_ports serialized as a TOML array", /intercept_ports = \[443, 8443, 2053\]/.test(last.body),
    JSON.stringify(last.body));
  ok("sni_only serialized with quoted strings", /sni_only = \["\*\.example\.com", "keep\.org"\]/.test(last.body));
  ok("both SHA-256 pins accepted", getSettings().win_divert_sha256.length === 2);
  ok("token saved", getSettings().web_ui_token === "abcdefghijklmnop");
  ok("kill switch + adapter saved", getSettings().enable_kill_switch === true && getSettings().kill_switch_adapter === "Wi-Fi 2");
  ok("whole body under the 4096-byte cap", last.body.length < 4096, "len=" + last.body.length);

  console.log("\n[18] empty secret means 'leave as-is' (Save never wipes them)");
  setText(doc, "web_ui_token", "");
  setText(doc, "win_divert_sha256", "");
  setText(doc, "decoy_ttl", "9");
  await settle(20);
  click(doc, "btn_save");
  await settle(250);
  ok("token preserved", getSettings().web_ui_token === "abcdefghijklmnop",
    JSON.stringify(getSettings().web_ui_token));
  ok("pins preserved", getSettings().win_divert_sha256.length === 2);
  eq("other change still applied", getSettings().decoy_ttl, 9);

  console.log("\n[19] export contains every non-secret field");
  let exported = null;
  dom.window.URL.createObjectURL = (blob) => { exported = blob; return "blob:x"; };
  dom.window.URL.revokeObjectURL = () => {};
  let clicked = null;
  const origCreate = doc.createElement.bind(doc);
  doc.createElement = (t) => {
    const el = origCreate(t);
    if (t === "a") el.click = () => { clicked = el.download; };
    return el;
  };
  click(doc, "btn_export");
  await settle(50);
  ok("export triggered a download", clicked === "dpi_guard_ui_settings.json");
  const json = JSON.parse(await exported.text());
  const exportedKeys = Object.keys(json).sort();
  eq("export covers every non-secret field", exportedKeys.length, 80);
  ok("export omits secrets", !("web_ui_token" in json) && !("win_divert_sha256" in json));

  dom.window.close();
}

/* ---- 401 handling ---- */
console.log("\n[20] a bad token surfaces the token dialog (401 path)");
{
  const dom = await makeDom({ token: "wrong-token-wrong-token" });
  const doc = dom.window.document;
  await settle(300);
  ok("token overlay shown on 401", !doc.getElementById("ovl").classList.contains("hide"));
  ok("connection pill shows disconnected", doc.getElementById("conn").className === "pill off");
  ok("bad token cleared from storage", dom.window.localStorage.getItem("dpi_guard_token") === null);
  dom.window.close();
}

/* ---- hostile server values / XSS regression ---- */
console.log("\n[21] hostile status values render as text, not markup");
{
  const hostile = '<img src=x onerror=alert(1)>';
  const dom = await makeDom({
    status: {
      mutation_profile: hostile,
      fronting_benign_sni: hostile,
      recent_domains: [hostile],
      strategy_scores: [{ key: hostile, score: hostile }],
    },
  });
  const doc = dom.window.document;
  const booted = await waitFor(() => doc.getElementById("conn").className === "pill on");
  ok("hostile status fixture loaded", booted);
  ok("hostile card values are text, not elements",
    doc.querySelectorAll("#cards img, #cards svg, #cards script").length === 0 &&
    doc.getElementById("cardv_profile").textContent === hostile &&
    doc.getElementById("cardv_fronting").textContent === hostile);
  ok("hostile strategy score is text, not markup",
    doc.querySelectorAll("#scores img, #scores svg, #scores script").length === 0 &&
    doc.querySelector("#scores tr td")?.textContent === hostile);
  ok("hostile recent domain uses textContent",
    doc.getElementById("domains").textContent === hostile &&
    doc.getElementById("domains").children.length === 0);
  dom.window.close();
}

/* ---- HTML hygiene ---- */
console.log("\n[22] HTML hygiene");
{
  const html = fs.readFileSync(HTML_PATH, "utf8");
  ok("balanced <html>", (html.match(/<html/g) || []).length === 1 && (html.match(/<\/html>/g) || []).length === 1);
  ok("has a charset", /<meta charset="utf-8">/i.test(html));
  ok("is RTL Persian", /dir="rtl"/.test(html) && /lang="fa"/.test(html));
  ok("uses strict mode", /"use strict"/.test(html));
  // Every server-derived value rendered as HTML must go through esc();
  // the one place raw text is inserted uses textContent instead.
  ok("recent domains use textContent, not innerHTML",
    /\$\("domains"\)\.textContent =/.test(html));
  // Concretely: every value interpolated into an innerHTML builder must
  // pass through esc(), and the card builder must escape its own label.
  //
  // The cards are built ONCE from the CARD_DEFS table and only their value
  // node is refreshed on each poll (that was the fix for the overview
  // "jumping" — replacing #cards innerHTML every 4s reflowed the page).
  // So the schema under test is CARD_DEFS, and the builder is
  // buildCardsOnce() — not the old per-tick card("label", value) helper.
  const cardDefs = [...html.matchAll(/\{\s*id:\s*"([a-z0-9_]+)",\s*label:\s*"((?:[^"\\]|\\.)*)"/g)];
  ok("status cards exist", cardDefs.length >= 10, "n=" + cardDefs.length);
  const cardVals = [...html.matchAll(/get:\s*\(s\)\s*=>\s*([\s\S]*?)(?=\n\s*\{ id:|\n\];)/g)]
    .map((m) => m[1].trim());
  ok("one value getter per card definition", cardVals.length, cardDefs.length);
  ok("every status-card value is escaped or a badge",
    cardVals.every((v) => v.startsWith("esc(") || v.startsWith("badge(")),
    JSON.stringify(cardVals.filter((v) => !v.startsWith("esc(") && !v.startsWith("badge("))));
  ok("the card builder escapes its own label",
    /function buildCardsOnce\(\)[\s\S]{0,240}esc\(c\.label\)/.test(html));
  ok("strategy-score cells are escaped",
    /esc\(x\.key\)/.test(html) && /esc\(x\.score\)/.test(html));
  ok("profile buttons escape the profile name",
    /data-p="' \+ esc\(p\)/.test(html));
  ok("esc() escapes the HTML-significant set",
    /\[&<>"'`\]/.test(html) && html.includes("&amp;") && html.includes("&lt;"));
  const ids = [...html.matchAll(/id="([a-zA-Z_][\w]*)"/g)].map((m) => m[1]);
  const dup = ids.filter((x, i) => ids.indexOf(x) !== i);
  eq("no duplicate element ids", [...new Set(dup)], []);
}

server.close();
console.log("\n[A11y] the tab strip is a real ARIA tablist");
{
  /* aria-selected on a plain <button> is meaningless to a screen reader:
   * it is only valid on role="tab" inside role="tablist", and the tab has
   * to point at its panel with aria-controls. Fixed 2026-09-26; locked here. */
  const dom = await makeDom();
  await settle(250);
  const doc = dom.window.document;
  const bar = doc.getElementById("tabbar");
  const tabs = [...doc.querySelectorAll('.tabbtn')];
  ok("tab strip is a tablist", bar.getAttribute("role") === "tablist",
    "role=" + bar.getAttribute("role"));
  ok("every tab button has role=tab",
    tabs.length === 6 && tabs.every((b) => b.getAttribute("role") === "tab"),
    "tabs=" + tabs.length);
  const dangling = tabs.filter((b) => {
    const id = b.getAttribute("aria-controls");
    return !id || !doc.getElementById(id) ||
      doc.getElementById(id).getAttribute("role") !== "tabpanel";
  }).map((b) => b.getAttribute("aria-controls"));
  ok("every tab controls an existing tabpanel", dangling.length === 0,
    "dangling=" + JSON.stringify(dangling));
  const panels = [...doc.querySelectorAll('[role="tabpanel"]')];
  ok("every panel is labelled by its tab", panels.length === 6 &&
    panels.every((p) => {
      const lbl = doc.getElementById(p.getAttribute("aria-labelledby") || "");
      return lbl && lbl.getAttribute("role") === "tab";
    }), "panels=" + panels.length);
  ok("exactly one tab is selected and it matches the visible panel",
    tabs.filter((b) => b.getAttribute("aria-selected") === "true").length === 1 &&
    doc.querySelector(".tabpage.active").getAttribute("role") === "tabpanel");
  dom.window.close();
}

console.log("\n" + "=".repeat(56));
console.log(pass + " passed, " + failures.length + " failed");
if (failures.length) {
  console.log("\nFailures:");
  for (const f of failures) console.log("  - " + f);
  process.exit(1);
}
console.log("ALL UI TESTS PASSED");
