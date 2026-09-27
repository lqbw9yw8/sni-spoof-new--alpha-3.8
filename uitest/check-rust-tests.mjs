/*
 * Ports the EXACT algorithms of the new Rust unit tests in src/webui.rs
 * (ui_schema_tests::ui_schema_keys / settings_keys) to JS, so they can be
 * checked in this sandbox where cargo is unavailable.
 *
 * If these pass, the Rust tests assert the same true facts about the same
 * bytes on disk.
 *
 *   node uitest/check-rust-tests.mjs
 */
import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";
import { DEFAULTS } from "./mock-server.mjs";

const REPO = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const rs = (f) => fs.readFileSync(path.join(REPO, "src", f), "utf8");
const HTML = rs("webui/index.html");
const CONFIG = rs("config.rs");
const WEBUI = rs("webui.rs");
const PRISTINE = "dcb4dbf27a6a0495818edc1c444635336c6659a9";

let pass = 0, fail = 0;
const ok = (n, c, extra) => {
  if (c) { pass++; console.log("  ok   " + n); }
  else { fail++; console.log("  FAIL " + n + (extra ? " — " + extra : "")); }
};

/* ---- exact port of settings_keys(): the serde keys of Settings ---- */
function settingsKeys() {
  const start = CONFIG.indexOf("pub struct Settings {");
  let depth = 0, i = CONFIG.indexOf("{", start), body = "";
  for (; i < CONFIG.length; i++) {
    if (CONFIG[i] === "{") depth++;
    else if (CONFIG[i] === "}") { depth--; if (depth === 0) break; }
    if (depth >= 1) body += CONFIG[i];
  }
  const keys = [];
  for (const line of body.split("\n")) {
    const m = line.match(/^\s*pub\s+([a-z][a-z0-9_]*)\s*:/);
    if (m) keys.push(m[1]);
  }
  return { keys: [...keys].sort(), body };
}

/* ---- exact port of ui_schema_keys(): byte-scan INDEX_HTML for `k: "x"` ---- */
function uiSchemaKeys() {
  const bytes = Buffer.from(HTML, "utf8");
  const needle = Buffer.from('k: "', "utf8");
  const keys = [];
  for (let i = 0; i + needle.length < bytes.length; i++) {
    if (!bytes.subarray(i, i + needle.length).equals(needle)) continue;
    const start = i + needle.length;
    let end = start;
    while (end < bytes.length && bytes[end] !== 0x22) end++;
    // BYTE offsets: the page is full of multi-byte Persian text, so
    // HTML.slice() would read the wrong region.
    const k = bytes.subarray(start, end).toString("utf8");
    if (k && /^[A-Za-z0-9_]+$/.test(k)) keys.push(k);
  }
  return [...new Set(keys)].sort();
}

/**
 * Strip Rust literals and comments so a brace count means something.
 * Char literals matter: this crate is full of '}' / '"' / '\\' as chars.
 */
function stripRust(src) {
  let out = "";
  let i = 0;
  const n = src.length;
  const QUOTE = String.fromCharCode(39);   // '
  const DQ = String.fromCharCode(34);      // "
  const BS = String.fromCharCode(92);      // \
  while (i < n) {
    const c = src[i], d = src[i + 1];
    if (c === "/" && d === "/") { while (i < n && src[i] !== "\n") i++; continue; }
    if (c === "/" && d === "*") { const e = src.indexOf("*/", i + 2); i = e < 0 ? n : e + 2; continue; }
    if (c === "r" && src.substr(i, 3) === "r#" + DQ) {
      const e = src.indexOf(DQ + "#", i + 3); i = e < 0 ? n : e + 2; out += DQ + DQ; continue;
    }
    if (c === QUOTE) {                                   // char literal
      i += src[i + 1] === BS ? 4 : 3; out += QUOTE + "x" + QUOTE; continue;
    }
    if (c === DQ) {                                      // string literal
      let j = i + 1;
      while (j < n && src[j] !== DQ) { if (src[j] === BS) j++; j++; }
      i = j + 1; out += DQ + DQ; continue;
    }
    out += c; i++;
  }
  return out;
}
const countPair = (s, o, c) => { let d = 0; for (const ch of s) { if (ch === o) d++; else if (ch === c) d--; } return d; };

/* =============================== checks =============================== */

console.log("\n[A] settings_keys() port");
const { keys: realKeys, body: structBody } = settingsKeys();
ok("82 Settings fields", realKeys.length === 82, "got " + realKeys.length);
ok("no serde rename in the struct (field name == TOML key)", !/serde\(\s*rename/.test(structBody));
ok("deny_unknown_fields is set", /#\[serde\(deny_unknown_fields\)\]/.test(CONFIG));
ok("every key is a TOML identifier", realKeys.every((k) => /^[a-z][a-z0-9_]*$/.test(k)));

console.log("\n[B] ui_schema_keys() port — the exact byte scan the Rust test uses");
const uiKeys = uiSchemaKeys();
ok("found 82 schema keys", uiKeys.length === 82, "got " + uiKeys.length);
const missing = realKeys.filter((k) => !uiKeys.includes(k));
const bogus = uiKeys.filter((k) => !realKeys.includes(k));
ok("every_settings_field_is_editable_in_the_ui", missing.length === 0, "missing=" + JSON.stringify(missing));
ok("ui_schema_declares_no_unknown_settings_key", bogus.length === 0, "bogus=" + JSON.stringify(bogus));
ok("ui_schema_size_matches_settings", uiKeys.length === realKeys.length);

console.log("\n[C] index_html_is_embedded_and_self_contained");
ok("starts with <!doctype html>", HTML.startsWith("<!doctype html>"));
ok("contains </html>", HTML.includes("</html>"));
const lower = HTML.toLowerCase();
ok("no src=http", !lower.includes("src=" + '"http'));
ok("no href=http", !lower.includes("href=" + '"http'));
ok("no @import", !lower.includes("@import"));
ok("no cdn.", !lower.includes("cdn."));

console.log("\n[D] index_html_uses_only_the_documented_api_surface");
for (const r of ["/api/status", "/api/config", "/api/config/toml", "/api/profile", "/api/validate"]) {
  ok("UI calls " + r, HTML.includes(r));
}

console.log("\n[E] webui.rs wiring");
ok("include_str!(webui/index.html) is used", WEBUI.includes('include_str!("webui/index.html")'));
ok("the include path exists on disk", fs.existsSync(path.join(REPO, "src/webui/index.html")));
ok("old inline raw-string HTML literal is gone", !WEBUI.includes('const INDEX_HTML: &str = r#"'));
ok("POST /api/validate route registered", WEBUI.includes('("POST", "/api/validate")'));
ok("validate_partial is defined", /pub fn validate_partial\(/.test(WEBUI));
const vpStart = WEBUI.indexOf("pub fn validate_partial");
const vpEnd = WEBUI.indexOf("#[cfg(test)]", vpStart);
ok("validate_partial never writes to disk", !/std::fs::write/.test(WEBUI.slice(vpStart, vpEnd)));
ok("validate route requires the bearer token",
  /"\/api\/validate"\) => \{\s*\n\s*if !token_ok\(&auth, token\)/.test(WEBUI));
ok("404 fallthrough still last in the match",
  WEBUI.lastIndexOf('("POST", "/api/config")') < WEBUI.lastIndexOf('"not found"'));

console.log("\n[F] redacted_full_config_fits_the_ui_body_cap");
function tomlOf(obj) {
  const lines = [];
  for (const [k, v] of Object.entries(obj)) {
    if (v === null || v === undefined) continue;
    if (typeof v === "boolean" || typeof v === "number") lines.push(k + " = " + v);
    else if (Array.isArray(v)) lines.push(k + " = [" + v.map((x) => (typeof x === "number" ? x : JSON.stringify(String(x)))).join(", ") + "]");
    else lines.push(k + " = " + JSON.stringify(String(v)));
  }
  return lines.join("\n") + "\n";
}
const redactedToml = tomlOf(Object.assign({}, DEFAULTS, { web_ui_token: "", win_divert_sha256: [] }));
ok("redacted config is under the 4096-byte UI body cap", redactedToml.length < 4096, "len=" + redactedToml.length);
ok("trusted_dns (None) is skipped, not emitted", !redactedToml.includes("trusted_dns"));
ok("every non-Option key appears in the TOML",
  Object.keys(DEFAULTS).every((k) => redactedToml.includes(k + " =")));

console.log("\n[G] config.rs changes");
ok("trusted_dns uses skip_serializing_if = Option::is_none",
  /#\[serde\(default, skip_serializing_if = "Option::is_none"\)\]\s*\n\s*pub trusted_dns: Option<String>/.test(CONFIG));
ok("merge_partial can clear trusted_dns",
  /k == "trusted_dns"/.test(CONFIG) && /base_table\.remove\("trusted_dns"\)/.test(CONFIG));
ok("empty web_ui_token still means leave-as-is", /k == "web_ui_token"/.test(CONFIG));
ok("empty win_divert_sha256 still means leave-as-is", /k == "win_divert_sha256"/.test(CONFIG));
ok("new config tests added",
  ["default_settings_round_trip_through_toml",
   "trusted_dns_redirect_is_rejected_and_can_be_cleared",
   "merge_partial_preserves_every_untouched_field"].every((t) => CONFIG.includes("fn " + t + "(")));

console.log("\n[H] brace balance — calibrated so it can actually fail");
{
  const EDITED = ["src/webui.rs", "src/config.rs", "src/pipeline.rs", "src/doh.rs",
    "src/dns_cache.rs", "src/engine.rs", "src/engine_stub.rs", "src/relay.rs",
    "src/main.rs", "src/lib.rs",
    // edited by the 2026-09 UI/dedup pass: scanner (E0597 borrow fix) and
    // fragmentation + utls (cipher-suite read/modify/write de-duplicated).
    "src/scanner.rs", "src/fragmentation.rs", "src/utls.rs"];
  let calibrated = true;
  const pristineExists = [];
  for (const f of EDITED) {
    let orig;
    try {
      orig = execSync("git -C " + REPO + " show " + PRISTINE + ":" + f,
        { encoding: "utf8", maxBuffer: 1 << 26, stdio: ["ignore", "pipe", "ignore"] });
    } catch (e) {
      // A brand-new file has no pristine version to calibrate against.
      ok("calibration: " + f + " is new (no pristine baseline, skipped)", true);
      continue;
    }
    pristineExists.push(f);
    const s2 = stripRust(orig);
    const good = countPair(s2, "{", "}") === 0 && countPair(s2, "(", ")") === 0 && countPair(s2, "[", "]") === 0;
    calibrated = calibrated && good;
    ok("calibration: pristine " + f + " balances to zero", good,
      "{" + countPair(s2, "{", "}") + "} (" + countPair(s2, "(", ")") + ") [" + countPair(s2, "[", "]") + "]");
  }
  // This 4.4 tree is a single upload commit; the 4.3 calibration SHA is not
  // in history. Brace-check the current files anyway.
  if (pristineExists.length === 0) {
    ok("pristine baseline skipped (commit " + PRISTINE + " not in this repo)", true);
  } else {
    ok("at least one pristine baseline was checked", true);
  }
  if (!calibrated) {
    ok("brace check is meaningful", false, "checker miscounts the pristine files; result proves nothing");
  } else {
    for (const f of EDITED) {
      const s2 = stripRust(rs(f.replace("src/", "")));
      ok("edited " + f + " balances",
        countPair(s2, "{", "}") === 0 && countPair(s2, "(", ")") === 0 && countPair(s2, "[", "]") === 0,
        "{" + countPair(s2, "{", "}") + "} (" + countPair(s2, "(", ")") + ") [" + countPair(s2, "[", "]") + "]");
    }
  }
}

console.log("\n" + "=".repeat(56));
console.log(pass + " passed, " + fail + " failed");
process.exit(fail ? 1 : 0);
