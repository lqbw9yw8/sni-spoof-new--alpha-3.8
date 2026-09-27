/*
 * Live-overview + UX-safety tests for the 2026 GUI upgrade:
 *   - overview cards render the new /api/status fields
 *     (mutated packets, uptime, DoH state, driver handle count)
 *   - profile switch asks for confirmation before the immediate apply,
 *     and a cancelled confirmation sends nothing
 *   - beforeunload only fires when there are unsaved changes
 *   - accessibility: aria-label / aria-describedby / aria-invalid wiring,
 *     live-region message element
 *
 * Drives the REAL src/webui/index.html in jsdom against the mock API:
 *   node uitest/test-status.mjs
 */
import { JSDOM, VirtualConsole } from "jsdom";
import fs from "node:fs";
import path from "node:path";
import { createServer, resetForTests } from "./mock-server.mjs";

const REPO = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const HTML_PATH = path.join(REPO, "src/webui/index.html");
const TOKEN = "dev-token-dev-token";

let pass = 0;
const failures = [];
function ok(name, cond, extra) {
  if (cond) { pass++; console.log("  ok   " + name); }
  else { failures.push(name + (extra ? " — " + extra : "")); console.log("  FAIL " + name + (extra ? " — " + extra : "")); }
}

const server = createServer();
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const PORT = server.address().port;
const BASE = `http://127.0.0.1:${PORT}`;

const captured = [];
let confirmAnswer = true;
let lastConfirmText = "";

async function makeDom() {
  resetForTests();
  captured.length = 0;
  confirmAnswer = true;
  lastConfirmText = "";
  const vc = new VirtualConsole();
  vc.on("jsdomError", (e) => { throw e; });
  const dom = new JSDOM(fs.readFileSync(HTML_PATH, "utf8"), {
    url: BASE + "/",
    runScripts: "dangerously",
    pretendToBeVisual: true,
    virtualConsole: vc,
    beforeParse(window) {
      window.confirm = (text) => { lastConfirmText = String(text); return confirmAnswer; };
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
/* Fixed sleeps are the classic jsdom flake: a bare settle(250) is usually
 * enough for the page to fetch /api/config + /api/status and paint, but under
 * a loaded machine (the full `npm test` runs five other suites in parallel
 * with this one) it is not, and cards/chips were seen empty at 250 ms. Poll
 * for the condition instead, and only report failure once the deadline hits. */
async function waitFor(fn, timeout = 5000, step = 25) {
  const deadline = Date.now() + timeout;
  for (;;) {
    let v = false;
    try { v = fn(); } catch { v = false; }
    if (v) return true;
    if (Date.now() >= deadline) return false;
    await settle(step);
  }
}
const click = (doc, id) => doc.getElementById(id).dispatchEvent(
  new doc.defaultView.Event("click", { bubbles: true }));

console.log("\n[O1] overview cards render the new status fields");
{
  const dom = await makeDom();
  const doc = dom.window.document;
  ok("overview cards render", await waitFor(
    () => doc.getElementById("cards").textContent.includes("پکت جهش‌یافته")));
  const cards = doc.getElementById("cards").textContent;
  ok("uptime card present", cards.includes("مدت کارکرد"));
  ok("uptime formatted (3725s = 1 ساعت)", cards.includes("۱".length && "1 ساعت") || cards.includes("1 ساعت"),
    "cards text: " + cards.slice(0, 200));
  ok("DoH state card present", cards.includes("DoH رله"));
  ok("DoH state value rendered (off by default)",
    doc.getElementById("cardv_doh").textContent === "off",
    JSON.stringify(doc.getElementById("cardv_doh").textContent));
  ok("driver handle card present", cards.includes("هندل درایور"));
  ok("driver handle live+retired rendered", cards.includes("1 فعال + 2 بازنشسته"),
    "expected '1 فعال + 2 بازنشسته'");
  ok("intercepted-packets card still present", cards.includes("پکت رهگیری‌شده"));
  dom.window.close();
}

console.log("\n[O2] profile switch asks for confirmation before applying");
{
  const dom = await makeDom();
  const doc = dom.window.document;
  await settle(250);

  // Accepted confirmation -> POST /api/profile fires.
  click(doc, "profiles");
  const btn = doc.querySelector('button[data-p="Henan"]');
  ok("profile button exists", !!btn);
  btn.dispatchEvent(new doc.defaultView.Event("click", { bubbles: true }));
  await settle(250);
  ok("confirmation dialog shown", lastConfirmText.includes("Henan"),
    "confirm text: " + JSON.stringify(lastConfirmText));
  const post = captured.find((c) => c.path === "/api/profile");
  ok("POST /api/profile sent after confirm", !!post);
  ok("POST body carries the profile", post && post.body.includes("Henan"));

  // Cancelled confirmation -> nothing sent.
  captured.length = 0;
  confirmAnswer = false;
  const btn2 = doc.querySelector('button[data-p="Aggressive"]');
  btn2.dispatchEvent(new doc.defaultView.Event("click", { bubbles: true }));
  await settle(200);
  ok("cancel still shows the dialog", lastConfirmText.includes("Aggressive"));
  ok("cancelled confirm sends nothing", captured.length === 0,
    "captured: " + JSON.stringify(captured));
  dom.window.close();
}

console.log("\n[O3] beforeunload only warns with unsaved changes");
{
  const dom = await makeDom();
  const win = dom.window, doc = win.document;
  await settle(250);

  let warned = false;
  const handler = (e) => { if (e.defaultPrevented || e.returnValue === "") warned = true; };
  win.addEventListener("beforeunload", handler);
  const ev = new win.Event("beforeunload", { bubbles: true, cancelable: true });
  win.dispatchEvent(ev);
  ok("clean form does not warn", !warned);

  // dirty the form
  const el = doc.getElementById("f_decoy_ttl");
  el.value = "12";
  el.dispatchEvent(new win.Event("input", { bubbles: true }));
  await settle(50);
  warned = false;
  const ev2 = new win.Event("beforeunload", { bubbles: true, cancelable: true });
  win.dispatchEvent(ev2);
  ok("dirty form warns on unload", warned);
  win.removeEventListener("beforeunload", handler);
  dom.window.close();
}

console.log("\n[O4] accessibility wiring on form controls");
{
  const dom = await makeDom();
  const doc = dom.window.document;
  await settle(250);

  const inp = doc.getElementById("f_decoy_ttl");
  ok("aria-label on input", !!(inp && inp.getAttribute("aria-label")));
  ok("aria-describedby points at the error node",
    inp && inp.getAttribute("aria-describedby") === "e_decoy_ttl");
  ok("aria-invalid=false while valid",
    inp && inp.getAttribute("aria-invalid") === "false");

  // Make the field invalid -> aria-invalid flips to true.
  inp.value = "0";
  inp.dispatchEvent(new doc.defaultView.Event("input", { bubbles: true }));
  await settle(50);
  ok("aria-invalid=true on validation error",
    inp.getAttribute("aria-invalid") === "true");

  // Checkbox + select also labelled.
  const cb = doc.getElementById("f_enable_decoys");
  ok("checkbox has aria-label", !!(cb && cb.getAttribute("aria-label")));
  const sel = doc.getElementById("f_mutation_profile");
  ok("select has aria-label", !!(sel && sel.getAttribute("aria-label")));

  // Live regions for status messages.
  ok("#msg is a polite live region",
    doc.getElementById("msg").getAttribute("aria-live") === "polite");
  ok("#dirtypill is a polite live region",
    doc.getElementById("dirtypill").getAttribute("aria-live") === "polite");
  dom.window.close();
}

console.log("\n[O5] responsive layout hooks exist in the stylesheet");
{
  const html = fs.readFileSync(HTML_PATH, "utf8");
  ok("360px-class breakpoint present", html.includes("max-width: 430px"));
  ok("focus-visible ring present", html.includes(":focus-visible"));
}

console.log("\n[O6] the mock API mirrors the real /api/status contract");
{
  /* The UI tests are only worth as much as the mock they run against: if
   * `statusJson()` drifts from `status_json()` in src/webui.rs, every card
   * and chip bound to a renamed field reads `undefined` and the suite still
   * goes green. This check parses the real Rust format string and compares
   * it key-for-key with what the mock actually serves. */
  const WEBUI_RS = fs.readFileSync(path.join(REPO, "src", "webui.rs"), "utf8");
  const at = WEBUI_RS.indexOf("fn status_json(s: &DashboardSnapshot)");
  if (at < 0) throw new Error("status_json() not found in src/webui.rs");
  const body = WEBUI_RS.slice(at, WEBUI_RS.indexOf("\n}\n", at));
  const realKeys = [...new Set([...body.matchAll(/"([a-z_0-9]+)":/g)].map((m) => m[1]))]
    .filter((k) => k !== "key" && k !== "score")   // nested score-object keys
    .sort();

  const res = await fetch(BASE + "/api/status", {
    headers: { Authorization: "Bearer " + TOKEN },
  });
  const served = await res.json();

  const missing = realKeys.filter((k) => !(k in served));
  const stale = Object.keys(served).filter((k) => !realKeys.includes(k));
  ok("mock serves every field status_json() sends", missing.length === 0,
    "missing=" + JSON.stringify(missing));
  ok("mock sends no field status_json() dropped", stale.length === 0,
    "stale=" + JSON.stringify(stale));
  ok("status_json contract is non-trivial", realKeys.length > 40, "n=" + realKeys.length);

  // The technique chips must read real booleans, never `undefined`.
  const chipFields = ["enable_decoys", "enable_sni_fragmentation", "enable_reverse_frag",
    "enable_wrong_seq", "enable_wrong_checksum", "enable_oob_injection", "enable_hostdot",
    "enable_quic_port_bypass", "enable_utls_fingerprint", "enable_sni_scanner",
    "enable_anti_fingerprint", "randomize_ip_id", "enable_self_update"];
  ok("every technique chip has a real boolean in the payload",
    chipFields.every((k) => typeof served[k] === "boolean"),
    JSON.stringify(chipFields.filter((k) => typeof served[k] !== "boolean")));

  // ...and the chips actually light up in the DOM now.
  const dom = await makeDom();
  const d = dom.window.document;
  ok("technique chips render", await waitFor(() => d.querySelectorAll("#tech .chip").length > 0));
  const on = [...d.querySelectorAll("#tech .chip.on")];
  ok("flag values from the payload light up in the DOM", on.length > 0, "on=" + on.length);
  dom.window.close();
}

console.log(`\n${pass} passed, ${failures.length} failed`);
if (failures.length) {
  console.log("FAILURES:\n  " + failures.join("\n  "));
  process.exit(1);
}
console.log("ALL STATUS-UI TESTS PASSED");
process.exit(0);
