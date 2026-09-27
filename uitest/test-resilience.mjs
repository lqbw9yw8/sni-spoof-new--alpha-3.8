/*
 * Resilience requirements -> concrete evidence in the source.
 *
 * Maps the five network-resilience requirements (retry/backoff, timeouts,
 * graceful errors, resume, offline cache) onto the exact code that
 * implements them, and asserts each one is actually present.
 *
 * Labelling is deliberate:
 *   [STATIC SOURCE]  the mechanism exists in the Rust source. This proves
 *                    presence, NOT runtime behaviour.
 *   [RUST TEST]      a #[test] covering it exists and will run in CI on a
 *                    machine with a Rust toolchain. It was NOT executed
 *                    here — this sandbox has no cargo and no crates.io.
 *   [RUNS HERE]      genuinely executed by this script.
 *
 *   node uitest/test-resilience.mjs
 */
import fs from "node:fs";
import path from "node:path";

const REPO = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const read = (f) => fs.readFileSync(path.join(REPO, f), "utf8");

let pass = 0;
const failures = [];
const ok = (n, c, extra) => {
  if (c) { pass++; console.log("  ok   " + n); }
  else { failures.push(n + (extra ? " — " + extra : "")); console.log("  FAIL " + n + (extra ? " — " + extra : "")); }
};

const DOH = read("src/doh.rs");
const ENGINE = read("src/engine.rs");
const STUB = read("src/engine_stub.rs");
const RELAY = read("src/relay.rs");
const CACHE = read("src/dns_cache.rs");
const MAIN = read("src/main.rs");
const PIPELINE = read("src/pipeline.rs");
const FAILOPEN = read("src/fail_open.rs");
const LIB = read("src/lib.rs");

const num = (src, re) => { const m = src.match(re); return m ? Number(m[1]) : null; };

console.log("\n[REQ 1] Retry + exponential backoff");
{
  // capture loop
  ok("[STATIC SOURCE] capture recv errors back off instead of spinning",
    /std::thread::sleep\(recv_backoff\(consecutive_errors\)\)/.test(ENGINE));
  ok("[STATIC SOURCE] the consecutive-error counter resets on success",
    /Ok\(pkt\) => \{\s*\n\s*consecutive_errors = 0;/.test(ENGINE));
  ok("[STATIC SOURCE] the old unthrottled warn-and-continue is gone",
    !/log::warn!\("WinDivert recv error, continuing: \{e\}"\);\s*\n\s*continue;/.test(ENGINE));
  ok("[STATIC SOURCE] recv log is rate-limited (1st, then every 100th)",
    /consecutive_errors == 1 \|\| consecutive_errors % 100 == 0/.test(ENGINE));
  const cap = num(ENGINE, /recv_backoff[\s\S]{0,200}?ms\.min\((\d+)\)/);
  ok("[STATIC SOURCE] recv backoff is capped", cap !== null && cap <= 500, "cap=" + cap);

  // DoH
  ok("[STATIC SOURCE] DoH retries up to DOH_MAX_ATTEMPTS",
    /pub const DOH_MAX_ATTEMPTS: u32 = (\d)/.test(DOH));
  ok("[STATIC SOURCE] DoH sleeps between attempts using retry_backoff",
    /std::thread::sleep\(delay\)/.test(DOH) && /let delay = retry_backoff\(attempt - 1\)/.test(DOH));
  const base = num(DOH, /retry_backoff[\s\S]{0,200}?(\d+)u64\.saturating_mul/);
  ok("[STATIC SOURCE] DoH backoff starts small", base !== null && base <= 500, "base=" + base + "ms");
  ok("[STATIC SOURCE] DoH backoff is capped at 2 s",
    /retry_backoff[\s\S]{0,220}?ms\.min\(2000\)/.test(DOH));
  ok("[STATIC SOURCE] DoH attempts are clamped (cannot be 0 or huge)",
    /attempts\.clamp\(1, DOH_MAX_ATTEMPTS\)/.test(DOH));
  ok("[STATIC SOURCE] relay connect is deliberately NOT retried in-process",
    /Failing fast so the client can retry/.test(RELAY),
    "per-connection retry belongs to the client (v2rayN), not the relay");

  ok("[RUST TEST] recv_backoff schedule is unit tested",
    /fn recv_backoff_grows_then_caps\(/.test(STUB));
  ok("[RUST TEST] DoH retry schedule is unit tested",
    /fn retry_backoff_grows_and_is_capped\(/.test(DOH));
  ok("[RUST TEST] the whole DoH retry budget is asserted bounded",
    /fn total_retry_budget_is_bounded\(/.test(DOH));
}

console.log("\n[REQ 2] Explicit, bounded timeouts on every network wait");
{
  const dohTimeout = num(DOH, /DOH_TIMEOUT: Duration = Duration::from_secs\((\d+)\)/);
  const connectTimeout = num(RELAY, /CONNECT_TIMEOUT: Duration = Duration::from_secs\((\d+)\)/);
  const fakeWait = num(RELAY, /FAKE_ACK_WAIT: Duration = Duration::from_secs\((\d+)\)/);
  const holdTimeout = num(PIPELINE, /HOLD_TIMEOUT: Duration = Duration::from_millis\((\d+)\)/);
  const captureReady = num(MAIN, /wait_until_capture_ready\(std::time::Duration::from_secs\((\d+)\)\)/);

  ok("[STATIC SOURCE] DoH request timeout is set", dohTimeout !== null, "got " + dohTimeout);
  ok("[STATIC SOURCE] relay outbound connect has a timeout", connectTimeout !== null, "got " + connectTimeout);
  ok("[STATIC SOURCE] the connect actually goes through tokio::time::timeout",
    /tokio::time::timeout\(\s*\n?\s*CONNECT_TIMEOUT,\s*\n?\s*socket\.connect/.test(RELAY));
  ok("[STATIC SOURCE] fake-injection wait is bounded", fakeWait !== null, "got " + fakeWait);
  ok("[STATIC SOURCE] held packets have a watchdog timeout", holdTimeout !== null, "got " + holdTimeout);
  ok("[STATIC SOURCE] startup waits for capture with a bounded timeout", captureReady !== null, "got " + captureReady);

  // The numbers must compose sanely, not just exist.
  ok("[STATIC SOURCE] client-facing wait (connect + inject) stays under 15 s",
    (connectTimeout || 99) + (fakeWait || 99) <= 15,
    `${connectTimeout} + ${fakeWait}`);
  ok("[STATIC SOURCE] DoH per-attempt timeout is shorter than the old 10 s",
    dohTimeout !== null && dohTimeout < 10, "got " + dohTimeout);
  const attempts = num(DOH, /DOH_MAX_ATTEMPTS: u32 = (\d+)/);
  const total = (dohTimeout || 0) * (attempts || 0) + 0.25 + 0.5;
  ok("[STATIC SOURCE] worst-case DoH budget stays under 21 s", total <= 21, total + "s");
  ok("[RUST TEST] the client-facing wait bound is asserted",
    /fn client_facing_wait_is_bounded\(/.test(RELAY));
}

console.log("\n[REQ 3] Graceful error handling — never crash, wait to reconnect");
{
  ok("[STATIC SOURCE] the packet path is wrapped in catch_unwind (fail-open)",
    /catch_unwind\(AssertUnwindSafe/.test(FAILOPEN));
  ok("[STATIC SOURCE] panic re-injects the ORIGINAL packet",
    /Err\(panic_payload\)[\s\S]*?WireAction::Send\(vec!\[original\.to_vec\(\)\]\)/.test(FAILOPEN));
  ok("[STATIC SOURCE] Err also re-injects the original packet",
    /mutation returned error, passing original packet through/.test(FAILOPEN));
  ok("[STATIC SOURCE] capture loop keeps running after a recv error",
    /continue;/.test(ENGINE) && /recv_backoff/.test(ENGINE));
  ok("[STATIC SOURCE] overflow checks stay on in release (panic is caught, not UB)",
    /overflow-checks = true/.test(read("Cargo.toml")));
  ok("[STATIC SOURCE] panic=unwind so catch_unwind works in release",
    /panic = "unwind"/.test(read("Cargo.toml")));
  ok("[STATIC SOURCE] mutex poisoning does not take the packet path down",
    /pub fn recover_mutex/.test(LIB));

  // The key availability property: a relay that failed to start retries.
  ok("[STATIC SOURCE] a configured-but-dead relay is retried periodically",
    /wants_but_not_running\(&current\)/.test(MAIN));
  ok("[STATIC SOURCE] the retry only fires when the relay is actually down",
    /settings\.relay_enabled && self\.id\.is_none\(\)/.test(MAIN));
  ok("[STATIC SOURCE] the retry interval is bounded (30 s)",
    /RELAY_RETRY_INTERVAL: std::time::Duration =\s*\n?\s*std::time::Duration::from_secs\(30\)/.test(MAIN));
  ok("[STATIC SOURCE] a failed DoH at reconcile keeps the previous relay alive",
    /relay destination resolution failed/.test(MAIN));
  ok("[STATIC SOURCE] the blocking-trade-off of the retry is documented, not hidden",
    /previously a retry could stall held-packet flushing/.test(MAIN));
}

console.log("\n[REQ 4] State persistence / resume after a disconnect");
{
  ok("[STATIC SOURCE] the DNS cache is mirrored to disk",
    /pub fn save\(&self, path: &Path, now: Instant\) -> bool/.test(CACHE));
  ok("[STATIC SOURCE] the cache is loaded from disk on first use",
    /DnsCache::load\(\s*&crate::dns_cache::cache_path\(\)/.test(DOH));
  ok("[STATIC SOURCE] successful resolutions are persisted",
    /fn persist_cache\(\)/.test(DOH) && /persist_cache\(\);/.test(DOH));
  ok("[STATIC SOURCE] the cache file lives next to the exe, never cwd",
    /std::env::current_exe\(\)/.test(CACHE));
  ok("[STATIC SOURCE] cache I/O is best-effort (never fatal)",
    /best-effort|Best-effort/g.test(CACHE) && /Err\(e\) => \{[\s\S]{0,200}?Self::new\(\)/.test(CACHE));
  ok("[STATIC SOURCE] the cache file is capped at 64 KiB",
    /MAX_CACHE_BYTES: u64 = 64 \* 1024/.test(CACHE));
  ok("[STATIC SOURCE] malformed cache lines are skipped, not fatal",
    /Malformed lines are skipped, never fatal/.test(CACHE));
  ok("[STATIC SOURCE] the cache file is gitignored (it can contain server IPs)",
    /dpi_guard\.dns_cache/.test(read(".gitignore")));
  ok("[RUST TEST] disk round-trip is unit tested",
    /fn save_and_load_round_trip_on_disk\(/.test(CACHE));
  ok("[RUST TEST] a missing or oversize cache file degrades to empty",
    /fn load_of_missing_or_oversize_file_yields_empty_cache\(/.test(CACHE));
}

console.log("\n[REQ 5] Offline mode / cache so an outage is not total failure");
{
  ok("[STATIC SOURCE] a fresh answer is cached",
    /global_cache\(\)\.insert_with_ttl\(\s*host,\s*ips\.clone\(\)/.test(DOH));
  ok("[STATIC SOURCE] a cached answer is served when every attempt fails",
    /falling back to a \{\} \\?\n?\s*cached answer/.test(DOH) ||
    /falling back to a/.test(DOH));
  ok("[STATIC SOURCE] stale hits are distinguished from fresh ones in the log",
    /if fresh \{ "fresh" \} else \{ "STALE" \}/.test(DOH));
  ok("[STATIC SOURCE] stale serving is bounded by MAX_STALE",
    /MAX_STALE: Duration = Duration::from_secs\(6 \* 60 \* 60\)/.test(CACHE));
  ok("[STATIC SOURCE] an IP-literal destination needs no network at all",
    /if let Ok\(ip\) = host\.parse::<IpAddr>\(\)/.test(DOH));
  ok("[STATIC SOURCE] cached addresses are re-validated before use",
    /crate::netguard::validate_relay_ip\(\*ip\)\.is_ok\(\)/.test(CACHE));
  ok("[STATIC SOURCE] the cache is bounded in memory (MAX_ENTRIES)",
    /MAX_ENTRIES: usize = 256/.test(CACHE));
  ok("[RUST TEST] stale-then-drop behaviour is unit tested",
    /fn expired_entry_is_served_as_stale_then_dropped\(/.test(CACHE));
  ok("[RUST TEST] forbidden cached addresses are never returned",
    /fn forbidden_addresses_are_never_returned\(/.test(CACHE));
  ok("[RUST TEST] an IP literal resolves with the network down",
    /fn ip_literal_skips_the_network_and_the_cache\(/.test(DOH));
}

console.log("\n[CROSS] the module is actually wired into the crate");
{
  ok("[STATIC SOURCE] dns_cache is declared in lib.rs", /pub mod dns_cache;/.test(LIB));
  ok("[STATIC SOURCE] dns_cache.rs exists on disk", fs.existsSync(path.join(REPO, "src/dns_cache.rs")));
  ok("[STATIC SOURCE] tokio 'time' feature is enabled (tokio::time::timeout needs it)",
    /tokio = \{ version = "1", features = \[[^\]]*"time"/.test(read("Cargo.toml")));
  const mods = (LIB.match(/pub mod ([a-z_]+);/g) || []).map((m) => m.replace(/pub mod |;/g, ""));
  ok("[RUNS HERE] every declared module has a file",
    mods.every((m) => fs.existsSync(path.join(REPO, "src", m + ".rs"))),
    JSON.stringify(mods.filter((m) => !fs.existsSync(path.join(REPO, "src", m + ".rs")))));
}

console.log("\n" + "=".repeat(60));
console.log(pass + " passed, " + failures.length + " failed");
if (failures.length) {
  console.log("\nFailures:");
  for (const f of failures) console.log("  - " + f);
  process.exit(1);
}
console.log("ALL RESILIENCE REQUIREMENTS ARE IMPLEMENTED (per static evidence)");
console.log(`
Reminder: [STATIC SOURCE] proves the mechanism is present in the source.
It does NOT prove runtime behaviour — that needs \`cargo test\` on a machine
with a Rust toolchain, which this sandbox does not have.
`);
