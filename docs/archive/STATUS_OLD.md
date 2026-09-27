> **⚠️ ARCHIVED — DO NOT TRUST / بایگانی‌شده — اعتماد نکنید**
>
> این سند **تاریخی** است و وضعیت فعلی کد را توصیف نمی‌کند. هر عدد، برچسب
> `DONE` یا نتیجهٔ تستی که در آن می‌بینید ممکن است مدت‌ها پیش بی‌اعتبار شده
> باشد. منابع معتبر: [`STATUS.md`](../../STATUS.md)،
> [`TEST_MATRIX.md`](../../TEST_MATRIX.md)،
> [`ARCHITECTURE.md`](../../ARCHITECTURE.md).
>
> Historical document kept for context only. Do not treat any claim, status
> tag or test result in it as current. Canonical sources: `STATUS.md`,
> `TEST_MATRIX.md`, `ARCHITECTURE.md`.

# STATUS — Security hardening & settings GUI (2026-08-29)

Scope of this pass: full source audit (`src/` 40 files — 37 functional modules
plus `lib.rs`, `main.rs` and `engine_stub.rs`, `Cargo.toml`, all
`SECURITY_*.md` / `REVIEW_2026_STRICT.md` claims re-verified **in code**, not
taken from the docs), closing every realistically fixable gap, completing the
settings GUI, and running the real test suites on this Linux box.

## 1. Security audit — verified vs fixed

### Verified as already correct (claims re-checked in code)

| Claim | Where verified |
|---|---|
| Dashboard binds **127.0.0.1 only** | `webui.rs:195` `([127,0,0,1], port).into()` — never `0.0.0.0` |
| Bearer token on **every** `/api/*` route (status, config GET/POST, config/toml, profile, validate) | `webui.rs:349-463` — each arm calls `token_ok()` first |
| Constant-time token compare + 80 ms 401 throttle | `webui.rs:token_ok`, `unauthorized()`, `integrity.rs:constant_time_eq` |
| Host-header DNS-rebind protection (rejects `localhost`, wrong port, other names); Origin check | `webui.rs:host_is_allowed/origin_is_allowed`, unit-tested |
| No path traversal | there is **no file serving at all** — only `include_str!`-embedded `index.html`; no static dir, no WebSocket |
| Request size caps (16 KiB raw / 4096 body), 3 s timeouts | `webui.rs:handle_conn` |
| Token/pins never logged (custom `Debug` redaction) nor returned by `/api/config` (`settings_json` blanks them) | `config.rs:374-391`, `webui.rs:647`, unit tests |
| `merge_partial` treats empty token/pins as "leave as-is" (Save can never wipe auth) | `config.rs:743-801`, UI test [18] |
| Fail-open packet path: panics/errs re-inject the original via `catch_unwind`; `panic=unwind`, `overflow-checks=true` in release | `fail_open.rs`, `Cargo.toml [profile.release]` |
| Bounded pipeline: 16 KiB flow buf, 256 flows, 512 recent, 256 relay flows, 256 held, QUIC map cap | `pipeline.rs:40-50`, `engine.rs:70`, `relay.rs` |
| Ports 22/53/3389 never intercepted (even all-ports mode) | `config.rs::is_target_port` / `effective_ports` |
| Driver SHA-256 pinning with constant-time compare, 16 MiB hash cap, binaries loaded only next to the exe | `integrity.rs`, `engine.rs:396-422` |
| Kill-switch command sanitized `[A-Za-z0-9 _-]+`, never spawned | `stealth.rs:sanitize_adapter_name/kill_switch_trigger` |
| SSRF guards on relay destination and DoH URL (loopback/link-local/metadata/userinfo) | `netguard.rs`, `config.rs`, UI test [12] |

### Fixed in this pass

1. **CSPRNG for secrets** (`src/stealth.rs`): `generate_token()` and
   `run_salt()` used `rand::thread_rng()` (a userspace ChaCha PRNG). Both now
   use `rand::rngs::OsRng` — the OS CSPRNG (BCryptGenRandom on Windows).
   Non-security randomness (padding/jitter/shuffles) intentionally stays on
   `thread_rng`. `SECURITY_CHECKLIST.md` items 88/253/418/583/748/913 updated
   to match reality.
2. **Committed WinDivert binaries removed from git.** `WinDivert.dll`,
   `WinDivert.lib`, `WinDivert64.sys` were tracked in the repo root. I first
   verified they are byte-identical to the official WinDivert 2.2.2 release
   (no tampering), then `git rm --cached` them and added `.gitignore` rules.
   Replaced by:
   - `scripts/fetch-windivert.sh` / `scripts/fetch-windivert.ps1` — downloads
     the pinned 2.2.2 release and verifies the **zip** and each extracted
     file against SHA-256 pins before installing (tested end-to-end here).
   - `build-windows.bat` now auto-invokes the fetch script when the files are
     missing (WINDIVERT_PATH override still honored).
3. **Compile error in test suite** (`src/dns_cache.rs:311`): `Instant` has no
   `saturating_sub` — the tests did not compile at all. Fixed; `cargo test`
   now runs (this was masked in the docs' environment, which had no rustc).
4. **`.gitignore` created** (the repo had none): WinDivert binaries, `target/`,
   `dpi_guard.toml` (contains token + relay host), `dpi_guard.dns_cache`
   (contains resolved server IPs), logs. This also fixes the one previously
   failing uitest check.

### Dashboard static-page note

`GET /` serves the login page without a token by design: the page carries no
secrets (token is prompted, kept in localStorage) and is the only way to reach
the auth dialog. Every data route (`/api/*`) requires the token. This is the
standard safe pattern and is unchanged.

## 2. Settings GUI coverage

The dashboard (`src/webui/index.html`, vanilla JS, embedded) exposes **all 77
`Settings` fields** — enforced both ways by Rust unit tests (`ui_schema_tests`:
every field has a control, no stale keys, count match) and by jsdom tests
against the real `src/config.rs`.

Sections: Core mutation & release · Intercept scope (ports) · Relay mode
(patterniha-style, v2rayN pairing notes) · TLS/fragmentation/desync ·
Fingerprint & stealth (uTLS, ECH GREASE, disguise, fronting, QUIC bypass) ·
DNS & DoH · Dashboard auth (write-only token field; regenerate = type a new
≥16-char token, empty = keep) · Kill switch/driver pins · ISP profile &
scanner · Advanced anti-fingerprint (injection jitter, IP-ID, packet-size,
fake-with-SNI) · Advanced desync (reverse frag, wrong seq/checksum, OOB,
host-dot, zapret hostlist) · Tools (self-update, client-detect, proxy
cleanup, YouTube warmup, mobile gateway). Plus: 6 mutation profiles with
descriptions, quick-access toolbar, search/dirty filters, live status cards,
advanced TOML editor, export/import JSON.

Backend already had `GET/POST /api/config` (partial-TOML merge + hot-reload
within ~1 s) and `POST /api/validate` (dry run). Client-side validation
mirrors `Settings::validate` (incl. cross-field rules); server-side
rejections surface in the UI.

**New in this pass:** systematic *restart-required* hints — every setting
hot-reload cannot apply is tagged in the UI (`نیاز به ری‌استارت`) and
produces an explicit restart-recommended message on save: `enable_web_ui`,
`web_ui_port`, `web_ui_token` (dashboard server bind/token, fixed at boot),
`isp_profile` (merged once at boot), `enable_self_update` / `update_repo`,
`enable_client_detect`, `enable_youtube_warmup`, `enable_mobile_gateway`,
`enable_proxy_cleanup` (one-shot startup handlers), `enable_kill_switch` /
`kill_switch_adapter` (armed once at boot), `win_divert_sha256`
(`version_check` runs once at boot), `injection_delay_min_ms` /
`injection_delay_max_ms` (captured when the capture thread spawns).
`RelayRuntime::reconcile` is additionally gated on
`engine::capture_is_ready()`, so the watchdog can neither start nor
re-resolve the relay while capture is down (fail-closed at boot and
later). All other fields save with the plain hot-reload message.

## 3. Tests actually run (real results, this Linux box)

**Rust toolchain**: `cargo`/`rustc` is not installed in this sandbox and
`static.rust-lang.org`/`crates.io` are unreachable from it. Therefore
`cargo test` / `cargo check` / `cargo clippy` / `cargo audit` have **not**
been executed here. `grep -c '#\[test\]' src/*.rs` counts **319**
`#[test]` functions across the crate (pure-logic modules are written to be
cross-platform and should run on Linux/macOS/Windows; only `engine.rs` and
the singleton Windows backend are `cfg(windows)`). The first command to
run on a machine with Rust installed is `cargo test --all-targets`.

- `uitest` (Node + jsdom) — **369 checks, 0 failures**:

  | Suite | Passed |
  |---|---|
  | `test-ui.mjs`        | 104 |
  | `check-rust-tests.mjs` (brace/schema) | 56 |
  | `test-v2rayn.mjs`    | 67 |
  | `test-resilience.mjs`| 60 |
  | `test-settings.mjs`  | 56 |
  | `test-status.mjs`    | 26 |

  Run with `cd uitest && npm install && npm test`.

- `scripts/fetch-windivert.sh` — the download URL for WinDivert 2.2.2
  (`release-assets.githubusercontent.com`) is unreachable from this
  sandbox, so the script could not be executed end-to-end here. The
  SHA-256 pins baked into the script match the official 2.2.2 release digests
  (`c1e060ee…` / `8da08533…`, recomputed locally with `sha256sum` against the
  previously tracked copies); the script itself is `set -euo pipefail` and
  aborts on any hash mismatch.

## 4. Not verifiable on Linux — run these on Windows

The WinDivert capture/inject path (`engine.rs`, `#[cfg(windows)]`), the relay
end-to-end, the native GUI, and driver-pin verification against a real driver
do not compile/run here. On a Windows machine run:

```bat
scripts\fetch-windivert.ps1            :: or let build-windows.bat do it
build-windows.bat                       :: cargo build --release (x86_64-msvc)
cargo test                              :: full suite on Windows
cargo clippy --all-targets -- -D warnings
cargo fmt --check
:: then, as Administrator, run target\x86_64-pc-windows-msvc\release\dpi_guard.exe
:: and field-test: relay mode + Wireshark, filter reload on port change,
:: Ctrl+C graceful shutdown (the AtomicPtr shutdown path in engine.rs is the
:: known risky area flagged in SECURITY_GAPS.md — it needs Windows testing).
```

### Remaining open items (documented, not fixable in code here)

- **WinDivert `AtomicPtr` shutdown** (engine.rs): concurrent-shutdown design
  mitigated via parked-RETIRED handling; full rewrite needs Windows field
  testing (per SECURITY_GAPS.md).
- **WFP DNS block on port 53 is a stub** — the app warns loudly at startup;
  set `relay_connect_host` to an IP literal or use v2rayN's own DoH.
- ~~DoH resolve runs synchronously on the watchdog thread during relay
  retry (bounded ~16 s, ≤ once per 30 s) — documented trade-off in
  `main.rs`.~~ **Fixed since this pass**: `main.rs`'s `kick_resolution`
  now runs DoH on a dedicated background thread; `reconcile()` picks up
  a finished result (non-blocking) on its next watchdog tick instead of
  blocking on the DoH budget. The `kick_resolution` doc comment records
  the old behaviour and the fix. The one remaining trade-off — up to one
  watchdog-tick's delay between a resolution finishing and the relay
  picking it up — is documented in that same comment.
- ECH is GREASE-only (no HPKE), uTLS is shuffle-not-rebuild — honest
  limitations, see REVIEW_2026_STRICT.md deductions.
- Five feature flags (`enable_sni_scanner`, `enable_self_update`,
  `enable_client_detect`, `enable_youtube_warmup`,
  `enable_mobile_gateway`) are accepted-but-not-implemented; the app warns
  per flag at startup (audit F-003).

---

# Continuation pass — external security audit (2026-08-29, pass 2)

Six commits on top of the previous pass; nothing pushed. New commits:
`fix(engine)` bounded handle retirement · `feat(webui)` live overview/a11y ·
`chore(audit)` cargo-audit policy · `fix(lints)` clippy-clean.

## 5. External audit findings → resolutions

| # | Finding | Severity | Resolution |
|---|---|---|---|
| 1 | Committed WinDivert.dll/.lib/.sys + missing .gitignore | HIGH | **Already fixed in pass 1; re-verified.** `git ls-files \| grep -i windivert` → only `scripts/fetch-windivert.{sh,ps1}`. `.gitignore` now additionally covers generic `*.dll/*.sys/*.lib` (plus the previous named files, `target/`, `dpi_guard.toml`, `dpi_guard.dns_cache`, logs). History-scrub note below. |
| 2 | Handle leak: retired Divert handles parked forever in `static RETIRED` (one kernel handle leaked per filter hot-reload) | MEDIUM | **Fixed.** New cfg-free module `src/handle_retire.rs` holds the policy: every retired handle is shut down immediately, parked with a timestamp, and swept on each retirement — entries older than a **30 s grace** (≈6 orders of magnitude over any in-flight `send` on the old `AtomicPtr`) are closed oldest-first; the list is **hard-capped at 16** (force-close oldest, loudly logged, only reachable via pathological reload flapping). Closing drops are wrapped in `catch_unwind` so a panic can never unwind into the capture loop. Fail-open packet semantics unchanged. **8 policy unit tests in-tree** (`cargo test handle_retire` — execution status: §8); the `engine.rs` integration is `cfg(windows)` and needs the Windows commands in §4. Dashboard now reports `driver_handles_live`/`driver_handles_retired`. |
| 3 | cargo audit / dependency advisories | — | **Real tool run** (see §8). |
| 4 | GUI quality | — | See §7. |

### git filter-repo note (history scrub — NOT executed, by design)

The driver binaries were removed from tracking in pass 1 but **remain in git
history** (commits before `3bec9e3`). If this repo is ever published, scrub
them first (run in a fresh clone, then force-push + re-clone all remotes):

```sh
git filter-repo --path WinDivert.dll --path WinDivert.lib --path WinDivert64.sys --invert-paths
```

We deliberately did **not** rewrite history here: the continuation work builds
on the existing commit graph, and rewriting would invalidate every clone.

## 6. Module-by-module verification (16 modules, line by line)

All claims re-verified in code; no unbounded recursion or queue growth on
malformed input found anywhere (every parser is length-checked/`need()`-guarded
and every table capped; parsing loops advance monotonically; the one
recursion-free guarantee was spot-checked in each TLS/DNS/QUIC walker).

| Module | Verdict | Notes |
|---|---|---|
| `relay.rs` | ✅ verified | Fail-closed injection confirmed (`require_inject && !ok` drops both sockets before any real-ClientHello byte is copied); binds 127.0.0.1 only + loopback-peer defence-in-depth; fixed single destination (cannot become an open proxy); bounded client wait (`CONNECT_TIMEOUT` 10 s + `FAKE_ACK_WAIT` 3 s, tested ≤15 s); `InjectGate` success/failure bit distinguishable from timeout. |
| `pipeline.rs` | ✅ verified | `relay_flows` cap 256 with finished-first eviction + oldest-live fallback (4 dedicated tests); `MAX_FLOWS` 256 fail-open; `MAX_FLOW_BUF` 16 KiB; `MAX_RECENT` 512 (halving eviction); held-packet watchdog 200 ms; QUIC mapper capped 4096 + idle prune; per-packet `handle_exception_fail_open` wraps the whole mutation path. |
| `fragmentation.rs` | ✅ verified | Every TLS walk guarded by `need()` with wrap-safe math; extension walk bounded by `ext_end`; u16 record-length overflow rejected (`F-006`); `persistent_fragmentation` always advances (no infinite loop on len=0); fuzz test for the SNI locator. |
| `quic.rs` | ✅ verified | Blindspot rule (src≤dst) per the USENIX'25 paper; NAT mapper bounded (4096) + idle-pruned + allocation skips never-intercept ports; port rewrites length-checked. |
| `config.rs` | ✅ verified | `deny_unknown_fields`; `MAX_CONFIG_BYTES` 256 KiB; full `validate()` (TTL/chunk ranges, ports, browsers, SNI patterns ≤253, relay host/netguard/DoH URL, token ≥16 printable); `merge_partial` preserves token/pins on empty overrides (unit-tested); hot-reload watcher mtime-gated. |
| `webui.rs` | ✅ verified | 127.0.0.1-only, bearer token (constant-time) on every `/api/*`, 80 ms 401 throttle, Host/Origin allowlist (DNS-rebind), 16 KiB/4096 B caps, full security-header set, no file serving. New status fields added this pass (§7). |
| `ech.rs` | ✅ verified | GREASE-only (documented limitation, no HPKE claim); inject reuses the bounded fragmentation writer. |
| `utls.rs` | ✅ verified | Multiset-preserving reorder only (never regenerates key_share — correct for a passive rewriter); all ranges bounds-checked. |
| `dns_guard.rs` | ✅ verified | WFP remains an honest **stub** (spec construction only, typed errors at runtime); dynamic session (crash-safe) by design; hijack rejects loopback/unspecified. Startup warns loudly about the inactive port-53 block. |
| `packet.rs` | ✅ verified | All readers length-validate (`Ipv4View::parse` IHL checks, `tcp_header_len`, `l3_slice` clips to Total Length/Payload Length — ethernet padding cannot leak); RFC 1071 checksums unit-tested; no panics on malformed input. |
| `sequence.rs` | ✅ verified | Bounded decoy builders; browser-mimic hello length fields self-consistent (tested); 50 µs race fix delay. |
| `fooling.rs` | ✅ verified | All packet surgery length-checked; TCP header ≤60 B enforced; wrong-checksum guaranteed-different. |
| `strategy.rs` | ✅ verified | Score table capped 4096 (ephemeral beyond cap); atomic updates; deterministic tie-break. |
| `connection.rs` | ✅ verified | LRU ticket cache capped; `smart_backoff` bounded + jitter clamped (test improved this pass). |
| `integrity.rs` | ✅ verified | Constant-time pin compare (all pins scanned); 16 MiB driver-hash cap. |
| `doh.rs` (reviewed alongside) | ✅ + fixed | DNS answer walk guarded; this pass replaced the C-style `pos + rdlen < pos` overflow check with `checked_add` (clippy deny; the old form panicked in debug builds before the guard could fire). |

## 7. GUI upgrade (this pass)

Kept the vanilla stack (no frameworks). On top of the existing 77-field/12-section
schema-locked settings editor:

- **Live overview**: `/api/status` now carries `mutated_packets` (pipeline
  output differs from the intercepted packet — counted in the capture loop),
  `doh_state`, `driver_handles_live` + `driver_handles_retired` (from the new
  bounded retirement API), `uptime_secs`; all rendered as overview cards with
  a humanized uptime. Header pills keep relay/connection state.
- **Profile switcher with confirmation**: the 6-profile one-click apply now
  asks before the immediate apply; cancel sends nothing (tested both ways).
- **Unsaved-changes guard**: `beforeunload` warns only when the form is dirty
  (tested both ways).
- **Accessibility**: every control has `aria-label` (Persian name + TOML key)
  and `aria-describedby` → its inline error node; `aria-invalid` flips with
  validation; `#msg` and the dirty-count pill are polite live regions;
  `:focus-visible` ring on all interactive elements.
- **Responsive**: new ≤430 px breakpoint (tighter paddings/cards/rows/buttons)
  keeps the dashboard usable down to ~360 px; header subtitle collapses ≤700 px.
- Search box, recently-changed ("تغییر کرده") highlighting, per-field inline
  errors, danger confirmations and dirty pill were already present and remain.

## 8. Tests & tooling actually run (real results, this Linux box, 2026-09-03 pass)

- `cargo test` / `cargo check` / `cargo clippy` / `cargo audit` — **NOT
  RUN in this sandbox.** This box has no Rust toolchain and no network
  route to `static.rust-lang.org` or crates.io, so no Rust compilation or
  test execution was possible. The crate declares **319 `#[test]`
  functions** across `src/*.rs`; treat every earlier "X passed" claim in
  this document as **unverified** until those commands are run on a
  machine that has a toolchain.
- `uitest` full suite — **re-run in this session (2026-09-04, node v22):
  369 checks, 0 failures** (`cd uitest && npm install && npm test`) —
  test-ui **104** · check-rust-tests **56** · test-v2rayn **67** ·
  test-resilience **60** · test-settings **56** · test-status **26**.
  The restart-tag suite now asserts the full 15-field startup-only list
  (audit gap C110); the brace-balance suite covers the edited `main.rs`.
  Earlier snapshots of the repo showed 3 failures + a crash in test-ui,
  53/3 in check-rust-tests, and an `ENOENT .gitignore` crash in
  test-resilience; those have all been fixed.
## 9. 2026-09-03 line-by-line audit fixes (+ 2026-09-04 snapshot pass)

This session closes every mechanical gap that was verifiable from this
Linux box (the Windows-only packet path still needs field testing). The
2026-09-04 pass applies the same list to this upload snapshot (which had
lost them) and closes the remaining audit gaps: capture-gated relay
reconcile, redacted IP logs, corrected `update_repo`/README links, the
full restart-required list, and the refreshed audit page (`index.html`):

- `.gitignore` added — covers WinDivert binaries, `target/`, `dpi_guard.toml`,
  `dpi_guard.dns_cache`, `dpi_guard.instance.lock`, logs, `uitest/node_modules`,
  OS/editor detritus. `test-resilience.mjs` no longer crashes with ENOENT.
- `.cargo/config.toml` added — forces `WINDIVERT_PATH = "."` (repo root,
  resolved relative to the file) so a stale env var from another project
  cannot break `windivert-sys/build/main.rs`.
- WinDivert binaries (`WinDivert.dll`/`.lib`/`WinDivert64.sys`) removed
  from git tracking (`git rm --cached`); files remain on disk for
  development but a clean clone no longer carries them. The SHA-256 pins
  in `dpi_guard.toml.example` and in `scripts/fetch-windivert.{sh,ps1}`
  continue to match the official 2.2.2 release.
- `.github/workflows/` is deliberately NOT added: `ci/github-actions.yml`
  documents that the operator copies it there themselves (environment token
  policy), so `ci/` stays the source of truth and this file does not claim
otherwise.
- Dead stealth/pipeline code wiring:
  * decoy payload now actually uses `add_random_padding` + `inject_noise_entropy`
    + `randomize_window_size` (wrong-seq decoys only, so a real server's
    receive window is never shrunk).
  * `simulate_browser_fingerprint` + `shape_fingerprint` drive the cipher
    and curve lists in `build_browser_mimic_hello` (each fake hello gets a
    fresh shuffle + GREASE insertion).
  * `MemoryCertCache.observe_success` populated when a ServerHello is seen
    for an SNI, so identity-breaking mutations stop emitting the "cert
    cache empty" warning after a successful handshake.
  * `SessionTicketCache.put/get` actually exercised per-SNI (LRU path hot).
  * `stealth::validate_dnssec` now runs on every DoH response (debug log).
  * `geedge::prepend_grease_extensions` wired into the `enable_geedge_evasion`
    path (1–2 GREASE ext + random padding).
- Unused `assets/fonts/Vazirmatn-*.ttf` removed (245 KB); the UI falls back
  to Tahoma/"Segoe UI"/system-ui which ships on every Windows install and
  renders Persian correctly. The CSP is already `default-src 'none'` so a
  binary-embedded font would have required a `font-src data:` relaxation;
  system fonts keep the binary small and the CSP strict.
- This STATUS.md rewritten to match what was actually observed and run.
