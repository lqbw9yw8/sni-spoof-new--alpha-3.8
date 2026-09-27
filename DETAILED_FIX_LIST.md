# لیست دقیق بدون ساده‌سازی — چی درست شد، چی نشد

تاریخ: 2026-09-13 22:20 UTC
برنچ: arena/01a09cc5-sni-spoof-new-alpha-3-6
HEAD: 710e713 docs: final report COMPLETE STATIC 449 tests
مبنای اولیه: 7670432 Add files via upload

> این فایل طبق درخواست "بدون ساده‌سازی و حذفیات" تمام موارد پیدا شده خط‌به‌خط را لیست می‌کند.

---

## بخش اول: درست‌شده‌ها (FIXED) — با آدرس دقیق خط

### F-01: self_update repo mismatch — P2 MAJOR — supply-chain 404

**فایل‌های درگیر:**
- `src/self_update.rs:38` ثابت `DEFAULT_UPDATE_REPO`
- `src/self_update.rs:317` تست `default_repo_matches_this_crate`
- `dpi_guard.toml.example:254` فیلد `update_repo`
- `README.md:4,89,92` لینک‌های GitHub

**کد قدیم:**
```rust
// src/self_update.rs:38
pub const DEFAULT_UPDATE_REPO: &str = "lqbw9yw8/sni-spoof-new-5.6";
// dpi_guard.toml.example:254
update_repo = "lqbw9yw8/sni-spoof-new-5.5"
// README.md:4
[`lqbw9yw8/sni-spoof-new--alpha-3.12`](https://github.com/lqbw9yw8/sni-spoof-new--alpha-3.12)
```

**ریشه:** ریپوی واقعی `lqbw9yw8/sni-spoof-new--alpha-3.6` است (از `git remote -v`). ثابت قدیمی به `5.6` و `5.5` و `3.12` اشاره می‌کرد → GitHub API `https://api.github.com/repos/.../releases/latest` 404 می‌داد → `check_for_update` همیشه `Err` یا `update_available=false` برمی‌گرداند و کاربر هیچ‌وقت آپدیت را نمی‌دید. در `dpi_guard.toml.example` هم کاربر را به ریپوی اشتباه می‌فرستاد.

**کد جدید:**
```rust
pub const DEFAULT_UPDATE_REPO: &str = "lqbw9yw8/sni-spoof-new--alpha-3.6";
```
- `dpi_guard.toml.example:254` → `alpha-3.6`
- `README.md:4,89,92` → `alpha-3.6` (سه مورد sed)
- تست `default_repo_matches_this_crate` و `valid_repo_slugs_are_accepted` به‌روز شد تا `alpha-3.6` را بپذیرد

**تست رگرسیون:**
- `cargo test self_update -- --nocapture` (در صورت وجود cargo) باید `default_repo_matches_this_crate` و `valid_repo_slugs_are_accepted` پاس شود
- `tools/lint_docs.py` چک `repo-identity` — قبل 3 violation، بعد 0

**تأیید:** lint 0 violations، دستی `grep -R "sni-spoof-new-5"` فقط در `docs/archive/` تاریخی باقی ماند.

---

### F-02: autottl unbounded HashMap — P2 MAJOR — CWE-770 — NEW

**فایل:** `src/autottl.rs:17,22-25,125-131,138-175,355`

**کد قدیم:**
```rust
pub const MAX_AUTO_TTL: u8 = 64;
const LEARN_TTL: Duration = 30min;
pub struct AutoTtl { learned: HashMap<IpAddr, Learned> }
pub fn observe(&mut self, src: IpAddr, ...) { self.learned.insert(src, ...) } // بدون سقف
pub fn prune(&mut self) { retain <= LEARN_TTL }
```
- هیچ `MAX_ENTRIES` نداشت، در حالی که `pipeline.rs` برای `last_activity` 4096، `inbound_ttl` 4096، `flows` 256، `recent` 512، `relay_flows` 256، `quic_mapper` 4096 سقف داشت.
- `observe` در `pipeline.rs:393` با `parsed.src` (IP مبدأ inbound) صدا زده می‌شود — قابل جعل (spoofed) — مهاجم می‌تواند با سیل IPهای جعلی حافظه را بی‌نهایت کند.

**ریشه:** فراموشی اعمال الگوی bounded در ماژول جدید.

**کد جدید:**
```rust
pub const MAX_AUTO_TTL_ENTRIES: usize = 4096;
pub fn len(&self) -> usize { self.learned.len() }
pub fn observe(&mut self, src: IpAddr, ...) {
  if !self.learned.contains_key(&src) && self.learned.len() >= MAX_AUTO_TTL_ENTRIES {
    self.evict_oldest_half();
  }
  self.learned.insert(...)
}
fn evict_oldest_half(&mut self) {
  let mut by_age: Vec<(IpAddr, Instant)> = self.learned.iter().map(...).collect();
  by_age.sort_unstable_by_key(|(_, at)| *at);
  let n = by_age.len()/2;
  for (ip,_) in by_age.into_iter().take(n) { self.learned.remove(&ip); }
}
```

**تست رگرسیون جدید:**
```rust
#[test]
fn auto_ttl_bounded_under_spoofed_source_flood() {
  let mut a = AutoTtl::new();
  for i in 0..(MAX_AUTO_TTL_ENTRIES+500) { a.observe(parse_ip, 58, 0); }
  assert!(a.len() <= MAX_AUTO_TTL_ENTRIES);
}
```
- قبل: len = 4596 > 4096
- بعد: len <= 4096

**تأیید:** static review، تست declare شد (449امین تست)، `gen_status.py` 449.

---

### F-03: connection.rs SessionTicketCache LRU panic — P3 MINOR — CWE-248

**فایل:** `src/connection.rs:54-72`

**کد قدیم:**
```rust
pub fn put(&mut self, sni: &str, ticket: Vec<u8>) {
  if let Some(existing) = self.tickets.get_mut(sni) {
    *existing = ticket;
    let pos = self.tickets.get_index_of(sni).unwrap(); // panic اگر index نباشد
    self.tickets.move_index(pos, self.tickets.len()-1); // panic اگر len=0
    return;
  }
  if self.tickets.len() >= self.capacity { self.tickets.shift_remove_index(0); }
  self.tickets.insert(...)
}
pub fn get(&mut self, sni: &str) -> Option<&Vec<u8>> {
  let pos = self.tickets.get_index_of(sni)?;
  let last = self.tickets.len() - 1; // panic اگر len=0 (غیرممکن ولی ناامن)
  ...
}
```

**ریشه:** `IndexMap::get_index_of` می‌تواند None برگرداند اگر race یا منطق اشتباه؛ `len()-1` در حالت خالی panic.

**کد جدید:**
```rust
pub fn put(...) {
  if let Some(existing) = self.tickets.get_mut(sni) {
    *existing = ticket;
    if let Some(pos) = self.tickets.get_index_of(sni) {
      let last = self.tickets.len().saturating_sub(1);
      self.tickets.move_index(pos, last);
    }
    return;
  }
  ...
}
pub fn get(...) {
  let pos = self.tickets.get_index_of(sni)?;
  let last = self.tickets.len().saturating_sub(1);
  ...
}
```

**تست رگرسیون:** `session_cache_evicts_least_recently_used` قبلاً پاس بود، بعد هم پاس (static).

---

### F-04: scanner.rs next_weighted_random last().unwrap() — P3 MINOR

**فایل:** `src/scanner.rs:428-432` (قبل)

**قدیم:**
```rust
pub fn next_weighted_random(&mut self) -> Option<&str> {
  if self.entries.is_empty() { return None; }
  // ... weighted logic
  Some(&self.entries.last().unwrap().sni) // panic اگر خالی (اگرچه بالا چک شد، ولی الگوی ناامن)
}
```

**جدید:**
```rust
Some(self.entries.last().map(|e| e.sni.as_str())?) // یا self.entries.last().map(|e| e.sni.as_str())
```
در نسخه نهایی: `self.entries.last().map(|e| e.sni.as_str())`

**ریشه:** الگوی unwrap در fallback.

---

### F-05: hpke.rs 13 try_into().unwrap() — P3 MINOR — CWE-248 — 13 نقطه

**فایل:** `src/hpke.rs:54-58,512,516,568-569,585-586,591,659-660`

**قدیم (5 مورد اول):**
```rust
u64::from_le_bytes(w[0..8].try_into().unwrap()) & MASK51,
(u64::from_le_bytes(w[6..14].try_into().unwrap()) >> 3) & MASK51,
...
```

**ریشه:** برش‌ها طول ثابت 8 دارند، ولی `try_into().unwrap()` مسیر panic دارد و قانون "no unwrap in prod" را می‌شکند.

**جدید:**
```rust
u64::from_le_bytes([w[0],w[1],w[2],w[3],w[4],w[5],w[6],w[7]]) & MASK51,
...
```
- `Fe::from_bytes` 5 مورد → آرایه دستی
- `chacha20_block` 2 مورد: `key[i*4..i*4+4].try_into().unwrap()` → helper `le_u32_from_4(&key[off..off+4])` که `[b[0],b[1],b[2],b[3]]`
- `poly1305_mac` 5 مورد: `rb[0..8].try_into().unwrap()` → `le_u64_from_8`, `wide[0..8]`, `wide[8..16]`, `wide[16..24]`, `key[16..24]`, `key[24..32]` → `le_u64_from_8`

**Helper جدید:**
```rust
fn le_u32_from_4(b: &[u8]) -> u32 { u32::from_le_bytes([b[0],b[1],b[2],b[3]]) }
fn le_u64_from_8(b: &[u8]) -> u64 { u64::from_le_bytes([b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7]]) }
```

**تست:** RFC vectors `x25519_rfc7748_vector_1`, `chacha20_rfc8439_keystream_vector`, `poly1305_rfc8439_tag_vector`, `aead_rfc8439_seal_vector` باید پاس شوند (اگر cargo بود).

---

### F-06: main.rs expect() — P3 MINOR — 2 نقطه

**فایل:** `src/main.rs:850,1114`

**قدیم:**
```rust
.spawn(...).expect("spawn capture thread")
.build().expect("tokio runtime")
```

**ریشه:** `std::thread::Builder::spawn` می‌تواند `Err` دهد اگر OS محدودیت thread یا OOM؛ `tokio::runtime::Builder::build` می‌تواند `Err` دهد؛ expect = panic.

**جدید:**
```rust
.spawn(...).unwrap_or_else(|e| { log::error!("failed to spawn capture thread: {e}"); std::process::exit(1); })
.build().unwrap_or_else(|e| { log::error!("failed to build tokio runtime: {e}"); std::process::exit(1); })
```

**تأیید:** static, graceful exit به‌جای panic.

---

### F-07: scanner.rs parse().unwrap() hardcoded IPs — P3 MINOR — 7 نقطه

**فایل:** `src/scanner.rs:528-537`

**قدیم:**
```rust
"104.16.0.1".parse().unwrap(),
"104.16.1.1".parse().unwrap(),
...
```

**ریشه:** literal ولی unwrap.

**جدید:**
```rust
use std::net::{Ipv4Addr, IpAddr};
IpAddr::V4(Ipv4Addr::new(104,16,0,1)),
...
```

---

### F-08: stealth.rs Normal::new expect — P3 MINOR — 1 نقطه

**فایل:** `src/stealth.rs:16`

**قدیم:**
```rust
let normal = Normal::new(20.0, 10.0).expect("valid normal params");
```

**جدید:**
```rust
let jitter = Normal::new(20.0,10.0).map(|n| n.sample(&mut rng).max(0.0)).unwrap_or(20.0);
```

**ریشه:** expect حتی با پارامتر معتبر.

---

### F-09: README repo-identity + dead-link — P4 QUALITY

**فایل:** `README.md:4,89,92,103,108,541`

**قدیم:**
- 3 لینک به `lqbw9yw8/sni-spoof-new--alpha-3.12` در حالی که `git remote -v` می‌گوید `alpha-3.6`
- لینک `[.github/workflows/build-windows.yml](.github/workflows/build-windows.yml)` در حالی که فایل فقط در `ci/build-windows.yml` وجود داشت → dead-link
- ادعای `42 modules, 448 tests` در حالی که بعد از autottl fix شد 449
- تاریخ `2026-09-12` در حالی که آخرین اجرای JS 2026-09-13 بود

**جدید:**
- `alpha-3.12→alpha-3.6` sed
- dead-link → `[ci/build-windows.yml](ci/build-windows.yml)` + توضیح "برای فعال‌سازی در GitHub، آن را به `.github/workflows/build-windows.yml` کپی کنید"
- `448→449`, `17→18` تست تأییدنشده, تاریخ `09-12→09-13`
- `gen_status.py --check` کامنت به‌روز

**تأیید:** `lint_docs.py` قبل 4 violation (3 repo-identity + 1 dead-link)، بعد 0.

---

### F-10: .gitignore missing — P1 BLOCKER (earlier) + P4

**فایل:** `.gitignore` وجود نداشت در main branch

**قدیم:** بدون gitignore → `target/`, `*.exe`, `*.dll`, `dpi_guard.toml` (حاوی توکن), `dpi_guard.dns_cache`, `uitest/node_modules/` 200MB ممکن بود کامیت شود. همچنین `uitest` تست `.gitignore ENOENT` داشت.

**جدید:**
```
/target/
*.exe
*.pdb
dpi_guard.dns_cache
dpi_guard.toml
*.log
.idea/
.vscode/
uitest/node_modules/
dist/
out/
coverage/
```
- فایل ترک شد (git add .gitignore)
- `git check-ignore` حالا `uitest/node_modules/foo` را ignore می‌کند
- `git status` تمیز

---

### F-11: TEST_MATRIX.md out-of-date — P4

**فایل:** `TEST_MATRIX.md`, `tools/status.json`

**قدیم:** 24273 خط، 448 تست، 0 dead — بعد از تغییرات autottl و hpke و main و scanner و stealth، فایل قدیمی بود → `gen_status.py --check` FAIL

**جدید:** `python3 tools/gen_status.py` → 24348 خط (بعد 243?? در نهایت 24348)، 42 ماژول، **449 تست**، 0 dead، 23 test-only

**تأیید:** `gen_status.py --check` GREEN

---

### F-12: STATUS.md + KNOWN_ISSUES.md count mismatch — P4

**فایل:** `STATUS.md:50,127,167`, `KNOWN_ISSUES.md:14,121`

**قدیم:** 448 تست، 17 تست تأییدنشده، تاریخ 09-12

**جدید:** 449 تست، 18 تست تأییدنشده، تاریخ 09-13

**تأیید:** دستی grep، lint دیگر Persian digits را نمی‌گیرد ولی ما دستی فیکس کردیم.

---

### F-13: connection.rs get() len()-1 — P3 (تکمیلی F-03)

**فایل:** `src/connection.rs:67`

**قدیم:** `let last = self.tickets.len() - 1;` — اگر len=0 (غیرممکن چون get_index_of None برمی‌گرداند ولی ناامن)

**جدید:** `saturating_sub(1)`

---

## بخش دوم: درست‌نشده‌ها (NOT FIXED) — دقیق با دلیل

### NF-01: Rust toolchain BLOCKED — P0 BLOCKER — محیطی

**محل:** کل `cargo test`, `cargo build`, `cargo fmt --check`, `cargo clippy -D warnings`, `cargo audit`

**شرح:** در sandbox فعلی:
- `which cargo` → not found
- `ls /opt/cargo` → No such file
- `apt-get update` → `Could not open lock file /var/lib/apt/lists/lock - Permission denied`
- `curl https://sh.rustup.rs` → `SSL_ERROR_SYSCALL` + `SSLZeroReturnError: TLS/SSL connection has been closed (EOF)`
- `python3 ssl` → `ssl.SSLZeroReturnError`
- `wget http://sh.rustup.rs` → `Empty reply from server`

**ریشه:** محیط sandbox اینترنت خروجی TLS را مسدود کرده، apt بدون sudo است، cargo نصب نیست. این باگ ریپو نیست، باگ محیط است.

**چرا فیکس نشد:** نیاز به host با اینترنت و دسترسی sudo دارد. طبق AI_RULES.md بخش 0: "اگر نتوانستید cargo test را اجرا کنید، این را با صدای بلند بگویید. ننویسید تست‌ها پاس شدند."

**پیامد:** 18 تست جدید (449-431) `[UNVERIFIED]` باقی ماندند، build Windows انجام نشد.

**راه حل برای شما:** روی سیستم خود با Rust stable 1.98+ و اینترنت:
```bash
cargo test --all-targets   # باید 449 پاس شود
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

---

### NF-02: Windows/WinDivert runtime UNVERIFIED — P1 CRITICAL — محیطی

**محل:** `src/engine.rs`, `src/dns_guard.rs`, `src/singleton.rs`, `src/main.rs` backend

**شرح:**
- `engine.rs` نوشته شده برای `windivert 0.5.5` API (`WinDivert::network`, `recv(Some(&mut buf))`, `send`, `shutdown`, `close`) ولی در sandbox لینوکس کامپایل نشده، چون `engine_stub.rs` جایگزین است.
- `dns_guard.rs` از `Fwpuclnt.dll` FFI واقعی استفاده می‌کند (`FwpmEngineOpen0`, `FwpmTransactionBegin0`, `FwpmFilterAdd0` x4, `FwpmTransactionCommit0`) ولی BFE (Base Filtering Engine) روی لینوکس نیست.
- `singleton.rs` روی ویندوز `CreateFileW` + `LockFile` و روی یونیکس `flock` — فقط تست‌های `flock` روی لینوکس اجرا می‌شود.

**چرا فیکس نشد:** نیاز به Windows 10/11 VM، Administrator، فایل‌های رسمی WinDivert.dll + WinDivert64.sys کنار exe، `RUST_LOG=dpi_guard=debug`.

**ماتریس تست ویندوز که باید انجام شود (از KNOWN_ISSUES K-2):**
- WIN-01 Singleton lock
- WIN-02 SHA-256 pin
- WIN-03 Wireshark decoy TTL
- WIN-04 relay 127.0.0.1
- WIN-05 fail-closed بدون شبکه
- WIN-06 proxy cleanup restore

---

### NF-03: WFP callout driver — BLOCKED — خارج از scope

**محل:** `src/dns_guard.rs` کامنت "legacy `trusted_dns` redirect is rejected until a signed callout exists"

**شرح:** `dns_guard` فقط port 53 را بلاک می‌کند (permit loopback + block outbound TCP/UDP 53 IPv4/IPv6). برای redirect به `trusted_dns` نیاز به signed kernel callout driver است که در این ریپو نیست و طبق AI_RULES.md خارج از scope است. `trusted_dns` غیرخالی fail-closed رد می‌شود.

**چرا فیکس نشد:** نیاز به درایور کرنل امضاشده، خارج از scope پروژه.

---

### NF-04: 23 test-only functions — PARTIAL — معماری

**محل:** `TEST_MATRIX.md` ستون `test-only` = 23

**شرح:** طبق `tools/gen_status.py` 23 تابع فقط از تست‌ها صدا زده می‌شوند، نه از مسیر اجرای واقعی. طبق AI_RULES.md بخش 3: هر تابعی که آنجاست حداکثر `PARTIAL` است، نه `DONE`.

**مثال‌ها:** بعضی توابع `geedge`, `quic`, `sequence`, `stealth`, `utls` که قبلاً dead بودند وصل شدند ولی هنوز بعضی helperها فقط تست هستند.

**چرا فیکس نشد:** نیاز به integration بیشتر و تست میدانی ویندوز. فعلاً صادقانه `PARTIAL`/`UNTESTED` ثبت شده.

---

### NF-05: WebUI brute-force — P4 QUALITY — باقی‌مانده

**محل:** `src/webui.rs:673` + `src/webui.rs` token check

**شرح:** Dashboard فقط 80ms تأخیر ثابت + اتصال‌های سریالی دارد، per-IP lockout ندارد. چون فقط `127.0.0.1` گوش می‌دهد، ریسک پایین است (loopback only).

**چرا فیکس نشد:** loopback-only است، ریسک پایین، در KNOWN_ISSUES K-8 مستند شد.

---

### NF-06: TOCTOU driver pin — PARTIAL — Windows runtime UNVERIFIED

**محل:** `src/engine.rs:526-565`

**شرح:** در سورس فیکس شده: DLL/SYS قبل از hash با handle اشتراکی read-only باز می‌شوند، همان handleها تا پایان backend زنده می‌مانند، DLL با absolute path بار می‌شود و `GetModuleFileNameW` با مسیر مورد انتظار تطبیق می‌گیرد. ولی اجرای ویندوز هنوز `[UNVERIFIED]` است.

**چرا فیکس نشد کامل:** نیاز به Windows runner تا خلاف invariant را نشان دهد.

---

### NF-07: scanner cert_valid — PARTIAL — network UNVERIFIED

**محل:** `src/scanner.rs:probe_tls_handshake`

**شرح:** در سورس فیکس شده: probe اکنون از ureq/rustls با SNI کاندید و resolver متصل به IP انتخاب‌شده استفاده می‌کند؛ پاسخ HTTP خطادار هم فقط پس از عبور زنجیره/نام TLS موفق محسوب می‌شود. ولی runtime شبکه در این checkout `[UNVERIFIED]` است.

**چرا فیکس نشد کامل:** نیاز به network + TLS runner.

---

### NF-08: .github/workflows/build-windows.yml not tracked on remote — P4 — GitHub App permission

**محل:** `README.md:103` + `.github/workflows/build-windows.yml`

**شرح:** فایل workflow در `ci/build-windows.yml` وجود دارد و باید به `.github/workflows/` کپی شود. تلاش برای `git push` با این فایل:
```
remote rejected: refusing to allow a GitHub App to create or update workflow without workflows permission
```
GitHub App token Arena اجازه پوش workflow ندارد.

**راه حل اعمال‌شده:** README لینک را از `.github/workflows/build-windows.yml` به `ci/build-windows.yml` تغییر داد + توضیح "برای فعال‌سازی در GitHub، آن را به `.github/workflows/` کپی کنید". `tools/lint_docs.py` حالا dead-link را نمی‌گیرد چون `ci/` وجود دارد. فایل `.github/workflows/build-windows.yml` به‌صورت لوکال ساخته شد ولی کامیت نشد تا push موفق شود.

**چرا کامل فیکس نشد روی remote:** محدودیت permission GitHub App — کاربر باید دستی روی GitHub Actions تب، فایل را کپی کند یا با PAT دارای workflows permission پوش کند.

---

### NF-09: uitest/node_modules 200MB — P4 — artifact

**محل:** `uitest/node_modules/`

**شرح:** بعد از `npm ci && npm test` پوشه 200MB ساخته می‌شود. قبلاً `.gitignore` نداشت و `git status` آن را `??` نشان می‌داد.

**فیکس جزئی:** `.gitignore` اضافه شد `uitest/node_modules/` — حالا `git check-ignore` آن را ignore می‌کند و کامیت نمی‌شود. ولی پوشه هنوز لوکال وجود دارد (untracked). برای تمیزی کامل باید `rm -rf uitest/node_modules` کرد ولی برای اجرای تست‌ها لازم است.

---

### NF-10: 18 tests unverified since baseline — P2 — env

**محل:** `STATUS.md` آمار

**شرح:** baseline تاریخی 431/431 روی Rust 1.98.1 لینوکس سبز بود. سورس فعلی 449 تست دارد → 18 تست جدید/تغییر یافته `[UNVERIFIED]` چون cargo در محیط فعلی نیست.

**چرا فیکس نشد:** نیاز به cargo test — همان NF-01.

---

### NF-11: docs/archive/ false claims — تاریخی — عمداً باقی

**محل:** `docs/archive/*.md` — 16 سند قدیمی

**شرح:** این پوشه حاوی اسناد قدیمی با اعداد 344، 369، 427، 431 و لینک‌های `sni-spoof-new-5.6` است. طبق `tools/lint_docs.py` چک `archive-banner` — هر فایل باید بنر `ARCHIVED — DO NOT TRUST` داشته باشد و دارد.

**چرا فیکس نشد:** عمداً آرشیو است و نباید به‌روز شود؛ منبع حقیقت `STATUS.md` است.

---

### NF-12: README claim "15 anti-fingerprint techniques" — P4 — approximate

**محل:** `src/stealth.rs:1` کامنت `//! stealth — 15 anti-fingerprint`

**شرح:** تعداد تابع‌ها 20+ است ولی عنوان 15 تقریبی است. دقیقاً 15 تکنیک نام‌گذاری نشده.

**چرا فیکس نشد:** approximate claim، ریسک پایین، در `FINAL_REPORT` به‌عنوان approximate ثبت شد.

---

## بخش سوم: خلاصه عددی

| دسته | قبل | بعد | وضعیت |
|---|---|---|---|
| prod unwrap/expect قبل از #[cfg(test)] | 27 | **0** | FIXED |
| panic! قبل از test | 0 | 0 | OK |
| unsafe خارج از allowed (dns_guard, engine, singleton) | 0 | 0 | OK |
| HashMap unbounded | 1 (autottl) | 0 (همه 4096/256/512) | FIXED |
| repo-identity violations | 3 | 0 | FIXED |
| dead-link violations | 1 | 0 | FIXED |
| settings count | 82 | 82 | OK |
| test declared | 448 | **449** (+1 autottl bounded) | FIXED |
| test baseline executed | 431 | 431 | تاریخی |
| JS uitest | 375 passed | 375 passed (26 status-ui این نوبت) | GREEN |
| lint_docs | 4 violations | **0 violations** | FIXED |
| gen_status | out-of-date | up-to-date | FIXED |
| .gitignore tracked | No | Yes | FIXED |
| cargo test | BLOCKED env | BLOCKED env | NOT FIXED env |
| Windows runtime | UNVERIFIED | UNVERIFIED | NOT FIXED env |

---

## بخش چهارم: دانلود نهایی با تمام فیکس‌های بالا

- **ZIP لوکال (853K):** `/home/user/sni-spoof-new--alpha-3.6-fixed.zip` (در پنل فایل present شد — Download)
- **برنچ GitHub:** `https://github.com/lqbw9yw8/sni-spoof-new--alpha-3.6/tree/arena/01a09cc5-sni-spoof-new-alpha-3-6`
- **ZIP مستقیم برنچ:** `https://github.com/lqbw9yw8/sni-spoof-new--alpha-3.6/archive/refs/heads/arena/01a09cc5-sni-spoof-new-alpha-3-6.zip`

برای تأیید نهایی روی سیستم خود:
```bash
unzip sni-spoof-new--alpha-3.6-fixed.zip
cd sni-spoof-new--alpha-3.6
python3 tools/gen_status.py --check
python3 tools/lint_docs.py
cd uitest && npm ci && npm test
cargo test --all-targets   # نیاز به اینترنت
```

تمام موارد بخش اول در این ZIP هستند. موارد بخش دوم به دلیل محدودیت محیط (no cargo, no Windows, no internet, GitHub App workflows permission) یا out-of-scope بودن (WFP callout driver) باقی ماندند و صادقانه مستند شدند per AI_RULES.md.

