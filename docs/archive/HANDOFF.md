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

# بریف پروژهٔ dpi_guard برای ادامهٔ کار

تاریخ بازبینی: 2026-08-26
ریپو: https://github.com/lqbw9yw8/sni-spoof-new-2.3.4
crate: `dpi_guard`
شاخهٔ کار: `arena/01a06386-sni-spoof-new-2-3-4`
کامیت پایهٔ این checkout: `10736ca693e639922c6e9ac1ec9a0f8608f19b7d` («Add files via upload») — تنها کامیت تاریخ ریپو

> این سند **جایگزین بریف 4.3** است. ادعاها در همین session با خواندن فایل‌ها
> و اجرای تست‌های Node تأیید شده‌اند. هر چیزی که اجرا نشد، صریحاً علامت خورده.

---

## ۰) اصلاحات نسبت به بریف 4.3 (نچسبانید به این ریپو)

بریف قبلی مربوط به `sni-spoof-new-4.3` / شاخه `arena/01a03a02-sni-spoof-new-4-3`
/ کامیت `2d9da03` / PR `#1` بود. **هیچ‌کدام اینجا درست نیستند.**

| ادعا در بریف 4.3 | واقعیت 4.4 |
|---|---|
| ریپو `…/sni-spoof-new-4.3` | `…/sni-spoof-new-2.3.4` (نه 4.4 — آن ریپو وجود ندارد) |
| شاخه `arena/01a03a02-sni-spoof-new-4-3` | `arena/01a06386-sni-spoof-new-2-3-4` |
| کامیت `2d9da03` / پایهٔ audit `dcb4dbf` | فقط یک کامیت: `10736ca` |
| «`.gitignore` اضافه شد (F2 رفع شد)» | **فایل وجود نداشت** تا این بازبینی |
| «۲۸۵ بررسی UI پاس» | در بازبینی 2026-09 اندازه‌گیری شد: suite عملاً ۳ خطا + crash داشت. بعد از اصلاحات 2026-09: **۳۶۹ پاس، ۰ خطا** (۱۰۴+۵۶+۶۷+۶۰+۵۶+۲۶) |
| `check-rust-tests.mjs` روی SHA `dcb4dbf` | آن کامیت در تاریخ 4.4 نیست؛ کالیبراسیون skip می‌شود |

---

## ۱) پروژه چیست

رلهٔ محلی SNI-spoofing به سبک patterniha برای ویندوز. هستهٔ Xray/v2ray/sing-box
ندارد و VPN نیست — **IP مقصد روی سیم دیده می‌شود**. کارش این است که قبل از
ClientHello واقعی، یک ClientHello جعلی با SNI خوش‌خیم و SEQ اشتباه تزریق کند
تا DPI جریان را whitelist کند و سرور واقعی پکت جعلی را بیندازد.

Packet I/O فقط ویندوز (`cfg(windows)` + crate `windivert` 0.5). ماژول‌های منطقی
روی هر OS بیلد و تست می‌شوند؛ روی لینوکس `src/engine_stub.rs` جایگزین
`src/engine.rs` می‌شود و باینری با پیام پلتفرم `exit 1` می‌کند.

---

## ۲) وضعیت تست — اجراشده در این session

### اجرا شد

| دستور | نتیجه |
|---|---|
| `cd uitest && npm install && npm test` | **۲۸۵ پاس، ۰ شکست** (۱۰۳ UI + ۵۶ اسکیما + ۶۶ v2rayN + ۶۰ resilience) |
| `node uitest/test-ui.mjs` | ۱۰۳ پاس |
| `node uitest/check-rust-tests.mjs` | ۵۶ پاس (کالیبراسیون `dcb4dbf` در این درخت نیست؛ skip شد) |
| `node uitest/test-v2rayn.mjs` | ۶۶ پاس |
| `node uitest/test-resilience.mjs` | ۶۰ پاس — قبل از افزودن `.gitignore` با `ENOENT` می‌ترکید |

`.gitignore` در این اسنپ‌شات وجود نداشت (خلاف بریف 4.3 و خلاف README). اضافه شد تا `dpi_guard.dns_cache` / `*.dll` / `*.sys` / `dpi_guard.toml` ignore شوند.

### اجرا نشد (این sandbox)

- `rustc` / `cargo` نصب نیست.
- `https://static.rust-lang.org` و `https://crates.io` از اینجا پاسخ ندادند.
- بنابراین **`cargo fmt` / `cargo clippy` / `cargo test` / بیلد ویندوز اجرا نشدند.**
- WinDivert / Windows field test اجرا نشد.

اولین کار روی ماشین دارای Rust:

```
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release --target x86_64-pc-windows-msvc   # روی ویندوز
```

یافتهٔ خوانده‌شده که `cargo test` باید روشن کند: در `src/webui.rs`
`DashboardSnapshot` از `Default` مشتق شده پس `relay_require_inject` پیش‌فرض
`false` است، ولی تست `status_json_is_well_formed_for_empty_snapshot` انتظار
`"relay_require_inject":true` دارد. این را بدون کامپایل قطعی نمی‌گویم — فقط
کاندید شکست است.

---

## ۳) اولویت ۱ — نشتی DNS (بزرگ‌ترین شکاف کارکردی)

تأیید از `README.md` / `START_HERE.md` / `src/main.rs:218` / `src/dns_guard.rs`:

- جهش SNI دامنه را از resolver پنهان نمی‌کند؛ OS هنوز می‌تواند UDP/53 بزند.
- `dns_guard` فقط **spec** می‌سازد (`allow 127.0.0.1:53` سپس `block :53`).
- `block_port_53_except_localhost()` روی ویندوز همیشه
  `Err("WFP FFI bindings not implemented in this build")` برمی‌گرداند.
- درایور callout امضاشده در اسکوپ این crate نیست (`needs_callout_driver: true`).

`trusted_dns`: فقط در `src/config.rs` (فیلد + validate IP + merge/clear) و
`src/webui.rs` (JSON داشبورد). **هیچ ماژول دیگری آن را نمی‌خواند** — گزینهٔ
مرده. `doh_server` مسیر واقعی resolve است (`src/doh.rs`، بدون fallback به UDP/53).

کارهای ممکن (بدون پیاده‌سازی در این session):

- WFP FFI + callout امضاشده — سنگین، نیاز به امضای درایور.
- اجبار DoH سیستمی (ویندوز ۱۱) و مستندسازی.
- قوی‌ترین راه موجود در خود کد: `relay_connect_host` را IP literal بگذارید
  (`dpi_guard.toml.example` همین را می‌کند) → resolve نمی‌زند.

این session **WFP FFI پیاده نکرد** (خارج از اسکوپ audit و نیاز به درایور هسته).

---

## ۴) اولویت ۲ — use-after-free در `engine.rs` (تخفیف داده شد، کامپایل ویندوز نشده)

قبلاً `store_handle` / `drop_stored_handle` بعد از `Box::from_raw` هندل را
drop می‌کردند در حالی که watchdog `DIVERT.load()` کرده بود.

حالا `retire()` هندل را `shutdown` می‌کند و `Box` را در
`static RETIRED: Mutex<Vec<Box<Divert>>>` پارک می‌کند (نشتی کران‌دار به تعداد
reload فیلتر). deref بعد از swap دیگر UAF روی allocation نیست؛ `send` روی
هندل خاموش‌شده باید خطا بدهد نه حافظهٔ آزاد.

هنوز `AtomicPtr` است نه `RwLock<Arc<_>>`. بدون Windows این پچ کامپایل/تست نشده.
تست رگرسیون reload+flush هنوز seam ندارد.

---

## ۵) اولویت ۳ — STUBهای باقی‌مانده

تأییدشده:

- WFP FFI (`FwpmEngineOpen0` / `FwpmFilterAdd0`) — وجود ندارد
- درایور callout امضاشده برای redirect DNS — وجود ندارد
- auto-spawn کیل‌سوییچ: `kill_switch_trigger` فقط رشتهٔ PowerShell می‌سازد؛
  `main.rs` آن را لاگ می‌کند (`ARMED (not spawned)`) و هرگز `Command` اجرا نمی‌کند
- `engine.rs` روی ویندوز واقعی در این محیط کامپایل/تست نشده؛ بر اساس API منتشرشدهٔ
  `windivert` 0.5 نوشته شده

---

## ۶) اولویت ۴ — تست میدانی روی ویندوز

تا حالا هیچ‌کدام در عمل اینجا تست نشده‌اند:

- `WinDivert::network` / `recv` / `send` / `shutdown` / `close`
- TTL دِکوی تا DPI (`decoy_ttl` را حدسی نگذارید)
- watchdog پکت‌های held (`HOLD_TIMEOUT = 200ms` در `pipeline.rs`)
- graceful shutdown که `recv` را unblock کند
- همزیستی واقعی با v2rayN — روش دستی ۵ مرحله‌ای در انتهای `uitest/test-v2rayn.mjs`

شرایط: ویندوز ۱۰/۱۱ ۶۴ بیتی، Administrator، `WinDivert.dll` + `WinDivert64.sys`
رسمی از reqrypt.org **کنار exe** (نه cwd)، `RUST_LOG=dpi_guard=debug`.

---

## ۷) معاوضهٔ معلوم (عمداً پذیرفته)

`src/main.rs` watchdog: retry راه‌اندازی رله هر ۳۰ ثانیه
(`RELAY_RETRY_INTERVAL`). `reconcile()` مقصد را همگام resolve می‌کند → این
ترد تا بودجهٔ DoH بلاک می‌شود و flush پکت‌های held عقب می‌افتد. فقط وقتی رله
خاموش است. کامنت همان کد راه‌حل درست را می‌گوید: resolve روی ترد جدا.

اعداد DoH در سورس (نه اجرا): تلاش‌ها + timeout در `doh.rs`؛ تست resilience
ادعا می‌کند بودجهٔ بدترین حالت زیر ۲۱ ثانیه است (بریف 4.3 می‌گفت ~۱۶ ثانیه —
عدد را از سورس بخوانید، حدس نزنید).

---

## ۸) چیزهایی که عمداً ناقص‌اند (باگ نیستند)

- `stealth::validate_dnssec` فقط حضور RRSIG (type 46) را چک می‌کند
- `MemoryCertCache` خالی = اجازهٔ همهٔ SNIها (`has_valid_cert_for`:
  `valid.is_empty() || contains`)
- REALITY / Hysteria / TUIC از مسیر این رله کار نمی‌کنند (مستند در START_HERE)
- توکن خودکار داشبورد در لاگ چاپ می‌شود (`log::warn!("web UI token (auto-generated): {t}")`)
- `webui::serve_loop` تک‌تردی است → DoS محلی کم‌خطر
- `handle_conn` کل درخواست HTTP را با یک `read()` می‌خواند؛
  `Transfer-Encoding: chunked` پشتیبانی نمی‌شود (fail-closed روی body ناقص)

---

## ۹) اینورینت‌هایی که نباید شکسته شوند

تأییدشده در سورس:

- `#![deny(unsafe_code)]` crate-wide در `lib.rs`؛ فقط `engine.rs` و `singleton.rs` opt-in
- فیلتر همیشه با `!loopback` شروع می‌شود؛ `NEVER_INTERCEPT_PORTS = [22, 53, 3389]`
- رله فقط روی `127.0.0.1` bind می‌شود، peer غیر-loopback دور ریخته می‌شود، یک مقصد ثابت
- `relay_require_inject = true` پیش‌فرض در `Settings::default`
- fail-open روی مسیر پکت: `fail_open::handle_exception_fail_open` با `catch_unwind`؛
  panic یا `Err` → پکت اصلی
- داشبورد bind `127.0.0.1`؛ همهٔ `/api/*` Bearer؛ `Host` باید دقیقاً `127.0.0.1` باشد
  (`localhost` رد می‌شود)
- ۷۷ فیلد `Settings` = ۷۷ کنترل در `src/webui/index.html` (تست UI و اسکیما پاس شد)
- `*.dll` / `*.sys` / `dpi_guard.toml` / `dpi_guard.dns_cache` نباید کامیت شوند —
  `.gitignore` در این بازبینی اضافه شد چون سند ادعا می‌کرد و فایل نبود

`panic = "unwind"` و `overflow-checks = true` در `[profile.release]`.

---

## ۱۰) مستندات کلیدی در ریپو

| فایل | محتوا |
|---|---|
| `START_HERE.md` | راهنمای شروع از صفر (فارسی) + همزیستی با v2rayN |
| `RESILIENCE.md` | قطعی اینترنت، تنظیمات، تشخیص از لاگ |
| `SECURITY_AUDIT_2026-08.md` | یافته‌های F1–F10 روی درخت 4.3؛ F2 اینجا دوباره باز بود |
| `README.md` | معماری، ماژول‌ها، داشبورد، تست‌ها |
| `SECURITY_CHECKLIST.md` | کنترل‌های با منبع |
| `ci/github-actions.yml` | دو job: تست Rust (۳ OS) + تست UI (jsdom) — هنوز زیر `.github/workflows/` نیست |
| `HANDOFF.md` | همین سند |

---

## ۱۱) معماری (عمیق / کم‌عمق) — فقط مشاهده

ماژول‌های نسبتاً **عمیق**: `relay` (یک مقصد ثابت + InjectGate پشت چند invariant)،
`netguard`، `fail_open`، `doh` (بدون fallback plaintext).

ماژول‌های **کم‌عمق / اصطکاک**:

- `trusted_dns` فیلد UI است بدون مصرف‌کننده — interface بدون رفتار.
- `DIVERT: AtomicPtr` seam ناامن بین capture / watchdog / hot-reload؛ تست‌پذیر نیست.
- `dns_guard` فقط spec برمی‌گرداند؛ callers باید خودشان FFI بنویسند که وجود ندارد.

اولویت deepening اگر قرار باشد کدی نوشته شود: **مالکیت هندل WinDivert** (F1)،
نه سوئیت فایروال و نه WFP کامل.

---

## ۱۲) مهارت‌های نصب‌شده در `.agents/skills/` (۴۷)

برای کار بعدی روی این crate بیشترین leverage:

- Rust: `rust-best-practices`, `unsafe-checker`, `rust-router`, `rust-learner`
- مهندسی: `diagnosing-bugs`, `tdd`, `codebase-design`, `improve-codebase-architecture`
- شبکهٔ مرتبط با این محصول (نه سوئیچ campus): `incident-response-network`,
  `network-log-analysis`, `zero-trust-assessment`, `vulnerability-assessment`

بقیهٔ netsec-skills-suite (Palo Alto / FortiGate / BGP / OSPF / …) برای audit
این crate تقریباً بی‌ربط‌اند.
