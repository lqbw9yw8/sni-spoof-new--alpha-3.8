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

# چک‌لیست کمبودها — وضعیت بعد از هماهنگی 4.4

موارد زیر **در همین شاخه اصلاح شدند**:

- `HandshakeMonitor::fail()` اضافه شد (کامپایل pipeline).
- `intercept_all_tcp/udp`: serde default با `Settings::default()` یکی شد (`true`).
- `sni_only`/`sni_except` روی **SNI واقعی** ClientHello اعمال می‌شود، نه روی fake_sni.
- جهش هویت‌شکن با کش گواهی خالی **اعمال نمی‌شود**.
- توکن داشبورد با `eprintln` چاپ می‌شود، نه `log::warn` (کمتر داخل فایل لاگ).
- نام فیلدهای `/api/status` با `Settings` یکی شد (`enable_quic_port_bypass`, `fronting_benign_sni`, `enable_utls_fingerprint`).
- `trusted_dns` و `rotate_ips` اگر ست شوند warn می‌دهند که روی سیم اثری ندارند.
- `START_HERE.md` پورت را سخت `40443` قفل نمی‌کند.

## هنوز باز (عمدی یا نیاز به ویندوز)

| # | چرا باز ماند |
|---|---|
| WinDivert `AtomicPtr` | shutdown باید همزمان با `recv` باشد؛ پارک `RETIRED` UAF را کم کرد. بازنویسی کامل نیاز به تست ویندوز دارد. |
| پین درایور اختیاری | بدون هش، اولین اجرا غیرممکن می‌شود. warn می‌ماند. |
| WFP DNS | بدون درایور امضاشده در user-mode کامل نمی‌شود. |
| Kill switch spawn | عمداً اجرا نمی‌شود. |
| `cargo test` | rustc در این sandbox نیست — **روی ویندوز حتماً اجرا کنید**. |
| DoH روی ترد watchdog | ~~resolve همگام است~~ — رفع شد: `kick_resolution` در `main.rs` رزولوشن را روی یک ترد جدا می‌برد؛ watchdog دیگر روی DoH بلاک نمی‌شود (رجوع کنید به STATUS.md §4). |

اولین کار شما: `cargo test` و `cargo clippy --all-targets -- -D warnings` روی ویندوز.
