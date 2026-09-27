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

# PROJECT_GUIDE.md — هندآف فنی

این سند نمای فنی کرایت `dpi_guard` را برای نگهدارنده‌ی بعدی جمع می‌کند. جزئیات
پیاده‌سازی و وضعیت ماژول‌ها در فایل‌های از پیش‌موجود زیر هم باقی مانده‌اند و
دست‌نخورده‌اند:

- `IMPLEMENTATION_STATUS.md`
- `REVIEW_2026_STRICT.md`
- `SECURITY_REVIEW_FIXES.md`

این فایل صرفاً نکات مربوط به دور hardening را اضافه می‌کند.

## اصول و غیرقابل‌ها

- کرایت یک رله محلی SNI-spoof به سبک patterniha است.
- **هسته Xray/v2ray/sing-box ندارد** و VPN نیست.
- IP مقصد روی سیم پنهان نمی‌شود؛ پنهان‌سازی با REALITY/VPN در اسکوپ نیست.
- `exploid`/`malware` ننویس.
- باینری‌های `WinDivert.dll` و `WinDivert64.sys` را کامیت نکن (در `.gitignore`).
- فایل‌های `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `LICENSE` و
  اسناد بررسی بالا بدون نیاز تغییر نکن.

## ساختار ماژول‌ها

| فایل | نقش |
|---|---|
| `src/lib.rs` | ماژول‌ها، `build_filter`، `deny(unsafe_code)` |
| `src/config.rs` | `Settings` با `deny_unknown_fields`، اعتبارسنجی، merge_partial |
| `src/pipeline.rs` | پردازش پکت، مسیر رله، تزریق fake، reassembly |
| `src/relay.rs` | رله TCP، `InjectGate`، `HandshakeMonitor` |
| `src/engine.rs` | capture/inject ویندایورت (ویندوز، `allow(unsafe_code)`) |
| `src/engine_stub.rs` | استاب غیرویندوز با همان امضا |
| `src/doh.rs` | DoH با سقف و بدون fallback |
| `src/netguard.rs` | ضدSSRF: مقاصد/hostnames ممنوع |
| `src/singleton.rs` | قفل تک‌نمونه‌ای (ویندوز/یونیکس) |
| `src/autottl.rs` | یادگیری TTL |
| `src/http_host.rs` | ترفند Host و فیلتر SNI |
| `src/fragmentation.rs` | parse/splice و `fragment_as_tls_records` |
| `src/stealth.rs` | `redact_endpoint`, hash |
| `src/strategy.rs` | امتیازدهی و `DesyncMode` |
| `src/webui.rs` | داشبورد loopback با توکن |

## unsafe

`#![deny(unsafe_code)]` در سطح کرایت. فقط دو فایل می‌توانند opt-in کنند:

- `src/engine.rs` — FFI ویندایورت.
- `src/singleton.rs` — `flock` و `CreateFileW`.

هر جای دیگری که unsafe لازم باشد باید یکی از این دو باشد یا در قالب ماژول
جدا با توجيه مستند اضافه شود.

## ترتیب استارت (در `main.rs` ویندوز)

1. `singleton::acquire()` — قفل کنار exe.
2. بارگذاری و اعتبارسنجی کانفیگ.
3. `engine::version_check` برای درایور کنار exe.
4. اسپاون ترد capture با `engine::capture_loop`.
5. `engine::wait_until_capture_ready(Duration::from_secs(3))` — اگر آماده
   نشد، رله استارت نمی‌شود.
6. رله با `relay::run(...)` و `register_relay_flow`.
7. داشبورد در صورت فعال بودن.
8. watchdog + hot-reload.

## فیلتر

`build_filter` پیش‌فرض همه پورت‌ها جز 22/53/3389 را می‌گیرد. اگر
`relay_enabled` باشد پورت رله هم تضمین می‌شود. `DEFAULT_FILTER` ثابت کرایت
با همین منطق به‌روز شده است.

## fail-closed رله

- `RelayTarget.require_inject` پیش‌فرض `true`.
- پاپلاین با `InjectGate` موفقیت/شکست را به رله اعلام می‌کند.
- اگر تا ۳ ثانیه `was_ok` نشد، رله کلاینت و سرور را قبل از کپی بایت واقعی
  می‌بندد.

## محدودیت‌های شناخته‌شده (صادقانه)

- بلاک DNS در WFP استاب است.
- ECH فقط GREASE.
- تزریق روی ویندوز واقعی در این سندباکس تست نشد.
- `cargo test` در سندباکسی که کد نوشته شد اجرا نشد.
- آی‌پی مقصد پنهان نمی‌شود.

## CI

به‌جای کامیت در `.github/workflows/` (که توکن گیتهاب ممکن است پوش نکند)،
فایل workflow در `ci/github-actions.yml` نگه‌داری شده. `ci/README.md` می‌گوید
اپراتور آن را کپی کند به `.github/workflows/ci.yml`.
