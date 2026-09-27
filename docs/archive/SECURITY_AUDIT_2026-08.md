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

# SECURITY_AUDIT_2026-08.md — بازبینی امنیتی و بازنویسی داشبورد

تاریخ: 2026-08-25
کامیت پایه: `dcb4dbf27a6a0495818edc1c444635336c6659a9`
شاخه: `arena/01a03a02-sni-spoof-new-4-3`

> **محدودیت مهم و صادقانه:** در این محیط sandbox نه Rust toolchain نصب است و نه
> `crates.io` / `static.rust-lang.org` در دسترس‌اند (تأییدشده با `curl`: هر دو
> `SSL_ERROR_SYSCALL`، درحالی‌که `github.com` پاسخ `200` می‌دهد). بنابراین
> **`cargo test` / `cargo clippy` / `cargo build` اجرا نشده‌اند.**
> هر چیزی که واقعاً اجرا شده، در بخش «آنچه واقعاً اجرا شد» آمده است.
> تغییرات Rust کامپایل‌نشده‌اند و باید روی یک ماشین دارای Rust تأیید شوند.

---

## ۱) آنچه واقعاً اجرا شد

| اجرا | دستور | نتیجه |
|---|---|---|
| تست‌های مرورگری داشبورد (jsdom روی `src/webui/index.html` واقعی) | `node uitest/test-ui.mjs` | **۱۰۳ پاس، ۰ شکست** |
| بررسی پوشش اسکیمای UI در برابر `Settings` | `node uitest/check-rust-tests.mjs` | **۴۱ پاس، ۰ شکست** |
| همزیستی با v2rayN (داشبورد واقعی + تطابق مستندات + invariantهای منبع) | `node uitest/test-v2rayn.mjs` | **۶۶ پاس، ۰ شکست** |
| سلامت سرور mock (401 بدون توکن، 200 با توکن، رد/پذیرش `/api/validate`) | `curl` | تأیید شد |
| `git check-ignore` روی مسیرهایی که مستندات ادعا می‌کنند ignore هستند | `git check-ignore -v` | **NOT IGNORED** (یافته F2) |

آنچه اجرا **نشده**: `cargo test`، `cargo clippy`، `cargo fmt --check`، بیلد ویندوز.

---

## ۲) یافته‌ها

### F1 — بالا · حافظه · use-after-free در مسابقهٔ `DIVERT` (فقط ویندوز)

`src/engine.rs` هندل WinDivert را به‌صورت یک `AtomicPtr<Divert>` خام نگه می‌دارد:

- `store_handle()` (خط ~۱۵۴) هندل قدیمی را با `DIVERT.swap` بیرون می‌کشد و با
  `Box::from_raw(old)` **آزاد می‌کند**.
- `drop_stored_handle()` (خط ~۱۶۷) همین کار را در خروج capture loop می‌کند.
- در همان حال، `request_shutdown()` (خط ~۱۷۹) و `reinject_held_packets()` (خط ~۱۱۵)
  روی **تردهای دیگر** `DIVERT.load()` کرده و سپس `(*ptr).shutdown(...)` /
  `(*ptr).send(...)` را صدا می‌زنند — بدون هیچ قفل یا epoch/guard.

اگر ترِد capture بین `load()` و dereference در ترِد دیگر، هندل را swap و آزاد کند،
آن dereference یک **use-after-free** است. این مسیر بدون مهاجم هم قابل رسیدن است:
کافی است اپراتور `intercept_ports` را در `dpi_guard.toml` تغییر دهد
(`request_filter_reload` → `request_shutdown`) هم‌زمان با اینکه watchdog هر ۲۰۰ms
پکت‌های held را flush می‌کند.

**چرا اصلاح نکردم:** این کد `unsafe` و `cfg(windows)` است و در این sandbox نه
کامپایل می‌شود نه اجرا. امضای دقیق `Divert::close` (مالکیت `self` یا `&mut self`)
برای من تأییدشده نیست، و حدس‌زدن روی FFI بدتر از مستندکردن است.

**پچ پیشنهادی** (یکی از این دو):
1. در `store_handle` هندل قدیمی را آزاد نکنید — فقط `shutdown`/`close` کنید و
   `Box` را در یک `static RETIRED: Mutex<Vec<Divert>>` پارک کنید (نشتی کران‌دار:
   فقط به تعداد reload فیلتر). این `Box::from_raw` مخرب را حذف می‌کند.
2. یا کل دسترسی به `DIVERT` را زیر یک `RwLock<Option<Arc<Divert>>>` ببرید و
   `request_shutdown`/`reinject_held_packets` را مجبور کنید guard بگیرند.

یک تست رگرسیون هم لازم است: reload فیلتر هم‌زمان با flush پکت held.

---

### F2 — بالا · زنجیرهٔ تأمین · `.gitignore` وجود نداشت (رفع شد)

سه سند ادعا می‌کنند `.gitignore` باینری‌های درایور را حذف می‌کند:

- `README.md:143` — «gitignores `*.dll` / `*.sys` / `dpi_guard.toml`»
- `START_HERE.md:22` — «`.gitignore` حذفشان کرده است»
- `PROJECT_GUIDE.md:19` — «در `.gitignore`»

واقعیت (با `git check-ignore -v` تأیید شد):

```
WinDivert.dll     NOT IGNORED
WinDivert64.sys   NOT IGNORED
target/x          NOT IGNORED
dpi_guard.toml    NOT IGNORED
```

پیامد: کامیت‌شدن تصادفی `WinDivert.dll`/`WinDivert64.sys` (نقض خط‌مشیٔ خود پروژه)
و مهم‌تر، کامیت‌شدن `dpi_guard.toml` که می‌تواند `web_ui_token` و pinهای درایور
را داشته باشد (CWE-540 / CWE-538).

**رفع شد:** `.gitignore` اضافه شد. اکنون هر چهار مسیر IGNORED هستند.

---

### F3 — متوسط · تابعی/امنیتی · `Option<String>` داشبورد را می‌شکست (رفع شد)

`Settings.trusted_dns: Option<String>` بدون `skip_serializing_if` بود. سریالایزر
`toml` مقدار `None` را می‌پذیرد نه — خطای `UnsupportedNone` می‌دهد — درحالی‌که
هر دو مسیر داشبورد کل struct را از `toml::to_string` رد می‌کنند:

- `config::redacted_toml()` ← ویرایشگر پیشرفتهٔ TOML (`GET /api/config/toml`)
- `config::merge_partial()` ← دکمهٔ «ذخیره» (`POST /api/config`)

یعنی روی کانفیگ پیش‌فرض (که `trusted_dns = None` است) هر دو باید شکست می‌خوردند.

**رفع شد:** `#[serde(default, skip_serializing_if = "Option::is_none")]` اضافه شد
و تست `default_settings_round_trip_through_toml` نوشتن/خواندن رفت‌وبرگشتی را
پوشش می‌دهد. اگر `toml 0.8.19` از قبل `None` را رد می‌نکرده، این تغییر هیچ
اثری ندارد (no-op)؛ اگر رد می‌کرده، مسیر ذخیره را تعمیر می‌کند. در هر دو حالت
درست است — ولی چون کامپایل نشده، به‌عنوان تأییدنشده علامت می‌خورد.

---

### F4 — متوسط · سطح کنترل · ۲۰ تنظیم از ۴۷ در داشبورد قابل تغییر نبود (رفع شد)

اندازه‌گیری روی کد قدیمی (`git show dcb4dbf:src/webui.rs`) نشان می‌دهد
`buildPartialToml` فقط **۲۷** کلید می‌نوشت، درحالی‌که `Settings` **۴۷** فیلد دارد.
این ۲۰ مورد از UI قابل تغییر نبودند:

```
autottl_delta              doh_server                 enable_combined_fragmentation
enable_decoys              enable_kill_switch         enable_md5sig_fooling
enable_sni_fragmentation   enable_swap_foolers        enable_web_ui
idle_timeout_secs          intercept_all_tcp          intercept_all_udp
kill_switch_adapter        quic_bypass_use_low_port   rotate_ips
trusted_dns                utls_browser               web_ui_port
web_ui_token               win_divert_sha256
```

این فقط یک کمبود راحتی نیست: اپراتور مجبور بود TOML را دستی ویرایش کند، یعنی
بدون اعتبارسنجی لحظه‌ای و با خطر typo — دقیقاً همان چیزی که `deny_unknown_fields`
و `Settings::validate()` برای جلوگیری از آن هستند. ضمن اینکه
`intercept_all_tcp/udp` (خطرناک‌ترین گزینه‌ها) اصلاً در UI نبودند.

**رفع شد:** بازنویسی کامل داشبورد؛ اکنون ۴۷ از ۴۷ قابل تغییرند و سه تست
(`every_settings_field_is_editable_in_the_ui`، `ui_schema_declares_no_unknown_settings_key`،
`ui_schema_size_matches_settings`) تضمین می‌کنند افزودن فیلد جدید به `Settings`
بدون اضافه‌کردنش به UI، تست را می‌شکند.

---

### F5 — پایین · `trusted_dns` write-once بود (رفع شد)

`merge_partial` فقط کلیدهای ارائه‌شده را override می‌کند، پس هیچ راهی برای
**خالی‌کردن** `trusted_dns` از داشبورد وجود نداشت (مقدار خالی هم ذخیره‌شدنی نیست
چون `validate` آن را IP نامعتبر می‌داند).

**رفع شد:** در `merge_partial`، رشتهٔ خالی برای `trusted_dns` یعنی کلید حذف شود
(→ `None`). تست: `trusted_dns_can_be_set_and_cleared_from_the_ui`.

---

### F6 — پایین · DoS محلی · `serve_loop` تک‌تردی است (تغییر نکرد)

`webui::serve_loop` اتصال‌ها را یکی‌یکی هندل می‌کند و `unauthorized()` یک
`sleep(80ms)` دارد؛ `handle_conn` هم read timeout سه‌ثانیه‌ای ست می‌کند. یک
فرآیند محلی می‌تواند با درخواست‌های بی‌توکن یا اتصال‌های نیمه‌باز، داشبورد را
برای چند ثانیه متوقف کند. چون سرویس فقط روی `127.0.0.1` است و مهاجم باید از قبل
دسترسی محلی داشته باشد، شدت پایین است. تغییر مدل threading اینجا out-of-scope و
غیرقابل تست بود؛ فقط مستند می‌شود.

---

### F7 — پایین · robustness · خواندن تک‌`read()` برای کل درخواست (تغییر نکرد)

`handle_conn` یک بار `read()` می‌کند (حداکثر ۱۶ KiB). اگر header+body یک POST در
بیش از یک سگمنت TCP برسد، body ناقص می‌شود و `merge_partial` با خطای پارس رد
می‌کند — یعنی **fail-closed**، نه تغییر بی‌صدا. همچنین
`Transfer-Encoding: chunked` پشتیبانی نمی‌شود. روی loopback بعید است؛ مستند شد.

---

### F8 — اطلاع‌رسانی · توکن خودکار در لاگ چاپ می‌شود (تغییر نکرد)

`main.rs`: `log::warn!("web UI token (auto-generated): {t}")`. این تنها راه
فهمیدن توکن است، پس حذفش UI را غیرقابل استفاده می‌کند (و `SECURITY_CHECKLIST.md`
کنترل ۶۱ همین استثنا را ثبت کرده). ریسک باقی‌مانده: اگر `RUST_LOG` به فایل یا
Event Viewer برود، توکن آنجا می‌ماند (CWE-532).
**توصیه:** در داشبورد یک راهنما اضافه شد؛ بهتر است اپراتور
`web_ui_token` را صریحاً در کانفیگ ست کند تا توکن خودکار هیچ‌وقت چاپ نشود.

---

### F9 — متوسط · حافظه · جدول `relay_flows` سقف نداشت (رفع شد)

`Pipeline::register_relay_flow` برای **هر اتصال کلاینت** یک ورودی در
`relay_flows` درج می‌کرد و هیچ سقفی نداشت — درحالی‌که `flows` سقف
`MAX_FLOWS = 256` دارد. ورودی‌ها فقط با prune بر اساس
`idle_timeout_secs` (پیش‌فرض ۱۲۰ ثانیه) خارج می‌شدند، حتی وقتی هندشیک
تمام شده بود (`done = true`).

v2rayN پشت یک مرورگر صدها اتصال کوتاه می‌سازد، پس این رشد مستقیماً از
رفتار عادی کلاینت ناشی می‌شود (CWE-770). ضمناً کنترل ۴۴ در
`SECURITY_CHECKLIST.md` («Cap concurrent flow table at 256 flows») فقط
`flows` را پوشش می‌داد و دربارهٔ `relay_flows` اغراق می‌کرد.

**رفع شد:** سقف `MAX_RELAY_FLOWS = 256` اضافه شد. تخلیه اول جریان‌های
`done` را برمی‌دارد (که دیگر به monitor نیاز ندارند) و فقط اگر جدول هنوز پر
بود قدیمی‌ترین جریان **زنده** را با `log::warn!` حذف می‌کند — چون حذف یک
جریان زنده یعنی تزریق SNI جعلی‌اش دیگر تأییدشدنی نیست و با fail-closed آن
اتصال قطع می‌شود. درج مجدد همان 4-tuple هم جایگزین می‌کند نه رشد.

تست‌ها: `relay_flow_table_is_capped_under_many_connections`،
`relay_flow_cap_evicts_finished_flows_before_live_ones`،
`relay_flow_reregistration_does_not_grow_or_evict`،
`relay_flows_are_pruned_when_idle`.

> مثل بقیهٔ تغییرات Rust، این هم **کامپایل نشده** — ولی با چک‌کنندهٔ
> توازن براست (که روی نسخهٔ دست‌نخوردهٔ `pipeline.rs` کالیبره شده) تأیید
> شد که ساختار فایل سالم است.

---

### F10 — پایین · قابلیت تشخیص · برخورد پورت با v2rayN بی‌صدا بود (رفع شد)

`Settings::validate` فقط `relay_listen_port == web_ui_port` را رد می‌کرد.
اگر اپراتور رله را روی `10808`/`10809`/`10853` می‌گذاشت، یکی از دو برنامه
bind نمی‌کرد و خطا شبیه باگ dpi_guard به نظر می‌رسید.

**رفع شد:** ثابت `KNOWN_V2RAY_LOCAL_PORTS` اضافه شد و `validate` در این
حالت `log::warn!` می‌دهد (رد نمی‌کند، چون ممکن است v2rayN عمداً بسته شده
باشد). تست: `coexists_with_v2rayn_default_local_ports`.

---

## ۳) مواردی که بررسی شدند و **سالم** بودند

این‌ها تأیید شدند، نه فرض:

- `#![deny(unsafe_code)]` crate-wide؛ تنها `engine.rs` و `singleton.rs` opt-in
  کرده‌اند (با `grep -rn unsafe` تأیید شد)؛ هیچ `get_unchecked` / `transmute` /
  `from_raw_parts` در کل `src/` نیست.
- `panic!` / `unreachable!` فقط داخل `#[cfg(test)]` هستند؛ مسیر پکت از
  `fail_open::handle_exception_fail_open` با `catch_unwind` رد می‌شود و در صورت
  panic یا `Err` پکت اصلی را re-inject می‌کند.
- `overflow-checks = true` و `panic = "unwind"` در `[profile.release]`.
- `netguard`: loopback / unspecified / broadcast / multicast / link-local /
  `169.254.169.254` رد می‌شوند؛ IPv4-mapped IPv6 با `to_ipv4_mapped` باز می‌شود
  تا `::ffff:127.0.0.1` رد شود؛ `*.local`، `*.internal`، `localhost`،
  `metadata.google.internal` رد می‌شوند؛ DoH باید `https://` و بدون userinfo باشد.
- `doh.rs`: بدون fallback به DNS متنی (plaintext)، سقف ۶۴ KiB روی بدنه، سقف ۳۲ hop روی
  compression pointer، رد pointer رو‌به‌جلو/خودارجاع، سقف ۶۳ بایت label و
  ۲۵۳ بایت name.
- `packet.rs` / `fragmentation.rs`: هر slice با بررسی طول محافظت شده
  (`buf.len() < ...`، `saturating_add/sub`، `.min(len)`)؛ `ihl < 20` و
  `doff < 20` رد می‌شوند.
- `stealth::sanitize_adapter_name` فقط `[A-Za-z0-9 _-]+` را می‌پذیرد و
  `kill_switch_command` هرگز spawn نمی‌شود (فقط رشته می‌سازد).
- `integrity::constant_time_eq` طول را هم در انباشتر مخلوط می‌کند؛
  `hash_is_pinned` روی match زود return نمی‌کند.
- `webui`: bind فقط `127.0.0.1`، همهٔ `/api/*` نیاز به Bearer دارند، مقایسهٔ
  constant-time، تأخیر ۸۰ms قبل از 401، `Host` باید `127.0.0.1` باشد (دفاع
  DNS-rebind)، `Origin` بررسی می‌شود، CSP سخت‌گیرانه، توکن و pinها در
  `/api/config` قرمزپوشانی‌اند و `merge_partial` با مقدار خالی آن‌ها را پاک نمی‌کند.
- `relay.rs`: bind فقط `127.0.0.1`، peer غیر-loopback دور ریخته می‌شود، یک مقصد
  ثابت (پروکسی باز نمی‌شود)، fail-closed: اگر تزریق تأیید نشود اتصال بدون
  کپی‌شدن حتی یک بایت از ClientHello واقعی بسته می‌شود.
- **همزیستی با v2rayN** (با `node uitest/test-v2rayn.mjs` بررسی شد):
  قفل تک‌نمونه `dpi_guard.instance.lock` است و فقط با یک نمونهٔ دیگر یا
  patterniha تداخل دارد؛ پورت پیش‌فرض رله (۴۰۴۴۳) و داشبورد (۹۰۹۰) روی
  هیچ‌کدام از پورت‌های محلی v2rayN نیستند؛ فیلتر با `!loopback` شروع
  می‌شود پس اتصال v2rayN→رله هرگز divert نمی‌شود؛ UDP غیر-QUIC بدون تغییر
  رد می‌شود؛ و `HOLD_TIMEOUT` (۲۰۰ms) بسیار کمتر از `FAKE_ACK_WAIT` (۳s)
  است. `handle_conn` سوکت خروجی را **قبل از connect** به `local_ip:0`
  bind می‌کند، پس 4-tuple‌ای که ثبت می‌شود با آنچه روی سیم دیده می‌شود
  یکی است (این را بررسی کردم چون اگر این‌طور نبود، با `relay_require_inject`
  هر اتصال پس از ۳ ثانیه قطع می‌شد).

---

## ۴) بازنویسی داشبورد — چه چیزی تغییر کرد

`src/webui.rs` دیگر HTML را به‌صورت رشتهٔ خام در خود فایل نگه نمی‌دارد؛ صفحه به
`src/webui/index.html` منتقل شد و با `include_str!` embed می‌شود. نتیجه: صفحه یک
فایل HTML واقعی است که مستقیماً در مرورگر/jsdom قابل اجرا و تست است، درحالی‌که
باینری همچنان **هیچ asset خارجی** ندارد (CSP `default-src 'none'` دست‌نخورده).

- **۴۷ از ۴۷ فیلد `Settings` قابل تغییر** — اسکیمامحور، در ۸ بخش فارسی/RTL.
- **اعتبارسنجی لحظه‌ای سمت کلاینت** که `Settings::validate()` را آینه می‌کند
  (۲۶ قاعده در تست پوشش داده شده) + قواعد چندفیلدی.
- **جداسازی خطا از هشدار**: خطاها Save را می‌بندند، هشدارها هرگز. (در نسخهٔ اول
  من این تفکیک نبود و حالت پیش‌فرض `intercept_all_tcp && intercept_all_udp` باعث
  می‌شد دکمهٔ Save برای همیشه غیرفعال بماند — تست آن را گرفت.)
- **`POST /api/validate`** جدید: همان `merge_partial` + `validate` بدون نوشتن روی
  دیسک، تا دلیل ردشدن سمت سرور قبل از ذخیره دیده شود.
- **ذخیرهٔ جزئی**: فقط کلیدهایی که واقعاً تغییر کرده‌اند ارسال می‌شوند.
- **تأییدیه برای گزینه‌های پرخطر**: `intercept_all_tcp`، `intercept_all_udp`،
  `enable_swap_foolers`، و خاموش‌کردن `relay_require_inject` (fail-closed).
- جست‌وجو، فیلتر «فقط تغییرکرده‌ها»، بازگردانی، ورود/خروجی JSON، ویرایشگر TOML
  پیشرفته، و وضعیت زندهٔ قابل توقف.
- فیلدهای secret (`web_ui_token`, `win_divert_sha256`) write-only می‌مانند:
  خالی‌گذاشتنشان یعنی «دست نزن»، پس Save هرگز توکن/pin را پاک نمی‌کند.

---

## ۵) قبل از استقرار روی ویندوز

1. `cargo fmt --all -- --check && cargo clippy --all-targets -- -D warnings && cargo test`
   را روی یک ماشین دارای Rust اجرا کنید. **اینجا اجرا نشدند.**
2. `cd uitest && npm install && npm test` — این‌ها اینجا پاس شدند، ولی دوباره
   اجرا کردنشان ضرری ندارد.
3. F1 (مسابقهٔ `DIVERT`) را قبل از استفاده از hot-reload فیلتر برطرف کنید.
4. تست‌های Rust جدید: `ui_schema_tests::*` در `src/webui.rs` و
   `default_settings_round_trip_through_toml` /
   `trusted_dns_can_be_set_and_cleared_from_the_ui` /
   `merge_partial_preserves_every_untouched_field` در `src/config.rs`.
