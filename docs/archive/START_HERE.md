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

# START HERE — راهنمای شروع از صفر (فارسی)

این کرایت (`dpi_guard`) یک رله محلی از نوع **patterniha / SNI-Spoofing** است.
هسته Xray/v2ray/sing-box ندارد و VPN نیست. **IP مقصد روی سیم دیده می‌شود** و
قرار نیست با ساخت VPN یا REALITY پنهان شود. هدف فقط فریب DPI با تزریق یک
ClientHello جعلی با SNI خوش‌خیم است.

این راهنما از صفر است و هیچ هسته/پروکسی خارجی لازم ندارد.

---

## ۱) پیش‌نیازها

- ویندوز ۱۰/۱۱ ۶۴ بیتی
- دسترسی **Administrator**
- درایور رسمی **WinDivert** (فقط فایل‌های رسمی از reqrypt.org):
  - `WinDivert.dll`
  - `WinDivert64.sys`

این دو فایل را **کنار خود `dpi_guard.exe`** بگذارید، نه کنار فایل کانفیگ و نه
در `cwd`. این برنامه عمداً فقط پوشه‌ی کنار exe را جست‌وجو می‌کند (جلوگیری از
DLL planting). **این دو فایل را در گیت کامیت نکنید** — `.gitignore` حذفشان
کرده است.

دریافت نسخه رسمی:
- https://reqrypt.org/windivert.html
- https://github.com/basil00/Divert/releases

اختیاری ولی توصیه‌شده: هش SHA-256 فایل‌های رسمی را با
`certutil -hashfile WinDivert.dll SHA256` و
`certutil -hashfile WinDivert64.sys SHA256` بگیرید و در `win_divert_sha256`
در کانفیگ بگذارید تا فقط درایور تأییدشده لود شود.

> این پروژه خودش این دو باینری را توزیع نمی‌کند و نباید کامیت شوند.

---

## ۲) ساخت

ساده‌ترین راه — همین یک دستور:

```powershell
cd C:\dpi_guard
.\build-windows.bat
```

خودش target را اضافه می‌کند، اگر `WinDivert.lib` کنار `Cargo.toml` نبود نسخهٔ
پین‌شدهٔ رسمی ۲.۲.۲ را با `scripts\fetch-windivert.ps1` (SHA-256 verify)
می‌گیرد، `WINDIVERT_PATH` را ست می‌کند و build می‌گیرد.

خروجی: `target\x86_64-pc-windows-msvc\release\dpi_guard.exe`.

### اگر می‌خواهی دستی `cargo` بزنی

`windivert-sys` دقیقاً دو شاخه دارد (`windivert-sys-0.9.3/build/main.rs`):

```rust
if let Ok(p) = env::var("WINDIVERT_PATH") {
    for f in fs::read_dir(&p).unwrap() {   // ← خط ۲۲
        ... کپی WinDivert.dll / .lib / WinDivert32.sys / WinDivert64.sys ...
    }
} else if cfg!(feature = "vendored") {
    build_windivert();                     // vendor\dll\windivert.c با cc + MSVC
}
```

دو نکته که همهٔ دردسر از این‌جاست:

1. **هر** مقدارِ `WINDIVERT_PATH` شاخهٔ اول را انتخاب می‌کند — حتی رشتهٔ خالی.
   اگر آن پوشه وجود نداشته باشد، `read_dir` با `Os { code: 3, kind: NotFound }`
   panic می‌کند. یعنی یک `WINDIVERT_PATH` جامانده در محیط ویندوز (از یک تلاش
   قبلی، یک آموزش، یا یک پروژهٔ دیگر) build را می‌کُشد و از بیرون نمی‌شود
   پاکش کرد.
2. آن پوشه باید **واقعاً** هر سه فایل را داشته باشد، وگرنه چیزی کپی نمی‌شود
   و در مرحلهٔ link با `LNK1104: cannot open file 'WinDivert.lib'` می‌میرد.

برای همین `.cargo\config.toml` این ریپو این خط را دارد:

```toml
[env]
WINDIVERT_PATH = { value = ".", force = true, relative = true }
```

- `force = true` → کارگو هر مقدارِ از قبل موجود در محیط را **بازنویسی** می‌کند
  (`cargo/src/context/mod.rs:2001`: `if v.is_force() || env.is_none()`). پس یک
  متغیر خراب دیگر هرگز به build script نمی‌رسد.
- `relative = true` → مقدار نسبت به پوشه‌ای که `.cargo` در آن است resolve می‌شود
  (`Definition::Path(p).root() == p.parent().parent()`)، یعنی **ریشهٔ همین ریپو**،
  دقیقاً همان‌جا که `scripts\fetch-windivert.ps1` فایل‌ها را می‌گذارد.
- نتیجه یک مسیر **مطلق** است و این مهم است: build script هر crate با cwd =
  ریشهٔ همان crate اجرا می‌شود (`cargo/src/compiler/compilation.rs:465`:
  `cmd.cwd(pkg.root())`)، پس یک `.` خام به پوشهٔ `windivert-sys` در
  `.cargo\registry` اشاره می‌کرد، نه به ریپو.

پس workflow این است:

```powershell
.\scripts\fetch-windivert.ps1 -Arch x64    # یک بار: سه فایل رسمی ۲.۲.۲ را می‌گیرد
cargo build --release --target x86_64-pc-windows-msvc
```

یا همان `build-windows.bat` که هر دو را پشت‌سرهم انجام می‌دهد.

تا وقتی آن سه فایل در ریشهٔ ریپو نباشند، build در مرحلهٔ link با
`cannot open file 'WinDivert.lib'` می‌ایستد — خطایی که می‌گوید چه چیزی کم است،
به‌جای panic داخل یک وابستگی.

> **یک اشتباه من که اینجا اصلاح شد.** نسخهٔ قبلی این سند می‌گفت
> `WINDIVERT_PATH="."` در یک `.cargo/config.toml` میانی علت همان panic بوده.
> غلط بود: چون cwd برابر ریشهٔ خودِ `windivert-sys` است، `read_dir(".")` موفق
> می‌شد و panic رخ نمی‌داد. علت واقعی یک `WINDIVERT_PATH` ست‌شده در محیط
> ویندوز است که به پوشه‌ای اشاره می‌کند که وجود ندارد — و `force = true`
> دقیقاً برای خنثی‌کردن همان اضافه شده.

---

## ۳) کانفیگ

فایل نمونه کنار همین سند هست: `dpi_guard.toml.example`. آن را به
`dpi_guard.toml` کنار exe کپی کنید و حداقل این‌ها را تنظیم کنید:

> **مهم:** همهٔ کلیدها در سطح ریشهٔ فایل هستند. هیچ هدر بخشی مثل `[relay]`
> ننویس — `Settings` با `deny_unknown_fields` تعریف شده و یک جدول ناشناخته
> باعث می‌شود برنامه موقع بارگذاری کانفیگ `exit 1` کند.

```toml
relay_enabled       = true
relay_listen_port   = 40443          # پورت دلخواه؛ همین عدد را در v2rayN هم بگذار
relay_connect_host  = "server.example.com"  # دامنه کافی است؛ DoH خودش IP را پیدا می‌کند
relay_connect_port  = 443
relay_fake_sni      = "www.microsoft.com"
relay_require_inject = true          # fail-closed؛ دست نزنید

doh_server          = "https://1.1.1.1/dns-query"
```

- **`relay_connect_host` دامنه یا IP.** دامنه مثل patterniha است: برنامه با
  DoH (نه UDP/53) IP را پیدا می‌کند. IP دستی لازم نیست. اگر IP بگذاری، DNS
  برای این مقصد کلاً زده نمی‌شود.
- آدرس‌های لوپ‌بک، لینک‌لوکال، مالتی‌کست و `169.254.169.254` به‌عنوان مقصد
  رد می‌شوند (ضد SSRF). آدرس‌های RFC1918 مثل `10.x` مجازند.
- `doh_server` پیش‌فرض `https://1.1.1.1/dns-query` است. هیچ fallback به
  DNS متن‌باز UDP/53 وجود ندارد. فقط AAAA کوئری نمی‌شود.

### فیلتر پیش‌فرض: همه پورت‌ها

پیش‌فرض جدید **همه پورت‌های TCP و UDP** را در هر دو جهت می‌گیرد، به‌جز
SSH (22)، DNS (53) و RDP (3389). اگر خواستید فقط پورت‌های خاصی را بگیرید:

```toml
intercept_all_tcp = false
intercept_all_udp = false
intercept_ports   = [443, 8443, 2053, 2083, 8080]
```

---

## ۴) اجرا

یک پنجره PowerShell یا CMD **به‌صورت Administrator** باز کنید و:

```powershell
.\dpi_guard.exe
```

به ترتیب اتفاق می‌افتد:
1. قفل تک‌نمونه‌ای (`dpi_guard.instance.lock` کنار exe) گرفته می‌شود.
   اگر هم‌زمان نسخه دیگری یا اسکریپت پایتون **patterniha** در حال اجرا باشد،
   برنامه با خطای روشن خارج می‌شود.
2. اعتبارسنجی کانفیگ و درایور.
3. **اول** ترد capture ویندایورت استارت می‌شود و برنامه تا ۳ ثانیه صبر
   می‌کند capture آماده شود؛ **بعد** رله استارت می‌شود.
4. رله فقط روی `127.0.0.1:<relay_listen_port>` گوش می‌دهد (هرگز 0.0.0.0).

اگر capture ظرف ۳ ثانیه آماده نشود، رله استارت نمی‌شود (fail-closed).

---

## ۵) تنظیم کلاینت TLS محلی

کلاینت محلی (مثلاً v2rayN یا هر کلاینت TLS) را این‌طور تنظیم کنید:

- **آدرس سرور: `127.0.0.1`**
- **پورت: همان `relay_listen_port`** (مثال پیش‌فرض `40443`)
- **SNI / ServerName: دامنه واقعی سرور** (نه fake_sni)

یعنی کلاینت با دامنه واقعی TLS handshake می‌کند به `127.0.0.1:<relay_listen_port>` و
`dpi_guard` خودش قبل از ClientHello واقعی، یک ClientHello جعلی با SNI
`www.microsoft.com` تزریق می‌کند.

> این برنامه با REALITY، Hysteria و TUIC کار نمی‌کند — آن‌ها از مسیر این
> رله رد نشوند.

### همزیستی با v2rayN (تداخل ندارند)

زنجیرهٔ intended این است:

```
مرورگر/برنامه  →  v2rayN (SOCKS 10808 / HTTP 10809)
                      →  رلهٔ dpi_guard روی 127.0.0.1:<relay_listen_port>   (loopback: رهگیری نمی‌شود)
                           →  سرور واقعی <ip>:443             (رهگیری می‌شود: SNI جعلی تزریق می‌شود)
```

چرا تداخل ندارند:

| مورد | وضعیت |
|---|---|
| قفل تک‌نمونه | `dpi_guard.instance.lock` کنار exe. فقط با یک `dpi_guard` دیگر یا **patterniha** تداخل دارد، هرگز با v2rayN |
| پورت‌ها | رله = `relay_listen_port` (پیشنهاد `40443`)، داشبورد `9090` — با `10808`/`10809`/`10853` یکی نکنید |
| اتصال v2rayN → رله | loopback است و فیلتر WinDivert با `!loopback` شروع می‌شود، پس هرگز divert نمی‌شود |
| اتصال رله → سرور | تنها مسیری است که divert می‌شود؛ همان‌جا SNI جعلی تزریق می‌شود |
| SSH/DNS/RDP | `22`/`53`/`3389` حتی در حالت «همهٔ پورت‌ها» هرگز رهگیری نمی‌شوند |
| UDP غیر-QUIC | بدون تغییر رد می‌شود؛ بازنویسی فقط روی QUIC Initial واقعی و فقط وقتی `enable_quic_port_bypass = true` |
| جدول جریان‌های رله | سقف `MAX_RELAY_FLOWS = 256`؛ اول جریان‌های تمام‌شده تخلیه می‌شوند، بعد قدیمی‌ترین جریان زنده (با لاگ) |

اگر `relay_listen_port` را روی `10808`/`10809`/`10853` بگذارید، برنامه
**هشدار** می‌دهد (خطا نمی‌دهد، چون ممکن است عمداً v2rayN را بسته باشید) — ولی
در آن صورت یکی از دو برنامه نمی‌تواند bind کند.

تست خودکار این همزیستی:

```bash
cd uitest && npm install && npm run test:v2rayn
```

این سوئیت سه نوع بررسی دارد و صادقانه برچسب خورده‌اند: `[RUNS SHIPPED CODE]`
صفحهٔ واقعی داشبورد را در jsdom اجرا می‌کند و TOML خروجی‌اش را با یک پارسر
واقعی می‌سنجد؛ `[STATIC SOURCE]` فقط حضور یک invariant را در متن Rust
اثبات می‌کند (نه رفتار زمان اجرا); `[DOC CONSISTENCY]` تطابق مستندات با
پیش‌فرض‌های کد. **تست سرتاسری واقعی به ویندوز + WinDivert + v2rayN نیاز
دارد و در CI اجرا نمی‌شود** — روش دستی در پایان همان فایل آمده است.

---

## ۶) داشبورد (اختیاری)

```toml
enable_web_ui = true
web_ui_port   = 9090
# web_ui_token = ""   # خالی = توکن خودکار تولید و در لاگ چاپ می‌شود
```

- فقط روی `http://127.0.0.1:9090` باز کنید، نه `localhost`.
- هدر `Host` باید دقیقاً `127.0.0.1` باشد (دفاع DNS-rebind).
- توکن در هدر `Authorization: Bearer ...`.
- فرم آدرس سرور را نشان می‌دهد (اپراتور باید بتواند تنظیم کند) ولی **لاگ‌ها
  آدرس را به‌صورت خام نمی‌نویسند** — به‌صورت `ep-<sha256 کوتاه>` redact
  می‌شوند.

### همهٔ تنظیمات از داشبورد قابل تغییرند

صفحه‌ی داشبورد (`src/webui/index.html`) هر ۷۷ فیلد `Settings` را پوشش
می‌دهد، در ۱۲ بخش فارسی/راست‌به‌چپ:

| بخش | چه چیزی |
|---|---|
| هستهٔ جهش | `mutation_profile`, `decoy_ttl`, `idle_timeout_secs`, `fragment_chunk_size`, decoys، fragmentation، desync تطبیقی، ترفند HTTP Host |
| محدودهٔ پورت | `intercept_all_tcp`, `intercept_all_udp`, `intercept_ports` |
| رله | همهٔ `relay_*` شامل مقصد، پورت، SNI جعلی و fail-closed |
| TLS/desync | رکورد TLS، `enable_frag_by_sni`، AutoTTL و دلتای آن |
| اثرانگشت | uTLS، ECH GREASE، MD5SIG، Geedge، disguise، fronting، swap foolers، QUIC |
| DNS/DoH | `doh_server`, `trusted_dns`, `sni_only`, `sni_except` |
| داشبورد وب | `enable_web_ui`, `web_ui_port`, `web_ui_token` |
| عملیات | kill switch و آداپتور، `rotate_ips`، pin هش درایور |

نکته‌های رفتاری:

- **اعتبارسنجی لحظه‌ای** همان قواعد `Settings::validate()` را آینه می‌کند؛
  خطا دکمهٔ «ذخیره» را می‌بندد، ولی حالت‌های «قانونی ولی پرخطر» فقط هشدار
  می‌دهند و Save را نمی‌بندند.
- **ذخیرهٔ جزئی**: فقط کلیدهایی که تغییر داده‌اید ارسال می‌شوند، پس بقیهٔ
  کانفیگ دست‌نخورده می‌ماند.
- **`POST /api/validate`**: همان اعتبارسنجی بدون نوشتن روی دیسک — دلیل دقیق
  ردشدن سمت سرور را قبل از ذخیره می‌بینید.
- برای گزینهٔ پرخطر (`intercept_all_tcp`، `intercept_all_udp`،
  `enable_swap_foolers`، و خاموش‌کردن `relay_require_inject`) تأییدیه می‌پرسد.
- `web_ui_token` و `win_divert_sha256` فقط‌نوشتنی‌اند: خالی‌گذاشتن یعنی
  «دست نزن»، پس ذخیره هرگز توکن یا pin شما را پاک نمی‌کند.
- دکمهٔ جداگانهٔ «Start/Stop relay» حذف شده؛ `relay_enabled` خودش یک
  کلید است و hot-reload ظرف ~۱ ثانیه رله را می‌سازد یا متوقف می‌کند.

اگر فیلد جدیدی به `Settings` اضافه شود و به صفحه اضافه نشود،
`cargo test` می‌شکند
(`webui::ui_schema_tests::every_settings_field_is_editable_in_the_ui`).

### تست داشبورد

چون صفحه build step ندارد، به‌شکل همان چیزی که هست تست می‌شود: پوشهٔ
`uitest/` صفحهٔ **واقعی** را در jsdom روی یک mock از همین routeها اجرا
می‌کند (شامل پورت وفادار `Settings::validate` و `config::merge_partial`) و
یک پارسر TOML واقعی (`@iarna/toml`) هر چیزی را که صفحه تولید می‌کند
اعتبارسنجی می‌کند.

```bash
cd uitest && npm install && npm test     # ۱۰۳ تست UI + ۳۹ بررسی پوشش
npm run preview                          # http://127.0.0.1:8787
```

---

## ۷) رفتار fail-closed (مهم)

`relay_require_inject = true` پیش‌فرض است. یعنی:

- بعد از 3WHS خروجی، برنامه یک ClientHello جعلی با SEQ اشتباه تزریق می‌کند.
- منتظر می‌ماند سرور آن را با dup-ACK تأیید کند (نشانه اینکه بسته به DPI
  رسیده و در پنجره‌ی واقعی سرور افتاده).
- اگر ظرف ۳ ثانیه تأیید نشد، **اتصال بسته می‌شود و ClientHello واقعی اصلاً
  کپی نمی‌شود** تا SNI واقعی روی سیم نرود.

اگر روی یک شبکه واقعی ویندوزی injection جواب نداد، با `RUST_LOG=dpi_guard=debug`
اجرا کنید و لاگ‌ها را ببینید. زمان‌بندی تزریق روی ویندوز واقعی در این
سندباکس تست نشده است (صادقانه).

---

## ۸) چیزهایی که عمداً محدودند

- **IP مقصد پنهان نمی‌شود**؛ مثل خود patterniha روی سیم قابل دیدن است.
- بلاک DNS با WFP فعلاً **استاب** است؛ برای جلوگیری از لو رفتن DNS،
  DoH سیستمی را روشن کنید یا `doh_server` را روی IP literal بگذارید.
- ECH فقط GREASE است، نه HPKE واقعی.
- رله دقیقاً **یک مقصد** دارد. دو سرور با دو IP در یک پروسه نمی‌شود.
- `cargo test` در سندباکسی که این کد در آن نوشته شد اجرا نشد (rustc و
  crates.io در دسترس نبودند). لطفاً روی ماشین خودتان اجرا کنید:
  `cargo test` و `cargo clippy -- -D warnings`.

---

## ۹) عیب‌یابی سریع

| خطا | علت | راه‌حل |
|---|---|---|
| `lock ... held` | یک نمونه دیگر یا patterniha باز است | ببندید |
| `relay bind ... failed` | پورت 40443 توسط patterniha یا نمونه دیگر گرفته شده | پورت را عوض کنید یا پروسه را ببندید |
| `WinDivert ... not found next to executable` | dll/sys کنار exe نیست | فایل‌های رسمی را کنار exe بگذارید |
| build با panic در `windivert-sys` (`Os { code: 3, kind: NotFound }` در `fs::read_dir`، `build/main.rs:22`) | یک `WINDIVERT_PATH` در محیط ویندوز به پوشه‌ای اشاره می‌کند که وجود ندارد. `.cargo\config.toml` با `force = true` باید آن را بازنویسی کند؛ اگر باز هم این خطا را دیدی یعنی آن فایل در checkout تو نیست | `git checkout -- .cargo/config.toml` و بعد `.\build-windows.bat`. برای یک build فوری بدون آن: `cmd /c "set WINDIVERT_PATH= && cargo build --release"` (متغیر را برای همان process خالی می‌کند تا شاخهٔ `vendored` اجرا شود) |
| `capture did not become ready within 3s` | درایور/فیلتر/دسترسی | Administrator اجرا کنید، فیلتر را چک کنید |
| `relay destination ... forbidden` | مقصد لوپ‌بک/لینک‌لوکال/متادیتا است | IP عمومی یا RFC1918 بدهید |

---

مستندهای دیگر:
- `FINAL.md` — نسخه نهایی و تصمیم‌های fail-closed
- `PROJECT_GUIDE.md` — هندآف فنی
- `SECURITY_CHECKLIST.md` — چک‌لیست امنیتی با منبع
- `ci/README.md` — نحوه نصب CI workflow
