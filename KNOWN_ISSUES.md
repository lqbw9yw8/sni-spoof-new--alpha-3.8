# KNOWN ISSUES — وضعیت و مستندات مشکلات واقعی

آخرین به‌روزرسانی: ۲۰۲۶/۰۹/۲۳

این فایل بر اساس خروجی ابزار تحلیل ایستا `tools/gen_status.py` و بازبینی دقیق سورس‌کد به‌روزرسانی شده است.

---

## 🟡 K-1 — محیط اجرای تست

**وضعیت:** در این checkout فعلی `BLOCKED / UNVERIFIED`

در یک baseline تاریخی با Rust stable 1.98.1 روی Linux، `cargo test`
**۴۳۱/۴۳۱** پاس شده بود. سورس فعلی **۴۵۷ تست اعلام‌شده** دارد؛ ۲۶ مورد تست/تغییر این دور هنوز با cargo اجرا نشده‌اند. در محیط ممیزی فعلی
`cargo`/`rustc`/`rustup` وجود ندارند، بنابراین build، test، fmt، clippy،
audit و deny برای این checkout `NOT TESTED` هستند. سوئیت JavaScript فعلی
جداگانه **۳۹۸/۳۹۸** پاس شده است. جزئیات و raw output در `STATUS.md` و
گزارش تحویل همین ممیزی ثبت شده‌اند.

ادعاهای ۳۸۳/۴۲۷/۴۳۱ در بخش‌های تاریخی این فایل و CHANGELOG فقط سابقه‌اند؛
آنها نتیجهٔ اجرای فعلی نیستند.

---

## 🟡 K-2 — چک‌لیست و ماتریس آزمون واقعی روی محیط ویندوز

**وضعیت:** تدوین ماتریس آزمون لایو روی ویندوز

موتور رهگیری و تزریق پکت `engine.rs` به درایور کرنل WinDivert و دسترسی Administrator نیاز دارد. ماتریس آزمون‌های لایو روی ویندوز به شرح زیر است:

| شناسه | عنوان آزمون | پیش‌نیاز | روش راستی‌آزمایی | معیار قبولی |
|---|---|---|---|---|
| WIN-01 | راه‌اندازی با قفل Singleton | اجرای فایل با دسترسی ادمین | تلاش برای اجرای همزمان دو نمونه `dpi_guard.exe` | نمونهٔ دوم با خطای singleton خارج شود |
| WIN-02 | تطابق هش SHA-256 درایور | تنظیم `win_divert_sha256` | بازبینی هش درایور قبل از باز کردن هندل WinDivert | در صورت عدم تطابق، برنامه قبل از شبکه متوقف شود |
| WIN-03 | تزریق و جهش ClientHello در Wireshark | فیلتر پورت 443 | مشاهده ترافیک TLS handshake در Wireshark | مشاهده پکت‌های decoy با TTL کم و قطعات فرگمنت |
| WIN-04 | حالت رله و تفکیک جریان‌ها | تنظیم `relay_enabled = true` | تست اتصال کلاینت محلی به 127.0.0.1:listen_port | رله به سرور مقصد با SNI جعلی متصل و داده را عبور دهد |
| WIN-05 | بازیابی از مسدودسازی شبکه (Fail-Closed) | قطعی شبکه در زمان شروع | اجرای برنامه در نبود شبکه و سپس اتصال مجدد | عدم نشت پکت، رله بعد از آماده‌سازی فعال شود |
| WIN-06 | بازگردانی پروکسی سیستم (Proxy Cleanup) | `enable_proxy_cleanup = true` | خروج با Ctrl+C، دکمهٔ Stop GUI، یا panic عمدی | تنظیمات پروکسی سیستم ویندوز به حالت اولیه بازگردد (گارد Drop + فایل `<config>.stop` + مسیر Ctrl+C) |

---

## 🟢 K-3 — پوشش تست‌های `main.rs` و `native_gui.rs`

**وضعیت:** برطرف شد (RESOLVED)

ماژول‌های `main.rs`، `native_gui.rs` و `error.rs` اکنون دارای مجموعه تست‌های کامل هستند:
- `main.rs`: تست‌های تطابق `RelayId`، چرخه حیات `RelayRuntime`، بازیابی از مسمومیت قفل (Mutex Poisoning Recovery)، اعتبارسنجی IPهای رله، و اطمینان از Redaction آدرس‌های LAN و Edge.
- `native_gui.rs`: تست‌های تفکیک و پردازش خطوط با بافرها (`lines`)، همگام‌سازی فهرست‌ها و پورت‌ها (`sync_lists`)، بارگذاری و اعتبارسنجی خطاهای TOML، و مدیریت صف لاگ‌ها.
- `error.rs`: تست‌های قالب‌بندی `Display` برای تمام حالات خطای `DpiGuardError`.

---

## 🟢 K-4 — اتصال توابع بدون فراخوان به مسیرهای زنده موتور

**وضعیت:** برطرف شد (RESOLVED) — با یک اصلاحیه در ممیزی ۲۰۲۶-۰۹-۰۹

توابعی که قبلاً فقط در تست‌ها صدا زده می‌شدند، به مسیرهای اجرای زنده متصل شدند یا به عنوان افزونه‌های فعال در پایپ‌لاین یکپارچه شدند:
- `geedge::inject_fake_record_before_hello` و `would_geedge_miss_sni` و `should_use_ip_fragmentation` در `pipeline.rs`.
- `ech::build_outer_sni_for_ech` در بخش ECH پایپ‌لاین.
  > **یادداشت ممیزی ۰۹-۰۹:** این فراخوانی «وصل» بود اما نتیجه‌اش با
  > `let _ =` دور ریخته می‌شد — از نظر gen_status متصل، روی سیم مرده
  > (دقیقاً از جنس «فقط شبیه پیاده‌سازی»). اکنون نتیجه اعمال می‌شود.
- `stealth::normalize_ttl` در ایجاد پکت‌های decoy.
- `quic::build_quic_decoy` در مسیر رهگیری UDP/QUIC.
- `sequence::calculate_wrong_seq` و `add_padding_to_decoy` در پکت‌های decoy.
- `fragmentation::shuffle_cipher_suites_in_hello` در پردازش اثرانگشت uTLS.

---

## 🟢 K-5 — رسیدن تعداد توابع مرده به صفر (۰ Dead Functions)

**وضعیت:** برطرف شد (RESOLVED)

طبق خروجی `python3 tools/gen_status.py`:
- تعداد کل توابع مرده بدون فراخوان در کل مخزن: **۰ تابع**.
- توابع `client_detect::any_running` و `first_running` در چرخهٔ شروع `main.rs` برای پایش کلاینت‌های پروکسی استفاده می‌شوند.
- `proxy_cleanup::enable_dpi_guard_proxy` و `disable_dpi_guard_proxy` دارای تست‌های کامل ذخیره و بازیابی وضعیت هستند.
- `mobile_gateway::connected_device_count` در اسکن دستگاه‌های LAN استفاده شد.
- تمام ۴۲ ماژول مخزن دارای فراخوان‌های معتبر در کد یا تست‌ها هستند؛ عدد جاری را `tools/gen_status.py` تولید می‌کند.

---

## ℹ️ K-6 — مرزهای معماری و STUBهای مستندشده

**وضعیت:** مستندسازی صادقانه و بدون ابهام

| مؤلفه | وضعیت معماری | توضیحات |
|---|---|---|
| `dns_guard::block_port_53_except_localhost` | Partial; real user-mode WFP FFI, Windows runtime `[UNVERIFIED]` | Dynamic BFE session blocks outbound TCP/UDP 53 except loopback on IPv4 + IPv6. `trusted_dns` packet redirection still needs a signed kernel callout. |
| `stealth::prevent_dns_leak` | Partial alias | Re-exports the WFP guard; behavior is subject to the same Windows/runtime limitation. |
| `singleton` روی سیستم‌عامل‌های غیر ویندوز/یونیکس | پلتفرم نامتعارف | روی ویندوز با Win32 LockFile و روی یونیکس با `flock` پیاده‌سازی شده است. |
| `self_update` | Check-Only | طبق نیازمندی‌های امنیتی، فقط بررسی نسخه از API گیت‌هاب انجام می‌شود و دانلود خودکار باینری انجام نمی‌گیرد. |

---

## 🟢 K-7 — تقسیم ۱-۲ بایتی TCP روی SNI در مسیر زنده

**وضعیت:** برطرف شد (RESOLVED)

`enable_frag_by_sni` (بدون TLS-record reframing) اکنون دقیقاً قبل از SNI
و ۱ بایت داخل نام، TCP payload را با شماره‌های seq پیوسته برش می‌دهد
(`packet::tcp_segment_payload_at_offsets` + تست `frag_by_sni_emits_tcp_one_byte_split`).

---

## ℹ️ K-8 — محدودیت‌های شناخته‌شدهٔ باقی‌مانده (صادقانه، بدون ادعا)

| موضوع | شرح | ریسک واقعی |
|---|---|---|
| TOCTOU پین درایور | برطرف شد در source: DLL/SYS قبل از hash با handle اشتراکیِ read-only باز می‌شوند، همان handleها تا پایان backend زنده می‌مانند، DLL با absolute path بار می‌شود و `GetModuleFileNameW` با مسیر مورد انتظار تطبیق می‌گیرد؛ Windows runtime هنوز `[UNVERIFIED]` است | اگر Windows runner خلاف این invariant را نشان دهد، startup fail-closed و release را متوقف کنید |
| `scanner.rs::cert_valid` | برطرف شد در source: probe اکنون از ureq/rustls با SNI کاندید و resolver متصل به IP انتخاب‌شده استفاده می‌کند؛ پاسخ HTTP خطادار هم فقط پس از عبور زنجیره/نام TLS موفق محسوب می‌شود؛ runtime شبکه در این checkout `[UNVERIFIED]` است | اگر CA/TLS runner خلاف انتظار باشد، candidate را ناموفق نگه دارید و نتیجه را `DONE` نکنید |
| مقایسهٔ TS/ابزارهای شروع | `client_detect` و `proxy_cleanup::save_state` به‌جای ترد اختصاصی، inline اجرا می‌شوند (مستند در STATUS) | صرفاً ترتیب، نه صحت |
| بروت‌فورس WebUI | فقط تأخیر ثابت 80ms + اتصال‌های سریالی؛ lockout per-IP وجود ندارد (فقط loopback) | پایین |
| موتور اسکن موازی (۲۰۶-۰۹-۱۶) | `probe_pairs_parallel` (worker pool با `thread::scope`) و اسکن پس‌زمینهٔ GUI + Stop بدون block + جدول نتایج پیاده‌سازی شدند؛ ۸ مورد unit-test آفلاین **اعلام** شده ولی در این sandbox `cargo` اجرا نشده (`NOT TESTED`) | تا اجرای cargo روی ویندوز/CI، رفتار هم‌زمانی (لغو، progress، join workerها) فقط با test اعلام‌شده پوشش دارد؛ اگر CI fail کند، اول این ماژول‌ها را ببندید |
| تأیید بصری داشبورد بازسازی‌شده (۲۰۲۶-۰۹-۲۳) | `src/webui/index.html` کاملاً بازنویسی شد و ۳۹۸ تست jsdom روی همان فایل واقعی پاس شدند، اما **هیچ مرورگری در این sandbox در دسترس نیست** (دانلود Chromium/Playwright و crates.io مسدود است) → رندر نهایی (فاصله‌ها، فونت فارسی، شکستن واژه‌ها در عرض‌های مختلف) **دیده نشده** | پایین تا متوسط: ساختار و رفتار با تست پوشش دارد، ظاهر نه. قبل از انتشار یک بار در مرورگر واقعی باز شود |
| تکرار باقی‌مانده در سورس (۲۰۲۶-۰۹-۲۳) | `engine.rs`/`engine_stub.rs` ۱۲ تابع را آینه‌ای نگه می‌دارند (عمدی: stub برای cfg غیر-ویندوز)؛ `observability.rs`↔`webui.rs` ۱۶ خط فیلدهای متریک را تکرار می‌کنند (آینهٔ `MetricsSnapshot` در `DashboardSnapshot`؛ ادغام آن شکل JSON پاسخ `/api/status` را عوض می‌کند)؛ `doh.rs`/`stealth.rs` دو `skip_name` نزدیک‌به‌هم دارند؛ فیچرهای تست در `main.rs`/`doh.rs`/`native_gui.rs` struct literalهای تکراری دارند. خروجی کامل: `python3 tools/dup_report.py` | هر بار تغییر در یکی باید در آینه‌اش هم اعمال شود؛ ادغام `MetricsSnapshot` نیازمند تغییر قرارداد API و اجرای cargo است |
| پوشش تنظیمات در پنل دسکتاپ | `native_gui.rs` فقط ۲۳ فیلد از ۸۲ فیلد `Settings` را نشان می‌دهد (داشبورد وب هر ۸۲ تا را دارد — با تست قفل شده است). پنل دسکتاپ و وب دو UI موازی با پوشش متفاوت‌اند | اپراتوری که فقط پنل دسکتاپ را باز کند، ۵۹ تنظیم را نمی‌بیند |
| هیچ CI واقعی تا ۲۰۲۶-۰۹-۲۳ (جدید) | `.github/workflows/` در این checkout اصلاً **وجود نداشت**؛ فایل‌های YAML فقط در `ci/` بودند و `ci/README.md` ادعا می‌کرد `.github/workflows/ci.yml|e2e.yml|release.yml` اجرا می‌شوند. `gh run list` → **صفر اجرا** و `gh release list` / `gh api …/tags` → **خالی**، یعنی هر ادعای «CI سبز» در مستندات غیرقابل‌اتکا بود. حالا `ci/ci.yml` و `ci/build-windows.yml` آماده‌اند و باید **یک‌بار با دست** کپی شوند (توکن اپلیکیشن اجازهٔ نوشتن workflow ندارد): `mkdir -p .github/workflows && cp ci/ci.yml ci/build-windows.yml .github/workflows/` | بالا: تا وقتی workflowها نروند، **هیچ کامپایل/تست خودکاری روی این کد اجرا نشده است**؛ اولین کار بعد از merge |
| `cargo fmt --check` قرمز است (جدید) | درخت هیچ‌وقت فرمت نشده: **۱۴ فایل / ۹۵ هانک** (`src/lib.rs` ۴۶، `src/scanner.rs` ۱۴، `src/native_gui.rs` ۱۰، `src/dns_guard.rs` ۶، `src/netguard.rs` ۵، `src/main.rs` ۳، `src/doh.rs` ۳، `src/observability.rs` ۲ و ۷ فایلِ ۱ هانکی)، با rustfmt 1.8.0 / edition 2021 | در `ci/ci.yml` عمداً گنجانده نشده تا شکستِ ظاهری نتیجهٔ build/test را مخفی نکند؛ یک بار `cargo fmt` اجرا و بعد گیت را اضافه کنید |

---

## 🟡 K-9 — اولین CI واقعی این مخزن هنوز اجرا نشده است (۲۰۲۶/۰۹/۲۳)

**کشف:** `ci/README.md` می‌گفت «workflowهای canonical در `.github/workflows/`
هستند و خودکار اجرا می‌شوند»، اما آن شاخه در مخزن وجود ندارد:

```
$ ls .github/workflows          → No such file or directory
$ gh run list --limit 5         → (خالی)
$ gh release list --limit 5     → (خالی)
$ gh api repos/.../tags         → []
```

یعنی در تمام طول عمر مخزن **یک اجرای CI هم ثبت نشده** و بنابراین:

* هیچ نسخه‌ای از این کد تاکنون با `cargo build` کامپایل نشده است؛
* عدد «۴۵۷ تست اعلام‌شده» صرفاً شمارشِ `#[test]` در سورس است، نه نتیجهٔ اجرا؛
* ادعاهای «۰ dead fn» و «CI passes» در STATUS/CHANGELOG/KNOWN_ISSUES
  غیرقابل‌اتکا هستند تا وقتی workflowها واقعاً اجرا شوند.

**چه چیزی آماده شده:** `ci/ci.yml` (ساخت + تست روی ubuntu و windows، clippy
غیرمسدودکننده، jsdom، `gen_status.py --check` و `lint_docs.py`) و
`ci/build-windows.yml` (`dpi_guard.exe` به‌صورت artifact با SHA-256). فایل‌ها
در `ci/` هستند چون اپلیکیشن گیت‌هاب اجازهٔ نوشتن `.github/workflows/` را ندارد
(`refusing to allow a GitHub App to create or update workflow … without
`workflows` permission`)؛ یک انسان باید آن‌ها را کپی و push کند (دستور در
`ci/README.md`).

**وضعیت:** `[BLOCKED]` تا اجرای دستیِ آن یک دستور — بعد از آن خروجی ران جایگزین
این بخش می‌شود.

---

## ✅ خلاصهٔ اعتبارسنجی و وضعیت ماژول‌ها

* **تعداد ماژول‌های فعال:** ۴۲ ماژول (طبق `tools/gen_status.py`)
* **تعداد کل تست‌های اعلام‌شده:** ۴۵۷ تست (تعریف‌شده در سورس، نه الزاماً اجراشده)
* **تست‌های اجرا و پاس‌شده:** baseline تاریخی ۴۳۱ از ۴۳۱؛ ۲۶ مورد تست/تغییر جدید این دور `[UNVERIFIED]`
* **تعداد توابع مرده:** ۰ (استاتیک)
* **خطای clippy:** `NOT TESTED` در checkout فعلی؛ baseline تاریخی ۰
* **همگام‌سازی کامل فیلدهای Settings:** ۸۲ از ۸۲ فیلد در کد و داشبورد همگام هستند.
