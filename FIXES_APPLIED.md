# FIXES_APPLIED — فهرست کامل اصلاحات اعمال‌شده

این فایل خلاصهٔ رفع‌باگ‌های اعمال‌شده روی مخزن `sni-spoof-new--alpha-3.6` است.
هر مورد با اجرای واقعی (`cargo test`, `clippy`, `fmt`, سوئیت‌های jsdom، ابزارهای
متای خود پروژه) تأیید شده است.

---

## دور ۳ (۲۰۲۶-۰۹-۲۷) — CI واقعی، SSRF شکل‌کوتاه، گیت ECH، بهداشت گیت

### ۱) `.github/workflows/` — چهار workflow واقعی (ادعا می‌شد، هرگز وجود نداشت)
- `ci.yml`: گیت `cargo fmt --check` + `cargo build/test --all-targets` روی
  ubuntu **و** windows + clippy + سوئیت jsdom داشبورد + چک‌های docs
  (`gen_status.py --check`, `lint_docs.py`, `dup_report.py`).
- `build-windows.yml`: بیلد release و آرتیفکت `dpi_guard-windows`.
- `e2e.yml`: smoke میدانی واقعی روی windows-latest (فقط دستی/هفتگی) — لود
  درایور WinDivert، اجرای `dpi_guard.exe --backend`، پروب `/api/status` با
  توکن، خاموشی graceful با stop-file؛ روی اجرای دستی سخت‌گیر، روی زمان‌بندی
  هفتگی tolerant.
- `release.yml`: انتشار tag-driven به‌همراه `SHA256SUMS.txt`.
- هر پاچهٔ ویندوزی پیش از لینک، SDK رسمی WinDivert 2.2.2 را با
  `scripts/fetch-windivert.ps1` (hash-pinned) می‌گیرد — چون
  `windivert-sys` در زمان build از `WINDIVERT_PATH` لینک می‌کند و باینری‌ها
  عمداً در گیت نیستند.
- کپی‌های `ci/*.yml` بایت‌به‌بایت همگام شدند؛ `ci/README.md` و `README.md`
  دیگر «کپی کنید تا فعال شود» ندارند — workflowها واقعاً commit شده‌اند.

### ۲) `src/netguard.rs` — گره بستهٔ SSRF برای شکل‌کوتاه IPv4
- `parse_legacy_ipv4` قبلاً فقط ۴-پارت یا عدد تکی (دهدهی/هگز/اکتال) را
  می‌شناخت؛ رشته‌هایی مثل `127.1` که `getaddrinfo` ویندوز مثل `inet_aton` به
  `127.0.0.1` بازمی‌گرداند از فیلتر عبور می‌کردند.
- حالا قواعد کامل `inet_aton` پیاده شده: `a`، `a.b`، `a.b.c`، `a.b.c.d` با
  رادیکس‌های ۸/۱۰/۱۶ و اعتبارسنجی عرض هر جزء.
- تست جدید: `short_form_ipv4_cannot_smuggle_loopback`.

### ۳) `src/pipeline.rs` — گیت ECH واقعی روی کل نردبان فرگمنتیشن
- با `enable_real_ech` مسلح و ECHConfig معتبر، پروفایل NestedCloak از قبل
  خاموش بود اما نردبان فرگمنتیشن/آشوب روشن می‌ماند و hello مهرشده را به ۲۱
  پکت می‌شکست (ترکیب تنظیمات رفتار طراحی‌شده نداشت).
- حالا `combined_on`، `use_tls_record_frag`، `use_frag_by_sni`،
  `use_frag_mid_sni` و `should_disorder` همگی با `!real_ech_armed` گیت
  می‌شوند؛ خروجی دقیقاً ۱ پکت است. تست مرجع:
  `ech_real_x_nested_cloak_no_ff01_leak`.

### ۴) بهداشت گیت — باینری‌های WinDivert
- `WinDivert.dll` / `WinDivert.lib` / `WinDivert64.sys` از ایندکس گیت حذف
  شدند (`git rm --cached`)؛ `.gitignore` حالا `*.dll` / `*.lib` / `*.sys` /
  `*.toml.stop` را دارد.
- `.cargo/config.toml` بازسازی شد: `WINDIVERT_PATH = { value = ".", relative
  = true, force = true }` — `build-windows.bat` بدون دستکاری دستی کار می‌کند.
- README دیگر با واقعیت `.gitignore` تناقض ندارد و تاریخچهٔ کامیت‌شدن قدیمی
  این باینری‌ها را صادقانه توضیح می‌دهد.
- در ZIP ارسالی، این سه فایل رسمی (hash-verified) به‌صورت محلی حضور دارند تا
  بیلد ویندوز خارج از جعبه کار کند؛ با push بعدی از مخزن گیت‌هاب حذف می‌شوند
  و CI خودش نسخهٔ رسمی را می‌گیرد.

### ۵) رفع ۵ تست قرمز + ۱ خطای کامپایل (باقی‌ماندهٔ دور قبل)
- `src/observability.rs`: E0277 (`&Cow<str>` به‌عنوان Pattern) با `&*`؛ شرط
  چرخش لاگ `>` → `>=` (فایل هرگز از سقف رد نمی‌شود؛ مطابق `open()` و نام تست).
- `src/config.rs`: دو assertion تک-پینی کهنه به ناوردار «دقیقاً ۲ پین مرتب یا
  ۰» تبدیل شد (کد تولیدی دست نخورد).
- `src/native_gui.rs`: `ScanState::reset` حالا `results` را هم پاک می‌کند.
- `src/webui/index.html`: `startPolling()` ایدمپوتنت؛ در `boot()` **و**
  `tok_save` صدا زده می‌شود (باگ «اولین نشست، داشبورد پول نمی‌شد»).

### ۶) `src/scanner.rs` — مموایزِ انتخاب خودکار
- `auto_select_best_relay_target` هر تیک ~۱ ثانیه‌ای watchdog (وقتی
  `relay_connect_host = "auto"`) یک موج کامل پروب TLS ۱۶-کاندیداه اجرا
  می‌کرد. حالا نتیجهٔ موفق ۱۰ دقیقه و شکست ۳۰ ثانیه کش می‌شود
  (`OnceLock<Mutex<>>`) + تست قفل رفتار.

### ۷) بهداشت کد
- `cargo fmt` روی کل درخت (پیش‌نیاز گیت fmt در CI).
- clippy روی همهٔ targetها صفر (autottl `is_empty`، حلقهٔ fragmentation،
  if تودرتو و struct-init در native_gui، rebind های زائد و borrowed-expr در
  scanner).

### ۸) نتایج وارسی نهایی
- `cargo test --all-targets`: **۴۵۹/۴۵۹** (۴۵۲ lib + ۷ bin)
- `cargo clippy --all-targets -- -D warnings`: ۰ هشدار
- `cargo fmt --all -- --check`: تمیز
- `tools/gen_status.py --check`: ۴۲ ماژول، ۴۵۹ تست، ۰ تابع مرده
- `tools/lint_docs.py`: ۰ تخلف (۸۲ فیلد Settings)
- سوئیت‌های jsdom: status ۳۲/۳۲ · settings ۶۲/۶۲ · check-rust-tests ۶۲/۶۲

### ۹) محدودیت‌های صادقانه (تغییرنکرده)
- رفتار زمان اجرای WinDivert/WFP روی ویندوز واقعی نیاز به تست میدانی دارد
  (`e2e.yml` همین را خودکار می‌کند).
- قابلیت‌های report-only (kill-switch، mobile-gateway، self-update، چرخش
  SniPool روی سیم، ارسال decoy QUIC) طبق مستندات خود پروژه دست‌نخورده
  ماندند — تصمیم مالک و نیازمند تصمیم طراحی.
- هشدار transcript: دست‌کاری ClientHello واقعی در حالت شفاف می‌تواند هندشیک
  را بشکند؛ مسیر relay پیش‌فرض بایت‌به‌بایت امن است.

---

## دور ۲ (۲۰۲۶-۰۹-۲۶) — خلاصه
`randomize_ip_id` به `status_json` اضافه شد و mock همگام شد؛ انتخاب خودکار
relay سبک شد؛ `.cargo/config.toml` و الگوهای `.gitignore` بازسازی شدند؛
داشبورد در ۱۲۸۰/۳۹۰ پیکسل با صفحهٔ دانلود فارسی تأیید شد.
