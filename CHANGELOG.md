# CHANGELOG

قالب: [Keep a Changelog](https://keepachangelog.com/) · نسخه‌بندی: SemVer

> وضعیت هر ورودی طبق `AI_RULES.md` بخش ۳ برچسب می‌خورد.

## [Unreleased] — دور چهارم: سازگاری سرتاسری + بهینه‌سازی منابع بدون کاهش قابلیت (۲۰۲۶-۰۹-۲۷) — `DONE_VERIFIED`

ممیزی دو-سمتهٔ «سازگاری همهٔ ماژول‌ها با هم بعد از هر به‌روزرسانی» + «سرعت/رم/منابع»؛
هیچ قابلیتی حذف یا ساده نشد — فقط کارِ بیهوده و کپی‌های اضافی حذف شد.

- **باگ رگرسیون داشبورد (W1) — `randomize_ip_id` از `status_json` جا افتاده بود (`DONE_VERIFIED`):** ترمیم دور دوم در کلونِ سوم از دست رفته بود؛ چیپ «IP-ID تصادفی» در داشبورد هیچ‌وقت روشن نمی‌شد. سه‌جا همگام شد: `webui.rs` (سریال‌سازی) + `uitest/mock-server.mjs` + `chipFields` در `test-status.mjs`.
- **H1 — مسیر داغ zero-copy (`DONE_VERIFIED`):** قرارداد `capture_loop`/`fail_open` از `FnMut(Vec<u8>)` به `FnMut(&[u8])` تغییر کرد و نوع جدید `WireAction::Passthrough` اضافه شد؛ ۱۹ نقطهٔ بازگشتِ «پکت دست‌نخورده» در `pipeline.rs` به `Passthrough` تبدیل شد. برای ~۹۹٪ پکت‌ها (عبوری) ۲ تخصیص heap + ۲ memcpy کامل بافر + ۱ مقایسهٔ O(n) در هر پکت حذف شد. fallback خطا/panic همان تضمین fail-open قبلی را دارد.
- **H2 — `forget_held_for_flow` (`DONE_VERIFIED`):** خروج سریع وقتی لیست HELD خالی است — قبلاً برای هر پکت ارسالی، کلید flow دوباره parse و تا ۲۵۶ پکتِ نگه‌داشته با memcmp کامل اسکن می‌شد.
- **H3 — گیت زمانی روی `flush_idle` (`DONE_VERIFIED`):** جاروی ۶ نقشهٔ state (تا ~۱۳هزار مدخل) از «هر پکت» به «حداکثر هر ۱ ثانیه» — از نظر معنایی یکسان چون انقضا بر اساس زمان است.
- **H4/H5 — زباله‌های QUIC (`DONE_VERIFIED`):** ساختِ `build_quic_decoy(64)` دورریز (۱ تخصیص + ~۸۵ فراخوانی rand) برای هر پکت UDP حذف شد؛ لاگ reverse-NAT از info به debug منتقل شد (برای هر پکتِ پاسخِ یک flow، SHA-256 redaction اجرا می‌کرد)؛ `hash_sensitive` از ۳۲ تخصیص به ۱ تخصیص از پیش اندازه‌گیری‌شده.
- **H6 — کش پورت‌های explicit در Pipeline (`DONE_VERIFIED`):** چک پورت در مسیر داغ از «ساخت Vec + sort + dedup در هر فراخوانی» به binary search روی لیست مرتبِ کش‌شده؛ با hot-reload با `refresh_port_cache()` باطل می‌شود.
- **M1 — جدول امتیاز strategy (`DONE_VERIFIED`):** `score_of` با lookup مستقیم جایگزین دو اسکن کامل O(4096) در هر ClientHello شد؛ `select_best`/`select_rotating` دیگر با `entry` ردیف صفر می‌ساختند (آلودگی جدول تا سقف 4096 حتی بدون هیچ بازخوردی) — جدول حالا فقط با `update_score` رشد می‌کند.
- **M2 — قفل مسیر پکت دیگر برای داشبورد بلاک نمی‌شود (`DONE_VERIFIED`):** ساخت snapshot سبک شد (کلون Settings + دو handle ارزان زیر قفل)؛ هشِ SHA-256 امتیازها (تا ۴۰۹۶ مدخل) و دامنه‌ها بیرونِ قفل اجرا می‌شود. `RelayId::desired` (موج پروب auto تا ~۱.۵ ثانیه بلاک) از ترد watchdog به ترد کارگر منتقل شد (`desired_cached`/`kick_desired`) — الگوی همان رزولوشن DoH.
- **M3/M4/M5/M6/M7 — (`DONE_VERIFIED`):** سه محاسبهٔ دورریز geedge (هرکدام hello را دوباره parse می‌کرد) حذف؛ reassembly دیگر بافر را در هر سگمنت clone نمی‌کند (فقط یک‌بار بعد از parse موفق)؛ `/api/scanner/probe` دیگر موج ۱۶-کاندیدا را دوبار اجرا نمی‌کند (best از ranked مشتق می‌شود — stall داشبورد نصف شد)؛ چک‌سام‌ها pseudo-header را بدون تخصیص Vec جمع می‌کنند (تست‌های بردار RFC سبز)؛ کلاینت DoH یک‌بار ساخته و کش می‌شود (TLS session reuse، همان resolver امن و https_only و redirects=0).
- **W2/W4/W5/W6/L1/L3 — (`DONE_VERIFIED`):** ۷ فیلد مردهٔ DashboardSnapshot (پر می‌شدند اما هرگز سریال نمی‌شدند) حذف شد؛ `settings_json` به‌جای `[""]` اکنون `[]` برای پین‌های redact‌شده می‌فرستد؛ هر سه گیت utls/geedge/padding روی `real_ech_armed` یکدست شدند؛ کامنت گمراه‌کنندهٔ e2e.yml اصلاح شد؛ `from_utf8_lossy(...).to_string()` → `into_owned()`؛ هش درایور در `integrity.rs` به‌جای خواندن کل فایل، استریمی ۶۴KiB شد.
- **وضعیت نهایی:** `cargo test --locked` = **۴۶۰/۴۶۰** (۴۵۳ lib + ۷ bin؛ +۱ تست قرارداد zero-copy) · `clippy -D warnings` = ۰ · `fmt --check` = تمیز · `gen_status.py --check` = ۴۲ ماژول، ۴۶۰ تست، ۰ تابع مرده · `lint_docs.py` = ۰ تخلف · jsdom = ۱۱۵+۶۲+۳۲+۶۲ سبز · mock↔`status_json` همگام.

## [Unreleased] — دور سوم اصلاحات: CI واقعی، SSRF شکل‌کوتاه IPv4، گیت ECH روی فرگمنتیشن، بهداشت گیت (۲۰۲۶-۰۹-۲۷) — `DONE_VERIFIED`

- **`.github/workflows/` — چهار workflow واقعی که ادعا می‌شد اما هرگز وجود نداشت (`DONE_VERIFIED`):** `ci.yml` (گیت `cargo fmt --check` + build/test روی ubuntu **و** windows + clippy + سوئیت jsdom + چک‌های docs)، `build-windows.yml` (آرتیفکت release)، `e2e.yml` (smoke میدانی واقعی: لود درایور WinDivert + اجرای exe واقعی + پروب `/api/status` + خاموشی با stop-file؛ فقط دستی/هفتگی)، و `release.yml` (انتشار tag-driven با SHA-256SUMS). هر پاچهٔ ویندوزی قبل از لینک، SDK رسمی را با `scripts/fetch-windivert.ps1` (hash-pinned) می‌گیرد. کپی‌های `ci/*.yml` بایت‌به‌بایت همگام شدند و `ci/README.md` + `README.md` دیگر ادعای «کپی کنید تا فعال شود» ندارند.
- **`src/netguard.rs` — گره بستهٔ SSRF برای شکل‌کوتاه IPv4 (`DONE_VERIFIED`):** `parse_legacy_ipv4` قبلاً فقط ۴-پارت یا عدد تکی را می‌شناخت؛ `127.1` (که `getaddrinfo` ویندوز مثل `inet_aton` به `127.0.0.1` بازمی‌گرداند) از فیلتر رد می‌شد. حالا قواعد `inet_aton` کامل پیاده شده (`a`، `a.b`، `a.b.c`، `a.b.c.d` با رادیکس‌های ۸/۱۰/۱۶) و تست جدید `short_form_ipv4_cannot_smuggle_loopback` آن را قفل می‌کند.
- **`src/pipeline.rs` — گیت `real_ech_armed` به کل نردبان فرگمنتیشن/آشوب گسترش یافت (`DONE_VERIFIED`):** با ECH واقعی مسلح، `combined_on`، `use_tls_record_frag`، `use_frag_by_sni`، `use_frag_mid_sni` و `should_disorder` دیگر روشن نمی‌شوند — خروجی hello مهرشده دقیقاً ۱ پکت است (قبلاً ۲۱ پکت فرگمنت با پروفایل NestedCloak ارسال می‌شد؛ ترکیب تنظیمات رفتار طراحی‌شده نداشت).
- **بهداشت گیت — باینری‌های WinDivert (`DONE_VERIFIED`):** `WinDivert.dll`/`WinDivert.lib`/`WinDivert64.sys` از ایندکس گیت حذف شدند؛ `.gitignore` حالا `*.dll`/`*.lib`/`*.sys`/`*.toml.stop` را دارد؛ `.cargo/config.toml` بازیابی شد (`WINDIVERT_PATH` با `force=true` و `relative=true`) تا `build-windows.bat` بدون دستکاری دستی کار کند و README دیگر با واقعیت تناقض نداشته باشد.
- **رفع ۵ تست قرمز + ۱ خطای کامپایل باقی‌مانده از دور قبل (`DONE_VERIFIED`):** `observability.rs` (E0277 Pattern + ترشیح چرخش لاگ با `>=`)، `config.rs` (دو assertion تک-پینی کهنه به ناوردار دو-پینی مرتب تبدیل شد)، `native_gui.rs` (`ScanState::reset` حالا نتایج را هم پاک می‌کند)، `webui/index.html` (polling با `startPolling()` idempotent از `boot()` **و** `tok_save` — باگ «اولین نشست پول نمی‌شد»).
- **`src/scanner.rs` — مموایزِ `auto_select_best_relay_target` (`DONE_VERIFIED`):** با `relay_connect_host="auto"` هر تیک ~۱ ثانیه‌ای watchdog یک موج کامل پروب TLS ۱۶-کاندیداه را اجرا می‌کرد؛ حالا نتیجهٔ موفق ۱۰ دقیقه و شکست ۳۰ ثانیه کش می‌شود + تست قفل رفتار.
- **clippy صفر روی همهٔ targetها + `cargo fmt` کل درخت (`DONE_VERIFIED`):** پیش‌نیاز گیت fmt در `ci.yml`.
- **وضعیت نهایی:** `cargo test --all-targets` = **۴۵۹/۴۵۹** (۴۵۲ lib + ۷ bin) · `clippy -D warnings` = ۰ · `fmt --check` = تمیز · `gen_status.py --check` = ۴۲ ماژول، ۴۵۹ تست، ۰ تابع مرده · `lint_docs.py` = ۰ تخلف · سوئیت‌های jsdom = ۳۲+۶۲+۶۲ سبز.

## [Unreleased] — انحراف مقادیر پیش‌فرض mock از Rust + نقص ARIA تب‌ها (۲۰۲۶-۰۹-۲۶) — `DONE_VERIFIED`

- **`uitest/mock-server.mjs` — دو مقدار پیش‌فرض غلط (`DONE_VERIFIED`):** مقایسهٔ
  خودکارِ `DEFAULTS` با `impl Default for Settings` در `src/config.rs` نشان داد
  `enable_tls_record_fragmentation` در mock برعکسِ مقدار واقعی (`true` به‌جای
  `false`) و `update_repo` به مخزنِ اشتباهی اشاره می‌کرد
  (`sni-spoof-new-5.6` به‌جای مقدار `self_update::DEFAULT_UPDATE_REPO`). یعنی
  تست‌ها رفتاری را تأیید می‌کردند که باینری واقعی تولید نمی‌کند.
- **`uitest/test-settings.mjs` — قرارداد پیش‌فرض‌ها (`DONE_VERIFIED`):** تست
  جدید `[S6]` فیلدهای `Settings::default()` را از سورس استخراج، helperهای
  `default_*()` و ثابت‌های `crate::mod::CONST` را resolve و با mock مقایسه
  می‌کند؛ فیلد گم‌شده/اضافی/مقدارِ متفاوت ⇒ قرمز. (`trusted_dns` عامداً مستثنا
  است: `Option<String>` و غایب‌بودن یعنی `None`.)
- **`src/webui/index.html` — نقص واقعی ARIA (`DONE_VERIFIED`):** نوار تب‌ها
  `aria-selected` داشت بی‌آنکه `role="tab"`/`role="tablist"` داشته باشد — طبق
  WAI-ARIA آن ویژگی روی یک `<button>` ساده نادیده گرفته می‌شود. حالا
  `role="tablist"` روی نوار، `role="tab"` + `aria-controls` روی هر دکمه و
  `role="tabpanel"` + `aria-labelledby` روی هر پنل است. تابعِ هرگز‌فراخوانی‌نشدهٔ
  `badge()` هم حذف شد.
- **`uitest/test-ui.mjs` — قفل ARIA (`DONE_VERIFIED`):** بلوک `[A11y]` سیم‌کشیِ
  تب→پنل را بررسی می‌کند (نقص بالا پیش از اصلاح در اینجا قرمز می‌شد).

## [Unreleased] — همگام‌سازی mock با قرارداد واقعی API، آماده‌سازی CI، رفع flake تست‌ها (۲۰۲۶-۰۹-۲۶) — `DONE_VERIFIED` (بخش jsdom) / `BLOCKED` (بخش CI)

- **`uitest/mock-server.mjs` — رفع انحراف خطرناک (`DONE_VERIFIED`):** تابع
  `statusJson()` فقط **۲۸ فیلد** از **۵۶ فیلدی** را که `status_json()` در
  `src/webui.rs` واقعاً می‌فرستد سرو می‌کرد و ۳ کلید منسوخ
  (`enable_quic_bypass`, `enable_utls`, `fronting_benign`) هم داشت. یعنی
  بخشی از داشبورد در تست‌ها مقدار `undefined` می‌خواند و سوئیت با این حال
  سبز بود. حالا هر ۵۶ فیلد آینه می‌شوند و `statusOverrides` در انتها پخش
  می‌شود.
- **`uitest/test-status.mjs` — قفل کردن قرارداد (`DONE_VERIFIED`):** تست جدید
  `[O6]` کلیدهای فرمت واقعی را از `src/webui.rs` استخراج و با پاسخِ سرو‌شده
  مقایسه می‌کند (فیلد گم‌شده یا منسوخ ⇒ قرمز) و تأیید می‌کند مقادیر بولی تا
  DOM می‌رسند. همراه با helper جدید `waitFor()` که جای خواب ثابت ۲۵۰ms را در
  `[O1]`/`[O6]` گرفت: flake‌ای که در اجرای کامل `npm test` رخ می‌داد برطرف شد
  (دو اجرای پشت‌سرهم سبز، ۳۸۷/۳۸۷).
- **`ci/ci.yml` + `ci/build-windows.yml` — اولین CI واقعی (`BLOCKED`):**
  تعریف workflow برای `cargo build --all-targets` + `cargo test
  --all-targets` روی ubuntu و windows، clippy (غیرمسدودکننده)، سوئیت jsdom،
  و `gen_status.py --check` / `lint_docs.py`؛ به‌علاوه ساخت `dpi_guard.exe`
  به‌صورت artifact با SHA-256. **این فایل‌ها هنوز اجرا نشده‌اند:** تا این
  تاریخ `.github/workflows/` در مخزن وجود ندارد و `gh run list` خالی است
  (→ `KNOWN_ISSUES.md` K-9). انتشارشان یک دستور انسانی می‌خواهد چون توکن
  اپلیکیشن اجازهٔ نوشتن workflow ندارد.
- **`KNOWN_ISSUES.md` — K-9 جدید:** «هیچ CI/تست خودکاری روی این کد اجرا نشده
  است» + دو ردیف در K-8 برای CI و برای `cargo fmt` (۱۴ فایل / ۹۵ هانک).

## [Unreleased] — بازسازی داشبورد وب، رفع E0597 اسکنر، رفع تکرار مسیر پکت (۲۰۲۶-۰۹-۲۳) — `PARTIAL_UNVERIFIED`

- **`src/scanner.rs` — رفع خطای کامپایل `E0597`:** `probe_pairs_parallel`
  دیگر شمارندهٔ کار را داخل حلقهٔ wave نمی‌سازد؛ یک صف مشترک با
  `min(total, MAX_PARALLEL_PROBES)` worker دارد که خودش حد هم‌زمانی است.
  امضا و رفتار API عمومی بدون تغییر.
- **`src/webui/index.html` — بازسازی UI:** سیستم طراحی مبتنی بر توکن، نوار
  بالا/پایین چسبانِ واحد (حذف نوار ابزار دوتاییِ `*_2`), تب‌های معنایی،
  ۱۶ کارت وضعیت + ۱۸ چیپ تکنیک (به‌جای ۳۷ کارت), جست‌وجو در نوار ابزار
  چسبان، سوئیچ‌های واقعی به‌جای چک‌باکس خام، دسترسی‌پذیری (skip link،
  `aria-selected`/`aria-invalid`/`aria-describedby`, `:focus-visible`,
  `prefers-reduced-motion`), و حذف کپی‌کاری در سمت کلاینت (`PRESETS`
  داده‌محور به‌جای چهار هندلر کپی‌شده؛ پروفایل‌ها مشتق از schema).
- **`src/fragmentation.rs` + `src/utls.rs` — رفع تکرار:** چرخهٔ
  read/modify/write لیست cipher-suite که در دو ماژول کپی شده بود، به یک
  `rewrite_cipher_suites<F>` منتقل شد (مالک بررسی مرز و ترتیب بایت).
- **`tools/dup_report.py` (جدید):** گزارش تکرار/افزونگی پروژه با چهار
  آشکارساز (کد، نام تابع، سطح تنظیمات، مستندات).
- **`uitest/check-rust-tests.mjs`:** فایل‌های ویرایش‌شدهٔ این نوبت
  (`scanner.rs`, `fragmentation.rs`, `utls.rs`) به فهرست بررسی توازن آکولاد
  اضافه شدند.
- **مدرک:** `cd uitest && npm test` → ۳۸۱ passed / ۰ failed.
  `cargo build`/`cargo test` اجرا **نشد** (crates.io در این محیط در دسترس
  نیست)؛ کد Rust در سطح crate `NOT TESTED` است.

## [0.1.0] — ۲۰۲۶-۰۹-۱۱

Baseline source release. Publish only after the Windows CI/release workflow
has produced and verified the signed/checksummed artifact.

## [Unreleased] — GUI no longer hangs: parallel scan, background thread, non-blocking stop, results table (۲۰۲۶-۰۹-۱۶) — `PARTIAL_UNVERIFIED`

- **`src/scanner.rs` — پروب موازی به‌جای توالی (رفع هنگ ~۲۴ ثانیه‌ای):**
  `probe_pairs_parallel` همهٔ کاندیدها را روی worker pool با `std::thread::scope`
  پروب می‌کند (حداکثر `MAX_PARALLEL_PROBES = 16` هم‌زمان، wave‌به-wave)؛ زمان
  کل ≈ کندترین handshake واحد (~۱.۵s) به‌جای مجموع همه (~۲۴s). پشتیبانی
  لغو زنده (`cancel: Option<&AtomicBool>`) و شمارندهٔ پیشرفت
  (`progress: Option<&AtomicUsize>`). ترتیب‌بندی جدا شد:
  `rank_probe_pairs` (پایدار: TLS-verified اول، بعد کمترین ping) و APIهای
  جدید `probe_and_rank_detailed` / `probe_and_rank_detailed_cancellable`.
  **امضای `probe_and_rank_spoof_pairs` و `best_spoof_pair` بدون تغییر ماند** —
  callers در `webui.rs` و `main.rs` بدون ویرایش، خودکار موازی شدند.
- **`src/native_gui.rs` — اسکن روی thread پس‌زمینه (UI دیگر block نمی‌شود):**
  دکمه‌های «⚡ Scan All & Show Results» و «⭐ Auto-Select Lowest Ping» اسکن را
  در `std::thread::spawn` + `mpsc::channel` اجرا می‌کنند؛
  `catch_unwind(AssertUnwindSafe)` دور کل اسکن (پانیک نمی‌تواند UI را بکشد؛
  پیام «Scan failed» می‌شود)؛ spinner + شمارندهٔ زندهٔ «Scanning n/16…» در
  نوار بالا و تابلوی Connection؛ دکمهٔ «✖ Cancel»؛
  `request_repaint_after(100ms)` فقط هنگام اسکن/stop (وگرنه ریتم ۱s قبلی).
- **`src/native_gui.rs` — Stop بدون block:** `stop()` دیگر ۳ ثانیه UI thread
  را خواب نمی‌اندازد؛ child به thread پس‌زمینه می‌رود (stop-file →
  `try_wait`×۶۰ → `kill` fallback) و `poll_stop()` پایان را به UI می‌رساند.
  `on_exit` در صورت stop در‌حالت‌پرواز تا ۱۰s منتظر همان thread می‌ماند،
  وگرنه `stop_sync` همگام را می‌زند.
- **`src/native_gui.rs` — جدول دامنه‌ها + انتخاب دستی (درخواست مستقیم کاربر):**
  نتایج اسکن در تابلوی Connection به‌صورت جدول
  Provider | IP | Fake SNI (domain) | Ping | TLS | Action نمایش می‌شود؛
  رنگ ping (سبز <۱۰۰ms، زرد <۳۰۰ms، قرمز ≥۳۰۰ms، خاکستری timeout) با متن
  رنگی به‌جای emoji فونت‌وابسته؛ ردیف برتر با «(BEST)»؛ دکمهٔ «Select» هر
  ردیف `relay_connect_host`/`relay_connect_port`/`relay_fake_sni` را پر
  می‌کند؛ Auto-Select ردیف BEST را اعمال می‌کند؛ «Clear results» پاک می‌کند.
- **تست‌ها (۸ مورد جدید، همه آفلاین):** ۶ مورد برای موتور موازی
  `scanner.rs` (ترتیب/progress برای ۲۰ کاندید = دو wave، ورودی خالی،
  cancel پیشین، ترتیب TLS-اول-سپس-ping، ثبات sort، ورود از APIهای عمومی)
  و ۲ مورد GUI در `native_gui.rs` (reset `ScanState`، variants `ScanMsg`).
  مجموع اعلام‌شده: ۴۴۹ → ۴۵۷.
- **مدرک اجرا در این sandbox (بدون cargo/rustc):** `cd uitest && npm test`
  ۳۷۵ پاس/۰ شکست ✅؛ `gen_status.py --check` ✅؛ `lint_docs.py` ۰ نقص ✅؛
  syntax-check tree-sitter برای فایل‌های Rust تغییریافته ✅. **`cargo
  build`/`cargo test` در این نوبت اجرا نشد — Rust `NOT TESTED`؛** اجرای واقعی
  روی ویندوز (build-windows.bat) یا CI لازم است.
- Rollback: revert این پچ؛ APIهای قدیمی scanner امضای قبلی خود را دارند،
  پس هیچ caller دیگری آسیب نمی‌بیند.

## [Unreleased] — Restoring `.cargo/config.toml`, the third lost file (۲۰۲۶-۰۹-۱۳) — `PARTIAL_UNVERIFIED`

- **`.cargo/config.toml` بازسازی شد** — سومین فایلی که آپلود squash جا گذاشت
  (بعد از `.gitignore` و `.github/workflows/`). بدون آن، روی ماشینی که
  `WINDIVERT_PATH` از قبل در محیطش ست شده (از یک پروژهٔ دیگر) و به پوشهٔ
  ناموجود اشاره می‌کند، **هر** دستور cargo با این panic می‌میرد:
  `windivert-sys-0.9.3/build/main.rs:22` → `fs::read_dir(&lib_path).unwrap()`
  → `Os { code: 3, kind: NotFound }`. خودِ ریپو این را پیش‌بینی کرده بود:
  `build-windows.bat:28-29` می‌گوید این فایل متغیر را force می‌کند، و
  `docs/archive/AUDIT_LINE_BY_LINE.md:63` عیناً همین panic را مستند کرده.
  محتوا دقیقاً همان نسخهٔ نهایی شاخهٔ خواهر است
  (`docs/archive/GAPS_2026-09.md:285`):
  `WINDIVERT_PATH = { value = ".", force = true, relative = true }` — یعنی
  force هر مقدار کهنهٔ محیطی را بازنویسی می‌کند و `.` به ریشهٔ ریپو resolve
  می‌شود، همان‌جا که `fetch-windivert.ps1` سه فایل رسمی را می‌گذارد.
  با این فایل `build-windows.bat` دوباره end-to-end کار می‌کند.
- **پیامد برای CI**: چون `WINDIVERT_PATH` حالا force می‌شود، build script
  وارد شاخهٔ کپی می‌شود و روی runner تمیز (که سه فایل را ندارد) لینک شکست
  می‌خورد — مگر اینکه job اول `scripts/fetch-windivert.ps1` را اجرا کند.
  jobهای ویندوزی `ci.yml`، `build-windows.yml` و `release.yml` بنابراین یک گام
  fetch گرفتند (`e2e.yml` از قبل داشت). آن تغییر در کامیت دنبال‌کننده است که
  مثل بقیهٔ فایل‌های workflow بدون scope ‏`workflows` قابل push نیست.
- تأیید در این checkout: تغییری در `src/` نیست، پس
  `python3 tools/gen_status.py --check` (۴۲ ماژول/۴۴۸ تست/۰ تابع مرده) و
  `python3 tools/lint_docs.py` (۰ نقص) و `cd uitest && npm test`
  (۳۷۵ پاس/۰ شکست) بدون تغییر سبز می‌مانند. خودِ رفع روی ویندوز واقعی تأیید
  شده است (همان panic گزارش‌شده دیگر تولید نمی‌شود) ولی build کامل همچنان
  `NOT TESTED` در این sandbox است چون toolchain Rust اینجا قابل نصب نیست.
- Rollback: حذف این فایل همان panic کهنه را برمی‌گرداند؛ تنها راه امن‌تر،
  ست‌کردن دستی `WINDIVERT_PATH` به ریشهٔ ریپو قبل از هر cargo است.

## [Unreleased] — `main.rs` dead WFP spec calls (۲۰۲۶-۰۹-۱۲) — `PARTIAL_UNVERIFIED`

- **`src/main.rs` — سه فراخوانی مرده حذف شد** (پیش‌تر خط‌های ۷۶۹-۷۷۱):
  `init_wfp_hook_spec()`، `dns_protection_filters()` و
  `block_port_53_except_localhost_spec()` با `let _ =` صدا زده می‌شدند. این‌ها
  سازندهٔ خالص struct هستند (بدون فراخوانی BFE، بدون side effect، بدون
  `Result`)، پس نتیجه‌شان بلافاصله دور ریخته می‌شد و هیچ چیزی نصب نمی‌شد.
  نصب واقعی WFP در همان تابع با `_dns_wfp_guard` انجام می‌شود و مسیر شکستش
  `exit(1)` است (fail-closed).
  خطر واقعی همین بود که این سه خط **کنار** `log::info!("plaintext DNS
  protection is active")` نشسته بودند و باربرینگ به نظر می‌رسیدند: اگر
  رفکتور بعدی guard واقعی را حذف می‌کرد و این‌ها را نگه می‌داشت، محافظت خاموش
  می‌شد ولی log ادعای فعال بودن می‌کرد — همان الگوی K-4/F-05 که خود پروژه قبلاً
  باگ اعلام کرده. جای آن‌ها اکنون کامنتی است که صریحاً می‌گوید آن log صحتش را
  از `_dns_wfp_guard` می‌گیرد و اگر جابه‌جایش کنید باید log را هم ببرید.
- **بررسی شد که باگ زودهنگام drop نیست.** چون `dns_guard.rs:75` هشدار می‌دهد
  drop شدن `WfpGuard` همهٔ فیلترها را حذف می‌کند، scope این binding مستقیماً از
  روی کد خوانده شد: `_dns_wfp_guard` یک binding مستقیم در بدنهٔ
  `backend_main()` است (خط ۵۲۴، match تا خط ۵۳۳ بسته می‌شود) و تا انتهای تابع
  (خط ۱۲۰۲) زنده می‌ماند، یعنی **بعد از** `engine::capture_loop` در خط ۸۱۹.
  محافظت هنگام capture برقرار است.
- هر سه تابع با حذف این فراخوانی‌ها **مرده نشدند**: هر سه همچنان توسط تست‌های
  واحد خودشان در `dns_guard.rs` (خط‌های ۶۷۰، ۶۷۵، ۶۸۵) صدا زده می‌شوند.
  `tools/gen_status.py` این را تأیید می‌کند: **۰ تابع مرده، ۴۴۸ تست** بدون
  تغییر. فقط شمار خط ماژول `main` از ۱۳۹۳ به ۱۴۰۸ رفت و `TEST_MATRIX.md` /
  `tools/status.json` با خود ژنراتور بازتولید شدند (نه دستی).
- تأیید در این checkout: `cd uitest && npm test` → **۳۷۵ پاس، ۰ شکست**؛
  `python3 tools/gen_status.py --check` و `python3 tools/lint_docs.py` →
  ۰ نقص؛ `git diff --check` → ۰.
- **محدودیت:** این ویرایش با `cargo build` کامپایل‌چک **نشده** —
  `static.rust-lang.org`، `sh.rustup.rs` و `static.crates.io` در این محیط با
  `SSL_ERROR_SYSCALL` مسدود هستند، پس هیچ toolchain جدیدتر از Rust ۱.۷۵ِ apt
  قابل نصب نیست و build کامل به‌دلیل نیاز `icu_normalizer_data` به
  `edition2024` (Rust ≥ ~۱.۸۵) ممکن نیست. ریسک سینتکسی این ویرایش عملاً صفر
  است (حذف سه statement کامل + افزودن کامنت؛ خالص دلیمیترها `(0,0)`)، ولی صحت
  کامپایل جایگزین نمی‌شود.
- Rollback: `git revert` این کامیت. بازگرداندن سه خط مرده بی‌ضرر ولی گمراه‌کننده
  است؛ کامنت توضیحی را نگه دارید.

## [Unreleased] — Restoring `.github/workflows/` and `.gitignore` after the squash upload (۲۰۲۶-۰۹-۱۲) — `PARTIAL_UNVERIFIED`

این ریپو (`sni-spoof-new--alpha-3.12`) با یک کامیت squash شده ساخته شده
(`9c1236d` «Add files via upload»). آن آپلود **سورس سخت‌شده را آورد ولی دو چیز
را نیاورد**: پوشهٔ `.github/workflows/` و فایل `.gitignore`. هر دو در شاخهٔ
خواهر (`sni-spoof-new--alpha-3`) وجود داشتند — `SENTRY_REPORT.md` و
`CHANGELOG.md:39` و `ci/README.md` همه به آن‌ها ارجاع می‌دهند — ولی در این
checkout غایب بودند، بنابراین README/SENTRY به فایل‌هایی لینک می‌دادند که
وجود نداشت.

- **`.gitignore` restored** — `DONE` (verified in this checkout). بدون آن
  `uitest/test-resilience.mjs` با `ENOENT` کرش می‌کرد و **۶۰ چک بی‌صدا از
  `npm test` حذف می‌شد** (خروجی `npm test` هنوز ۰ بود چون سوئیت‌های بعدی
  اجرا نشدند). علاوه بر آن، بدون این فایل اولین `git add -A` توکن Web UI
  (`dpi_guard.toml`)، کش DNS حاوی IP سرورها (`dpi_guard.dns_cache`)،
  `dpi_guard.proxy_state` و باینری درایور WinDivert را کامیت می‌کرد.
  محتوا از شواهد خود ریپو بازسازی شد، نه حدس: `src/dns_cache.rs:46`،
  `src/observability.rs:110`، `README.md:448`، `CHANGELOG.md:203`،
  `fuzz/README.md`، هدر `scripts/fetch-windivert.sh`.
  `dpi_guard.toml.example` عمداً با `!` مستثنا شد چون `src/config.rs:1105`
  آن را از `CARGO_MANIFEST_DIR` می‌خواند و باید tracked بماند.
  مدرک: `git check-ignore -v` روی ۱۳ مسیر حساس → همه ignore؛
  `git ls-files --error-unmatch dpi_guard.toml.example` → هنوز tracked.
- **uitest suite** — `DONE`. با بازگشت `.gitignore` کل سوئیت سبز شد:
  ۱۱۰ + ۵۶ + ۶۷ + ۶۰ + ۵۶ + ۲۶ = **۳۷۵ پاس، ۰ شکست** — همان عددی که
  `SENTRY_REPORT.md:66` ادعا می‌کرد و در این checkout قابل بازتولید نبود.
- **`tools/lint_docs.py` — دو باگ واقعی رفع شد** — `DONE` (verified both
  directions). (۱) `check_repo_identity` با `.split(".")[0]` نام ریپو را در
  **اولین نقطه** قطع می‌کرد، پس برای ریپویی که نامش نقطه دارد
  (`sni-spoof-new--alpha-3.12`) حتی لینک *صحیح* به همین ریپو را به‌عنوان
  «لینک به ریپو بیگانه» گزارش می‌کرد — این چک هرگز نمی‌توانست پاس شود.
  اکنون فقط پسوند `.git` حذف می‌شود. (۲) `check_workflow_paths` فرض می‌کرد هر
  منبع `Copy-Item` باید فایل کامیت‌شده باشد؛ مسیرهایی که `.gitignore` *عمداً*
  آن‌ها را exclude می‌کند (`WinDivert.dll`/`WinDivert64.sys` که در زمان اجرا
  توسط `scripts/fetch-windivert.ps1` با پین SHA-256 گرفته می‌شوند) از قاعده
  مستثنا شدند. هر دو اصلاح با تست رگرسیون منفی تأیید شد: لینک به
  `sni-spoof-new-5.6` هنوز گرفته می‌شود و `Copy-Item` یک فایل واقعاً غایب
  هنوز گزارش می‌شود.
- **`README.md` repo identity** — `DONE`. سه لینک که به
  `lqbw9yw8/sni-spoof-new--alpha-3` اشاره می‌کردند به همین ریپو
  (`--alpha-3.12`) اصلاح شدند؛ `tools/lint_docs.py` اکنون
  **۰ نقص (۷ چک، ۸۲ فیلد Settings)** می‌دهد.
- **پنج workflow در `.github/workflows/` بازسازی شد** — `UNTESTED`. این‌ها از
  روی مشخصات `SENTRY_REPORT.md` (S-01، S-04، S-05، S-06) و قالب‌های `ci/`
  نوشته شدند: `ci.yml` (fmt/build/test/clippy روی سه OS + audit/deny + jsdom +
  docs parity)، `build-windows.yml` (آرتیفکت + SHA-256)، `fuzz.yml` (هر سه
  تارگت با بودجهٔ زمانی محدود، کرش = شکست job، آپلود corpus/crash حتی هنگام
  شکست)، `release.yml` (امضای **اجباری**)، `e2e.yml` (pktmon +
  `scripts/assert-e2e-pcap.py`).
  **هیچ‌کدام اجرا نشده‌اند.** تنها چیزی که اینجا verify شد ساختار است:
  هر ۵ فایل با یک پارسر واقعی YAML پارس شدند و `runs-on`/`steps`/`uses|run`
  دارند. در `release.yml` این نامتغیرها به‌صورت مکانیکی بررسی شدند: ترتیب
  secrets-gate → verify → stage → publish، نبودِ هر
  `continue-on-error`/`if: always()` بین verify و publish (تنها `always()`
  پاک‌سازی گواهی است، قبل از staging)، و نبودِ هر `upload-artifact` که بتواند
  بدون امضا چیزی منتشر کند.
- **محدودیت صریح** — این محیط `cargo`/`rustc`/`rustup`/`rustfmt` ندارد، پس
  **هیچ** build/test/clippy/fmt راستی اینجا اجرا نشد و هیچ نتیجهٔ Rust از
  سوئیت jsdom استنتاج نشده. اجرای واقعی workflowها هم به توکنی با scope
  `workflows` نیاز دارد — همان محدودیتی که در
  `docs/BAZARSI_2026_AUDIT.md:29` مستند شده و دلیل اصلی گم‌شدن این فایل‌هاست.
  تا زمانی که خروجی واقعی Actions ضمیمه نشود، وضعیت‌ها باید
  `[UNVERIFIED]`/`UNTESTED` بمانند.
- Rollback: `git revert` این کامیت. حذف `.gitignore` سوئیت تست را دوباره
  می‌شکند و فایل‌های runtime حساس را قابل کامیت می‌کند، پس اگر workflowها را
  نمی‌خواهید فقط `.github/` را بردارید، نه `.gitignore` را.

## [Unreleased] — DNS enforcement and resolver hardening (۲۰۲۶-۰۹-۱۲) — `PARTIAL_UNVERIFIED`

- `src/dns_guard.rs` now contains real `Fwpuclnt.dll` FFI: one dynamic BFE
  transaction installs IPv4/IPv6 loopback permits and port-53 block filters;
  `WfpGuard` deletes them on normal shutdown and the dynamic session cleans
  them after a crash. `trusted_dns` packet redirection remains `[UNVERIFIED]`
  because it needs a signed kernel callout.
- `src/doh.rs` now uses a per-attempt `ureq::Agent` resolver. The built-in
  `cloudflare-dns.com` endpoint keeps the TLS certificate/SNI hostname but
  uses pinned `1.1.1.1`/`1.0.0.1` addresses; custom endpoint `SocketAddr`s
  are resolved once, filtered with `netguard` before ureq connects, and
  redirects are disabled. There is no second lookup after validation.
- Windows `engine::version_check` now fails closed when the ordered DLL/SYS
  SHA-256 pin list is empty; presence-only driver loading is removed.
- `rotate_ips` is now a real relay-mode round-robin over validated,
  operator-supplied destination IPs; transparent flows deliberately keep their
  established 4-tuple. The setting is no longer an inert warning.
- Verification in this checkout: `cd uitest && npm test` passed (all six
  suites); `python3 tools/gen_status.py --check`, `python3 tools/lint_docs.py`,
  `git diff --check` passed. Rust `cargo`/`rustc` are absent (`NOT TESTED`),
  and Windows/BFE/WinDivert E2E is `[UNVERIFIED]`.
- Rollback: revert this changelog entry together with the source/docs patch;
  do not remove the signed-driver pins or restore presence-only loading in a
  deployed Windows binary.

## [Unreleased] — SENTRY audit hardening (۲۰۲۶-۰۹-۱۱) — `PARTIAL_UNVERIFIED_RUST`

- فعال‌سازی workflowهای واقعی در `.github/workflows/` برای CI، Windows build،
  E2E و semver release؛ artifact ویندوز checksum دارد و WinDivert جدا می‌ماند.
- `tools/gen_status.py --check` و `tools/lint_docs.py` برای جلوگیری از drift
  آمار/لینک/بایگانی؛ README به repo canonical و ۸۲ فیلد هماهنگ شد.
- جلوگیری از legacy IPv4 SSRF forms، pinهای ordered DLL/SYS، سقف و پاک‌سازی
  QuicPortMapper، و parse/checksumهای length-safe؛ regression XSS در jsdom.
- `tools/gen_status.py` اکنون **۴۴۸ تست و ۴۲ ماژول** Rust اعلام می‌کند؛ baseline
  قبلی ۴۳۱/۴۳۱ سبز بود و ۱۷ تست/تغییر جدید این دور [UNVERIFIED] مانده‌اند.
- Rust build/test جدید در محیط این نشست اجرا نشد: `cargo` و `rustup` نصب نبودند
  و crates.io/static.rust-lang.org با `SSL_ERROR_SYSCALL` در دسترس نبودند.
- jsdom پس از regressionهای XSS، raw-TOML confirmation و boot از ۳۶۹ به **۳۷۵/۳۷۵** رسید.

## [Unreleased] — ممیزی Master Prompt V2 (۲۰۲۶-۰۹-۰۹) — `FIXED_AND_VERIFIED`

نشست ممیزی جنایی (Master Prompt V2) دور NestedCloak را با اجرای واقعی
`cargo test` راستی‌آزمایی کرد: **۹ شکست** پیدا شد که ریشهٔ همه در ۴ باگ
ریاضی/رمزنگاری بود. همه رفع و با ۳ تست رگرسیون جدید تثبیت شدند.

### Fixed — باگ‌های بحرانی مسیر تولید (راستی‌آزمایی‌شده با بردارهای RFC)
- **`hpke.rs::Fe::sub`** — بایاس‌های اشتباه ۶۴-بیتی (نه مضرب p، نه در
  محدوده) → panic سرریز در تمام X25519. بازنویسی کامل: کانونیکال‌سازی +
  زنجیرهٔ قرض i128 + تصحیح −۱۹ با انتشار بین‌اندامی. `DONE` (بردار
  RFC 7748 §6.1 سبز شد).
- **`hpke.rs::poly1305_mac`** — ضریب fold اشتباه ×5 به‌جای ×20 (نرادیکس
  2^44: B³ ≡ 20) + `u128::from_le_bytes` روی برش ۸ بایتی. `DONE`
  (بردار RFC 8439 §2.5.2 و §2.8.2 سبز شدند).
- **`hpke.rs::Fe::to_bytes`** — شمارش دوباره بیت‌های بالای اندام + بُرش
  بیت‌های ≥2^256 → کدگذاری چند-اندامی همیشه غلط. `DONE` (تست خواص جبری).
- **`fragmentation.rs::tls_record_split_mid_sni`** — تقسیم کف به‌جای سقف
  → برش وسط نام غلط. `DONE` (تست straddle سبز شد).
- **`pipeline.rs`** — نتیجهٔ `build_outer_sni_for_ech` دور ریخته می‌شد
  (فراخوانی مرده روی سیم). `DONE`.

### Fixed — کیفیت و هماهنگی
- ۹ خطای `clippy -D warnings` در ۴ فایل (وضعیت قبلی: BUILD FAILED).
- `cargo fmt --check` روی ۲ فایل (وضعیت قبلی: FAILS).
- `dpi_guard.toml.example`: `rotate_ips` و `trusted_dns` مستند شدند
  (F-04)؛ نکتهٔ اعتبارسنجی `trusted_dns` در خود فایل.

### Added
- ۳ تست رگرسیون: `fe_algebraic_properties_hold`،
  `fe_sub_borrow_wraps_correctly`،
  `shipped_toml_example_parses_and_documents_partial_fields`.

### نتیجهٔ نهایی این دور
`cargo test --all-targets` → **۴۲۷/۴۲۷ پاس** · clippy → **۰** · fmt →
**پاک** · jsdom → **۳۶۹/۳۶۹** · `gen_status.py` → **۴۱ ماژول، ۴۲۷ تست،
۰ تابع مرده**. برای جزئیات `STATUS.md` بخش ممیزی ۰۹-۰۹.

---

## [Unreleased] — نقشهٔ راه ۲۰۲۶: پروفایل NestedCloak + شش تکنیک جدید (IMPLEMENTED — در انتظار `cargo test`)

> **⬆️ به‌روزرسانی:** آزمون‌ها اکنون اجرا شدند — ۹ شکست پیدا و رفع شد؛
> وضعیت این دور به `FIXED_AND_VERIFIED` تغییر کرد. (ورودی بالا)

این دور «نقشهٔ راه ارتقای موتور» به‌صورت واقعی در کد پیاده شد — نه فقط
مستندسازی. تمام تغییرات با `tools/gen_status.py` تأیید استاتیک شدند
(**۴۱ ماژول، ۴۲۳ تست تعریف‌شده، ۰ تابع مرده، ۸۲ فیلد تنظیمات ↔ ۸۲ کنترل
UI، ۰ فیلد بی‌خواننده**)؛ اجرای `cargo test`/`clippy` در این نشست ممکن
نبود (بدون دسترسی به toolchain) و باید در اولین بیلد ویندوزی/CI دویده شود.

### Added — پروفایل «پوشش تو در تو» (Nested Extension Cloaking)
- **پروفایل هفتم `NestedCloak`** در `sni_mutations.rs` (در همهٔ فهرست‌ها:
  `ALL`، `FromStr`، وب‌سایت، داشبورد بومی، وب‌یوآی).
- **`fragmentation::nested_cloak`**: SNI پوششی بی‌خطر به‌جای `0x0000`
  + نام واقعی دست‌نخورده در افزونهٔ خصوصی `0xFF01` (fronting + hidden ext
  در یک تابع).
- **`fragmentation::nested_cloak_split_offsets`**: نقاط برش برای چیدمان
  کلاسیک ۳ بخشی: `[سرپوش] → [هدر افزونهٔ مخفی + ۳۲ بایت اول نام] → [بقیهٔ
  نام]`؛ اندازهٔ تکه دقیقاً `min(32, len(SNI))` و نام‌های ۱ بایتی به دو
  بخش جمع می‌شوند.
- سیم‌کشی کامل در `pipeline.rs`: آفست‌ها روی رکورد **نهایی** (بعد از
  geedge/پدینگ) محاسبه می‌شوند؛ پروفایل `enable_combined_fragmentation` را
  حتی اگر خاموش باشد **الزامی** می‌کند و `disorder` برایش همیشه روشن است.
- پوشش پیش‌فرض تصادفی از فهرست `NESTED_COVER_SNIS` وقتی
  `fronting_benign_sni` تنظیم نشده باشد.

### Added — شش تکنیک نقشهٔ راه
1. **برش رکورد TLS وسطِ نام (`enable_frag_mid_sni`)** —
   `fragmentation::tls_record_split_mid_sni`: نام بین دو رکورد `0x16`
   سالم پاره می‌شود؛ هیچ رکوردی نام کامل را ندارد.
2. **بادکردن پدینگ با طول تصادفی (`enable_padding_inflation`)** —
   `geedge::inflate_padding_random`: پدینگ ۶۴ تا ۳۸۴ بایتی تصادفی در هر
   اتصال (شکستن اثرانگشت‌های اندازهٔ ثابت مثل شکل ۵۱۷ بایتی).
3. **ECH-GREASE همیشگی با نوع واقعی `0xFE0D`** —
   `ech::inject_ech_grease_fe0d`: هر هللو یک افزونهٔ `0xFE0D` با payload
   تصادفی ۶۴ تا ۱۶۰ بایت می‌گیرد؛ طبقه‌بندی «ECH دارد/ندارد» بی‌اثر
   می‌شود. (فقط وقتی `enable_ech_grease` روشن و ECH واقعی خاموش باشد.)
4. **چرخش استراتژی هر اتصال (`enable_strategy_rotation`)** —
   `strategy::StrategyTable::select_rotating`: انتخاب تصادفیِ وزن‌دار بین
   تکنیک‌های برنده برای آن دامنه؛ اگر هیچ برنده‌ای نباشد همان رفتار قطعی
   قبلی.
5. **ECH واقعی (`enable_real_ech` + `real_ech_config_hex`)** —
   `ech::seal_real_ech_hello`: نام واقعی داخل ClientHello داخلی با
   **HPKE واقعی** مهر می‌شود؛ بیرون فقط `public_name` دیده می‌شود. پشتهٔ
   رمز بدون وابستگی جدید در ماژول تازهٔ **`hpke.rs`** پیاده شد:
   X25519 (RFC 7748)، HMAC/HKDF-SHA256 (RFC 5869 روی `sha2`)،
   ChaCha20-Poly1305 (RFC 8439) و KeySchedule حالت پایهٔ RFC 9180 —
   هر کدام با بردارهای تست رسمی RFC. قالب سیمی طبق **RFC 9849** (نسخهٔ
   نهایی استاندارد) و راستی‌آزمایی‌شده با کد مرجع BoringSSL و NSS: بدنهٔ
   افزونه `kdf|aead|config_id|enc|payload`، هدر داخلی با سشن‌آیدی خالی +
   مارکر `0xFE0D→0x01` + پدینگ صفر تا مضرب ۳۲، `info = "tls ech\0"||ECHConfig`
   و AAD = کل بدنهٔ هلوی بیرونی با بایت‌های payload صفرشده. تست دوررفت
   کامل (رمزگشایی سمت سرور) دارد. نیازمند سرور مقصد با پشتیبانی ECH.
6. **حلقهٔ بازخورد تطبیقی تقویت‌شده** — `strategy::decay_all` (پوسیدگی
   امتیازها هر ۳۲ رخداد بازخورد)، نردبان ارتقای
   `strategy::ESCALATION_LADDER`/`next_rung` (وقتی پروفایل پیکربندی‌شده
   امتیاز منفی گرفت، اتصال بعدی یک پله بالاتر می‌رود).

### Changed
- `pipeline.rs`: انتخاب پروفایل از `select_best` خالص به مسیر دوگانهٔ
  «چرخش/ارتقا وقتی روشن است، قطعی وقتی خاموش» تغییر کرد؛ بلوک
  fronting/disguise حالا شاخهٔ اولش NestedCloak است.

### Fixed — سازگاری بین‌تکنیکی (حسابرسی هماهنگی)
- **نشت نام واقعی در ترکیب NestedCloak + ECH واقعی**: افزونهٔ مخفی
  `0xFF01` در هلوی بیرونیِ مهرشده به‌صورت متن آشکار باقی می‌ماند؛ حالا
  مهر واقعی وقتی مسلح باشد کلاک اجرا نمی‌شود و `seal_real_ech_hello` هم
  `0xFF01` را از هر دو هلو (داخلی/بیرونی) حذف می‌کند.
- **ترتیب مُهر واقعی**: مُهر باید آخرین تغییر هللو باشد چون AAD کل هلوی
  بیرونی را پوشش می‌دهد؛ بلوک‌های uTLS/Geedge/پدینگ تصادفی وقتی
  `enable_real_ech` روشن است اجرا نمی‌شوند و مُهر بعد از همهٔ تغییرات می‌نشیند.
- **بازخوانی تنبل کانفیگ ECH در هات‌ریلود**: اگر پرچم بعد از ساخت
  پایپ‌لاین روشن شود، کانفیگ دوباره پارس می‌شود به‌جای اینکه مُهر برای
  همیشه بی‌صدا بپرد.
- **قالب افزونهٔ ECHClientHello**: شناسه‌های suite که در پیاده‌سازی اولیه
  جا افتاده بود اضافه شد و ترتیب فیلدها با RFC 9849 یکی شد.
- `.gitignore` وجود نداشت (تست `test-resilience` شکست می‌خورد و
  `node_modules` در git می‌نشست)؛ ساخته شد.
- فهرست پروفایل‌ها در `webui.rs`، `webui/index.html`، `native_gui.rs` و
  `uitest/mock-server.mjs` به‌روز شد (۷ پروفایل).

### تست‌ها
- ۴۰ تست جدید: ۹ در `fragmentation`، ۱۰ در `hpke` (بردارهای رسمی
  RFC 7748/5869/8439/9180)، ۴ در `ech`، ۵ در `strategy`، ۲ در `geedge`،
  ۴ در `sni_mutations`، ۲ در `config`، ۴ در `pipeline`.

## [Unreleased] — گیت‌های کامل CI سبز شد (TESTS_EXECUTED)

این دور تمام پنج گیت `ci/github-actions.yml` واقعاً اجرا و سبز شد
(Rust 1.98.1 stable، لینوکس): `cargo fmt --all -- --check` ✓،
`cargo check --all-targets` → **۰ خطا / ۰ هشدار**، `cargo test --all-targets`
→ **۳۸۳ پاس / ۰ شکست**، `cargo clippy --all-targets -- -D warnings` ✓،
`npm test` (uitest) → **۳۶۹ پاس / ۰ شکست**.

### Fixed — `VERIFIED` (اجرا شده روی Rust 1.98.1)
- **ادعای قبلیِ «صفر هشدار» ناقص بود** — `cargo check --all-targets` هنوز ۳ هشدار داشت که در چک‌های قبلی از قلم افتاده بود:
  - **`dns_cache.rs`**: فیلد هرز `DnsCache.ttl` (هرگز خوانده نمی‌شد؛ تازگی per-entry جایگزینش شده بود) و سازندهٔ بلااستفادهٔ `with_ttl` حذف شدند؛ دلیل طراحی per-entry در کامنت مستند شد.
  - **`main.rs`**: `ProxyRestoreGuard` فقط داخل `backend_main` ویندوزی arm می‌شود و به `proxy_cleanup` فقط-ویندوزی وصل است — با `#[cfg(windows)]` گیت شد تا چک غیر-ویندوزی هم بدون هشدار باشد (رفتار ویندوزی بدون تغییر).
  - **`pipeline.rs`**: نام تست `hold_watchdog_preserves_original_winDivert_address_semantics` به snake_case اصلاح شد.
- **۱۰ ماسک `#[allow(unused_imports)]`** در geedge/scanner/client_detect/mobile_gateway/proxy_cleanup/engine برداشته شد: ۶ ایمپورت واقعاً مرده حذف (`Rng`، `DpiGuardError` ×۳، `ToSocketAddrs` — که بعداً با تست کامپایل برگشت، `CloseAction`، `Path`) و بقیه بدون ماسک نگه داشته شدند.
- **۴۸ هشدار clippy صفر شد** (گیت CI `-D warnings` می‌بست و قرمز می‌ماند):
  - ۲۰ × `field_reassign_with_default` → سینتکس struct-update (`..Default::default()`) در تست‌های lib/config/main/pipeline/webui/native_gui.
  - ۱۲ × `doc_list_item_without_indentation` → تورفتگی ادامه‌بندهای لیست در `strategy.rs`/`geedge.rs`.
  - ۴ × `&mut Vec` → `&mut [_]` در `packet.rs`/`sequence.rs`/`engine_stub.rs` (بدون تغییر رفتار؛ صدا زننده‌ها با coerce خودکار).
  - ۲ × `type_complexity` → الیاس `ResolvedSlot` در main.rs و `MutationFn` در sni_mutations.rs.
  - `manual_clamp` در autottl.rs و `chunks_exact_to_as_chunks` در packet.rs::checksum_rfc1071 (کدجنریشن هم‌ارز).
  - ۴ × `too_many_arguments` با `#[allow]` مستند (امضاهای ۸-پارامتری آینهٔ فلگ‌های سیم TCP هستند؛ refactor ساختار ریسک بی‌مورد دارد).
- **`cargo fmt`** دو انحراف فرمت (fragmentation.rs از clippy-fix و derive دوخطی proxy_cleanup.rs) نرمال شد.

### Fixed — تست‌های داشبورد (uitest، `VERIFIED`)
- **`test-v2rayn.mjs`**: regex پارسِ `default_relay_listen_port`/`default_web_ui_port` فقط بدنهٔ تک‌خطی می‌پذیرفت در حالی که `cargo fmt` (گیت CI) همان بدنه را چندخطی می‌کند — regex به `\s*` تساهل‌پذیر شد و تست «parsed … — got NaN» پاس شد.
- **`test-resilience.mjs`**: دو regex کهنه به API فعلی سورس به‌روز شد — `DnsCache::load` چندخطی در doh.rs و `insert_with_ttl` (TTL authoritative) به‌جای `insert` ساده.
- **`.gitignore`** (شکاف واقعی حریم خصوصی): فایل‌های runtime که کنار exe بیلد-محلی نوشته می‌شوند و IP/آدرس سرور دارند (`dpi_guard.dns_cache`، `dpi_guard.proxy_state`، `dpi_guard.instance.lock`) commit‌نشدنی شدند — تست «the cache file is gitignored» همین را گِرد می‌کرد.
- **`test-settings.mjs`**: فهرست انتظاریِ فیلدهای restart-required ۴ فیلد اسکنر (`edge_candidates`، `enable_sni_scanner`، `sni_candidates`، `sni_rotation_mode`) را کم داشت — راستی‌آزمایی شد که `backend_main` این‌ها را فقط هنگام بوت می‌خواند، پس تگ‌گذاری schema درست است و فهرست تست به‌روز شد (۱۹ فیلد).

## [Unreleased] — ممیزی معماری ۲۰۲۶-۰۹ (TESTS_EXECUTED)

این دور اولین باری است که سوئیت روی کامپایلر واقعی اجرا شده است
(Rust 1.98.1 stable، لینوکس): `cargo test` → **۳۸۳ پاس / ۰ شکست**،
`cargo clippy --all-targets` → **۰ خطا**، `gen_status.py` →
**۴۰ ماژول، ۳۸۳ تست، ۰ تابع مرده**.

### Fixed — `VERIFIED` (اجرا شده روی Rust 1.98.1)
- **`geedge.rs::prepend_grease_extensions`** (بحرانی): طول handshake سه‌بایتی به‌اشتباه به‌صورت u16 بروزرسانی می‌شد (`delta<<8`) و ClientHello خروجی مسیر پیش‌فرض `enable_geedge_evasion` برای هر سرور واقعی خراب بود. وصلهٔ u24 با `checked_add` و خطای صریح. تست رگرسیون: `grease_prepend_keeps_record_parseable`، `padding_after_grease_keeps_record_parseable`.
- **`pipeline.rs::on_inbound`** (بحرانی): ServerHello ورودی entry جدول `recent` را مصرف نمی‌کرد — هر segment تکراری یک `+1` دیگر به استراتژی می‌داد. اکنون با `remove()` یک تلاش = حداکثر یک امتیاز. تست `inbound_serverhello_scores_once` پاس شد.
- **`pipeline.rs` MD5SIG**: آپشن TCP 19 در آفست ثابت `l4+20` نوشته می‌شد و با هدرهای دارای options واقعی (MSS/timestamps) داخل آپشن‌ها/پیلود می‌نوشت. اکنون آفست padding از data-offset پکت wrap‌شده محاسبه می‌شود.
- **`scanner.rs::probe_tls_handshake`**: علاوه بر `0x16`، handshake-type `0x02` (ServerHello واقعی) در بایت ۶ اعتبارسنجی می‌شود؛ رکورد ساختگی middlebox دیگر «سالم» شمرده نمی‌شود.
- **`native_gui.rs`**: نقض قرض‌گیری در دکمهٔ «⚡ Test & Select Lowest Ping Target» (E0500) که کامپایل GUI را می‌شکست.
- **`engine_stub.rs`**: تست `capture_loop` با امضای قدیمی ۳-آرگومتری (E0061).
- **`main.rs`**: تست `redact_lan_and_rewrites_guarantees` برای فرمت فعلی `ep-`+۱۶hex.
- **`quic.rs`**: importهای بلااستفاده (E0433 در بیلد تست).
- **`webui.rs`**: تجمیع کامل هدرهای fragment‌شده قبل از parse (قبلاً Content-Length داخل segment دوم گم می‌شد) + رد صریح `Transfer-Encoding: chunked` با 501.
- **`singleton.rs`**: `truncate(false)` صریح روی هر سه باز فایل قفل + حذف ثابت مردهٔ `LOCK_SH`.
- **`mobile_gateway.rs`**: مقایسهٔ همیشه‌درست `count >= 0` (clippy deny) با نامساوی معنادار.

### Added — `VERIFIED`
- **تقسیم ۱-۲ بایتی TCP روی SNI در مسیر زنده**: `packet::tcp_segment_payload_at_offsets` + سیم‌کشی به `enable_frag_by_sni` (بدون reframing) در `pipeline.rs::apply_client_hello` با seq پیوسته و fallback امن. تست: `frag_by_sni_emits_tcp_one_byte_split`.
- **TTL واقعی DNS**: `doh::parse_a_records` کمینهٔ TTL رکوردهای A را برمی‌گرداند (کف ۳۰s، سقف `MAX_STALE`)؛ `dns_cache::insert_with_ttl` و تازگی per-entry؛ ستون چهارم در فایل کش با سازگاری کامل با فایل‌های ۳-ستونی قدیمی. تست‌ها: `ttl_floor_and_cap_are_applied`، `per_entry_ttl_overrides_default`.
- **توقف نرم بک‌اند از GUI**: فایل `<config>.stop` توسط watcher (چرخهٔ ≤۲۰۰ms) خوانده می‌شود و مسیر کامل graceful shutdown (WinDivert close + restore پروکسی) را اجرا می‌کند؛ دکمهٔ Stop ابتدا graceful، سپس پس از ۳s فال‌بک به kill.
- **گارد Drop بازیابی پروکسی** (`ProxyRestoreGuard` در main.rs): `restore_state` روی هر مسیر unwind/خروج زودهنگام اجرا می‌شود، نه فقط Ctrl+C.
- تست‌های جدید در این دور: ۷ (geedge ×۲، packet ×۲، pipeline ×۱، doh ×۱، dns_cache ×۱).

### Changed — `VERIFIED`
- `scanner.rs`: حذف ثابت‌های مردهٔ `SCAN_PROBES`/`SCAN_TIMEOUT` (بودجهٔ probe از caller می‌آید).
- `config.rs`: کامنت کهنهٔ «بدون TLS probe زنده» حذف و با رفتار واقعی هماهنگ شد.
- `engine.rs`: doc توالی backoff با سلوک واقعی (شروع از 40ms) هماهنگ شد.
- `main.rs`: importهای فقط-ویندوز (`engine`, `webui`, `AtomicU64`) به‌صورت `cfg(windows)` شرطی شدند.
- `native_gui.rs`: hint توکن از «empty = no token» به «empty = auto-generated token» اصلاح شد (رفتار واقعی از همیشه همین بود).

## [Unreleased] — شاخهٔ `arena/01a06e41-sni-spoof-new-5-6`

### Added
- `AI_RULES.md` — قوانین اجباری برای توسعهٔ AI-assisted
- `ARCHITECTURE.md` — گراف وابستگی تولیدشده از سورس
- `TEST_MATRIX.md` + `tools/gen_status.py` — جدول وضعیت خودکار
- `KNOWN_ISSUES.md` — مشکلات تأییدشده
- `.gitignore`
- ۱۹ تست جدید Rust (**اجرا نشده**)

### Fixed — همه `UNTESTED` (کامپایل نشده)
- `lib.rs::build_filter`: `||` → `&&`
- `webui.rs::token_ok`: رد توکن خالی
- `webui.rs::handle_conn`: حلقهٔ خواندن کراندار
- `doh.rs::parse_a_records`: بررسی مرز
- `main.rs`: `recover_mutex` به‌جای `unwrap`
- `self_update.rs`: `validate_repo_slug` + اصلاح repo + حذف ادعای SHA-256
- `singleton.rs`: حذف unlink مسابقه‌ای
- `pipeline.rs`: سقف `last_activity`/`inbound_ttl`
- `autottl.rs`: اصلاح مقیاس وارونه
- `relay.rs`: `FlowHooks` + `FlowSlot` (RAII)

### Changed
- ۱۶ سند قدیمی به `docs/archive/` منتقل شد
- `relay::run()` امضایش عوض شد: `Arc<FlowHooks>` به‌جای closure

### Verified
- `uitest`: ۳۶۹ پاس / ۰ شکست

### Not verified
- `cargo test`, `cargo clippy`, `cargo build` — `cargo` در محیط نبود
- هر رفتار مربوط به ویندوز/WinDivert

---

## تاریخچهٔ git

- `9d77955` Update audit report: all 11 findings now fixed
- `a2e8020` Fix the 5 remaining audit findings
- `8658116` Add full-project audit findings (11 issues: 6 fixed, 5 open)
- `1013c0d` Add line-by-line review report for 2026-09
- `40cdfc0` Fix filter/auth/DoH/mutex bugs found in line-by-line review
- `7a076ac` Add .gitignore so the full uitest suite runs (test-resilience no longer crashes)
- `a2ce27e` Add files via upload
