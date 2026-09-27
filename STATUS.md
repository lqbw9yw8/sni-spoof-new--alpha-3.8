# STATUS — تنها منبع حقیقت

آخرین به‌روزرسانی: ۲۰۲۶/۰۹/۲۳ · Rust last-run baseline: `07f2ddc` + ممیزی SENTRY؛ cargo/Windows هنوز `[UNVERIFIED]`

> این فایل **تنها** مرجع وضعیت پروژه است. اگر فایل دیگری ادعای مغایری
> دارد، آن فایل قدیمی است. اسناد تاریخی در `docs/archive/`.

---

## تغییرات این نوبت — ۲۰۲۶/۰۹/۲۳ — `PARTIAL_UNVERIFIED` (Rust در این محیط `NOT TESTED`)

- **رفع خطای کامپایل `E0597` در `src/scanner.rs::probe_pairs_parallel`:**
  شمارندهٔ کار (`next: AtomicUsize`) داخل حلقهٔ wave ساخته می‌شد، در حالی که
  threadهای scoped تا پایان `std::thread::scope` زنده‌اند → «borrowed value
  does not live long enough». شمارنده **بیرون** scope منتقل شد و مدل اجرا از
  «wave‌به-wave» به **یک صف مشترک با `min(total, MAX_PARALLEL_PROBES)` worker**
  تغییر کرد. حد هم‌زمانی (≤۱۶) و رفتار cancel/progress همان است: خروجی یک
  `DetailedProbeOutcome` به‌ازای هر ورودی، در همان ترتیب ورودی.
- **بازسازی کامل داشبورد وب (`src/webui/index.html`):** یک سیستم طراحی واقعی
  (توکن‌های رنگ/فاصله/شعاع/زمان در `:root`)، نوار بالای چسبان، تب‌های
  معنایی با `aria-selected`، **حذف نوار ابزار دوتایی** (`btn_save2` /
  `btn_validate2` / `btn_revert2` / `btn_live2` یک کپی از نوار اصلی بودند —
  اکنون یک نوار اقدام چسبان در پایین است)، ۳۷ کارت وضعیتِ پراکنده به **۱۶
  کارت معنادار + ۱۸ چیپ تکنیک** تبدیل شد، دو هشدارِ متنیِ بلند بالای صفحه به
  یک `<details>` جمع شد، جست‌وجو/فیلتر به نوار ابزارِ چسبانِ بالای تنظیمات
  رفت، و وضعیت روشن/خاموش به‌جای متن انگلیسیِ پراکنده، سوئیچ + برچسب فارسی
  گرفت. انیمیشن‌ها فقط روی `transform`/`opacity`/رنگ‌اند و
  `prefers-reduced-motion` همه را خاموش می‌کند؛ `:focus-visible` روی همهٔ
  کنترل‌ها حلقه دارد؛ اعداد `tabular-nums`؛ هیچ وابستگی خارجی (CSP
  `default-src 'none'`، بدون فونت/CDN).
- **الگوی ترکیب (composition) در سمت کلاینت:** چهار هندلر کپی‌شدهٔ
  «اقدام سریع» (`qa_all_on` / `qa_all_off` / `qa_stealth` / `qa_aggressive`)
  با یک جدول `PRESETS` و یک `applyPreset()` جایگزین شد — دکمه‌ها هم از همان
  جدول ساخته می‌شوند، نه در HTML دستی. فهرست پروفایل‌ها دیگر دو بار نوشته
  نشده و از `byKey.mutation_profile.opts` مشتق می‌شود. تزریقِ
  `refreshAllRows` (monkey-patch انتهای فایل) حذف و با فراخوانی مستقیم
  `refresh() = refreshRows() + updateDirtyPill() + updateFeatureCount()`
  جایگزین شد.
- **رفع تکرار در مسیر پکت (`src/fragmentation.rs` + `src/utls.rs`):** چرخهٔ
  «خواندن لیست cipher-suite → جایگشت → نوشتن مجدد» در دو ماژول کپی شده بود
  (۲۴ خط یکسان). هم‌اکنون یک `rewrite_cipher_suites<F>(record, f)` در
  `fragmentation.rs` مالک بررسی مرز و ترتیب بایت است و هر دو caller فقط
  جایگشت خود را می‌دهند. رفتار تغییر نکرده: fragmentation کل لیست را
  جابه‌جا می‌کند، uTLS سه‌تای اول (TLS 1.3) را ثابت نگه می‌دارد.
- **ابزار جدید `tools/dup_report.py`:** گزارش تکرار/افزونگی با چهار آشکارساز
  (بلوک‌های کد تکراری در `src/**/*.rs`، نام تابع تکراری، سطح تنظیمات که سه
  بار اعلام شده، پاراگراف‌های تکراری در مستندات). خروجی‌اش اندازه‌گیری
  است، نه ادعا.
- **مدرک اجرا (این محیط، ۲۰۲۶/۰۹/۲۳، آخرین اجرا):** `cd uitest && npm test` → **۳۹۸
  passed، ۰ failed** ✅ (تست‌های jsdom روی همان فایل واقعی
  `src/webui/index.html`). `python3 tools/gen_status.py` → بازتولید
  `TEST_MATRIX.md` ✅. `python3 tools/lint_docs.py` → ۰ parity violation ✅.
  `python3 tools/dup_report.py` → تکرار ۲۴ خطیِ fragmentation/uTLS حذف شد ✅.
  ⚠️ **CI:** تعریف workflowها (`ci/ci.yml`, `ci/build-windows.yml`) آماده است ولی
  `.github/workflows/` هنوز خالی است و تا این لحظه **هیچ اجرای CI/تست خودکاری
  روی این مخزن ثبت نشده** (`gh run list` خالی) — بنابراین `cargo build/test`
  برای این کد **NOT TESTED** است. جزئیات: `KNOWN_ISSUES.md` → K-9.
  کامپایل قطعه‌کدهای تغییریافتهٔ Rust با **rustc 1.88.0** روی harness
  استخراج‌شده از خودِ فایل‌ها: `probe_pairs_parallel` (۲۰ کاندید > حد هم‌زمانی،
  cancel پیشین، شمارندهٔ progress، ورودی خالی) و `rewrite_cipher_suites` + هر
  دو caller (ترتیب، چندمجموعه، خطای کوتاهیِ پکت، non-ClientHello) ✅.
  **اما `cargo` در این محیط نیست (دسترسی به crates.io مسدود است)، بنابراین
  `cargo build` / `cargo test` / `cargo clippy` روی کل crate اجرا نشد — کد
  Rust همچنان `NOT TESTED` در سطح crate است و باید روی ویندوز
  (`build-windows.bat`) یا CI اجرا شود.**

## تغییرات این نوبت — ۲۰۶/۰۹/۱۶ — `PARTIAL_UNVERIFIED` (Rust در این محیط `NOT TESTED`)

- **رفع هنگ UI هنگام اسکن (hang fix):** `src/scanner.rs` — پروب ۱۶ کاندید دیگر
  توالی نیست. موتور جدید `probe_pairs_parallel` روی worker pool با
  `std::thread::scope` اجرا می‌شود (حداکثر `MAX_PARALLEL_PROBES = 16` پروب
  هم‌زمان، wave‌به-wave). زمان کل ≈ کندترین handshake واحد (~۱.۵ s) به‌جای
  مجموع همهٔ handshakeها (~۲۴ s). APIهای عمومی قدیمی
  (`probe_and_rank_spoof_pairs`، `best_spoof_pair`) امضای بدون‌تغییر دارند و
  خودکار موازی شدند — callers در `webui.rs`/`main.rs` بدون ویرایش همان سرعت
  جدید را می‌گیرند. تابع‌های جدید: `rank_probe_pairs` (ترتیب‌بندی پایدار:
  TLS-verified اول، بعد کمترین ping)، `probe_and_rank_detailed` و
  `probe_and_rank_detailed_cancellable` (لغو زنده + شمارندهٔ progress).
- **اسکن پس‌زمینه در GUI:** `src/native_gui.rs` — دکمه‌های
  «⚡ Scan All & Show Results» و «⭐ Auto-Select Lowest Ping» اسکن را در
  `std::thread::spawn` با `mpsc::channel` اجرا می‌کنند؛ UI هرگز block
  نمی‌شود (خاموشی/Not Responding هنگام اسکن دیگر رخ نمی‌دهد). spinner +
  شمارندهٔ زنده «Scanning n/16…» هم در نوار بالا و هم در تابلوی
  Connection؛ دکمهٔ «✖ Cancel» (آتمیک: workerها پروب تازه‌ای شروع نمی‌کنند؛
  پروب‌های در حال اجرا تا سقف ۱.۵s خود را تمام می‌کنند)؛
  `catch_unwind(AssertUnwindSafe)` دور کل اسکن، پس پانیکِ thread اسکن
  نمی‌تواند UI را بکشد (به‌جای crash، پیام «Scan failed» می‌شود)؛
  `request_repaint_after(100ms)` فقط در حالت اسکن/stop فعال است وگرنه ریتم
  قبلی (۱s) برمی‌گردد.
- **Stop بدون block:** توقف backend دیگر ۳ ثانیه UI thread را ختم نمی‌کند.
  `stop()` child را به thread پس‌زمینه واگذار می‌کند (نوشتن stop-file →
  `try_wait` ×۶۰ با فاصلهٔ ۵۰ms → fallback به `kill`) و UI با `poll_stop()`
  پایان را می‌بیند. `on_exit` اگر stopی در حال پرواز باشد حداکثر ۱۰s روی
  همان thread می‌ماند، وگرنه `stop_sync` همگام کلاسیک را انجام می‌دهد.
- **جدول دامنه‌ها + انتخاب دستی:** نتایج اسکن در تابلوی Connection به‌صورت
  جدول نمایش داده می‌شود: Provider | IP | Fake SNI (domain) | Ping | TLS |
  Action. رنگ ping: سبز <۱۰۰ms، زرد <۳۰۰ms، قرمز ≥۳۰۰ms، خاکستری
  timeout/cancelled (متن رنگی؛ از emoji وابسته به فونت استفاده نشد تا در
  فونت پیش‌فرض egui tofu نشود). ردیف برتر (اولین ردیف TLS-verified) با
  «(BEST)» مشخص است. دکمهٔ «Select» هر ردیف، `relay_connect_host` +
  `relay_connect_port` + `relay_fake_sni` را پر می‌کند؛ «Auto-Select» همان
  ردیف BEST را خودکار اعمال می‌کند؛ «Clear results» جدول را خالی می‌کند.
- **تست‌های جدید (۸):** ۶ تست آفلاین موتور موازی در `scanner.rs` (نگه‌داشتن
  ترتیب ورودی + progress برای ۲۰ کاندید = دو wave، ورودی خالی، cancel پیشین
  = همهٔ slots به‌عنوان skipped، ترتیب TLS-اول-سپس-ping، ثبات مرتب‌سازی،
  ورود از APIهای عمومی) و ۲ تست GUI در `native_gui.rs` (reset کامل
  `ScanState`، ساخت variants `ScanMsg`). مجموع تست‌های اعلام‌شده: ۴۴۹ → ۴۵۷.
- **مدرک اجرا (این محیط، ۲۰۲۶/۰۹/۱۶):** `cd uitest && npm test` → **۳۷۵
  passed، ۰ failed** ✅؛ `python3 tools/gen_status.py --check` → up to date
  ✅؛ `python3 tools/lint_docs.py` → ۰ parity violations ✅؛ اعتبارسنجی
  syntax تمام فایل‌های Rust تغییریافته با parser درخت‌نحوی
  (tree-sitter-rust روی node) → بدون خطای grammar ✅. **cargo/rustc در این
  محیط موجود نیست؛ `cargo build`/`cargo test` در این نوبت اجرا نشد — کد Rust
  `NOT TESTED` است و باید روی ویندوز (build-windows.bat) یا CI اجرا شود.**

## تغییرات دور ۲۰۲/۰۹/۲

- **WFP:** `src/dns_guard.rs` از spec/stub به FFI واقعی `Fwpuclnt.dll` تبدیل شد.
  نصب چهار filter در یک transaction انجام می‌شود: permit برای `127.0.0.1` و
  `::1` و block برای outbound TCP/UDP port 53 در IPv4/IPv6. `WfpGuard` مسیر
  cleanup عادی و `FWPM_SESSION_FLAG_DYNAMIC` مسیر cleanup پس از crash را دارد.
  اجرای Windows/BFE هنوز `[UNVERIFIED]` است.
- **DoH rebinding/TLS:** `src/doh.rs` برای هر تلاش `ureq::Agent` با resolver
  سفارشی می‌سازد؛ endpoint پیش‌فرض `cloudflare-dns.com` با hostname دارای
  گواهی TLS و آدرس‌های `1.1.1.1`/`1.0.0.1` pin می‌شود، و endpointهای custom
  فقط یک بار resolve و قبل از connect با `netguard` فیلتر می‌شوند؛ redirect
  خاموش است. unit testهای source اضافه شده‌اند، ولی cargo بعد از این
  تغییرات اجرا نشده (`NOT TESTED`).
- **Driver integrity:** `src/engine.rs` بدون دو pin مرتب DLL/SYS دیگر start
  نمی‌کند. مسیر rollback عملیاتی: در صورت شکست فقط به commit قبل از این patch
  برگردید؛ presence-only loading عمداً rollback امن محسوب نمی‌شود.
- **مدرک اجرا:** `cd uitest && npm test` در این patch با **۳۷۵ passed،
  ۰ failed** پاس شد؛ `gen_status.py --check`، `lint_docs.py`،
  `git diff --check` و `python3 -m py_compile scripts/assert-e2e-pcap.py`
  نیز پاس شدند. cargo/rustc در محیط موجود نیستند و Windows/WinDivert E2E،
  fuzz و signing `[UNVERIFIED]` باقی می‌مانند.

## ⚠️ وضعیت کلی پروژه: `JS_VERIFIED_2026-09-16 / RUST_LAST_RUN_2026-09-09 / REAL_WIN_PENDING`

**توضیح وضعیت:** سوئیت کامل jsdom/Node داشبورد در همین patch در
۲۰۲۶-۰۹-۱۲ **واقعاً اجرا شد**: ۳۷۵ چک، ۰ شکست (شامل regression XSS،
raw-TOML confirmation و انتظار boot مقاوم). سوئیت Rust آخرین بار در
۲۰۲۶-۰۹-۰۹ روی
Rust 1.98.1 (لینوکس) اجرا و سبز شد؛ در محیط ممیزی ۲۰۲۶-۰۹-۱۱ **قابل اجرا
نبود** (بدون دسترسی به crates.io — جزئیات در بخش «ممیزی SENTRY»). اعداد Rust
پایین «آخرین اجرای ثبت‌شده» هستند، نه نتیجهٔ امروز.

مسیرهای وابسته به WinDivert فقط روی ویندوز اجرا می‌شوند و همچنان نیازمند
آزمون میدانی ویندوز هستند.

```bash
# آخرین اجرای ثبت‌شدهٔ Rust (لینوکس، Rust 1.98.1، ۲۰۲۶-۰۹-۰۹):
cargo fmt --all -- --check   # clean
cargo clippy --all-targets -- -D warnings   # 0 error
cargo test --all-targets     # آخرین اجرای قبل از پچ‌های SENTRY: 431 passed; 0 failed
python3 tools/gen_status.py  # current source: 42 modules, 457 tests declared, 0 dead fns

# اجرای واقعی در ممیزی ۲۰۲۶-۰۹-۱۳ این patch:
cd uitest && npm test                       # 398 passed; 0 failed  ✅
python3 tools/gen_status.py --check        # up to date            ✅
python3 tools/lint_docs.py                 # 0 parity violations   ✅

# اجرای واقعی این نوبت (۲۰/۰/۱ — cargo/rustc در محیط نبود):
cd uitest && npm test                       # 398 passed; 0 failed  ✅
python3 tools/gen_status.py --check        # up to date (457)      ✅
python3 tools/lint_docs.py                 # 0 parity violations   ✅
```

> ⚠️ عددهای ۳۴۴، ۳۶۹، ۴۲۷ و ۴۳۱ که پیش‌تر در اسناد بودند تاریخی‌اند
> و برای ادعاهای فعلی استفاده نمی‌شوند. `tools/gen_status.py` اکنون **۴۵۷**
> تست اعلام‌شده را گزارش می‌کند؛ ۲۶ مورد تست/تغییر تستیِ پس از baseline در این
> checkout هنوز با cargo اجرا نشده‌اند.

---

## 🆕 دور «ممیزی Master Prompt V2» (۲۰۲۶-۰۹-۰۹) — `FIXED_AND_VERIFIED`

این دور، دور NestedCloak قبلی را با اجرای واقعی `cargo test` **راستی‌آزمایی
کرد و ۹ شکست پیدا کرد** — دقیقاً همان چیزی که STATUS قبلی به‌صورت صادقانه
پیش‌بینی کرده بود («این تست‌های Rust هنوز اجرا نشده‌اند»). کل پشتهٔ رمز
ECH واقعی از نظر ریاضی خراب بود؛ ریشه‌ها با شبیه‌سازی bignum (Python) و
مدل مینی-مُد جداسازی و رفع شدند، سپس با ۳ تست رگرسیون جدید تثبیت شدند.

### شکست‌های اجرا (۹) و ریشه‌های آن‌ها — همه رفع شد

| # | محل | باگ | اصلاح |
|---|---|---|---|
| ۱ | `hpke.rs::Fe::sub` | بایاس‌های «donna fsub» با ثابت‌های **۶۴-بیتی** برای اندام‌های ۵۱-بیتی — نه مضرب p بودند نه جا می‌شدند → panic سرریز در هر مسیر X25519 | بازنویسی sub: کانونیکال‌سازی هر دو عملوند + زنجیرهٔ قرض i128 + تصحیح −۱۹ (چون زنجیرهٔ قرض 2^255 ≡ 19 اضافه می‌کند) با انتشار قرض بین‌اندامی |
| ۲ | `hpke.rs::poly1305_mac` | fold ضرب با ضریب **×5** در نرادیکس 2^44 — درست: **×20** (B³ = 2^132 ≡ 20)؛ برچسب هر پیام غلط بود | s1/s2 = r·20 به سبک poly1305-donna-64 + بازنویسی زنجیرهٔ carry |
| ۳ | `hpke.rs::poly1305_mac` | `u128::from_le_bytes` روی برش **۸ بایتی** → panic | `u64::from_le_bytes` + توضیح چرایی |
| ۴ | `hpke.rs::Fe::to_bytes` | شمارش **دوباره** بیت‌های بالای اندام (هم انباشت u128، هم pre-place صریح) → هر کدگذاری چند-اندامی غلط؛ همچنین بُرش بیت‌های ≥2^256 (اختلاف 38 = 2·19 در تست خواص) | حذف pre-place + carry-normalize اولیهٔ اندام‌ها پیش از بسته‌بندی |
| ۵ | `fragmentation.rs::tls_record_split_mid_sni` | تقسیم با کف (`name_len/2`) در حالی که تست/قصد، سقف می‌خواست → برش وسط نام غلط | `name_len.div_ceil(2)` |
| ۶-۹ | (همان ریشه‌های ۱-۴) | شکست‌های `x25519_*`، `kem_encapsulate_*`، `hpke_derive_*`، `real_ech_seal_*` | با رفع ۱-۴ سبز شدند |

### اصلاحات ایستا و هماهنگی

| ID | محل | شرح |
|---|---|---|
| F-02 | `src/*.rs` | `cargo fmt --check` روی ۲ فایل شکست می‌خورد → `cargo fmt --all` |
| F-03 | ۹ خطا در ۴ فایل | `cargo clippy -D warnings` شکست می‌خورد (manual_is_multiple_of، repeat().take()، needless_range_loop، doc indentation، range contains) → همه رفع |
| F-04 | `dpi_guard.toml.example` / relay | `rotate_ips` اکنون در relay mode واقعاً به‌صورت round-robin روی فهرست IPهای operator اعمال می‌شود؛ transparent flowها mid-connection بازنویسی نمی‌شوند. `trusted_dns` همچنان عمداً کامنت است و مقدار غیرخالی را رد می‌کند چون redirect به signed WFP callout نیاز دارد |
| F-05 | `pipeline.rs` (بلوک ECH GREASE) | نتیجهٔ `build_outer_sni_for_ech` با `let _ =` دور ریخته می‌شد — فراخوانی مرده روی سیم؛ در مسیر NestedCloakِ شکست‌خورده + fronting، SNI واقعی می‌ماند → اکنون اعمال می‌شود |
| F-01 | `tools/gen_status.py` | برطرف شد: `git_head()` اکنون `--show-toplevel` را با ROOT مقایسه می‌کند و در checkout/tarball نامطمئن `unknown` می‌نویسد؛ marker دیگر از repository والد جعل نمی‌شود |

### تست‌های رگرسیون جدید (۳)

- `hpke::tests::fe_algebraic_properties_hold` — جبر اندام‌ها (جابه‌جایی، توزیع‌پذیری، (a−b)+b==a، ایدمپوتنت بودن کدگذاری) روی ورودی‌های با slack، با RNG قطعی
- `hpke::tests::fe_sub_borrow_wraps_correctly` — زنجیرهٔ قرض و مسیر منفی sub
- `config::tests::shipped_toml_example_parses_and_documents_partial_fields` — مثالِ ارسالی همیشه parse+validate می‌شود و فیلدهای محدود/partial را مستند نگه می‌دارد

---

## دور قبل — «نقشهٔ راه ۲۰۲۶» (تاریخچه)

بعد از آخرین اجرای سبز، یک دور بزرگ به کدبیس اضافه شد: **پروفایل هفتم
`NestedCloak` (پوشش تو در تو) + شش تکنیک نقشهٔ راه** — برش رکورد وسطِ
نام، پدینگ تصادفی، چرخش استراتژی، بهبود حلقهٔ بازخورد، و **ECH واقعی**
با ماژول رمز جدید `hpke.rs` (X25519 + HKDF-SHA256 + ChaCha20Poly1305،
با بردارهای تست رسمی خود RFCها). در یک حسابرسی هماهنگیِ بعدی، **قالب
سیمویی ECH واقعی با استاندارد نهایی RFC 9849 تطبیق داده شد** (راستی‌آزمایی
در برابر کد مرجع BoringSSL و NSS) و چند تداخل بین‌تکنیکی رفع شد.

**وضعیت صادقانهٔ این دور:**
- حدود ۲۶۰۰ خط کد و **۴۱ تست جدید** (مجموع تعریف‌شده در همان زمان: ۴۲۴ تست؛
  آن snapshot تاریخی `tools/gen_status.py` **۴۴۰** تست و **۴۱** ماژول
  داشت؛ وضعیت فعلی در بخش بالاتر ثبت شده است، با ۰ تابع مرده و
  ۸۲ فیلد تنظیمات ↔ ۸۲ کنترل وب‌سایت).
- **این تست‌های Rust هنوز اجرا نشده‌اند** — این دور در محیط بدون زنجیرهٔ
  ابزار Rust نوشته شد؛ هیچ کامپایل/اجرای `cargo` صورت نگرفته است. اولین
  کار: `cargo test` + `cargo clippy` در محیط دارای ابزار، سپس به‌روزرسانی
  اعداد این جدول. (سوئیت **۳۶۹** تستی جاوااسکریپت داشبورد در آن اجرای
  تاریخی روی همین کد **اجرا و پاس** شده بود؛ اجرای فعلی ۳۷۵ چک است.)
- همهٔ تکنیک‌های جدید روی مسیر موجود سوارند (همان پروفایل‌های قبلی با
  پرچم‌های خاموش به‌صورت پیش‌فرض)؛ رفتار پیش‌فرض تغییری نکرده است.

> **⬆️ تکمیل‌شده در دور ممیزی ۲۰۲۶-۰۹-۰۹:** این دور اکنون اجرا شد —
> ۹ شکست (عمدتاً ریاضیاتِ `hpke.rs`) پیدا و رفع شد؛ جدول بالا برای
> مرور تاریخی نگه داده شده است. اعداد فعلی: **۴۵۷ تست اعلام‌شده در سورس و
> ۴۲ ماژول**؛ آخرین اجرای سبزِ baseline در ۲۰۲۶-۰۹-۰۹، ۴۳۱ تست تاریخی بود؛
> ۲۶ مورد تست/تغییر پس از آن baseline هنوز با cargo اجرا نشده‌اند. clippy = ۰ و fmt = پاک
> مربوط به همان baseline هستند. جزئیات در بخش «ممیزی Master Prompt V2» بالای همین فایل.

**تداخل‌های رفع‌شده در حسابرسی هماهنگی:**
- نشت نام واقعی در ترکیب NestedCloak + ECH واقعی (حذف `0xFF01` از هر دو
  هلوی داخلی/بیرونی و غیرفعال‌سازی کلاک وقتی مُهر مسلح است).
- مُهر واقعی باید آخرین تغییر هللو باشد (AAD کل هلوی بیرونی را پوشش
  می‌دهد)؛ بلوک‌های uTLS/Geedge/پدینگ با `enable_real_ech` سازگار شدند.
- بازخوانی تنبل کانفیگ ECH در هات‌ریلود.

---

## جدول وضعیت ماژول‌ها و بخش‌های اصلی

| بخش | Implementation | Tests source / evidence | Tests اجراشده (JS/AST) | Real-world Windows | Status |
|---|:---:|---|:---:|:---:|---|
| Configuration + validation | ✅ | `TEST_MATRIX.md` | ✅ JS/schema evidence | ⏳ | `UNTESTED` (Rust) |
| Pipeline (هستهٔ پردازش پکت) | ✅ | `TEST_MATRIX.md` | `[UNVERIFIED]` Rust | ⏳ | `PARTIAL` (Windows pending) |
| HPKE / رمز ECH واقعی | ✅ | `TEST_MATRIX.md` | `[UNVERIFIED]` Rust | ⏳ | `UNTESTED` (Rust) |
| Web UI (backend) | ✅ | `TEST_MATRIX.md` | `[UNVERIFIED]` Rust | ⏳ | `UNTESTED` (Rust) |
| Web UI (frontend) | ✅ | ۳۷۵ JS checks | ✅ **پاس** | ⏳ | `VERIFIED` |
| Relay (رله TCP و fail-closed) | ✅ | `TEST_MATRIX.md` | `[UNVERIFIED]` Rust | ⏳ | `PARTIAL` (runtime pending) |
| Fragmentation / parsing | ✅ | `TEST_MATRIX.md` | `[UNVERIFIED]` Rust | ⏳ | `UNTESTED` (Rust) |
| DoH + DNS cache | ✅ | `TEST_MATRIX.md` | `[UNVERIFIED]` | `[UNVERIFIED]` | `PARTIAL` |
| `main.rs` (reconcile/hot-reload) | ✅ | `TEST_MATRIX.md` | `[UNVERIFIED]` Rust | ⏳ | `UNTESTED` (Rust) |
| `native_gui.rs` | ✅ | `TEST_MATRIX.md` | `[UNVERIFIED]` Rust | ⏳ | `UNTESTED` (Rust) |
| Engine / WinDivert FFI | ✅ | `TEST_MATRIX.md` | — | ⏳ | `BLOCKED` (ویندوز) |
| DNS leak prevention | 🟡 PARTIAL (real user-mode WFP FFI) | `TEST_MATRIX.md`; source-only | `[UNVERIFIED]` cargo | `[UNVERIFIED]` Windows/BFE | `PARTIAL` |
| WFP callout driver | ❌ | خارج از scope | — | ❌ | `BLOCKED` (خارج از scope) |
| Self-update (بررسی نسخه) | ✅ | `TEST_MATRIX.md` | `[UNVERIFIED]` Rust | ⏳ | `UNTESTED` (Rust, check-only) |

---

## آمار و معیارهای پروژه

| معیار | مقدار |
|---|---:|
| ماژول‌های Rust | **۴۲** (طبق `tools/gen_status.py`) |
| `#[test]` تعریف‌شده در کد Rust | **۴۵۷** (طبق `tools/gen_status.py`) |
| تست‌های **آخرین اجرای ثبت‌شده و پاس‌شده** (cargo test، لینوکس) | **۴۳۱ از ۴۳۱** ✅؛ ۲۶ مورد تست/تغییر پس از آن [UNVERIFIED] |
| توابع بدون هیچ فراخوان (Dead Functions) | **۰** ✅ (استاتیک) |
| هشدار خطای clippy (-D warnings، --all-targets) | **۰** ✅ (اجرای ۲۰۲۶-۰۹-۰۹) |
| `cargo fmt --check` | **پاک** ✅ (اجرای ۲۰۲۶-۰۹-۰۹) |
| تست‌های UI (JavaScript) | ۳۷۵ (همه پاس — اجرای ۲۰۲۶-۰۹-۱۱) |
| فیلدهای `Settings` | ۸۲ (۷۷ + ۵ پرچم جدید) |
| ↳ خوانده‌شده توسط موتور | ۸۲ از ۸۲ (۱۰۰٪) ✅ |
| کنترل‌های Web UI | ۸۲ (تطابق کامل و هماهنگی پرچم restart) ✅ |

جزئیات کامل به تفکیک ماژول: **`TEST_MATRIX.md`** (تولیدشده با `tools/gen_status.py`).

---

## وضعیت رسیدگی به مسایل شناخته‌شده (Known Issues)

۱. **K-1 (محیط Sandbox بدون Rust):** شفاف‌سازی و مستندسازی نیازمندی‌های کامپایل و اجرای آزمون‌ها.
۲. **K-2 (ماتریس آزمون واقعی ویندوز):** تدوین ۶ سناریوی آزمون لایو روی ویندوز با WinDivert.
۳. **K-3 (تست‌های `main.rs` و `native_gui.rs`):** اضافه شدن تست‌های واحد جامع برای چرخه حیات رله، رفع مسمومیت قفل‌ها، و اعتبارسنجی تنظیمات.
۴. **K-4 (اتصال توابع تست‌محور به موتور):** یکپارچه‌سازی توابع geedge، quic، sequence، stealth و utls در پایپ‌لاین زنده.
۵. **K-5 (کدهای مرده):** رساندن تعداد توابع بدون فراخوان به ۰.
۶. **K-6 (مرزهای باقی‌مانده):** اجرای Windows/BFE برای WFP هنوز `[UNVERIFIED]` است؛ redirect به `trusted_dns` به callout driver امضاشده نیاز دارد؛ Singleton و self_update محدودیت‌های مستند دارند.

---

## تاریخچهٔ ۱۱ رفع باگ اصلی

| # | محل | شرح اصلاحیه و تضمین آزمون |
|---|---|---|
| ۱ | `lib.rs::build_filter` | تبدیل شرط اتصال پورت‌ها به `&&` به‌جای `\|\|` جهت جلوگیری از رهگیری ناخواسته |
| ۲ | `webui.rs::token_ok` | رد صریح توکن‌های خالی با مقایسه زمان‌ثابت و اعتبارسنجی مقادیر کوتاه |
| ۳ | `webui.rs::handle_conn` | خواندن کامل و امن بدنهٔ درخواست‌های HTTP چندبخشی (Chunked/Slow) |
| ۴ | `doh.rs::parse_a_records` | بررسی امن طول پاسخ DNS برای پیشگیری از Slice Out-of-Bounds Panic |
| ۵ | `main.rs` | بازیابی خودکار از Poisoned Mutex در حلقهٔ Watchdog/Reconcile با `recover_mutex` |
| ۶ | `.gitignore` | ایجاد `.gitignore` جامع و لغو رهگیری باینری‌های درایور WinDivert |
| ۷ | `self_update.rs` | فراخوانی `validate_repo_slug` درون `check_for_update` برای پیشگیری از تزریق در URL |
| ۸ | `singleton.rs::drop` | بررسی تطابق `acquired` قبل از حذف فایل قفل جهت جلوگیری از شکستن قفل سایر پردازه‌ها |
| ۹ | `pipeline.rs` | اعمال سقف ظرفیت `MAX_LAST_ACTIVITY` و `MAX_INBOUND_TTL` و الگوریتم تخلیهٔ نیمهٔ قدیمی |
| ۱۰ | `autottl.rs::suggest_ttl_scaled` | اصلاح فرمول مقیاس‌گذاری خطی و تست یکنوایی صعودی تابع با افزایش فاصله |
| ۱۱ | `relay.rs` | آزادسازی فوری اسلات‌های جدول Flow در اتصالات ناموفق با `unregister_relay_flow` |

---

## ممیزی معماری ۲۰۲۶-۰۹ (اجرای واقعی تست‌ها + ۹ اصلاحیه جدید)

این دور، اولین دوری است که سوئیت تست **واقعاً اجرا** شده (Rust 1.98.1 stable،
لینوکس). نتیجه: کد قبلاً اصلاً کامپایل نمی‌شد — ۳ خطای کامپایل و ۹ شکست تست
پیدا و رفع شد، به‌علاوه باگ‌های واقعی مسیر تولید که در ادامه آمده است.

### رفع‌های بحرانی مسیر تولید (Production)

| # | محل | باگ | اصلاح |
|---|---|---|---|
| ۱ | `geedge.rs::prepend_grease_extensions` | طول ۳-بایتی handshake به‌صورت u16 بروزرسانی می‌شد (`delta<<8`) — **هر** ClientHello خروجیِ مسیر پیش‌فرض `enable_geedge_evasion` خراب بود و سرور واقعی آن را رد می‌کرد | وصلهٔ صحیح u24 با حساب checked و خطای صریح + تست رگرسیون `grease_prepend_keeps_record_parseable` |
| ۲ | `pipeline.rs::on_inbound` | ServerHello ورودی `recent.get()` را مصرف نمی‌کرد — هر segment تکراری یک `+1` امتیاز دیگر به جدول استراتژی می‌داد و `select_best` را سوگیره می‌کرد | مصرف entry با `remove()` — یک تلاش، حداکثر یک نتیجه (تست `inbound_serverhello_scores_once` حالا پاس) |
| ۳ | `pipeline.rs` (MD5SIG) | نوشتن آپشن 19 در آفست ثابت `l4+20` — با TCP options واقعی ویندوز (MSS/timestamps) داخل آپشن‌ها/پیلود می‌نوشت | محاسبهٔ طول هدر اصلی از data-offset پکتِ wrap شده |
| ۴ | `scanner.rs::probe_tls_handshake` | فقط بایت 0x16 را چک می‌کرد؛ رکورد ساختگی middlebox هم «سالم» شمرده می‌شد | خواندن و اعتبارسنجی handshake-type `0x02` در بایت ۶ |
| ۵ | `native_gui.rs` + `main.rs` | دکمهٔ «⚡ Test & Select Lowest Ping» قرض‌گیری (`&mut self.settings`) را نقض می‌کرد — باینری GUI کامپایل نمی‌شد | جداسازی نتیجه در local + اعمال پس از closure |

### سیم‌کشی قابلیت‌های ادعاشده به مسیر زنده

| # | قابلیت | قبل | بعد |
|---|---|---|---|
| ۶ | تقسیم ۱-۲ بایتی TCP روی SNI | فقط توابع تست‌محور (dead on wire) | `enable_frag_by_sni` بدون reframing → برش دقیق قبل از SNI + ۱ بایت داخل نام (`packet::tcp_segment_payload_at_offsets` جدید + تست pipeline) |
| ۷ | TTL واقعی DNS | TTL پاسخ دور ریخته می‌شد؛ TTL ثابت ۳۰۰s | `parse_a_records` کمینهٔ TTL رکوردهای A را برمی‌گرداند (کف ۳۰s، سقف MAX_STALE)؛ `DnsCache::insert_with_ttl` + ستون چهارم سازگار با فایل‌های قدیمی |

### پایدارسازی چرخهٔ حیات (Fail-Closed Lifecycle)

| # | حفره | اصلاح |
|---|---|---|
| ۸ | `proxy_cleanup::restore_state` فقط در مسیر Ctrl+C اجرا می‌شد؛ panic یا خروج زودهنگام، پروکسی سیستم را روی رلهٔ مرده باقی می‌گذاشت | گارد Drop (`ProxyRestoreGuard`) که روی **هر** مسیر unwind اجرا می‌شود |
| ۹ | دکمهٔ Stop در GUI با `child.kill()` (TerminateProcess) بک‌اند را می‌کشت — cleanup هرگز اجرا نمی‌شد | توقف نرم با فایل `<config>.stop`: بک‌اند در ≤۲۰۰ms تشخیص می‌دهد، مسیر کامل shutdown (بستن WinDivert + restore پروکسی) را اجرا می‌کند؛ kill فقط به‌عنوان fallback پس از ۳ ثانیه |

### رفع‌های فرعی
`webui.rs` تجمیع هدرهای fragment‌شده قبل از parse + رد صریح `Transfer-Encoding: chunked` با 501 · حذف ثابت‌های مرده `SCAN_PROBES`/`SCAN_TIMEOUT` و `LOCK_SH` · `truncate(false)` صریح روی فایل‌های lock · importهای شرطی `cfg(windows)` در main.rs · doc ناهماهنگ backoff و کامنت کهنهٔ F-003 · متن راهنمای توکن GUI.

---

## ساختار مستندات پروژه

| فایل | نقش |
|---|---|
| `AI_RULES.md` | قوانین اجباری توسعه و نگهداری بدون ساده‌سازی |
| `STATUS.md` | همین فایل — گزارش وضعیت و معیارهای اعتبارسنجی |
| `ARCHITECTURE.md` | گراف ماژول‌ها، چرخه حیات راه‌اندازی و مدل چندنخی |
| `TEST_MATRIX.md` | ماتریس تولید خودکار وضعیت ماژول‌ها و تست‌ها |
| `KNOWN_ISSUES.md` | گزارش شفاف مشکلات شناخته‌شده و ماتریس تست ویندوز |
| `CHANGELOG.md` | تاریخچه تغییرات و نسخه‌ها |
| `README.md` | مستندات کاربری، راهنمای نصب و پیکربندی |
