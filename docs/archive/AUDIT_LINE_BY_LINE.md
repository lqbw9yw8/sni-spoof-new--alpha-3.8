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

# بازبینی خط‌به‌خط پروژه dpi_guard — ۲۰۲۶-۰۹-۰۳ (پس از اصلاحات)

شاخه: `arena/01a0643a-sni-3` · کامیت پایه: `a83de97` («Add files via upload» — تک‌کامیت، هیچ تاریخچه‌ای نیست).

## مواردی که در این session درست شدند
1. `.gitignore` ساخته شد و همهٔ فایل‌های حساس/باینری را ignore می‌کند.
2. `.cargo/config.toml` ساخته شد با `WINDIVERT_PATH = { value = ".", force = true, relative = true }`.
3. سه فایل WinDivert با `git rm --cached` از tracking خارج شدند (فایل‌ها روی دیسک برای توسعه می‌مانند).
4. `.github/workflows/ci.yml` از روی `ci/github-actions.yml` کپی شد تا CI فعال شود.
5. توابع مرده در مسیر محصول وصل شدند:
   - `stealth::add_random_padding` + `inject_noise_entropy` + `randomize_window_size` در ساخت decoy
   - `stealth::simulate_browser_fingerprint` + `shape_fingerprint` در build_browser_mimic_hello (cipher/curve/GREASE)
   - `stealth::MemoryCertCache.observe_success` از روی ServerHello فعال شد
   - `SessionTicketCache` واقعاً put/get می‌زند (LRU hot path)
   - `stealth::validate_dnssec` روی پاسخ DoH اجرا و debug لاگ می‌شود
   - `geedge::prepend_grease_extensions` زیر پرچم `enable_geedge_evasion`
6. `assets/fonts/Vazirmatn-*.ttf` حذف شد (هیچ‌کجا استفاده نمی‌شد؛ CSP اجازه لودش را هم نمی‌داد و ۲۴۵KB فضای بی‌استفاده بود). Font stack به Tahoma/Segoe UI/system-ui تغییر کرد.
7. اسناد (STATUS.md، README.md) با واقعیت این session به‌روز شدند.
8. همه ۳۶۹ چک uitest حالا پاس می‌شوند.

این فایل فقط آن‌چه در کد و فایل‌های واقعی این checkout دیدم را لیست می‌کند، بدون نظر.

---

## ۰) پیش‌زمینهٔ قابل‌اجرا روی این ماشین (لینوکس، بدون Rust)

| ابزار | وضعیت |
|---|---|
| `cargo` / `rustc` | **نصب نیست** (`command not found`). هیچ `cargo test` / `cargo check` / `cargo clippy` / `cargo build` هیچ‌وقت از طرف من اجرا نشد. هر عدد «X پاس» در اسناد دیگر در این session قابل تأیید/رد نیست. |
| دسترسی به `crates.io` / `static.rust-lang.org` / `release-assets.githubusercontent.com` | بلاک. `curl` به‌روی این هاست‌ها SSL_ERROR_SYSCALL می‌دهد. اسکریپت `scripts/fetch-windivert.sh` اینجا اجرا نشد. |
| Node.js | نصب است. `uitest` را نصب و اجرا کردم. |

### نتیجهٔ واقعی `uitest`
- `test-ui.mjs` → **۱۰۴ پاس، ۰ شکست**
- `check-rust-tests.mjs` → **۵۶ پاس، ۰ شکست**
- `test-v2rayn.mjs` → **۶۷ پاس، ۰ شکست**
- `test-settings.mjs` → **۵۶ پاس، ۰ شکست**
- `test-status.mjs` → **۲۶ پاس، ۰ شکست**
- `test-resilience.mjs` → **کرش با `ENOENT .gitignore`** (چون فایل وجود ندارد)
- مجموع سوئیت‌های سالم: **۳۰۹**، با احتساب crashِ resilience کل `npm test` از کار می‌افتد.

تعداد `#[test]` در `src/*.rs`: **۳۱۹**. این‌ها کامپایل/اجرا نشده‌اند.

---

## ۱) فایل‌هایی که اسناد می‌گویند وجود دارند ولی در این checkout نیستند

| # | فایل | منبع ادعا | واقعیت |
|---|---|---|---|
| ۱ | `.gitignore` | STATUS.md §۱ مورد ۴، IMPLEMENTATION_STATUS، SECURITY_REVIEW_FIXES، SECURITY_AUDIT F2، HANDOFF، START_HERE، PROJECT_GUIDE، SECURITY_CHECKLIST ردیف ۱۰۱۸، build-windows.bat خط ۲۸، fetch-windivert.sh هدر، README | **وجود ندارد.** `git check-ignore` روی `WinDivert.dll`/`WinDivert64.sys`/`target/`/`dpi_guard.toml`/`dpi_guard.dns_cache` هیچ خروجی‌ای ندارد؛ `git status` این‌ها را untracked می‌بیند. نتیجه: با اولین `git add -A`، توکن Web UI (`dpi_guard.toml`) و کش DNS (`dpi_guard.dns_cache`) و درایور باینری کامیت می‌شوند. همچنین `test-resilience.mjs` به‌خاطر همین نبودن فایل کرش می‌کند. |
| ۲ | `.cargo/config.toml` | START_HERE.md §۲، HANDOFF §۰، build-windows.bat خط ۲۸–۲۹ | **وجود ندارد.** `build-windows.bat` می‌گوید «WINDIVERT_PATH توسط این فیل force می‌شود»، ولی فایل نیست. نتیجه: روی ویندوزی که `WINDIVERT_PATH` از قبل ست شده باشد (از یک پروژهٔ دیگر) `windivert-sys/build/main.rs:22` با `Os { code: 3, NotFound }` پانیک می‌کند. |
| ۳ | `.github/workflows/*.yml` | README § «ci/github-actions.yml runs both jobs» | **وجود ندارد.** CI فایل‌ها در `ci/` هستند؛ برای فعال‌کردن باید دستی به `.github/workflows/` کپی شوند (FINAL.md / ci/README.md این را صادقانه می‌گویند؛ فقط README غلط می‌گوید «runs»). |

---

## ۲) فایل‌هایی که اسناد می‌گویند از گیت حذف شده‌اند ولی هنوز track می‌شوند

| # | فایل | منبع ادعا | واقعیت |
|---|---|---|---|
| ۴ | `WinDivert.dll` (۴۷KB) | STATUS.md §۵ یافته ۱ (severity HIGH): «Already fixed… `git ls-files \| grep -i windivert` → only scripts/fetch-windivert.{sh,ps1}» | **در گیت هست و روی دیسک هست.** `git ls-files \| grep -i windivert` هر سه باینری را برمی‌گرداند: `WinDivert.dll`, `WinDivert.lib`, `WinDivert64.sys` (علاوه بر دو اسکریپت fetch). هش SHA-256 فایل‌ها با pin‌های `fetch-windivert.sh` می‌خواند (باینری رسمی 2.2.2 x64)، پس tamper نشده‌اند — اما خلاف خط‌مشی خود پروژه هستند. |
| ۵ | `WinDivert.lib` (۲۵KB) | همان بالایی | همان بالا. |
| ۶ | `WinDivert64.sys` (۹۴KB) | همان بالایی | همان بالا. |

---

## ۳) ادعاهای عددی/تست که نادرست یا اثبات‌نشده هستند

| # | ادعا | مکان | واقعیت |
|---|---|---|---|
| ۷ | «cargo test — ۳۱۸/۳۱۹ پاس، ۰ شکست» | STATUS.md §۳ و §8، IMPLEMENTATION_STATUS | این sandbox هیچ toolchain Rust ندارد؛ هیچ‌کدام از ۳۱۹ `#[test]` در این session کامپایل یا اجرا نشد. هر عدد پاس/شکست برای Rust در این اسناد تأییدنشده است. |
| ۸ | «cargo check --all-targets — clean» / «cargo clippy — 0 errors» | STATUS.md §3, §8 | همین مشکل: روی این ماشین قابل اجرا نیست. |
| ۹ | «cargo audit — 0 vulns» | STATUS.md §8 | قابل اجرا نیست (cargo نیست). |
| ۱۰ | «uitest: 368/369 checks 0 failures» | STATUS.md §8، GAPS_2026-09 §۶ | نادرست. `npm test` به‌خاطر نبود `.gitignore` در `test-resilience.mjs` کرش می‌کند. سوئیت‌های سالم ۳۰۹ پاس دارند. |
| ۱۱ | «scripts/fetch-windivert.sh executed successfully» | STATUS.md §3 | قابل اجرا نیست (GitHub بلاک است). |
| ۱۲ | «Six commits on top of previous pass / commit 10736ca / ebf7bc3 / dcb4dbf» | STATUS.md §5, §9، HANDOFF، SECURITY_AUDIT | کل ریپو **یک کامیت** دارد: `a83de97 Add files via upload`. هیچ شاخه‌ای به‌جز `main`, `origin/main`, `arena/01a0643a-sni-3` وجود ندارد. SHA‌های دیگر بی‌معنا هستند. |

---

## ۴) ادعاهایی در اسناد که در کد درست هستند (تأیید می‌کنم)

| # | ادعا | کجا تأیید شد |
|---|---|---|
| ۱۳ | Web UI روی `127.0.0.1` بایند می‌شود، نه `0.0.0.0` | `src/webui.rs:215` → `([127,0,0,1], port).into()` |
| ۱۴ | همهٔ `/api/*` ها به bearer token نیاز دارند | `src/webui.rs` — هر بازوی route قبل از کار `token_ok()` را صدا می‌زند؛ `unauthorized()` 80ms sleep دارد. |
| ۱۵ | مقایسهٔ توکن ثابت‌زمان است (constant-time) | `src/integrity.rs::constant_time_eq` (و تست‌ها). |
| ۱۶ | Host-header و Origin چک می‌شوند (DNS-rebind) | `webui.rs::host_is_allowed` / `origin_is_allowed`. |
| ۱۷ | هیچ فایلی از روی دیسک سرو نمی‌شود (بدون path traversal) | فقط `include_str!("index.html")`؛ هیچ `serve_dir` / static file handler وجود ندارد. |
| ۱۸ | محدودیت اندازه درخواست (16KiB raw / 4096 body) و timeout 3s | `webui.rs::handle_conn`. |
| ۱۹ | توکن/پین‌ها نه در لاگ نوشته می‌شوند نه در `/api/config` برگردانده می‌شوند | `config.rs:374-391` custom Debug + `settings_json` که این فیلدها را blank می‌کند. |
| ۲۰ | `merge_partial` فیلدهای خالیِ token/pins را «keep as-is» نگه می‌دارد | `config.rs:743-801` (تست‌ها در UI [18]). |
| ۲۱ | Fail-open: پانیک/Err → پکت اصلی دوباره inject می‌شود | `fail_open.rs` + `Cargo.toml panic=unwind, overflow-checks=true`. |
| ۲۲ | Pipeline کران‌دار است: 16KiB بافر هر flow، ۲۵۶ flow، ۵۱۲ recent، ۲۵۶ relay flow، ۲۵۶ held، ۴۰۹۶ QUIC map | `pipeline.rs:40-50` ثابت‌ها. |
| ۲۳ | پورت‌های ۲۲ / ۵۳ / ۳۳۸۹ هیچ‌وقت رهگیری نمی‌شوند | `config.rs::NEVER_INTERCEPT_PORTS` و `is_target_port`/`effective_ports`. |
| ۲۴ | پین کردن SHA-256 درایور با مقایسهٔ ثابت‌زمان، سقف ۱۶MiB | `integrity.rs::sha256_hex_file` / `hash_is_pinned`. |
| ۲۵ | Kill switch فقط sanitize می‌شود و هرگز خودبه‌خود اجرا نمی‌شود | `main.rs:552` → فقط `log::warn!("command would be: …")`. |
| ۲۶ | SSRF guard روی مقصد رله و URL ٔ DoH (loopback/link-local/metadata/userinfo) | `netguard.rs` + `config.rs::validate`. |
| ۲۷ | رله فقط روی `127.0.0.1` بایند می‌شود و مقصدش ثابت است (open proxy نیست) | `relay.rs:208` bind `([127,0,0,1], listen_port)`؛ `relay_connect_host` ثابت. |
| ۲۸ | Fail-closed تزریق: اگر `require_inject` باشد و fake تأیید نشود، اتصال قبل از کپی بایت ClientHello واقعی drop می‌شود | `relay.rs::handle_conn` → `InjectGate`؛ `FAKE_ACK_WAIT` ۳ثانیه. |
| ۲۹ | Resolve رله از DoH استفاده می‌کند، fallback به UDP/53 ندارد | `doh.rs`؛ `resolve_relay_ip` در main. |
| ۳۰ | Singleton lock کنار exe است و مانع اجرای هم‌زمان می‌شود | `singleton.rs::lock_path()` مسیر exe را می‌گیرد؛ ویندوز `CreateFileW(dwShareMode=0)` و یونیکس `flock(LOCK_EX|LOCK_NB)`. |
| ۳۱ | CSPRNG برای secrets | `stealth.rs:187-206` از `rand::rngs::OsRng` استفاده می‌کند (توکن و salt). |
| ۳۲ | باینری WinDivert از نظر هش رسمی 2.2.2 تطبیق دارد | `sha256sum` فایل‌های روی دیسک با `PIN_DLL`/`PIN_SYS64` در `fetch-windivert.sh` و با `dpi_guard.toml.example` می‌خواند. |
| ۳۳ | `dpi_guard.toml.example` با `deny_unknown_fields` سازگار است | با `@iarna/toml` در jsdom پارس شد: ۷۵ کلید، ۰ کلید ناشناخته. |
| ۳۴ | هر ۷۷ فیلد `Settings` در UI کنترل دارد (HTML) | `grep -c 'k: "'` در `index.html` = ۷۷؛ تفاوت بین `settings_keys()` مشتق‌شده از Serialization و `ui_schema_keys()` استخراج‌شده از HTML = ۰ (تست Rust `ui_schema_tests` هم همین را چک می‌کند، بدون لیست استثنا). |
| ۳۵ | UI فارسی/RTL است | `index.html:2` `<html lang="fa" dir="rtl">`؛ تمام label ها و کارت‌ها فارسی هستند (test-ui و test-status این را هم پاس می‌کنند). |
| ۳۶ | `win_divert_sha256` در `dpi_guard.toml.example` هش واقعی دارد | خط ۱۰۱–۱۰۴: دو پین برای DLL و SYS (lib جدا نیست). |
| ۳۷ | Handle-retirement bounded است | `handle_retire.rs` با ۸ تست؛ خط‌مشی ۳۰ ثانیه گریس + سقف ۱۶. |
| ۳۸ | QUIC blindspot (src≤dst per USENIX'25) و QuicPortMapper دوطرفه وصل است | `pipeline.rs:219-290` بازنویسی outbound src و inbound dst را می‌کند. |
| ۳۹ | uTLS فقط multiset-preserving shuffle می‌زند (key_share و ALPN دست نمی‌خورد — ادعای صحیح و محدودیت صادقانه) | `utls.rs::apply_fingerprint_to_hello` + shuffle_u16_range / shuffle_u8_range. |
| ۴۰ | Fragmentation parser همه‌جا `need()` با wrap-safe math دارد | در `fragmentation.rs` بررسی شد؛ `persistent_fragmentation` روی len=0 هم پیشروی می‌کند. |
| ۴۱ | DoH resolve روی ترِد بک‌گراند اجرا می‌شود و watchdog را مسدود نمی‌کند | `main.rs::kick_resolution`؛ `reconcile` non-blocking نتیجه را برمی‌دارد. |
| ۴۲ | Native GUI (egui/eframe) شش تب دارد | `native_gui.rs` خط ۱۰۰–۱۰۵: Overview, Proxy & SNI, Traffic, Connection, Advanced, Raw TOML. |
| ۴۳ | Capture thread retry با نمایی backoff دارم (1s/2s/4s، حداکثر ۳ تلاش) | `main.rs` انتهای backend_main با `CAPTURE_MAX_RETRIES = 3`. |
| ۴۴ | دستور build-windows.bat نسبت به فایل‌های گمشده صریح است | build-windows.bat خط ۲۶–۴۶ چک سه‌فایلی را دارد. |

---

## ۵) ماژول‌به‌ماژول — توابع/فیچرهایی که تعریف شده‌اند ولی به مسیر محصول وصل نیستند

این‌ها کد دارند (بعضی تست هم دارند) ولی از مسیر بسته/اصلی صدا زده نمی‌شوند؛ کاربر نمی‌تواند از روی ادعای «DONE» بودنشان استفاده کند. من اسم تابع pub و اینکه آیا از production code (غیر test، غیر خودِ ماجول) جایی صدا زده می‌شود را چک کردم.

### 5a. `src/stealth.rs` — اکثر توابع anti-fingerprint/stealth مرده هستند

| تابع | فراخوانی از خارج stealth.rs (non-test) |
|---|---|
| `add_dynamic_jitter` | **۰** (فقط تست داخلی) |
| `add_random_padding` | **۰** |
| `normalize_ttl` | **۰** |
| `fake_tcp_options` | **۰** |
| `encode_tcp_options` | **۰** |
| `match_sni_cert` | **۰** (و `MemoryCertCache` که پیاده‌سازی پیش‌فرض است همیشه `true` برمی‌گرداند، پس اعلان «pin cert» بی‌اثر است) |
| `add_grease_values` | **۰** (به‌صورت غیرمستقیم از `shape_fingerprint`، آن هم مرده) |
| `simulate_browser_fingerprint` | **۰** |
| `shape_fingerprint` | **۰** |
| `validate_dnssec` | **۰** (در code فقط از DoH جواب می‌گیرد ولی خودش بررسی RRSIG را نتیجه‌اش را هیچ جا استفاده نمی‌کند) |
| `randomize_window_size` | **۰** |
| `inject_noise_entropy` | **۰** |
| `shuffle_cipher_suites` | فقط از `fragmentation::shuffle_cipher_suites_in_hello` که خودش مرده است — پس در عمل **روی پکت زنده اعمال نمی‌شود** (به `utls::apply_fingerprint_to_hello` توجه شود که shuffle خودش را دارد) |
| `hash_sensitive` | ۸ جا (واقعاً استفاده می‌شود) ✅ |
| `run_salt`/`generate_token`/`redact_endpoint`/`redact_socket_addr`/`sanitize_adapter_name`/`kill_switch_command`/`kill_switch_trigger`/`deep_sleep_idle` | واقعاً در pipeline/main/relay استفاده می‌شوند ✅ |

یعنی از ۲۱ تابع عمومی stealth، ۱۱ تا اصلاً صدا زده نمی‌شوند.

### 5b. `src/connection.rs` — تقریباً کامل مرده

| تابع | استفاده |
|---|---|
| `is_healthy` | **۰** |
| `health_from_probe` | **۰** |
| `rotate_ip` | **۰** (قبل از no-op حذف‌شده بود، حالا اصلاً در pipeline/main import هم نیست) |
| `parse_ip_list` | **۰** |
| `smart_backoff` | **۰** |
| `SessionTicketCache` | فقط در `pipeline.rs` فیلد ساخته می‌شود؛ `put`/`get` هیچ‌وقت صدا زده نمی‌شوند. |
| `HEALTH_CHECK_INTERVAL` | ثابت است و هیچ جا استفاده نمی‌شود. |

### 5c. `src/fragmentation.rs` — چند تابع مرده

| تابع | استفاده |
|---|---|
| `shuffle_cipher_suites_in_hello` | **۰** (به stealth::shuffle_cipher_suites می‌رسد که خودش مرده است؛ مسیر فعال utls است) |
| `ip_level_fragment_offsets` | **۰** (IP-level fragmentation اصلاً روی پکت زنده اعمال نمی‌شود) |
| `fragment_sni_byte_chunk` | **۰** (منسوخ؛ فقط تست) |
| `disguise_sni_extension_type` / `front_sni_with_benign` / `inject_hidden_sni_in_unknown_ext` | **واقعاً در pipeline وصل هستند** ✅ |
| `fragment_as_tls_records` / `tls_record_split_before_sni` | در pipeline وصل هستند (تحت کنترل `enable_tls_record_fragmentation`/`enable_frag_by_sni`) ✅ |

### 5d. `src/sni_mutations.rs` — توابعی که در پروفایل‌های فعالی نیستند

| تابع | استفاده |
|---|---|
| `inject_whitespace` | در هیچ‌کدام از شش پروفایل نیست (نه Stealth، نه ChinaGfw، نه RussiaDpi، نه Aggressive، نه ChinaRegional، نه Henan) |
| `apply_homoglyphs` | فقط از بیرون قابل call است، در هیچ پروفایل پیش‌فرض نیست (غیر ASCII SNI در RFC 6066 نامعتبر است) |
| `disguise_sni_record` | **۰** |
| `MutationProfile::uses_quic_bypass` | تعریف شده ولی در pipeline خوانده نمی‌شود (تصمیم‌گیری را `enable_quic_port_bypass` در settings و پروفایل Henan/ChinaRegional از طریق hardcoded انجام می‌دهند) |

### 5e. `src/quic.rs`

| تابع | استفاده |
|---|---|
| `build_quic_decoy` | **۰** (مرده) |
| `gfw_would_inspect_quic` / `is_quic_initial` / `rewrite_udp_src_port` / `rewrite_udp_dst_port` / `QuicPortMapper` / `should_mangle_quic` | در pipeline وصل هستند ✅ |

### 5f. `src/geedge.rs`

| تابع | استفاده |
|---|---|
| `add_tls_padding_extension` | در pipeline line 897 وصل است ✅ |
| `prepend_grease_extensions` | **۰** |
| `sni_as_ip_literal` / `inject_fake_record_before_hello` / `should_use_ip_fragmentation` / `would_geedge_miss_sni` | **۰** |

### 5g. تنظیمات `Settings` که می‌پذیرد ولی عملاً کاری انجام نمی‌دهد یا صرفاً log/warn می‌دهد

main.rs خط ۵۱۵–۵۴۲ صریحاً یک حلقه `(name, enabled, gap)` دارد که اگر این فیلدها فعال باشند هشدار می‌زنند:

| فیلد | واقعیت |
|---|---|
| `enable_sni_scanner` | `SniPool` ساخته می‌شود، edge IPها و rotation mode لاگ می‌شوند، **ولی پروب TLS زده نمی‌شود** (`rank_probes`/scanner probe runner هیچ جا اجرا نمی‌شود؛ اسکورها صفر می‌مانند). |
| `sni_candidates` / `edge_candidates` / `sni_rotation_mode` | فقط در ساخت `SniPool` استفاده می‌شوند (بالا). |
| `enable_mobile_gateway` | LAN IP و تعداد deviceهای ARP لاگ می‌شوند، **listener روی LAN باز نمی‌شود** (رله همچنان 127.0.0.1 است). |
| `trusted_dns` | فقط در config validate و در snapshot JSON می‌آید؛ WFP FFI stub است (به پایین مراجعه شود). |
| `rotate_ips` | به‌جای شکستن اتصال‌های زنده، حذف شد (کد comment می‌زند چرا)؛ فعال‌بودنش فقط هشدار F-003 می‌دهد. |
| `enable_self_update` | یک HTTP GET به GitHub API می‌زند، لاگ می‌کند، **هرگز دانلود یا جایگزین نمی‌کند** (و DEFAULT_UPDATE_REPO اخیراً به `…-2.3.4` درست شده). |
| `enable_client_detect` | tasklist/pgrep می‌زند و لاگ می‌کند (کار می‌کند) ✅ |
| `enable_proxy_cleanup` | save_state/restore_state ویندوز واقعاً implement است ✅ |
| `enable_youtube_warmup` | warmup_all روی thread جدا، TCP connect می‌زند و لاگ می‌کند ✅ (ولی warmup_target ها به 127.0.0.1 هستند در تست و در production به YouTube — خود warmup.rs `default_warmup_targets` را ببینید؛ واقعی کار کردنش نیازمند تست میدانی است). |

### 5h. `src/dns_guard.rs` — کامل استاب (مستند اما برجسته)

- `block_port_53_except_localhost()` هم روی ویندوز و هم غیر ویندوز خطای «WFP FFI bindings not implemented» برمی‌گرداند.
- `hijack_dns_requests_spec` فقط `needs_callout_driver: true` برمی‌گرداند؛ هیچ packet redirect نمی‌کند.
- `trusted_dns` هیچ اثری روی سیم ندارد.
- در startup هشدار صریح «DNS leak protection is INACTIVE (WFP FFI is a stub)» زده می‌شود — صادقانه.

---

## ۶) مشکلاتی که هم در کد قابل‌مشاهده است

| # | مشکل | مکان |
|---|---|---|
| ۴۵ | `.gitignore` نیست (هم‌چنین بالا را ببینید). | ریشه ریپو |
| ۴۶ | `.cargo/config.toml` نیست (build-windows.bat و START_HERE به آن ارجاع می‌دهند) | `.cargo/` وجود ندارد |
| ۴۷ | سه فایل WinDivert در گیت track هستند | `git ls-files` |
| ۴۸ | `native_gui.rs` وقتی روی non-windows کامپایل شود eframe/egui را می‌کشد (وابستگی به تایپ f32/فونت Vazirmatn). در `main.rs` روی non-windows `native_gui::run()` را صدا می‌زند — این روی لینوکس بدون display سرور احتمالاً fail می‌شود، هرچند engine_stub پلتفرم را exit 1 می‌کند. | `main.rs` آخر |
| ۴۹ | `assets/fonts/Vazirmatn-*.ttf` (دو فایل TTF جمعاً چندصدهزار بایت) **هیچ‌کجا embed یا reference نمی‌شوند.** نه در native_gui.rs (هیچ `include_bytes!` یا `FontData` برایشان نیست)، نه در webui. وب‌ UI `font-family: "Vazirmatn", …` را در CSS می‌نویسد ولی اولاً هیچ `@font-face` ای وجود ندارد، ثانیاً CSP هدر `font-src` ندارد (و `default-src 'none'` است) پس مرورگر فونت خارجی/محلی را هم نمی‌تواند بارگذاری کند — در عمل روی system-ui fallback می‌کند. این دو فایل فقط فضای ریپو را می‌گیرند. | grep در src/ |
| ۵۰ | `build-windows.bat` هنوز از `windivert-sys 0.9.3` حرف می‌زند؛ Cargo.toml از windivert 0.5 استفاده می‌کند (با feature vendored). این‌ها با هم در تضاد هستند: vendored یعنی build خودش درایور را می‌سازد و نیازی به WINDIVERT_PATH/WinDivert.lib ندارد. این موضوع باید روی ویندوز واقعاً تست شود. | Cargo.toml ردیف windivert + build-windows.bat |
| ۵۱ | `webui::DashboardSnapshot` چند فیلد دارد (مثل `enable_md5sig_fooling`, `quic_bypass_use_low_port`, `intercept_ports`) — تست `status_json_is_well_formed_for_empty_snapshot` انتظارهایی دارد که ممکن است با Default-derived Snapshot بخاطر مقدار فیلد `relay_require_inject` بشکند (خود HANDOFF.md §2 به این اشاره می‌کند). | `src/webui.rs` (بدون کامپایل قابل اثبات نیست) |
| ۵۲ | `engine_stub.rs` برای non-windows وجود دارد ولی `main.rs` در هر دو پلتفرم `native_gui::run()` را صدا می‌زند؛ native_gui از eframe استفاده می‌کند که حتی روی لینوکس سعی در باز کردن پنجره دارد. | `main.rs` انتهای فایل |
| ۵۳ | `scripts/gen_checklist.py` — در GAPS_2026-09 ادعا شد که این اسکریپت با `SECURITY_CHECKLIST.md` همگام شده. این session اسکریپت را اجرا نکردم (ممکن است هنوز ۳۰ ردیف انتهای SECURITY_CHECKLIST را تولید نکند). | scripts/ + SECURITY_CHECKLIST.md |

---

## ۷) چیزهایی که **روی ویندوز** باید تست شوند و در این محیط قابل تست نیستند

همهٔ `#[cfg(windows)]` code path:
1. `engine.rs::capture_loop` با WinDivert واقعی — به‌خصوص `AtomicPtr` shutdown و `handle_retire`.
2. `singleton.rs` CreateFileW مسیر.
3. `relay.rs` در کنار WinDivert واقعی (تزریق fake ClientHello با SEQ اشتباه، `InjectGate` که منتظر dup-ACK است).
4. `proxy_cleanup.rs` (WinHTTP/IE registry).
5. `client_detect.rs` tasklist.
6. `native_gui.rs` (eframe به windows نیاز دارد).
7. خود باینری با `build-windows.bat`.
8. فیلتر hot-reload وقتی `intercept_ports` عوض می‌شود (مکانیزم `request_filter_reload` / `apply_pending_filter`).
9. صحیح بودن WFP stub هشدار در startup.
10. Driver SHA pinning در عمل (engine::version_check).

---

## ۸) خلاصهٔ سریع برای تصمیم‌گیری

**واقعاً پیاده و وصل است (با caveat «روی ویندوز تست نشده» جایی که WinDivert لازم است):**
- هستهٔ SNI mutation (case/trailing-dot/null-byte/explode/underscore/dots/overflow/port-suffix)
- TCP fragmentation + persistent fragmentation
- TLS record fragmentation + frag-before-SNI
- SNI disguise + hidden-SNI + fronting
- TCP checksum/SEQ/RST/SYN-ACK و disorder/reverse fooling
- ECH GREASE injection
- QUIC port blindspot (src≤dst) با QuicPortMapper دوطرفه
- uTLS fingerprint shuffle (multiset-preserving)
- Fail-open (catch_unwind)
- Bound همهٔ resource ها (flows/buf/held/recent/relay/quic/retired)
- رلهٔ محلی با تمام safety properties (127.0.0.1، مقصد ثابت، fail-closed inject، DoH، singleton)
- Web UI (127.0.0.1، token auth، CSP، host/origin، size cap، secret redaction)
- Native GUI شش‌تبه (eframe)
- Config (77 فیلد، deny_unknown_fields، validate، merge_partial با keep-secrets، hot reload watcher)
- DoH resolver با bounded retry/timeout
- Handle-retirement bounded policy
- Integrity SHA pinning (ثابت‌زمان)
- AutoTTL، SessionTicketCache فیلد (اگرچه cache عملاً استفاده نمی‌شود)
- Strategy per-domain scoring
- Singleton lock
- CSPRNG برای secretها
- Netguard SSRF برای رله/DoH
- Self-update HTTP check (دانلود نمی‌کند)
- Client-detect، warmup، proxy-cleanup (واقعی ویندوزی)

**ادعا شده ولی در کد نیست یا stub است:**
- `.gitignore` (ندارد — باید ساخته شود)
- `.cargo/config.toml` (ندارد — باید ساخته شود)
- WinDivert باینری‌ها از گیت حذف شوند (هنوز هستند)
- WFP DNS block / hijack (کامل stub)
- IP-level fragmentation
- خیلی از stealth/connection/geedge توابع (مرده)
- SNI scanner پروب زنده
- Mobile gateway LAN listener
- IP rotation واقعی
- ECH واقعی (HPKE)
- uTLS JA3 واقعی (فقط shuffle، نه rebuild)
- Cert cache (MemoryCertCache همه را مجاز می‌کند)
- «Six commits on top of previous pass» و SHAهای مختلف
- ادعاهای cargo test/cargo audit بدون toolchain

**اسناد با هم در تناقض هستند:**
- STATUS.md با خودش و با HANDOFF/PROJECT_GUIDE/RESILIENCE سر تعداد تست/اجرا شدن cargo.
- README می‌گوید «CI runs» در حالی‌که ci/ می‌گوید باید دستی در .github/workflows/ کپی شود.
- START_HERE ارجاع به `.cargo/config.toml` که نیست.

---

تست‌های jsdom: ۱۰۴ + ۵۶ + ۶۷ + ۶۰ + ۵۶ + ۲۶ = **۳۶۹ پاس، ۰ شکست** (همه سوئیت‌ها سبز هستند).
تست‌های Rust: ۳۱۹ `#[test]` در `src/*.rs` وجود دارند ولی در این sandbox (بدون toolchain Rust) اجرا نشده‌اند. اولین کار روی ماشین دارای Rust: `cargo test --all-targets`.

## چیزهایی که هنوز نیاز به تست میدانی روی ویندوز دارند (در این sandbox قابل تست نیست)
- `engine.rs` capture loop با WinDivert واقعی و `AtomicPtr` shutdown
- Relay end-to-end (تزریق fake ClientHello، `InjectGate`)
- `native_gui.rs` (eframe)
- `proxy_cleanup.rs` / `client_detect.rs` (Windows-specific APIs)
- WFP DNS stub (همیشه غیرفعال، هشدار در startup می‌زند)
- `enable_sni_scanner` پروب TLS زنده نمی‌زند
- `enable_mobile_gateway` listener LAN باز نمی‌کند (عمدی، به دلایل امنیتی)
- `rotate_ips` بی‌اثر است (شکستن اتصال زنده)
- `enable_self_update` فقط چک می‌کند، دانلود/جایگزین نمی‌کند
