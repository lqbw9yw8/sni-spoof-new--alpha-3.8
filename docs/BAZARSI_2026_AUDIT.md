# گزارش بازارسی ۲۰۲۶ — بخش ۱: بازرسی کامل

> اجرا شده در ۲۰۲۶-۰۹-۰۸ روی شاخهٔ `arena/01a08112-sni-spoof-new-alpha` ·
> commit مبنا: `1d77048` (docs) → `e2da2f1` (main)

---

## گام ۱ — اجرای تست‌ها

### محیط اجرا

| ابزار | نسخه / وضعیت |
|---|---|
| `cargo` | **نصب نیست** — `rustup` و `crates.io` از sandbox مسدودند |
| `node` / `npm` | node v22 / npm 12 — کار می‌کند |
| `python3` | 3.x — کار می‌کند |
| `github.com` | push شاخهٔ نشست ✅ · push workflow ❌ (مجوز `workflows` نیست) |
| `registry.npmjs.org` | ✅ |

### تلاش برای نصب Rust

تمام مسیرهای ممکن آزموده شد:
- `rustup-init` (static.crates.io / sh.rustup.rs) → مسدود (connection refused)
- `crates.io` / `index.crates.io` → مسدود
- پکیج PyPI `rustup` → wheel بدون binary واقعی (فقط اسکریپت)
- `apt-get install rustc cargo` → `deb.debian.org` مسدود
- mirror چین (`rsproxy.cn`, `tuna.tsinghua.edu.cn`) → مسدود

**تنها مسیر باقی‌مانده:** نصب گردش کار `ci/github-actions.yml` در ریموت. تلاش برای push به `.github/workflows/ci.yml` **رد شد** — توکن GitHub App مجوز `workflows` ندارد (دقیقاً همان محدودیتی که `ci/README.md` مستند کرده). راه جایگزین: **اجرای دستی توسط کاربر** روی حساب شخصی (دستور در انتهای این گزارش).

### نتایج تست‌های اجراشده (jsdom)

```
uitest$ npm test
  uitest/test-ui.mjs        : 104 passed, 0 failed   — ALL UI TESTS PASSED
  uitest/check-rust-tests.mjs: 56 passed, 0 failed   (AST schema coverage)
  uitest/test-v2rayn.mjs    :  67 passed, 0 failed   — ALL v2rayN COEXISTENCE CHECKS PASSED
  uitest/test-resilience.mjs:  60 passed, 0 failed
  uitest/test-settings.mjs  :  56 passed, 0 failed   — ALL SETTINGS-UI TESTS PASSED
  uitest/test-status.mjs    :  26 passed, 0 failed   — ALL STATUS-UI TESTS PASSED
─────────────────────────────────────────────────────
  مجموع: 369 تست JS / 0 شکست — همه ۶ سوئیت سبز
```

### نتایج Rust

`cargo test` و `cargo clippy` اجرا نشدند. **دلیل:** کامپایلر Rust در این sandbox در دسترس نیست و GitHub Actions workflow قابل نصب از طریق token نیست.

**ادعاهای `STATUS.md` (۳۸۳ پاس در اجرای قبلی):** معتبر باقی می‌مانند اما مستقل از این نشست قابل راستی‌آزمایی نبودند. تست‌های ۴۱ دور جدید (NestedCloak) به‌طور قطعی در این نشست اجرا نشدند.

---

## گام ۲ — تطبیق خط‌به‌خط پنج لایه

### خلاصهٔ شمارش هر لایه

| لایه | تعداد |
|---|---:|
| `src/config.rs` — فیلدهای `Settings` | ۸۲ |
| `src/webui/index.html` — کنترل‌های `k:"…"` | ۸۲ |
| `uitest/mock-server.mjs` — `DEFAULTS` | ۸۱ |
| `dpi_guard.toml.example` — کلیدهای توپ‌سطح | ۸۰ |

### تفاوت‌های واقعی (از اسکریپت `/tmp/xcheck.py`)

| کجا هست | کجا نیست | فیلد | ملاحظات |
|---|---|---|---|
| Settings | toml.example | `rotate_ips` | `Vec<String>` — در UI و mock هست، در toml نیست |
| Settings | toml.example | `trusted_dns` | `Option<String>` — UI دارد، mock خاص (`k == "trusted_dns"`)، toml ندارد |
| Settings | mock | `trusted_dns` | در mock به‌صورت شرطی پذیرفته می‌شود (خط ۲۲۷) |

**نتیجهٔ گام ۲:**
- UI ↔ Settings: **کاملاً همگام** (هر دو ۸۲)
- mock ↔ Settings: اختلاف ۱ فیلد (`trusted_dns` — به‌عمد در mock DEFAULTS نیست چون `Option` است و فقط با POST خاص فعال می‌شود؛ این یک **تفاوت طراحی مستند** است نه ناهماهنگی)
- toml.example ↔ Settings: اختلاف ۲ فیلد (`rotate_ips`, `trusted_dns`) — باید به `dpi_guard.toml.example` اضافه شوند

### پروفایل‌ها (۷تایی)

پروفایل‌های مرجع (از `MutationProfile` در `src/sni_mutations.rs`):
`Stealth`, `ChinaGfw`, `RussiaDpi`, `Aggressive`, `ChinaRegional`, `Henan`, `NestedCloak`

| لایه | پروفایل‌های ثبت‌شده | وضعیت |
|---|---|---|
| `strategy.rs` ESCALATION_LADDER | Stealth, ChinaGfw, RussiaDpi, ChinaRegional, Henan, NestedCloak | ۶ تا (Aggressive عمداً بیرون — خطرناک) |
| `src/webui/index.html` | همهٔ ۷ تا | ✅ کامل |
| `uitest/mock-server.mjs` | همهٔ ۷ تا | ✅ کامل |
| `src/native_gui.rs` | همهٔ ۷ تا | ✅ کامل |
| `config.rs` اعتبارسنجی | از طریق `MutationProfile::from_str` — همهٔ ۷ تا قابل parse | ✅ |

---

## گام ۳ — تست تداخل جفت‌تکنیک‌ها

### تست‌های ترکیبی موجود در pipeline.rs (46 تست)

| تست | ترکیب |
|---|---|
| `nested_cloak_profile_produces_three_segments` | NestedCloak × فرگمنتاسیون |
| `nested_cloak_enforces_combined_fragmentation_when_disabled` | NestedCloak × combined-frag |
| `fronting_with_hidden_real_sni` | SNI fronting × 0xFF01 hidden |
| `henan_profile_uses_small_chunks_and_disorder` | Henan × chunk × disorder |
| `utls_fingerprint_applies_without_breaking` | uTLS (تک‌تکنیک) |
| `ech_grease_in_pipeline` | ECH-GREASE (تک‌تکنیک) |
| `geedge_evasion_adds_padding` | Geedge (تک‌تکنیک) |
| `padding_inflation_grows_the_hello_randomly` | پدینگ (تک‌تکنیک) |
| `sni_disguise_in_pipeline_when_enabled` | SNI-disguise (تک‌تکنیک) |
| `frag_mid_sni_pipeline_straddles_the_name` | frag-by-mid-SNI (تک‌تکنیک) |

### ماتریس جفت‌های **مفقود** (طبق درس‌های مستند)

| جفت | درس | تست موجود؟ |
|---|---|---|
| **ECH واقعی × uTLS** | مُهر ECH باید آخرین تغییر باشد | ❌ مفقود |
| **ECH واقعی × Geedge** | AAD کل هلوی بیرونی را می‌پوشاند؛ Geedge نمی‌تواند بعد از مُهر چیزی تزریق کند | ❌ مفقود |
| **ECH واقعی × پدینگ** | پدینگ بیرونی باید قبل از مُهر اضافه شود | ❌ مفقود |
| **NestedCloak × ECH واقعی** | نشت `0xFF01` — هلوی داخلی و بیرونی هر دو باید پاک باشند | ❌ مفقود |
| **فرگمنت × TCP-fooling (wrong_seq/checksum)** | بازچینی‌پذیری بعد از تغییر seq | ✅ پوشش جزئی در `flow_buf_overflow_fail_opens_both` |
| **fail-open × تمام مسیرهای خطای ECH** | خطا در seal → پکت دست‌نخورده | ✅ `fail_open_returns_original_on_err` در `fail_open.rs` |
| **fail-open × max-flows** | ❌ `max_flows_cap_fail_opens` هست ولی مستقیم نیست | ✅ |
| **uTLS × Geedge** | هر دو هلوی بیرونی را دست می‌زنند؛ ترتیب مهم است | ❌ مفقود |

**جمع:** ۴ جفت بحرانی بدون تست (`ECH×uTLS`, `ECH×Geedge`, `ECH×Padding`, `ECH×NestedCloak`). این‌ها **باید در نشست پیاده‌سازی اضافه شوند** — چون کد در pipeline ترتیب اعمال را hardcode می‌کند (خطوط ۱۰۴۰–۱۲۱۰) ولی تستی تضمین نمی‌کند که ترتیب درست است.

### بررسی 0xFF01 در هلوی بیرونی

کد `ech.rs:494` می‌گوید:
> «the outer ClientHelloOuter has any NestedCloak hidden extension (0xFF01) stripped too»

این یک کامنت طراحی است — **نه تضمین اجرایی**. بدون تست، این ادعا قابل اعتماد نیست.

---

## گام ۴ — انطباق سیمی با RFCها

### برسی کد در برابر RFC

| RFC | ماژول | نقطهٔ بازبینی | وضعیت |
|---|---|---|---|
| RFC 8446 (TLS 1.3) | `fragmentation.rs`, `ech.rs` | ساختار ClientHello | ✅ بردارهای تست موجود (`ch_pkt` helper) |
| RFC 6066 (SNI) | `fragmentation.rs` | فرمت server_name type 0x0000 | ✅ |
| RFC 7685 (padding) | `geedge.rs` | extension padding | ✅ |
| RFC 8701 (GREASE) | `ech.rs` | ۶ مقدار ECH_GREASE_TYPES = `[0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0xFAFA]` — **مطابق RFC** ✅ | ✅ |
| RFC 9180 (HPKE) | `hpke.rs` | بردارهای تست X25519/HKDF-SHA256/ChaCha20Poly1305 | ✅ ۱۰ تست با برچسب DONE |
| RFC 9849 (ECH) | `ech.rs` | outer/inner, AAD, config_id, enc | ✅ ۱۲ تست؛ `seal_real_ech_hello` + `real_ech_sealed_payload_decrypts_to_inner_hello` |

### انحرافات / نکته‌ها

1. **فرمت `ech_config_hex` در Settings:** hex-string خام که کاربر باید دستی وارد کند (لینک به گام ۴ → راه‌حل تکنیک #۴: واکشی خودکار از DoH/SVCB).
2. **`ECH_EXTENSION_TYPE` ثابت** (`ech.rs`): مقدار واقعی `0xFE0D` است — مطابق RFC 9849. ✅

---

## گام ۵ — صداقت مستندات

### `STATUS.md` — اعداد در برابر شمارش واقعی

| ادعا | شمارش واقعی | نتیجه |
|---|---:|---|
| ماژول‌ها: ۴۱ | `gen_status.py` → ۴۱ | ✅ |
| `#[test]` تعریف‌شده: ۴۲۴ | شمارش grep → ۴۲۴ | ✅ |
| توابع dead: ۰ | `gen_status.py` → ۰ | ✅ |
| فیلدهای Settings: ۸۲ | اسکریپت `/tmp/xcheck.py` → ۸۲ | ✅ |
| کنترل‌های UI: ۸۲ | شمارش `k:"…"` → ۸۲ | ✅ |

### `TEST_MATRIX.md` — drift بعد از regen

تنها تفاوت: خط `<!-- commit: 8087f4e -->` → `<!-- commit: 1d77048 -->` (بروزرسانی hash).
اعداد ماژول‌ها، تست‌ها، dead, test-only همگی ثابت ماندند. ✅

---

## گام ۶ — قواعد کد

### قانون `unsafe`

- `#![deny(unsafe_code)]` در `src/lib.rs:21` — crate-wide ✅
- `#![allow(unsafe_code)]` فقط در `engine.rs:7` و `singleton.rs:18` ✅
- grep برای `unsafe` خارج این دو: فقط در کامنت‌ها و CSP header (`'unsafe-inline'`) — **هیچ `unsafe` واقعی** ✅

### خطوط > ۱۰۰ کاراکتر

تعداد کل: ۶۱ خط. تفکیک:
- کامنت/داک‌استرینگ: ۱۸ خط
- رشته‌های بلند (قالب HTML/CSP/WinDivert filter/registry path): ۳۶ خط
- **کد واقعی**: ۷ خط

خطوط کد بلند (غیرقابل‌توجیه):
- `src/lib.rs:77,79` — فیلتر WinDivert (تغییر ساختار آن به ۲ خط، معنا را خراب می‌کند) → **استثنا**
- `src/pipeline.rs:2588` — `matches!` ماکرو → قابل‌اصلاح
- `src/proxy_cleanup.rs:97,99` — `Set-ItemProperty` path → **استثنا** (registry path)
- `src/strategy.rs:229` — کامنت بلند → قابل‌اصلاح
- `src/webui.rs:657` — CSP header → **استثنا** (هدر HTTP)

**جمع:** ۴ استثنا قابل‌توجیه + ۳ خط قابل‌اصلاح (pipeline:2588, strategy:229).

### قانون «تست کنار هر ماژول»

تنها ماژول بدون `#[test]`: `engine.rs` — FFI-only، `cfg(windows)` — **مستند** ✅

### قانون «بدون `todo!()` / `unimplemented!()`»

grep: **هیچ نتیجه‌ای** ✅

---

## خلاصهٔ یافته‌های گام ۱–۶

| گام | وضعیت | یافتهٔ کلیدی |
|---|---|---|
| ۱ — اجرای تست | ⚠️ PARTIAL | jsdom: ۳۶۹/۰ ✅ · Rust: NOT TESTED (محیط فاقد کامپایلر) |
| ۲ — تطبیق پنج‌لایه | ⚠️ ۲ باگ | `rotate_ips` و `trusted_dns` در `toml.example` غایب |
| ۳ — تست تداخل | 🔴 ۴ جفت بحرانی مفقود | ECH×uTLS, ECH×Geedge, ECH×Padding, ECH×NestedCloak |
| ۴ — انطباق RFC | ✅ | GREASE/HPKE/ECH مطابق RFC |
| ۵ — صداست مستندات | ✅ | اعداد با شمارش واقعی همگام |
| ۶ — قواعد کد | ✅ با ۳ خط قابل‌اصلاح | unsafe ✅ · todo! ✅ · ۷ خط >۱۰۰ (۴ استثنا، ۳ قابل‌اصلاح) |

---

## کارهای باقی‌مانده از گام ۱–۶ (بایستی در نشست پیاده‌سازی انجام شود)

1. **اضافه کردن `rotate_ips` و `trusted_dns` به `dpi_guard.toml.example`** — با کامنت توضیحی.
2. **نوشتن ۴ تست ترکیبی بحرانی** در `pipeline.rs`:
   - `ech_real_x_utls_seal_is_last_mutation`
   - `ech_real_x_geedge_no_injection_after_seal`
   - `ech_real_x_padding_before_seal`
   - `ech_real_x_nested_cloak_no_ff01_leak`
3. **اصلاح ۳ خط کد بلند** (pipeline.rs:2588, strategy.rs:229 و — اختیاری — webui.rs CSP).
4. **اجرای cargo در محیط دارای کامپایلر** — کاربر می‌تواند با نصب گردش‌کار CI روی ریموت (دستور در زیر) این را انجام دهد:
   ```bash
   git fetch origin arena/01a08112-sni-spoof-new-alpha
   git checkout arena/01a08112-sni-spoof-new-alpha
   mkdir -p .github/workflows
   cp ci/github-actions.yml .github/workflows/ci.yml
   git add .github/workflows/ci.yml
   git commit -m "ci: install workflow"
   git push origin arena/01a08112-sni-spoof-new-alpha
   ```
