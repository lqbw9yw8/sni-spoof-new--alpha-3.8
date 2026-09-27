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

# بازبینی خط‌به‌خط — ۲۰۲۶/۰۹/۰۵

بازبینی کل مخزن در کامیت پایهٔ `a2ce27e`، شامل ۱۶٬۶۹۹ خط Rust (۳۹ ماژول)،
۱٬۴۲۲ خط `src/webui/index.html`، ۱٬۹۹۷ خط تست JS و ۴٬۴۹۷ خط مستندات.

## محدودیت مهم این بازبینی — لطفاً بخوانید

**کد Rust کامپایل نشده است.** در این محیط `cargo`/`rustc` نصب نیستند و
قابل نصب هم نبودند:

| مقصد | وضعیت |
|---|---|
| `sh.rustup.rs`، `static.rust-lang.org` | ✗ مسدود (SSL_ERROR_SYSCALL) |
| `crates.io`، `index.crates.io`، `static.crates.io` | ✗ مسدود |
| conda-forge، `raw.githubusercontent.com` | ✗ مسدود |
| `github.com` (git clone)، PyPI، npm | ✓ باز |

حتی با نصب کامپایلر، `crates.io` مسدود است و مخزن پوشهٔ `vendor/` ندارد،
پس ~۱۰۰ وابستگی `Cargo.lock` دریافت‌شدنی نیستند.

**نتیجه:** یافته‌های زیر از خواندن سورس به‌دست آمده‌اند، نه از
`cargo check`/`cargo test`. تست‌های رگرسیونی که اضافه شده‌اند نوشته شده‌اند
ولی **اجرا نشده‌اند**. اولین کاری که روی یک ماشین با Rust باید کرد:

```
cargo test && cargo clippy -- -D warnings
```

تست‌های `uitest` (که JS هستند) اجرا شدند: **۳۶۹ پاس، ۰ شکست**.
توجه: `check-rust-tests.mjs` و `test-resilience.mjs` فقط regex روی سورس
می‌زنند — خودشان هم تصریح می‌کنند که رفتار زمان‌اجرا را اثبات نمی‌کنند.

---

## یافته‌ها

### ۱ — `lib.rs::build_filter` — نشت ترافیک (شدید)

```rust
let mut ports = if settings.intercept_all_tcp || settings.intercept_all_udp {
    Vec::new()          // ← لیست صریح دور ریخته می‌شود
} else {
    settings.explicit_port_list()
};
```

`tcp_clause` و `udp_clause` هرکدام wildcard خودشان را جدا بررسی می‌کنند،
پس لیست صریح هنوز برای پروتکلِ **بدون** wildcard لازم است. با شرط `||`:

- `intercept_all_tcp = true`، `intercept_all_udp = false`، `intercept_ports = [443]`
- → `ports` خالی → `udp_clause` می‌بیند `ports.is_empty()` → `"false"`
- → **هیچ بستهٔ UDP/QUIC ای گرفته نمی‌شود** با اینکه کاربر ۴۴۳ را خواسته

کامنت خود کد خلافش را ادعا می‌کرد («we still carry the relay port so the
non-wildcard side (if any) includes it»). هیچ تستی این حالت را پوشش
نمی‌داد؛ هر پنج تست موجود همیشه هر دو wildcard را با هم خاموش می‌کردند.

**رفع:** شرط به `&&` تغییر کرد. دو تست اضافه شد
(`one_wildcard_keeps_explicit_ports_for_the_other_protocol`،
`both_wildcards_ignore_the_explicit_list`).

### ۲ — `webui.rs::token_ok` — دور زدن احراز هویت (شدید، در عمل غیرفعال)

```rust
crate::integrity::constant_time_eq(got.as_bytes(), expected.as_bytes())
```

`constant_time_eq("", "")` مقدار `true` می‌دهد — تستِ خودِ ماژول در
`integrity.rs:80` این را تأیید می‌کند. پس توکن انتظاری خالی یعنی هر
درخواستی با هدر `Bearer ` تمام مسیرهای `/api/*` را باز می‌کند.

**در عمل قابل بهره‌برداری نیست:** `main.rs:705` وقتی `web_ui_token` خالی
است خودش یکی تولید می‌کند. ولی این تنها لایهٔ دفاعی بود — هر فراخوانی
دیگر `webui::start` با رشتهٔ خالی سطح کنترل را کاملاً باز می‌کرد.

**رفع:** `if expected.is_empty() { return false; }` + سه assert.

### ۳ — `webui.rs::handle_conn` — از دست رفتن بدنهٔ POST (متوسط)

```rust
let n = stream.read(&mut buf)?;   // ← فقط یک بار
```

TCP تضمین نمی‌کند هدر و بدنه در یک سگمنت برسند. اگر بدنه در سگمنت بعدی
بیاید، `body` خالی یا بریده می‌ماند و ذخیرهٔ تنظیمات از داشبورد به‌طور
متناوب و غیرقابل‌بازتولید شکست می‌خورد.

**رفع:** حلقهٔ `read` تا رسیدن `content_length` بایت بعد از `\r\n\r\n`،
با همان سقف ۱۶ KiB و همان پاسخ ۴۱۳.

### ۴ — `doh.rs::parse_a_records` — پنیک روی پاسخ بریده (متوسط)

```rust
for _ in 0..qdcount {
    pos = skip_name(resp, pos)?;
    pos += 4;              // ← بدون بررسی مرز
}
```

`Cargo.toml` صراحتاً `overflow-checks = true` دارد (با این استدلال که
سرریز باید پنیک کند تا fail-open بگیردش). ولی این مسیر، پارسِ پاسخ یک
سرور DoH بیرونی است: یک پاسخ بریده یا خصمانه به‌جای افت به کش DNS،
پنیک می‌دهد. خودِ `skip_name` امن است (حلقهٔ فشرده‌سازی، اشاره‌گر رو به
جلو و طول برچسب همه چک شده‌اند) — مشکل فقط همین خط بیرون از آن است.

**رفع:** بررسی مرز پیش از `pos += 4` + دو تست
(`truncated_question_section_is_an_error_not_a_panic`،
`partial_qtype_qclass_is_an_error`).

### ۵ — `main.rs` — مسمومیت Mutex حلقهٔ reconcile را می‌کُشد (متوسط)

```rust
*slot.lock().unwrap() = Some((want, ip));        // نخ resolve
let finished = self.resolved.lock().unwrap().take();  // حلقهٔ reconcile
```

اگر `resolve_relay_ip` پنیک کند (مثلاً داخل ureq/DoH — به یافتهٔ ۴ ربط
مستقیم دارد)، Mutex مسموم می‌شود و از آن پس **هر بار** `reconcile` پنیک
می‌کند؛ یعنی رله دیگر هرگز آشتی داده نمی‌شود.

پروژه دقیقاً برای همین `recover_mutex()` را در `lib.rs` دارد و در ۱۶ جای
دیگر استفاده می‌کند. `main.rs` تنها فایلی بود که دورش می‌زد — همان دو نقطه،
هر دو روی همان Mutex مشترک.

**رفع:** هر دو به `dpi_guard::recover_mutex` تبدیل شدند.

### ۶ — نبودِ `.gitignore` (رفع‌شده در کامیت قبلی)

`test-resilience.mjs` با `ENOENT` کرش می‌کرد، پس `npm test` هرگز کامل
اجرا نمی‌شد. ده‌ها جای مستندات ادعا می‌کردند این فایل وجود دارد.

---

## آنچه بررسی شد و سالم بود

- **`netguard.rs`** — کاملاً تمیز. IPv4-mapped IPv6 باز می‌شود و دوباره چک
  می‌شود، متادیتای ابری، mDNS و `*.internal` رد می‌شوند، پارس دستی URL
  برای DoH userinfo را می‌گیرد. ۱۲ تست، پوشش خوب.
- **`fragmentation.rs::parse_client_hello`** — پارسر TLS واقعاً محکم است.
  تابع `need()` سرریز `p + n` را می‌گیرد، همهٔ طول‌ها پیش از استفاده چک
  می‌شوند، `ext_body_start + ext_len > ext_end` رد می‌شود.
- **`packet.rs`** — `saturating_*` و `.min(buf.len())` همه‌جا؛ همهٔ
  پارس‌کننده‌ها `Option` برمی‌گردانند. هیچ اندیس‌گذاری خام بدون بررسی نیست.
- **`doh.rs::skip_name`** — سقف hop برای فشرده‌سازی، رد اشاره‌گر رو به جلو
  (حلقهٔ بی‌نهایت)، سقف طول برچسب.
- **`integrity.rs::constant_time_eq`** — درست پیاده شده (طول را هم در
  `diff` می‌آورد، بدون بازگشت زودهنگام).
- **`src/webui/index.html`** — فارسی/RTL، ۷۷ کنترل برابر ۷۷ فیلد
  `Settings`، `esc()` روی همهٔ مقادیر، `textContent` به‌جای `innerHTML`،
  بدون id تکراری. ۱۰۴ تست jsdom پاس.
- **هدرهای امنیتی `respond()`** — CSP، `X-Frame-Options: DENY`، nosniff،
  CORP/COOP، `no-store`. بدون CORS. بدون سرو فایل از دیسک.

## ماژول‌های بدون هیچ تستی

`engine.rs` (FFI ویندوز — طبیعی)، `error.rs` (فقط تعریف)،
`native_gui.rs` (۶۹۷ خط، UI)، `main.rs` (۹۹۴ خط — **این یکی نگران‌کننده
است**؛ منطق reconcile رله و hot-reload آنجاست و هر دو باگ ۵ همان‌جا بودند).

## کارهای باقی‌مانده

1. روی ماشینی با Rust: `cargo test` و `cargo clippy -- -D warnings`.
   پنج تست رگرسیونی این بازبینی هنوز اجرا نشده‌اند.
2. برای منطق reconcile در `main.rs` تست بنویسید — بی‌تست‌ترین بخش پرریسک
   پروژه است.
3. ادعاهای مستندات دربارهٔ «۱۰۰٪ پوشش» و «همه‌چیز تست‌شده» با واقعیت
   نمی‌خوانند (`AUDIT_LINE_BY_LINE.md` و `GAPS_2026-09.md` خودشان قبلاً به
   بخشی از این اغراق‌ها اشاره کرده‌اند).
