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

# FINAL.md — نسخه نهایی `dpi_guard`

این فایل رفتار نهایی و تصمیم‌های سخت‌گیرانه‌ی این نسخه را مستند می‌کند.

## خلاصه

`dpi_guard` یک رله محلی **SNI-spoof** به سبک patterniha است:

- کلاینت TLS محلی به `127.0.0.1:40443` وصل می‌شود.
- رله به یک مقصد ثابت (`relay_connect_host:relay_connect_port`) وصل می‌شود.
- قبل از ClientHello واقعی، یک ClientHello جعلی با SNI خوش‌خیم و با
  **sequence number اشتباه** (`syn_seq + 1 - len`) تزریق می‌کند تا:
  - یک DPI آماری آن را به‌عنوان اتصال به دامنه‌ی خوش‌خیم بپذیرد،
  - استک TCP واقعی سرور آن را به‌عنوان داده قدیمی ACK کند و دور بریزد.
- بعد از تأیید (dup-ACK سرور)، داده‌های واقعی رله می‌شوند.

**هسته Xray/v2ray/sing-box وجود ندارد. VPN نیست. IP مقصد روی سیم پنهان
نمی‌شود.** این ابزار دور زدن سانسور در لایه‌ی SNI است، نه پنهان‌سازی مقصد.

## رفتار نهایی

1. **bind فقط 127.0.0.1**، نه 0.0.0.0. پیر غیرلوپبک drop می‌شود.
2. **Singleton lock** کنار exe با نام `dpi_guard.instance.lock`:
   - unix: `flock(LOCK_EX | LOCK_NB)`
   - windows: `CreateFileW` با `dwShareMode = 0`
   - هم‌زمان با اسکریپت پایتون patterniha اجرا نمی‌شود.
3. **ترتیب استارت**: اول singleton، بعد capture thread ویندایورت، بعد
   انتظار حداکثر ۳ ثانیه برای `capture_is_ready()`, و **بعد** رله.
4. **fail-closed injection** (`relay_require_inject = true` پیش‌فرض):
   اگر ClientHello جعلی ظرف ۳ ثانیه تأیید نشد، رله اتصال را می‌بندد تا
   ClientHello واقعی هیچ بایتی کپی نشود.
5. **فیلتر پیش‌فرض همه پورت‌ها** جز 22 (SSH)، 53 (DNS)، 3389 (RDP)، در هر
   دو جهت TCP و UDP.
6. **DoH پیش‌فرض** `https://1.1.1.1/dns-query`، با هدر
   `Accept: application/dns-message`، سقف بدنه 64 KiB، بدون fallback به
   UDP/53، فقط A، رد پاسخ‌های loopback/link-local.
7. **مقاصد ممنوع**: loopback, unspecified, broadcast, multicast,
   link-local, `169.254.169.254`, و IPv4-mapped IPv6. RFC1918 (مثل 10.x)
   مجاز است.
8. **hostnameهای ممنوع**: `localhost`, `metadata.google.internal`,
   `*.local`, `*.internal`.
9. **بدون لاگ IP خام**: تمام آدرس‌ها با `stealth::redact_endpoint` و
   نمک تصادفی پردازه به `ep-<sha256 کوتاه>` تبدیل می‌شوند. توکن و پین و
   `relay_connect_host` در `Debug` سانسور می‌شوند.
10. **داشبورد فقط 127.0.0.1** با توکن؛ `Host` باید 127.0.0.1 باشد
    (`localhost` رد می‌شود)؛ Origin محدود؛ CSP, X-Frame-Options=DENY,
    CORP, COOP؛ تأخیر 80ms روی هر 401؛ سقف درخواست ~16 KiB.

## فیلدها و ماژول‌های کلیدی

- `config::Settings` — `deny_unknown_fields`; فیلدهای جدید:
  `sni_only`, `sni_except`, `enable_tls_record_fragmentation`,
  `tls_record_chunk_size`, `enable_frag_by_sni`, `enable_autottl`,
  `autottl_delta`, `enable_http_host_tricks`, `enable_adaptive_desync`,
  `relay_require_inject`.
- `netguard` — `is_forbidden_dest`, `is_forbidden_hostname`,
  `validate_doh_url`, `validate_relay_ip`.
- `singleton` — قفل تک‌نمونه‌ای.
- `autottl` — یادگیری TTL از هاپ اینباند.
- `http_host` — ترفند Host و فیلتر `sni_only`/`sni_except`.
- `relay::InjectGate` — سیگنال موفقیت/شکست با `succeed/fail/was_ok/wait`.
- `relay::HandshakeMonitor` — تکنیک wrong_seq.
- `pipeline` — در ACK نهایی 3WHS بسته جعلی تزریق می‌شود؛ پس از
  dup-ACK سرور، `Complete`؛ در fail و با `require_inject` بایت واقعی کپی
  نمی‌شود.
- `fragmentation` — `fragment_as_tls_records` و
  `tls_record_split_before_sni`.
- `strategy::DesyncMode` — `tls-record`, `frag-by-sni`, `disorder`,
  `decoy`, `none`.

## صادقانه (بدون دروغ)

- **IP مقصد روی سیم دیده می‌شود**، دقیقاً مثل خود patterniha. پنهان‌سازی
  IP لایه VPN/REALITY است و در اسکوپ نیست.
- **بلاک DNS با WFP استاب است**؛ FFI واقعی پیاده نشده. برای جلوگیری از
  لو رفتن DNS از DoH سیستمی یا `doh_server` IP-literal استفاده کنید.
- **ECH فقط GREASE است** نه HPKE/ECH واقعی.
- **زمان‌بندی تزریق روی ویندوز واقعی در این سندباکس تست نشده است.**
- **`cargo test` اینجا اجرا نشده** چون rustc و crates.io در سندباکس قبلی
  در دسترس نبودند. روی ماشین ویندوزی خودتان `cargo test` و
  `cargo clippy -- -D warnings` را اجرا کنید.
- توکن گیتهاب نمی‌تواند محتوای `.github/workflows` را پوش کند؛ فایل
  workflow در `ci/github-actions.yml` نگه داشته شده و اپراتور باید خودش
  آن را در `.github/workflows/ci.yml` کپی کند.

## کامیت پیشنهادی

```
Harden patterniha-style relay: fail-closed inject, loopback bind, SSRF/DoH caps, all-port default.
Remove WinDivert binaries. Add first-run docs without an Xray core and a 1000-item sourced security checklist.
```

## LICENSE

MIT.
