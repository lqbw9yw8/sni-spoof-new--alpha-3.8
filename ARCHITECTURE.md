# ARCHITECTURE — وابستگی‌ها و مسیر اجرا

<!-- بخش گراف از tools/status.json تولید شده -->
<!-- source snapshot: 5231c27 + docs audit ۲۰۲۶-۰۹ -->

## چرخهٔ حیات خروج (Fail-Closed Lifecycle)

همهٔ مسیرهای خروج باید پروکسی سیستم را بازیابی کنند:

```text
Ctrl+C (tokio)  ─┐
فایل <config>.stop ──► watcher (≤200ms) ─┤
panic unwind    ─┘                       ▼
                    engine::graceful_shutdown
                              │
                              ▼
       restore_state()  ←  ProxyRestoreGuard (Drop, main.rs)
```

* GUI «Stop» ابتدا فایل stop را می‌نویسد و ۳ ثانیه مهلت می‌دهد؛
  kill فقط fallback است (قبلاً TerminateProcess بدون cleanup بود).
* `exit(1)`های محدود (پس از اتمام بودجه retry) بعد از restore رخ می‌دهند.

## مسیر اصلی اجرا

```text
  dpi_guard.toml
        │
        ▼
  config::Settings  ──validate()──►  خطا = بالا نمی‌آید
        │
        ▼
     main.rs   ◄──── webui.rs (hot-reload از /api/config)
        │
        ├──► singleton.rs      قفل تک‌نمونه
        ├──► integrity.rs      بررسی SHA-256 درایور
        ├──► engine.rs         WinDivert FFI  [Windows فقط]
        │         │
        │         ▼
        │    pipeline.rs       ◄── قلب پروژه، ۱۹ وابستگی
        │         │
        │         ├──► fragmentation.rs   پارس ClientHello
        │         ├──► sni_mutations.rs   تغییر SNI
        │         ├──► sequence.rs        seq/ack
        │         ├──► fooling.rs         بسته‌های decoy
        │         ├──► autottl.rs         تخمین TTL
        │         ├──► strategy.rs        انتخاب راهبرد
        │         └──► packet.rs          ساخت/checksum
        │
        └──► relay.rs          حالت رله TCP
                  │
                  └──► doh.rs ──► dns_cache.rs ──► netguard.rs
```

## ماژول‌های بحرانی

تغییر در این‌ها بیشترین ریسک را دارد:

| ماژول | چند ماژول به آن وابسته‌اند |
|---|---:|
| `error` | 29 |
| `fragmentation` | 8 |
| `packet` | 7 |
| `stealth` | 7 |
| `config` | 5 |
| `netguard` | 3 |
| `sni_mutations` | 3 |
| `fail_open` | 3 |
| `anti_fingerprint` | 2 |
| `integrity` | 2 |

## وابستگی هر ماژول

| ماژول | → وابسته به |
|---|---|
| `pipeline` | `anti_fingerprint`, `autottl`, `config`, `connection`, `ech`, `error`, `fail_open`, `fooling`, `fragmentation`, `geedge`, `http_host`, `packet`, `quic`, `relay`, `sequence`, `sni_mutations`, `stealth`, `strategy`, `utls` |
| `engine` | `anti_fingerprint`, `error`, `fail_open`, `fragmentation`, `handle_retire`, `integrity`, `packet`, `sequence` |
| `config` | `doh`, `error`, `isp_profiles`, `netguard`, `self_update`, `sni_mutations`, `stealth` |
| `engine_stub` | `engine`, `error`, `fail_open`, `fragmentation`, `packet` |
| `doh` | `dns_cache`, `error`, `netguard`, `stealth` |
| `webui` | `config`, `error`, `integrity`, `pipeline` |
| `geedge` | `error`, `fragmentation`, `sni_mutations` |
| `quic` | `config`, `error`, `packet` |
| `sequence` | `error`, `packet`, `stealth` |
| `utls` | `error`, `fragmentation`, `stealth` |
| `ech` | `error`, `fragmentation` |
| `fooling` | `error`, `packet` |
| `fragmentation` | `error`, `stealth` |
| `http_host` | `error`, `fragmentation` |
| `isp_profiles` | `config`, `error` |
| `relay` | `error`, `stealth` |
| `sni_mutations` | `error`, `fragmentation` |
| `stealth` | `dns_guard`, `error` |
| `anti_fingerprint` | `packet` |
| `client_detect` | `error` |
| `dns_cache` | `netguard` |
| `dns_guard` | `error` |
| `fail_open` | `error` |
| `integrity` | `error` |
| `mobile_gateway` | `error` |
| `native_gui` | `config` |
| `netguard` | `error` |
| `packet` | `error` |
| `proxy_cleanup` | `error` |
| `scanner` | `error` |
| `self_update` | `error` |
| `singleton` | `error` |

## نکات معماری که باید بدانید

* `#![deny(unsafe_code)]` روی کل crate اعمال می‌شود. فقط `engine.rs`
  (WinDivert FFI) و `singleton.rs` (`flock`/`CreateFileW`) دوباره فعالش می‌کنند.
* `engine_stub.rs` نسخهٔ غیرویندوزی `engine.rs` است تا crate روی Linux
  کامپایل و تست شود.
* `pipeline.rs` بزرگ‌ترین ماژول است (۳٬۳۱۹ خط؛ جزئیات جاری در
  `TEST_MATRIX.md`) و ۵۰ تست در سورس دارد. این اعداد شمارش ایستا هستند؛
  هر تغییری در آن باید با تست همراه باشد و اجرای فعلی Rust در این محیط
  `NOT TESTED` است.
* `error.rs` را ۲۹ ماژول استفاده می‌کنند — افزودن variant امن است،
  تغییر یا حذف variant نیست.
