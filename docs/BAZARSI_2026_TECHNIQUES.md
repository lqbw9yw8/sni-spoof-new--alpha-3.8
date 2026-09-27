# گزارش بازارسی ۲۰۲۶ — بخش ۲: ارزیابی ۱۰ تکنیک جدید

> اجرا شده در ۲۰۲۶-۰۹-۰۸ · مبنا: کد موجود `dpi_guard` + RFCهای مرجع

قالب ارزیابی (طبق پرامپت): مرجع پژوهشی، مکانیزم، چرا DPI را می‌شکند، ریسک ناسازگاری،
سختی، طرح تست، وضعیت پیشنهادی.

---

## تکنیک ۱ — تصادفی‌سازی ترتیب اکستنشن‌ها در هر اتصال

- **مرجع پژوهشی:** Chrome 110+ (ژانویه ۲۰۲۳) و Chrome 129.0.6668.58 (سپتامبر ۲۰۲۴)
  پیاده‌سازی‌های اصلی — [JA3 → JA4 migration analysis](https://voidmob.com/blog/ja3-vs-ja4-tls-fingerprinting-bot-detection-2026).
  همچنین Lantern corpus: «Randomization generates ≈994 billion unique fingerprint
  permutations (cipher shuffling: 109,600; extension shuffling: 994,218,624,000)»
  [corpus.lantern.io](https://corpus.lantern.io/techniques/tls-fingerprint/).
- **مکانیزم:** در `fragmentation.rs` قبل از هر seal/mutation، لیست اکستنشن‌های
  ClientHello (بعد از parser فعلی) shuffle می‌شود. پیاده‌سازی: parse → جمع‌آوری
  extension offsets → `rand::seq::SliceRandom::shuffle` → بازنویسی.
- **چرا DPI را می‌شکند:** اکثر DPIها استخراج‌کنندهٔ آفست‌محور دارند — با ترتیب ثابت،
  SNI همیشه در یک آفنس از ابتدای hello است. با ترتیب تصادفی، هر اتصال fingerprint
  یکتا تولید می‌کند و بلوک‌لیست‌های مبتنی بر JA3 (غیر از JA4 که مرتب می‌کند)
  ناکارآمد می‌شوند.
- **ریسک ناسازگاری با سرور:** **بسیار کم** — RFC 8446 §4.2 صراحتاً می‌گوید
  «The list of extensions MAY appear in any order». سرورها (Cloudflare, Nginx,
  Apache, AWS ALB) ترتیب را نادیده می‌گیرند.
- **سختی:** **متوسط** — نیاز به parser کامل اکستنشن‌ها + بازنویسی. موجود نیست
  در کد فعلی (grep `randomize.*extension` هیچ نتیجه ندارد). ~۲۰۰ خط + ۴ تست.
- **طرح تست:** واحد: بعد از permutation، record همچنان parseable است و همان
  extension-type set حفظ می‌شود. سیم: JA3 hash متفاوت است اما JA4 یکسان. TEST_MATRIX:
  ستون جدید `extension_shuffle`.
- **وضعیت پیشنهادی:** **پیاده‌سازی فوری** — ریسک کم، اثربخشی بالا، بدون تداخل با
  ECH واقعی.

---

## تکنیک ۲ — GREASE در cipher-suiteها + ترتیب تصادفی سایفر

- **مرجع پژوهشی:** RFC 8701 (GREASE). پیاده‌سازی Chrome: cipher-suites هم GREASE
  می‌شوند، نه فقط extensions.
- **مکانیزم:** در `utls.rs` یا ماژول جدید، قبل از seal: (الف) ۱–۲ cipher-suite
  GREASE (مقادیر `0x0A0A`, `0x1A1A`, …) به ابتدای لیست تزریق می‌شوند؛ (ب) کل لیست
  shuffle می‌شود.
- **چرا DPI را می‌شکند:** DPIهایی که cipher-suite list را به‌عنوان fingerprint
  استفاده می‌کنند (JA3، uTLS matcher) گیج می‌شوند. ترکیب با تکنیک ۱ → fingerprint
  کاملاً ناپایدار.
- **ریسک ناسازگاری:** **کم** — RFC 8701 صراحتاً می‌گوید سرورها مقادیر GREASE را
  باید نادیده بگیرند. ترتیب سایفر هم از نظر RFC آزاد است.
- **سختی:** **کم** — `utls.rs` قبلاً fingerprint templates دارد (۷ تست)؛ افزودن
  shuffle بعد از template application کافی است. ~۸۰ خط.
- **طرح تست:** واحد: بعد از shuffle، مقادیر GREASE در لیست هستند و سرور
  (mock handshake) همچنان cipher واقعی را انتخاب می‌کند.
- **وضعیت پیشنهادی:** **پیاده‌سازی فوری** — کم‌هزینه، بدون تداخل با ECH.

---

## تکنیک ۳ — SNI چندتایی (بی‌خطر اول، واقعی دوم)

- **مرجع پژوهشی:** RFC 6066 §3 — «"HostNameList" is a list of ServerName entries.
  The current specification only defines one type, host_name (0)». هیچ محدودیتی
  برای تعداد ورودی در RFC نیست.
- **مکانیزم:** در `fragmentation.rs::inject_hidden_sni_in_unknown_ext` (که قبلاً
  ۰xFF01 را استفاده می‌کند)، یک SNI اضافی type 0x0000 (host_name) به لیست اضافه
  شود — اول بی‌خطر، دوم واقعی. سرور اولین entry قابل‌پشتیبانی را انتخاب می‌کند.
- **چرا DPI را می‌شکند:** برخی DPIها فقط **اولین** SNI entry type 0x0000 را می‌خوانند.
  با این تکنیک، اولین SNI بی‌خطر است و DPI اجازه می‌دهد، ولی سرور می‌تواند دومین
  entry را هم ببیند.
- **ریسک ناسازگاری:** **متوسط** — برخی سرورها (و libraryها) فقط اولین SNI type 0
  را می‌پذیرند یا با خطا رد می‌کنند. نیاز به تست میدانی.
- **سختی:** **کم** — `inject_hidden_sni_in_unknown_ext` زیرساخت مشابه دارد؛ تغییر
  از type 0xFF01 به type 0x0000 و افزودن entry. ~۱۰۰ خط.
- **طرح تست:** واحد: SNI-list دارای ۲ entry type 0 است. سیم: DPI ساده فقط اولی را
  می‌بیند.
- **وضعیت پیشنهادی:** **پس از آزمون میدانی** — بدون تست روی سرورهای واقعی، نمی‌توان
  ادعای سازگاری کرد.

---

## تکنیک ۴ — واکشی خودکار ECHConfig از DoH/SVCB

- **مرجع پژوهشی:** RFC 9849 §5 — ECHConfig از HTTPS DNS record (type 65, SvcParam
  type 5 = `ech`). همچنین draft-ietf-dnsop-svcb-https.
- **مکانیزم:** در `doh.rs` یا `ech.rs`: پس از resolve دامنه، query HTTPS record
  (SVCB) از DoH server → استخراج `ech` SvcParam → parse با `parse_ech_config_from_https_record`
  (که **قبلاً در `ech.rs:70` وجود دارد**!) → تنظیم خودکار `real_ech_config_hex`.
- **چرا DPI را می‌شکند:** کاربر دیگر نیاز به copy-paste دستی hex ندارد؛ ECH واقعی
  به‌طور خودکار فعال می‌شود → SNI واقعی روی سیم پنهان می‌شود.
- **ریسک ناسازگاری:** **صفر** — کاملاً سمت کلاینت است؛ اگر واکشی شکست بخورد،
  fallback به رفتار قبلی (manual config) است.
- **سختی:** **متوسط** — زیرساخت DoH موجود است (`doh.rs` + `dns_cache.rs`)، parser
  ECHConfig موجود است. فقط wire-up + retry logic + cache. ~۳۰۰ خط.
- **طرح تست:** واحد: mock DoH response با HTTPS record → parse موفق. سیم: ECH
  واقعی بدون config دستی فعال می‌شود.
- **وضعیت پیشنهادی:** **پیاده‌سازی فوری** — UX عظیم + اثربخشی بالا.

---

## تکنیک ۵ — تصادفی‌سازی اثرانگشت هدر TCP/IP

- **مرجع پژوهشی:** `anti_fingerprint.rs` — قبلاً `randomize_ip_id` را پیاده کرده
  (۸ تست). این تکنیک گسترش به: window size، TCP options، TTL، DF bit.
- **مکانیزم:** در `anti_fingerprint.rs`: پرچم‌های جدید `randomize_window_size`,
  `randomize_tcp_options`, `randomize_ttl`. هر کدام یک range دارند.
- **چرا DPI را می‌شکند:** mTLS fingerprinters (p0f, nDPI) از این فیلدها برای
  تشخیص سیستم‌عامل و نوع کلاینت استفاده می‌کنند. با تصادفی‌سازی، fingerprint
  ناپایدار می‌شود.
- **ریسک ناسازگاری:** **کم–متوسط** — window size خیلی کوچک/بزرگ می‌تواند throughput
  را کم کند. TCP options اشتباه می‌تواند handshake را خراب کند. نیاز به range
  معتبر.
- **سختی:** **متوسط** — باید در packet-creation path (`packet.rs`) ادغام شود، نه
  فقط post-mutation. ~۲۵۰ خط.
- **طرح تست:** واحد: IP ID / TCP options در range معتبرند. سیم: Wireshark.
- **وضعیت پیشنهادی:** **پیاده‌سازی فوری** با پرچم خاموش پیش‌فرض + range محدود
  و مستند.

---

## تکنیک ۶ — جیتر زمانی تطبیقی (یادگیری تایم‌اوت باف DPI)

- **مرجع پژوهشی:** تحقیقات GFW — باف‌های DPI معمولاً قبل از آزادسازی ~۳۰–۱۲۰
  ثانیه بافر می‌کنند. اگر ترافیک بعد از آزادسازی بافر بیاید، DPI ردیابی نمی‌کند.
- **مکانیزم:** در `sequence.rs` یا `stealth.rs`: `adaptive_jitter_ms` — فاصلهٔ بین
  پکت decoy و پکت واقعی به‌طور تصادفی در یک range پویا (که از رفتار شبکه یاد می‌گیرد)
  توزیع می‌شود.
- **چرا DPI را می‌شکند:** اگر jitter > TTL بافر DPI، DPI دیگر decoy را به جریان
  واقعی ربط نمی‌دهد.
- **ریسک ناسازگاری:** **صفر** — فقط تأخیر، تغییری در payload. سرور متوجه نمی‌شود
  (TCP خودش ACK می‌فرستد).
- **سختی:** **متوسط** — یادگیری تطبیقی نیاز به state per-flow + الگوریتم ساده
  (exponential moving average). ~۲۰۰ خط.
- **طرح تست:** واحد: jitter در range است، میانگین با مشاهده‌ها adapt می‌شود.
- **وضعیت پیشنهادی:** **پیاده‌سازی فوری** — تأخیر قابل‌قبول (≤۵۰ms) + اثر بالا.

---

## تکنیک ۷ — فریب QUIC (Version Negotiation/Retry جعلی)

- **مرجع مرجع:** RFC 9000 (QUIC) — Version Negotiation packet (type 0) و Retry packet.
- **مکانیزم:** در `quic.rs` (که قبلاً `is_quic_initial` + `build_quic_decoy` دارد):
  پکت Version Negotiation جعلی بفرست که QUIC Initial server را گیج کند.
- **چرا DPI را می‌شکند:** برخی DPIهای QUIC (که تازه در حال ظهورند) فقط Initial
  packet را parse می‌کنند. با تزریق VN/Retry جعلی، parser به بن‌بست می‌رود.
- **ریسک ناسازگاری:** **بالا** — سرور QUIC واقعی این پکت‌ها را نمی‌پذیرد و
  connection را می‌بندد. فقط برای QUIC-avoidance (نه QUIC-multiplexing) قابل‌استفاده.
- **سختی:** **زیاد** — QUIC state machine پیچیده است. ~۴۰۰ خط.
- **طرح تست:** واحد: پکت جعلی با فرمت درست. سیم: Wireshark.
- **وضعیت پیشنهادی:** **فقط پژوهش** — ریسک ناسازگاری بالا، اثربخشی در عمل نامشخص.

---

## تکنیک ۸ — استتار آماری ضد DPI یادگیرنده (ML)

- **مرجع پژوهشی:** Frolov & Wustlow (2020) — هر ابزار circumvention (Tor, Lantern,
  OpenVPN, Psiphon) fingerprint آماری **قابل‌تمایز** از Chrome/Firefox دارد.
- **مکانیزم:** به‌جای تقلید یک fingerprint ثابت (که `utls.rs` انجام می‌دهد)،
  **توزیع آماری** fingerprintهای واقعی مرورگر را شبیه‌سازی کن: cipher-suites،
  extensions، lengths — همه با وزن واقعی.
- **چرا DPI را می‌شکند:** DPI یادگیرنده (ML-based) روی ویژگی‌های آماری آموزش
  دیده، نه روی مقادیر ثابت. با تطبیق توزیع، classifier نمی‌تواند تمایز دهد.
- **ریسک ناسازگاری:** **کم** — چون از توزیع واقعی مرورگر نمونه‌برداری می‌کند،
  سرور نمی‌تواند تمایز دهد.
- **سختی:** **زیاد** — نیاز به dataset واقعی fingerprintها + sampler. ~۵۰۰ خط +
  dataset embedding.
- **طرح تست:** واحد: توزیع نمونه‌ها از توزیع مرجع قابل‌تمایز نیست (Kolmogorov–
  Smirnov). سیم: Wireshark.
- **وضعیت پیشنهادی:** **فقط پژوهش** — ROI پایین در کوتاه‌مدت.

---

## تکنیک ۹ — دکوی نسخهٔ رکورد/هندشیک

- **مرجع:** RFC 8446 §4.1.2 — «A TLS 1.3 client which receives a TLS 1.2 or
  earlier ServerHello during the handshake MUST abort the handshake with a
  protocol_version alert». اما برای ClientHello: «legacy_record_version MUST be
  set to 0x0301 for all records».
- **مکانیزم:** رکورد TLS با `legacy_record_version = 0x0303` (TLS 1.2) ولی
  `ServerHello.version = 0x0304` (TLS 1.3) ارسال کن. یا برعکس.
- **چرا DPI را می‌شکند:** DPIهای سخت‌گیر که انتظار TLS 1.3 دارند، با version
  اشتباه به بن‌بست می‌روند یا پکت را رد می‌کنند.
- **ریسک ناسازگاری:** **بالا** — سرور واقعی alert می‌فرستد و connection را
  می‌بندد.
- **سختی:** **کم** — تغییر ۲ بایت. ~۵۰ خط.
- **طرح تست:** واحد: byte manipulation. سیم: Wireshark.
- **وضعیت پیشنهادی:** **فقط پژوهش** — سرورها خیلی سخت‌گیرند.

---

## تکنیک ۱۰ — پنهان‌سازی با ازسرگیری نشست (PSK/0-RTT)

- **مرجع:** RFC 8446 §4.2.9 — Pre-Shared Key extension و 0-RTT early data.
- **مکانیزم:** در `ech.rs` یا ماژول جدید: یک «warm-up» connection واقعی به سرور
  انجام بده، PSK استخراج کن، سپس connectionهای بعدی با PSK (و بدون SNI واضح)
  بساز.
- **چرا DPI را می‌شکند:** در 0-RTT، ClientHello بسیار کوتاه‌تر است و SNI می‌تواند
  در inner hello پنهان شود. DPI فقط outer hello را می‌بیند.
- **ریسک ناسازگاری:** **متوسط** — PSK نیاز به connection قبلی دارد (warm-up
  latency). 0-RTT replay protection لازم است.
- **سختی:** **زیاد** — نیاز به state management + TLS session cache. ~۴۰۰ خط.
- **طرح تست:** واحد: PSK درست استخراج و ذخیره می‌شود. سیم: Wireshark — handshake
  دوم SNI ندارد.
- **وضعیت پیشنهادی:** **پس از آزمون میدانی** — پیچیده، ولی اثربخشی بالا در برابر
  DPIهای SNI-based.

---

## اولویت‌بندی نهایی ۱۰ تکنیک

| # | تکنیک | ریسک | سختی | اثربخشی | اولویت |
|---|---|---|---|---|---|
| ۱ | تصادفی‌سازی ترتیب اکستنشن | کم | متوسط | بالا | 🔥 **P0** |
| ۲ | GREASE cipher-suite + shuffle | کم | کم | بالا | 🔥 **P0** |
| ۴ | واکشی خودکار ECHConfig از DoH/SVCB | صفر | متوسط | بالا | 🔥 **P0** |
| ۶ | جیتر زمانی تطبیقی | صفر | متوسط | متوسط–بالا | **P1** |
| ۵ | تصادفی‌سازی هدر TCP/IP | کم–متوسط | متوسط | متوسط | **P1** |
| ۳ | SNI چندتایی | متوسط | کم | متوسط | **P2** |
| ۱۰ | PSK/0-RTT | متوسط | زیاد | بالا | **P2** |
| ۷ | فریب QUIC | بالا | زیاد | نامشخص | **P3** |
| ۹ | دکوی نسخه | بالا | کم | کم | **P3** |
| ۸ | استتار آماری ML | کم | زیاد | بالا | **P4** |

### جمع‌بندی بخش ۲

- **۳ تکنیک P0** باید در نشست پیاده‌سازی اولویت‌دار باشند (تکنیک‌های ۱، ۲، ۴).
- **۲ تکنیک P1** (تکنیک‌های ۵، ۶) برای دور بعد.
- **۳ تکنیک P2/P3/P4** فعلاً در مرحلهٔ پژوهش باقی می‌مانند.
- **هیچ‌کدام از ۱۰ تکنیک با ECH واقعی تداخل ذاتی ندارند** — اما ترتیب اعمال
  آن‌ها (مُهر ECH به‌عنوان آخرین تغییر) بحرانی است، و تست‌های ترکیبی از گام ۳
  باید قبل از پیاده‌سازی هر تکنیک جدید نوشته شوند.
