# dpi_guard (Rust)

Modular DPI-evasion engine. Crate name: `dpi_guard` (GitHub repo:
[`lqbw9yw8/sni-spoof-new--alpha-3.6`](https://github.com/lqbw9yw8/sni-spoof-new--alpha-3.6)).
Windows-only for packet capture/injection (WinDivert);
every pure-logic module builds and tests on Linux/macOS/CI.

This crate is standalone. It does not include a Python engine or Node
control panel.

---

## ⚠️ وضعیت فعلی: `JS_VERIFIED_2026-09-12 / RUST_LAST_RUN_2026-09-09 / REAL_WIN_PENDING`

سه عدد مختلف برای «تعداد تست» در این مخزن دست‌به‌دست می‌شد (README: ۳۴۴،
STATUS: ۴۲۷، TEST_MATRIX: ۴۳۱). منبع حقیقت **سورس** است:

```bash
python3 tools/gen_status.py --check   # 42 modules, 449 tests declared
python3 tools/lint_docs.py            # prose may not drift from source
```

* **۴۴۹** تست Rust در سورس **نوشته** شده (`#[test]`). آخرین اجرای سبزِ
  baseline ثبت‌شده ۲۰۲۶-۰۹-۰۹ روی Rust 1.98.1/لینوکس **۴۳۱ تست** بود؛
  ۱۸ تست/تغییر تستیِ فعلی پس از آن baseline هنوز با cargo اجرا نشده‌اند
  (`cargo` در این محیط موجود نیست).
* **۳۷۵** چک jsdom/Node داشبورد (با regression XSS، raw-TOML confirmation و انتظار boot مقاوم) — این عدد
  در همین patch در ۲۰۲۶-۰۹-۱۲ **اجرا و پاس شد** (`cd uitest && npm test`).
* هیچ‌کدام از این‌ها ثابت نمی‌کند برنامه روی ویندوز با WinDivert درست کار
  می‌کند. برای آن `STATUS.md` و `.github/workflows/e2e.yml` را ببینید.

پیش از اعتماد به هر ادعایی، `cargo test --all-targets` را در محیطی که
`crates.io` در دسترس است اجرا کنید.

## نقشهٔ مستندات

| فایل | نقش |
|---|---|
| **[`AI_RULES.md`](AI_RULES.md)** | 🔴 اگر AI هستید، **اول این را بخوانید** |
| [`STATUS.md`](STATUS.md) | تنها منبع حقیقت دربارهٔ وضعیت |
| [`TEST_MATRIX.md`](TEST_MATRIX.md) | 🤖 تولید خودکار — دستی ویرایش نکنید |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | گراف وابستگی و مسیر اجرا |
| [`KNOWN_ISSUES.md`](KNOWN_ISSUES.md) | مشکلات تأییدشده با مدرک |
| [`CHANGELOG.md`](CHANGELOG.md) | تاریخچهٔ تغییرات |
| `docs/archive/` | ۱۶ سند قدیمی — ممکن است متناقض باشند |

```bash
python3 tools/gen_status.py   # بازتولید TEST_MATRIX.md از سورس
```

---

## How to use / نحوهٔ کار (خیلی ساده)

مثل توضیح برای یک بچهٔ ۱۰ ساله: قدم‌ها را **به ترتیب** انجام بده.
اگر یک قدم را جا بیندازی، برنامه کار نمی‌کند.

این برنامه **VPN نیست**. آدرس IP سرور روی اینترنت دیده می‌شود.
کارش فقط این است: قبل از دست‌دادن واقعی TLS، یک «سلام جعلی» با یک اسم سایت
بی‌خطر می‌فرستد تا فیلتر گول بخورد.

This is **not a VPN**. The server IP is still visible on the wire.
The program only sends a fake TLS “hello” with a harmless website name first,
so a filter may whitelist the connection.

### ۰) چه چیزی لازم داری / What you need

1. کامپیوتر **ویندوز ۱۰ یا ۱۱، ۶۴ بیتی** (روی لینوکس/مک خود برنامهٔ پکت کار نمی‌کند).
2. حساب **Administrator** (مثل کلید مدیر مدرسه).
3. برنامهٔ **Rust** برای ساختن فایل `.exe`
   ([rustup.rs](https://rustup.rs/) — گزینهٔ پیش‌فرض را بزن).
4. فایل‌های رسمی **WinDivert** (درایور):
   [reqrypt.org/windivert](https://reqrypt.org/windivert.html)
   یا [github.com/basil00/Divert/releases](https://github.com/basil00/Divert/releases)
5. اختیاری: **v2rayN** برای وصل کردن مرورگر به این رله.

1. A **64-bit Windows 10/11** PC (packet capture does not run on Linux/macOS).
2. An **Administrator** account.
3. **Rust** to build the `.exe` ([rustup.rs](https://rustup.rs/) — click the default).
4. Official **WinDivert** files (`WinDivert.dll` + `WinDivert64.sys`).
5. Optional: **v2rayN** so your browser can talk to this relay.

### ۱) دانلود آخرین نسخه / Download the latest version

آخرین کد روی همین ریپو است. شاخهٔ کار فعلی را از اینجا بگیر
(دکمهٔ سبز **Code → Download ZIP**):

**Latest zip (branch `main`):**
https://github.com/lqbw9yw8/sni-spoof-new--alpha-3.6/archive/refs/heads/main.zip

**Browse on GitHub:**
https://github.com/lqbw9yw8/sni-spoof-new--alpha-3.6/tree/main

ZIP را باز کن. پوشه را جایی ساده بگذار، مثلاً `C:\dpi_guard`.

Unzip it. Put the folder somewhere simple, e.g. `C:\dpi_guard`.

> هنوز یک فایل `.exe` آماده داخل گیت نیست. دو راه داری:
>
> **الف) روی خود ویندوز دابل‌کلیک:** `build-windows.bat` (Rust باید نصب باشد).
>
> **ب) گیت‌هاب برایت بسازد:** workflow واقعیِ
> [`.github/workflows/build-windows.yml`](.github/workflows/build-windows.yml)
> روی هر push اجرا می‌شود. در تب **Actions**، آرتیفکت `dpi_guard-windows` را
> دانلود کن. WinDivert داخل آن نیست.
>
> There is no pre-built `.exe` in git. Run `build-windows.bat` on Windows,
> or let the committed [`.github/workflows/build-windows.yml`](.github/workflows/build-windows.yml) workflow build the
> artifact on every push. The release workflow is tag-driven and publishes SHA-256 sums.
> The `ci/*.yml` files are byte-identical template copies kept for reference;
> the workflows GitHub executes live under `.github/workflows/`.


### ۲) ساختن برنامه / Build the program

یک پنجرهٔ **PowerShell** باز کن و برو داخل پوشه:

```powershell
cd C:\dpi_guard
rustup target add x86_64-pc-windows-msvc
cargo build --release --target x86_64-pc-windows-msvc
```

فایل ساخته‌شده اینجاست:

`target\x86_64-pc-windows-msvc\release\dpi_guard.exe`

The finished program is `dpi_guard.exe` in that folder.

### ۳) دو فایل جادویی را کنار exe بگذار / Put WinDivert next to the exe

از بستهٔ رسمی WinDivert این دو فایل را **دقیقاً کنار** `dpi_guard.exe` کپی کن
(نه در پوشهٔ کانفیگ، نه در Desktop جدا):

- `WinDivert.dll`
- `WinDivert64.sys`

Copy those two official files **next to** `dpi_guard.exe` (same folder).
Do **not** put them in git. Do **not** put them only in your Downloads folder.

### ۴) یک برگهٔ تنظیمات بنویس / Make a settings file

فایل نمونه را کپی کن:

```powershell
copy dpi_guard.toml.example dpi_guard.toml
```

با Notepad فایل `dpi_guard.toml` را باز کن و حداقل این‌ها را درست کن
(مثل پر کردن نام روی یک برگهٔ تکلیف):

```toml
relay_enabled       = true
relay_listen_port   = 40443              # هر پورتی خواستی؛ همین عدد را در v2rayN هم بگذار
relay_connect_host  = "server.example.com"  # دامنه کافی است؛ خودش IP را با DoH پیدا می‌کند
relay_connect_port  = 443
relay_fake_sni      = "www.microsoft.com"
relay_require_inject = true              # این را خاموش نکن
enable_web_ui       = true
web_ui_port         = 9090               # پورت داشبورد؛ با پورت رله یکی نباشد
doh_server          = "https://cloudflare-dns.com/dns-query"
```

- **پورت دلخواه است.** `40443` فقط یک پیشنهاد است. هر عدد آزاد بین ۱ تا ۶۵۵۳۵
  را می‌توانی بگذاری، **به شرطی که همان عدد** در v2rayN هم باشد.
  نگذار روی پورت داشبورد (`web_ui_port`) یا روی پورت‌های خود v2rayN
  (`10808` / `10809` / `10853`) مگر عمداً v2rayN را بسته باشی.
  پورت‌های ۲۲ / ۵۳ / ۳۳۸۹ را برای رله انتخاب نکن.
- **دیگر `ping` نزن و IP را از CMD کپی نکن** (مثل ویدیوی قدیمی patterniha
  که `ping static.cloudflareinsights.com` می‌زد و `104.16.79.73` را دستی
  وارد می‌کرد). آن کار مال این نسخه نیست.
- `relay_connect_host` را **دامنه** بگذار. برنامه با DoH خودش IP را پیدا می‌کند.
- اگر IP را خودت داری، همان را بگذار — آن‌وقت اصلاً DNS نمی‌زند (امن‌تر در برابر نشتی DNS).
- `relay_resolve_doh` را `true` بگذار (پیش‌فرض همین است). UDP/53 برای این lookup استفاده نمی‌شود.

You can put a **domain** in `relay_connect_host`. The program resolves the
real IPv4 over DoH (no plaintext UDP/53). An IP is optional, not required.
The listen port is **yours to choose** — same number in v2rayN.
Leave `relay_require_inject = true`.

Save the file **next to** `dpi_guard.exe`.

### ۵) اجرا با دسترسی مدیر / Run as Administrator

1. روی `dpi_guard.exe` راست‌کلیک → **Run as administrator**.
2. اگر قفل گفت برنامهٔ دیگری باز است، آن را ببند.
3. اگر داشبورد روشن است، در پنجره یک خط شبیه این می‌بینی:
   `web UI token (auto-generated, not written to the log file): ....`
   این رمز را کپی کن (مثل رمز درِ اتاق).

Right-click `dpi_guard.exe` → **Run as administrator**.
Copy the printed `web UI token` if the dashboard is on.

### ۵.۵) پنجرهٔ دسکتاپ — تب Overview / The desktop window — Overview tab

وقتی `dpi_guard.exe` را (به‌عنوان Administrator) اجرا می‌کنی، به‌جای مرورگر یک
**پنجرهٔ واقعی ویندوز** باز می‌شود. تب اول که باز می‌شود **Overview** است.
هر بخش این تب یعنی چه:

Running `dpi_guard.exe` (as Administrator) opens a **native Windows window**
instead of a browser tab. It starts on the **Overview** tab. What each part
of that screen means:

> توجه: جدول زیر پنجره را آن‌طور که طراحی شده توضیح می‌دهد؛ خودِ مسیر پکت روی ویندوز واقعی هنوز فیلدتست نشده (بخش Status را ببین).
> Note: the table below describes the window as designed; the packet path itself is not yet Windows field-tested (see Status).

| بخش پنجره / Screen part | توضیح / What it means |
|---|---|
| نوار عنوان `dpi_guard — Desktop Control Panel` | عنوان پنجره؛ فقط تأیید می‌کند این همان برنامه است. / Window title only — confirms this is the app. |
| نوار تب‌ها: `Overview · Proxy & SNI · Traffic · Connection · Advanced · Raw TOML` | شش بخش تنظیمات؛ هرکدام گروهی از ۸۲ تنظیم `dpi_guard.toml` را نشان می‌دهد تا در یک صفحهٔ بلند گم نشوی. کلیک روی هرکدام محتوا را عوض می‌کند، پنجره را نمی‌بندد. / Six settings groups (out of the 82 total in `dpi_guard.toml`), split up so you don't scroll one giant page. Clicking a tab swaps content only. |
| `dpi_guard` (تیتر بزرگ) + `Desktop control panel — no browser needed` | فقط توضیح می‌دهد این پنجره جایگزین داشبورد وب (`127.0.0.1:9090`) است؛ نیازی به مرورگر نیست. / Confirms this window replaces the web dashboard — no browser step needed. |
| `● Stopped` (قرمز) / `● Running` (سبز) | وضعیت زندهٔ پردازش پس‌زمینه (`dpi_guard.exe --backend`، همان که پکت‌ها را با WinDivert می‌گیرد). قرمز = چیزی گرفته نمی‌شود. سبز = فیلتر فعال است. / Live status of the backend process that actually captures packets via WinDivert. Red = nothing is intercepted. Green = filtering is active. |
| `Config file` | مسیر کامل فایل `dpi_guard.toml` که پنجره از آن می‌خواند/در آن می‌نویسد (مثلاً: `C:\dpi_guard\dpi_guard.toml`). / Full path of the `dpi_guard.toml` this window reads from and writes to. |
| `Mutation profile` | نام پروفایل جعل SNI که الان فعال است (`Stealth` و بقیه در تب Proxy & SNI انتخاب می‌شوند). / Which SNI-mutation profile is active (chosen on the Proxy & SNI tab). |
| `Covered ports` | چه پورت‌هایی رهگیری می‌شوند. مقدار پیش‌فرض «All ports (except 22/53/3389)» یعنی همه‌چیز به‌جز SSH، DNS و RDP. / Which ports are intercepted. Default shown is "all ports except 22/53/3389" (SSH, DNS, RDP always excluded). |
| `Relay mode` | اگر رلهٔ TCP (برای v2rayN) روشن باشد، آدرس گوش‌دادن و مقصد را همین‌جا می‌بینی؛ اگر `Disabled` است یعنی فقط جعل SNI روی ترافیک مستقیم انجام می‌شود، رله‌ای در کار نیست. / If TCP relay mode (for v2rayN) is on, its listen/destination address shows here. In the screenshot it's `Disabled` — only in-place SNI mutation runs, no relay. |
| دکمهٔ `▶ Start` | پردازش پس‌زمینه را با تنظیمات ذخیره‌شدهٔ فعلی روشن می‌کند؛ تا وقتی `Stopped` است فعال است. / Spawns the backend process using the currently saved settings. Enabled only while stopped. |
| دکمهٔ `■ Stop` | پردازش پس‌زمینه را می‌بندد؛ تا وقتی چیزی اجرا نشده غیرفعال (خاکستری) است. / Kills the backend process. Disabled (greyed) while nothing is running. |
| دکمهٔ `↻ Reload` | تنظیمات را دوباره از روی فایل `dpi_guard.toml` روی دیسک می‌خواند — هر تغییری که در پنجره زدی و هنوز Save نکردی از بین می‌رود. / Re-reads settings from `dpi_guard.toml` on disk — discards any unsaved edits made in the window. |
| دکمهٔ `💾 Save` | همهٔ فیلدهای پنجره (از هر شش تب) را روی فایل `dpi_guard.toml` می‌نویسد. اگر فایل وجود نداشته باشد، همین دکمه آن را با مقادیر پیش‌فرض می‌سازد (همان پیام پایین عکس). / Writes every field from all six tabs to `dpi_guard.toml`. If the file doesn't exist yet, this button creates it with defaults — matching the message shown under the button. |
| خط پیام زیر دکمه‌ها (مثال: «No config file found; defaults loaded. Click Save to create it.») | پیام موقت وضعیت یا خطا؛ بعد از هر عملیات (Start/Stop/Reload/Save) به‌روز می‌شود. / Transient status/error line, updated after each Start/Stop/Reload/Save action. |
| `Event log` (زیر پیام، در پنجره‌های بعدی اسکرول می‌شود) | تاریخچهٔ رویدادهای پردازش پس‌زمینه (روشن‌شدن، خاموش‌شدن، ری‌استارت خودکار در صورت کرش غیرمنتظره). / Scrolling history of backend events (start, stop, one automatic restart on an unexpected crash). |

### ۶) مرورگر را وصل کن (با v2rayN) / Point your client at it

زنجیره این است، مثل سه تا لولهٔ اسباب‌بازی که به هم وصل می‌شوند:

```
مرورگر  →  v2rayN  →  dpi_guard (127.0.0.1:<همان پورت>)  →  سرور واقعی
```

در v2rayN یک سرور بساز. **پورت را از جیبت در نیاور** — همان عددی که در
`relay_listen_port` نوشتی:

| فیلد | مقدار |
|---|---|
| Address / آدرس | `127.0.0.1` |
| Port / پورت | **همان `relay_listen_port`** (مثال: اگر toml شد `5555`، اینجا هم `5555`) |
| SNI / ServerName | **دامنهٔ واقعی سرور** (نه `www.microsoft.com`) |

اگر پورت برنامه `40443` باشد و v2rayN را روی `10808` بگذاری، به هم وصل نمی‌شوند.
دو تا در باید یک کلید داشته باشند.

- **REALITY / Hysteria / TUIC را از این مسیر رد نکن.** کار نمی‌کنند.
- در v2rayN، DNS را جدا تنظیم کن (تب Basic DNS Settings):
  Remote DNS = یک آدرس DoH مثل `https://dns.adguard.com/dns-query`
  Bootstrap DNS = یک IP مثل `94.140.14.14`
  آن تب مال v2rayN است، نه مال این برنامه.

Do **not** send REALITY / Hysteria / TUIC through this relay.
In v2rayN, set Remote DNS to DoH and Bootstrap DNS to an IP.

### ۷) داشبورد (اختیاری) / Dashboard (optional)

فقط این آدرس را در مرورگر باز کن (نه `localhost`):

http://127.0.0.1:9090

توکن را بچسبان. همهٔ ۸۲ تنظیم از همین صفحه عوض می‌شوند.
دکمهٔ **ذخیره** را بزن. حدود ۱ ثانیه بعد اعمال می‌شود.

Open **http://127.0.0.1:9090** (not `localhost`). Paste the token.
All 82 settings are editable there. Click **Save**.

### ۸) اگر خراب شد / If it breaks

| چه می‌بینی | یعنی چه | چه کار کن |
|---|---|---|
| `lock ... held` | یک نسخهٔ دیگر باز است | آن را ببند |
| `WinDivert ... not found` | dll/sys کنار exe نیست | قدم ۳ |
| `capture did not become ready` | درایور یا دسترسی | Administrator + WinDivert رسمی |
| `relay destination ... forbidden` | IP لوپ‌بک/ممنوع | یک IP عمومی یا LAN بگذار |
| `fake injection not confirmed ... dropping` | تزریق تأیید نشد (عمدی) | فیلتر و پورت مقصد را چک کن |

Set `RUST_LOG=dpi_guard=debug` if you want more log lines.

### ۹) چیزهایی که نباید فراموش کنی / Do not forget

- این برنامه IP را قایم نمی‌کند.
- WinDivert پورت‌های ۲۲ و ۵۳ و ۳۳۸۹ را نمی‌گیرد؛ DNS خروجیِ پورت ۵۳ در Windows با WFP (به‌جز loopback) مسدود می‌شود.
- رله فقط به `127.0.0.1` گوش می‌دهد، نه به کل اینترنت.
- فایل‌های `.dll` و `.sys` و `dpi_guard.toml` را داخل گیت نگذار.

This program does **not** hide the destination IP.
WinDivert does not intercept ports 22, 53, or 3389; on Windows, outbound
plaintext DNS on port 53 is blocked by WFP except to loopback.
The relay listens on `127.0.0.1` only.

راهنمای فارسیِ کامل‌تر: [`START_HERE.md`](docs/archive/START_HERE.md)

---


## Status: read this before deploying

This is a first pass, not a finished, field-tested tool. Two tiers:

- **[IMPLEMENTED / verification-dependent]** — implementation and unit tests
  are present in-tree; the current source declares **449** `#[test]`
  functions. This is not evidence that the current checkout was executed:
  the last recorded Rust baseline is **431/431**, while 16 current tests or
  test changes remain `[UNVERIFIED]` because this environment has no
  `cargo`. Run `cargo test --all-targets` before treating a module as
  runtime-verified. See `STATUS.md` §3/§8.
- **[PARTIAL]** — the dynamic user-mode WFP FFI now installs a real
  fail-closed port-53 block (loopback exception, IPv4 + IPv6) on Windows.
  The signed kernel callout needed for packet *redirection* to `trusted_dns`
  is still not in this repository, and the kill-switch process is still not
  auto-spawned (its command is built and sanitised, never executed).

`engine.rs` is written against the published `windivert` 0.5.5 API
(`WinDivert::network`, `recv(Some(&mut buf))`, `send`, `shutdown`,
`close`) but has **not** been compiled on a Windows host in this
environment. Before a real network path: `cargo build --release --target
x86_64-pc-windows-msvc`, place official `WinDivert.dll` +
`WinDivert64.sys` next to the binary (never commit them), run as
Administrator.

## Why this should not destabilize Windows

- **Fail-open on every packet.** `fail_open::handle_exception_fail_open`
  wraps every mutation in `catch_unwind`. Panic *or* `Err` re-injects the
  original packet. The fallback is logged.
- **Filter.** The default filter is **all TCP and UDP ports in both
  directions, never loopback, always excluding SSH (22), DNS (53) and RDP
  (3389)** (`NEVER_INTERCEPT_PORTS`). SSH/RDP remain available; the separate
  Windows WFP guard handles plaintext DNS and blocks it except to loopback.
  Narrow it by setting
  `intercept_all_tcp = false`, `intercept_all_udp = false` and listing
  ports in `intercept_ports`. When relay mode is on, the relay destination
  port is guaranteed to be included in the filter.
- **Hot-reload filter.** When `intercept_ports` / `intercept_all_*` change
  in `dpi_guard.toml`, the watcher requests a WinDivert filter reload: the
  capture loop closes the old handle and reopens with the new filter
  (`engine::request_filter_reload`).
- **Dynamic WFP DNS guard.** On Windows startup,
  `dns_guard::block_port_53_except_localhost` opens a real dynamic BFE
  session, installs four transactional filters (loopback permit + port-53
  block for IPv4 and IPv6), and fails closed if any WFP call fails. The
  session is explicitly deleted on normal shutdown and is crash-cleaned by
  `FWPM_SESSION_FLAG_DYNAMIC`. Semantics note (fail-closed, by design): the
  guard **blocks** plaintext port 53 — it does **not** redirect it to DoH.
  An app that insists on plaintext DNS loses DNS entirely instead of
  silently leaking through an unguarded path.
- **Graceful shutdown.** Ctrl+C (`tokio::signal`) sets a flag and calls
  `WinDivertShutdown`, which unblocks `recv` so diversion does not sit on
  the NIC until the next packet.
- **One capture handle.** Extra injects use a send-only handle with
  filter `false`, so they do not steal packets from capture. Decoys
  produced by the pipeline are sent on the capture handle with the
  original WinDivert address.
- **Outbound decoys** use this host's existing 5-tuple and a TTL low
  enough to die before the real server. Endpoint-swap SYN-ACK/RST
  foolers are off unless `enable_swap_foolers = true`.

None of this makes kernel-level packet interception risk-free. Test on a
VM first. Tune `decoy_ttl` by measuring hops to the DPI box.

## Build & Dev

```bash
# pure-logic modules — any OS, no WinDivert needed
# RUST_LOG=dpi_guard=debug cargo test
cargo test

# formatting + lint (rust-toolchain.toml requires stable + clippy + rustfmt)
cargo fmt --check
cargo clippy -- -D warnings

# Windows build prerequisite: windivert-sys needs the official DLL, LIB and
# SYS files at compile time. Set this to the x64 folder from the WinDivert
# archive before cargo run/build:
#   $env:WINDIVERT_PATH = 'C:\\path\\to\\WinDivert\\x64'
# The DLL and SYS must also be copied next to the final exe at runtime.

# the real binary — Windows only
cargo build --release --target x86_64-pc-windows-msvc
```

### What still needs a real Windows host

`engine.rs` was written against the published `windivert` 0.5.5 docs and type
signatures but has NOT been field-tested in this sandbox (no Windows, no driver):
- `WinDivert::network`, `recv(Some(&mut buf))`, `send`, `shutdown`, `close`
- TTL-limited decoys actually reaching DPI but expiring before origin
- `take_expired_held` watchdog (200ms) re-injecting with original WinDivert address
- graceful shutdown unblocking `recv`

To test: Windows 10/11 VM, Administrator, official WinDivert dll/sys from
reqrypt.org next to exe, `RUST_LOG=dpi_guard=debug`, measure `decoy_ttl`
by `tracert -d 1.1.1.1` and set to hops-to-DPI.

Hold/reassembly integration tests are now covered in `pipeline.rs`:
`expired_held_is_flushed_by_watchdog`, `max_flows_cap_fail_opens`,
`flow_buf_overflow_fail_opens_both`, `recent_eviction_halves_on_cap`,
`idle_flush_removes_old_flows_and_recent`.

Copy `dpi_guard.toml.example` to `dpi_guard.toml` next to the binary and
edit it. Run as Administrator. Place `WinDivert.dll`/`WinDivert64.sys`
next to the binary — **do not commit those binaries**; `.gitignore`
excludes `*.dll` / `*.sys` / `*.lib` (they were historically tracked once;
the 2026-09 fix round removed them — use
`scripts/fetch-windivert.ps1` / `.sh` for the hash-verified official
release, which `.cargo/config.toml` and CI call automatically). Fetch
WinDivert from its official release:
https://reqrypt.org/windivert.html and https://github.com/basil00/Divert/releases

Pin the driver hashes (supply-chain protection):
```powershell
# Windows PowerShell - after downloading official WinDivert zip
certutil -hashfile WinDivert.dll SHA256
certutil -hashfile WinDivert64.sys SHA256
# paste the two hex strings into win_divert_sha256 in dpi_guard.toml
```
```bash
# Linux verify (if you check the zip on Linux first)
sha256sum WinDivert.dll WinDivert64.sys
```

## DNS leak warning (important)

SNI mutation alone does **NOT** hide which domain you visit. On Windows,
`dns_guard` now installs a real dynamic WFP policy that blocks outbound
TCP/UDP port 53 except `127.0.0.1:53` and `[::1]:53`; startup fails closed if
that policy cannot be installed. This is blocking, not redirection: the
signed kernel callout required to redirect to `trusted_dns` is not shipped;
non-empty `trusted_dns` values are rejected fail-closed rather than
pretending that a user-mode block performs redirection.

**What to do instead:**
- Windows 11: Settings → Network → DNS → enable DNS over HTTPS (DoH) to
  `1.1.1.1` / `8.8.8.8` / `9.9.9.9` with template `https://cloudflare-dns.com/dns-query`
- Windows 10: use [dnscrypt-proxy](https://github.com/DNSCrypt/dnscrypt-proxy) or
  [AdGuard](https://adguard.com/) or YogaDNS with DoH/DoT upstream
- Verify: https://www.cloudflare.com/ssl/encrypted-sni/ and `https://1.1.1.1/help`
  should show "Using DNS over HTTPS (DoH) - Yes"
- `trusted_dns` in `dpi_guard.toml` is a legacy redirect key. Non-empty
  values are rejected because the signed WFP callout is not shipped; it does
  NOT enable DoH. Use `doh_server` / `relay_resolve_doh` instead.

If you keep plain UDP/53, DPI sees the domain even if SNI is mutated.

## Security note

An earlier sibling codebase (not in this repo) was flagged for binding a
proxy to `0.0.0.0`, a control-panel API without auth/CSRF, and committing
pre-built WinDivert binaries. This crate:

- has **no** network-facing listen socket. The optional dashboard
  (`enable_web_ui = true`) binds `127.0.0.1` only, requires
  `Host: 127.0.0.1` (DNS-rebind names and `localhost` are rejected),
  checks `Origin` on browser fetches, and requires a bearer token on
  every API call; it is OFF by default. Tokens in logs/`Debug` are
  redacted except the one-time auto-generated print.
- gitignores `*.dll` / `*.sys` / `dpi_guard.toml`
- `version_check` searches **only the executable directory** (never cwd)
  and refuses to start if the driver files are missing. It also refuses
  to start unless `win_divert_sha256` contains exactly two pins. Every
  driver binary is SHA-256 compared in constant time against the ordered
  two-pin list (`WinDivert.dll`, then `WinDivert64.sys`); files over 16 MiB
  are refused.
- a missing default `dpi_guard.toml` uses compiled defaults; an
  **invalid or explicitly-passed missing** config file is fail-closed
  (process exits). Unknown TOML keys are rejected.
- kill-switch adapter names are restricted to `[A-Za-z0-9 _-]+` and the
  process is never spawned unless you add that yourself with
  `enable_kill_switch` (even then only the command string is logged)
- fail-open: panics, parse errors, and held ClientHello fragments that
  time out are re-injected unmodified. Mutex poisoning does not take
  the packet path down.

## Resilience on unreliable networks

Designed for links that drop constantly (frequent outages, heavy packet
loss, adapters being reset, sleep/resume). `RESILIENCE.md` documents the
full behaviour; the short version:

| Requirement | Where | Bound |
|---|---|---|
| Retry + exponential backoff | `engine::recv_backoff`, `doh::retry_backoff` | 500 ms / 2 s caps |
| Timeouts on every network wait | DoH 5 s, relay connect 10 s, inject wait 3 s, held 200 ms | client wait ≤ 15 s |
| Never crash, wait to reconnect | `fail_open::handle_exception_fail_open` + a 30 s relay start retry | — |
| Resume after a restart mid-outage | `dns_cache` mirrored to `dpi_guard.dns_cache` next to the exe | 64 KiB / 256 entries |
| Offline survival | stale DoH answers served (logged as `STALE`) when every attempt fails | ≤ 6 h stale |

The single strongest option for an unstable link: set
`relay_connect_host` to an **IP literal**. Then no DNS happens at all —
no DoH, no UDP/53 — and nothing in the startup path depends on the
network being up.

`uitest/test-resilience.mjs` (60 checks) maps each requirement onto the
code that implements it.

## Optional local dashboard

Set `enable_web_ui = true` (and optionally `web_ui_port`, `web_ui_token`)
in `dpi_guard.toml`. The dashboard serves at `http://127.0.0.1:9090`
(**not** `http://localhost:9090` — the `Host` header must be loopback
IPv4) and shows live settings, packet count, hashed per-domain strategy
scores, and hashed recent SNIs. Every `/api/*` route requires the bearer
token; leave `web_ui_token` empty to auto-generate one (printed to the
console/stderr — deliberately never written to the log file). A configured token must be at least 16 printable ASCII characters.

**Every setting is editable.** The page (`src/webui/index.html`, embedded
with `include_str!`) declares a schema covering all 82 `Settings` fields,
grouped into twelve sections (core, fingerprint, anti-fingerprint, ISP,
port scope, TLS, desync, relay, DNS, web-UI, ops, tools) across the
Proxy & SNI / Traffic / Connection / Advanced tabs, in Persian RTL,
with search, dirty tracking, revert, JSON
import/export, and an advanced TOML editor. Client-side validation mirrors
`Settings::validate()`; errors block Save while risky-but-legal states only
warn. Saving sends a *partial* TOML containing only the keys you changed.
`POST /api/validate` runs the same validation without touching disk, so you
can see the server's exact rejection reason before committing.

Dangerous toggles ask for confirmation first: `intercept_all_tcp`,
`intercept_all_udp`, `enable_swap_foolers`, and turning **off**
`relay_require_inject` (fail-closed). The web-UI token and driver pins are
never echoed back by the API — leaving them empty means "keep what is
there", so Save can never wipe them.

Adding a field to `Settings` without adding it to the page fails
`cargo test` (`webui::ui_schema_tests::every_settings_field_is_editable_in_the_ui`).

### Dashboard tests

The page has no build step, so it is tested as the artifact it is:
`uitest/` loads the **real** `src/webui/index.html` in jsdom against a mock
of the routes above (including a faithful port of `Settings::validate` and
`config::merge_partial`) and asserts coverage, validation parity, partial-TOML
correctness, redaction, and the 401 path. A real TOML parser
(`@iarna/toml`) validates everything the page emits.

```bash
cd uitest && npm ci && npm test   # 110 UI + 56 schema + 67 v2rayN + 60 resilience + 56 settings + 26 status = 375 checks
npm run test:v2rayn                    # just the v2rayN coexistence suite
npm run preview                        # click it: http://127.0.0.1:8787
```

`test-v2rayn.mjs` labels each of its checks honestly: `[RUNS SHIPPED CODE]`
drives the real dashboard in jsdom and parses its output with a real TOML
parser; `[STATIC SOURCE]` only proves an invariant is present in the Rust
source (not that it behaves correctly at runtime); `[DOC CONSISTENCY]`
checks the documented v2rayN setup against the code's defaults. True
end-to-end interop needs Windows + WinDivert + v2rayN; the manual
procedure is printed at the end of that file.

`.github/workflows/ci.yml` runs Rust fmt/build/test/clippy, the jsdom suite, and documentation parity checks on every push/PR. `.github/workflows/build-windows.yml` builds the Windows artifact; `.github/workflows/e2e.yml` is the manual/scheduled WinDivert field job.

## Module map (2025-2026 upgrades)

> **Current verification boundary:** the Rust toolchain is absent in this checkout. `UNTESTED` means implementation is present but current Rust tests were not executed; it is not a green runtime claim. Windows/WinDivert rows remain separately unverified.

| File | Role | Status |
|---|---|---|
| `sni_mutations.rs` | 12+ SNI mutations + 7 profiles (Stealth, ChinaGfw, RussiaDpi, Aggressive, ChinaRegional, Henan, **NestedCloak**) + SNI disguise GREASE/private | UNTESTED |
| `fragmentation.rs` | TLS parse, SNI splice + length rewrite, TCP-level split + **disguise_sni_extension_type**, **front_sni_with_benign**, **inject_hidden_sni_in_unknown_ext** | UNTESTED + NEW |
| `packet.rs` | IPv4/IPv6 + TCP/UDP parse, checksums, segmentation, l3_slice | UNTESTED |
| `quic.rs` | **NEW**: QUIC Initial detection, port blindspot (src<=dst bypass per USENIX 2025), UDP src rewrite, decoy, QuicPortMapper | UNTESTED + NEW |
| `pipeline.rs` | live packet processor + QUIC bypass + SNI fronting/disguise + combined TCP+TLS frag for Henan | UNTESTED + ENHANCED |
| `fail_open.rs` | panic/Err → original packet | UNTESTED |
| `sequence.rs` | decoy / SEQ / TTL | UNTESTED |
| `fooling.rs` | checksum/RST/SYN-ACK/disorder/UDP-len builders | UNTESTED |
| `strategy.rs` | per-domain scoring, A/B block-type | UNTESTED |
| `stealth.rs` | jitter, options, GREASE, hash, kill-switch string | PARTIAL |
| `connection.rs` | health, IP rotate, LRU tickets, backoff | UNTESTED |
| `dns_guard.rs` | Dynamic WFP port-53 block with loopback exception (IPv4 + IPv6); legacy `trusted_dns` redirect is rejected until a signed callout exists | PARTIAL, Windows runtime unverified |
| `doh.rs` | DoH A-record lookup plus per-request resolver filtering of endpoint `SocketAddr`s | PARTIAL, cargo/runtime NOT TESTED after hardening |
| `engine.rs` | WinDivert I/O | written to 0.5.5 API, unverified on Windows |
| `engine_stub.rs` | same signatures, PlatformNotSupported | STUB |
| `config.rs` | TOML + validated fields + hot reload + new QUIC/fronting options | UNTESTED + ENHANCED |
| `integrity.rs` | SHA-256 pin compare and bounded driver-file hashing | UNTESTED |
| `observability.rs` | rotating JSON-lines metrics and bounded runtime counters | PARTIAL, cargo/runtime unverified |
| `hpke.rs` | **NEW 2026**: pure-Rust HPKE base mode for real ECH — X25519, HKDF-SHA256, ChaCha20Poly1305 (RFC 7748/5869/8439/9180 vectors) | UNTESTED |
| `webui.rs` | opt-in 127.0.0.1 dashboard + 7 profiles | UNTESTED + ENHANCED |
| `netguard.rs` | SSRF guards: forbidden dests/hostnames, DoH URL + relay IP validation | UNTESTED |
| `singleton.rs` | one-instance file lock next to the exe (flock/CreateFileW) | UNTESTED |
| `autottl.rs` | learn decoy TTL from inbound hop count | UNTESTED |
| `http_host.rs` | HTTP Host-line split trick + `sni_only`/`sni_except` filters | UNTESTED |
| `error.rs` | crate error type | UNTESTED |

### New profiles (2025 research)

- **ChinaGfw**: case randomization + 64-byte TCP frag + QUIC port bypass if enabled. Classic GFW.
- **ChinaRegional / Henan**: case + trailing dot, 32/24-byte chunks, disorder_mode always ON, combined TCP+TLS fragmentation (persistent_fragmentation 16), TTL decoys. Targets Henan Firewall stateless parsing bug (IEEE S&P 2025).
- **Stealth**: minimal, identity-preserving.
- **Aggressive**: null-byte, explode, underscore, dots, overflow, port suffix + optional SNI disguise + fronting.
- **NestedCloak** (2026): nested extension cloaking — visible SNI becomes a
  benign cover (`fronting_benign_sni`), the real name travels intact inside
  private extension `0xFF01`, and the ClientHello is emitted as exactly three
  TCP segments `[cover] [ext header + 32 bytes of the name] [rest of the
  name]` with `disorder_mode` ON and combined fragmentation forced. A DPI
  that does not reassemble TCP streams ever sees only the cover.

### 2026 roadmap upgrades (all opt-in, defaults unchanged)

- **`enable_frag_mid_sni`** — TLS-record fragmentation that straddles the SNI:
  the name is split across two well-formed `0x16` records; no single record
  contains the full name (`fragmentation::tls_record_split_mid_sni`).
- **`enable_padding_inflation`** — random 64–384-byte RFC 7685 padding per
  connection to break fixed-size ClientHello fingerprints
  (`geedge::inflate_padding_random`).
- **`enable_ech_grease`** — always-on ECH-GREASE under the real type
  `0xFE0D` (was GREASE `0x1201`), random 64–160-byte payload, so ECH
  presence/absence cannot classify traffic (`ech::inject_ech_grease_fe0d`).
- **`enable_strategy_rotation`** — per-connection weighted-random strategy
  rotation among winning techniques (`strategy::select_rotating`), with
  score decay every 32 feedback events and an escalation ladder
  (Stealth → ChinaGfw → RussiaDpi → ChinaRegional → Henan → NestedCloak)
  when the configured profile keeps losing.
- **`enable_real_ech` + `real_ech_config_hex`** — real Encrypted Client
  Hello: the inner ClientHello is HPKE-sealed with the server's ECHConfig
  (DHKEM(X25519) + HKDF-SHA256 + ChaCha20Poly1305, suite `0x0001`,`0x0003`),
  outer SNI becomes the config's `public_name` (`ech::seal_real_ech_hello`,
  crypto in `hpke.rs`). The wire format follows the final standard
  **RFC 9849** (extension `kdf|aead|config_id|enc|payload`; AAD = the outer
  ClientHello body with the payload zeroed; `info = "tls ech\0" || ECHConfig`;
  inner hello with empty session-id, inner marker `0xFE0D→0x01`, zero
  padding to a multiple of 32), validated against the BoringSSL/NSS
  reference behaviour and round-trip decrypt-tested. Requires a destination
  server that actually supports ECH; paste the `ech=` SVCB octets as hex.
  When armed it supersedes fronting/disguise/NestedCloak and must run last,
  so the pipeline skips uTLS/Geedge/padding-inflation for that connection.

### QUIC blindspot (USENIX 2025 #1)

GFW inspects QUIC Initial only when `src_port > dst_port`. Setting `src_port <= dst_port` (e.g., 443->443) bypasses completely. This crate implements:

```rust
quic::is_quic_initial(payload) -> bool
quic::gfw_would_inspect_quic(src, dst) -> bool // src > dst
quic::choose_bypass_source_port(dst) -> u16 // dst itself (equal)
quic::rewrite_udp_src_port(packet, new_sport)
```

Enable via `enable_quic_port_bypass = true` in config. WinDivert can spoof any
src port even privileged. The pipeline now tracks every spoofed flow in
`quic::QuicPortMapper` and rewrites the whole flow, not just the Initial:
outbound packets keep the spoofed source port, and inbound replies to the
spoofed port are rewritten back to the client's original source port
(`quic::rewrite_udp_dst_port`). The blindspot rule applies to any intercepted
UDP port, not just 443. Mappings are capped (`quic::MAX_QUIC_MAPS`) and pruned
on idle.

## Relay mode (patterniha-style, opt-in)

In addition to the transparent SNI-mutation mode, the crate can run as a
**local TCP relay** like `patterniha/SNI-Spoofing`:

1. `dpi_guard` binds `127.0.0.1:<relay_listen_port>`.
2. You point v2rayN at `127.0.0.1:<relay_listen_port>` with the real server
   domain as SNI.
3. For each connection the relay connects to the fixed destination
   `relay_connect_host:relay_connect_port` and injects a fake ClientHello
   carrying `relay_fake_sni` (a benign domain) with a wrong sequence number,
   so a stateless DPI whitelists the flow on the benign SNI while the real
   server drops the fake.

Safety properties (differences from the reference implementation):

- The listener binds **127.0.0.1 only** (never `0.0.0.0`); non-loopback
  accepted peers are dropped.
- The destination is **fixed** (`relay_connect_host`), so the relay can
  never be used as an open proxy by third parties.
- A singleton file lock (`dpi_guard.instance.lock` next to the exe)
  prevents running two copies, or running dpi_guard alongside the
  patterniha Python relay.
- The WinDivert capture thread is started **first** and the relay waits up
  to 3 s for `capture_is_ready()` before connecting; if capture never
  comes up the relay is not started — at boot or later (`reconcile` and
  the 30 s retry are gated on the same flag, fail-closed).
- **Fail-closed injection.** After the outbound 3-way handshake the relay
  waits up to 3 s for the pipeline to confirm the fake ClientHello was
  dup-ACKed by the server. If `relay_require_inject = true` (the default)
  and that confirmation never arrives, the relay drops the connection
  **without copying a single byte of the real ClientHello**.
- Domain resolution is **DoH-only** (`relay_resolve_doh`, default
  `https://cloudflare-dns.com/dns-query`); the built-in endpoint keeps the
  certificate-bearing hostname for TLS verification while pinning
  `1.1.1.1`/`1.0.0.1` before connect. There is **no** plaintext-DNS fallback,
  no AAAA queries, and loopback/metadata answers are rejected.
- Configuring `relay_connect_host` as an IP literal skips DNS entirely
  (zero leak). Loopback/link-local/multicast/metadata destinations are
  refused (see `netguard`).
- Destination endpoints in log lines are hashed with a per-process salt
  (`stealth::redact_endpoint`); raw IPs are never logged — this covers the
  relay destination, the DoH cache-fallback path, the SNI-scanner edge list
  and the mobile-gateway LAN report. The configured destination *domain
  name* still appears in DoH diagnostic lines by design (it is not an IP).

> **DNS / IP leak notes:** (1) use an IP literal for `relay_connect_host` or
> keep `relay_resolve_doh = true`; (2) the injected fake uses the real
> connection's IP — this is SNI spoofing, not IP hiding; the DPI still sees
> the destination IP. Hiding the destination IP is a different technique
> (e.g. VLESS Reality) and out of scope here. (3) Hostname DoH endpoints are
> supported: the per-request `ureq::Agent` filters every resolver
> `SocketAddr` with `netguard` before connecting and disables redirects, so a
> DNS-rebinding answer cannot move the request to a forbidden address. The
> built-in `cloudflare-dns.com` endpoint additionally uses pinned
> `1.1.1.1`/`1.0.0.1` addresses while retaining the hostname for TLS SNI and
> certificate verification. Custom endpoints use their one checked resolver
> result; there is no second lookup after validation.

Extra relay toggles (defense-in-depth, both off by default):

- `relay_mutate_real_sni = true` — after the fake handshake completes, the
  flow's *real* ClientHello is also run through the normal SNI-mutation
  pipeline.
- `relay_emit_decoy = true` — at injection time, an extra TTL-limited
  wrong-checksum decoy of the fake ClientHello is also emitted.

### Dashboard config editing & Start/Stop

With `enable_web_ui = true`, the dashboard (`http://127.0.0.1:9090`) edits
**every** setting: 82 schema-driven controls in twelve sections, plus an
advanced full-config TOML editor. There is no separate "Start relay" /
"Stop relay" button any more — `relay_enabled` is just another switch, and
because Save writes `dpi_guard.toml` through the exact same validated parse
path as the file itself (`config::merge_partial`), the running relay is
reconciled automatically within about a second (≈1 s with an IP literal;
longer while the destination domain resolves over DoH on a background
thread): enabling it starts the
relay, disabling it stops it, and changing the destination/ports/fake SNI
restarts it with the new target. No process restart is needed.

The web-UI bearer token and driver pins are never echoed back by the config
API; the form shows them as write-only fields where empty means "keep the
current value".

### uTLS fingerprint rotation (passive rewriter)

`utls::apply_fingerprint_to_hello` rotates the JA3/JA4 fingerprint in place:
cipher suites (TLS 1.3 kept at the front), `supported_groups`,
`signature_algorithms` and `ec_point_formats` are all reordered while
preserving each list's multiset and the wire length. This is the correct
scope for a packet rewriter — the `key_share` and ALPN are deliberately not
regenerated, because a MITM that swaps in a fresh key share produces a
ClientHello the client's own stack cannot complete. Enable via
`enable_utls_fingerprint = true`.

### SNI disguise as unknown extension (#54)

Instead of deleting SNI, change its extension type 0x0000 -> 0x0A0A (GREASE) or 0xFF01 (private). Naive DPI that looks for 0x0000 misses it; server per RFC 8446 should ignore unknown extensions (but loses vhost routing, serves default cert). Use with fronting:

```
visible SNI = www.microsoft.com (benign)
hidden real = example.com in extension 0xFF01
```

Implemented as `fragmentation::disguise_sni_extension_type` and `inject_hidden_sni_in_unknown_ext`. Enable via `enable_sni_disguise` + `fronting_benign_sni`.

### Combined TCP+TLS fragmentation (Henan)

Regional firewalls like Henan are stateless and fail when BOTH layers are fragmented simultaneously. Pipeline now:

- effective_chunk = min(config, profile.recommended_fragment_size())
- disorder_mode always ON for Henan/ChinaRegional
- if Henan + combined enabled: TCP segments are further split via `persistent_fragmentation(..., 16)` simulating TLS-level fragmentation inside TCP segmentation.

Config: `enable_combined_fragmentation = true` (default ON).

## License

MIT. See `LICENSE`.
CENSE`.
