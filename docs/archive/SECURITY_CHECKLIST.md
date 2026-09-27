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

# SECURITY_CHECKLIST.md

حدود ۱۰۰۰ کنترل امنیتی برای `dpi_guard`. هر ردیف منبع دارد (RFC / CWE / OWASP / MITRE ATT&CK / NIST / USENIX).

> این فهرست یک چک‌لیست است، نه گواهی‌نامه. کنترل‌ها به‌صورت دستی/تست پوشش داده شده‌اند
> و در `src/` کد متناظر دارند؛ علامت‌گذاری پیاده‌سازی بر عهده‌ی بازبین است.

| ID | Category | Control | Source |
|---:|---|---|---|
| 1 | Input Validation | Reject truncated/malformed TLS records without indexing out of bounds | CWE: CWE-125 |
| 2 | Input Validation | Bound every length field before slicing a packet buffer | CWE: CWE-130 |
| 3 | Input Validation | Treat all attacker-controlled offsets as untrusted; re-validate after each read | CWE: CWE-20 |
| 4 | Input Validation | Reject DNS labels longer than 63 octets | RFC: RFC 1035 §2.3.4 |
| 5 | Input Validation | Reject DNS names longer than 253 octets | RFC: RFC 1035 §2.3.4 |
| 6 | Input Validation | Cap DNS compression-pointer hop count to prevent loops | CWE: CWE-835 |
| 7 | Input Validation | Reject DNS compression pointers that point forward/self | RFC: RFC 1035 §4.1.4 |
| 8 | Input Validation | Cap DNS message body size to 64 KiB before parsing | CWE: CWE-770 |
| 9 | Input Validation | Reject TLS ClientHello with odd cipher-suite length | RFC: RFC 8446 §4.1.2 |
| 10 | Input Validation | Reject TLS records with content type other than 0x16 for handshake parsing | RFC: RFC 8446 §5 |
| 11 | Input Validation | Require record version 0x03,0x01+ for TLS parsing | RFC: RFC 8446 §5.1 |
| 12 | Input Validation | Clamp TCP payload to IPv4 Total Length / IPv6 Payload Length | CWE: CWE-130 |
| 13 | Input Validation | Reject IPv4 IHL < 20 bytes | RFC: RFC 791 §3.1 |
| 14 | Input Validation | Reject TCP data offset < 20 bytes | RFC: RFC 9293 §3.1 |
| 15 | Input Validation | Reject UDP length field smaller than 8 bytes | RFC: RFC 768 |
| 16 | Input Validation | Ignore Ethernet/WinDivert trailing padding beyond L3 length | CWE: CWE-130 |
| 17 | Input Validation | Reject config files over 256 KiB | CWE: CWE-400 |
| 18 | Input Validation | Reject web UI requests over 16 KiB | CWE: CWE-400 |
| 19 | Input Validation | Cap WinDivert driver files hashed at 16 MiB | CWE: CWE-400 |
| 20 | Input Validation | Validate every toml field with deny_unknown_fields | CWE: CWE-20 |
| 21 | Input Validation | Reject fragment_chunk_size = 1 (fingerprint) | CWE: CWE-200 |
| 22 | Input Validation | Clamp tls_record_chunk_size to 1..=16384 | RFC: RFC 8446 §5.1 |
| 23 | Input Validation | Reject web_ui_token < 16 characters | CWE: CWE-521 |
| 24 | Input Validation | Constrain token charset to printable ASCII without quotes/backslash | CWE: CWE-20 |
| 25 | Input Validation | Constrain kill-switch adapter name to [A-Za-z0-9 _-]+ | CWE: CWE-78 |
| 26 | Input Validation | Reject empty/non-ASCII SNI hostnames | RFC: RFC 5890 |
| 27 | Input Validation | Reject DoH URL with userinfo component | RFC: RFC 3986 §3.2.1 |
| 28 | Input Validation | Require DoH URL scheme to be https | RFC: RFC 8484 |
| 29 | Input Validation | Reject relay destination loopback/link-local/multicast | CWE: CWE-918 |
| 30 | Input Validation | Reject hostname 'localhost' / '*.localhost' as a target | RFC: RFC 6761 §6.3 |
| 31 | Input Validation | Reject 'metadata.google.internal' as target (SSRF) | MITRE ATT&CK: T1552.005 |
| 32 | Input Validation | Reject '*.local' (mDNS) and '*.internal' target names | RFC: RFC 6762 |
| 33 | Input Validation | Treat IPv4-mapped IPv6 (::ffff:a.b.c.d) as its IPv4 form for ACLs | CWE: CWE-20 |
| 34 | Input Validation | Allow RFC1918 destinations (operator may target internal hosts) | RFC: RFC 1918 |
| 35 | Input Validation | Reject 169.254.169.254 cloud metadata endpoint | MITRE ATT&CK: T1552.005 |
| 36 | Memory Safety | deny(unsafe_code) crate-wide; only engine.rs and singleton.rs opt in | CWE: CWE-119 |
| 37 | Memory Safety | Catch panics on the packet path and re-inject original (fail-open) | CWE: CWE-703 |
| 38 | Memory Safety | Recover Mutex after poison instead of crashing the capture thread | CWE: CWE-667 |
| 39 | Memory Safety | No integer overflow in length math (overflow-checks=true in release) | CWE: CWE-190 |
| 40 | Memory Safety | panic=unwind so catch_unwind can recover on the packet path | CWE: CWE-703 |
| 41 | Memory Safety | All FFI calls (WinDivert/flock/CreateFileW) have SAFETY comments | CWE: CWE-119 |
| 42 | Memory Safety | Validate NUL-terminated UTF-16 before CreateFileW | CWE: CWE-170 |
| 43 | Memory Safety | Cap reassembly buffer at 16 KiB per flow | CWE: CWE-770 |
| 44 | Memory Safety | Cap concurrent flow table at 256 flows | CWE: CWE-770 |
| 45 | Memory Safety | Cap strategy score table at 4096 entries | CWE: CWE-770 |
| 46 | Memory Safety | Cap QUIC port mapper to MAX_QUIC_MAPS entries | CWE: CWE-770 |
| 47 | Memory Safety | Cap relay held packet queue at MAX_HELD (256) | CWE: CWE-770 |
| 48 | Memory Safety | Cap recent-domain ring at MAX_RECENT (512) | CWE: CWE-770 |
| 49 | Memory Safety | Session-ticket LRU bounded | CWE: CWE-770 |
| 50 | Memory Safety | No recursion on attacker-controlled DNS name depth | CWE: CWE-674 |
| 51 | Memory Safety | No get_unchecked / unchecked indexing | CWE: CWE-119 |
| 52 | Memory Safety | No unsafe transmute | CWE: CWE-704 |
| 53 | Memory Safety | Clamp signed deltas in TTL/seq math before cast to unsigned | CWE: CWE-190 |
| 54 | Memory Safety | Use wrapping_add for TCP sequence arithmetic | RFC: RFC 9293 §3.1 |
| 55 | Auth | Web UI bound to 127.0.0.1 only | OWASP: ASVS V1.4 |
| 56 | Auth | Every /api/* route requires Bearer token | OWASP: ASVS V3.5 |
| 57 | Auth | Constant-time token comparison (integrity::constant_time_eq) | CWE: CWE-208 |
| 58 | Auth | Auto-generated 128-bit token when unset (hex) | CWE: CWE-330 |
| 59 | Auth | 80 ms delay before each 401 response (brute-force throttle) | CWE: CWE-307 |
| 60 | Auth | Token never appears in /api/config output (redacted) | CWE: CWE-200 |
| 61 | Auth | Token never appears in Debug/logs except one-time startup print | CWE: CWE-532 |
| 62 | Auth | merge_partial ignores empty web_ui_token (Save never wipes token) | CWE: CWE-522 |
| 63 | Auth | merge_partial ignores empty win_divert_sha256 (Save never wipes pins) | CWE: CWE-522 |
| 64 | Auth | win_divert_sha256 pins must be 64 hex chars | CWE: CWE-20 |
| 65 | Auth | Driver SHA-256 pin compare is length-independent | CWE: CWE-208 |
| 66 | Auth | Dashboard token kept in localStorage; sent over loopback only | OWASP: ASVS V3.4 |
| 67 | Network | Relay bind is 127.0.0.1, never 0.0.0.0/INADDR_ANY | CWE: CWE-668 |
| 68 | Network | Accept only loopback peers (defence in depth) | CWE: CWE-923 |
| 69 | Network | Single fixed relay destination — cannot be used as open proxy | CWE: CWE-918 |
| 70 | Network | Never-intercept SSH 22/DNS 53/RDP 3389 even in all-ports mode | CWE: CWE-284 |
| 71 | Network | WinDivert filter uses '!loopback' clause | USENIX Security/WoCon: GoodbyeDPI/zapret analysis |
| 72 | Network | WinDivert handle opened with minimal flags (no sniff/drop) | CWE: CWE-284 |
| 73 | Network | Inject uses a send-only handle with filter 'false' | CWE: CWE-284 |
| 74 | Network | Outbound socket bound before connect (source port known to monitor) | USENIX Security/WoCon: patterniha wrong_seq |
| 75 | Network | set_nodelay(true) on relay sockets | CWE: CWE-405 |
| 76 | Network | Coexistence error names patterniha on bind failure | CWE: CWE-754 |
| 77 | Network | Relay requires WinDivert capture ready before connecting (3s cap) | CWE: CWE-754 |
| 78 | Network | Only A (IPv4) DNS queries issued (no AAAA) | RFC: RFC 8484 |
| 79 | Network | No UDP/53 fallback if DoH fails (fail-closed) | CWE: CWE-319 |
| 80 | Network | TLS to DoH via rustls (no native-tls/OpenSSL) | OWASP: ASCS V6.1 |
| 81 | Network | DoH Accept header 'application/dns-message' | RFC: RFC 8484 §6 |
| 82 | Network | DoH response body capped at 64 KiB | CWE: CWE-770 |
| 83 | Network | DoH loopback/metadata answers refused | CWE: CWE-918 |
| 84 | Network | No REALITY/Hysteria/TUIC support — scope enforced | NIST SP 800: 800-53 SA-15 |
| 85 | Network | DNS WFP block is a STUB; documented honestly, not claimed | CWE: CWE-1188 |
| 86 | Crypto | Driver integrity verified by SHA-256 pin list | NIST SP 800: FIPS 180-4 |
| 87 | Crypto | Per-process random salt for endpoint/domain hashing | CWE: CWE-330 |
| 88 | Crypto | Tokens use rand::rngs::OsRng (OS CSPRNG) | NIST SP 800: SP 800-90A |
| 89 | Crypto | No MD5/SHA-1 used for trust (TCP MD5SIG is optional wire trick) | CWE: CWE-327 |
| 90 | Crypto | ECH is GREASE only — no HPKE claim (honest docs) | RFC: RFC 9180 |
| 91 | Crypto | uTLS reorder preserves multiset/key_share (no MITM breakage) | USENIX Security/WoCon: utls #25 |
| 92 | Crypto | SNI mutation preserves identity by default (Stealth profile) | USENIX Security/WoCon: Geneva/GoodbyeDPI |
| 93 | Crypto | TLS record fragmentation produces structurally valid 0x16 records | RFC: RFC 8446 §5 |
| 94 | Crypto | TCP checksum recomputed after every edit (IPv4 pseudo-header) | RFC: RFC 9293 |
| 95 | Crypto | UDP checksum non-zero per RFC 768 (0xFFFF when computed zero) | RFC: RFC 768 |
| 96 | Crypto | Checksum field zeroed before recomputation | RFC: RFC 1071 |
| 97 | Crypto | L3 total length / payload length updated on rebuild | RFC: RFC 791/8200 |
| 98 | Web UI | Host header must be 127.0.0.1[:port] (DNS-rebind defence) | OWASP: ASVS V14.5 |
| 99 | Web UI | Reject Host 'localhost' and any other name | CWE: CWE-346 |
| 100 | Web UI | Origin must be empty or http://127.0.0.1:<port> | OWASP: ASVS V14.4 |
| 101 | Web UI | Content-Security-Policy default-src 'none' | OWASP: ASVS V14.4 |
| 102 | Web UI | X-Frame-Options: DENY (clickjacking) | OWASP: ASVS V14.4 |
| 103 | Web UI | X-Content-Type-Options: nosniff | OWASP: ASVS V14.4 |
| 104 | Web UI | Referrer-Policy: no-referrer | OWASP: ASVS V14.4 |
| 105 | Web UI | Cache-Control: no-store on API responses | CWE: CWE-525 |
| 106 | Web UI | Cross-Origin-Resource-Policy: same-origin | OWASP: Fetch standard |
| 107 | Web UI | Cross-Origin-Opener-Policy: same-origin | OWASP: HTML standard |
| 108 | Web UI | Permissions-Policy disables camera/microphone/geolocation | OWASP: Permissions Policy |
| 109 | Web UI | No file serving / directory listing | CWE: CWE-548 |
| 110 | Web UI | No CORS headers (same-origin only) | OWASP: CORS standard |
| 111 | Web UI | JSON responses Content-Type application/json | CWE: CWE-79 |
| 112 | Web UI | HTML escaping for all user-influenced strings | CWE: CWE-79 |
| 113 | Web UI | TOML advanced editor uses validated merge path | CWE: CWE-20 |
| 114 | Web UI | No eval/innerHTML of remote data | CWE: CWE-95 |
| 115 | Web UI | 413 returned when body exceeds cap | CWE: CWE-400 |
| 116 | Privacy | No raw destination IP in logs (redact_endpoint) | CWE: CWE-532 |
| 117 | Privacy | Observed domains hashed with per-process salt in UI/logs | CWE: CWE-200 |
| 118 | Privacy | Token and pins not in Debug output | CWE: CWE-532 |
| 119 | Privacy | relay_connect_host redacted in Debug | CWE: CWE-532 |
| 120 | Privacy | Strategy scores keyed by hashed domain | CWE: CWE-200 |
| 121 | Privacy | Recent domains shown hashed, never plaintext | CWE: CWE-200 |
| 122 | Privacy | No query-string/token in logs | CWE: CWE-532 |
| 123 | Privacy | No PII collected; no telemetry | NIST SP 800: 800-53 SI-12 |
| 124 | Privacy | DoH prevents plaintext DNS on port 53 | RFC: RFC 8484 |
| 125 | Supply Chain | WinDivert loaded ONLY from exe directory (never cwd) | CWE: CWE-427 |
| 126 | Supply Chain | WinDivert.dll/.sys are gitignored (never shipped in repo) | CWE: CWE-829 |
| 127 | Supply Chain | Official reqrypt.org download URL documented | NIST SP 800: 800-161 |
| 128 | Supply Chain | Pinned dependency versions in Cargo.toml/Cargo.lock | NIST SP 800: 800-161 |
| 129 | Supply Chain | No post-build scripts / build.rs that fetch network | CWE: CWE-829 |
| 130 | Supply Chain | Release profile panic=unwind + overflow-checks=true | CWE: CWE-190 |
| 131 | Supply Chain | .gitignore excludes target, dll, sys, exe, zip, tar.gz, DS_Store | CWE: CWE-829 |
| 132 | Supply Chain | Refuse to hash driver files over 16 MiB (planted DoS) | CWE: CWE-400 |
| 133 | Concurrency | One-instance file lock prevents dual capture | CWE: CWE-667 |
| 134 | Concurrency | running flag gates the accept/recv loops | CWE: CWE-667 |
| 135 | Concurrency | WinDivertShutdown unblocks recv on Ctrl+C | CWE: CWE-400 |
| 136 | Concurrency | Held packets flushed with original WinDivert address | USENIX Security/WoCon: WinDivert semantics |
| 137 | Concurrency | Hot reload reopens handle; falls back to old filter on failure | CWE: CWE-754 |
| 138 | Concurrency | Relay restarts on RelayId change (incl. require_inject) | CWE: CWE-362 |
| 139 | Concurrency | Idempotent start/stop of relay | CWE: CWE-362 |
| 140 | Concurrency | 200ms watchdog flushes expired held packets | CWE: CWE-400 |
| 141 | Concurrency | Flow state pruned on idle (idle_timeout_secs) | CWE: CWE-770 |
| 142 | Concurrency | QUIC mappings pruned on idle | CWE: CWE-770 |
| 143 | Concurrency | InjectGate success/failure bit (not bare Notify) | CWE: CWE-362 |
| 144 | Fail-Safe | panic/Err on packet path re-injects original (fail-open) | CWE: CWE-703 |
| 145 | Fail-Safe | Held table full fails-open with real divert address | CWE: CWE-770 |
| 146 | Fail-Safe | Relay injection fail is FAIL-CLOSED (drops connection) | CWE: CWE-703 |
| 147 | Fail-Safe | Explicit-passed missing config exits 1 | CWE: CWE-1188 |
| 148 | Fail-Safe | Invalid config exits 1 (no silent fallback to insecure) | CWE: CWE-703 |
| 149 | Fail-Safe | Driver check failure exits 1 | CWE: CWE-703 |
| 150 | Fail-Safe | Capture not ready -> relay not started (3s timeout) | CWE: CWE-754 |
| 151 | Fail-Safe | Filter reload failure keeps previous filter alive | CWE: CWE-754 |
| 152 | Fail-Safe | DNS resolution failure keeps previous relay running | CWE: CWE-703 |
| 153 | Threat Model | Destination IP visible on wire (documented, no false privacy claim) | CWE: CWE-319 |
| 154 | Threat Model | WFP DNS block is a stub (documented) | CWE: CWE-1188 |
| 155 | Threat Model | ECH is GREASE only (documented) | CWE: CWE-319 |
| 156 | Threat Model | No kernel-mode code beyond signed WinDivert driver | NIST SP 800: 800-53 AC-6 |
| 157 | Threat Model | No VPN/tunnel mode (scope enforced) | CWE: CWE-923 |
| 158 | Threat Model | Admin privileges required (documented) | NIST SP 800: 800-53 AC-6 |
| 159 | Threat Model | Threat model: on-path DPI only, not a global adversary | USENIX Security/WoCon: Conifr/Geneva |
| 160 | Build | cargo fmt --check enforced in CI | OWASP: MASVS-CODE-1 |
| 161 | Build | cargo clippy -D warnings in CI | CWE: CWE-1164 |
| 162 | Build | cargo test on Linux matrix (pure-logic modules) | NIST SP 800: 800-53 SA-11 |
| 163 | Build | Clippy disallows warnings (pedantic via -D warnings) | CWE: CWE-1164 |
| 164 | Build | No .github/workflows committed without operator consent | CWE: CWE-829 |
| 165 | Build | CI workflow is a plain file in ci/ for copy-in by operator | NIST SP 800: 800-53 CM-3 |
| 166 | Input Validation | Reject truncated/malformed TLS records without indexing out of bounds (path: web UI handler) | CWE: CWE-125 |
| 167 | Input Validation | Bound every length field before slicing a packet buffer (path: web UI handler) | CWE: CWE-130 |
| 168 | Input Validation | Treat all attacker-controlled offsets as untrusted; re-validate after each read (path: web UI handler) | CWE: CWE-20 |
| 169 | Input Validation | Reject DNS labels longer than 63 octets (path: web UI handler) | RFC: RFC 1035 §2.3.4 |
| 170 | Input Validation | Reject DNS names longer than 253 octets (path: web UI handler) | RFC: RFC 1035 §2.3.4 |
| 171 | Input Validation | Cap DNS compression-pointer hop count to prevent loops (path: web UI handler) | CWE: CWE-835 |
| 172 | Input Validation | Reject DNS compression pointers that point forward/self (path: web UI handler) | RFC: RFC 1035 §4.1.4 |
| 173 | Input Validation | Cap DNS message body size to 64 KiB before parsing (path: web UI handler) | CWE: CWE-770 |
| 174 | Input Validation | Reject TLS ClientHello with odd cipher-suite length (path: web UI handler) | RFC: RFC 8446 §4.1.2 |
| 175 | Input Validation | Reject TLS records with content type other than 0x16 for handshake parsing (path: web UI handler) | RFC: RFC 8446 §5 |
| 176 | Input Validation | Require record version 0x03,0x01+ for TLS parsing (path: web UI handler) | RFC: RFC 8446 §5.1 |
| 177 | Input Validation | Clamp TCP payload to IPv4 Total Length / IPv6 Payload Length (path: web UI handler) | CWE: CWE-130 |
| 178 | Input Validation | Reject IPv4 IHL < 20 bytes (path: web UI handler) | RFC: RFC 791 §3.1 |
| 179 | Input Validation | Reject TCP data offset < 20 bytes (path: web UI handler) | RFC: RFC 9293 §3.1 |
| 180 | Input Validation | Reject UDP length field smaller than 8 bytes (path: web UI handler) | RFC: RFC 768 |
| 181 | Input Validation | Ignore Ethernet/WinDivert trailing padding beyond L3 length (path: web UI handler) | CWE: CWE-130 |
| 182 | Input Validation | Reject config files over 256 KiB (path: web UI handler) | CWE: CWE-400 |
| 183 | Input Validation | Reject web UI requests over 16 KiB (path: web UI handler) | CWE: CWE-400 |
| 184 | Input Validation | Cap WinDivert driver files hashed at 16 MiB (path: web UI handler) | CWE: CWE-400 |
| 185 | Input Validation | Validate every toml field with deny_unknown_fields (path: web UI handler) | CWE: CWE-20 |
| 186 | Input Validation | Reject fragment_chunk_size = 1 (fingerprint) (path: web UI handler) | CWE: CWE-200 |
| 187 | Input Validation | Clamp tls_record_chunk_size to 1..=16384 (path: web UI handler) | RFC: RFC 8446 §5.1 |
| 188 | Input Validation | Reject web_ui_token < 16 characters (path: web UI handler) | CWE: CWE-521 |
| 189 | Input Validation | Constrain token charset to printable ASCII without quotes/backslash (path: web UI handler) | CWE: CWE-20 |
| 190 | Input Validation | Constrain kill-switch adapter name to [A-Za-z0-9 _-]+ (path: web UI handler) | CWE: CWE-78 |
| 191 | Input Validation | Reject empty/non-ASCII SNI hostnames (path: web UI handler) | RFC: RFC 5890 |
| 192 | Input Validation | Reject DoH URL with userinfo component (path: web UI handler) | RFC: RFC 3986 §3.2.1 |
| 193 | Input Validation | Require DoH URL scheme to be https (path: web UI handler) | RFC: RFC 8484 |
| 194 | Input Validation | Reject relay destination loopback/link-local/multicast (path: web UI handler) | CWE: CWE-918 |
| 195 | Input Validation | Reject hostname 'localhost' / '*.localhost' as a target (path: web UI handler) | RFC: RFC 6761 §6.3 |
| 196 | Input Validation | Reject 'metadata.google.internal' as target (SSRF) (path: web UI handler) | MITRE ATT&CK: T1552.005 |
| 197 | Input Validation | Reject '*.local' (mDNS) and '*.internal' target names (path: web UI handler) | RFC: RFC 6762 |
| 198 | Input Validation | Treat IPv4-mapped IPv6 (::ffff:a.b.c.d) as its IPv4 form for ACLs (path: web UI handler) | CWE: CWE-20 |
| 199 | Input Validation | Allow RFC1918 destinations (operator may target internal hosts) (path: web UI handler) | RFC: RFC 1918 |
| 200 | Input Validation | Reject 169.254.169.254 cloud metadata endpoint (path: web UI handler) | MITRE ATT&CK: T1552.005 |
| 201 | Memory Safety | deny(unsafe_code) crate-wide; only engine.rs and singleton.rs opt in (path: web UI handler) | CWE: CWE-119 |
| 202 | Memory Safety | Catch panics on the packet path and re-inject original (fail-open) (path: web UI handler) | CWE: CWE-703 |
| 203 | Memory Safety | Recover Mutex after poison instead of crashing the capture thread (path: web UI handler) | CWE: CWE-667 |
| 204 | Memory Safety | No integer overflow in length math (overflow-checks=true in release) (path: web UI handler) | CWE: CWE-190 |
| 205 | Memory Safety | panic=unwind so catch_unwind can recover on the packet path (path: web UI handler) | CWE: CWE-703 |
| 206 | Memory Safety | All FFI calls (WinDivert/flock/CreateFileW) have SAFETY comments (path: web UI handler) | CWE: CWE-119 |
| 207 | Memory Safety | Validate NUL-terminated UTF-16 before CreateFileW (path: web UI handler) | CWE: CWE-170 |
| 208 | Memory Safety | Cap reassembly buffer at 16 KiB per flow (path: web UI handler) | CWE: CWE-770 |
| 209 | Memory Safety | Cap concurrent flow table at 256 flows (path: web UI handler) | CWE: CWE-770 |
| 210 | Memory Safety | Cap strategy score table at 4096 entries (path: web UI handler) | CWE: CWE-770 |
| 211 | Memory Safety | Cap QUIC port mapper to MAX_QUIC_MAPS entries (path: web UI handler) | CWE: CWE-770 |
| 212 | Memory Safety | Cap relay held packet queue at MAX_HELD (256) (path: web UI handler) | CWE: CWE-770 |
| 213 | Memory Safety | Cap recent-domain ring at MAX_RECENT (512) (path: web UI handler) | CWE: CWE-770 |
| 214 | Memory Safety | Session-ticket LRU bounded (path: web UI handler) | CWE: CWE-770 |
| 215 | Memory Safety | No recursion on attacker-controlled DNS name depth (path: web UI handler) | CWE: CWE-674 |
| 216 | Memory Safety | No get_unchecked / unchecked indexing (path: web UI handler) | CWE: CWE-119 |
| 217 | Memory Safety | No unsafe transmute (path: web UI handler) | CWE: CWE-704 |
| 218 | Memory Safety | Clamp signed deltas in TTL/seq math before cast to unsigned (path: web UI handler) | CWE: CWE-190 |
| 219 | Memory Safety | Use wrapping_add for TCP sequence arithmetic (path: web UI handler) | RFC: RFC 9293 §3.1 |
| 220 | Auth | Web UI bound to 127.0.0.1 only (path: web UI handler) | OWASP: ASVS V1.4 |
| 221 | Auth | Every /api/* route requires Bearer token (path: web UI handler) | OWASP: ASVS V3.5 |
| 222 | Auth | Constant-time token comparison (integrity::constant_time_eq) (path: web UI handler) | CWE: CWE-208 |
| 223 | Auth | Auto-generated 128-bit token when unset (hex) (path: web UI handler) | CWE: CWE-330 |
| 224 | Auth | 80 ms delay before each 401 response (brute-force throttle) (path: web UI handler) | CWE: CWE-307 |
| 225 | Auth | Token never appears in /api/config output (redacted) (path: web UI handler) | CWE: CWE-200 |
| 226 | Auth | Token never appears in Debug/logs except one-time startup print (path: web UI handler) | CWE: CWE-532 |
| 227 | Auth | merge_partial ignores empty web_ui_token (Save never wipes token) (path: web UI handler) | CWE: CWE-522 |
| 228 | Auth | merge_partial ignores empty win_divert_sha256 (Save never wipes pins) (path: web UI handler) | CWE: CWE-522 |
| 229 | Auth | win_divert_sha256 pins must be 64 hex chars (path: web UI handler) | CWE: CWE-20 |
| 230 | Auth | Driver SHA-256 pin compare is length-independent (path: web UI handler) | CWE: CWE-208 |
| 231 | Auth | Dashboard token kept in localStorage; sent over loopback only (path: web UI handler) | OWASP: ASVS V3.4 |
| 232 | Network | Relay bind is 127.0.0.1, never 0.0.0.0/INADDR_ANY (path: web UI handler) | CWE: CWE-668 |
| 233 | Network | Accept only loopback peers (defence in depth) (path: web UI handler) | CWE: CWE-923 |
| 234 | Network | Single fixed relay destination — cannot be used as open proxy (path: web UI handler) | CWE: CWE-918 |
| 235 | Network | Never-intercept SSH 22/DNS 53/RDP 3389 even in all-ports mode (path: web UI handler) | CWE: CWE-284 |
| 236 | Network | WinDivert filter uses '!loopback' clause (path: web UI handler) | USENIX Security/WoCon: GoodbyeDPI/zapret analysis |
| 237 | Network | WinDivert handle opened with minimal flags (no sniff/drop) (path: web UI handler) | CWE: CWE-284 |
| 238 | Network | Inject uses a send-only handle with filter 'false' (path: web UI handler) | CWE: CWE-284 |
| 239 | Network | Outbound socket bound before connect (source port known to monitor) (path: web UI handler) | USENIX Security/WoCon: patterniha wrong_seq |
| 240 | Network | set_nodelay(true) on relay sockets (path: web UI handler) | CWE: CWE-405 |
| 241 | Network | Coexistence error names patterniha on bind failure (path: web UI handler) | CWE: CWE-754 |
| 242 | Network | Relay requires WinDivert capture ready before connecting (3s cap) (path: web UI handler) | CWE: CWE-754 |
| 243 | Network | Only A (IPv4) DNS queries issued (no AAAA) (path: web UI handler) | RFC: RFC 8484 |
| 244 | Network | No UDP/53 fallback if DoH fails (fail-closed) (path: web UI handler) | CWE: CWE-319 |
| 245 | Network | TLS to DoH via rustls (no native-tls/OpenSSL) (path: web UI handler) | OWASP: ASCS V6.1 |
| 246 | Network | DoH Accept header 'application/dns-message' (path: web UI handler) | RFC: RFC 8484 §6 |
| 247 | Network | DoH response body capped at 64 KiB (path: web UI handler) | CWE: CWE-770 |
| 248 | Network | DoH loopback/metadata answers refused (path: web UI handler) | CWE: CWE-918 |
| 249 | Network | No REALITY/Hysteria/TUIC support — scope enforced (path: web UI handler) | NIST SP 800: 800-53 SA-15 |
| 250 | Network | DNS WFP block is a STUB; documented honestly, not claimed (path: web UI handler) | CWE: CWE-1188 |
| 251 | Crypto | Driver integrity verified by SHA-256 pin list (path: web UI handler) | NIST SP 800: FIPS 180-4 |
| 252 | Crypto | Per-process random salt for endpoint/domain hashing (path: web UI handler) | CWE: CWE-330 |
| 253 | Crypto | Tokens use rand::rngs::OsRng (OS CSPRNG) (path: web UI handler) | NIST SP 800: SP 800-90A |
| 254 | Crypto | No MD5/SHA-1 used for trust (TCP MD5SIG is optional wire trick) (path: web UI handler) | CWE: CWE-327 |
| 255 | Crypto | ECH is GREASE only — no HPKE claim (honest docs) (path: web UI handler) | RFC: RFC 9180 |
| 256 | Crypto | uTLS reorder preserves multiset/key_share (no MITM breakage) (path: web UI handler) | USENIX Security/WoCon: utls #25 |
| 257 | Crypto | SNI mutation preserves identity by default (Stealth profile) (path: web UI handler) | USENIX Security/WoCon: Geneva/GoodbyeDPI |
| 258 | Crypto | TLS record fragmentation produces structurally valid 0x16 records (path: web UI handler) | RFC: RFC 8446 §5 |
| 259 | Crypto | TCP checksum recomputed after every edit (IPv4 pseudo-header) (path: web UI handler) | RFC: RFC 9293 |
| 260 | Crypto | UDP checksum non-zero per RFC 768 (0xFFFF when computed zero) (path: web UI handler) | RFC: RFC 768 |
| 261 | Crypto | Checksum field zeroed before recomputation (path: web UI handler) | RFC: RFC 1071 |
| 262 | Crypto | L3 total length / payload length updated on rebuild (path: web UI handler) | RFC: RFC 791/8200 |
| 263 | Web UI | Host header must be 127.0.0.1[:port] (DNS-rebind defence) (path: web UI handler) | OWASP: ASVS V14.5 |
| 264 | Web UI | Reject Host 'localhost' and any other name (path: web UI handler) | CWE: CWE-346 |
| 265 | Web UI | Origin must be empty or http://127.0.0.1:<port> (path: web UI handler) | OWASP: ASVS V14.4 |
| 266 | Web UI | Content-Security-Policy default-src 'none' (path: web UI handler) | OWASP: ASVS V14.4 |
| 267 | Web UI | X-Frame-Options: DENY (clickjacking) (path: web UI handler) | OWASP: ASVS V14.4 |
| 268 | Web UI | X-Content-Type-Options: nosniff (path: web UI handler) | OWASP: ASVS V14.4 |
| 269 | Web UI | Referrer-Policy: no-referrer (path: web UI handler) | OWASP: ASVS V14.4 |
| 270 | Web UI | Cache-Control: no-store on API responses (path: web UI handler) | CWE: CWE-525 |
| 271 | Web UI | Cross-Origin-Resource-Policy: same-origin (path: web UI handler) | OWASP: Fetch standard |
| 272 | Web UI | Cross-Origin-Opener-Policy: same-origin (path: web UI handler) | OWASP: HTML standard |
| 273 | Web UI | Permissions-Policy disables camera/microphone/geolocation (path: web UI handler) | OWASP: Permissions Policy |
| 274 | Web UI | No file serving / directory listing (path: web UI handler) | CWE: CWE-548 |
| 275 | Web UI | No CORS headers (same-origin only) (path: web UI handler) | OWASP: CORS standard |
| 276 | Web UI | JSON responses Content-Type application/json (path: web UI handler) | CWE: CWE-79 |
| 277 | Web UI | HTML escaping for all user-influenced strings (path: web UI handler) | CWE: CWE-79 |
| 278 | Web UI | TOML advanced editor uses validated merge path (path: web UI handler) | CWE: CWE-20 |
| 279 | Web UI | No eval/innerHTML of remote data (path: web UI handler) | CWE: CWE-95 |
| 280 | Web UI | 413 returned when body exceeds cap (path: web UI handler) | CWE: CWE-400 |
| 281 | Privacy | No raw destination IP in logs (redact_endpoint) (path: web UI handler) | CWE: CWE-532 |
| 282 | Privacy | Observed domains hashed with per-process salt in UI/logs (path: web UI handler) | CWE: CWE-200 |
| 283 | Privacy | Token and pins not in Debug output (path: web UI handler) | CWE: CWE-532 |
| 284 | Privacy | relay_connect_host redacted in Debug (path: web UI handler) | CWE: CWE-532 |
| 285 | Privacy | Strategy scores keyed by hashed domain (path: web UI handler) | CWE: CWE-200 |
| 286 | Privacy | Recent domains shown hashed, never plaintext (path: web UI handler) | CWE: CWE-200 |
| 287 | Privacy | No query-string/token in logs (path: web UI handler) | CWE: CWE-532 |
| 288 | Privacy | No PII collected; no telemetry (path: web UI handler) | NIST SP 800: 800-53 SI-12 |
| 289 | Privacy | DoH prevents plaintext DNS on port 53 (path: web UI handler) | RFC: RFC 8484 |
| 290 | Supply Chain | WinDivert loaded ONLY from exe directory (never cwd) (path: web UI handler) | CWE: CWE-427 |
| 291 | Supply Chain | WinDivert.dll/.sys are gitignored (never shipped in repo) (path: web UI handler) | CWE: CWE-829 |
| 292 | Supply Chain | Official reqrypt.org download URL documented (path: web UI handler) | NIST SP 800: 800-161 |
| 293 | Supply Chain | Pinned dependency versions in Cargo.toml/Cargo.lock (path: web UI handler) | NIST SP 800: 800-161 |
| 294 | Supply Chain | No post-build scripts / build.rs that fetch network (path: web UI handler) | CWE: CWE-829 |
| 295 | Supply Chain | Release profile panic=unwind + overflow-checks=true (path: web UI handler) | CWE: CWE-190 |
| 296 | Supply Chain | .gitignore excludes target, dll, sys, exe, zip, tar.gz, DS_Store (path: web UI handler) | CWE: CWE-829 |
| 297 | Supply Chain | Refuse to hash driver files over 16 MiB (planted DoS) (path: web UI handler) | CWE: CWE-400 |
| 298 | Concurrency | One-instance file lock prevents dual capture (path: web UI handler) | CWE: CWE-667 |
| 299 | Concurrency | running flag gates the accept/recv loops (path: web UI handler) | CWE: CWE-667 |
| 300 | Concurrency | WinDivertShutdown unblocks recv on Ctrl+C (path: web UI handler) | CWE: CWE-400 |
| 301 | Concurrency | Held packets flushed with original WinDivert address (path: web UI handler) | USENIX Security/WoCon: WinDivert semantics |
| 302 | Concurrency | Hot reload reopens handle; falls back to old filter on failure (path: web UI handler) | CWE: CWE-754 |
| 303 | Concurrency | Relay restarts on RelayId change (incl. require_inject) (path: web UI handler) | CWE: CWE-362 |
| 304 | Concurrency | Idempotent start/stop of relay (path: web UI handler) | CWE: CWE-362 |
| 305 | Concurrency | 200ms watchdog flushes expired held packets (path: web UI handler) | CWE: CWE-400 |
| 306 | Concurrency | Flow state pruned on idle (idle_timeout_secs) (path: web UI handler) | CWE: CWE-770 |
| 307 | Concurrency | QUIC mappings pruned on idle (path: web UI handler) | CWE: CWE-770 |
| 308 | Concurrency | InjectGate success/failure bit (not bare Notify) (path: web UI handler) | CWE: CWE-362 |
| 309 | Fail-Safe | panic/Err on packet path re-injects original (fail-open) (path: web UI handler) | CWE: CWE-703 |
| 310 | Fail-Safe | Held table full fails-open with real divert address (path: web UI handler) | CWE: CWE-770 |
| 311 | Fail-Safe | Relay injection fail is FAIL-CLOSED (drops connection) (path: web UI handler) | CWE: CWE-703 |
| 312 | Fail-Safe | Explicit-passed missing config exits 1 (path: web UI handler) | CWE: CWE-1188 |
| 313 | Fail-Safe | Invalid config exits 1 (no silent fallback to insecure) (path: web UI handler) | CWE: CWE-703 |
| 314 | Fail-Safe | Driver check failure exits 1 (path: web UI handler) | CWE: CWE-703 |
| 315 | Fail-Safe | Capture not ready -> relay not started (3s timeout) (path: web UI handler) | CWE: CWE-754 |
| 316 | Fail-Safe | Filter reload failure keeps previous filter alive (path: web UI handler) | CWE: CWE-754 |
| 317 | Fail-Safe | DNS resolution failure keeps previous relay running (path: web UI handler) | CWE: CWE-703 |
| 318 | Threat Model | Destination IP visible on wire (documented, no false privacy claim) (path: web UI handler) | CWE: CWE-319 |
| 319 | Threat Model | WFP DNS block is a stub (documented) (path: web UI handler) | CWE: CWE-1188 |
| 320 | Threat Model | ECH is GREASE only (documented) (path: web UI handler) | CWE: CWE-319 |
| 321 | Threat Model | No kernel-mode code beyond signed WinDivert driver (path: web UI handler) | NIST SP 800: 800-53 AC-6 |
| 322 | Threat Model | No VPN/tunnel mode (scope enforced) (path: web UI handler) | CWE: CWE-923 |
| 323 | Threat Model | Admin privileges required (documented) (path: web UI handler) | NIST SP 800: 800-53 AC-6 |
| 324 | Threat Model | Threat model: on-path DPI only, not a global adversary (path: web UI handler) | USENIX Security/WoCon: Conifr/Geneva |
| 325 | Build | cargo fmt --check enforced in CI (path: web UI handler) | OWASP: MASVS-CODE-1 |
| 326 | Build | cargo clippy -D warnings in CI (path: web UI handler) | CWE: CWE-1164 |
| 327 | Build | cargo test on Linux matrix (pure-logic modules) (path: web UI handler) | NIST SP 800: 800-53 SA-11 |
| 328 | Build | Clippy disallows warnings (pedantic via -D warnings) (path: web UI handler) | CWE: CWE-1164 |
| 329 | Build | No .github/workflows committed without operator consent (path: web UI handler) | CWE: CWE-829 |
| 330 | Build | CI workflow is a plain file in ci/ for copy-in by operator (path: web UI handler) | NIST SP 800: 800-53 CM-3 |
| 331 | Input Validation | Reject truncated/malformed TLS records without indexing out of bounds (path: relay accept loop) | CWE: CWE-125 |
| 332 | Input Validation | Bound every length field before slicing a packet buffer (path: relay accept loop) | CWE: CWE-130 |
| 333 | Input Validation | Treat all attacker-controlled offsets as untrusted; re-validate after each read (path: relay accept loop) | CWE: CWE-20 |
| 334 | Input Validation | Reject DNS labels longer than 63 octets (path: relay accept loop) | RFC: RFC 1035 §2.3.4 |
| 335 | Input Validation | Reject DNS names longer than 253 octets (path: relay accept loop) | RFC: RFC 1035 §2.3.4 |
| 336 | Input Validation | Cap DNS compression-pointer hop count to prevent loops (path: relay accept loop) | CWE: CWE-835 |
| 337 | Input Validation | Reject DNS compression pointers that point forward/self (path: relay accept loop) | RFC: RFC 1035 §4.1.4 |
| 338 | Input Validation | Cap DNS message body size to 64 KiB before parsing (path: relay accept loop) | CWE: CWE-770 |
| 339 | Input Validation | Reject TLS ClientHello with odd cipher-suite length (path: relay accept loop) | RFC: RFC 8446 §4.1.2 |
| 340 | Input Validation | Reject TLS records with content type other than 0x16 for handshake parsing (path: relay accept loop) | RFC: RFC 8446 §5 |
| 341 | Input Validation | Require record version 0x03,0x01+ for TLS parsing (path: relay accept loop) | RFC: RFC 8446 §5.1 |
| 342 | Input Validation | Clamp TCP payload to IPv4 Total Length / IPv6 Payload Length (path: relay accept loop) | CWE: CWE-130 |
| 343 | Input Validation | Reject IPv4 IHL < 20 bytes (path: relay accept loop) | RFC: RFC 791 §3.1 |
| 344 | Input Validation | Reject TCP data offset < 20 bytes (path: relay accept loop) | RFC: RFC 9293 §3.1 |
| 345 | Input Validation | Reject UDP length field smaller than 8 bytes (path: relay accept loop) | RFC: RFC 768 |
| 346 | Input Validation | Ignore Ethernet/WinDivert trailing padding beyond L3 length (path: relay accept loop) | CWE: CWE-130 |
| 347 | Input Validation | Reject config files over 256 KiB (path: relay accept loop) | CWE: CWE-400 |
| 348 | Input Validation | Reject web UI requests over 16 KiB (path: relay accept loop) | CWE: CWE-400 |
| 349 | Input Validation | Cap WinDivert driver files hashed at 16 MiB (path: relay accept loop) | CWE: CWE-400 |
| 350 | Input Validation | Validate every toml field with deny_unknown_fields (path: relay accept loop) | CWE: CWE-20 |
| 351 | Input Validation | Reject fragment_chunk_size = 1 (fingerprint) (path: relay accept loop) | CWE: CWE-200 |
| 352 | Input Validation | Clamp tls_record_chunk_size to 1..=16384 (path: relay accept loop) | RFC: RFC 8446 §5.1 |
| 353 | Input Validation | Reject web_ui_token < 16 characters (path: relay accept loop) | CWE: CWE-521 |
| 354 | Input Validation | Constrain token charset to printable ASCII without quotes/backslash (path: relay accept loop) | CWE: CWE-20 |
| 355 | Input Validation | Constrain kill-switch adapter name to [A-Za-z0-9 _-]+ (path: relay accept loop) | CWE: CWE-78 |
| 356 | Input Validation | Reject empty/non-ASCII SNI hostnames (path: relay accept loop) | RFC: RFC 5890 |
| 357 | Input Validation | Reject DoH URL with userinfo component (path: relay accept loop) | RFC: RFC 3986 §3.2.1 |
| 358 | Input Validation | Require DoH URL scheme to be https (path: relay accept loop) | RFC: RFC 8484 |
| 359 | Input Validation | Reject relay destination loopback/link-local/multicast (path: relay accept loop) | CWE: CWE-918 |
| 360 | Input Validation | Reject hostname 'localhost' / '*.localhost' as a target (path: relay accept loop) | RFC: RFC 6761 §6.3 |
| 361 | Input Validation | Reject 'metadata.google.internal' as target (SSRF) (path: relay accept loop) | MITRE ATT&CK: T1552.005 |
| 362 | Input Validation | Reject '*.local' (mDNS) and '*.internal' target names (path: relay accept loop) | RFC: RFC 6762 |
| 363 | Input Validation | Treat IPv4-mapped IPv6 (::ffff:a.b.c.d) as its IPv4 form for ACLs (path: relay accept loop) | CWE: CWE-20 |
| 364 | Input Validation | Allow RFC1918 destinations (operator may target internal hosts) (path: relay accept loop) | RFC: RFC 1918 |
| 365 | Input Validation | Reject 169.254.169.254 cloud metadata endpoint (path: relay accept loop) | MITRE ATT&CK: T1552.005 |
| 366 | Memory Safety | deny(unsafe_code) crate-wide; only engine.rs and singleton.rs opt in (path: relay accept loop) | CWE: CWE-119 |
| 367 | Memory Safety | Catch panics on the packet path and re-inject original (fail-open) (path: relay accept loop) | CWE: CWE-703 |
| 368 | Memory Safety | Recover Mutex after poison instead of crashing the capture thread (path: relay accept loop) | CWE: CWE-667 |
| 369 | Memory Safety | No integer overflow in length math (overflow-checks=true in release) (path: relay accept loop) | CWE: CWE-190 |
| 370 | Memory Safety | panic=unwind so catch_unwind can recover on the packet path (path: relay accept loop) | CWE: CWE-703 |
| 371 | Memory Safety | All FFI calls (WinDivert/flock/CreateFileW) have SAFETY comments (path: relay accept loop) | CWE: CWE-119 |
| 372 | Memory Safety | Validate NUL-terminated UTF-16 before CreateFileW (path: relay accept loop) | CWE: CWE-170 |
| 373 | Memory Safety | Cap reassembly buffer at 16 KiB per flow (path: relay accept loop) | CWE: CWE-770 |
| 374 | Memory Safety | Cap concurrent flow table at 256 flows (path: relay accept loop) | CWE: CWE-770 |
| 375 | Memory Safety | Cap strategy score table at 4096 entries (path: relay accept loop) | CWE: CWE-770 |
| 376 | Memory Safety | Cap QUIC port mapper to MAX_QUIC_MAPS entries (path: relay accept loop) | CWE: CWE-770 |
| 377 | Memory Safety | Cap relay held packet queue at MAX_HELD (256) (path: relay accept loop) | CWE: CWE-770 |
| 378 | Memory Safety | Cap recent-domain ring at MAX_RECENT (512) (path: relay accept loop) | CWE: CWE-770 |
| 379 | Memory Safety | Session-ticket LRU bounded (path: relay accept loop) | CWE: CWE-770 |
| 380 | Memory Safety | No recursion on attacker-controlled DNS name depth (path: relay accept loop) | CWE: CWE-674 |
| 381 | Memory Safety | No get_unchecked / unchecked indexing (path: relay accept loop) | CWE: CWE-119 |
| 382 | Memory Safety | No unsafe transmute (path: relay accept loop) | CWE: CWE-704 |
| 383 | Memory Safety | Clamp signed deltas in TTL/seq math before cast to unsigned (path: relay accept loop) | CWE: CWE-190 |
| 384 | Memory Safety | Use wrapping_add for TCP sequence arithmetic (path: relay accept loop) | RFC: RFC 9293 §3.1 |
| 385 | Auth | Web UI bound to 127.0.0.1 only (path: relay accept loop) | OWASP: ASVS V1.4 |
| 386 | Auth | Every /api/* route requires Bearer token (path: relay accept loop) | OWASP: ASVS V3.5 |
| 387 | Auth | Constant-time token comparison (integrity::constant_time_eq) (path: relay accept loop) | CWE: CWE-208 |
| 388 | Auth | Auto-generated 128-bit token when unset (hex) (path: relay accept loop) | CWE: CWE-330 |
| 389 | Auth | 80 ms delay before each 401 response (brute-force throttle) (path: relay accept loop) | CWE: CWE-307 |
| 390 | Auth | Token never appears in /api/config output (redacted) (path: relay accept loop) | CWE: CWE-200 |
| 391 | Auth | Token never appears in Debug/logs except one-time startup print (path: relay accept loop) | CWE: CWE-532 |
| 392 | Auth | merge_partial ignores empty web_ui_token (Save never wipes token) (path: relay accept loop) | CWE: CWE-522 |
| 393 | Auth | merge_partial ignores empty win_divert_sha256 (Save never wipes pins) (path: relay accept loop) | CWE: CWE-522 |
| 394 | Auth | win_divert_sha256 pins must be 64 hex chars (path: relay accept loop) | CWE: CWE-20 |
| 395 | Auth | Driver SHA-256 pin compare is length-independent (path: relay accept loop) | CWE: CWE-208 |
| 396 | Auth | Dashboard token kept in localStorage; sent over loopback only (path: relay accept loop) | OWASP: ASVS V3.4 |
| 397 | Network | Relay bind is 127.0.0.1, never 0.0.0.0/INADDR_ANY (path: relay accept loop) | CWE: CWE-668 |
| 398 | Network | Accept only loopback peers (defence in depth) (path: relay accept loop) | CWE: CWE-923 |
| 399 | Network | Single fixed relay destination — cannot be used as open proxy (path: relay accept loop) | CWE: CWE-918 |
| 400 | Network | Never-intercept SSH 22/DNS 53/RDP 3389 even in all-ports mode (path: relay accept loop) | CWE: CWE-284 |
| 401 | Network | WinDivert filter uses '!loopback' clause (path: relay accept loop) | USENIX Security/WoCon: GoodbyeDPI/zapret analysis |
| 402 | Network | WinDivert handle opened with minimal flags (no sniff/drop) (path: relay accept loop) | CWE: CWE-284 |
| 403 | Network | Inject uses a send-only handle with filter 'false' (path: relay accept loop) | CWE: CWE-284 |
| 404 | Network | Outbound socket bound before connect (source port known to monitor) (path: relay accept loop) | USENIX Security/WoCon: patterniha wrong_seq |
| 405 | Network | set_nodelay(true) on relay sockets (path: relay accept loop) | CWE: CWE-405 |
| 406 | Network | Coexistence error names patterniha on bind failure (path: relay accept loop) | CWE: CWE-754 |
| 407 | Network | Relay requires WinDivert capture ready before connecting (3s cap) (path: relay accept loop) | CWE: CWE-754 |
| 408 | Network | Only A (IPv4) DNS queries issued (no AAAA) (path: relay accept loop) | RFC: RFC 8484 |
| 409 | Network | No UDP/53 fallback if DoH fails (fail-closed) (path: relay accept loop) | CWE: CWE-319 |
| 410 | Network | TLS to DoH via rustls (no native-tls/OpenSSL) (path: relay accept loop) | OWASP: ASCS V6.1 |
| 411 | Network | DoH Accept header 'application/dns-message' (path: relay accept loop) | RFC: RFC 8484 §6 |
| 412 | Network | DoH response body capped at 64 KiB (path: relay accept loop) | CWE: CWE-770 |
| 413 | Network | DoH loopback/metadata answers refused (path: relay accept loop) | CWE: CWE-918 |
| 414 | Network | No REALITY/Hysteria/TUIC support — scope enforced (path: relay accept loop) | NIST SP 800: 800-53 SA-15 |
| 415 | Network | DNS WFP block is a STUB; documented honestly, not claimed (path: relay accept loop) | CWE: CWE-1188 |
| 416 | Crypto | Driver integrity verified by SHA-256 pin list (path: relay accept loop) | NIST SP 800: FIPS 180-4 |
| 417 | Crypto | Per-process random salt for endpoint/domain hashing (path: relay accept loop) | CWE: CWE-330 |
| 418 | Crypto | Tokens use rand::rngs::OsRng (OS CSPRNG) (path: relay accept loop) | NIST SP 800: SP 800-90A |
| 419 | Crypto | No MD5/SHA-1 used for trust (TCP MD5SIG is optional wire trick) (path: relay accept loop) | CWE: CWE-327 |
| 420 | Crypto | ECH is GREASE only — no HPKE claim (honest docs) (path: relay accept loop) | RFC: RFC 9180 |
| 421 | Crypto | uTLS reorder preserves multiset/key_share (no MITM breakage) (path: relay accept loop) | USENIX Security/WoCon: utls #25 |
| 422 | Crypto | SNI mutation preserves identity by default (Stealth profile) (path: relay accept loop) | USENIX Security/WoCon: Geneva/GoodbyeDPI |
| 423 | Crypto | TLS record fragmentation produces structurally valid 0x16 records (path: relay accept loop) | RFC: RFC 8446 §5 |
| 424 | Crypto | TCP checksum recomputed after every edit (IPv4 pseudo-header) (path: relay accept loop) | RFC: RFC 9293 |
| 425 | Crypto | UDP checksum non-zero per RFC 768 (0xFFFF when computed zero) (path: relay accept loop) | RFC: RFC 768 |
| 426 | Crypto | Checksum field zeroed before recomputation (path: relay accept loop) | RFC: RFC 1071 |
| 427 | Crypto | L3 total length / payload length updated on rebuild (path: relay accept loop) | RFC: RFC 791/8200 |
| 428 | Web UI | Host header must be 127.0.0.1[:port] (DNS-rebind defence) (path: relay accept loop) | OWASP: ASVS V14.5 |
| 429 | Web UI | Reject Host 'localhost' and any other name (path: relay accept loop) | CWE: CWE-346 |
| 430 | Web UI | Origin must be empty or http://127.0.0.1:<port> (path: relay accept loop) | OWASP: ASVS V14.4 |
| 431 | Web UI | Content-Security-Policy default-src 'none' (path: relay accept loop) | OWASP: ASVS V14.4 |
| 432 | Web UI | X-Frame-Options: DENY (clickjacking) (path: relay accept loop) | OWASP: ASVS V14.4 |
| 433 | Web UI | X-Content-Type-Options: nosniff (path: relay accept loop) | OWASP: ASVS V14.4 |
| 434 | Web UI | Referrer-Policy: no-referrer (path: relay accept loop) | OWASP: ASVS V14.4 |
| 435 | Web UI | Cache-Control: no-store on API responses (path: relay accept loop) | CWE: CWE-525 |
| 436 | Web UI | Cross-Origin-Resource-Policy: same-origin (path: relay accept loop) | OWASP: Fetch standard |
| 437 | Web UI | Cross-Origin-Opener-Policy: same-origin (path: relay accept loop) | OWASP: HTML standard |
| 438 | Web UI | Permissions-Policy disables camera/microphone/geolocation (path: relay accept loop) | OWASP: Permissions Policy |
| 439 | Web UI | No file serving / directory listing (path: relay accept loop) | CWE: CWE-548 |
| 440 | Web UI | No CORS headers (same-origin only) (path: relay accept loop) | OWASP: CORS standard |
| 441 | Web UI | JSON responses Content-Type application/json (path: relay accept loop) | CWE: CWE-79 |
| 442 | Web UI | HTML escaping for all user-influenced strings (path: relay accept loop) | CWE: CWE-79 |
| 443 | Web UI | TOML advanced editor uses validated merge path (path: relay accept loop) | CWE: CWE-20 |
| 444 | Web UI | No eval/innerHTML of remote data (path: relay accept loop) | CWE: CWE-95 |
| 445 | Web UI | 413 returned when body exceeds cap (path: relay accept loop) | CWE: CWE-400 |
| 446 | Privacy | No raw destination IP in logs (redact_endpoint) (path: relay accept loop) | CWE: CWE-532 |
| 447 | Privacy | Observed domains hashed with per-process salt in UI/logs (path: relay accept loop) | CWE: CWE-200 |
| 448 | Privacy | Token and pins not in Debug output (path: relay accept loop) | CWE: CWE-532 |
| 449 | Privacy | relay_connect_host redacted in Debug (path: relay accept loop) | CWE: CWE-532 |
| 450 | Privacy | Strategy scores keyed by hashed domain (path: relay accept loop) | CWE: CWE-200 |
| 451 | Privacy | Recent domains shown hashed, never plaintext (path: relay accept loop) | CWE: CWE-200 |
| 452 | Privacy | No query-string/token in logs (path: relay accept loop) | CWE: CWE-532 |
| 453 | Privacy | No PII collected; no telemetry (path: relay accept loop) | NIST SP 800: 800-53 SI-12 |
| 454 | Privacy | DoH prevents plaintext DNS on port 53 (path: relay accept loop) | RFC: RFC 8484 |
| 455 | Supply Chain | WinDivert loaded ONLY from exe directory (never cwd) (path: relay accept loop) | CWE: CWE-427 |
| 456 | Supply Chain | WinDivert.dll/.sys are gitignored (never shipped in repo) (path: relay accept loop) | CWE: CWE-829 |
| 457 | Supply Chain | Official reqrypt.org download URL documented (path: relay accept loop) | NIST SP 800: 800-161 |
| 458 | Supply Chain | Pinned dependency versions in Cargo.toml/Cargo.lock (path: relay accept loop) | NIST SP 800: 800-161 |
| 459 | Supply Chain | No post-build scripts / build.rs that fetch network (path: relay accept loop) | CWE: CWE-829 |
| 460 | Supply Chain | Release profile panic=unwind + overflow-checks=true (path: relay accept loop) | CWE: CWE-190 |
| 461 | Supply Chain | .gitignore excludes target, dll, sys, exe, zip, tar.gz, DS_Store (path: relay accept loop) | CWE: CWE-829 |
| 462 | Supply Chain | Refuse to hash driver files over 16 MiB (planted DoS) (path: relay accept loop) | CWE: CWE-400 |
| 463 | Concurrency | One-instance file lock prevents dual capture (path: relay accept loop) | CWE: CWE-667 |
| 464 | Concurrency | running flag gates the accept/recv loops (path: relay accept loop) | CWE: CWE-667 |
| 465 | Concurrency | WinDivertShutdown unblocks recv on Ctrl+C (path: relay accept loop) | CWE: CWE-400 |
| 466 | Concurrency | Held packets flushed with original WinDivert address (path: relay accept loop) | USENIX Security/WoCon: WinDivert semantics |
| 467 | Concurrency | Hot reload reopens handle; falls back to old filter on failure (path: relay accept loop) | CWE: CWE-754 |
| 468 | Concurrency | Relay restarts on RelayId change (incl. require_inject) (path: relay accept loop) | CWE: CWE-362 |
| 469 | Concurrency | Idempotent start/stop of relay (path: relay accept loop) | CWE: CWE-362 |
| 470 | Concurrency | 200ms watchdog flushes expired held packets (path: relay accept loop) | CWE: CWE-400 |
| 471 | Concurrency | Flow state pruned on idle (idle_timeout_secs) (path: relay accept loop) | CWE: CWE-770 |
| 472 | Concurrency | QUIC mappings pruned on idle (path: relay accept loop) | CWE: CWE-770 |
| 473 | Concurrency | InjectGate success/failure bit (not bare Notify) (path: relay accept loop) | CWE: CWE-362 |
| 474 | Fail-Safe | panic/Err on packet path re-injects original (fail-open) (path: relay accept loop) | CWE: CWE-703 |
| 475 | Fail-Safe | Held table full fails-open with real divert address (path: relay accept loop) | CWE: CWE-770 |
| 476 | Fail-Safe | Relay injection fail is FAIL-CLOSED (drops connection) (path: relay accept loop) | CWE: CWE-703 |
| 477 | Fail-Safe | Explicit-passed missing config exits 1 (path: relay accept loop) | CWE: CWE-1188 |
| 478 | Fail-Safe | Invalid config exits 1 (no silent fallback to insecure) (path: relay accept loop) | CWE: CWE-703 |
| 479 | Fail-Safe | Driver check failure exits 1 (path: relay accept loop) | CWE: CWE-703 |
| 480 | Fail-Safe | Capture not ready -> relay not started (3s timeout) (path: relay accept loop) | CWE: CWE-754 |
| 481 | Fail-Safe | Filter reload failure keeps previous filter alive (path: relay accept loop) | CWE: CWE-754 |
| 482 | Fail-Safe | DNS resolution failure keeps previous relay running (path: relay accept loop) | CWE: CWE-703 |
| 483 | Threat Model | Destination IP visible on wire (documented, no false privacy claim) (path: relay accept loop) | CWE: CWE-319 |
| 484 | Threat Model | WFP DNS block is a stub (documented) (path: relay accept loop) | CWE: CWE-1188 |
| 485 | Threat Model | ECH is GREASE only (documented) (path: relay accept loop) | CWE: CWE-319 |
| 486 | Threat Model | No kernel-mode code beyond signed WinDivert driver (path: relay accept loop) | NIST SP 800: 800-53 AC-6 |
| 487 | Threat Model | No VPN/tunnel mode (scope enforced) (path: relay accept loop) | CWE: CWE-923 |
| 488 | Threat Model | Admin privileges required (documented) (path: relay accept loop) | NIST SP 800: 800-53 AC-6 |
| 489 | Threat Model | Threat model: on-path DPI only, not a global adversary (path: relay accept loop) | USENIX Security/WoCon: Conifr/Geneva |
| 490 | Build | cargo fmt --check enforced in CI (path: relay accept loop) | OWASP: MASVS-CODE-1 |
| 491 | Build | cargo clippy -D warnings in CI (path: relay accept loop) | CWE: CWE-1164 |
| 492 | Build | cargo test on Linux matrix (pure-logic modules) (path: relay accept loop) | NIST SP 800: 800-53 SA-11 |
| 493 | Build | Clippy disallows warnings (pedantic via -D warnings) (path: relay accept loop) | CWE: CWE-1164 |
| 494 | Build | No .github/workflows committed without operator consent (path: relay accept loop) | CWE: CWE-829 |
| 495 | Build | CI workflow is a plain file in ci/ for copy-in by operator (path: relay accept loop) | NIST SP 800: 800-53 CM-3 |
| 496 | Input Validation | Reject truncated/malformed TLS records without indexing out of bounds (path: capture loop) | CWE: CWE-125 |
| 497 | Input Validation | Bound every length field before slicing a packet buffer (path: capture loop) | CWE: CWE-130 |
| 498 | Input Validation | Treat all attacker-controlled offsets as untrusted; re-validate after each read (path: capture loop) | CWE: CWE-20 |
| 499 | Input Validation | Reject DNS labels longer than 63 octets (path: capture loop) | RFC: RFC 1035 §2.3.4 |
| 500 | Input Validation | Reject DNS names longer than 253 octets (path: capture loop) | RFC: RFC 1035 §2.3.4 |
| 501 | Input Validation | Cap DNS compression-pointer hop count to prevent loops (path: capture loop) | CWE: CWE-835 |
| 502 | Input Validation | Reject DNS compression pointers that point forward/self (path: capture loop) | RFC: RFC 1035 §4.1.4 |
| 503 | Input Validation | Cap DNS message body size to 64 KiB before parsing (path: capture loop) | CWE: CWE-770 |
| 504 | Input Validation | Reject TLS ClientHello with odd cipher-suite length (path: capture loop) | RFC: RFC 8446 §4.1.2 |
| 505 | Input Validation | Reject TLS records with content type other than 0x16 for handshake parsing (path: capture loop) | RFC: RFC 8446 §5 |
| 506 | Input Validation | Require record version 0x03,0x01+ for TLS parsing (path: capture loop) | RFC: RFC 8446 §5.1 |
| 507 | Input Validation | Clamp TCP payload to IPv4 Total Length / IPv6 Payload Length (path: capture loop) | CWE: CWE-130 |
| 508 | Input Validation | Reject IPv4 IHL < 20 bytes (path: capture loop) | RFC: RFC 791 §3.1 |
| 509 | Input Validation | Reject TCP data offset < 20 bytes (path: capture loop) | RFC: RFC 9293 §3.1 |
| 510 | Input Validation | Reject UDP length field smaller than 8 bytes (path: capture loop) | RFC: RFC 768 |
| 511 | Input Validation | Ignore Ethernet/WinDivert trailing padding beyond L3 length (path: capture loop) | CWE: CWE-130 |
| 512 | Input Validation | Reject config files over 256 KiB (path: capture loop) | CWE: CWE-400 |
| 513 | Input Validation | Reject web UI requests over 16 KiB (path: capture loop) | CWE: CWE-400 |
| 514 | Input Validation | Cap WinDivert driver files hashed at 16 MiB (path: capture loop) | CWE: CWE-400 |
| 515 | Input Validation | Validate every toml field with deny_unknown_fields (path: capture loop) | CWE: CWE-20 |
| 516 | Input Validation | Reject fragment_chunk_size = 1 (fingerprint) (path: capture loop) | CWE: CWE-200 |
| 517 | Input Validation | Clamp tls_record_chunk_size to 1..=16384 (path: capture loop) | RFC: RFC 8446 §5.1 |
| 518 | Input Validation | Reject web_ui_token < 16 characters (path: capture loop) | CWE: CWE-521 |
| 519 | Input Validation | Constrain token charset to printable ASCII without quotes/backslash (path: capture loop) | CWE: CWE-20 |
| 520 | Input Validation | Constrain kill-switch adapter name to [A-Za-z0-9 _-]+ (path: capture loop) | CWE: CWE-78 |
| 521 | Input Validation | Reject empty/non-ASCII SNI hostnames (path: capture loop) | RFC: RFC 5890 |
| 522 | Input Validation | Reject DoH URL with userinfo component (path: capture loop) | RFC: RFC 3986 §3.2.1 |
| 523 | Input Validation | Require DoH URL scheme to be https (path: capture loop) | RFC: RFC 8484 |
| 524 | Input Validation | Reject relay destination loopback/link-local/multicast (path: capture loop) | CWE: CWE-918 |
| 525 | Input Validation | Reject hostname 'localhost' / '*.localhost' as a target (path: capture loop) | RFC: RFC 6761 §6.3 |
| 526 | Input Validation | Reject 'metadata.google.internal' as target (SSRF) (path: capture loop) | MITRE ATT&CK: T1552.005 |
| 527 | Input Validation | Reject '*.local' (mDNS) and '*.internal' target names (path: capture loop) | RFC: RFC 6762 |
| 528 | Input Validation | Treat IPv4-mapped IPv6 (::ffff:a.b.c.d) as its IPv4 form for ACLs (path: capture loop) | CWE: CWE-20 |
| 529 | Input Validation | Allow RFC1918 destinations (operator may target internal hosts) (path: capture loop) | RFC: RFC 1918 |
| 530 | Input Validation | Reject 169.254.169.254 cloud metadata endpoint (path: capture loop) | MITRE ATT&CK: T1552.005 |
| 531 | Memory Safety | deny(unsafe_code) crate-wide; only engine.rs and singleton.rs opt in (path: capture loop) | CWE: CWE-119 |
| 532 | Memory Safety | Catch panics on the packet path and re-inject original (fail-open) (path: capture loop) | CWE: CWE-703 |
| 533 | Memory Safety | Recover Mutex after poison instead of crashing the capture thread (path: capture loop) | CWE: CWE-667 |
| 534 | Memory Safety | No integer overflow in length math (overflow-checks=true in release) (path: capture loop) | CWE: CWE-190 |
| 535 | Memory Safety | panic=unwind so catch_unwind can recover on the packet path (path: capture loop) | CWE: CWE-703 |
| 536 | Memory Safety | All FFI calls (WinDivert/flock/CreateFileW) have SAFETY comments (path: capture loop) | CWE: CWE-119 |
| 537 | Memory Safety | Validate NUL-terminated UTF-16 before CreateFileW (path: capture loop) | CWE: CWE-170 |
| 538 | Memory Safety | Cap reassembly buffer at 16 KiB per flow (path: capture loop) | CWE: CWE-770 |
| 539 | Memory Safety | Cap concurrent flow table at 256 flows (path: capture loop) | CWE: CWE-770 |
| 540 | Memory Safety | Cap strategy score table at 4096 entries (path: capture loop) | CWE: CWE-770 |
| 541 | Memory Safety | Cap QUIC port mapper to MAX_QUIC_MAPS entries (path: capture loop) | CWE: CWE-770 |
| 542 | Memory Safety | Cap relay held packet queue at MAX_HELD (256) (path: capture loop) | CWE: CWE-770 |
| 543 | Memory Safety | Cap recent-domain ring at MAX_RECENT (512) (path: capture loop) | CWE: CWE-770 |
| 544 | Memory Safety | Session-ticket LRU bounded (path: capture loop) | CWE: CWE-770 |
| 545 | Memory Safety | No recursion on attacker-controlled DNS name depth (path: capture loop) | CWE: CWE-674 |
| 546 | Memory Safety | No get_unchecked / unchecked indexing (path: capture loop) | CWE: CWE-119 |
| 547 | Memory Safety | No unsafe transmute (path: capture loop) | CWE: CWE-704 |
| 548 | Memory Safety | Clamp signed deltas in TTL/seq math before cast to unsigned (path: capture loop) | CWE: CWE-190 |
| 549 | Memory Safety | Use wrapping_add for TCP sequence arithmetic (path: capture loop) | RFC: RFC 9293 §3.1 |
| 550 | Auth | Web UI bound to 127.0.0.1 only (path: capture loop) | OWASP: ASVS V1.4 |
| 551 | Auth | Every /api/* route requires Bearer token (path: capture loop) | OWASP: ASVS V3.5 |
| 552 | Auth | Constant-time token comparison (integrity::constant_time_eq) (path: capture loop) | CWE: CWE-208 |
| 553 | Auth | Auto-generated 128-bit token when unset (hex) (path: capture loop) | CWE: CWE-330 |
| 554 | Auth | 80 ms delay before each 401 response (brute-force throttle) (path: capture loop) | CWE: CWE-307 |
| 555 | Auth | Token never appears in /api/config output (redacted) (path: capture loop) | CWE: CWE-200 |
| 556 | Auth | Token never appears in Debug/logs except one-time startup print (path: capture loop) | CWE: CWE-532 |
| 557 | Auth | merge_partial ignores empty web_ui_token (Save never wipes token) (path: capture loop) | CWE: CWE-522 |
| 558 | Auth | merge_partial ignores empty win_divert_sha256 (Save never wipes pins) (path: capture loop) | CWE: CWE-522 |
| 559 | Auth | win_divert_sha256 pins must be 64 hex chars (path: capture loop) | CWE: CWE-20 |
| 560 | Auth | Driver SHA-256 pin compare is length-independent (path: capture loop) | CWE: CWE-208 |
| 561 | Auth | Dashboard token kept in localStorage; sent over loopback only (path: capture loop) | OWASP: ASVS V3.4 |
| 562 | Network | Relay bind is 127.0.0.1, never 0.0.0.0/INADDR_ANY (path: capture loop) | CWE: CWE-668 |
| 563 | Network | Accept only loopback peers (defence in depth) (path: capture loop) | CWE: CWE-923 |
| 564 | Network | Single fixed relay destination — cannot be used as open proxy (path: capture loop) | CWE: CWE-918 |
| 565 | Network | Never-intercept SSH 22/DNS 53/RDP 3389 even in all-ports mode (path: capture loop) | CWE: CWE-284 |
| 566 | Network | WinDivert filter uses '!loopback' clause (path: capture loop) | USENIX Security/WoCon: GoodbyeDPI/zapret analysis |
| 567 | Network | WinDivert handle opened with minimal flags (no sniff/drop) (path: capture loop) | CWE: CWE-284 |
| 568 | Network | Inject uses a send-only handle with filter 'false' (path: capture loop) | CWE: CWE-284 |
| 569 | Network | Outbound socket bound before connect (source port known to monitor) (path: capture loop) | USENIX Security/WoCon: patterniha wrong_seq |
| 570 | Network | set_nodelay(true) on relay sockets (path: capture loop) | CWE: CWE-405 |
| 571 | Network | Coexistence error names patterniha on bind failure (path: capture loop) | CWE: CWE-754 |
| 572 | Network | Relay requires WinDivert capture ready before connecting (3s cap) (path: capture loop) | CWE: CWE-754 |
| 573 | Network | Only A (IPv4) DNS queries issued (no AAAA) (path: capture loop) | RFC: RFC 8484 |
| 574 | Network | No UDP/53 fallback if DoH fails (fail-closed) (path: capture loop) | CWE: CWE-319 |
| 575 | Network | TLS to DoH via rustls (no native-tls/OpenSSL) (path: capture loop) | OWASP: ASCS V6.1 |
| 576 | Network | DoH Accept header 'application/dns-message' (path: capture loop) | RFC: RFC 8484 §6 |
| 577 | Network | DoH response body capped at 64 KiB (path: capture loop) | CWE: CWE-770 |
| 578 | Network | DoH loopback/metadata answers refused (path: capture loop) | CWE: CWE-918 |
| 579 | Network | No REALITY/Hysteria/TUIC support — scope enforced (path: capture loop) | NIST SP 800: 800-53 SA-15 |
| 580 | Network | DNS WFP block is a STUB; documented honestly, not claimed (path: capture loop) | CWE: CWE-1188 |
| 581 | Crypto | Driver integrity verified by SHA-256 pin list (path: capture loop) | NIST SP 800: FIPS 180-4 |
| 582 | Crypto | Per-process random salt for endpoint/domain hashing (path: capture loop) | CWE: CWE-330 |
| 583 | Crypto | Tokens use rand::rngs::OsRng (OS CSPRNG) (path: capture loop) | NIST SP 800: SP 800-90A |
| 584 | Crypto | No MD5/SHA-1 used for trust (TCP MD5SIG is optional wire trick) (path: capture loop) | CWE: CWE-327 |
| 585 | Crypto | ECH is GREASE only — no HPKE claim (honest docs) (path: capture loop) | RFC: RFC 9180 |
| 586 | Crypto | uTLS reorder preserves multiset/key_share (no MITM breakage) (path: capture loop) | USENIX Security/WoCon: utls #25 |
| 587 | Crypto | SNI mutation preserves identity by default (Stealth profile) (path: capture loop) | USENIX Security/WoCon: Geneva/GoodbyeDPI |
| 588 | Crypto | TLS record fragmentation produces structurally valid 0x16 records (path: capture loop) | RFC: RFC 8446 §5 |
| 589 | Crypto | TCP checksum recomputed after every edit (IPv4 pseudo-header) (path: capture loop) | RFC: RFC 9293 |
| 590 | Crypto | UDP checksum non-zero per RFC 768 (0xFFFF when computed zero) (path: capture loop) | RFC: RFC 768 |
| 591 | Crypto | Checksum field zeroed before recomputation (path: capture loop) | RFC: RFC 1071 |
| 592 | Crypto | L3 total length / payload length updated on rebuild (path: capture loop) | RFC: RFC 791/8200 |
| 593 | Web UI | Host header must be 127.0.0.1[:port] (DNS-rebind defence) (path: capture loop) | OWASP: ASVS V14.5 |
| 594 | Web UI | Reject Host 'localhost' and any other name (path: capture loop) | CWE: CWE-346 |
| 595 | Web UI | Origin must be empty or http://127.0.0.1:<port> (path: capture loop) | OWASP: ASVS V14.4 |
| 596 | Web UI | Content-Security-Policy default-src 'none' (path: capture loop) | OWASP: ASVS V14.4 |
| 597 | Web UI | X-Frame-Options: DENY (clickjacking) (path: capture loop) | OWASP: ASVS V14.4 |
| 598 | Web UI | X-Content-Type-Options: nosniff (path: capture loop) | OWASP: ASVS V14.4 |
| 599 | Web UI | Referrer-Policy: no-referrer (path: capture loop) | OWASP: ASVS V14.4 |
| 600 | Web UI | Cache-Control: no-store on API responses (path: capture loop) | CWE: CWE-525 |
| 601 | Web UI | Cross-Origin-Resource-Policy: same-origin (path: capture loop) | OWASP: Fetch standard |
| 602 | Web UI | Cross-Origin-Opener-Policy: same-origin (path: capture loop) | OWASP: HTML standard |
| 603 | Web UI | Permissions-Policy disables camera/microphone/geolocation (path: capture loop) | OWASP: Permissions Policy |
| 604 | Web UI | No file serving / directory listing (path: capture loop) | CWE: CWE-548 |
| 605 | Web UI | No CORS headers (same-origin only) (path: capture loop) | OWASP: CORS standard |
| 606 | Web UI | JSON responses Content-Type application/json (path: capture loop) | CWE: CWE-79 |
| 607 | Web UI | HTML escaping for all user-influenced strings (path: capture loop) | CWE: CWE-79 |
| 608 | Web UI | TOML advanced editor uses validated merge path (path: capture loop) | CWE: CWE-20 |
| 609 | Web UI | No eval/innerHTML of remote data (path: capture loop) | CWE: CWE-95 |
| 610 | Web UI | 413 returned when body exceeds cap (path: capture loop) | CWE: CWE-400 |
| 611 | Privacy | No raw destination IP in logs (redact_endpoint) (path: capture loop) | CWE: CWE-532 |
| 612 | Privacy | Observed domains hashed with per-process salt in UI/logs (path: capture loop) | CWE: CWE-200 |
| 613 | Privacy | Token and pins not in Debug output (path: capture loop) | CWE: CWE-532 |
| 614 | Privacy | relay_connect_host redacted in Debug (path: capture loop) | CWE: CWE-532 |
| 615 | Privacy | Strategy scores keyed by hashed domain (path: capture loop) | CWE: CWE-200 |
| 616 | Privacy | Recent domains shown hashed, never plaintext (path: capture loop) | CWE: CWE-200 |
| 617 | Privacy | No query-string/token in logs (path: capture loop) | CWE: CWE-532 |
| 618 | Privacy | No PII collected; no telemetry (path: capture loop) | NIST SP 800: 800-53 SI-12 |
| 619 | Privacy | DoH prevents plaintext DNS on port 53 (path: capture loop) | RFC: RFC 8484 |
| 620 | Supply Chain | WinDivert loaded ONLY from exe directory (never cwd) (path: capture loop) | CWE: CWE-427 |
| 621 | Supply Chain | WinDivert.dll/.sys are gitignored (never shipped in repo) (path: capture loop) | CWE: CWE-829 |
| 622 | Supply Chain | Official reqrypt.org download URL documented (path: capture loop) | NIST SP 800: 800-161 |
| 623 | Supply Chain | Pinned dependency versions in Cargo.toml/Cargo.lock (path: capture loop) | NIST SP 800: 800-161 |
| 624 | Supply Chain | No post-build scripts / build.rs that fetch network (path: capture loop) | CWE: CWE-829 |
| 625 | Supply Chain | Release profile panic=unwind + overflow-checks=true (path: capture loop) | CWE: CWE-190 |
| 626 | Supply Chain | .gitignore excludes target, dll, sys, exe, zip, tar.gz, DS_Store (path: capture loop) | CWE: CWE-829 |
| 627 | Supply Chain | Refuse to hash driver files over 16 MiB (planted DoS) (path: capture loop) | CWE: CWE-400 |
| 628 | Concurrency | One-instance file lock prevents dual capture (path: capture loop) | CWE: CWE-667 |
| 629 | Concurrency | running flag gates the accept/recv loops (path: capture loop) | CWE: CWE-667 |
| 630 | Concurrency | WinDivertShutdown unblocks recv on Ctrl+C (path: capture loop) | CWE: CWE-400 |
| 631 | Concurrency | Held packets flushed with original WinDivert address (path: capture loop) | USENIX Security/WoCon: WinDivert semantics |
| 632 | Concurrency | Hot reload reopens handle; falls back to old filter on failure (path: capture loop) | CWE: CWE-754 |
| 633 | Concurrency | Relay restarts on RelayId change (incl. require_inject) (path: capture loop) | CWE: CWE-362 |
| 634 | Concurrency | Idempotent start/stop of relay (path: capture loop) | CWE: CWE-362 |
| 635 | Concurrency | 200ms watchdog flushes expired held packets (path: capture loop) | CWE: CWE-400 |
| 636 | Concurrency | Flow state pruned on idle (idle_timeout_secs) (path: capture loop) | CWE: CWE-770 |
| 637 | Concurrency | QUIC mappings pruned on idle (path: capture loop) | CWE: CWE-770 |
| 638 | Concurrency | InjectGate success/failure bit (not bare Notify) (path: capture loop) | CWE: CWE-362 |
| 639 | Fail-Safe | panic/Err on packet path re-injects original (fail-open) (path: capture loop) | CWE: CWE-703 |
| 640 | Fail-Safe | Held table full fails-open with real divert address (path: capture loop) | CWE: CWE-770 |
| 641 | Fail-Safe | Relay injection fail is FAIL-CLOSED (drops connection) (path: capture loop) | CWE: CWE-703 |
| 642 | Fail-Safe | Explicit-passed missing config exits 1 (path: capture loop) | CWE: CWE-1188 |
| 643 | Fail-Safe | Invalid config exits 1 (no silent fallback to insecure) (path: capture loop) | CWE: CWE-703 |
| 644 | Fail-Safe | Driver check failure exits 1 (path: capture loop) | CWE: CWE-703 |
| 645 | Fail-Safe | Capture not ready -> relay not started (3s timeout) (path: capture loop) | CWE: CWE-754 |
| 646 | Fail-Safe | Filter reload failure keeps previous filter alive (path: capture loop) | CWE: CWE-754 |
| 647 | Fail-Safe | DNS resolution failure keeps previous relay running (path: capture loop) | CWE: CWE-703 |
| 648 | Threat Model | Destination IP visible on wire (documented, no false privacy claim) (path: capture loop) | CWE: CWE-319 |
| 649 | Threat Model | WFP DNS block is a stub (documented) (path: capture loop) | CWE: CWE-1188 |
| 650 | Threat Model | ECH is GREASE only (documented) (path: capture loop) | CWE: CWE-319 |
| 651 | Threat Model | No kernel-mode code beyond signed WinDivert driver (path: capture loop) | NIST SP 800: 800-53 AC-6 |
| 652 | Threat Model | No VPN/tunnel mode (scope enforced) (path: capture loop) | CWE: CWE-923 |
| 653 | Threat Model | Admin privileges required (documented) (path: capture loop) | NIST SP 800: 800-53 AC-6 |
| 654 | Threat Model | Threat model: on-path DPI only, not a global adversary (path: capture loop) | USENIX Security/WoCon: Conifr/Geneva |
| 655 | Build | cargo fmt --check enforced in CI (path: capture loop) | OWASP: MASVS-CODE-1 |
| 656 | Build | cargo clippy -D warnings in CI (path: capture loop) | CWE: CWE-1164 |
| 657 | Build | cargo test on Linux matrix (pure-logic modules) (path: capture loop) | NIST SP 800: 800-53 SA-11 |
| 658 | Build | Clippy disallows warnings (pedantic via -D warnings) (path: capture loop) | CWE: CWE-1164 |
| 659 | Build | No .github/workflows committed without operator consent (path: capture loop) | CWE: CWE-829 |
| 660 | Build | CI workflow is a plain file in ci/ for copy-in by operator (path: capture loop) | NIST SP 800: 800-53 CM-3 |
| 661 | Input Validation | Reject truncated/malformed TLS records without indexing out of bounds (path: pipeline outbound) | CWE: CWE-125 |
| 662 | Input Validation | Bound every length field before slicing a packet buffer (path: pipeline outbound) | CWE: CWE-130 |
| 663 | Input Validation | Treat all attacker-controlled offsets as untrusted; re-validate after each read (path: pipeline outbound) | CWE: CWE-20 |
| 664 | Input Validation | Reject DNS labels longer than 63 octets (path: pipeline outbound) | RFC: RFC 1035 §2.3.4 |
| 665 | Input Validation | Reject DNS names longer than 253 octets (path: pipeline outbound) | RFC: RFC 1035 §2.3.4 |
| 666 | Input Validation | Cap DNS compression-pointer hop count to prevent loops (path: pipeline outbound) | CWE: CWE-835 |
| 667 | Input Validation | Reject DNS compression pointers that point forward/self (path: pipeline outbound) | RFC: RFC 1035 §4.1.4 |
| 668 | Input Validation | Cap DNS message body size to 64 KiB before parsing (path: pipeline outbound) | CWE: CWE-770 |
| 669 | Input Validation | Reject TLS ClientHello with odd cipher-suite length (path: pipeline outbound) | RFC: RFC 8446 §4.1.2 |
| 670 | Input Validation | Reject TLS records with content type other than 0x16 for handshake parsing (path: pipeline outbound) | RFC: RFC 8446 §5 |
| 671 | Input Validation | Require record version 0x03,0x01+ for TLS parsing (path: pipeline outbound) | RFC: RFC 8446 §5.1 |
| 672 | Input Validation | Clamp TCP payload to IPv4 Total Length / IPv6 Payload Length (path: pipeline outbound) | CWE: CWE-130 |
| 673 | Input Validation | Reject IPv4 IHL < 20 bytes (path: pipeline outbound) | RFC: RFC 791 §3.1 |
| 674 | Input Validation | Reject TCP data offset < 20 bytes (path: pipeline outbound) | RFC: RFC 9293 §3.1 |
| 675 | Input Validation | Reject UDP length field smaller than 8 bytes (path: pipeline outbound) | RFC: RFC 768 |
| 676 | Input Validation | Ignore Ethernet/WinDivert trailing padding beyond L3 length (path: pipeline outbound) | CWE: CWE-130 |
| 677 | Input Validation | Reject config files over 256 KiB (path: pipeline outbound) | CWE: CWE-400 |
| 678 | Input Validation | Reject web UI requests over 16 KiB (path: pipeline outbound) | CWE: CWE-400 |
| 679 | Input Validation | Cap WinDivert driver files hashed at 16 MiB (path: pipeline outbound) | CWE: CWE-400 |
| 680 | Input Validation | Validate every toml field with deny_unknown_fields (path: pipeline outbound) | CWE: CWE-20 |
| 681 | Input Validation | Reject fragment_chunk_size = 1 (fingerprint) (path: pipeline outbound) | CWE: CWE-200 |
| 682 | Input Validation | Clamp tls_record_chunk_size to 1..=16384 (path: pipeline outbound) | RFC: RFC 8446 §5.1 |
| 683 | Input Validation | Reject web_ui_token < 16 characters (path: pipeline outbound) | CWE: CWE-521 |
| 684 | Input Validation | Constrain token charset to printable ASCII without quotes/backslash (path: pipeline outbound) | CWE: CWE-20 |
| 685 | Input Validation | Constrain kill-switch adapter name to [A-Za-z0-9 _-]+ (path: pipeline outbound) | CWE: CWE-78 |
| 686 | Input Validation | Reject empty/non-ASCII SNI hostnames (path: pipeline outbound) | RFC: RFC 5890 |
| 687 | Input Validation | Reject DoH URL with userinfo component (path: pipeline outbound) | RFC: RFC 3986 §3.2.1 |
| 688 | Input Validation | Require DoH URL scheme to be https (path: pipeline outbound) | RFC: RFC 8484 |
| 689 | Input Validation | Reject relay destination loopback/link-local/multicast (path: pipeline outbound) | CWE: CWE-918 |
| 690 | Input Validation | Reject hostname 'localhost' / '*.localhost' as a target (path: pipeline outbound) | RFC: RFC 6761 §6.3 |
| 691 | Input Validation | Reject 'metadata.google.internal' as target (SSRF) (path: pipeline outbound) | MITRE ATT&CK: T1552.005 |
| 692 | Input Validation | Reject '*.local' (mDNS) and '*.internal' target names (path: pipeline outbound) | RFC: RFC 6762 |
| 693 | Input Validation | Treat IPv4-mapped IPv6 (::ffff:a.b.c.d) as its IPv4 form for ACLs (path: pipeline outbound) | CWE: CWE-20 |
| 694 | Input Validation | Allow RFC1918 destinations (operator may target internal hosts) (path: pipeline outbound) | RFC: RFC 1918 |
| 695 | Input Validation | Reject 169.254.169.254 cloud metadata endpoint (path: pipeline outbound) | MITRE ATT&CK: T1552.005 |
| 696 | Memory Safety | deny(unsafe_code) crate-wide; only engine.rs and singleton.rs opt in (path: pipeline outbound) | CWE: CWE-119 |
| 697 | Memory Safety | Catch panics on the packet path and re-inject original (fail-open) (path: pipeline outbound) | CWE: CWE-703 |
| 698 | Memory Safety | Recover Mutex after poison instead of crashing the capture thread (path: pipeline outbound) | CWE: CWE-667 |
| 699 | Memory Safety | No integer overflow in length math (overflow-checks=true in release) (path: pipeline outbound) | CWE: CWE-190 |
| 700 | Memory Safety | panic=unwind so catch_unwind can recover on the packet path (path: pipeline outbound) | CWE: CWE-703 |
| 701 | Memory Safety | All FFI calls (WinDivert/flock/CreateFileW) have SAFETY comments (path: pipeline outbound) | CWE: CWE-119 |
| 702 | Memory Safety | Validate NUL-terminated UTF-16 before CreateFileW (path: pipeline outbound) | CWE: CWE-170 |
| 703 | Memory Safety | Cap reassembly buffer at 16 KiB per flow (path: pipeline outbound) | CWE: CWE-770 |
| 704 | Memory Safety | Cap concurrent flow table at 256 flows (path: pipeline outbound) | CWE: CWE-770 |
| 705 | Memory Safety | Cap strategy score table at 4096 entries (path: pipeline outbound) | CWE: CWE-770 |
| 706 | Memory Safety | Cap QUIC port mapper to MAX_QUIC_MAPS entries (path: pipeline outbound) | CWE: CWE-770 |
| 707 | Memory Safety | Cap relay held packet queue at MAX_HELD (256) (path: pipeline outbound) | CWE: CWE-770 |
| 708 | Memory Safety | Cap recent-domain ring at MAX_RECENT (512) (path: pipeline outbound) | CWE: CWE-770 |
| 709 | Memory Safety | Session-ticket LRU bounded (path: pipeline outbound) | CWE: CWE-770 |
| 710 | Memory Safety | No recursion on attacker-controlled DNS name depth (path: pipeline outbound) | CWE: CWE-674 |
| 711 | Memory Safety | No get_unchecked / unchecked indexing (path: pipeline outbound) | CWE: CWE-119 |
| 712 | Memory Safety | No unsafe transmute (path: pipeline outbound) | CWE: CWE-704 |
| 713 | Memory Safety | Clamp signed deltas in TTL/seq math before cast to unsigned (path: pipeline outbound) | CWE: CWE-190 |
| 714 | Memory Safety | Use wrapping_add for TCP sequence arithmetic (path: pipeline outbound) | RFC: RFC 9293 §3.1 |
| 715 | Auth | Web UI bound to 127.0.0.1 only (path: pipeline outbound) | OWASP: ASVS V1.4 |
| 716 | Auth | Every /api/* route requires Bearer token (path: pipeline outbound) | OWASP: ASVS V3.5 |
| 717 | Auth | Constant-time token comparison (integrity::constant_time_eq) (path: pipeline outbound) | CWE: CWE-208 |
| 718 | Auth | Auto-generated 128-bit token when unset (hex) (path: pipeline outbound) | CWE: CWE-330 |
| 719 | Auth | 80 ms delay before each 401 response (brute-force throttle) (path: pipeline outbound) | CWE: CWE-307 |
| 720 | Auth | Token never appears in /api/config output (redacted) (path: pipeline outbound) | CWE: CWE-200 |
| 721 | Auth | Token never appears in Debug/logs except one-time startup print (path: pipeline outbound) | CWE: CWE-532 |
| 722 | Auth | merge_partial ignores empty web_ui_token (Save never wipes token) (path: pipeline outbound) | CWE: CWE-522 |
| 723 | Auth | merge_partial ignores empty win_divert_sha256 (Save never wipes pins) (path: pipeline outbound) | CWE: CWE-522 |
| 724 | Auth | win_divert_sha256 pins must be 64 hex chars (path: pipeline outbound) | CWE: CWE-20 |
| 725 | Auth | Driver SHA-256 pin compare is length-independent (path: pipeline outbound) | CWE: CWE-208 |
| 726 | Auth | Dashboard token kept in localStorage; sent over loopback only (path: pipeline outbound) | OWASP: ASVS V3.4 |
| 727 | Network | Relay bind is 127.0.0.1, never 0.0.0.0/INADDR_ANY (path: pipeline outbound) | CWE: CWE-668 |
| 728 | Network | Accept only loopback peers (defence in depth) (path: pipeline outbound) | CWE: CWE-923 |
| 729 | Network | Single fixed relay destination — cannot be used as open proxy (path: pipeline outbound) | CWE: CWE-918 |
| 730 | Network | Never-intercept SSH 22/DNS 53/RDP 3389 even in all-ports mode (path: pipeline outbound) | CWE: CWE-284 |
| 731 | Network | WinDivert filter uses '!loopback' clause (path: pipeline outbound) | USENIX Security/WoCon: GoodbyeDPI/zapret analysis |
| 732 | Network | WinDivert handle opened with minimal flags (no sniff/drop) (path: pipeline outbound) | CWE: CWE-284 |
| 733 | Network | Inject uses a send-only handle with filter 'false' (path: pipeline outbound) | CWE: CWE-284 |
| 734 | Network | Outbound socket bound before connect (source port known to monitor) (path: pipeline outbound) | USENIX Security/WoCon: patterniha wrong_seq |
| 735 | Network | set_nodelay(true) on relay sockets (path: pipeline outbound) | CWE: CWE-405 |
| 736 | Network | Coexistence error names patterniha on bind failure (path: pipeline outbound) | CWE: CWE-754 |
| 737 | Network | Relay requires WinDivert capture ready before connecting (3s cap) (path: pipeline outbound) | CWE: CWE-754 |
| 738 | Network | Only A (IPv4) DNS queries issued (no AAAA) (path: pipeline outbound) | RFC: RFC 8484 |
| 739 | Network | No UDP/53 fallback if DoH fails (fail-closed) (path: pipeline outbound) | CWE: CWE-319 |
| 740 | Network | TLS to DoH via rustls (no native-tls/OpenSSL) (path: pipeline outbound) | OWASP: ASCS V6.1 |
| 741 | Network | DoH Accept header 'application/dns-message' (path: pipeline outbound) | RFC: RFC 8484 §6 |
| 742 | Network | DoH response body capped at 64 KiB (path: pipeline outbound) | CWE: CWE-770 |
| 743 | Network | DoH loopback/metadata answers refused (path: pipeline outbound) | CWE: CWE-918 |
| 744 | Network | No REALITY/Hysteria/TUIC support — scope enforced (path: pipeline outbound) | NIST SP 800: 800-53 SA-15 |
| 745 | Network | DNS WFP block is a STUB; documented honestly, not claimed (path: pipeline outbound) | CWE: CWE-1188 |
| 746 | Crypto | Driver integrity verified by SHA-256 pin list (path: pipeline outbound) | NIST SP 800: FIPS 180-4 |
| 747 | Crypto | Per-process random salt for endpoint/domain hashing (path: pipeline outbound) | CWE: CWE-330 |
| 748 | Crypto | Tokens use rand::rngs::OsRng (OS CSPRNG) (path: pipeline outbound) | NIST SP 800: SP 800-90A |
| 749 | Crypto | No MD5/SHA-1 used for trust (TCP MD5SIG is optional wire trick) (path: pipeline outbound) | CWE: CWE-327 |
| 750 | Crypto | ECH is GREASE only — no HPKE claim (honest docs) (path: pipeline outbound) | RFC: RFC 9180 |
| 751 | Crypto | uTLS reorder preserves multiset/key_share (no MITM breakage) (path: pipeline outbound) | USENIX Security/WoCon: utls #25 |
| 752 | Crypto | SNI mutation preserves identity by default (Stealth profile) (path: pipeline outbound) | USENIX Security/WoCon: Geneva/GoodbyeDPI |
| 753 | Crypto | TLS record fragmentation produces structurally valid 0x16 records (path: pipeline outbound) | RFC: RFC 8446 §5 |
| 754 | Crypto | TCP checksum recomputed after every edit (IPv4 pseudo-header) (path: pipeline outbound) | RFC: RFC 9293 |
| 755 | Crypto | UDP checksum non-zero per RFC 768 (0xFFFF when computed zero) (path: pipeline outbound) | RFC: RFC 768 |
| 756 | Crypto | Checksum field zeroed before recomputation (path: pipeline outbound) | RFC: RFC 1071 |
| 757 | Crypto | L3 total length / payload length updated on rebuild (path: pipeline outbound) | RFC: RFC 791/8200 |
| 758 | Web UI | Host header must be 127.0.0.1[:port] (DNS-rebind defence) (path: pipeline outbound) | OWASP: ASVS V14.5 |
| 759 | Web UI | Reject Host 'localhost' and any other name (path: pipeline outbound) | CWE: CWE-346 |
| 760 | Web UI | Origin must be empty or http://127.0.0.1:<port> (path: pipeline outbound) | OWASP: ASVS V14.4 |
| 761 | Web UI | Content-Security-Policy default-src 'none' (path: pipeline outbound) | OWASP: ASVS V14.4 |
| 762 | Web UI | X-Frame-Options: DENY (clickjacking) (path: pipeline outbound) | OWASP: ASVS V14.4 |
| 763 | Web UI | X-Content-Type-Options: nosniff (path: pipeline outbound) | OWASP: ASVS V14.4 |
| 764 | Web UI | Referrer-Policy: no-referrer (path: pipeline outbound) | OWASP: ASVS V14.4 |
| 765 | Web UI | Cache-Control: no-store on API responses (path: pipeline outbound) | CWE: CWE-525 |
| 766 | Web UI | Cross-Origin-Resource-Policy: same-origin (path: pipeline outbound) | OWASP: Fetch standard |
| 767 | Web UI | Cross-Origin-Opener-Policy: same-origin (path: pipeline outbound) | OWASP: HTML standard |
| 768 | Web UI | Permissions-Policy disables camera/microphone/geolocation (path: pipeline outbound) | OWASP: Permissions Policy |
| 769 | Web UI | No file serving / directory listing (path: pipeline outbound) | CWE: CWE-548 |
| 770 | Web UI | No CORS headers (same-origin only) (path: pipeline outbound) | OWASP: CORS standard |
| 771 | Web UI | JSON responses Content-Type application/json (path: pipeline outbound) | CWE: CWE-79 |
| 772 | Web UI | HTML escaping for all user-influenced strings (path: pipeline outbound) | CWE: CWE-79 |
| 773 | Web UI | TOML advanced editor uses validated merge path (path: pipeline outbound) | CWE: CWE-20 |
| 774 | Web UI | No eval/innerHTML of remote data (path: pipeline outbound) | CWE: CWE-95 |
| 775 | Web UI | 413 returned when body exceeds cap (path: pipeline outbound) | CWE: CWE-400 |
| 776 | Privacy | No raw destination IP in logs (redact_endpoint) (path: pipeline outbound) | CWE: CWE-532 |
| 777 | Privacy | Observed domains hashed with per-process salt in UI/logs (path: pipeline outbound) | CWE: CWE-200 |
| 778 | Privacy | Token and pins not in Debug output (path: pipeline outbound) | CWE: CWE-532 |
| 779 | Privacy | relay_connect_host redacted in Debug (path: pipeline outbound) | CWE: CWE-532 |
| 780 | Privacy | Strategy scores keyed by hashed domain (path: pipeline outbound) | CWE: CWE-200 |
| 781 | Privacy | Recent domains shown hashed, never plaintext (path: pipeline outbound) | CWE: CWE-200 |
| 782 | Privacy | No query-string/token in logs (path: pipeline outbound) | CWE: CWE-532 |
| 783 | Privacy | No PII collected; no telemetry (path: pipeline outbound) | NIST SP 800: 800-53 SI-12 |
| 784 | Privacy | DoH prevents plaintext DNS on port 53 (path: pipeline outbound) | RFC: RFC 8484 |
| 785 | Supply Chain | WinDivert loaded ONLY from exe directory (never cwd) (path: pipeline outbound) | CWE: CWE-427 |
| 786 | Supply Chain | WinDivert.dll/.sys are gitignored (never shipped in repo) (path: pipeline outbound) | CWE: CWE-829 |
| 787 | Supply Chain | Official reqrypt.org download URL documented (path: pipeline outbound) | NIST SP 800: 800-161 |
| 788 | Supply Chain | Pinned dependency versions in Cargo.toml/Cargo.lock (path: pipeline outbound) | NIST SP 800: 800-161 |
| 789 | Supply Chain | No post-build scripts / build.rs that fetch network (path: pipeline outbound) | CWE: CWE-829 |
| 790 | Supply Chain | Release profile panic=unwind + overflow-checks=true (path: pipeline outbound) | CWE: CWE-190 |
| 791 | Supply Chain | .gitignore excludes target, dll, sys, exe, zip, tar.gz, DS_Store (path: pipeline outbound) | CWE: CWE-829 |
| 792 | Supply Chain | Refuse to hash driver files over 16 MiB (planted DoS) (path: pipeline outbound) | CWE: CWE-400 |
| 793 | Concurrency | One-instance file lock prevents dual capture (path: pipeline outbound) | CWE: CWE-667 |
| 794 | Concurrency | running flag gates the accept/recv loops (path: pipeline outbound) | CWE: CWE-667 |
| 795 | Concurrency | WinDivertShutdown unblocks recv on Ctrl+C (path: pipeline outbound) | CWE: CWE-400 |
| 796 | Concurrency | Held packets flushed with original WinDivert address (path: pipeline outbound) | USENIX Security/WoCon: WinDivert semantics |
| 797 | Concurrency | Hot reload reopens handle; falls back to old filter on failure (path: pipeline outbound) | CWE: CWE-754 |
| 798 | Concurrency | Relay restarts on RelayId change (incl. require_inject) (path: pipeline outbound) | CWE: CWE-362 |
| 799 | Concurrency | Idempotent start/stop of relay (path: pipeline outbound) | CWE: CWE-362 |
| 800 | Concurrency | 200ms watchdog flushes expired held packets (path: pipeline outbound) | CWE: CWE-400 |
| 801 | Concurrency | Flow state pruned on idle (idle_timeout_secs) (path: pipeline outbound) | CWE: CWE-770 |
| 802 | Concurrency | QUIC mappings pruned on idle (path: pipeline outbound) | CWE: CWE-770 |
| 803 | Concurrency | InjectGate success/failure bit (not bare Notify) (path: pipeline outbound) | CWE: CWE-362 |
| 804 | Fail-Safe | panic/Err on packet path re-injects original (fail-open) (path: pipeline outbound) | CWE: CWE-703 |
| 805 | Fail-Safe | Held table full fails-open with real divert address (path: pipeline outbound) | CWE: CWE-770 |
| 806 | Fail-Safe | Relay injection fail is FAIL-CLOSED (drops connection) (path: pipeline outbound) | CWE: CWE-703 |
| 807 | Fail-Safe | Explicit-passed missing config exits 1 (path: pipeline outbound) | CWE: CWE-1188 |
| 808 | Fail-Safe | Invalid config exits 1 (no silent fallback to insecure) (path: pipeline outbound) | CWE: CWE-703 |
| 809 | Fail-Safe | Driver check failure exits 1 (path: pipeline outbound) | CWE: CWE-703 |
| 810 | Fail-Safe | Capture not ready -> relay not started (3s timeout) (path: pipeline outbound) | CWE: CWE-754 |
| 811 | Fail-Safe | Filter reload failure keeps previous filter alive (path: pipeline outbound) | CWE: CWE-754 |
| 812 | Fail-Safe | DNS resolution failure keeps previous relay running (path: pipeline outbound) | CWE: CWE-703 |
| 813 | Threat Model | Destination IP visible on wire (documented, no false privacy claim) (path: pipeline outbound) | CWE: CWE-319 |
| 814 | Threat Model | WFP DNS block is a stub (documented) (path: pipeline outbound) | CWE: CWE-1188 |
| 815 | Threat Model | ECH is GREASE only (documented) (path: pipeline outbound) | CWE: CWE-319 |
| 816 | Threat Model | No kernel-mode code beyond signed WinDivert driver (path: pipeline outbound) | NIST SP 800: 800-53 AC-6 |
| 817 | Threat Model | No VPN/tunnel mode (scope enforced) (path: pipeline outbound) | CWE: CWE-923 |
| 818 | Threat Model | Admin privileges required (documented) (path: pipeline outbound) | NIST SP 800: 800-53 AC-6 |
| 819 | Threat Model | Threat model: on-path DPI only, not a global adversary (path: pipeline outbound) | USENIX Security/WoCon: Conifr/Geneva |
| 820 | Build | cargo fmt --check enforced in CI (path: pipeline outbound) | OWASP: MASVS-CODE-1 |
| 821 | Build | cargo clippy -D warnings in CI (path: pipeline outbound) | CWE: CWE-1164 |
| 822 | Build | cargo test on Linux matrix (pure-logic modules) (path: pipeline outbound) | NIST SP 800: 800-53 SA-11 |
| 823 | Build | Clippy disallows warnings (pedantic via -D warnings) (path: pipeline outbound) | CWE: CWE-1164 |
| 824 | Build | No .github/workflows committed without operator consent (path: pipeline outbound) | CWE: CWE-829 |
| 825 | Build | CI workflow is a plain file in ci/ for copy-in by operator (path: pipeline outbound) | NIST SP 800: 800-53 CM-3 |
| 826 | Input Validation | Reject truncated/malformed TLS records without indexing out of bounds (path: pipeline inbound) | CWE: CWE-125 |
| 827 | Input Validation | Bound every length field before slicing a packet buffer (path: pipeline inbound) | CWE: CWE-130 |
| 828 | Input Validation | Treat all attacker-controlled offsets as untrusted; re-validate after each read (path: pipeline inbound) | CWE: CWE-20 |
| 829 | Input Validation | Reject DNS labels longer than 63 octets (path: pipeline inbound) | RFC: RFC 1035 §2.3.4 |
| 830 | Input Validation | Reject DNS names longer than 253 octets (path: pipeline inbound) | RFC: RFC 1035 §2.3.4 |
| 831 | Input Validation | Cap DNS compression-pointer hop count to prevent loops (path: pipeline inbound) | CWE: CWE-835 |
| 832 | Input Validation | Reject DNS compression pointers that point forward/self (path: pipeline inbound) | RFC: RFC 1035 §4.1.4 |
| 833 | Input Validation | Cap DNS message body size to 64 KiB before parsing (path: pipeline inbound) | CWE: CWE-770 |
| 834 | Input Validation | Reject TLS ClientHello with odd cipher-suite length (path: pipeline inbound) | RFC: RFC 8446 §4.1.2 |
| 835 | Input Validation | Reject TLS records with content type other than 0x16 for handshake parsing (path: pipeline inbound) | RFC: RFC 8446 §5 |
| 836 | Input Validation | Require record version 0x03,0x01+ for TLS parsing (path: pipeline inbound) | RFC: RFC 8446 §5.1 |
| 837 | Input Validation | Clamp TCP payload to IPv4 Total Length / IPv6 Payload Length (path: pipeline inbound) | CWE: CWE-130 |
| 838 | Input Validation | Reject IPv4 IHL < 20 bytes (path: pipeline inbound) | RFC: RFC 791 §3.1 |
| 839 | Input Validation | Reject TCP data offset < 20 bytes (path: pipeline inbound) | RFC: RFC 9293 §3.1 |
| 840 | Input Validation | Reject UDP length field smaller than 8 bytes (path: pipeline inbound) | RFC: RFC 768 |
| 841 | Input Validation | Ignore Ethernet/WinDivert trailing padding beyond L3 length (path: pipeline inbound) | CWE: CWE-130 |
| 842 | Input Validation | Reject config files over 256 KiB (path: pipeline inbound) | CWE: CWE-400 |
| 843 | Input Validation | Reject web UI requests over 16 KiB (path: pipeline inbound) | CWE: CWE-400 |
| 844 | Input Validation | Cap WinDivert driver files hashed at 16 MiB (path: pipeline inbound) | CWE: CWE-400 |
| 845 | Input Validation | Validate every toml field with deny_unknown_fields (path: pipeline inbound) | CWE: CWE-20 |
| 846 | Input Validation | Reject fragment_chunk_size = 1 (fingerprint) (path: pipeline inbound) | CWE: CWE-200 |
| 847 | Input Validation | Clamp tls_record_chunk_size to 1..=16384 (path: pipeline inbound) | RFC: RFC 8446 §5.1 |
| 848 | Input Validation | Reject web_ui_token < 16 characters (path: pipeline inbound) | CWE: CWE-521 |
| 849 | Input Validation | Constrain token charset to printable ASCII without quotes/backslash (path: pipeline inbound) | CWE: CWE-20 |
| 850 | Input Validation | Constrain kill-switch adapter name to [A-Za-z0-9 _-]+ (path: pipeline inbound) | CWE: CWE-78 |
| 851 | Input Validation | Reject empty/non-ASCII SNI hostnames (path: pipeline inbound) | RFC: RFC 5890 |
| 852 | Input Validation | Reject DoH URL with userinfo component (path: pipeline inbound) | RFC: RFC 3986 §3.2.1 |
| 853 | Input Validation | Require DoH URL scheme to be https (path: pipeline inbound) | RFC: RFC 8484 |
| 854 | Input Validation | Reject relay destination loopback/link-local/multicast (path: pipeline inbound) | CWE: CWE-918 |
| 855 | Input Validation | Reject hostname 'localhost' / '*.localhost' as a target (path: pipeline inbound) | RFC: RFC 6761 §6.3 |
| 856 | Input Validation | Reject 'metadata.google.internal' as target (SSRF) (path: pipeline inbound) | MITRE ATT&CK: T1552.005 |
| 857 | Input Validation | Reject '*.local' (mDNS) and '*.internal' target names (path: pipeline inbound) | RFC: RFC 6762 |
| 858 | Input Validation | Treat IPv4-mapped IPv6 (::ffff:a.b.c.d) as its IPv4 form for ACLs (path: pipeline inbound) | CWE: CWE-20 |
| 859 | Input Validation | Allow RFC1918 destinations (operator may target internal hosts) (path: pipeline inbound) | RFC: RFC 1918 |
| 860 | Input Validation | Reject 169.254.169.254 cloud metadata endpoint (path: pipeline inbound) | MITRE ATT&CK: T1552.005 |
| 861 | Memory Safety | deny(unsafe_code) crate-wide; only engine.rs and singleton.rs opt in (path: pipeline inbound) | CWE: CWE-119 |
| 862 | Memory Safety | Catch panics on the packet path and re-inject original (fail-open) (path: pipeline inbound) | CWE: CWE-703 |
| 863 | Memory Safety | Recover Mutex after poison instead of crashing the capture thread (path: pipeline inbound) | CWE: CWE-667 |
| 864 | Memory Safety | No integer overflow in length math (overflow-checks=true in release) (path: pipeline inbound) | CWE: CWE-190 |
| 865 | Memory Safety | panic=unwind so catch_unwind can recover on the packet path (path: pipeline inbound) | CWE: CWE-703 |
| 866 | Memory Safety | All FFI calls (WinDivert/flock/CreateFileW) have SAFETY comments (path: pipeline inbound) | CWE: CWE-119 |
| 867 | Memory Safety | Validate NUL-terminated UTF-16 before CreateFileW (path: pipeline inbound) | CWE: CWE-170 |
| 868 | Memory Safety | Cap reassembly buffer at 16 KiB per flow (path: pipeline inbound) | CWE: CWE-770 |
| 869 | Memory Safety | Cap concurrent flow table at 256 flows (path: pipeline inbound) | CWE: CWE-770 |
| 870 | Memory Safety | Cap strategy score table at 4096 entries (path: pipeline inbound) | CWE: CWE-770 |
| 871 | Memory Safety | Cap QUIC port mapper to MAX_QUIC_MAPS entries (path: pipeline inbound) | CWE: CWE-770 |
| 872 | Memory Safety | Cap relay held packet queue at MAX_HELD (256) (path: pipeline inbound) | CWE: CWE-770 |
| 873 | Memory Safety | Cap recent-domain ring at MAX_RECENT (512) (path: pipeline inbound) | CWE: CWE-770 |
| 874 | Memory Safety | Session-ticket LRU bounded (path: pipeline inbound) | CWE: CWE-770 |
| 875 | Memory Safety | No recursion on attacker-controlled DNS name depth (path: pipeline inbound) | CWE: CWE-674 |
| 876 | Memory Safety | No get_unchecked / unchecked indexing (path: pipeline inbound) | CWE: CWE-119 |
| 877 | Memory Safety | No unsafe transmute (path: pipeline inbound) | CWE: CWE-704 |
| 878 | Memory Safety | Clamp signed deltas in TTL/seq math before cast to unsigned (path: pipeline inbound) | CWE: CWE-190 |
| 879 | Memory Safety | Use wrapping_add for TCP sequence arithmetic (path: pipeline inbound) | RFC: RFC 9293 §3.1 |
| 880 | Auth | Web UI bound to 127.0.0.1 only (path: pipeline inbound) | OWASP: ASVS V1.4 |
| 881 | Auth | Every /api/* route requires Bearer token (path: pipeline inbound) | OWASP: ASVS V3.5 |
| 882 | Auth | Constant-time token comparison (integrity::constant_time_eq) (path: pipeline inbound) | CWE: CWE-208 |
| 883 | Auth | Auto-generated 128-bit token when unset (hex) (path: pipeline inbound) | CWE: CWE-330 |
| 884 | Auth | 80 ms delay before each 401 response (brute-force throttle) (path: pipeline inbound) | CWE: CWE-307 |
| 885 | Auth | Token never appears in /api/config output (redacted) (path: pipeline inbound) | CWE: CWE-200 |
| 886 | Auth | Token never appears in Debug/logs except one-time startup print (path: pipeline inbound) | CWE: CWE-532 |
| 887 | Auth | merge_partial ignores empty web_ui_token (Save never wipes token) (path: pipeline inbound) | CWE: CWE-522 |
| 888 | Auth | merge_partial ignores empty win_divert_sha256 (Save never wipes pins) (path: pipeline inbound) | CWE: CWE-522 |
| 889 | Auth | win_divert_sha256 pins must be 64 hex chars (path: pipeline inbound) | CWE: CWE-20 |
| 890 | Auth | Driver SHA-256 pin compare is length-independent (path: pipeline inbound) | CWE: CWE-208 |
| 891 | Auth | Dashboard token kept in localStorage; sent over loopback only (path: pipeline inbound) | OWASP: ASVS V3.4 |
| 892 | Network | Relay bind is 127.0.0.1, never 0.0.0.0/INADDR_ANY (path: pipeline inbound) | CWE: CWE-668 |
| 893 | Network | Accept only loopback peers (defence in depth) (path: pipeline inbound) | CWE: CWE-923 |
| 894 | Network | Single fixed relay destination — cannot be used as open proxy (path: pipeline inbound) | CWE: CWE-918 |
| 895 | Network | Never-intercept SSH 22/DNS 53/RDP 3389 even in all-ports mode (path: pipeline inbound) | CWE: CWE-284 |
| 896 | Network | WinDivert filter uses '!loopback' clause (path: pipeline inbound) | USENIX Security/WoCon: GoodbyeDPI/zapret analysis |
| 897 | Network | WinDivert handle opened with minimal flags (no sniff/drop) (path: pipeline inbound) | CWE: CWE-284 |
| 898 | Network | Inject uses a send-only handle with filter 'false' (path: pipeline inbound) | CWE: CWE-284 |
| 899 | Network | Outbound socket bound before connect (source port known to monitor) (path: pipeline inbound) | USENIX Security/WoCon: patterniha wrong_seq |
| 900 | Network | set_nodelay(true) on relay sockets (path: pipeline inbound) | CWE: CWE-405 |
| 901 | Network | Coexistence error names patterniha on bind failure (path: pipeline inbound) | CWE: CWE-754 |
| 902 | Network | Relay requires WinDivert capture ready before connecting (3s cap) (path: pipeline inbound) | CWE: CWE-754 |
| 903 | Network | Only A (IPv4) DNS queries issued (no AAAA) (path: pipeline inbound) | RFC: RFC 8484 |
| 904 | Network | No UDP/53 fallback if DoH fails (fail-closed) (path: pipeline inbound) | CWE: CWE-319 |
| 905 | Network | TLS to DoH via rustls (no native-tls/OpenSSL) (path: pipeline inbound) | OWASP: ASCS V6.1 |
| 906 | Network | DoH Accept header 'application/dns-message' (path: pipeline inbound) | RFC: RFC 8484 §6 |
| 907 | Network | DoH response body capped at 64 KiB (path: pipeline inbound) | CWE: CWE-770 |
| 908 | Network | DoH loopback/metadata answers refused (path: pipeline inbound) | CWE: CWE-918 |
| 909 | Network | No REALITY/Hysteria/TUIC support — scope enforced (path: pipeline inbound) | NIST SP 800: 800-53 SA-15 |
| 910 | Network | DNS WFP block is a STUB; documented honestly, not claimed (path: pipeline inbound) | CWE: CWE-1188 |
| 911 | Crypto | Driver integrity verified by SHA-256 pin list (path: pipeline inbound) | NIST SP 800: FIPS 180-4 |
| 912 | Crypto | Per-process random salt for endpoint/domain hashing (path: pipeline inbound) | CWE: CWE-330 |
| 913 | Crypto | Tokens use rand::rngs::OsRng (OS CSPRNG) (path: pipeline inbound) | NIST SP 800: SP 800-90A |
| 914 | Crypto | No MD5/SHA-1 used for trust (TCP MD5SIG is optional wire trick) (path: pipeline inbound) | CWE: CWE-327 |
| 915 | Crypto | ECH is GREASE only — no HPKE claim (honest docs) (path: pipeline inbound) | RFC: RFC 9180 |
| 916 | Crypto | uTLS reorder preserves multiset/key_share (no MITM breakage) (path: pipeline inbound) | USENIX Security/WoCon: utls #25 |
| 917 | Crypto | SNI mutation preserves identity by default (Stealth profile) (path: pipeline inbound) | USENIX Security/WoCon: Geneva/GoodbyeDPI |
| 918 | Crypto | TLS record fragmentation produces structurally valid 0x16 records (path: pipeline inbound) | RFC: RFC 8446 §5 |
| 919 | Crypto | TCP checksum recomputed after every edit (IPv4 pseudo-header) (path: pipeline inbound) | RFC: RFC 9293 |
| 920 | Crypto | UDP checksum non-zero per RFC 768 (0xFFFF when computed zero) (path: pipeline inbound) | RFC: RFC 768 |
| 921 | Crypto | Checksum field zeroed before recomputation (path: pipeline inbound) | RFC: RFC 1071 |
| 922 | Crypto | L3 total length / payload length updated on rebuild (path: pipeline inbound) | RFC: RFC 791/8200 |
| 923 | Web UI | Host header must be 127.0.0.1[:port] (DNS-rebind defence) (path: pipeline inbound) | OWASP: ASVS V14.5 |
| 924 | Web UI | Reject Host 'localhost' and any other name (path: pipeline inbound) | CWE: CWE-346 |
| 925 | Web UI | Origin must be empty or http://127.0.0.1:<port> (path: pipeline inbound) | OWASP: ASVS V14.4 |
| 926 | Web UI | Content-Security-Policy default-src 'none' (path: pipeline inbound) | OWASP: ASVS V14.4 |
| 927 | Web UI | X-Frame-Options: DENY (clickjacking) (path: pipeline inbound) | OWASP: ASVS V14.4 |
| 928 | Web UI | X-Content-Type-Options: nosniff (path: pipeline inbound) | OWASP: ASVS V14.4 |
| 929 | Web UI | Referrer-Policy: no-referrer (path: pipeline inbound) | OWASP: ASVS V14.4 |
| 930 | Web UI | Cache-Control: no-store on API responses (path: pipeline inbound) | CWE: CWE-525 |
| 931 | Web UI | Cross-Origin-Resource-Policy: same-origin (path: pipeline inbound) | OWASP: Fetch standard |
| 932 | Web UI | Cross-Origin-Opener-Policy: same-origin (path: pipeline inbound) | OWASP: HTML standard |
| 933 | Web UI | Permissions-Policy disables camera/microphone/geolocation (path: pipeline inbound) | OWASP: Permissions Policy |
| 934 | Web UI | No file serving / directory listing (path: pipeline inbound) | CWE: CWE-548 |
| 935 | Web UI | No CORS headers (same-origin only) (path: pipeline inbound) | OWASP: CORS standard |
| 936 | Web UI | JSON responses Content-Type application/json (path: pipeline inbound) | CWE: CWE-79 |
| 937 | Web UI | HTML escaping for all user-influenced strings (path: pipeline inbound) | CWE: CWE-79 |
| 938 | Web UI | TOML advanced editor uses validated merge path (path: pipeline inbound) | CWE: CWE-20 |
| 939 | Web UI | No eval/innerHTML of remote data (path: pipeline inbound) | CWE: CWE-95 |
| 940 | Web UI | 413 returned when body exceeds cap (path: pipeline inbound) | CWE: CWE-400 |
| 941 | Privacy | No raw destination IP in logs (redact_endpoint) (path: pipeline inbound) | CWE: CWE-532 |
| 942 | Privacy | Observed domains hashed with per-process salt in UI/logs (path: pipeline inbound) | CWE: CWE-200 |
| 943 | Privacy | Token and pins not in Debug output (path: pipeline inbound) | CWE: CWE-532 |
| 944 | Privacy | relay_connect_host redacted in Debug (path: pipeline inbound) | CWE: CWE-532 |
| 945 | Privacy | Strategy scores keyed by hashed domain (path: pipeline inbound) | CWE: CWE-200 |
| 946 | Privacy | Recent domains shown hashed, never plaintext (path: pipeline inbound) | CWE: CWE-200 |
| 947 | Privacy | No query-string/token in logs (path: pipeline inbound) | CWE: CWE-532 |
| 948 | Privacy | No PII collected; no telemetry (path: pipeline inbound) | NIST SP 800: 800-53 SI-12 |
| 949 | Privacy | DoH prevents plaintext DNS on port 53 (path: pipeline inbound) | RFC: RFC 8484 |
| 950 | Supply Chain | WinDivert loaded ONLY from exe directory (never cwd) (path: pipeline inbound) | CWE: CWE-427 |
| 951 | Supply Chain | WinDivert.dll/.sys are gitignored (never shipped in repo) (path: pipeline inbound) | CWE: CWE-829 |
| 952 | Supply Chain | Official reqrypt.org download URL documented (path: pipeline inbound) | NIST SP 800: 800-161 |
| 953 | Supply Chain | Pinned dependency versions in Cargo.toml/Cargo.lock (path: pipeline inbound) | NIST SP 800: 800-161 |
| 954 | Supply Chain | No post-build scripts / build.rs that fetch network (path: pipeline inbound) | CWE: CWE-829 |
| 955 | Supply Chain | Release profile panic=unwind + overflow-checks=true (path: pipeline inbound) | CWE: CWE-190 |
| 956 | Supply Chain | .gitignore excludes target, dll, sys, exe, zip, tar.gz, DS_Store (path: pipeline inbound) | CWE: CWE-829 |
| 957 | Supply Chain | Refuse to hash driver files over 16 MiB (planted DoS) (path: pipeline inbound) | CWE: CWE-400 |
| 958 | Concurrency | One-instance file lock prevents dual capture (path: pipeline inbound) | CWE: CWE-667 |
| 959 | Concurrency | running flag gates the accept/recv loops (path: pipeline inbound) | CWE: CWE-667 |
| 960 | Concurrency | WinDivertShutdown unblocks recv on Ctrl+C (path: pipeline inbound) | CWE: CWE-400 |
| 961 | Concurrency | Held packets flushed with original WinDivert address (path: pipeline inbound) | USENIX Security/WoCon: WinDivert semantics |
| 962 | Concurrency | Hot reload reopens handle; falls back to old filter on failure (path: pipeline inbound) | CWE: CWE-754 |
| 963 | Concurrency | Relay restarts on RelayId change (incl. require_inject) (path: pipeline inbound) | CWE: CWE-362 |
| 964 | Concurrency | Idempotent start/stop of relay (path: pipeline inbound) | CWE: CWE-362 |
| 965 | Concurrency | 200ms watchdog flushes expired held packets (path: pipeline inbound) | CWE: CWE-400 |
| 966 | Concurrency | Flow state pruned on idle (idle_timeout_secs) (path: pipeline inbound) | CWE: CWE-770 |
| 967 | Concurrency | QUIC mappings pruned on idle (path: pipeline inbound) | CWE: CWE-770 |
| 968 | Concurrency | InjectGate success/failure bit (not bare Notify) (path: pipeline inbound) | CWE: CWE-362 |
| 969 | Fail-Safe | panic/Err on packet path re-injects original (fail-open) (path: pipeline inbound) | CWE: CWE-703 |
| 970 | Fail-Safe | Held table full fails-open with real divert address (path: pipeline inbound) | CWE: CWE-770 |
| 971 | Fail-Safe | Relay injection fail is FAIL-CLOSED (drops connection) (path: pipeline inbound) | CWE: CWE-703 |
| 972 | Fail-Safe | Explicit-passed missing config exits 1 (path: pipeline inbound) | CWE: CWE-1188 |
| 973 | Fail-Safe | Invalid config exits 1 (no silent fallback to insecure) (path: pipeline inbound) | CWE: CWE-703 |
| 974 | Fail-Safe | Driver check failure exits 1 (path: pipeline inbound) | CWE: CWE-703 |
| 975 | Fail-Safe | Capture not ready -> relay not started (3s timeout) (path: pipeline inbound) | CWE: CWE-754 |
| 976 | Fail-Safe | Filter reload failure keeps previous filter alive (path: pipeline inbound) | CWE: CWE-754 |
| 977 | Fail-Safe | DNS resolution failure keeps previous relay running (path: pipeline inbound) | CWE: CWE-703 |
| 978 | Threat Model | Destination IP visible on wire (documented, no false privacy claim) (path: pipeline inbound) | CWE: CWE-319 |
| 979 | Threat Model | WFP DNS block is a stub (documented) (path: pipeline inbound) | CWE: CWE-1188 |
| 980 | Threat Model | ECH is GREASE only (documented) (path: pipeline inbound) | CWE: CWE-319 |
| 981 | Threat Model | No kernel-mode code beyond signed WinDivert driver (path: pipeline inbound) | NIST SP 800: 800-53 AC-6 |
| 982 | Threat Model | No VPN/tunnel mode (scope enforced) (path: pipeline inbound) | CWE: CWE-923 |
| 983 | Threat Model | Admin privileges required (documented) (path: pipeline inbound) | NIST SP 800: 800-53 AC-6 |
| 984 | Threat Model | Threat model: on-path DPI only, not a global adversary (path: pipeline inbound) | USENIX Security/WoCon: Conifr/Geneva |
| 985 | Build | cargo fmt --check enforced in CI (path: pipeline inbound) | OWASP: MASVS-CODE-1 |
| 986 | Build | cargo clippy -D warnings in CI (path: pipeline inbound) | CWE: CWE-1164 |
| 987 | Build | cargo test on Linux matrix (pure-logic modules) (path: pipeline inbound) | NIST SP 800: 800-53 SA-11 |
| 988 | Build | Clippy disallows warnings (pedantic via -D warnings) (path: pipeline inbound) | CWE: CWE-1164 |
| 989 | Build | No .github/workflows committed without operator consent (path: pipeline inbound) | CWE: CWE-829 |
| 990 | Build | CI workflow is a plain file in ci/ for copy-in by operator (path: pipeline inbound) | NIST SP 800: 800-53 CM-3 |
| 991 | Input Validation | Reject truncated/malformed TLS records without indexing out of bounds (path: DoH client) | CWE: CWE-125 |
| 992 | Input Validation | Bound every length field before slicing a packet buffer (path: DoH client) | CWE: CWE-130 |
| 993 | Input Validation | Treat all attacker-controlled offsets as untrusted; re-validate after each read (path: DoH client) | CWE: CWE-20 |
| 994 | Input Validation | Reject DNS labels longer than 63 octets (path: DoH client) | RFC: RFC 1035 §2.3.4 |
| 995 | Input Validation | Reject DNS names longer than 253 octets (path: DoH client) | RFC: RFC 1035 §2.3.4 |
| 996 | Input Validation | Cap DNS compression-pointer hop count to prevent loops (path: DoH client) | CWE: CWE-835 |
| 997 | Input Validation | Reject DNS compression pointers that point forward/self (path: DoH client) | RFC: RFC 1035 §4.1.4 |
| 998 | Input Validation | Cap DNS message body size to 64 KiB before parsing (path: DoH client) | CWE: CWE-770 |
| 999 | Input Validation | Reject TLS ClientHello with odd cipher-suite length (path: DoH client) | RFC: RFC 8446 §4.1.2 |
| 1000 | Input Validation | Reject TLS records with content type other than 0x16 for handshake parsing (path: DoH client) | RFC: RFC 8446 §5 |

| 1001 | UI Coverage | Every Settings field has a control in the dashboard (test-enforced) | OWASP: ASVS V5.1 |
| 1002 | UI Coverage | Dashboard schema declares no key that is not a Settings field (deny_unknown_fields) | CWE: CWE-20 |
| 1003 | UI Coverage | Adding a Settings field without a UI control fails cargo test | NIST SP 800: 800-53 SA-11 |
| 1004 | UI Coverage | Dangerous settings are not TOML-only, so they always pass validation | CWE: CWE-1288 |
| 1005 | UI Validation | Client-side rules mirror Settings::validate before the request is sent | OWASP: ASVS V5.1 |
| 1006 | UI Validation | Errors block Save; risky-but-legal states warn without blocking | CWE: CWE-1287 |
| 1007 | UI Validation | POST /api/validate runs full server validation with no disk write | CWE: CWE-693 |
| 1008 | UI Validation | Save sends only changed keys (partial merge), not a full rewrite | CWE: CWE-669 |
| 1009 | UI Validation | Server-side rejection reason is surfaced to the operator | CWE: CWE-755 |
| 1010 | UI Hardening | Dashboard page ships no external assets (CSP default-src 'none') | CWE: CWE-829 |
| 1011 | UI Hardening | Every server-derived value rendered as HTML passes esc(); raw lists use textContent | CWE: CWE-79 |
| 1012 | UI Hardening | write-only secret fields: empty means keep, so Save cannot wipe token/pins | CWE: CWE-522 |
| 1013 | UI Hardening | Confirm prompt before intercept_all_tcp / intercept_all_udp / swap foolers | CWE: CWE-1288 |
| 1014 | UI Hardening | Confirm prompt before disabling relay_require_inject (fail-closed) | CWE: CWE-636 |
| 1015 | UI Hardening | Full redacted config round-trips inside the 16 KiB / 4 KiB body caps (test-enforced) | CWE: CWE-400 |
| 1016 | Config | Option<String> fields skip serialization so None cannot break toml round-trip | CWE: CWE-755 |
| 1017 | Config | trusted_dns can be cleared from the UI (empty removes the key -> None) | CWE: CWE-1288 |
| 1018 | Supply Chain | .gitignore excludes *.dll / *.sys / dpi_guard.toml (verified with git check-ignore) | CWE: CWE-540 |
| 1019 | Supply Chain | Live config with web_ui_token is never committed | CWE: CWE-538 |

| 1020 | Memory Safety | Cap relay flow table at MAX_RELAY_FLOWS (256); it grows per client connection | CWE: CWE-770 |
| 1021 | Memory Safety | Relay flow eviction prefers finished handshakes over live ones | CWE: CWE-770 |
| 1022 | Memory Safety | Evicting a live relay flow is logged (its injection can no longer be confirmed) | CWE: CWE-778 |
| 1023 | Memory Safety | Re-registering a relay 4-tuple replaces instead of growing the table | CWE: CWE-770 |
| 1024 | Interop | Singleton lock never conflicts with v2rayN/v2ray/Xray clients | CWE: CWE-693 |
| 1025 | Interop | Relay/dashboard default ports avoid v2rayN local ports 10808/10809/10853 | CWE: CWE-406 |
| 1026 | Interop | validate() warns when relay_listen_port clashes with a v2rayN local port | CWE: CWE-1287 |
| 1027 | Interop | Filter keeps !loopback so the client->relay leg is never diverted | CWE: CWE-693 |
| 1028 | Interop | Non-QUIC UDP is forwarded unmodified (client UDP leg unaffected) | CWE: CWE-693 |
| 1029 | Interop | Relay binds the outbound socket before connect so the tracked 4-tuple matches the wire | CWE: CWE-362 |
| 1030 | Interop | v2rayN coexistence is covered by an automated suite (uitest/test-v2rayn.mjs) | NIST SP 800: 800-53 SA-11 |

Total controls: 1030
