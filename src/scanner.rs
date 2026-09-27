//! scanner — SNI / CDN-Edge scanner and ranker. [UNTESTED]
//!
//! Probes candidate SNI domains and CDN edge IPs by opening real TLS/TCP
//! connections (no root/admin needed for the SNI scan). Results are
//! scored by latency, TLS handshake success, and certificate validity
//! so the operator can pick the best SNI / edge for their ISP.
//!
//! Two scan modes:
//!   - **SNI scan** — outbound TLS/TCP to a known IP with different SNI
//!     values. Works without admin/root.
//!   - **Edge scan** — outbound TLS/TCP to different CDN IPs with a fixed
//!     SNI. Also works without admin/root.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering as AtomicOrdering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

// Note: there are deliberately no SCAN_TIMEOUT/SCAN_PROBES constants here.
// Probe budgets come from the caller (web UI / startup probe pass their own
// timeout); dead module constants only invited drift.

/// Result of a single probe.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProbeResult {
    pub candidate: String,
    pub ip: Option<IpAddr>,
    pub success: bool,
    pub latency_ms: Option<u64>,
    pub tls_ok: bool,
    pub cert_valid: bool,
    pub error: Option<String>,
}

/// Aggregated ranking for a candidate.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RankedCandidate {
    pub candidate: String,
    pub score: f64,
    pub avg_latency_ms: f64,
    pub success_rate: f64,
    pub probes: u32,
    pub tls_successes: u32,
}

/// A candidate pair for SNI spoofing and relaying: a known CDN edge IP and a matching whitelisted SNI.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SpoofCandidatePair {
    pub provider: String,
    pub connect_ip: String,
    pub port: u16,
    pub fake_sni: String,
    pub description: String,
}

impl SpoofCandidatePair {
    pub fn new(
        provider: impl Into<String>,
        connect_ip: impl Into<String>,
        port: u16,
        fake_sni: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            provider: provider.into(),
            connect_ip: connect_ip.into(),
            port,
            fake_sni: fake_sni.into(),
            description: description.into(),
        }
    }
}

/// Pre-configured list of verified, high-performance (CONNECT_IP, FAKE_SNI) pairs for Iranian networks.
pub fn default_spoof_pairs() -> Vec<SpoofCandidatePair> {
    vec![
        // Category 1: Cloudflare & Vercel
        SpoofCandidatePair::new(
            "Cloudflare",
            "104.19.229.21",
            443,
            "hcaptcha.com",
            "Cloudflare Whitelist Edge / hCaptcha",
        ),
        SpoofCandidatePair::new(
            "Cloudflare",
            "104.19.230.21",
            443,
            "challenges.cloudflare.com",
            "Cloudflare Turnstile Challenges",
        ),
        SpoofCandidatePair::new(
            "Cloudflare",
            "104.16.80.73",
            443,
            "static.cloudflareinsights.com",
            "Cloudflare Insights Analytics",
        ),
        SpoofCandidatePair::new(
            "Vercel",
            "188.114.98.0",
            443,
            "auth.vercel.com",
            "Vercel Anycast Edge / Auth",
        ),
        SpoofCandidatePair::new(
            "Vercel",
            "104.18.4.130",
            443,
            "security.vercel.com",
            "Vercel Edge Security",
        ),
        SpoofCandidatePair::new(
            "Cloudflare",
            "162.159.192.1",
            443,
            "time.cloudflare.com",
            "Cloudflare Time / CDNJS",
        ),
        SpoofCandidatePair::new(
            "Cloudflare",
            "172.67.75.1",
            443,
            "speed.cloudflare.com",
            "Cloudflare Speed Test Edge",
        ),
        // Category 2: Fastly CDN
        SpoofCandidatePair::new(
            "Fastly",
            "151.101.1.140",
            443,
            "pypi.org",
            "Fastly CDN / Python Repo",
        ),
        SpoofCandidatePair::new(
            "Fastly",
            "151.101.65.140",
            443,
            "github.global.ssl.fastly.net",
            "Fastly GitHub Global Edge",
        ),
        SpoofCandidatePair::new(
            "Fastly",
            "151.101.129.140",
            443,
            "launchpad.net",
            "Fastly Launchpad / Ubuntu Repo",
        ),
        // Category 3: Amazon CloudFront / AWS
        SpoofCandidatePair::new(
            "Amazon",
            "13.224.0.1",
            443,
            "aws.amazon.com",
            "Amazon AWS Main Portal",
        ),
        SpoofCandidatePair::new(
            "Amazon",
            "99.84.0.1",
            443,
            "d1.awsstatic.com",
            "Amazon AWS Static Assets",
        ),
        SpoofCandidatePair::new(
            "Amazon",
            "54.230.0.1",
            443,
            "cloudfront.net",
            "Amazon CloudFront Global",
        ),
        // Category 4: Microsoft & Azure
        SpoofCandidatePair::new(
            "Microsoft",
            "204.79.197.200",
            443,
            "www.bing.com",
            "Microsoft Bing Front",
        ),
        SpoofCandidatePair::new(
            "Microsoft",
            "13.107.21.200",
            443,
            "www.microsoft.com",
            "Microsoft Portal Edge",
        ),
        SpoofCandidatePair::new(
            "Microsoft",
            "13.107.21.200",
            443,
            "login.live.com",
            "Microsoft Live Login Edge",
        ),
    ]
}

/// Automatically selects the best (lowest latency) relay destination and fake SNI.
///
/// Memoized: `RelayId::desired` runs on every ~1 s watchdog tick while
/// `relay_connect_host = "auto"`, so the full multi-candidate TLS probe
/// wave must never re-run that often. A successful sweep is cached for
/// 10 minutes; a failed sweep (no working candidate, e.g. offline) is
/// retried at most once per 30 s so a cold-start outage cannot wedge the
/// "auto" choice for the full success TTL.
pub fn auto_select_best_relay_target(timeout: Duration) -> Option<(String, String)> {
    const SUCCESS_TTL: Duration = Duration::from_secs(600);
    const FAILURE_TTL: Duration = Duration::from_secs(30);

    struct AutoSelectCache {
        at: Instant,
        value: Option<(String, String)>,
    }

    static CACHE: OnceLock<Mutex<AutoSelectCache>> = OnceLock::new();
    let expired = AutoSelectCache {
        at: Instant::now()
            .checked_sub(SUCCESS_TTL)
            .unwrap_or_else(Instant::now),
        value: None,
    };
    let cache = CACHE.get_or_init(|| Mutex::new(expired));
    let mut guard = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let ttl = if guard.value.is_some() {
        SUCCESS_TTL
    } else {
        FAILURE_TTL
    };
    if guard.at.elapsed() < ttl {
        return guard.value.clone();
    }
    let pairs = default_spoof_pairs();
    let fresh = best_spoof_pair(&pairs, timeout).map(|(pair, _)| (pair.connect_ip, pair.fake_sni));
    *guard = AutoSelectCache {
        at: Instant::now(),
        value: fresh.clone(),
    };
    fresh
}

/// Performs a real live HTTPS probe to `(ip, port)` with the specified SNI.
///
/// The old probe wrote a hand-rolled ClientHello and treated a bare
/// `ServerHello` record as `cert_valid`. That only proved that something on
/// the path emitted a TLS-looking byte sequence. This path uses ureq's
/// rustls verifier with the candidate SNI, while its resolver pins the TCP
/// connection to the caller-supplied IP. A successful response — including
/// an HTTP error status — therefore means the certificate chain and hostname
/// were accepted by rustls. It never follows redirects.
///
/// Returns `(latency, certificate_and_tls_ok, error)`.
pub fn probe_tls_handshake(
    ip: IpAddr,
    port: u16,
    sni: &str,
    timeout: Duration,
) -> (Option<Duration>, bool, Option<String>) {
    if crate::netguard::validate_relay_ip(ip).is_err() {
        return (None, false, Some("probe target IP is forbidden".into()));
    }
    let sni = sni.trim();
    if sni.is_empty()
        || sni.len() > 253
        || crate::netguard::is_forbidden_hostname(sni)
        || !sni
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        || sni.starts_with('.')
        || sni.ends_with('.')
        || sni.contains("..")
    {
        return (
            None,
            false,
            Some("probe SNI is not a valid hostname".into()),
        );
    }

    let start = Instant::now();
    let resolver = move |_netloc: &str| -> std::io::Result<Vec<SocketAddr>> {
        // ureq receives the URL hostname for TLS/SNI but this callback makes
        // the actual socket use the already-selected edge IP. No second DNS
        // lookup is possible in the probe.
        Ok(vec![SocketAddr::new(ip, port)])
    };
    let agent = ureq::AgentBuilder::new()
        .resolver(resolver)
        .https_only(true)
        .redirects(0)
        .build();
    let url = format!("https://{sni}:{port}/");
    match agent
        .get(&url)
        .timeout(timeout)
        .set("Connection", "close")
        .call()
    {
        Ok(_) => (Some(start.elapsed()), true, None),
        Err(ureq::Error::Status(code, _)) => (
            Some(start.elapsed()),
            true,
            Some(format!(
                "HTTPS server returned HTTP status {code} after TLS verification"
            )),
        ),
        Err(e) => (
            Some(start.elapsed()),
            false,
            Some(format!("HTTPS probe failed: {e}")),
        ),
    }
}

/// Measures TCP connection establishment latency (ping) to a target IP and port.
pub fn probe_tcp_latency(ip: IpAddr, port: u16, timeout: Duration) -> Option<Duration> {
    let addr = SocketAddr::new(ip, port);
    let start = Instant::now();
    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(_) => Some(start.elapsed()),
        Err(_) => None,
    }
}

/// Probes a single `SpoofCandidatePair` using real live TLS handshake and returns a `ProbeResult`.
pub fn probe_spoof_pair(pair: &SpoofCandidatePair, timeout: Duration) -> ProbeResult {
    let parsed_ip = pair.connect_ip.parse::<IpAddr>().ok();
    match parsed_ip {
        Some(ip) => {
            let (lat, tls_ok, err) = probe_tls_handshake(ip, pair.port, &pair.fake_sni, timeout);
            ProbeResult {
                candidate: pair.fake_sni.clone(),
                ip: Some(ip),
                // A TCP connection or a server-generated TLS alert is not a
                // successful candidate. Only the rustls-verified handshake
                // counts as success; HTTP status errors are still represented
                // as `tls_ok=true` by probe_tls_handshake.
                success: lat.is_some() && tls_ok,
                latency_ms: lat.map(|d| d.as_millis() as u64),
                tls_ok,
                cert_valid: tls_ok,
                error: err,
            }
        }
        None => ProbeResult {
            candidate: pair.fake_sni.clone(),
            ip: None,
            success: false,
            latency_ms: None,
            tls_ok: false,
            cert_valid: false,
            error: Some("invalid IP address".into()),
        },
    }
}

/// Maximum number of concurrent probes. 16 matches the default candidate
/// count, so the full default list is probed in a single parallel wave.
/// Probing never blocks on each other: total wall time ≈ slowest single
/// handshake instead of the sum of all handshakes.
pub const MAX_PARALLEL_PROBES: usize = 16;

/// Result of one parallel probe wave. One entry per candidate, in the order
/// the caller wants to display the rows (i.e. input order; the GUI sorts via
/// `rank_probe_pairs` when it needs a ranked view).
#[derive(Debug, Clone)]
pub struct DetailedProbeOutcome {
    pub candidate: SpoofCandidatePair,
    pub result: ProbeResult,
    /// True when the probe was cancelled before this candidate was reached.
    pub skipped: bool,
}

/// Runs `probe_spoof_pair` for every candidate on a bounded worker pool:
/// `std::thread::scope` with `min(total, MAX_PARALLEL_PROBES)` workers
/// pulling index numbers from one shared atomic queue.
///
/// The worker count *is* the concurrency bound, so the previous
/// "one wave per batch of `MAX_PARALLEL_PROBES`" loop is gone: a shared
/// queue gives the same ≤16 concurrent handshakes with less bookkeeping.
///
/// ## Why the queue lives outside the scope
///
/// `Scope::spawn` requires the closure — and everything it borrows — to
/// live for `'scope`, and scoped threads are only joined when the scope
/// ends, *not* when a loop iteration ends. Declaring the counter inside
/// a `for wave` loop therefore made it drop while workers could still
/// hold a reference to it (`E0597`). Hoisting it above the scope keeps
/// it alive until every worker has been joined.
///
/// - `cancel`: when set, workers stop picking up new candidates; probes
///   already in flight finish (each is individually time-bounded by
///   `timeout`), their results are dropped and the corresponding slots are
///   reported as `skipped`.
/// - `progress`: incremented after each candidate completes (0..=pairs.len()).
/// - Returns one `DetailedProbeOutcome` per input candidate in input order.
///
/// NOTE: this function panics if any probe thread panics (the pool joins all
/// workers). Callers in the UI thread must isolate it with
/// `std::panic::catch_unwind`.
pub fn probe_pairs_parallel(
    pairs: &[SpoofCandidatePair],
    timeout: Duration,
    cancel: Option<&AtomicBool>,
    progress: Option<&AtomicUsize>,
) -> Vec<DetailedProbeOutcome> {
    let total = pairs.len();
    if total == 0 {
        return Vec::new();
    }
    // Slots are allocated up-front (one per candidate) so a cancelled wave
    // leaves a deterministic shape: probed slots keep their result, never-
    // probed slots stay None and surface as `skipped: true`.
    let slots: Vec<Mutex<Option<ProbeResult>>> = (0..total).map(|_| Mutex::new(None)).collect();

    // `next` MUST outlive the whole scope: `Scope::spawn` requires the
    // closure (and everything it borrows) to live for `'scope`, and scoped
    // threads are only joined when the scope ends — not when a loop
    // iteration does. A single shared work queue with a fixed worker count
    // (≤ MAX_PARALLEL_PROBES) therefore doubles as the concurrency bound.
    let next = AtomicUsize::new(0);
    let workers = total.min(MAX_PARALLEL_PROBES);

    std::thread::scope(|scope| {
        for _ in 0..workers {
            let next = &next;
            let slots = &slots;
            let pairs = &pairs;
            scope.spawn(move || loop {
                if cancel.is_some_and(|c| c.load(AtomicOrdering::Relaxed)) {
                    break;
                }
                let idx = next.fetch_add(1, AtomicOrdering::Relaxed);
                if idx >= total {
                    break;
                }
                let pair = &pairs[idx];
                // Per-candidate cancel: a probe already in flight is not
                // abortable (each is bounded by `timeout`), but we refuse
                // to start a new one — the slot stays `None` and is
                // reported as `skipped: true`.
                if cancel.is_some_and(|c| c.load(AtomicOrdering::Relaxed)) {
                    break;
                }
                let result = probe_spoof_pair(pair, timeout);
                if let Ok(mut slot) = slots[idx].lock() {
                    *slot = Some(result);
                }
                if let Some(p) = progress {
                    p.fetch_add(1, AtomicOrdering::Relaxed);
                }
            });
        }
    });

    (0..total)
        .map(|i| {
            let r = slots[i].lock().ok().and_then(|mut g| g.take());
            match r {
                Some(result) => DetailedProbeOutcome {
                    candidate: pairs[i].clone(),
                    result,
                    skipped: false,
                },
                None => DetailedProbeOutcome {
                    candidate: pairs[i].clone(),
                    result: ProbeResult {
                        candidate: pairs[i].fake_sni.clone(),
                        ip: None,
                        success: false,
                        latency_ms: None,
                        tls_ok: false,
                        cert_valid: false,
                        error: Some("cancelled".into()),
                    },
                    skipped: true,
                },
            }
        })
        .collect()
}

/// Ranks detailed probe outcomes for display: verified TLS responses first
/// (lowest ping first), then timed-out/unverified candidates with a ping,
/// then the rest. Stable sort, so equal keys keep input order.
pub fn rank_probe_pairs(outcomes: Vec<DetailedProbeOutcome>) -> Vec<DetailedProbeOutcome> {
    let mut out = outcomes;
    out.sort_by(|a, b| match (a.result.tls_ok, b.result.tls_ok) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => match (a.result.latency_ms, b.result.latency_ms) {
            (Some(la), Some(lb)) => la.cmp(&lb),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        },
    });
    out
}

/// Probes all pairs in parallel (no cancellation, no progress counter) and
/// returns ranked detailed outcomes.
pub fn probe_and_rank_detailed(
    pairs: &[SpoofCandidatePair],
    timeout: Duration,
) -> Vec<(SpoofCandidatePair, ProbeResult)> {
    let outcomes = probe_pairs_parallel(pairs, timeout, None, None);
    rank_probe_pairs(outcomes)
        .into_iter()
        .map(|o| (o.candidate, o.result))
        .collect()
}

/// Probes all pairs in parallel with live cancellation + progress tracking.
/// Used by the GUI background-scan thread.
pub fn probe_and_rank_detailed_cancellable(
    pairs: &[SpoofCandidatePair],
    timeout: Duration,
    cancel: &AtomicBool,
    progress: &AtomicUsize,
) -> Vec<(SpoofCandidatePair, ProbeResult)> {
    let outcomes = probe_pairs_parallel(pairs, timeout, Some(cancel), Some(progress));
    rank_probe_pairs(outcomes)
        .into_iter()
        .map(|o| (o.candidate, o.result))
        .collect()
}

/// Probes a slice of `SpoofCandidatePair`s with live TLS handshakes and returns them sorted by priority:
/// verified TLS responses with lowest ping first, then timeouts.
///
/// Implemented on top of `probe_and_rank_detailed`: all candidates are probed
/// **in parallel** (≤ `MAX_PARALLEL_PROBES` concurrent handshakes), so the
/// full 16-candidate default list takes ~1× the slowest handshake instead of
/// the sum of all of them. Signature unchanged — webui/main callers keep
/// working and simply become faster.
pub fn probe_and_rank_spoof_pairs(
    pairs: &[SpoofCandidatePair],
    timeout: Duration,
) -> Vec<(SpoofCandidatePair, Option<u64>)> {
    probe_and_rank_detailed(pairs, timeout)
        .into_iter()
        .map(|(p, r)| (p, r.latency_ms))
        .collect()
}

/// Finds the candidate pair with the lowest measured latency (ping).
pub fn best_spoof_pair(
    pairs: &[SpoofCandidatePair],
    timeout: Duration,
) -> Option<(SpoofCandidatePair, u64)> {
    probe_and_rank_spoof_pairs(pairs, timeout)
        .into_iter()
        .find_map(|(pair, lat)| lat.map(|ms| (pair, ms)))
}

/// Helper function to pick the candidate with the lowest latency from a given list of SNI domain names.
pub fn select_lowest_latency_sni(
    candidates: &[String],
    port: u16,
    timeout: Duration,
) -> Option<(String, u64)> {
    let mut best: Option<(String, u64)> = None;

    for sni in candidates {
        let host_port = format!("{}:{}", sni, port);
        if let Ok(addrs) = host_port.to_socket_addrs() {
            for addr in addrs {
                if let Some(dur) = probe_tcp_latency(addr.ip(), addr.port(), timeout) {
                    let lat = dur.as_millis() as u64;
                    match &best {
                        Some((_, min_lat)) if lat < *min_lat => {
                            best = Some((sni.clone(), lat));
                        }
                        None => {
                            best = Some((sni.clone(), lat));
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    best
}

/// A pool of candidate SNI domains for rotation.
#[derive(Debug, Clone)]
pub struct SniPool {
    entries: Vec<SniEntry>,
    index: usize,
}

#[derive(Debug, Clone)]
pub struct SniEntry {
    pub sni: String,
    pub score: f64,
    pub last_used: Instant,
}

impl SniPool {
    pub fn new(candidates: Vec<String>) -> Self {
        let entries = candidates
            .into_iter()
            .map(|sni| SniEntry {
                sni,
                score: 0.0,
                last_used: Instant::now(),
            })
            .collect();
        Self { entries, index: 0 }
    }

    /// Round-robin selection.
    pub fn next_round_robin(&mut self) -> Option<&str> {
        if self.entries.is_empty() {
            return None;
        }
        let entry = &self.entries[self.index % self.entries.len()];
        self.index += 1;
        Some(&entry.sni)
    }

    /// Weighted-random selection based on scores.
    pub fn next_weighted_random(&self) -> Option<&str> {
        if self.entries.is_empty() {
            return None;
        }
        let total: f64 = self.entries.iter().map(|e| e.score.max(0.1)).sum();
        let mut r = rand::random::<f64>() * total;
        for entry in &self.entries {
            r -= entry.score.max(0.1);
            if r <= 0.0 {
                return Some(&entry.sni);
            }
        }
        // Fallback to last entry if floating-point rounding prevented selection.
        // Safe because empty case already returned None above.
        self.entries.last().map(|e| e.sni.as_str())
    }

    /// Least-recently-used selection.
    pub fn next_lru(&mut self) -> Option<&str> {
        if self.entries.is_empty() {
            return None;
        }
        let oldest = self
            .entries
            .iter()
            .enumerate()
            .min_by_key(|(_, e)| e.last_used)
            .map(|(i, _)| i)
            .unwrap_or(0);
        self.entries[oldest].last_used = Instant::now();
        self.index = oldest;
        Some(&self.entries[oldest].sni)
    }

    pub fn update_score(&mut self, sni: &str, score: f64) {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.sni == sni) {
            entry.score = score;
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> &[SniEntry] {
        &self.entries
    }
}

/// Rank a list of probe results by latency and success rate.
pub fn rank_probes(results: &[ProbeResult]) -> Vec<RankedCandidate> {
    let mut by_candidate: HashMap<String, Vec<&ProbeResult>> = HashMap::new();
    for r in results {
        by_candidate.entry(r.candidate.clone()).or_default().push(r);
    }

    let mut ranked: Vec<RankedCandidate> = by_candidate
        .into_iter()
        .map(|(candidate, probes)| {
            let total = probes.len() as u32;
            let successes = probes.iter().filter(|p| p.success).count() as u32;
            let tls_ok = probes.iter().filter(|p| p.tls_ok).count() as u32;
            let latencies: Vec<u64> = probes.iter().filter_map(|p| p.latency_ms).collect();
            let avg_latency = if latencies.is_empty() {
                f64::MAX
            } else {
                latencies.iter().sum::<u64>() as f64 / latencies.len() as f64
            };
            let success_rate = if total == 0 {
                0.0
            } else {
                successes as f64 / total as f64
            };
            // Score: high success rate + low latency = high score.
            // Normalize latency to 0..1 range (lower is better).
            let lat_score = if avg_latency == f64::MAX {
                0.0
            } else {
                1.0 / (1.0 + avg_latency / 1000.0)
            };
            let score =
                (success_rate * 0.6 + lat_score * 0.3 + if tls_ok > 0 { 0.1 } else { 0.0 }) * 100.0;
            RankedCandidate {
                candidate,
                score,
                avg_latency_ms: avg_latency,
                success_rate,
                probes: total,
                tls_successes: tls_ok,
            }
        })
        .collect();

    ranked.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    ranked
}

/// Well-known CDN edge IPs for common providers.
pub fn known_cdn_edges(provider: &str) -> Vec<IpAddr> {
    use std::net::{IpAddr, Ipv4Addr};
    match provider.to_lowercase().as_str() {
        "cloudflare" => vec![
            IpAddr::V4(Ipv4Addr::new(104, 16, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(104, 16, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
        ],
        "fastly" => vec![
            IpAddr::V4(Ipv4Addr::new(151, 101, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(151, 101, 65, 1)),
        ],
        "akamai" => vec![
            IpAddr::V4(Ipv4Addr::new(23, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(23, 32, 0, 1)),
        ],
        _ => vec![],
    }
}

/// Common SNI candidates for Iranian ISPs (based on community knowledge).
pub fn default_sni_candidates() -> Vec<String> {
    vec![
        "www.microsoft.com".into(),
        "www.apple.com".into(),
        "speedtest.net".into(),
        "www.cloudflare.com".into(),
        "cdn.discordapp.com".into(),
        "www.vercel.com".into(),
        "security.cloudflare-dns.com".into(),
        "learn.microsoft.com".into(),
        "azure.microsoft.com".into(),
        "developer.android.com".into(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_spoof_pairs_has_verified_entries() {
        let pairs = default_spoof_pairs();
        assert!(pairs.len() >= 15);
        assert!(pairs.iter().any(|p| p.fake_sni == "hcaptcha.com"));
        assert!(pairs.iter().any(|p| p.fake_sni == "auth.vercel.com"));
        assert!(pairs
            .iter()
            .any(|p| p.fake_sni == "static.cloudflareinsights.com"));
        assert!(pairs.iter().any(|p| p.fake_sni == "pypi.org"));
        assert!(pairs.iter().any(|p| p.fake_sni == "aws.amazon.com"));
        assert!(pairs.iter().any(|p| p.fake_sni == "www.bing.com"));
        assert!(pairs.iter().any(|p| p.fake_sni == "login.live.com"));
    }

    #[test]
    fn auto_select_best_relay_target_runs() {
        let _ = auto_select_best_relay_target(Duration::from_millis(10));
    }

    #[test]
    fn auto_select_best_relay_target_is_memoized() {
        // Second call inside the TTL window must return the memoized value
        // instead of re-running the whole probe wave (the watchdog tick
        // calls this every second when relay_connect_host = "auto").
        let a = auto_select_best_relay_target(Duration::from_millis(10));
        let start = Instant::now();
        let b = auto_select_best_relay_target(Duration::from_millis(10));
        assert_eq!(a, b);
        assert!(start.elapsed() < Duration::from_millis(5));
    }

    #[test]
    fn probe_tls_handshake_handles_invalid_target() {
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let (lat, tls_ok, err) =
            probe_tls_handshake(ip, 443, "example.com", Duration::from_millis(20));
        assert!(!tls_ok);
        assert!(lat.is_none());
        assert!(err.is_some());

        let tcp_lat = probe_tcp_latency(ip, 443, Duration::from_millis(20));
        assert!(tcp_lat.is_none());
    }

    #[test]
    fn best_spoof_pair_and_select_lowest_latency_sni() {
        let pairs = vec![SpoofCandidatePair::new(
            "test",
            "invalid_ip",
            443,
            "test.com",
            "desc",
        )];
        let best = best_spoof_pair(&pairs, Duration::from_millis(10));
        assert!(best.is_none());

        let snis = vec!["invalid-domain-12345.local".into()];
        let best_sni = select_lowest_latency_sni(&snis, 443, Duration::from_millis(10));
        assert!(best_sni.is_none());
    }

    #[test]
    fn probe_spoof_pair_handles_invalid_ip() {
        let pair = SpoofCandidatePair::new("test", "invalid_ip", 443, "test.com", "desc");
        let res = probe_spoof_pair(&pair, Duration::from_millis(50));
        assert!(!res.success);
        assert_eq!(res.error, Some("invalid IP address".into()));
    }

    #[test]
    fn probe_and_rank_spoof_pairs_sorts_correctly() {
        let pairs = vec![
            SpoofCandidatePair::new("p1", "127.0.0.1", 443, "sni1.com", "d1"),
            SpoofCandidatePair::new("p2", "invalid_ip", 443, "sni2.com", "d2"),
        ];
        let ranked = probe_and_rank_spoof_pairs(&pairs, Duration::from_millis(50));
        assert_eq!(ranked.len(), 2);
    }

    // ---- parallel probe engine (offline: loopback/invalid targets only) ----

    fn pr(sni: &str, tls_ok: bool, lat: Option<u64>, err: Option<&str>) -> ProbeResult {
        ProbeResult {
            candidate: sni.into(),
            ip: None,
            success: tls_ok,
            latency_ms: lat,
            tls_ok,
            cert_valid: tls_ok,
            error: err.map(str::to_string),
        }
    }

    fn outcome(provider: &str, r: ProbeResult, skipped: bool) -> DetailedProbeOutcome {
        DetailedProbeOutcome {
            candidate: SpoofCandidatePair::new(
                provider,
                "127.0.0.1",
                443,
                r.candidate.clone(),
                "t",
            ),
            result: r,
            skipped,
        }
    }

    #[test]
    fn probe_pairs_parallel_returns_all_in_input_order() {
        // 20 candidates (> MAX_PARALLEL_PROBES) exercises the multi-wave loop.
        // 127.0.0.1:443 / invalid IPs never reach the network; each probe
        // fails fast with a bounded timeout.
        let pairs: Vec<SpoofCandidatePair> = (0..20)
            .map(|i| {
                SpoofCandidatePair::new(
                    format!("prov-{i:02}"),
                    if i % 2 == 0 {
                        "127.0.0.1"
                    } else {
                        "invalid_ip"
                    },
                    443,
                    format!("sni{i}.test"),
                    "d",
                )
            })
            .collect();
        let progress = AtomicUsize::new(0);
        let out = probe_pairs_parallel(&pairs, Duration::from_millis(50), None, Some(&progress));
        assert_eq!(out.len(), 20);
        for (i, o) in out.iter().enumerate() {
            assert_eq!(o.candidate.provider, format!("prov-{i:02}"));
            assert!(!o.skipped);
            assert!(!o.result.tls_ok);
            assert!(o.result.error.is_some());
        }
        assert_eq!(progress.load(AtomicOrdering::Relaxed), 20);
    }

    #[test]
    fn probe_pairs_parallel_empty_input() {
        let out = probe_pairs_parallel(&[], Duration::from_millis(50), None, None);
        assert!(out.is_empty());
    }

    #[test]
    fn probe_pairs_parallel_pre_cancelled_skips_everything() {
        let pairs: Vec<SpoofCandidatePair> = (0..5)
            .map(|i| {
                SpoofCandidatePair::new(
                    format!("p{i}"),
                    "127.0.0.1",
                    443,
                    format!("s{i}.test"),
                    "d",
                )
            })
            .collect();
        let cancel = AtomicBool::new(true);
        let progress = AtomicUsize::new(0);
        let out = probe_pairs_parallel(
            &pairs,
            Duration::from_millis(50),
            Some(&cancel),
            Some(&progress),
        );
        assert_eq!(out.len(), 5);
        assert!(out.iter().all(|o| o.skipped));
        assert_eq!(progress.load(AtomicOrdering::Relaxed), 0);
    }

    #[test]
    fn rank_probe_pairs_orders_tls_first_then_latency() {
        let out = vec![
            outcome("a", pr("slow-tls", true, Some(900), None), false),
            outcome("b", pr("fast-tls", true, Some(40), None), false),
            outcome(
                "c",
                pr("fast-notls", false, Some(30), Some("timeout")),
                false,
            ),
            outcome("d", pr("no-lat", false, None, Some("err")), false),
        ];
        let ranked = rank_probe_pairs(out);
        let names: Vec<String> = ranked
            .iter()
            .map(|o| o.candidate.provider.clone())
            .collect();
        assert_eq!(names, vec!["b", "a", "c", "d"]);
    }

    #[test]
    fn rank_probe_pairs_is_stable_for_equal_keys() {
        let out = vec![
            outcome("x", pr("n1", false, Some(50), None), false),
            outcome("y", pr("n2", false, Some(50), None), false),
            outcome("z", pr("n3", false, Some(50), None), false),
        ];
        let ranked = rank_probe_pairs(out);
        let names: Vec<String> = ranked
            .iter()
            .map(|o| o.candidate.provider.clone())
            .collect();
        assert_eq!(names, vec!["x", "y", "z"]);
    }

    #[test]
    fn probe_and_rank_detailed_with_offline_pairs() {
        let pairs = vec![
            SpoofCandidatePair::new("p1", "127.0.0.1", 443, "sni1.com", "d1"),
            SpoofCandidatePair::new("p2", "invalid_ip", 443, "sni2.com", "d2"),
        ];
        let ranked = probe_and_rank_detailed(&pairs, Duration::from_millis(50));
        assert_eq!(ranked.len(), 2);
        assert!(ranked.iter().all(|(_, r)| !r.tls_ok));

        let cancel = AtomicBool::new(false);
        let progress = AtomicUsize::new(0);
        let ranked2 = probe_and_rank_detailed_cancellable(
            &pairs,
            Duration::from_millis(50),
            &cancel,
            &progress,
        );
        assert_eq!(ranked2.len(), 2);
        assert_eq!(progress.load(AtomicOrdering::Relaxed), 2);
    }

    #[test]
    fn sni_pool_round_robin_cycles() {
        let mut pool = SniPool::new(vec!["a.com".into(), "b.com".into(), "c.com".into()]);
        assert_eq!(pool.next_round_robin(), Some("a.com"));
        assert_eq!(pool.next_round_robin(), Some("b.com"));
        assert_eq!(pool.next_round_robin(), Some("c.com"));
        assert_eq!(pool.next_round_robin(), Some("a.com")); // wraps
    }

    #[test]
    fn sni_pool_empty_returns_none() {
        let mut pool = SniPool::new(vec![]);
        assert_eq!(pool.next_round_robin(), None);
        assert_eq!(pool.next_weighted_random(), None);
        assert_eq!(pool.next_lru(), None);
    }

    #[test]
    fn sni_pool_lru_picks_oldest() {
        let mut pool = SniPool::new(vec!["a.com".into(), "b.com".into()]);
        // Use a.com first
        let _ = pool.next_lru(); // a.com (both same age, first found)
                                 // Now advance time a bit
        std::thread::sleep(Duration::from_millis(2));
        let _ = pool.next_lru(); // b.com (a.com was used more recently)
    }

    #[test]
    fn sni_pool_update_score_works() {
        let mut pool = SniPool::new(vec!["a.com".into(), "b.com".into()]);
        pool.update_score("a.com", 95.0);
        assert_eq!(pool.entries()[0].score, 95.0);
    }

    #[test]
    fn rank_probes_sorts_by_score_desc() {
        let results = vec![
            ProbeResult {
                candidate: "slow.com".into(),
                ip: None,
                success: true,
                latency_ms: Some(500),
                tls_ok: true,
                cert_valid: true,
                error: None,
            },
            ProbeResult {
                candidate: "fast.com".into(),
                ip: None,
                success: true,
                latency_ms: Some(50),
                tls_ok: true,
                cert_valid: true,
                error: None,
            },
            ProbeResult {
                candidate: "fail.com".into(),
                ip: None,
                success: false,
                latency_ms: None,
                tls_ok: false,
                cert_valid: false,
                error: Some("timeout".into()),
            },
        ];
        let ranked = rank_probes(&results);
        assert_eq!(ranked.len(), 3);
        assert_eq!(ranked[0].candidate, "fast.com");
        assert_eq!(ranked[2].candidate, "fail.com");
    }

    #[test]
    fn known_cdn_edges_returns_ips() {
        let cf = known_cdn_edges("cloudflare");
        assert!(!cf.is_empty());
        let empty = known_cdn_edges("unknown");
        assert!(empty.is_empty());
    }

    #[test]
    fn default_sni_candidates_not_empty() {
        let c = default_sni_candidates();
        assert!(c.len() >= 5);
        assert!(c.iter().all(|s| !s.is_empty()));
    }
}
