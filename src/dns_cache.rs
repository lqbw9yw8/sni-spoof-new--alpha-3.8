//! dns_cache — TTL cache with best-effort disk persistence for DoH
//! answers. [UNTESTED] Pure logic, no async; current Rust tests were not executed.
//!
//! Why this exists: on a network with frequent outages and heavy packet
//! loss, a single failed DoH query must not cost the operator their
//! connection. Two properties matter:
//!
//! * **Offline survival** — a fresh but expired entry is still returned
//!   (as a *stale* hit) when the network is down, so the relay can start
//!   against the last known-good address instead of failing closed.
//! * **Resume across restarts** — the cache is mirrored to a small file
//!   next to the executable, so a process that restarts *during* an
//!   outage can still resolve its destination.
//!
//! This is safe here because the cached name is the operator's own,
//! explicitly configured relay destination — not an arbitrary lookup. A
//! stale answer for your own server beats no answer. Every value is
//! re-validated through [`crate::netguard::validate_relay_ip`] on the way
//! out, so a poisoned cache file cannot point the relay at a forbidden
//! destination.
//!
//! All disk I/O is best-effort: a missing, corrupt, or unwritable cache
//! file degrades to "empty cache", never to an error.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// How long a cached answer is considered fresh.
pub const DEFAULT_TTL: Duration = Duration::from_secs(300);

/// How long an *expired* answer may still be served when the network is
/// down. Bounded so a genuinely dead address does not outlive its usefulness.
pub const MAX_STALE: Duration = Duration::from_secs(6 * 60 * 60);

/// Hard cap on the cache file, so a hostile or runaway file cannot be
/// loaded into memory wholesale.
pub const MAX_CACHE_BYTES: u64 = 64 * 1024;

/// Hard cap on the number of entries held in memory.
pub const MAX_ENTRIES: usize = 256;

/// Name of the cache file, written next to the executable (never cwd —
/// the same reasoning as the singleton lock and the driver search).
pub const CACHE_FILE_NAME: &str = "dpi_guard.dns_cache";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub ips: Vec<IpAddr>,
    pub at: Instant,
    /// Freshness window for THIS entry, taken from the authoritative DNS
    /// TTL of the answer it came from (clamped at insert time). Entries
    /// persisted by older builds without a TTL column fall back to
    /// [`DEFAULT_TTL`].
    pub ttl: Duration,
}

impl Entry {
    pub fn age(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.at)
    }
    pub fn is_fresh(&self, now: Instant, ttl: Duration) -> bool {
        self.age(now) <= ttl
    }
    pub fn is_fresh_for_self(&self, now: Instant) -> bool {
        self.age(now) <= self.ttl
    }
    pub fn is_usable_stale(&self, now: Instant) -> bool {
        let age = self.age(now);
        age > self.ttl && age <= MAX_STALE
    }
}

// Freshness is deliberately per-entry (see [`Entry::ttl`]): each cached
// answer carries the authoritative TTL from its own DoH response. A
// cache-level TTL would either shorten long-TTL answers or over-serve
// short-TTL ones, so the struct holds no ttl field.
#[derive(Debug, Default)]
pub struct DnsCache {
    entries: HashMap<String, Entry>,
}

impl DnsCache {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Store a successful answer. Never grows past [`MAX_ENTRIES`]: the
    /// oldest entry is dropped instead, so the cache cannot be inflated by
    /// an unbounded stream of names. Uses [`DEFAULT_TTL`] — prefer
    /// [`Self::insert_with_ttl`] for answers whose authoritative TTL is
    /// known.
    pub fn insert(&mut self, host: &str, ips: Vec<IpAddr>) {
        self.insert_with_ttl(host, ips, DEFAULT_TTL);
    }

    /// Store a successful answer with an explicit freshness window (the
    /// authoritative TTL from the DoH response). The TTL is clamped into
    /// `[1 s, MAX_STALE]` so a hostile answer can neither evict itself
    /// instantly nor pin a dead address for days.
    pub fn insert_with_ttl(&mut self, host: &str, ips: Vec<IpAddr>, ttl: Duration) {
        if ips.is_empty() {
            return;
        }
        let key = normalize(host);
        if key.is_empty() {
            return;
        }
        let ttl = ttl.max(Duration::from_secs(1)).min(MAX_STALE);
        if self.entries.len() >= MAX_ENTRIES && !self.entries.contains_key(&key) {
            if let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.at)
                .map(|(k, _)| k.clone())
            {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(
            key,
            Entry {
                ips,
                at: Instant::now(),
                ttl,
            },
        );
    }

    /// Look up `host`. Returns `(ips, was_fresh)`.
    ///
    /// A fresh entry is returned with `was_fresh = true`. An expired but
    /// not-too-old entry is returned with `was_fresh = false` so the
    /// caller can decide whether to trust it (only when a live query
    /// failed). Anything older, or whose addresses are now forbidden, is
    /// dropped and reported as a miss.
    pub fn lookup(&mut self, host: &str, now: Instant) -> Option<(Vec<IpAddr>, bool)> {
        let key = normalize(host);
        let entry = self.entries.get(&key)?;
        // Freshness is per-entry: the authoritative TTL the answer carried.
        let fresh = entry.is_fresh_for_self(now);
        if !fresh && !entry.is_usable_stale(now) {
            self.entries.remove(&key);
            return None;
        }
        let ips: Vec<IpAddr> = entry
            .ips
            .iter()
            .copied()
            .filter(|ip| crate::netguard::validate_relay_ip(*ip).is_ok())
            .collect();
        if ips.is_empty() {
            self.entries.remove(&key);
            return None;
        }
        Some((ips, fresh))
    }

    /// Drop everything (used when the operator changes `doh_server`).
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    // ---- persistence -------------------------------------------------

    /// Serialize to the on-disk line format. Timestamps are absolute
    /// (seconds since the epoch) because `Instant` is meaningless across
    /// process restarts.
    pub fn to_text(&self, now: Instant) -> String {
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut out = String::new();
        let mut keys: Vec<&String> = self.entries.keys().collect();
        keys.sort();
        for k in keys {
            let e = &self.entries[k];
            let age = e.age(now).as_secs();
            let stored = wall.saturating_sub(age);
            let ips: Vec<String> = e.ips.iter().map(|ip| ip.to_string()).collect();
            // Column 4: per-entry TTL in seconds. Older builds wrote 3
            // columns; `from_text` still accepts those.
            out.push_str(&format!(
                "{}\t{}\t{}\t{}\n",
                k,
                stored,
                ips.join(","),
                e.ttl.as_secs()
            ));
        }
        out
    }

    /// Parse the on-disk format. Malformed lines are skipped, never fatal.
    /// Entries older than [`MAX_STALE`] are dropped on load.
    pub fn from_text(text: &str) -> Self {
        let mut cache = Self::new();
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        for line in text.lines() {
            let parts: Vec<&str> = line.split('\t').collect();
            // Column 4 (per-entry TTL in seconds) is written by current
            // builds; older 3-column files fall back to DEFAULT_TTL.
            if parts.len() != 3 && parts.len() != 4 {
                continue;
            }
            let host = parts[0].trim();
            let Ok(stored) = parts[1].trim().parse::<u64>() else {
                continue;
            };
            if host.is_empty() || stored > wall || wall - stored > MAX_STALE.as_secs() {
                continue;
            }
            let ttl = match parts.get(3) {
                Some(v) => v
                    .trim()
                    .parse::<u64>()
                    .map(|s| {
                        Duration::from_secs(s)
                            .max(Duration::from_secs(1))
                            .min(MAX_STALE)
                    })
                    .unwrap_or(DEFAULT_TTL),
                None => DEFAULT_TTL,
            };
            let ips: Vec<IpAddr> = parts[2]
                .split(',')
                .filter_map(|s| s.trim().parse::<IpAddr>().ok())
                .filter(|ip| crate::netguard::validate_relay_ip(*ip).is_ok())
                .collect();
            if ips.is_empty() {
                continue;
            }
            let key = normalize(host);
            if key.is_empty() {
                continue;
            }
            let entry = Entry {
                ips,
                at: Instant::now() - Duration::from_secs(wall - stored),
                ttl,
            };
            // Apply the same hard entry cap while loading as while inserting
            // live answers. Without this, a file below MAX_CACHE_BYTES could
            // still expand the in-memory HashMap beyond MAX_ENTRIES.
            if cache.entries.len() >= MAX_ENTRIES && !cache.entries.contains_key(&key) {
                if let Some(oldest) = cache
                    .entries
                    .iter()
                    .min_by_key(|(_, e)| e.at)
                    .map(|(k, _)| k.clone())
                {
                    cache.entries.remove(&oldest);
                }
            }
            cache.entries.insert(key, entry);
        }
        cache
    }

    /// Best-effort load from `path`. Any failure yields an empty cache.
    pub fn load(path: &Path) -> Self {
        let Ok(meta) = std::fs::metadata(path) else {
            return Self::new();
        };
        if meta.len() > MAX_CACHE_BYTES {
            log::warn!(
                "dns cache {} is {} bytes, over the {MAX_CACHE_BYTES} cap; starting empty",
                path.display(),
                meta.len()
            );
            return Self::new();
        }
        match std::fs::read_to_string(path) {
            Ok(text) => {
                let c = Self::from_text(&text);
                if !c.is_empty() {
                    log::info!(
                        "dns cache loaded: {} entr(ies) from {}",
                        c.len(),
                        path.display()
                    );
                }
                c
            }
            Err(e) => {
                log::debug!("dns cache unreadable ({}); starting empty", e);
                Self::new()
            }
        }
    }

    /// Best-effort save. Returns false on any failure; the caller must not
    /// treat that as fatal.
    pub fn save(&self, path: &Path, now: Instant) -> bool {
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(dir);
            }
        }
        match std::fs::write(path, self.to_text(now)) {
            Ok(()) => true,
            Err(e) => {
                log::debug!("dns cache save failed ({}); continuing without it", e);
                false
            }
        }
    }
}

fn normalize(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Cache file location: next to the running executable, falling back to a
/// bare relative name only if the OS cannot report the exe path.
pub fn cache_path() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            return dir.join(CACHE_FILE_NAME);
        }
    }
    PathBuf::from(CACHE_FILE_NAME)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn insert_then_lookup_is_fresh() {
        let mut c = DnsCache::new();
        c.insert("Example.COM", vec![ip("1.2.3.4")]);
        let now = Instant::now();
        let (ips, fresh) = c.lookup("example.com", now).unwrap();
        assert_eq!(ips, vec![ip("1.2.3.4")]);
        assert!(fresh);
    }

    /// The authoritative TTL must drive freshness per entry: a 60 s answer
    /// goes stale after 60 s even though the cache-wide default is 300 s,
    /// and it stays stale-but-usable (not evicted) inside MAX_STALE.
    #[test]
    fn per_entry_ttl_overrides_default() {
        let mut c = DnsCache::new();
        c.insert_with_ttl("short.com", vec![ip("1.2.3.4")], Duration::from_secs(60));
        let now = Instant::now();
        let (_, fresh) = c.lookup("short.com", now).unwrap();
        assert!(fresh, "inside the 60 s TTL the entry is fresh");

        // Age by 61 s — past this entry's TTL, still far inside DEFAULT_TTL.
        let now2 = now + Duration::from_secs(61);
        let (_, fresh2) = c.lookup("short.com", now2).unwrap();
        assert!(
            !fresh2,
            "after the authoritative TTL the entry must be reported stale"
        );
        assert!(
            c.lookup("short.com", now2).is_some(),
            "stale is still served"
        );

        // The 4th cache-file column carries the TTL across restarts.
        let text = c.to_text(now2);
        let back = DnsCache::from_text(&text);
        let e = back.entries.get("short.com").unwrap();
        assert_eq!(e.ttl, Duration::from_secs(60));
    }

    #[test]
    fn lookup_is_case_and_trailing_dot_insensitive() {
        let mut c = DnsCache::new();
        c.insert("server.example.com", vec![ip("1.2.3.4")]);
        assert!(c.lookup("SERVER.Example.Com.", Instant::now()).is_some());
    }

    #[test]
    fn empty_answer_is_not_cached() {
        let mut c = DnsCache::new();
        c.insert("a.com", vec![]);
        assert!(c.is_empty());
    }

    #[test]
    fn expired_entry_is_served_as_stale_then_dropped() {
        let mut c = DnsCache::new();
        c.insert("a.com", vec![ip("1.2.3.4")]);
        // Age it past the TTL but inside MAX_STALE.
        let now = Instant::now();
        c.entries.get_mut("a.com").unwrap().at = now - (DEFAULT_TTL + Duration::from_secs(10));
        let (ips, fresh) = c.lookup("a.com", now).unwrap();
        assert_eq!(ips, vec![ip("1.2.3.4")]);
        assert!(
            !fresh,
            "an expired entry must be reported as stale, not fresh"
        );

        // Past MAX_STALE it is dropped entirely.
        let now2 = Instant::now();
        if let Some(old_instant) = now2.checked_sub(MAX_STALE + Duration::from_secs(1)) {
            c.entries.get_mut("a.com").unwrap().at = old_instant;
            assert!(c.lookup("a.com", now2).is_none());
        }
        assert!(c.is_empty(), "an unusable entry must be evicted, not kept");
    }

    #[test]
    fn forbidden_addresses_are_never_returned() {
        let mut c = DnsCache::new();
        c.insert("a.com", vec![ip("127.0.0.1"), ip("169.254.169.254")]);
        // Both are forbidden, so the whole entry is dropped on lookup.
        assert!(c.lookup("a.com", Instant::now()).is_none());

        c.insert("b.com", vec![ip("127.0.0.1"), ip("8.8.8.8")]);
        let (ips, _) = c.lookup("b.com", Instant::now()).unwrap();
        assert_eq!(
            ips,
            vec![ip("8.8.8.8")],
            "only the permitted address survives"
        );
    }

    #[test]
    fn cache_is_bounded() {
        let mut c = DnsCache::new();
        for i in 0..(MAX_ENTRIES + 50) {
            c.insert(&format!("host{i}.example.com"), vec![ip("1.2.3.4")]);
        }
        assert_eq!(c.len(), MAX_ENTRIES);
    }

    #[test]
    fn text_round_trip_preserves_entries() {
        let mut c = DnsCache::new();
        c.insert("a.example.com", vec![ip("1.2.3.4"), ip("5.6.7.8")]);
        c.insert("b.example.com", vec![ip("9.9.9.9")]);
        let text = c.to_text(Instant::now());
        let mut back = DnsCache::from_text(&text);
        assert_eq!(back.len(), 2);
        let (ips, _) = back.lookup("a.example.com", Instant::now()).unwrap();
        assert_eq!(ips, vec![ip("1.2.3.4"), ip("5.6.7.8")]);
    }

    #[test]
    fn loading_many_valid_lines_still_honors_entry_cap() {
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let text: String = (0..(MAX_ENTRIES + 50))
            .map(|i| format!("host{i}.example\t{wall}\t1.2.3.4\t300\n"))
            .collect();
        assert_eq!(DnsCache::from_text(&text).len(), MAX_ENTRIES);
    }

    #[test]
    fn malformed_cache_lines_are_skipped_not_fatal() {
        let text = "garbage line\n\
                    a.com\tnot-a-number\t1.2.3.4\n\
                    \t1700000000\t1.2.3.4\n\
                    b.com\t1700000000\t127.0.0.1\n\
                    good.com\t999999999999\t1.2.3.4\n";
        let c = DnsCache::from_text(text);
        // Only lines that are well formed, not forbidden and not too old
        // survive; none of these qualify, and parsing must not panic.
        assert_eq!(c.len(), 0);

        let with_wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let ok = DnsCache::from_text(&format!("ok.com\t{with_wall}\t1.2.3.4\n"));
        assert_eq!(ok.len(), 1);
    }

    #[test]
    fn save_and_load_round_trip_on_disk() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("dpi_guard_dns_cache_test_{}", std::process::id()));
        let mut c = DnsCache::new();
        c.insert("a.example.com", vec![ip("1.2.3.4")]);
        assert!(c.save(&path, Instant::now()));
        let mut back = DnsCache::load(&path);
        assert_eq!(back.len(), 1);
        let (ips, _) = back.lookup("a.example.com", Instant::now()).unwrap();
        assert_eq!(ips, vec![ip("1.2.3.4")]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_of_missing_or_oversize_file_yields_empty_cache() {
        let dir = std::env::temp_dir();
        let missing = dir.join(format!("dpi_guard_dns_cache_absent_{}", std::process::id()));
        assert!(DnsCache::load(&missing).is_empty());

        let big = dir.join(format!("dpi_guard_dns_cache_big_{}", std::process::id()));
        std::fs::write(&big, vec![b'a'; (MAX_CACHE_BYTES + 10) as usize]).unwrap();
        assert!(
            DnsCache::load(&big).is_empty(),
            "oversize cache must be refused"
        );
        let _ = std::fs::remove_file(&big);
    }

    #[test]
    fn cache_path_points_next_to_the_exe() {
        assert!(cache_path().ends_with(CACHE_FILE_NAME));
    }
}
