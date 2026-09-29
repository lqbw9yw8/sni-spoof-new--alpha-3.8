//! strategy — adaptive technique selection by historical success score.
//! [UNTESTED]; unit tests are declared but were not executed in this checkout. Pure in-memory logic, no OS dependency.

use dashmap::DashMap;
use rand::Rng;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

/// Hard cap so a long-lived process cannot grow the score table without
/// bound (every distinct SNI × technique is otherwise a permanent entry).
const MAX_STRATEGY_ENTRIES: usize = 4096;

/// Score for one (domain, technique) pair. Atomic so concurrent
/// connection handlers can update it without locking the whole map.
#[derive(Debug, Default)]
pub struct Score(AtomicI64);

impl Score {
    pub fn value(&self) -> i64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Per-domain, per-technique score table.
/// Key: (domain, technique_name).
#[derive(Clone)]
pub struct StrategyTable {
    scores: Arc<DashMap<(String, String), Arc<ScoreRow>>>,
}

/// One table row: the score plus a lazily-materialized dashboard hash.
/// The hash ("<salted-domain>|<tech>") depends only on the immutable key
/// and the per-process salt, so it is computed at most once per row and
/// cloned on every dashboard poll instead of re-running SHA-256 for the
/// whole table (was O(rows) full hashes per poll).
#[derive(Debug, Default)]
pub struct ScoreRow {
    score: Score,
    hashed: std::sync::OnceLock<String>,
}

impl StrategyTable {
    pub fn new() -> Self {
        Self {
            scores: Arc::new(DashMap::new()),
        }
    }

    /// True when no feedback has ever been recorded. Read paths use this
    /// to skip per-ClientHello lookups whose result is provably the same
    /// as reading score 0 (an empty table makes every score read 0).
    pub fn is_empty(&self) -> bool {
        self.scores.is_empty()
    }

    fn entry(&self, domain: &str, technique: &str) -> Arc<ScoreRow> {
        let key = (domain.to_string(), technique.to_string());
        if let Some(existing) = self.scores.get(&key) {
            return existing.clone();
        }
        if self.scores.len() >= MAX_STRATEGY_ENTRIES {
            // Ephemeral: do not remember a new domain once the table is
            // full. Existing keys still update. Slight TOCTOU overshoot
            // under concurrency is acceptable.
            return Arc::new(ScoreRow::default());
        }
        self.scores
            .entry(key)
            .or_insert_with(|| Arc::new(ScoreRow::default()))
            .clone()
    }

    /// Read-only score lookup: O(1) dashmap `get`, no entry creation.
    /// Read paths (`select_best`, `select_rotating`, the pipeline's score
    /// comparisons) used to go through `entry`, which INSERTED a zero-score
    /// row per untried (domain, technique) — polluting the table toward
    /// `MAX_STRATEGY_ENTRIES` and paying a full O(table) scan per
    /// ClientHello at the `per_domain_scores` call sites. Unknown pairs
    /// read as 0, exactly like a freshly created row, so decisions are
    /// unchanged; the table now only grows when `update_score` actually
    /// records feedback.
    pub fn score_of(&self, domain: &str, technique: &str) -> i64 {
        self.scores
            .get(&(domain.to_string(), technique.to_string()))
            .map(|e| e.value().score.value())
            .unwrap_or(0)
    }

    /// 1. Pick the technique with the highest recorded score for this
    ///    domain out of `candidates`. Ties broken by input order (first
    ///    wins) so behavior is deterministic and testable. Untried
    ///    techniques start at score 0, same as a technique that broke even.
    pub fn select_best(&self, domain: &str, candidates: &[&str]) -> Option<String> {
        // NOTE: deliberately not `Iterator::max_by_key` — on a tie, that
        // returns the LAST matching element, but ties should keep
        // deterministic first-input-wins semantics.
        let mut best: Option<(&str, i64)> = None;
        for &name in candidates {
            let score = self.score_of(domain, name);
            match best {
                Some((_, best_score)) if score <= best_score => {}
                _ => best = Some((name, score)),
            }
        }
        best.map(|(name, _)| name.to_string())
    }

    /// 2. Atomically update a technique's score: +1 on success, -2 on
    ///    failure/RST (asymmetric penalty so a technique that gets flagged
    ///    by DPI drops out of rotation faster than one that merely hasn't
    ///    been tried much).
    pub fn update_score(&self, domain: &str, technique: &str, success: bool) -> i64 {
        let delta = if success { 1 } else { -2 };
        self.entry(domain, technique)
            .score
            .0
            .fetch_add(delta, Ordering::Relaxed)
            + delta
    }

    /// Hashed view of all scores (`domain|technique`, domains salted-hashed
    /// for the dashboard). Static so the watchdog can build it from an
    /// Arc-cloned table without holding the pipeline lock.
    pub fn scores_hashed(&self) -> Vec<(String, i64)> {
        self.scores
            .iter()
            .map(|entry| {
                let key = entry.key();
                let hashed = entry.value().hashed.get_or_init(|| {
                    format!(
                        "{}|{}",
                        crate::stealth::hash_sensitive(&key.0, crate::stealth::run_salt()),
                        key.1
                    )
                });
                (hashed.clone(), entry.value().score.value())
            })
            .collect()
    }

    /// 4. Per-domain tracking: list every technique tried against a given
    ///    domain and its current score.
    pub fn per_domain_scores(&self, domain: &str) -> Vec<(String, i64)> {
        self.scores
            .iter()
            .filter(|entry| entry.key().0 == domain)
            .map(|entry| (entry.key().1.clone(), entry.value().score.value()))
            .collect()
    }

    /// Per-connection rotation (2026 roadmap #4): weighted-random pick among
    /// the candidates that already scored positively for this domain, so
    /// consecutive connections don't all send the same shape — a fixed
    /// shape is exactly what lets a DPI learn it. Weights are the scores
    /// themselves, so a technique that wins twice as often is picked twice
    /// as often. Returns `None` when nothing has won yet; the caller falls
    /// back to deterministic selection (new domains behave as before).
    pub fn select_rotating(&self, domain: &str, candidates: &[&str]) -> Option<String> {
        let mut positives: Vec<(&str, i64)> = Vec::with_capacity(candidates.len());
        let mut total: i64 = 0;
        for &name in candidates {
            let score = self.score_of(domain, name);
            if score > 0 {
                positives.push((name, score));
                total = total.saturating_add(score);
            }
        }
        if positives.is_empty() || total <= 0 {
            return None;
        }
        let mut r = rand::thread_rng().gen_range(0..total);
        for (name, score) in &positives {
            r -= score;
            if r < 0 {
                return Some((*name).to_string());
            }
        }
        // Unreachable in practice (the weights sum to `total`); keep the
        // last candidate as a deterministic fallback.
        positives.last().map(|(name, _)| (*name).to_string())
    }

    /// Recency weighting for the adaptive feedback loop (2026 roadmap #6):
    /// pull every score halfway toward zero, so history fades and the table
    /// keeps tracking the DPI's *current* behaviour instead of last month's.
    pub fn decay_all(&self) {
        for entry in self.scores.iter() {
            let v = entry.value().score.value();
            if v != 0 {
                entry.value().score.0.store(v / 2, Ordering::Relaxed);
            }
        }
    }

    /// Flattened `domain|technique -> score` view, used by the dashboard.
    pub fn all_scores(&self) -> Vec<(String, i64)> {
        self.scores
            .iter()
            .map(|entry| {
                (
                    format!("{}|{}", entry.key().0, entry.key().1),
                    entry.value().score.value(),
                )
            })
            .collect()
    }
}

impl Default for StrategyTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Desynchronization / fragmentation mode selected for a flow. The pipeline
/// maps the operator config + learned strategy to one of these; the names
/// mirror the techniques discussed in the censorship-circumvention
/// literature (zapret, GoodbyeDPI, patterniha).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DesyncMode {
    /// Split the ClientHello into multiple TLS records (`fragment_as_tls_records`).
    TlsRecordFrag,
    /// Split immediately before the SNI (`tls_record_split_before_sni`).
    FragBySni,
    /// Reorder segments out of sequence (disorder).
    Disorder,
    /// Send a TTL-limited wrong-checksum decoy.
    Decoy,
    /// No desync — pass through.
    None,
}

impl DesyncMode {
    pub fn as_str(self) -> &'static str {
        match self {
            DesyncMode::TlsRecordFrag => "tls-record",
            DesyncMode::FragBySni => "frag-by-sni",
            DesyncMode::Disorder => "disorder",
            DesyncMode::Decoy => "decoy",
            DesyncMode::None => "none",
        }
    }
}

impl std::str::FromStr for DesyncMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.trim().to_ascii_lowercase().as_str() {
            "tls" | "tls-record" | "tls_record" | "tlsrecordfrag" => DesyncMode::TlsRecordFrag,
            "sni" | "frag-by-sni" | "frag_by_sni" | "fragbysni" => DesyncMode::FragBySni,
            "disorder" => DesyncMode::Disorder,
            "decoy" => DesyncMode::Decoy,
            "none" | "off" | "" => DesyncMode::None,
            other => return Err(format!("unknown desync mode: {other}")),
        })
    }
}

/// Result of one A/B probe against a domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockType {
    /// Handshake to the IP fails/resets even with a plain SNI-less probe
    /// (or a probe to an unrelated SNI on the same IP) -> IP is blocked.
    IpBlock,
    /// Plain IP-level probe succeeds but a probe carrying the real SNI
    /// fails -> filtering keys on SNI content, not the destination IP.
    SniBlock,
    /// Both probes succeeded.
    NotBlocked,
    /// Both probes failed the same way; cannot distinguish IP- from
    /// SNI-based blocking from this evidence alone.
    Inconclusive,
}

/// 3. Decide block type from two parallel probe outcomes: an SNI-less
///    (or decoy-SNI) connection attempt vs. one carrying the real SNI.
///    Pass in booleans (`true` = probe succeeded) collected by the caller
///    after running both probes concurrently — this function only holds the
///    decision table so it's independently testable.
pub fn ab_test_block_type(plain_probe_ok: bool, real_sni_probe_ok: bool) -> BlockType {
    match (plain_probe_ok, real_sni_probe_ok) {
        (true, true) => BlockType::NotBlocked,
        (true, false) => BlockType::SniBlock,
        (false, true) => BlockType::Inconclusive, // shouldn't happen; real SNI worked but plain didn't
        (false, false) => BlockType::IpBlock,
    }
}

/// Ordered escalation ladder for the adaptive feedback loop (2026 roadmap
/// #6): when the configured profile has learned to *fail* on a domain, the
/// pipeline climbs one rung instead of retrying a known-broken shape.
/// Ordered cheap-and-safe first, heavy machinery last.
pub const ESCALATION_LADDER: [&str; 6] = [
    "Stealth",
    "ChinaGfw",
    "RussiaDpi",
    "ChinaRegional",
    "Henan",
    "NestedCloak",
];

/// The next rung after `current`, if any. Unknown profiles have no rung.
pub fn next_rung(current: &str) -> Option<&'static str> {
    let pos = ESCALATION_LADDER.iter().position(|p| *p == current)?;
    ESCALATION_LADDER.get(pos + 1).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_best_picks_highest_score() {
        let table = StrategyTable::new();
        table.update_score("example.com", "frag", true);
        table.update_score("example.com", "frag", true);
        table.update_score("example.com", "case", false);
        let best = table.select_best("example.com", &["frag", "case"]);
        assert_eq!(best.as_deref(), Some("frag"));
    }

    #[test]
    fn select_best_ties_prefer_first_input() {
        let table = StrategyTable::new();
        let best = table.select_best("example.com", &["a", "b"]);
        assert_eq!(best.as_deref(), Some("a"));
    }

    #[test]
    fn update_score_asymmetric_penalty() {
        let table = StrategyTable::new();
        assert_eq!(table.update_score("d", "t", true), 1);
        assert_eq!(table.update_score("d", "t", false), -1);
        assert_eq!(table.update_score("d", "t", false), -3);
    }

    #[test]
    fn per_domain_scores_isolated_from_other_domains() {
        let table = StrategyTable::new();
        table.update_score("a.com", "x", true);
        table.update_score("b.com", "x", true);
        let scores = table.per_domain_scores("a.com");
        assert_eq!(scores.len(), 1);
        assert_eq!(scores[0].0, "x");
    }

    #[test]
    fn ab_test_decision_table() {
        assert_eq!(ab_test_block_type(true, true), BlockType::NotBlocked);
        assert_eq!(ab_test_block_type(true, false), BlockType::SniBlock);
        assert_eq!(ab_test_block_type(false, false), BlockType::IpBlock);
        assert_eq!(ab_test_block_type(false, true), BlockType::Inconclusive);
    }

    #[test]
    fn select_rotating_none_until_something_wins() {
        let table = StrategyTable::new();
        // All scores 0 (or negative): no rotation, deterministic fallback.
        assert_eq!(table.select_rotating("d", &["a", "b"]), None);
        table.update_score("d", "a", false);
        table.update_score("d", "b", false);
        assert_eq!(table.select_rotating("d", &["a", "b"]), None);
    }

    #[test]
    fn select_rotating_only_picks_winners_and_weights_them() {
        let table = StrategyTable::new();
        table.update_score("d", "frag", true); // +1
        table.update_score("d", "case", true); // +1
        table.update_score("d", "case", false); // -2 -> -1 (loser, excluded)
        let mut saw_frag = 0;
        let mut saw_case = 0;
        for _ in 0..100 {
            match table.select_rotating("d", &["frag", "case"]).as_deref() {
                Some("frag") => saw_frag += 1,
                Some("case") => saw_case += 1,
                other => panic!("unexpected {other:?}"),
            }
        }
        // "case" is negative -> never picked; "frag" is the only winner.
        assert_eq!(saw_frag, 100);
        assert_eq!(saw_case, 0);
    }

    #[test]
    fn select_rotating_explores_both_winners() {
        let table = StrategyTable::new();
        table.update_score("d", "a", true);
        table.update_score("d", "b", true);
        let mut saw_a = false;
        let mut saw_b = false;
        for _ in 0..200 {
            match table.select_rotating("d", &["a", "b"]).as_deref() {
                Some("a") => saw_a = true,
                Some("b") => saw_b = true,
                _ => {}
            }
        }
        // Equal weights: each is picked ~50%; missing one in 200 tries is
        // ~2^-200.
        assert!(saw_a && saw_b);
    }

    #[test]
    fn decay_all_halves_scores_toward_zero() {
        let table = StrategyTable::new();
        table.update_score("d", "t", true);
        table.update_score("d", "t", true);
        table.update_score("d", "t", true); // +3
        table.update_score("d", "u", false); // -2
        table.decay_all();
        let scores: std::collections::HashMap<_, _> =
            table.per_domain_scores("d").into_iter().collect();
        assert_eq!(scores["t"], 1); // 3 / 2
        assert_eq!(scores["u"], -1); // -2 / 2
        table.decay_all();
        let scores: std::collections::HashMap<_, _> =
            table.per_domain_scores("d").into_iter().collect();
        assert_eq!(scores["t"], 0);
        assert_eq!(scores["u"], 0);
    }

    #[test]
    fn escalation_ladder_climbs_in_order() {
        assert_eq!(next_rung("Stealth"), Some("ChinaGfw"));
        assert_eq!(next_rung("ChinaGfw"), Some("RussiaDpi"));
        assert_eq!(next_rung("ChinaRegional"), Some("Henan"));
        assert_eq!(next_rung("Henan"), Some("NestedCloak"));
        assert_eq!(next_rung("NestedCloak"), None); // top of the ladder
        assert_eq!(next_rung("Aggressive"), None); // not on the ladder
        assert_eq!(next_rung("Nope"), None);
    }

    #[test]
    fn desync_mode_parses_known_aliases() {
        use std::str::FromStr;
        assert_eq!(
            DesyncMode::from_str("tls").unwrap(),
            DesyncMode::TlsRecordFrag
        );
        assert_eq!(
            DesyncMode::from_str("frag-by-sni").unwrap(),
            DesyncMode::FragBySni
        );
        assert_eq!(
            DesyncMode::from_str("Disorder").unwrap(),
            DesyncMode::Disorder
        );
        assert_eq!(DesyncMode::from_str("DECOY").unwrap(), DesyncMode::Decoy);
        assert_eq!(DesyncMode::from_str("none").unwrap(), DesyncMode::None);
        assert!(DesyncMode::from_str("nope").is_err());
    }
}
