//! autottl — learn the decoy TTL from the inbound hop count. [UNTESTED]
//!
//! A TTL-limited decoy must travel far enough to reach the *in-line DPI*
//! box but die before the real origin replies. The safest first guess is the
//! number of IP hops to the destination, derived from the **inbound**
//! packet's remaining TTL: on a typical Ethernet path the client's SYN
//! leaves with a well-known initial TTL (64/128/255), so the hop count to
//! this host is `initial_ttl - observed_ttl`. We then emit the decoy with
//! that many hops of headroom (plus a small `delta`), so it reaches the DPI
//! but expires one hop past it.
//!
//! The learned value is a *hint*: the operator's `decoy_ttl` setting is the
//! hard ceiling, and we never raise TTL above 64 (the protocol's common
//! inner value). This module is pure logic + in-memory state, so it is unit
//! testable on every OS; the current checkout's Rust tests are not executed.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Hard cap on the learned TTL (never suggest more than this).
pub const MAX_AUTO_TTL: u8 = 64;
/// How long a learned TTL for a destination is kept.
const LEARN_TTL: Duration = Duration::from_secs(60 * 30);
/// Cap on the number of learned TTL entries to prevent unbounded growth
/// from spoofed source IPs (CWE-770). Same pattern as MAX_LAST_ACTIVITY
/// and MAX_INBOUND_TTL in pipeline.rs.
pub const MAX_AUTO_TTL_ENTRIES: usize = 4096;

/// Guess the sender's initial TTL from the observed remaining TTL.
/// Common stacks initialise IP TTL to 64, 128, or 255. We pick the
/// smallest common initial that is >= observed (so hop count is positive).
pub fn guess_initial_ttl(observed: u8) -> u8 {
    for &initial in &[64u8, 128, 255] {
        if observed <= initial {
            return initial;
        }
    }
    255
}

/// Number of hops a packet with `observed_ttl` has traversed, assuming a
/// common initial TTL (64/128/255). Returns 0 for nonsensical values.
pub fn inbound_hop_count(observed_ttl: u8) -> u8 {
    if observed_ttl == 0 {
        return 0;
    }
    let initial = guess_initial_ttl(observed_ttl);
    initial.saturating_sub(observed_ttl)
}

/// Suggest a decoy TTL given an observed inbound TTL and an operator delta.
/// The result is clamped to `[1, MAX_AUTO_TTL]`. The delta adds a small
/// safety margin so the decoy reaches *past* the DPI but still dies before
/// the origin (the operator's static `decoy_ttl` is the real ceiling).
pub fn suggest_ttl(inbound_observed_ttl: u8, delta: i8) -> u8 {
    let hops = inbound_hop_count(inbound_observed_ttl) as i16;
    // If the peer is on-link (hops == 0) there is no DPI between us; fall
    // back to a low safe default rather than emitting a 1-hop packet.
    let base = if hops == 0 { 4i16 } else { hops + 1 };
    let ttl = (base + delta as i16).clamp(1, MAX_AUTO_TTL as i16);
    ttl as u8
}

/// GoodbyeDPI-style auto-ttl with scale (`a1`-`a2`-`m`).
///
/// The decoy must travel far enough to be parsed by the in-line DPI but
/// expire before it reaches the origin, so its TTL is the measured hop
/// count minus a *reduction*:
///
/// ```text
/// decoy_ttl = clamp(hops - reduction(hops), 1, min(m, MAX_AUTO_TTL))
/// ```
///
/// `reduction` scales linearly with distance, from `a1` on a short path to
/// `a2` on a path at or beyond `m` hops. The rationale: on a short path
/// there is little room between "reaches the DPI" and "reaches the origin",
/// so trim conservatively; on a long path the DPI is proportionally much
/// closer than the origin, so a larger margin is both safe and more likely
/// to die before the far end.
///
/// * `a1` — reduction on the shortest paths (floored at 1).
/// * `a2` — reduction at/after `m` hops (raised to at least `a1`).
/// * `m`  — distance at which the reduction saturates, and the ceiling on
///   the returned TTL.
///
/// ## Previous behaviour (fixed)
///
/// The scale used to be inverted — `hops <= a2` took a reduction of
/// `a2 - 1` while distant paths took only `a1` — so with the shipped
/// defaults (`a1 = 0`, `a2 = 4`, `m = 10`) every path of four hops or
/// fewer produced `hops - 3` floored at 1, i.e. **TTL 1**. A TTL-1 decoy
/// is discarded by the first router and never reaches any DPI, silently
/// disabling the technique on exactly the short paths it was meant to
/// cover. It also had no test; the ones below pin the shape of the curve.
pub fn suggest_ttl_scaled(inbound_observed_ttl: u8, a1: u8, a2: u8, max_ttl: u8) -> u8 {
    let hops = inbound_hop_count(inbound_observed_ttl);
    if hops == 0 {
        // On-link peer (or an unusable observation): no DPI in between, so
        // fall back to the same conservative default `suggest_ttl` uses
        // instead of emitting a 1-hop packet.
        return 4;
    }
    let a1 = a1.max(1); // a reduction of 0 would make the decoy reach the origin
    let a2 = a2.max(a1); // a2 is the far-path reduction, never below a1
    let ceiling = max_ttl.clamp(1, MAX_AUTO_TTL);

    // Weight the reduction by how far along `max_ttl` this path is.
    // Saturates at 1.0 for hops >= max_ttl.
    let span = f64::from(ceiling.max(1));
    let weight = (f64::from(hops) / span).min(1.0);
    let reduction = f64::from(a1) + weight * f64::from(a2.saturating_sub(a1));
    // Round to nearest rather than truncating so the curve is symmetric.
    let reduction = reduction.round().max(1.0) as u8;

    hops.saturating_sub(reduction).max(1).min(ceiling)
}

/// Per-destination learned TTL, expired after [`LEARN_TTL`].
#[derive(Debug, Clone)]
struct Learned {
    ttl: u8,
    at: Instant,
}

/// Learns and caches a suggested decoy TTL per relay destination IP.
#[derive(Debug, Default)]
pub struct AutoTtl {
    learned: HashMap<IpAddr, Learned>,
}

impl AutoTtl {
    pub fn new() -> Self {
        Self {
            learned: HashMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.learned.len()
    }

    pub fn is_empty(&self) -> bool {
        self.learned.is_empty()
    }

    /// Record the TTL observed on an inbound packet from `src`. Safe to call
    /// for every inbound packet; only the most recent value is kept.
    /// Bounded by MAX_AUTO_TTL_ENTRIES to prevent spoofed-source growth.
    pub fn observe(&mut self, src: IpAddr, observed_ttl: u8, delta: i8) {
        if !self.learned.contains_key(&src) && self.learned.len() >= MAX_AUTO_TTL_ENTRIES {
            self.evict_oldest_half();
        }
        let ttl = suggest_ttl(observed_ttl, delta);
        self.learned.insert(
            src,
            Learned {
                ttl,
                at: Instant::now(),
            },
        );
    }

    fn evict_oldest_half(&mut self) {
        if self.learned.len() < MAX_AUTO_TTL_ENTRIES {
            return;
        }
        let mut by_age: Vec<(IpAddr, Instant)> =
            self.learned.iter().map(|(ip, l)| (*ip, l.at)).collect();
        by_age.sort_unstable_by_key(|(_, at)| *at);
        let n = by_age.len() / 2;
        for (ip, _) in by_age.into_iter().take(n) {
            self.learned.remove(&ip);
        }
    }

    /// Return the last learned TTL for `dst`, if fresh.
    pub fn get(&self, dst: IpAddr) -> Option<u8> {
        let l = self.learned.get(&dst)?;
        if l.at.elapsed() > LEARN_TTL {
            return None;
        }
        Some(l.ttl)
    }

    /// Resolve the effective decoy TTL: the learned value if present and
    /// fresh, otherwise the operator-configured `fallback` (already
    /// validated to be 1..=64 by `config::Settings::validate`).
    pub fn effective(&self, dst: IpAddr, fallback: u8) -> u8 {
        self.get(dst).unwrap_or(fallback).min(fallback).max(1)
    }

    /// Drop expired entries.
    pub fn prune(&mut self) {
        self.learned.retain(|_, l| l.at.elapsed() <= LEARN_TTL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guess_initial_ttl_picks_smallest_common_ge() {
        assert_eq!(guess_initial_ttl(10), 64);
        assert_eq!(guess_initial_ttl(64), 64);
        assert_eq!(guess_initial_ttl(65), 128);
        assert_eq!(guess_initial_ttl(128), 128);
        assert_eq!(guess_initial_ttl(200), 255);
        assert_eq!(guess_initial_ttl(255), 255);
    }

    #[test]
    fn hop_count_from_inbound_ttl() {
        // Remote peer started at 64, we see 58 -> 6 hops.
        assert_eq!(inbound_hop_count(58), 6);
        // On-link: observed == initial -> 0 hops.
        assert_eq!(inbound_hop_count(64), 0);
        assert_eq!(inbound_hop_count(128), 0);
        assert_eq!(inbound_hop_count(0), 0);
    }

    #[test]
    fn suggest_ttl_reaches_one_past_dpi() {
        // 6 hops away -> suggest 7 (plus delta), capped.
        assert_eq!(suggest_ttl(58, 0), 7);
        assert_eq!(suggest_ttl(58, -2), 5);
        assert_eq!(suggest_ttl(58, 100), MAX_AUTO_TTL);
        // On-link peer -> low safe default.
        assert_eq!(suggest_ttl(64, 0), 4);
        assert_eq!(suggest_ttl(64, -100), 1);
    }

    #[test]
    fn auto_ttl_learns_and_falls_back() {
        let mut a = AutoTtl::new();
        let dst: IpAddr = "1.1.1.1".parse().unwrap();
        assert_eq!(a.get(dst), None);
        a.observe(dst, 58, 0);
        assert_eq!(a.get(dst), Some(7));
        // effective() never exceeds the operator fallback.
        assert_eq!(a.effective(dst, 4), 4);
        assert_eq!(a.effective(dst, 64), 7);
        // Unknown destination uses the fallback.
        let other: IpAddr = "8.8.8.8".parse().unwrap();
        assert_eq!(a.effective(other, 8), 8);
    }

    // ---- suggest_ttl_scaled -------------------------------------------
    // This function shipped with no tests at all and an inverted scale.
    // These pin the properties that make the technique work.

    /// The regression that motivated the rewrite: with the shipped
    /// defaults every short path collapsed to TTL 1, which no router
    /// forwards, so no DPI ever saw the decoy.
    #[test]
    fn scaled_does_not_collapse_to_one_on_short_paths() {
        // Defaults from config.rs: a1 = 0, a2 = 4, m = 10.
        for observed in [60u8, 58, 56, 54] {
            let hops = inbound_hop_count(observed);
            let ttl = suggest_ttl_scaled(observed, 0, 4, 10);
            assert!(
                ttl > 1,
                "observed {observed} ({hops} hops) gave TTL {ttl}; a TTL-1 decoy \
                 dies at the first router and never reaches the DPI"
            );
        }
    }

    /// The decoy must be able to reach the DPI but not the origin, so its
    /// TTL is strictly below the measured hop count whenever there is any
    /// room at all.
    #[test]
    fn scaled_is_below_the_hop_count() {
        for observed in [60u8, 58, 56, 50, 44, 34] {
            let hops = inbound_hop_count(observed);
            let ttl = suggest_ttl_scaled(observed, 0, 4, 10);
            assert!(
                u16::from(ttl) < u16::from(hops).max(2),
                "TTL {ttl} must stay under the {hops}-hop distance to the origin"
            );
        }
    }

    /// A longer path must never yield a *smaller* decoy TTL: the curve is
    /// monotonic in distance. The old inverted scale failed this.
    #[test]
    fn scaled_is_monotonic_in_distance() {
        let mut prev = 0u8;
        // 64 down to 34 = 0..30 hops.
        for observed in (34u8..=63).rev() {
            let ttl = suggest_ttl_scaled(observed, 0, 4, 10);
            assert!(
                ttl >= prev,
                "TTL dropped from {prev} to {ttl} as the path got longer \
                 (observed {observed})"
            );
            prev = ttl;
        }
    }

    #[test]
    fn scaled_respects_the_m_ceiling_and_hard_cap() {
        // Distant destination, small ceiling: clamped to m.
        assert_eq!(suggest_ttl_scaled(20, 1, 4, 10), 10);
        // m above MAX_AUTO_TTL is clamped to MAX_AUTO_TTL.
        assert!(suggest_ttl_scaled(20, 1, 2, 200) <= MAX_AUTO_TTL);
        // Result is never zero.
        for observed in 1u8..=255 {
            assert!(suggest_ttl_scaled(observed, 0, 4, 10) >= 1);
        }
    }

    #[test]
    fn scaled_on_link_peer_uses_safe_default() {
        // hops == 0 -> no DPI in between; same fallback as suggest_ttl.
        assert_eq!(suggest_ttl_scaled(64, 0, 4, 10), 4);
        assert_eq!(suggest_ttl_scaled(128, 0, 4, 10), 4);
        assert_eq!(suggest_ttl_scaled(0, 0, 4, 10), 4);
    }

    /// `a1 = 0` is the shipped default but a zero reduction would let the
    /// decoy travel the full distance to the origin, so it is floored at 1,
    /// and `a2 < a1` is normalised rather than producing a negative span.
    #[test]
    fn scaled_normalises_degenerate_parameters() {
        let a = suggest_ttl_scaled(56, 0, 4, 10); // a1 floored to 1
        let b = suggest_ttl_scaled(56, 1, 4, 10);
        assert_eq!(a, b);
        // a2 below a1 is raised to a1; must not panic or underflow.
        let c = suggest_ttl_scaled(56, 6, 2, 10);
        assert!(c >= 1);
        // Zero ceiling is raised to 1.
        assert_eq!(suggest_ttl_scaled(56, 1, 2, 0), 1);
    }

    #[test]
    fn auto_ttl_bounded_under_spoofed_source_flood() {
        let mut a = AutoTtl::new();
        // Simulate spoofed source flood: many distinct IPs
        for i in 0..(MAX_AUTO_TTL_ENTRIES + 500) {
            let ip: IpAddr = format!("10.0.{}.{}", (i >> 8) & 0xFF, i & 0xFF)
                .parse()
                .unwrap();
            a.observe(ip, 58, 0);
        }
        // Must be bounded: after eviction oldest half, len <= MAX
        assert!(
            a.len() <= MAX_AUTO_TTL_ENTRIES,
            "AutoTtl grew to {} > {} under spoofed-source flood",
            a.len(),
            MAX_AUTO_TTL_ENTRIES
        );
    }
}
