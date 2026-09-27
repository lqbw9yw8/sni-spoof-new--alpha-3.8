//! Bounded retirement policy for WinDivert driver handles. [UNTESTED]
//!
//! Pure logic, cfg-free, so the policy can be compiled on every OS; the
//! current checkout's Rust tests are not executed in this environment. `engine.rs` (Windows-only) applies it to the retired-handle list.
//!
//! ## Why handles are parked at all
//!
//! The live capture handle is published through a raw `AtomicPtr` so that
//! `WinDivertShutdown` can run concurrent with a blocking `recv` (documented
//! as safe by the C API). Any thread that loaded the old pointer may still
//! be inside `send`/`shutdown` on it, so a retired handle cannot be closed
//! (dropped) at retirement time — that would free the `WinDivert` struct
//! under an in-flight FFI call (use-after-free).
//!
//! ## How the leak is bounded instead
//!
//! 1. Every retired handle is shut down immediately (its `recv` unblocks),
//!    then parked with a retirement timestamp.
//! 2. On every retirement the list is swept: entries older than
//!    [`RETIRED_GRACE`] are closed (dropped) from the oldest end. A thread
//!    that observed the pointer before the swap completes its short FFI
//!    call within microseconds; a 30 s grace is six orders of magnitude of
//!    margin.
//! 3. Hard bound: the list is never allowed to exceed [`RETIRED_CAP`]
//!    entries. If more than `cap` entries are still inside the grace
//!    window (only possible with pathological filter-reload flapping),
//!    the oldest entries are force-closed anyway — a bounded, rare, logged
//!    event that is strictly better than an unbounded kernel-handle leak.
//!    Even in this path nothing panics and the packet path is unaffected:
//!    the capture loop only ever sends on the *current* handle, and
//!    `reinject_held_packets` only sends packets whose captured
//!    `WinDivertAddress` is still owned by the held entry; it never constructs
//!    an address-less packet after the 0.5.5 wrapper's unsafe constructor.

use std::time::Duration;

/// Maximum number of parked (shut-down-but-not-closed) handles.
pub const RETIRED_CAP: usize = 16;

/// A retired handle must survive at least this long before it may be
/// closed, so an in-flight `send` that loaded the pointer before the
/// `AtomicPtr` swap has long finished.
pub const RETIRED_GRACE: Duration = Duration::from_secs(30);

/// Pure decision function: given the ages of all parked handles, oldest
/// first (`ages_ms[0]` is the oldest), return how many entries to close
/// from the front of the list.
///
/// * Every entry past the grace window is closed (eager cleanup — kernel
///   handles are released as soon as it is provably safe).
/// * Independently, if the list exceeds `cap`, enough of the oldest
///   entries are force-closed to bring it back to `cap` — the hard bound
///   wins over the grace window.
pub fn close_count(ages_ms: &[u64], cap: usize, grace_ms: u64) -> usize {
    let expired_prefix = ages_ms.iter().take_while(|&&age| age >= grace_ms).count();
    let over_cap = ages_ms.len().saturating_sub(cap);
    expired_prefix.max(over_cap)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAP: usize = 4;
    const GRACE: u64 = 30_000; // 30 s in ms

    #[test]
    fn empty_list_closes_nothing() {
        assert_eq!(close_count(&[], CAP, GRACE), 0);
    }

    #[test]
    fn young_entries_under_cap_are_kept() {
        // All inside the grace window, list below cap: park only.
        assert_eq!(close_count(&[1, 5, 100], CAP, GRACE), 0);
    }

    #[test]
    fn expired_entries_are_closed_eagerly() {
        // Oldest is past grace even though the list is under cap.
        assert_eq!(close_count(&[40_000, 5, 1], CAP, GRACE), 1);
        // Oldest two past grace.
        assert_eq!(close_count(&[40_000, 35_000, 5], CAP, GRACE), 2);
    }

    #[test]
    fn grace_boundary_is_inclusive() {
        // Exactly at grace: safe to close.
        assert_eq!(close_count(&[GRACE], CAP, GRACE), 1);
        assert_eq!(close_count(&[GRACE - 1], CAP, GRACE), 0);
    }

    #[test]
    fn cap_is_a_hard_bound_even_inside_grace() {
        // 6 young entries, cap 4: force-close 2 oldest despite grace.
        assert_eq!(close_count(&[10, 9, 8, 7, 6, 5], CAP, GRACE), 2);
        // Exactly at cap: nothing forced.
        assert_eq!(close_count(&[10, 9, 8, 7], CAP, GRACE), 0);
    }

    #[test]
    fn cap_and_grace_combine() {
        // 6 entries, oldest 2 expired, cap 4: expired prefix (2) and
        // over-cap (2) agree -> 2. But if only the oldest 1 is expired,
        // the hard bound still forces 2.
        assert_eq!(close_count(&[40_000, 35_000, 10, 9, 8, 7], CAP, GRACE), 2);
        assert_eq!(close_count(&[40_000, 10, 9, 8, 7, 6], CAP, GRACE), 2);
        // 7 entries, 5 expired: eager cleanup closes 5, which is also >= 3.
        assert_eq!(
            close_count(&[50_000, 45_000, 40_000, 35_000, 31_000, 10, 9], CAP, GRACE),
            5
        );
    }

    #[test]
    fn expired_prefix_never_reaches_young_entries() {
        // Ordering is oldest-first; a young entry can never be closed while
        // an older unexpired one is kept.
        let ages = [40_000, 1, 40_000];
        // Prefix semantics: only the leading expired run counts. Entry 1
        // (young) shields entry 2 (expired) — it stays parked until the
        // next sweep after the shield expires. Conservative and safe.
        assert_eq!(close_count(&ages, CAP, GRACE), 1);
    }

    #[test]
    fn zero_cap_forces_close_of_everything() {
        assert_eq!(close_count(&[5, 5, 5], 0, GRACE), 3);
    }
}
