//! Fail-open panic/error boundary used by the capture loop. [UNTESTED]
//! Lives in a cfg-free module so the tests run on every OS (they used to
//! sit inside `engine.rs`, which is `cfg(windows)` only).

use crate::error::DpiGuardError;
use std::panic::{catch_unwind, AssertUnwindSafe};

/// What the capture loop should do with a diverted packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireAction {
    /// Inject these packets in order (50µs gap between them).
    Send(Vec<Vec<u8>>),
    /// Send nothing now (reassembly is holding the bytes).
    Hold,
    /// Forward the ORIGINAL captured bytes unchanged. The engine still owns
    /// its receive buffer, so this arm reinjects it with zero extra heap
    /// copies — the pass-through case (~99% of packets) used to pay for a
    /// fresh `Vec` per packet here.
    Passthrough,
}

/// Run `f(original)`. On panic **or** `Err`, log and return the original
/// packet so a mutation bug never black-holes the user's connection.
pub fn handle_exception_fail_open<F>(original: &[u8], f: &mut F) -> WireAction
where
    F: FnMut(&[u8]) -> Result<WireAction, DpiGuardError>,
{
    // Hot path: this runs once per captured packet. The closure borrows the
    // engine's receive buffer (`&[u8]`) instead of taking an owned `Vec` —
    // this used to force one full-buffer copy per packet even when the
    // pipeline decided to pass the packet through untouched. The fallback
    // copy is only built on the empty-Send / Err / panic branches (rare),
    // so those call `original.to_vec()` inline, only when actually taken.
    // `Passthrough` needs no copy at all: the caller still owns `original`.
    match catch_unwind(AssertUnwindSafe(|| f(original))) {
        Ok(Ok(WireAction::Send(packets))) if !packets.is_empty() => WireAction::Send(packets),
        Ok(Ok(WireAction::Passthrough)) => WireAction::Passthrough,
        Ok(Ok(WireAction::Send(_))) => {
            crate::observability::fail_open_event();
            WireAction::Send(vec![original.to_vec()])
        }
        Ok(Ok(WireAction::Hold)) => WireAction::Hold,
        Ok(Err(e)) => {
            crate::observability::fail_open_event();
            log::error!("mutation returned error, passing original packet through: {e}");
            WireAction::Send(vec![original.to_vec()])
        }
        Err(panic_payload) => {
            crate::observability::fail_open_event();
            let msg = panic_payload
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| panic_payload.downcast_ref::<String>().cloned())
                .or_else(|| {
                    panic_payload
                        .downcast_ref::<Box<str>>()
                        .map(|s| s.to_string())
                })
                .unwrap_or_else(|| "non-string panic payload".to_string());
            log::error!("mutation panicked, passing original packet through: {msg}");
            WireAction::Send(vec![original.to_vec()])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fail_open_returns_original_on_panic() {
        let original = vec![1, 2, 3];
        let mut f = |_: &[u8]| -> Result<WireAction, DpiGuardError> { panic!("boom") };
        let out = handle_exception_fail_open(&original, &mut f);
        assert_eq!(out, WireAction::Send(vec![original]));
    }

    #[test]
    fn fail_open_returns_mutated_on_success() {
        let original = vec![1, 2, 3];
        let mut f = |v: &[u8]| -> Result<WireAction, DpiGuardError> {
            let mut v = v.to_vec();
            v.push(4);
            Ok(WireAction::Send(vec![v]))
        };
        let out = handle_exception_fail_open(&original, &mut f);
        assert_eq!(out, WireAction::Send(vec![vec![1, 2, 3, 4]]));
    }

    #[test]
    fn fail_open_returns_original_on_err() {
        let original = vec![9];
        let mut f =
            |_: &[u8]| -> Result<WireAction, DpiGuardError> { Err(DpiGuardError::SniNotFound) };
        let out = handle_exception_fail_open(&original, &mut f);
        assert_eq!(out, WireAction::Send(vec![original]));
    }

    #[test]
    fn fail_open_err_does_not_return_closure_mutations() {
        let original = vec![9, 8, 7];
        let expected = original.clone();
        let mut f = |owned: &[u8]| -> Result<WireAction, DpiGuardError> {
            let mut owned = owned.to_vec();
            owned.fill(0xEE);
            Err(DpiGuardError::SniNotFound)
        };
        let out = handle_exception_fail_open(&original, &mut f);
        assert_eq!(out, WireAction::Send(vec![expected]));
    }

    #[test]
    fn fail_open_empty_vec_becomes_original() {
        let original = vec![7, 8];
        let mut f =
            |_: &[u8]| -> Result<WireAction, DpiGuardError> { Ok(WireAction::Send(vec![])) };
        let out = handle_exception_fail_open(&original, &mut f);
        assert_eq!(out, WireAction::Send(vec![original]));
    }

    #[test]
    fn fail_open_preserves_hold() {
        let original = vec![1];
        let mut f = |_: &[u8]| -> Result<WireAction, DpiGuardError> { Ok(WireAction::Hold) };
        assert_eq!(
            handle_exception_fail_open(&original, &mut f),
            WireAction::Hold
        );
    }

    #[test]
    fn fail_open_propagates_passthrough_without_copy() {
        let original = vec![5, 6, 7];
        let mut f = |v: &[u8]| -> Result<WireAction, DpiGuardError> {
            // The callee sees the caller's buffer, not a private copy.
            assert_eq!(v, original);
            Ok(WireAction::Passthrough)
        };
        assert_eq!(
            handle_exception_fail_open(&original, &mut f),
            WireAction::Passthrough
        );
    }
}
