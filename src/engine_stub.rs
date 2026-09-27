//! engine_stub — compiled in place of `engine.rs` on any non-Windows
//! target. [STUB] Signatures match `engine.rs` so the rest of the crate links.

use crate::error::DpiGuardError;
use crate::fail_open::WireAction;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

pub use crate::DEFAULT_FILTER;

/// On non-Windows targets there is no capture driver, so this always
/// reports false. The relay still must not start without capture, and
/// `main` treats a false readiness as a fatal error.
pub fn capture_is_ready() -> bool {
    false
}

/// See [`crate::engine::wait_until_capture_ready`]. Always returns false
/// on non-Windows (no driver).
pub fn wait_until_capture_ready(_timeout: Duration) -> bool {
    false
}

fn not_supported() -> DpiGuardError {
    DpiGuardError::PlatformNotSupported {
        os: std::env::consts::OS,
    }
}

pub fn inject_packet(_packet: &[u8]) -> Result<(), DpiGuardError> {
    Err(not_supported())
}

pub fn reinject_held_packets(_packets: &[Vec<u8>]) -> Result<(), DpiGuardError> {
    Err(not_supported())
}

pub fn capture_loop<F>(
    _filter: &str,
    _running: Arc<AtomicBool>,
    _injection_delay: Option<(u64, u64)>,
    _on_packet: F,
) -> Result<(), DpiGuardError>
where
    F: FnMut(&[u8]) -> Result<WireAction, DpiGuardError> + Send + 'static,
{
    Err(not_supported())
}

/// Non-Windows placeholder matching the Windows lifetime guard type.
#[derive(Debug, Default)]
pub struct DriverPin;

pub fn version_check(_expected_hashes: &[String]) -> Result<DriverPin, DpiGuardError> {
    Err(not_supported())
}

pub fn graceful_shutdown(_running: Arc<AtomicBool>) -> Result<(), DpiGuardError> {
    Err(not_supported())
}

pub fn request_shutdown() {}

/// Mirrors `engine::retired_handle_count` for the dashboard. No driver on
/// non-Windows, so the list is always empty.
pub fn retired_handle_count() -> usize {
    0
}

/// Mirrors `engine::live_handle_open` for the dashboard. There is never a
/// live WinDivert handle on non-Windows.
pub fn live_handle_open() -> bool {
    false
}

pub fn request_filter_reload(_new_filter: &str) {
    // No-op: the WinDivert capture loop (and its open handle) only exists
    // on Windows.
}

/// Same backoff schedule as `engine.rs`, mirrored here so the logic is
/// compiled on non-Windows CI rather than only ever existing in a
/// `cfg(windows)` module nobody runs; current Rust tests were not executed.
pub fn recv_backoff(consecutive_errors: u32) -> Duration {
    let exp = consecutive_errors.min(5);
    let ms = 20u64.saturating_mul(1u64 << exp);
    Duration::from_millis(ms.min(500))
}

pub fn thread_safe_logging_init() {
    crate::init_logging();
}

pub fn parse_tls_client_hello(tcp_payload: &[u8]) -> Option<Vec<u8>> {
    crate::fragmentation::sni_bytes(tcp_payload)
}

pub fn recalculate_checksums(pkt: &mut [u8]) {
    crate::packet::recalculate_all_checksums(pkt);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inject_packet_reports_unsupported_off_windows() {
        let err = inject_packet(&[]).unwrap_err();
        assert!(matches!(err, DpiGuardError::PlatformNotSupported { .. }));
    }

    #[test]
    fn capture_loop_signature_matches_windows() {
        let running = Arc::new(AtomicBool::new(false));
        let err = capture_loop("true", running, None, |_| Ok(WireAction::Hold)).unwrap_err();
        assert!(matches!(err, DpiGuardError::PlatformNotSupported { .. }));
    }

    /// A flapping interface makes `recv` fail immediately and repeatedly.
    /// The backoff must start small (so a brief blip recovers fast), grow,
    /// and then cap — otherwise the capture loop pins a core at 100 %.
    #[test]
    fn recv_backoff_grows_then_caps() {
        assert_eq!(recv_backoff(0), Duration::from_millis(20));
        assert_eq!(recv_backoff(1), Duration::from_millis(40));
        assert_eq!(recv_backoff(2), Duration::from_millis(80));
        assert_eq!(recv_backoff(5), Duration::from_millis(500));
        // Past the cap: constant, and no overflow even at u32::MAX.
        assert_eq!(recv_backoff(6), Duration::from_millis(500));
        assert_eq!(recv_backoff(u32::MAX), Duration::from_millis(500));
        for n in 0..1000 {
            let d = recv_backoff(n);
            assert!(d >= Duration::from_millis(20));
            assert!(d <= Duration::from_millis(500));
        }
        // Monotonic non-decreasing.
        for n in 0..50 {
            assert!(recv_backoff(n) <= recv_backoff(n + 1));
        }
    }
}
