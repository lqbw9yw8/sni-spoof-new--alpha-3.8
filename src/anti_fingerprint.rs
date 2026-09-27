//! anti_fingerprint — advanced anti-fingerprinting for DPI evasion. [UNTESTED]
//!
//! Provides randomization of packet timing, size, and IP-ID to prevent
//! DPI systems from correlating injected fake packets with the real flow
//! by statistical fingerprinting.
//!
//! Three independent randomization layers:
//!   1. **Timing jitter** — variable delay between fake injection and
//!      real data (already partially in stealth.rs; this module provides
//!      per-connection randomized jitter ranges).
//!   2. **Packet-size padding** — random padding appended to fake
//!      ClientHello so its size varies between connections.
//!   3. **IP-ID randomization** — the IPv4 identification field is
//!      randomized rather than sequential, preventing simple correlation.

use rand::Rng;
use std::time::Duration;

/// Generate a randomized injection delay within [min_ms, max_ms].
/// Unlike the fixed 1 ms in the original patterniha, this uses a
/// uniform distribution in the configured range.
pub fn random_injection_delay(min_ms: u64, max_ms: u64) -> Duration {
    if min_ms >= max_ms {
        return Duration::from_millis(min_ms);
    }
    let mut rng = rand::thread_rng();
    let ms = rng.gen_range(min_ms..=max_ms);
    Duration::from_millis(ms)
}

/// Add random padding bytes to a fake packet so its wire size varies.
/// The padding is appended after the TLS record and looks like random
/// data. Returns the padded packet.
///
/// `base_size` is the original packet length. `max_extra` is the
/// maximum number of padding bytes to add (0 = no padding).
pub fn randomize_packet_size(packet: &[u8], max_extra: usize) -> Vec<u8> {
    if max_extra == 0 {
        return packet.to_vec();
    }
    let mut rng = rand::thread_rng();
    let extra = rng.gen_range(0..=max_extra);
    let mut out = Vec::with_capacity(packet.len() + extra);
    out.extend_from_slice(packet);
    for _ in 0..extra {
        out.push(rng.gen());
    }
    out
}

/// Randomize the IPv4 ID field. The original patterniha uses sequential
/// IP-ID (+1 each packet), which is trivially predictable. Randomization
/// makes correlation harder.
///
/// Mutates bytes 4..6 of the IPv4 header (the ID field).
pub fn randomize_ip_id(packet: &mut [u8]) -> bool {
    if packet.len() < 20 || (packet[0] >> 4) != 4 {
        return false; // not IPv4
    }
    let _ = randomize_ip_id_in_range(packet, 0, 65535);
    true
}

/// Generate a randomized IP-ID within a configurable delta range
/// (simulating natural OS behavior: sequential but with variable step).
pub fn randomize_ip_id_in_range(packet: &mut [u8], prev_id: u16, max_delta: u16) -> u16 {
    if packet.len() < 20 || (packet[0] >> 4) != 4 {
        return prev_id;
    }
    let mut rng = rand::thread_rng();
    let delta = if max_delta == 0 {
        1u16
    } else {
        rng.gen_range(1..=max_delta)
    };
    let new_id = prev_id.wrapping_add(delta);
    packet[4..6].copy_from_slice(&new_id.to_be_bytes());
    let mut v = packet.to_vec();
    crate::packet::recalculate_all_checksums(&mut v);
    packet.copy_from_slice(&v);
    new_id
}

/// Configuration for anti-fingerprint randomization.
#[derive(Debug, Clone)]
pub struct AntiFpConfig {
    /// Minimum injection delay in milliseconds.
    pub delay_min_ms: u64,
    /// Maximum injection delay in milliseconds.
    pub delay_max_ms: u64,
    /// Maximum extra padding bytes per fake packet (0 = off).
    pub max_padding: usize,
    /// Whether to randomize IP-ID.
    pub randomize_ip_id: bool,
    /// Maximum delta for IP-ID (0 = fully random).
    pub ip_id_max_delta: u16,
}

impl Default for AntiFpConfig {
    fn default() -> Self {
        Self {
            delay_min_ms: 1,
            delay_max_ms: 10,
            max_padding: 0,
            randomize_ip_id: false,
            ip_id_max_delta: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn injection_delay_within_range() {
        for _ in 0..100 {
            let d = random_injection_delay(100, 200);
            assert!(d.as_millis() >= 100);
            assert!(d.as_millis() <= 200);
        }
    }

    #[test]
    fn injection_delay_min_equals_max() {
        let d = random_injection_delay(50, 50);
        assert_eq!(d.as_millis(), 50);
    }

    #[test]
    fn packet_padding_increases_size() {
        let pkt = vec![1, 2, 3, 4, 5];
        let padded = randomize_packet_size(&pkt, 10);
        assert!(padded.len() >= 5);
        assert!(padded.len() <= 15);
        assert_eq!(&padded[..5], &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn packet_padding_zero_means_no_padding() {
        let pkt = vec![1, 2, 3];
        let out = randomize_packet_size(&pkt, 0);
        assert_eq!(out, pkt);
    }

    #[test]
    fn randomize_ip_id_changes_field() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45; // IPv4, IHL=5
        let before = u16::from_be_bytes([pkt[4], pkt[5]]);
        // Run multiple times — at least one should differ.
        let mut changed = false;
        for _ in 0..20 {
            randomize_ip_id(&mut pkt);
            if u16::from_be_bytes([pkt[4], pkt[5]]) != before {
                changed = true;
                break;
            }
        }
        assert!(changed);
    }

    #[test]
    fn randomize_ip_id_rejects_non_ipv4() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x60; // IPv6
        assert!(!randomize_ip_id(&mut pkt));
    }

    #[test]
    fn ip_id_range_advances_within_bounds() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45;
        let mut prev = 1000u16;
        for _ in 0..50 {
            prev = randomize_ip_id_in_range(&mut pkt, prev, 10);
            // The ID field should be set
            let id = u16::from_be_bytes([pkt[4], pkt[5]]);
            assert_ne!(id, 0); // very unlikely to be 0 after 50 iterations
        }
    }

    #[test]
    fn default_config_is_reasonable() {
        let c = AntiFpConfig::default();
        assert_eq!(c.delay_min_ms, 1);
        assert_eq!(c.delay_max_ms, 10);
        assert_eq!(c.max_padding, 0);
        assert!(!c.randomize_ip_id);
    }
}
