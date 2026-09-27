//! geedge — evasion based on leaked commercial firewall source code
//! Based on USENIX Security 2026 "Technical Analysis of the Geedge Networks Firewall Source Code Leak"
//! Geedge firewall does:
//! - Fast SNI extraction by scanning for 0x0000 extension type
//! - Assumes SNI is at fixed offset, doesn't handle fragmentation
//! - Fails on: IP literal SNI, trailing dot, case randomization, GREASE ext types, padded records
//!
//! This module provides Geedge-specific evasion techniques.

use crate::error::DpiGuardError;
use rand::Rng;

/// SNI as IP literal (RFC 6066 says SNI must NOT be IP literal, but Geedge may skip it)
/// Some DPI parsers check if SNI is IP and skip filtering (to avoid breaking IP-based virtual hosting)
pub fn sni_as_ip_literal(ip: std::net::IpAddr) -> Vec<u8> {
    ip.to_string().into_bytes()
}

/// Add TLS record padding (RFC 8446 padding extension) to confuse length-based fingerprinting
/// Padding extension type 0x0015, payload = zeros
pub fn add_tls_padding_extension(record: &[u8], pad_len: usize) -> Result<Vec<u8>, DpiGuardError> {
    if pad_len > 1024 {
        return Err(DpiGuardError::OutOfRange("padding too large".into()));
    }
    let padding = vec![0u8; pad_len];
    crate::fragmentation::inject_hidden_sni_in_unknown_ext(record, &padding, 0x0015)
        .map_err(|e| DpiGuardError::OutOfRange(format!("padding inject failed: {e}")))
}

/// Random-length padding inflation (2026 roadmap #2, RFC 7685): grow the
/// ClientHello by a *random* amount per connection. This breaks both
/// fixed-size ClientHello fingerprints (the classic 517-byte shape that
/// offset-based extractors anchor on) and DPIs with small reassembly
/// buffers. The pad is a standard TLS padding extension (type 0x0015),
/// which a standards-compliant server ignores. `max_pad` is clamped to the
/// same 1024-byte ceiling as [`add_tls_padding_extension`].
pub fn inflate_padding_random(
    record: &[u8],
    min_pad: usize,
    max_pad: usize,
) -> Result<Vec<u8>, DpiGuardError> {
    let max_pad = max_pad.min(1024);
    if min_pad > max_pad {
        return Err(DpiGuardError::OutOfRange(
            "padding inflation min_pad > max_pad".into(),
        ));
    }
    let pad = rand::thread_rng().gen_range(min_pad..=max_pad);
    add_tls_padding_extension(record, pad)
}

/// Geedge assumes SNI is the first extension; putting GREASE extensions
/// *before* it shifts the SNI to an offset a naive extractor does not look at.
///
/// This really prepends now. Each GREASE extension is `type(2) | len(2) |
/// 4 zero bytes` = 8 bytes, inserted at the very start of the extension
/// block, and the three length fields that cover that block (record length,
/// handshake length, extensions length) are grown by the same delta so the
/// ClientHello stays structurally valid and a real server still parses it.
///
/// If the record has no SNI extension there is no reliable set of offsets to
/// fix up, so the call falls back to appending the same extensions through
/// [`crate::fragmentation::inject_hidden_sni_in_unknown_ext`] — which still
/// moves the SNI, just from the other end.
pub fn prepend_grease_extensions(record: &[u8], count: usize) -> Result<Vec<u8>, DpiGuardError> {
    if count == 0 {
        return Ok(record.to_vec());
    }
    if count > 10 {
        return Err(DpiGuardError::OutOfRange("too many GREASE exts".into()));
    }

    let mut grease = Vec::with_capacity(count * 8);
    for _ in 0..count {
        let grease_type = crate::sni_mutations::random_disguise_type();
        grease.extend_from_slice(&grease_type.to_be_bytes());
        grease.extend_from_slice(&4u16.to_be_bytes());
        grease.extend_from_slice(&[0u8; 4]);
    }

    let info = crate::fragmentation::parse_client_hello(record)?;
    let (record_len_off, handshake_len_off, extensions_len_off) = match &info.sni {
        Some(loc) => (
            loc.record_len_off,
            loc.handshake_len_off,
            loc.extensions_len_off,
        ),
        // No SNI: nothing to shift, and no offsets to trust.
        None => {
            let mut out = record.to_vec();
            for _ in 0..count {
                let grease_type = crate::sni_mutations::random_disguise_type();
                out = crate::fragmentation::inject_hidden_sni_in_unknown_ext(
                    &out,
                    &[0u8; 4],
                    grease_type,
                )?;
            }
            return Ok(out);
        }
    };
    let exts = crate::fragmentation::list_extensions(record)?;
    let first = exts.first().ok_or(DpiGuardError::OutOfRange(
        "no extensions to prepend to".into(),
    ))?;
    // body_start skips the extension's own type(2) + length(2).
    if first.body_start < 4 {
        return Err(DpiGuardError::OutOfRange(
            "extension offset before record start".into(),
        ));
    }
    let insert_at = first.body_start - 4;
    if insert_at <= extensions_len_off + 1 {
        return Err(DpiGuardError::OutOfRange(
            "extension block offset out of order".into(),
        ));
    }

    let mut out = Vec::with_capacity(record.len() + grease.len());
    out.extend_from_slice(&record[..insert_at]);
    out.extend_from_slice(&grease);
    out.extend_from_slice(&record[insert_at..]);

    let delta = grease.len() as u16;
    // Record length and extensions length are 2-byte big-endian fields.
    for off in [record_len_off, extensions_len_off] {
        need_two(&out, off)?;
        let old = u16::from_be_bytes([out[off], out[off + 1]]);
        let new = old.checked_add(delta).ok_or(DpiGuardError::OutOfRange(
            "GREASE prepend would overflow a TLS length field".into(),
        ))?;
        out[off..off + 2].copy_from_slice(&new.to_be_bytes());
    }
    // The handshake length is a **3-byte** (u24) big-endian field. Patching
    // it with a u16 add would add `delta << 8` and silently corrupt every
    // produced ClientHello (parse_client_hello then rejects the record).
    if handshake_len_off + 3 > out.len() {
        return Err(DpiGuardError::PacketTooShort {
            need: handshake_len_off + 3,
            have: out.len(),
        });
    }
    let hs = (u32::from(out[handshake_len_off]) << 16)
        | (u32::from(out[handshake_len_off + 1]) << 8)
        | u32::from(out[handshake_len_off + 2]);
    let new_hs = hs
        .checked_add(u32::from(delta))
        .ok_or(DpiGuardError::OutOfRange(
            "GREASE prepend would overflow the handshake length".into(),
        ))?;
    if new_hs > 0xFF_FFFF {
        return Err(DpiGuardError::OutOfRange(
            "GREASE prepend would overflow the 3-byte handshake length".into(),
        ));
    }
    let b = new_hs.to_be_bytes();
    out[handshake_len_off] = b[1];
    out[handshake_len_off + 1] = b[2];
    out[handshake_len_off + 2] = b[3];
    Ok(out)
}

/// Bounds-check a 2-byte big-endian field before rewriting it in place.
fn need_two(buf: &[u8], off: usize) -> Result<(), DpiGuardError> {
    if off + 2 > buf.len() {
        return Err(DpiGuardError::PacketTooShort {
            need: off + 2,
            have: buf.len(),
        });
    }
    Ok(())
}

/// Split ClientHello across multiple TLS records (record injection)
/// Geneva-style: inject Alert or Heartbeat record before real ClientHello
/// Some DPI only inspects first record
pub fn inject_fake_record_before_hello(hello: &[u8], fake_type: u8) -> Vec<u8> {
    // fake_type: 0x15 = Alert, 0x14 = ChangeCipherSpec, 0x18 = Heartbeat
    let mut out = Vec::with_capacity(5 + 2 + hello.len());
    out.push(fake_type);
    out.extend_from_slice(&0x0303u16.to_be_bytes()); // version
    out.extend_from_slice(&2u16.to_be_bytes()); // length
    out.extend_from_slice(&[0x00, 0x00]); // payload
    out.extend_from_slice(hello);
    out
}

/// IP-level fragmentation evasion (GoodbyeDPI style)
/// Split IPv4 packet into fragments with MF flag
/// This bypasses DPI that doesn't reassemble IP fragments
pub fn should_use_ip_fragmentation(payload_len: usize, mtu: usize) -> bool {
    // Use IP frag when payload > MTU and DPI is known to not reassemble (Geedge, Henan)
    payload_len > mtu.saturating_sub(20)
}

/// Check if SNI would be missed by Geedge's naive extractor
/// Geedge looks for: extension type 0x0000 at fixed offset, SNI list len, name type 0
pub fn would_geedge_miss_sni(record: &[u8]) -> bool {
    // If SNI ext type is not 0x0000, Geedge misses
    if crate::fragmentation::sni_bytes(record).is_none() {
        return true;
    }
    // If SNI has trailing dot, some Geedge versions miss
    if let Some(sni) = crate::fragmentation::sni_bytes(record) {
        if sni.last() == Some(&b'.') {
            return true;
        }
        // IP literal
        if sni
            .iter()
            .all(|&b| b.is_ascii_digit() || b == b'.' || b == b':')
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fragmentation;
    use crate::fragmentation::encode_client_hello;

    #[test]
    fn ip_literal_sni_is_ip_string() {
        let ip: std::net::IpAddr = "1.1.1.1".parse().unwrap();
        let sni = sni_as_ip_literal(ip);
        assert_eq!(sni, b"1.1.1.1");
    }

    #[test]
    fn padding_extension_grows_record() {
        let record = encode_client_hello("example.com");
        let padded = add_tls_padding_extension(&record, 32).unwrap();
        assert!(padded.len() > record.len());
    }

    #[test]
    fn random_padding_inflation_is_in_range_and_varies() {
        let record = encode_client_hello("example.com");
        let base = record.len();
        let mut deltas = std::collections::HashSet::new();
        for _ in 0..40 {
            let padded = inflate_padding_random(&record, 64, 384).unwrap();
            let delta = padded.len() - base;
            // 4-byte extension header + pad body in [64, 384].
            assert!((64 + 4..=384 + 4).contains(&delta), "delta {delta}");
            // Record stays structurally valid.
            let rec_len = u16::from_be_bytes([padded[3], padded[4]]) as usize;
            assert_eq!(5 + rec_len, padded.len());
            deltas.insert(delta);
        }
        // Random length: 40 draws over a 320-wide range cannot all collide.
        assert!(deltas.len() > 1);
    }

    #[test]
    fn random_padding_inflation_validates_bounds() {
        let record = encode_client_hello("example.com");
        assert!(inflate_padding_random(&record, 500, 100).is_err());
        // max_pad clamps to the 1024 ceiling instead of erroring.
        assert!(inflate_padding_random(&record, 1024, 5000).is_ok());
    }

    #[test]
    fn grease_prepend_grows() {
        let record = encode_client_hello("example.com");
        let with_grease = prepend_grease_extensions(&record, 2).unwrap();
        assert!(with_grease.len() > record.len());
    }

    /// Regression: the 3-byte handshake length used to be patched as a u16,
    /// which added `delta << 8` and produced a ClientHello that
    /// `parse_client_hello` (and every real server) rejected. Prepending
    /// GREASE must keep the record structurally valid AND preserve the SNI.
    #[test]
    fn grease_prepend_keeps_record_parseable() {
        for count in 1..=3usize {
            for sni in ["example.com", "example.com.", "hcaptcha.com"] {
                let record = encode_client_hello(sni);
                let with_grease = prepend_grease_extensions(&record, count).unwrap();
                assert_eq!(
                    fragmentation::sni_bytes(&with_grease).as_deref(),
                    Some(sni.as_bytes()),
                    "SNI lost/corrupted after prepending {count} GREASE exts"
                );
                // The GREASE exts must sit BEFORE the SNI extension (that is
                // the whole point: shift the SNI off the fixed offset).
                let sni_before = fragmentation::list_extensions(&record)
                    .unwrap()
                    .iter()
                    .find(|e| e.ext_type == 0x0000)
                    .unwrap()
                    .body_start;
                let exts = fragmentation::list_extensions(&with_grease).unwrap();
                let sni_after = exts
                    .iter()
                    .find(|e| e.ext_type == 0x0000)
                    .unwrap()
                    .body_start;
                assert!(
                    sni_after > sni_before,
                    "SNI ext no longer shifted past GREASE"
                );
                assert_eq!(sni_after - sni_before, count * 8);
            }
        }
    }

    /// Padding rides on inject_hidden_sni_in_unknown_ext; assert it too
    /// keeps the record parseable after the geedge prepend (the exact order
    /// apply_client_hello uses: splice -> grease -> padding).
    #[test]
    fn padding_after_grease_keeps_record_parseable() {
        let record = encode_client_hello("example.com.");
        let greased = prepend_grease_extensions(&record, 2).unwrap();
        let padded = add_tls_padding_extension(&greased, 17).unwrap();
        assert_eq!(
            fragmentation::sni_bytes(&padded).as_deref(),
            Some(&b"example.com."[..])
        );
    }

    #[test]
    fn fake_record_injection() {
        let hello = encode_client_hello("example.com");
        let injected = inject_fake_record_before_hello(&hello, 0x15);
        assert_eq!(injected[0], 0x15);
        assert!(injected.windows(11).any(|w| w == b"example.com"));
    }

    #[test]
    fn geedge_miss_detection() {
        let record = encode_client_hello("example.com");
        assert!(!would_geedge_miss_sni(&record));
        let disguised = crate::fragmentation::disguise_sni_extension_type(&record, 0x0A0A).unwrap();
        assert!(would_geedge_miss_sni(&disguised));
        let with_dot = crate::fragmentation::encode_client_hello("example.com.");
        // Our simple encoder for trailing dot still has SNI bytes with dot, but sni_bytes returns Some
        // Geedge miss logic checks trailing dot
        assert!(would_geedge_miss_sni(&with_dot));
    }

    #[test]
    fn ip_frag_decision() {
        assert!(should_use_ip_fragmentation(2000, 1500));
        assert!(!should_use_ip_fragmentation(100, 1500));
    }
}
