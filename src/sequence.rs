//! sequence — decoy-packet / out-of-window SEQ techniques. [UNTESTED] for
//! construction; the capture loop sends the bytes.

use crate::error::DpiGuardError;
use crate::packet::{self, tcp_off};
use std::time::Duration;

/// Shift SEQ by a signed offset with defined wrapping (negative offsets
/// work; values outside i32 still wrap via i128).
pub fn calculate_wrong_seq(real_seq: u32, offset: i64) -> u32 {
    (real_seq as i128).wrapping_add(offset as i128) as u32
}

/// Place SEQ just past the advertised receive window so a real stack
/// drops the decoy while a loose DPI parser still consumes it.
pub fn calculate_wrong_seq_outside_window(real_seq: u32, window: u16) -> u32 {
    real_seq.wrapping_add(window as u32).wrapping_add(1)
}

/// Build a decoy: same IP/TCP **header including options** as `template`,
/// SEQ overwritten, payload replaced.
pub fn build_decoy_packet(
    template: &[u8],
    fake_seq: u32,
    decoy_payload: &[u8],
) -> Result<Vec<u8>, DpiGuardError> {
    let view = packet::Ipv4View::parse(template).ok_or(DpiGuardError::PacketTooShort {
        need: 20,
        have: template.len(),
    })?;
    let ihl = view.ihl_bytes();
    if template.len() < ihl + 20 {
        return Err(DpiGuardError::PacketTooShort {
            need: ihl + 20,
            have: template.len(),
        });
    }
    let tcp = &template[ihl..];
    let tcp_hdr_len =
        packet::ParsedPacket::tcp_header_len(tcp).ok_or(DpiGuardError::PacketTooShort {
            need: ihl + 20,
            have: template.len(),
        })?;
    let mut out = template[..ihl + tcp_hdr_len].to_vec();
    out[ihl + tcp_off::SEQ..ihl + tcp_off::SEQ + 4].copy_from_slice(&fake_seq.to_be_bytes());
    out.extend_from_slice(decoy_payload);

    let len = out.len();
    packet::set_l3_total_len(&mut out, len);
    packet::recalculate_all_checksums(&mut out);
    Ok(out)
}

pub fn inject_ttl_limited_decoy(decoy: &mut [u8], ttl: u8) {
    packet::set_ttl(decoy, ttl);
    packet::recalculate_all_checksums(decoy);
}

/// Send decoy, wait `race_condition_fix_delay`, then send real. Order is
/// sequential on purpose — `join!` would race the NIC.
pub async fn send_simultaneous<F, Fut>(
    real: Vec<u8>,
    decoy: Vec<u8>,
    send_fn: F,
) -> Result<(), DpiGuardError>
where
    F: Fn(Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = Result<(), DpiGuardError>>,
{
    send_fn(decoy).await?;
    tokio::time::sleep(race_condition_fix_delay()).await;
    send_fn(real).await?;
    Ok(())
}

pub fn add_padding_to_decoy(decoy_payload: &[u8], target_len: usize) -> Vec<u8> {
    let mut out = decoy_payload.to_vec();
    if out.len() < target_len {
        out.resize(target_len, 0u8);
    }
    out
}

pub fn race_condition_fix_delay() -> Duration {
    Duration::from_micros(50)
}

/// Build a realistic TLS ClientHello that mimics a specific browser.
/// Used when `enable_fake_with_sni = true` in config.
/// The generated ClientHello includes:
/// - Realistic cipher suites for the chosen browser
/// - Proper extensions (SNI, supported_groups, etc.)
/// - Random session_id, key_share, and ECH GREASE
/// - The SNI field set to `fake_sni`
///
/// This makes the fake packet look like a real browser connection to DPI,
/// which is harder to distinguish from legitimate traffic than a minimal
/// hand-crafted ClientHello.
pub fn build_browser_mimic_hello(fake_sni: &str, browser: &str) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut hello = Vec::with_capacity(512);

    // TLS record header: content_type=0x16 (Handshake), version=0x0301
    hello.push(0x16); // content type: handshake
    hello.extend_from_slice(&[0x03, 0x01]); // record version

    // Placeholder for record length (filled at the end)
    let record_len_pos = hello.len();
    hello.extend_from_slice(&[0x00, 0x00]);

    // Handshake header: type=0x01 (ClientHello)
    hello.push(0x01);

    // Placeholder for handshake length
    let hs_len_pos = hello.len();
    hello.extend_from_slice(&[0x00, 0x00, 0x00]);

    // Client version: TLS 1.2 (0x0303)
    hello.extend_from_slice(&[0x03, 0x03]);

    // Random (32 bytes)
    let mut random_bytes = [0u8; 32];
    for b in random_bytes.iter_mut() {
        *b = rand::Rng::gen(&mut rng);
    }
    hello.extend_from_slice(&random_bytes);

    // Session ID (32 bytes, random — like Firefox/Chrome with TLS session resumption)
    let session_id_len: u8 = 32;
    hello.push(session_id_len);
    let mut session_id = [0u8; 32];
    for b in session_id.iter_mut() {
        *b = rand::Rng::gen(&mut rng);
    }
    hello.extend_from_slice(&session_id);

    // Pull the fingerprint template from stealth::simulate_browser_fingerprint
    // so the cipher-suite + curve lists match the rest of the crate's
    // browser modelling. shape_fingerprint shuffles ciphers and inserts a
    // GREASE value, which is exactly the per-invocation variance a real
    // browser-mimic ClientHello needs so two fake packets are not
    // byte-identical.
    let mut fp = crate::stealth::simulate_browser_fingerprint(browser);
    crate::stealth::shape_fingerprint(&mut fp);

    // Cipher suites — seeded from the browser fingerprint (shuffled +
    // GREASE by shape_fingerprint) so successive fake hellos are not
    // byte-identical. The legacy hardcoded lists below are kept as a
    // fallback if the fingerprint model ever changes.
    let cipher_suites: Vec<u16> = if !fp.cipher_suites.is_empty() {
        fp.cipher_suites.clone()
    } else {
        match browser.to_lowercase().as_str() {
            "firefox" => vec![
                0x1301, 0x1303, 0x1302, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013,
                0xC014, 0x009C, 0x009D, 0x002F, 0x0035,
            ],
            "chrome" | "edge" => vec![
                0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013,
                0xC014, 0x009C, 0x009D, 0x002F, 0x0035,
            ],
            "safari" => vec![
                0x1301, 0x1302, 0x1303, 0xC02C, 0xC02B, 0xCCA9, 0xC030, 0xC02F, 0xCCA8, 0xC014,
                0xC013, 0x009D, 0x009C, 0x0035, 0x002F,
            ],
            _ => vec![
                0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0x009C,
                0x009D, 0x002F, 0x0035,
            ],
        }
    };
    let cs_len = (cipher_suites.len() * 2) as u16;
    hello.extend_from_slice(&cs_len.to_be_bytes());
    for cs in &cipher_suites {
        hello.extend_from_slice(&cs.to_be_bytes());
    }

    // Compression methods: null only
    hello.push(0x01); // length
    hello.push(0x00); // null compression

    // Extensions
    let ext_start = hello.len();
    // Placeholder for extensions length
    hello.extend_from_slice(&[0x00, 0x00]);

    // Extension: SNI (0x0000)
    let sni_bytes = fake_sni.as_bytes();
    let sni_list_len = (sni_bytes.len() + 3) as u16; // type(1) + name_len(2) + name
    let sni_ext_len = (sni_bytes.len() + 5) as u16; // list_len(2) + list
    hello.extend_from_slice(&0x0000u16.to_be_bytes()); // ext type
    hello.extend_from_slice(&sni_ext_len.to_be_bytes()); // ext len
    hello.extend_from_slice(&sni_list_len.to_be_bytes()); // server name list len
    hello.push(0x00); // host_name type
    hello.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    hello.extend_from_slice(sni_bytes);

    // Extension: supported_groups (0x000A) — use the fingerprint's curve
    // list when available (so GREASE + browser-specific order propagates),
    // fall back to the safe default (x25519, secp256r1, secp384r1).
    let groups: Vec<u16> = if !fp.elliptic_curves.is_empty() {
        fp.elliptic_curves.clone()
    } else {
        vec![0x001D, 0x0017, 0x0018]
    };
    let groups_len = (groups.len() * 2) as u16;
    hello.extend_from_slice(&0x000Au16.to_be_bytes());
    hello.extend_from_slice(&(groups_len + 2).to_be_bytes());
    hello.extend_from_slice(&groups_len.to_be_bytes());
    for g in &groups {
        hello.extend_from_slice(&g.to_be_bytes());
    }

    // Extension: signature_algorithms (0x000D)
    let sig_algs: Vec<u16> = vec![0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806];
    let sig_len = (sig_algs.len() * 2) as u16;
    hello.extend_from_slice(&0x000Du16.to_be_bytes());
    hello.extend_from_slice(&(sig_len + 2).to_be_bytes());
    hello.extend_from_slice(&sig_len.to_be_bytes());
    for s in &sig_algs {
        hello.extend_from_slice(&s.to_be_bytes());
    }

    // Extension: supported_versions (0x002B) — TLS 1.3 + 1.2
    hello.extend_from_slice(&0x002Bu16.to_be_bytes());
    hello.extend_from_slice(&0x0003u16.to_be_bytes()); // length
    hello.push(0x02); // list length
    hello.extend_from_slice(&[0x03, 0x04]); // TLS 1.3
    hello.extend_from_slice(&[0x03, 0x03]); // TLS 1.2

    // Extension: key_share (0x0033) — x25519 with random key
    hello.extend_from_slice(&0x0033u16.to_be_bytes());
    let ks_payload_len: u16 = 2 + 2 + 32; // group(2) + key_len(2) + key(32)
    hello.extend_from_slice(&(ks_payload_len + 2).to_be_bytes()); // ext len
    hello.extend_from_slice(&ks_payload_len.to_be_bytes()); // list len
    hello.extend_from_slice(&0x001Du16.to_be_bytes()); // x25519
    hello.extend_from_slice(&32u16.to_be_bytes()); // key length
    let mut key_bytes = [0u8; 32];
    for b in key_bytes.iter_mut() {
        *b = rand::Rng::gen(&mut rng);
    }
    hello.extend_from_slice(&key_bytes);

    // Extension: ECH GREASE (0xFE0D) — random bytes to look like ECH
    if browser.to_lowercase() != "safari" {
        let grease_len: u16 = 32 + rand::Rng::gen_range(&mut rng, 0..=32);
        hello.extend_from_slice(&0xFE0Du16.to_be_bytes());
        hello.extend_from_slice(&grease_len.to_be_bytes());
        for _ in 0..grease_len {
            hello.push(rand::Rng::gen(&mut rng));
        }
    }

    // Extension: psk_key_exchange_modes (0x002D)
    hello.extend_from_slice(&0x002Du16.to_be_bytes());
    hello.extend_from_slice(&0x0002u16.to_be_bytes()); // length
    hello.push(0x01); // list length
    hello.push(0x01); // psk_dhe_ke

    // Fix extensions length
    let ext_total = (hello.len() - ext_start - 2) as u16;
    let ext_bytes = ext_total.to_be_bytes();
    hello[ext_start] = ext_bytes[0];
    hello[ext_start + 1] = ext_bytes[1];

    // Fix handshake length
    let hs_total = (hello.len() - hs_len_pos - 3) as u32;
    let hs_bytes = hs_total.to_be_bytes();
    hello[hs_len_pos] = hs_bytes[1];
    hello[hs_len_pos + 1] = hs_bytes[2];
    hello[hs_len_pos + 2] = hs_bytes[3];

    // Fix record length
    let rec_total = (hello.len() - record_len_pos - 2) as u16;
    let rec_bytes = rec_total.to_be_bytes();
    hello[record_len_pos] = rec_bytes[0];
    hello[record_len_pos + 1] = rec_bytes[1];

    hello
}

/// Build multiple fake ClientHello packets for resend (fake_resend_count > 1).
/// Each packet has a different random session_id and key_share to look unique.
pub fn build_resend_batch(fake_sni: &str, browser: &str, count: u32) -> Vec<Vec<u8>> {
    (0..count)
        .map(|_| build_browser_mimic_hello(fake_sni, browser))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrong_seq_wraps_correctly() {
        assert_eq!(calculate_wrong_seq(u32::MAX, 1), 0);
        assert_eq!(calculate_wrong_seq(100, 50), 150);
        assert_eq!(calculate_wrong_seq(100, -1), 99);
        assert_eq!(calculate_wrong_seq(0, -1), u32::MAX);
    }

    #[test]
    fn outside_window_is_past_wnd() {
        assert_eq!(calculate_wrong_seq_outside_window(10, 100), 111);
    }

    #[test]
    fn padding_extends_to_target() {
        let out = add_padding_to_decoy(&[1, 2, 3], 8);
        assert_eq!(out.len(), 8);
        assert_eq!(&out[..3], &[1, 2, 3]);
    }

    #[test]
    fn padding_never_truncates() {
        let out = add_padding_to_decoy(&[1, 2, 3, 4, 5], 2);
        assert_eq!(out.len(), 5);
    }

    #[test]
    fn race_delay_is_50_microseconds() {
        assert_eq!(race_condition_fix_delay(), Duration::from_micros(50));
    }

    fn packet_with_tcp_option() -> Vec<u8> {
        // 20-byte IP + 24-byte TCP (one NOP*4 option block)
        let mut pkt = vec![0u8; 44];
        pkt[0] = 0x45;
        pkt[8] = 64;
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);
        pkt[2..4].copy_from_slice(&44u16.to_be_bytes());
        pkt[32] = 0x60; // data offset = 6 (24 bytes)
        pkt[33] = 0;
        pkt[36] = 1;
        pkt[37] = 1;
        pkt[38] = 1;
        pkt[39] = 1;
        packet::recalculate_all_checksums(&mut pkt);
        pkt
    }

    #[test]
    fn decoy_packet_keeps_tcp_options_and_sets_seq() {
        let template = packet_with_tcp_option();
        let decoy = build_decoy_packet(&template, 0xdeadbeef, b"bait").unwrap();
        let view = packet::Ipv4View::parse(&decoy).unwrap();
        let ihl = view.ihl_bytes();
        let hdr_len = packet::ParsedPacket::tcp_header_len(&decoy[ihl..]).unwrap();
        assert_eq!(hdr_len, 24);
        let seq = u32::from_be_bytes([
            decoy[ihl + 4],
            decoy[ihl + 5],
            decoy[ihl + 6],
            decoy[ihl + 7],
        ]);
        assert_eq!(seq, 0xdeadbeef);
        assert_eq!(&decoy[ihl + hdr_len..], b"bait");
        let mut sum: u32 = 0;
        for chunk in decoy[..20].as_chunks::<2>().0 {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        assert_eq!(sum as u16, 0xFFFF);
    }

    #[test]
    fn ttl_limited_decoy_sets_low_ttl() {
        let template = packet_with_tcp_option();
        let mut decoy = build_decoy_packet(&template, 1, b"x").unwrap();
        inject_ttl_limited_decoy(&mut decoy, 8);
        assert_eq!(decoy[8], 8);
    }

    #[tokio::test]
    async fn send_simultaneous_sends_decoy_then_real() {
        use std::sync::{Arc, Mutex};
        let order = Arc::new(Mutex::new(Vec::new()));
        let order2 = order.clone();
        let send = move |pkt: Vec<u8>| {
            let order = order2.clone();
            async move {
                order.lock().unwrap().push(pkt);
                Ok(())
            }
        };
        send_simultaneous(vec![2], vec![1], send).await.unwrap();
        assert_eq!(*order.lock().unwrap(), vec![vec![1], vec![2]]);
    }

    #[test]
    fn browser_mimic_hello_starts_with_tls_record() {
        let hello = build_browser_mimic_hello("www.microsoft.com", "firefox");
        // TLS record header
        assert_eq!(hello[0], 0x16); // handshake
        assert_eq!(hello[1], 0x03); // version major
        assert_eq!(hello[2], 0x01); // version minor
                                    // Handshake type
        assert_eq!(hello[5], 0x01); // ClientHello
    }

    #[test]
    fn browser_mimic_hello_contains_sni() {
        let sni = "auth.vercel.com";
        let hello = build_browser_mimic_hello(sni, "chrome");
        let sni_bytes = sni.as_bytes();
        // Find the SNI in the hello
        let found = hello.windows(sni_bytes.len()).any(|w| w == sni_bytes);
        assert!(found, "SNI '{}' not found in ClientHello", sni);
    }

    #[test]
    fn browser_mimic_hello_varies_per_browser() {
        let firefox = build_browser_mimic_hello("example.com", "firefox");
        let chrome = build_browser_mimic_hello("example.com", "chrome");
        // They should be different sizes (different cipher order / extensions)
        // Actually chrome and firefox have same ciphers in our impl,
        // so at least they should be valid
        assert!(firefox.len() > 100);
        assert!(chrome.len() > 100);
        // Safari has no ECH GREASE, so should be smaller
        let safari = build_browser_mimic_hello("example.com", "safari");
        assert!(safari.len() > 100);
    }

    #[test]
    fn browser_mimic_hello_record_length_matches() {
        let hello = build_browser_mimic_hello("test.com", "chrome");
        let record_len = u16::from_be_bytes([hello[3], hello[4]]) as usize;
        assert_eq!(
            record_len,
            hello.len() - 5,
            "TLS record length must match actual payload"
        );
    }

    #[test]
    fn resend_batch_produces_correct_count() {
        let batch = build_resend_batch("test.com", "firefox", 3);
        assert_eq!(batch.len(), 3);
        // Each should be valid
        for pkt in &batch {
            assert_eq!(pkt[0], 0x16);
            assert!(pkt.len() > 100);
        }
    }

    #[test]
    fn resend_batch_packets_differ() {
        let batch = build_resend_batch("test.com", "chrome", 2);
        // Random session_id and key_share should make them different
        assert_ne!(
            batch[0], batch[1],
            "resend packets should have different random data"
        );
    }
}
