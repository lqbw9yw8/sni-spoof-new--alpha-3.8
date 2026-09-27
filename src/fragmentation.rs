//! fragmentation — locate SNI, splice it, split ClientHello across TCP
//! segments. [UNTESTED] for byte math; live send is the capture loop.
//!
//! `fragment_sni_byte_chunk` returns **TCP-payload slices** of the original
//! TLS record (before-SNI / each SNI byte / after-SNI). They are not
//! wrapped as new TLS records — Zapret-style evasion splits at the TCP
//! layer so a stateless DPI box never sees the full name in one segment.

use crate::error::DpiGuardError;

/// Offsets of every length field that must move when the SNI host_name
/// changes size. All offsets are absolute in the TLS record buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SniLocation {
    pub name_start: usize,
    pub name_end: usize,
    pub name_len_off: usize,
    pub list_len_off: usize,
    pub ext_len_off: usize,
    pub extensions_len_off: usize,
    pub handshake_len_off: usize,
    pub record_len_off: usize,
}

#[derive(Debug, Clone)]
pub struct ClientHelloInfo {
    pub sni: Option<SniLocation>,
    /// Byte offset of the first cipher-suite value (after the 2-byte length).
    pub cipher_suites_off: usize,
    /// Length in bytes of the cipher-suite list (always even).
    pub cipher_suites_len: usize,
}

fn need(record: &[u8], p: usize, n: usize) -> Result<(), DpiGuardError> {
    // Guard against `p + n` wrapping on a corrupt length field.
    if n > record.len() || p > record.len() - n {
        Err(DpiGuardError::PacketTooShort {
            need: p.saturating_add(n),
            have: record.len(),
        })
    } else {
        Ok(())
    }
}

/// Walk a TLS record that should contain a ClientHello.
pub fn parse_client_hello(record: &[u8]) -> Result<ClientHelloInfo, DpiGuardError> {
    let mut pos = 0usize;
    need(record, pos, 5)?;
    if record[0] != 0x16 {
        return Err(DpiGuardError::NotClientHello);
    }
    // TLS 1.0–1.2 record version 0x03 0x01/02/03; TLS 1.3 still uses 0x03 0x01
    // or 0x03 0x03 on the record layer. Reject clearly non-TLS.
    if record[1] != 0x03 || record[2] < 0x01 {
        return Err(DpiGuardError::NotClientHello);
    }
    let record_len = u16::from_be_bytes([record[3], record[4]]) as usize;
    let record_len_off = 3;
    pos += 5;
    if 5 + record_len > record.len() {
        // Truncated — caller may be reassembling.
        return Err(DpiGuardError::PacketTooShort {
            need: 5 + record_len,
            have: record.len(),
        });
    }

    need(record, pos, 4)?;
    if record[pos] != 0x01 {
        return Err(DpiGuardError::NotClientHello);
    }
    let handshake_len_off = pos + 1;
    let hs_len =
        u32::from_be_bytes([0, record[pos + 1], record[pos + 2], record[pos + 3]]) as usize;
    pos += 4;
    // First handshake message must fit in this record.
    if pos + hs_len > 5 + record_len {
        return Err(DpiGuardError::NotClientHello);
    }

    need(record, pos, 2 + 32)?;
    pos += 2 + 32; // client_version + random

    need(record, pos, 1)?;
    let sid_len = record[pos] as usize;
    need(record, pos + 1, sid_len)?;
    pos += 1 + sid_len;

    need(record, pos, 2)?;
    let cs_len = u16::from_be_bytes([record[pos], record[pos + 1]]) as usize;
    if cs_len % 2 == 1 {
        return Err(DpiGuardError::NotClientHello);
    }
    pos += 2;
    need(record, pos, cs_len)?;
    let cipher_suites_off = pos;
    let cipher_suites_len = cs_len;
    pos += cs_len;

    need(record, pos, 1)?;
    let comp_len = record[pos] as usize;
    need(record, pos + 1, comp_len)?;
    pos += 1 + comp_len;

    need(record, pos, 2)?;
    let extensions_len_off = pos;
    let ext_total = u16::from_be_bytes([record[pos], record[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_total;
    if ext_end > record.len() || ext_end > 5 + record_len {
        return Err(DpiGuardError::PacketTooShort {
            need: ext_end,
            have: record.len(),
        });
    }

    let mut sni = None;
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([record[pos], record[pos + 1]]);
        let ext_len_off = pos + 2;
        let ext_len = u16::from_be_bytes([record[pos + 2], record[pos + 3]]) as usize;
        let ext_body_start = pos + 4;
        if ext_body_start + ext_len > ext_end {
            return Err(DpiGuardError::NotClientHello);
        }
        if ext_type == 0x0000 && sni.is_none() {
            need(record, ext_body_start, 5)?;
            let list_len_off = ext_body_start;
            let name_type = record[ext_body_start + 2];
            let name_len_off = ext_body_start + 3;
            let name_len =
                u16::from_be_bytes([record[name_len_off], record[name_len_off + 1]]) as usize;
            let name_start = name_len_off + 2;
            let name_end = name_start + name_len;
            if name_type != 0 || name_end > ext_body_start + ext_len {
                return Err(DpiGuardError::NotClientHello);
            }
            sni = Some(SniLocation {
                name_start,
                name_end,
                name_len_off,
                list_len_off,
                ext_len_off,
                extensions_len_off,
                handshake_len_off,
                record_len_off,
            });
        }
        pos = ext_body_start + ext_len;
    }

    Ok(ClientHelloInfo {
        sni,
        cipher_suites_off,
        cipher_suites_len,
    })
}

/// Return `(name_start, name_end)` absolute in `record` (NOT exclusive of
/// the 5-byte TLS record header — they index the full buffer).
pub fn calculate_smart_split_points(record: &[u8]) -> Result<(usize, usize), DpiGuardError> {
    let info = parse_client_hello(record)?;
    let sni = info.sni.ok_or(DpiGuardError::SniNotFound)?;
    Ok((sni.name_start, sni.name_end))
}

pub fn sni_bytes(record: &[u8]) -> Option<Vec<u8>> {
    calculate_smart_split_points(record)
        .ok()
        .map(|(s, e)| record[s..e].to_vec())
}

/// One extension's type and its body span (after the 2-byte length field).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtensionSpan {
    pub ext_type: u16,
    /// Absolute offset of the first body byte (skips the 2-byte length).
    pub body_start: usize,
    /// Absolute offset one past the last body byte.
    pub body_end: usize,
}

/// Walk a ClientHello's extension list and return each extension's type and
/// body byte range. Mirrors the walk in `parse_client_hello` but exposes the
/// spans so callers (e.g. uTLS reordering) can mutate individual extension
/// payloads without re-deriving the layout.
pub fn list_extensions(record: &[u8]) -> Result<Vec<ExtensionSpan>, DpiGuardError> {
    let mut pos = 0usize;
    need(record, pos, 5)?;
    if record[0] != 0x16 {
        return Err(DpiGuardError::NotClientHello);
    }
    pos += 5;
    need(record, pos, 4)?;
    if record[pos] != 0x01 {
        return Err(DpiGuardError::NotClientHello);
    }
    pos += 4;
    need(record, pos, 2 + 32)?;
    pos += 2 + 32; // client_version + random

    need(record, pos, 1)?;
    let sid_len = record[pos] as usize;
    need(record, pos + 1, sid_len)?;
    pos += 1 + sid_len;

    need(record, pos, 2)?;
    let cs_len = u16::from_be_bytes([record[pos], record[pos + 1]]) as usize;
    pos += 2 + cs_len;

    need(record, pos, 1)?;
    let comp_len = record[pos] as usize;
    need(record, pos + 1, comp_len)?;
    pos += 1 + comp_len;

    need(record, pos, 2)?;
    let ext_total = u16::from_be_bytes([record[pos], record[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_total;
    if ext_end > record.len() {
        return Err(DpiGuardError::PacketTooShort {
            need: ext_end,
            have: record.len(),
        });
    }

    let mut out = Vec::new();
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([record[pos], record[pos + 1]]);
        let ext_len = u16::from_be_bytes([record[pos + 2], record[pos + 3]]) as usize;
        let body_start = pos + 4;
        let body_end = body_start + ext_len;
        if body_end > ext_end {
            return Err(DpiGuardError::NotClientHello);
        }
        out.push(ExtensionSpan {
            ext_type,
            body_start,
            body_end,
        });
        pos = body_end;
    }
    Ok(out)
}

fn patch_u16(buf: &mut [u8], off: usize, delta: i32) {
    if buf.len() < off + 2 {
        return;
    }
    let cur = u16::from_be_bytes([buf[off], buf[off + 1]]) as i32;
    let new = (cur + delta).clamp(0, u16::MAX as i32) as u16;
    buf[off..off + 2].copy_from_slice(&new.to_be_bytes());
}

fn patch_u24(buf: &mut [u8], off: usize, delta: i32) {
    if buf.len() < off + 3 {
        return;
    }
    let cur = u32::from_be_bytes([0, buf[off], buf[off + 1], buf[off + 2]]) as i32;
    let new = (cur + delta).clamp(0, 0xFF_FFFF) as u32;
    let b = new.to_be_bytes();
    buf[off] = b[1];
    buf[off + 1] = b[2];
    buf[off + 2] = b[3];
}

/// Replace the SNI host_name and rewrite every enclosing length field so
/// the ClientHello stays structurally valid.
pub fn splice_sni(record: &[u8], new_sni: &[u8]) -> Result<Vec<u8>, DpiGuardError> {
    if new_sni.len() > u16::MAX as usize {
        return Err(DpiGuardError::OutOfRange("SNI longer than 65535".into()));
    }
    let info = parse_client_hello(record)?;
    let loc = info.sni.ok_or(DpiGuardError::SniNotFound)?;
    let old_len = loc.name_end - loc.name_start;
    let delta = new_sni.len() as i32 - old_len as i32;
    let new_record_len = (record.len() as i64) + i64::from(delta);
    // TLS record length is a u16 body length, so the complete wire record
    // cannot exceed 5 + 65535 bytes. Never let patch_u16 clamp a wrapped
    // length field and emit a structurally corrupt record.
    if new_record_len < 5 || new_record_len > 5 + i64::from(u16::MAX) {
        return Err(DpiGuardError::OutOfRange(
            "SNI splice would exceed the TLS record length limit".into(),
        ));
    }

    let mut out = Vec::with_capacity(record.len() + delta.max(0) as usize);
    out.extend_from_slice(&record[..loc.name_start]);
    out.extend_from_slice(new_sni);
    out.extend_from_slice(&record[loc.name_end..]);

    // Length fields all sit *before* name_start, so their offsets are stable.
    patch_u16(&mut out, loc.record_len_off, delta);
    patch_u24(&mut out, loc.handshake_len_off, delta);
    patch_u16(&mut out, loc.extensions_len_off, delta);
    patch_u16(&mut out, loc.ext_len_off, delta);
    patch_u16(&mut out, loc.list_len_off, delta);
    patch_u16(&mut out, loc.name_len_off, delta);
    Ok(out)
}

/// --- NEW: SNI Disguise as Unknown Extension (2025 research) ---
/// Change SNI extension type 0x0000 -> private/GREASE type so naive DPI
/// that only looks for 0x0000 misses the real SNI. Server should ignore
/// unknown extensions per RFC 8446, but will not know virtual host
/// without SNI -> may serve default cert. Use only with Aggressive / fronting.
pub fn disguise_sni_extension_type(record: &[u8], new_type: u16) -> Result<Vec<u8>, DpiGuardError> {
    let info = parse_client_hello(record)?;
    let loc = info.sni.ok_or(DpiGuardError::SniNotFound)?;
    // ext_len_off points to length field of SNI extension, type is 2 bytes before
    if loc.ext_len_off < 2 {
        return Err(DpiGuardError::NotClientHello);
    }
    let type_off = loc.ext_len_off - 2;
    if type_off + 2 > record.len() {
        return Err(DpiGuardError::PacketTooShort {
            need: type_off + 2,
            have: record.len(),
        });
    }
    let mut out = record.to_vec();
    out[type_off..type_off + 2].copy_from_slice(&new_type.to_be_bytes());
    Ok(out)
}

/// Replace visible SNI with a benign domain (domain fronting).
/// This is still using splice_sni internally but flagged as fronting
/// for strategy scoring.
pub fn front_sni_with_benign(record: &[u8], benign_sni: &[u8]) -> Result<Vec<u8>, DpiGuardError> {
    splice_sni(record, benign_sni)
}

/// Inject hidden real SNI as an unknown private extension while keeping
/// benign SNI visible as 0x0000. This is layered fronting:
/// visible SNI = benign (e.g., www.microsoft.com), hidden = real in type 0xFF01.
/// DPI that only checks first 0x0000 sees benign; server ignores unknown.
pub fn inject_hidden_sni_in_unknown_ext(
    record: &[u8],
    hidden_sni: &[u8],
    unknown_type: u16,
) -> Result<Vec<u8>, DpiGuardError> {
    if hidden_sni.len() > u16::MAX as usize {
        return Err(DpiGuardError::OutOfRange("hidden SNI too long".into()));
    }
    // Validate record is ClientHello
    let _info = parse_client_hello(record)?;
    // Re-parse to get ext_end accurately
    let mut pos = 0usize;
    need(record, pos, 5)?;
    pos += 5;
    need(record, pos, 4)?;
    pos += 4;
    need(record, pos, 2 + 32)?;
    pos += 2 + 32;
    need(record, pos, 1)?;
    let sid_len = record[pos] as usize;
    need(record, pos + 1, sid_len)?;
    pos += 1 + sid_len;
    need(record, pos, 2)?;
    let cs_len = u16::from_be_bytes([record[pos], record[pos + 1]]) as usize;
    pos += 2 + cs_len;
    need(record, pos, 1)?;
    let comp_len = record[pos] as usize;
    need(record, pos + 1, comp_len)?;
    pos += 1 + comp_len;
    need(record, pos, 2)?;
    let extensions_len_off_inner = pos;
    let ext_total = u16::from_be_bytes([record[pos], record[pos + 1]]) as usize;
    let ext_start = pos + 2;
    let ext_end = ext_start + ext_total;
    if ext_end > record.len() {
        return Err(DpiGuardError::PacketTooShort {
            need: ext_end,
            have: record.len(),
        });
    }
    // Build unknown extension: type + len + payload
    // Payload: we just put raw hidden_sni bytes (or could mimic SNI format). Use raw for simplicity.
    let ext_payload_len = hidden_sni.len();
    let mut new_ext = Vec::with_capacity(4 + ext_payload_len);
    new_ext.extend_from_slice(&unknown_type.to_be_bytes());
    new_ext.extend_from_slice(&(ext_payload_len as u16).to_be_bytes());
    new_ext.extend_from_slice(hidden_sni);

    // F-006: the TLS record length is a u16. If the hidden extension would
    // push the record past 65535 bytes, patch_u16 would silently clamp and
    // emit a corrupt record — reject instead.
    if record.len() + new_ext.len() > u16::MAX as usize {
        return Err(DpiGuardError::OutOfRange(
            "hidden SNI extension would overflow the TLS record length".into(),
        ));
    }

    // Insert new extension at end of existing extensions
    let mut out = Vec::with_capacity(record.len() + new_ext.len());
    out.extend_from_slice(&record[..ext_end]);
    out.extend_from_slice(&new_ext);
    out.extend_from_slice(&record[ext_end..]);

    // Patch lengths: extensions_len, handshake_len, record_len
    let delta = new_ext.len() as i32;
    // extensions_len_off_inner is same as earlier ext_len_off maybe
    patch_u16(&mut out, extensions_len_off_inner, delta);
    // handshake_len_off is 4 bytes before? We can get from parse info: need to find handshake_len_off
    // We have handshake_len_off = 5+1 =6? Actually record[5] is handshake type, 6..8 is length
    // Simpler: handshake_len_off = 5 +1 =6 always? No, record has 5-byte header, then handshake header 4 bytes
    // handshake_len_off is 6 (record[6..9]) in our encode. Use generic: from info or recalc
    // We'll find it via parse again for patched out? Easier: we know handshake body includes extensions, so patch handshake and record
    // handshake_len_off is at 6
    patch_u24(&mut out, 6, delta);
    patch_u16(&mut out, 3, delta);

    // Also need to keep original SNI if present - we didn't touch it
    Ok(out)
}

/// Decode a ClientHello's cipher-suite list, hand it to `f`, and write the
/// (possibly reordered) list back into `record` in place.
///
/// Returns `Ok(false)` **without touching `record`** when the hello carries
/// no list worth rewriting (< 4 bytes, i.e. fewer than two suites).
///
/// The read → modify → write cycle used to be open-coded twice — here and
/// in `utls::apply_fingerprint_to_hello` — so the bounds check and the
/// byte order existed in two places that could drift apart. Callers now
/// only supply the permutation.
///
/// `f` may reorder or replace values. It must not change the list length;
/// if it does, only the values that still fit are written back, so a
/// future caller cannot panic on the packet path.
pub fn rewrite_cipher_suites<F>(record: &mut [u8], f: F) -> Result<bool, DpiGuardError>
where
    F: FnOnce(&mut Vec<u16>),
{
    let info = parse_client_hello(record)?;
    if info.cipher_suites_len < 4 {
        return Ok(false);
    }
    let start = info.cipher_suites_off;
    let end = start + info.cipher_suites_len;
    // Same error the old inline check produced: `need` reports the absolute
    // offset it could not reach and the length it actually had.
    need(record, 0, end)?;
    let mut suites: Vec<u16> = record[start..end]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    f(&mut suites);
    let writable = suites.len().min(info.cipher_suites_len / 2);
    for (i, suite) in suites.iter().enumerate().take(writable) {
        let off = start + i * 2;
        record[off..off + 2].copy_from_slice(&suite.to_be_bytes());
    }
    Ok(true)
}

/// Shuffle the ClientHello cipher-suite list in place (same wire length).
pub fn shuffle_cipher_suites_in_hello(record: &mut [u8]) -> Result<(), DpiGuardError> {
    rewrite_cipher_suites(record, |suites| {
        crate::stealth::shuffle_cipher_suites(suites);
    })?;
    Ok(())
}

/// TCP-level split of a TLS record around the SNI: one chunk before the
/// name, one 1-byte chunk per SNI byte, one chunk after. Caller wraps
/// each chunk in its own TCP segment (`packet::tcp_segment_payload` or
/// `rebuild_with_payload`).
pub fn fragment_sni_byte_chunk(record: &[u8]) -> Result<Vec<Vec<u8>>, DpiGuardError> {
    let (sni_start, sni_end) = calculate_smart_split_points(record)?;
    let mut chunks = Vec::new();
    if sni_start > 0 {
        chunks.push(record[..sni_start].to_vec());
    }
    for &byte in &record[sni_start..sni_end] {
        chunks.push(vec![byte]);
    }
    if sni_end < record.len() {
        chunks.push(record[sni_end..].to_vec());
    }
    Ok(chunks)
}

/// Walk a TLS byte stream and cut Handshake (0x16) / AppData (0x17)
/// records into `chunk_size`-byte **TCP payload** pieces. This is not
/// valid TLS-record framing; it is intentional TCP segmentation.
pub fn persistent_fragmentation(stream: &[u8], chunk_size: usize) -> Vec<Vec<u8>> {
    let chunk_size = chunk_size.max(1);
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < stream.len() {
        if pos + 5 > stream.len() {
            out.push(stream[pos..].to_vec());
            break;
        }
        let record_type = stream[pos];
        let len = u16::from_be_bytes([stream[pos + 3], stream[pos + 4]]) as usize;
        let record_end = (pos + 5 + len).min(stream.len());
        let record = &stream[pos..record_end];
        if record_type == 0x16 || record_type == 0x17 {
            for chunk in record.chunks(chunk_size) {
                out.push(chunk.to_vec());
            }
        } else {
            out.push(record.to_vec());
        }
        pos = record_end;
    }
    out
}

/// IPv4 fragment offset table. `mtu` is the full L3 MTU (including the
/// 20-byte IPv4 header). Offsets are in 8-byte units; the last fragment
/// has MF=false.
pub fn ip_level_fragment_offsets(payload_len: usize, mtu: usize) -> Vec<(u16, bool)> {
    const IPV4_HEADER: usize = 20;
    let max_payload = (mtu.saturating_sub(IPV4_HEADER)).max(8) & !0x7;
    let mut offsets = Vec::new();
    let mut sent = 0usize;
    while sent < payload_len {
        let remaining = payload_len - sent;
        let this_len = remaining.min(max_payload);
        let more = sent + this_len < payload_len;
        offsets.push(((sent / 8) as u16, more));
        sent += this_len;
    }
    offsets
}

/// Split a *handshake payload* (the bytes after a 5-byte TLS record header)
/// into a sequence of valid TLS records, each carrying `chunk_size` bytes
/// and tagged as `0x16` (Handshake). This differs from
/// [`persistent_fragmentation`], which produces raw TCP-payload chunks with
/// no record framing. Every emitted record is structurally valid TLS, so a
/// permissive middlebox reassembles it, while a stateless DPI that only
/// inspects the first record never sees the SNI.
///
/// The input is expected to begin with a Handshake message (typically a
/// ClientHello); if it does not, it is returned as a single record.
pub fn fragment_as_tls_records(handshake_payload: &[u8], chunk_size: usize) -> Vec<Vec<u8>> {
    let chunk_size = chunk_size.clamp(1, 16384);
    if handshake_payload.is_empty() {
        return Vec::new();
    }
    // Preserve the record version from the caller's first bytes; default
    // TLS 1.0 (0x0301) which every middlebox accepts for ClientHello.
    let version = if handshake_payload.len() >= 3 && handshake_payload[0] == 0x01 {
        // The payload itself starts with the handshake type, so there is no
        // record version in it; use 0x0301.
        [0x03u8, 0x01]
    } else {
        [0x03u8, 0x01]
    };
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < handshake_payload.len() {
        let end = (pos + chunk_size).min(handshake_payload.len());
        let body = &handshake_payload[pos..end];
        let mut rec = Vec::with_capacity(5 + body.len());
        rec.push(0x16); // ContentType::handshake
        rec.extend_from_slice(&version);
        rec.extend_from_slice(&(body.len() as u16).to_be_bytes());
        rec.extend_from_slice(body);
        out.push(rec);
        pos = end;
    }
    out
}

/// Split a complete TLS record (5-byte header + handshake body) into two
/// valid `0x16` records at the byte immediately *before* the SNI hostname.
/// The first record carries everything up to (but not including) the SNI
/// name; the second carries the remainder. Both records have correct
/// ContentType/version/length, so a real stack reassembles them while a
/// stateless DPI scanning the first record misses the hostname.
///
/// Returns an error if the buffer is not a parseable ClientHello with an
/// SNI extension.
pub fn tls_record_split_before_sni(record: &[u8]) -> Result<Vec<Vec<u8>>, DpiGuardError> {
    let info = parse_client_hello(record)?;
    let loc = info.sni.ok_or(DpiGuardError::SniNotFound)?;
    // loc.name_start is the absolute offset of the first SNI byte within
    // `record`. We cut the *handshake body* there, i.e. after the 5-byte
    // record header, so split point = loc.name_start (which is >= 5).
    if loc.name_start <= 5 || loc.name_start >= record.len() {
        return Err(DpiGuardError::OutOfRange(
            "SNI offset outside record body".into(),
        ));
    }
    let cut = loc.name_start;
    let first_body = &record[5..cut];
    let second_body = &record[cut..];
    let version = [record[1], record[2]];

    let build = |body: &[u8]| -> Vec<u8> {
        let mut r = Vec::with_capacity(5 + body.len());
        r.push(0x16);
        r.extend_from_slice(&version);
        r.extend_from_slice(&(body.len() as u16).to_be_bytes());
        r.extend_from_slice(body);
        r
    };
    Ok(vec![build(first_body), build(second_body)])
}

/// --- Nested Extension Cloaking (2026) ---
/// Build the "cloaked" ClientHello for the `NestedCloak` profile: the
/// visible SNI (type `0x0000`) becomes the benign `cover_sni`, and the real
/// name rides inside a private-range extension (`hidden_type`, normally
/// `sni_mutations::NESTED_HIDDEN_EXT_TYPE`) appended at the end of the
/// extension list. The caller then cuts the wire at the hidden extension's
/// boundary via [`nested_cloak_split_offsets`] so a DPI that does not
/// reassemble TCP only ever sees the cover hello.
pub fn nested_cloak(
    record: &[u8],
    cover_sni: &[u8],
    real_sni: &[u8],
    hidden_type: u16,
) -> Result<Vec<u8>, DpiGuardError> {
    if real_sni.is_empty() {
        return Err(DpiGuardError::SniNotFound);
    }
    if cover_sni.is_empty() {
        return Err(DpiGuardError::OutOfRange("empty cover SNI".into()));
    }
    let fronted = front_sni_with_benign(record, cover_sni)?;
    inject_hidden_sni_in_unknown_ext(&fronted, real_sni, hidden_type)
}

/// TCP split points that give NestedCloak its classic 3-segment layout:
///
/// ```text
/// seg1: everything before the hidden extension (cover SNI visible, 0x0000)
/// seg2: hidden extension header (type+len) + first min(32, name_len) name bytes
/// seg3: the rest of the name + the rest of the record
/// ```
///
/// Returned offsets are payload-relative and feed straight into
/// `packet::tcp_segment_payload_at_offsets`. Names shorter than 2 bytes
/// collapse to 2 segments (nothing would be left for segment 3). A DPI that
/// never reassembles TCP sees only seg1 — the cover.
pub fn nested_cloak_split_offsets(
    record: &[u8],
    hidden_type: u16,
) -> Result<Vec<usize>, DpiGuardError> {
    let exts = list_extensions(record)?;
    let hidden = exts
        .iter()
        .find(|e| e.ext_type == hidden_type)
        .ok_or(DpiGuardError::SniNotFound)?;
    // The hidden extension's body is the raw real name; the 4-byte
    // type+length header sits just before `body_start`.
    let header_start = hidden
        .body_start
        .checked_sub(4)
        .ok_or_else(|| DpiGuardError::OutOfRange("hidden extension offset underflow".into()))?;
    let body_len = hidden.body_end.saturating_sub(hidden.body_start);
    let chunk = crate::sni_mutations::nested_chunk_size(body_len);
    // Keep at least one name byte for segment 3 whenever possible.
    let first_take = chunk.min(body_len.saturating_sub(1).max(1));
    let mut offsets = vec![header_start];
    let second = hidden.body_start.saturating_add(first_take);
    if second > header_start && second < record.len() {
        offsets.push(second);
    }
    Ok(offsets)
}

/// Split a complete TLS record into two valid `0x16` records *inside* the
/// SNI hostname (after the first half of the name), so the name straddles
/// the record boundary (2026 roadmap #1). Stateless DPIs that parse only
/// the first record miss the name, and DPIs that anchor on a name at the
/// *start* of the second record miss it too — no piece contains the full
/// name. Falls back to [`tls_record_split_before_sni`] for 1-byte names
/// (no middle to cut at).
pub fn tls_record_split_mid_sni(record: &[u8]) -> Result<Vec<Vec<u8>>, DpiGuardError> {
    let info = parse_client_hello(record)?;
    let loc = info.sni.ok_or(DpiGuardError::SniNotFound)?;
    let name_len = loc.name_end - loc.name_start;
    if name_len < 2 {
        return tls_record_split_before_sni(record);
    }
    // Split in the MIDDLE of the name, first half rounded up so an odd
    // name leaves the shorter tail on the second record ("exampl" | "e.com"
    // for an 11-byte name — matches the regression test's 6-char head
    // window). The old floor division put only 5 bytes up front and failed
    // its own straddle assertion (audit F-06, test never run before).
    let cut = loc.name_start + name_len.div_ceil(2);
    if cut <= 5 || cut >= record.len() {
        return Err(DpiGuardError::OutOfRange(
            "SNI offset outside record body".into(),
        ));
    }
    let first_body = &record[5..cut];
    let second_body = &record[cut..];
    let version = [record[1], record[2]];
    let build = |body: &[u8]| -> Vec<u8> {
        let mut r = Vec::with_capacity(5 + body.len());
        r.push(0x16);
        r.extend_from_slice(&version);
        r.extend_from_slice(&(body.len() as u16).to_be_bytes());
        r.extend_from_slice(body);
        r
    };
    Ok(vec![build(first_body), build(second_body)])
}

/// Remove the first extension of `ext_type` and patch every enclosing length
/// field so the ClientHello stays structurally valid. Records without a
/// matching extension are returned unchanged. Used by real ECH (the outer
/// hello must not keep an ECH/GREASE extension once the sealed one is
/// appended).
pub fn remove_extension(record: &[u8], ext_type: u16) -> Result<Vec<u8>, DpiGuardError> {
    let exts = list_extensions(record)?;
    let target = match exts.iter().find(|e| e.ext_type == ext_type) {
        Some(t) => t,
        None => return Ok(record.to_vec()),
    };
    // First extension begins at extensions_len_off + 2, and its body starts
    // 4 bytes after that (type + length header), so:
    let extensions_len_off = exts[0].body_start - 6;
    let start = target.body_start - 4; // includes the type+len header
    let end = target.body_end;
    let delta = (end - start) as i32;
    let mut out = Vec::with_capacity(record.len().saturating_sub(delta.max(0) as usize));
    out.extend_from_slice(&record[..start]);
    out.extend_from_slice(&record[end..]);
    patch_u16(&mut out, 3, -delta); // record length
    patch_u24(&mut out, 6, -delta); // handshake length
    patch_u16(&mut out, extensions_len_off, -delta);
    Ok(out)
}

/// Test helper: a structurally valid ClientHello whose SNI is `sni`.
pub fn encode_client_hello(sni: &str) -> Vec<u8> {
    let mut ext_body = Vec::new();
    ext_body.extend_from_slice(&((sni.len() + 3) as u16).to_be_bytes());
    ext_body.push(0x00);
    ext_body.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    ext_body.extend_from_slice(sni.as_bytes());

    let mut extension = Vec::new();
    extension.extend_from_slice(&0x0000u16.to_be_bytes());
    extension.extend_from_slice(&(ext_body.len() as u16).to_be_bytes());
    extension.extend_from_slice(&ext_body);

    let mut handshake_body = Vec::new();
    handshake_body.extend_from_slice(&0x0303u16.to_be_bytes());
    handshake_body.extend_from_slice(&[0u8; 32]);
    handshake_body.push(0);
    handshake_body.extend_from_slice(&4u16.to_be_bytes());
    handshake_body.extend_from_slice(&[0x13, 0x01, 0x13, 0x02]);
    handshake_body.push(1);
    handshake_body.push(0);
    handshake_body.extend_from_slice(&(extension.len() as u16).to_be_bytes());
    handshake_body.extend_from_slice(&extension);

    let mut handshake = Vec::new();
    handshake.push(0x01);
    let len = handshake_body.len() as u32;
    handshake.extend_from_slice(&len.to_be_bytes()[1..]);
    handshake.extend_from_slice(&handshake_body);

    let mut record = Vec::new();
    record.push(0x16);
    record.extend_from_slice(&0x0301u16.to_be_bytes());
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    #[test]
    fn finds_sni_exactly() {
        let record = encode_client_hello("example.com");
        let (start, end) = calculate_smart_split_points(&record).unwrap();
        assert_eq!(&record[start..end], b"example.com");
    }

    #[test]
    fn splice_longer_sni_roundtrips_and_reparses() {
        let record = encode_client_hello("a.com");
        let out = splice_sni(&record, b"longer.example.com").unwrap();
        let (s, e) = calculate_smart_split_points(&out).unwrap();
        assert_eq!(&out[s..e], b"longer.example.com");
        // record length field matches body
        let rec_len = u16::from_be_bytes([out[3], out[4]]) as usize;
        assert_eq!(5 + rec_len, out.len());
    }

    #[test]
    fn splice_shorter_sni_roundtrips() {
        let record = encode_client_hello("example.com");
        let out = splice_sni(&record, b"x.io").unwrap();
        let (s, e) = calculate_smart_split_points(&out).unwrap();
        assert_eq!(&out[s..e], b"x.io");
    }

    #[test]
    fn byte_chunking_reassembles_to_original_sni_bytes() {
        let record = encode_client_hello("test.org");
        let chunks = fragment_sni_byte_chunk(&record).unwrap();
        let sni_chunks: Vec<u8> = chunks
            .iter()
            .filter(|c| c.len() == 1)
            .map(|c| c[0])
            .collect();
        assert_eq!(sni_chunks, b"test.org".to_vec());
        let joined: Vec<u8> = chunks.into_iter().flatten().collect();
        assert_eq!(joined, record);
    }

    #[test]
    fn persistent_fragmentation_covers_full_stream() {
        let mut stream = encode_client_hello("a.com");
        stream.extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5]);
        let chunks = persistent_fragmentation(&stream, 3);
        let total: usize = chunks.iter().map(|c| c.len()).sum();
        assert_eq!(total, stream.len());
    }

    #[test]
    fn ip_fragment_offsets_subtract_header_and_last_has_mf_false() {
        let offsets = ip_level_fragment_offsets(3000, 1500);
        assert!(!offsets.is_empty());
        assert!(!offsets.last().unwrap().1);
        for (_off, more) in &offsets[..offsets.len() - 1] {
            assert!(more);
        }
        // 1500 MTU → 1480 payload aligned down to 1480 (already % 8 == 0)
        let first_span = 1480u16 / 8;
        assert_eq!(offsets[1].0, first_span);
    }

    #[test]
    fn fuzz_calculate_smart_split_points_never_panics() {
        let mut rng = rand::thread_rng();
        for _ in 0..200 {
            let len = rng.gen_range(0..300);
            let data: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
            let _ = calculate_smart_split_points(&data);
        }
    }

    #[test]
    fn truncated_client_hello_is_packet_too_short() {
        let record = encode_client_hello("example.com");
        let err = calculate_smart_split_points(&record[..20]).unwrap_err();
        matches_too_short(err);
    }

    fn matches_too_short(err: DpiGuardError) {
        match err {
            DpiGuardError::PacketTooShort { .. } | DpiGuardError::NotClientHello => {}
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn disguise_extension_type_hides_sni_from_naive_parser() {
        let record = encode_client_hello("example.com");
        assert!(sni_bytes(&record).is_some());
        let disguised = disguise_sni_extension_type(&record, 0x0A0A).unwrap();
        assert!(sni_bytes(&disguised).is_none());
        let rec_len = u16::from_be_bytes([disguised[3], disguised[4]]) as usize;
        assert_eq!(5 + rec_len, disguised.len());
        assert!(disguised.windows(11).any(|w| w == b"example.com"));
    }

    #[test]
    fn fronting_replaces_visible_sni() {
        let record = encode_client_hello("real.example.com");
        let fronted = front_sni_with_benign(&record, b"www.microsoft.com").unwrap();
        let (s, e) = calculate_smart_split_points(&fronted).unwrap();
        assert_eq!(&fronted[s..e], b"www.microsoft.com");
    }

    #[test]
    fn hidden_sni_in_unknown_ext_appends_and_patches_lengths() {
        let record = encode_client_hello("benign.example");
        let with_hidden =
            inject_hidden_sni_in_unknown_ext(&record, b"real.example.com", 0xFF01).unwrap();
        assert!(with_hidden.len() > record.len());
        let (s, e) = calculate_smart_split_points(&with_hidden).unwrap();
        assert_eq!(&with_hidden[s..e], b"benign.example");
        assert!(with_hidden.windows(16).any(|w| w == b"real.example.com"));
        let rec_len = u16::from_be_bytes([with_hidden[3], with_hidden[4]]) as usize;
        assert_eq!(5 + rec_len, with_hidden.len());
    }

    #[test]
    fn disguise_with_grease_values() {
        let record = encode_client_hello("test.com");
        for grease in [0x0A0Au16, 0x1A1A, 0x2A2A, 0x4A4A, 0xFAFA] {
            let out = disguise_sni_extension_type(&record, grease).unwrap();
            assert_eq!(out.len(), record.len());
        }
    }

    #[test]
    fn fragment_as_tls_records_wraps_each_chunk_as_0x16() {
        let record = encode_client_hello("example.com");
        // strip the 5-byte header to get a "handshake payload"
        let body = &record[5..];
        let recs = fragment_as_tls_records(body, 32);
        assert!(recs.len() >= 2);
        for r in &recs {
            assert_eq!(r[0], 0x16);
            let len = u16::from_be_bytes([r[3], r[4]]) as usize;
            assert_eq!(5 + len, r.len());
        }
        // Reassembly yields the original handshake body.
        let rejoined: Vec<u8> = recs.iter().flat_map(|r| r[5..].iter().copied()).collect();
        assert_eq!(rejoined, body);
    }

    #[test]
    fn tls_split_before_sni_keeps_name_out_of_first_record() {
        let record = encode_client_hello("example.com");
        let parts = tls_record_split_before_sni(&record).unwrap();
        assert_eq!(parts.len(), 2);
        // First record must be a valid 0x16 record.
        assert_eq!(parts[0][0], 0x16);
        // The raw SNI must not appear in the first record.
        assert!(!parts[0].windows(11).any(|w| w == b"example.com"));
        // It must appear in the second.
        assert!(parts[1].windows(11).any(|w| w == b"example.com"));
        // Both records are structurally valid.
        for r in &parts {
            let len = u16::from_be_bytes([r[3], r[4]]) as usize;
            assert_eq!(5 + len, r.len());
        }
    }

    #[test]
    fn shuffle_cipher_suites_in_hello_preserves_length_and_reparses() {
        let mut record = encode_client_hello("example.com");
        let orig_len = record.len();
        let res = shuffle_cipher_suites_in_hello(&mut record);
        assert!(res.is_ok());
        assert_eq!(record.len(), orig_len);
        let info = parse_client_hello(&record).unwrap();
        assert_eq!(info.cipher_suites_len, 4);
    }

    #[test]
    fn list_extensions_exposes_sni_and_injected_span() {
        let record = encode_client_hello("example.com");
        let exts = list_extensions(&record).unwrap();
        assert_eq!(exts.len(), 1);
        assert_eq!(exts[0].ext_type, 0x0000);
        // Inject a supported_groups extension and confirm it is listed with
        // the correct body span.
        let mut body = Vec::new();
        body.extend_from_slice(&4u16.to_be_bytes());
        body.extend_from_slice(&[0x00, 0x1D, 0x00, 0x17]);
        let with = inject_hidden_sni_in_unknown_ext(&record, &body, 0x000A).unwrap();
        let exts = list_extensions(&with).unwrap();
        let sg = exts.iter().find(|e| e.ext_type == 0x000A).unwrap();
        assert_eq!(&with[sg.body_start..sg.body_end], body.as_slice());
    }

    #[test]
    fn nested_cloak_cover_visible_and_real_hidden() {
        let record = encode_client_hello("secret.example.com");
        let cloaked =
            nested_cloak(&record, b"www.microsoft.com", b"secret.example.com", 0xFF01).unwrap();
        // Cover is the visible 0x0000 SNI.
        let (s, e) = calculate_smart_split_points(&cloaked).unwrap();
        assert_eq!(&cloaked[s..e], b"www.microsoft.com");
        // Real name rides inside the private-range extension.
        let exts = list_extensions(&cloaked).unwrap();
        let hidden = exts.iter().find(|x| x.ext_type == 0xFF01).unwrap();
        assert_eq!(
            &cloaked[hidden.body_start..hidden.body_end],
            b"secret.example.com"
        );
        // All length fields still add up.
        let rec_len = u16::from_be_bytes([cloaked[3], cloaked[4]]) as usize;
        assert_eq!(5 + rec_len, cloaked.len());
    }

    #[test]
    fn nested_cloak_three_segment_split() {
        let record = encode_client_hello("secret.example.com"); // 18-byte name
        let cloaked =
            nested_cloak(&record, b"www.microsoft.com", b"secret.example.com", 0xFF01).unwrap();
        let offsets = nested_cloak_split_offsets(&cloaked, 0xFF01).unwrap();
        assert_eq!(offsets.len(), 2, "expected 3 segments");
        // seg2 = 4-byte extension header + all-but-one name bytes (the last
        // byte is deliberately held back so segment 3 is never empty).
        assert_eq!(offsets[1], offsets[0] + 4 + 17);
        // seg1 must contain the cover but not the real name.
        assert!(cloaked[..offsets[0]]
            .windows(17)
            .any(|w| w == b"www.microsoft.com"));
        assert!(!cloaked[..offsets[0]].windows(6).any(|w| w == b"secret"));
        // seg2 starts with the hidden extension type, then the name prefix.
        assert_eq!(
            &cloaked[offsets[0]..offsets[0] + 2],
            &0xFF01u16.to_be_bytes()
        );
        assert_eq!(&cloaked[offsets[0] + 4..offsets[1]], b"secret.example.co");
        // seg3 carries exactly the final name byte.
        assert_eq!(&cloaked[offsets[1]..], b"m");
    }

    #[test]
    fn nested_cloak_long_name_splits_mid_name() {
        let long = "a-very-long-target-hostname.example.com"; // > 32 bytes
        let record = encode_client_hello(long);
        let cloaked = nested_cloak(&record, b"www.apple.com", long.as_bytes(), 0xFF01).unwrap();
        let offsets = nested_cloak_split_offsets(&cloaked, 0xFF01).unwrap();
        assert_eq!(offsets.len(), 2);
        // Only the first 32 name bytes ride in seg2; seg3 carries the rest.
        assert_eq!(offsets[1], offsets[0] + 4 + 32);
        assert!(offsets[1] < cloaked.len());
        let seg3 = &cloaked[offsets[1]..];
        assert_eq!(seg3.len(), long.len() - 32);
    }

    #[test]
    fn nested_cloak_one_byte_name_collapses_to_two_segments() {
        let record = encode_client_hello("x.io");
        // Hand-craft a record with a 1-byte name so seg3 would be empty.
        let small = splice_sni(&record, b"y").unwrap();
        let cloaked = nested_cloak(&small, b"www.microsoft.com", b"y", 0xFF01).unwrap();
        let offsets = nested_cloak_split_offsets(&cloaked, 0xFF01).unwrap();
        assert_eq!(offsets.len(), 1, "1-byte name cannot fill 3 segments");
    }

    #[test]
    fn nested_cloak_rejects_empty_inputs() {
        let record = encode_client_hello("example.com");
        assert!(nested_cloak(&record, b"cover.com", b"", 0xFF01).is_err());
        assert!(nested_cloak(&record, b"", b"example.com", 0xFF01).is_err());
        // No hidden extension of that type -> no split points.
        assert!(nested_cloak_split_offsets(&record, 0xFF01).is_err());
    }

    #[test]
    fn tls_split_mid_sni_straddles_the_name() {
        let record = encode_client_hello("example.com");
        let parts = tls_record_split_mid_sni(&record).unwrap();
        assert_eq!(parts.len(), 2);
        for r in &parts {
            assert_eq!(r[0], 0x16);
            let len = u16::from_be_bytes([r[3], r[4]]) as usize;
            assert_eq!(5 + len, r.len());
        }
        // Neither piece contains the full name.
        assert!(!parts[0].windows(11).any(|w| w == b"example.com"));
        assert!(!parts[1].windows(11).any(|w| w == b"example.com"));
        // First piece ends mid-name ("exampl"), second starts with "e.com".
        assert!(parts[0].windows(6).any(|w| w == b"exampl"));
        assert!(parts[1].windows(5).any(|w| w == b"e.com"));
        // Reassembled handshake bodies equal the original body.
        let rejoined: Vec<u8> = parts.iter().flat_map(|r| r[5..].iter().copied()).collect();
        assert_eq!(rejoined, record[5..].to_vec());
    }

    #[test]
    fn tls_split_mid_sni_one_byte_name_falls_back() {
        let record = encode_client_hello("example.com");
        let small = splice_sni(&record, b"y").unwrap();
        let parts = tls_record_split_mid_sni(&small).unwrap();
        assert_eq!(parts.len(), 2);
        // Fallback = split *before* the name; name wholly in the second part.
        assert!(parts[1].windows(1).any(|w| w == b"y"));
        assert!(!parts[0].windows(1).any(|w| w == b"y"));
    }

    #[test]
    fn remove_extension_patches_lengths() {
        let record = encode_client_hello("benign.example");
        let with_hidden =
            inject_hidden_sni_in_unknown_ext(&record, b"real.example.com", 0xFF01).unwrap();
        assert_eq!(list_extensions(&with_hidden).unwrap().len(), 2);
        let stripped = remove_extension(&with_hidden, 0xFF01).unwrap();
        // Back to a single SNI extension, real name gone, cover intact.
        let exts = list_extensions(&stripped).unwrap();
        assert_eq!(exts.len(), 1);
        assert_eq!(exts[0].ext_type, 0x0000);
        assert!(!stripped.windows(16).any(|w| w == b"real.example.com"));
        let (s, e) = calculate_smart_split_points(&stripped).unwrap();
        assert_eq!(&stripped[s..e], b"benign.example");
        let rec_len = u16::from_be_bytes([stripped[3], stripped[4]]) as usize;
        assert_eq!(5 + rec_len, stripped.len());
        assert_eq!(stripped.len(), record.len());
    }

    #[test]
    fn remove_extension_is_noop_when_absent() {
        let record = encode_client_hello("example.com");
        let same = remove_extension(&record, 0xFF01).unwrap();
        assert_eq!(same, record);
    }
}
