//! ech — Encrypted Client Hello (ECH) handling — [UNTESTED]
//! Based on draft-ietf-tls-esni and Cloudflare blog.
//! ECH encrypts the real SNI in an inner ClientHello, outer SNI is benign.
//! This module implements:
//! - GREASE ECH extension injection (both a GREASE type and, since the
//!   2026 roadmap, the real `0xFE0D` type with a random payload —
//!   [`inject_ech_grease_fe0d`] — so "has ECH / no ECH" classification is
//!   useless)
//! - Outer SNI handling
//! - Real ECHConfigList wire-format parsing (draft-ietf-tls-esni), so a
//!   `public_name` fetched via DNS HTTPS/SVCB can actually be extracted
//!   instead of hard-coded. The DNS-over-HTTPS *fetch* itself lives in
//!   `doh.rs`; this module only decodes bytes it is given — no network
//!   I/O, so it stays a pure, OS-independent lib function.
//! - **Real ECH sealing** (2026 roadmap #5): [`seal_real_ech_hello`]
//!   builds the inner ClientHello (real SNI restored, stale ECH removed,
//!   RFC 7685 padding to a 4-byte boundary) and HPKE-seals it with the
//!   server's ECHConfig — crypto provided by the dependency-free
//!   `hpke.rs` (DHKEM(X25519) + HKDF-SHA256 + ChaCha20Poly1305). The
//!   outer hello shows only the config's `public_name`. Requires a
//!   destination server that actually supports ECH.

use crate::error::DpiGuardError;
use rand::Rng;

/// ECH extension type (draft, value 0xFE0D)
pub const ECH_EXTENSION_TYPE: u16 = 0xFE0D;

/// GREASE values for ECH (RFC 8701 style)
pub const ECH_GREASE_TYPES: [u16; 6] = [0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0xFAFA];

#[derive(Debug, Clone)]
pub struct EchConfig {
    pub public_name: String,
    pub raw: Vec<u8>,
}

/// Read a big-endian u16 length prefix at `pos`, returning the value and
/// the offset just past it. `None` if there aren't 2 bytes left.
fn read_u16(buf: &[u8], pos: usize) -> Option<(u16, usize)> {
    let end = pos.checked_add(2)?;
    let bytes: [u8; 2] = buf.get(pos..end)?.try_into().ok()?;
    Some((u16::from_be_bytes(bytes), end))
}

/// Parse an `ECHConfigList` (draft-ietf-tls-esni §4) — the raw bytes of
/// the "ech" SvcParamValue from an HTTPS/SVCB record, as delivered by a
/// DNS-over-HTTPS response. The list is a back-to-back sequence of
/// `ECHConfig` entries (each self-delimiting via its own length field);
/// entries with an unrecognized `version` are skipped so a future/older
/// draft version in the same list doesn't break parsing.
///
/// Layout of one `ECHConfig` (version 0xfe0d, the deployed draft-13+
/// version used by Cloudflare/Chrome/Firefox in production today):
/// ```text
/// uint16 version;               // 0xfe0d
/// uint16 length;                // length of everything below, in bytes
/// -- HpkeKeyConfig --
/// uint8  config_id;
/// uint16 kem_id;
/// uint16 public_key_len; opaque public_key[public_key_len];
/// uint16 cipher_suites_len;     opaque cipher_suites[cipher_suites_len];
/// -- back in ECHConfigContents --
/// uint8  maximum_name_length;
/// uint8  public_name_len;       opaque public_name[public_name_len];
/// uint16 extensions_len;        opaque extensions[extensions_len];
/// ```
/// Returns the first `0xfe0d` config found. Malformed or truncated input
/// returns `Err` rather than panicking (fail-open friendly).
pub fn parse_ech_config_from_https_record(record: &[u8]) -> Result<EchConfig, DpiGuardError> {
    const ECH_CONFIG_VERSION: u16 = ECH_EXTENSION_TYPE; // 0xfe0d, same value

    let mut pos = 0usize;
    while pos < record.len() {
        let (version, after_version) =
            read_u16(record, pos).ok_or_else(|| trunc("ECHConfig version"))?;
        let (length, after_length) =
            read_u16(record, after_version).ok_or_else(|| trunc("ECHConfig length"))?;
        let length = length as usize;
        let contents_end = after_length
            .checked_add(length)
            .ok_or_else(|| DpiGuardError::OutOfRange("ECHConfig length overflow".into()))?;
        let contents = record
            .get(after_length..contents_end)
            .ok_or_else(|| trunc("ECHConfig contents"))?;

        if version == ECH_CONFIG_VERSION {
            let public_name = parse_ech_config_contents(contents)?;
            return Ok(EchConfig {
                public_name,
                raw: record[pos..contents_end].to_vec(),
            });
        }
        // Unknown version: skip this entry, keep scanning the list.
        pos = contents_end;
    }
    Err(DpiGuardError::OutOfRange(
        "no supported (0xfe0d) ECHConfig found in ECHConfigList".into(),
    ))
}

fn trunc(what: &str) -> DpiGuardError {
    DpiGuardError::OutOfRange(format!("ECHConfigList truncated (reading {what})"))
}

/// Parse the `ECHConfigContents` of a single version-0xfe0d entry and
/// return `public_name`. Walks past `HpkeKeyConfig` (config_id, kem_id,
/// public_key, cipher_suites) without needing to understand their
/// contents — only their lengths — since the wire format is fully
/// self-delimiting.
fn parse_ech_config_contents(c: &[u8]) -> Result<String, DpiGuardError> {
    // config_id (1 byte) + kem_id (2 bytes), then a u16-prefixed public key.
    let (pk_len, pos) = read_u16(c, 3).ok_or_else(|| trunc("public_key length"))?;
    let pk_len = pk_len as usize;
    let pos_after_pk = pos
        .checked_add(pk_len)
        .ok_or_else(|| DpiGuardError::OutOfRange("public_key length overflow".into()))?;
    if pos_after_pk > c.len() {
        return Err(trunc("public_key bytes"));
    }

    let (cs_len, pos) = read_u16(c, pos_after_pk).ok_or_else(|| trunc("cipher_suites length"))?;
    let cs_len = cs_len as usize;
    let pos_after_cs = pos
        .checked_add(cs_len)
        .ok_or_else(|| DpiGuardError::OutOfRange("cipher_suites length overflow".into()))?;
    if pos_after_cs > c.len() {
        return Err(trunc("cipher_suites bytes"));
    }

    // maximum_name_length (1 byte) — not needed by callers, skip.
    let max_name_pos = pos_after_cs;
    let public_name_len_pos = max_name_pos
        .checked_add(1)
        .ok_or_else(|| DpiGuardError::OutOfRange("offset overflow".into()))?;
    let public_name_len = *c
        .get(public_name_len_pos)
        .ok_or_else(|| trunc("public_name length"))? as usize;
    let name_start = public_name_len_pos + 1;
    let name_end = name_start
        .checked_add(public_name_len)
        .ok_or_else(|| DpiGuardError::OutOfRange("public_name length overflow".into()))?;
    let name_bytes = c
        .get(name_start..name_end)
        .ok_or_else(|| trunc("public_name bytes"))?;
    // public_name is DNS-name ASCII per spec; lossy-convert defensively
    // rather than reject a config over one bad byte (fail-open in spirit
    // with the rest of this fail-open codebase).
    let public_name = String::from_utf8_lossy(name_bytes).into_owned();
    if public_name.is_empty() {
        return Err(DpiGuardError::OutOfRange(
            "empty ECHConfig public_name".into(),
        ));
    }
    Ok(public_name)
}

/// Inject GREASE ECH extension (fake) to confuse DPI that fingerprints ECH
/// This adds an extension with GREASE type and random payload
pub fn inject_ech_grease_ext(record: &[u8]) -> Result<Vec<u8>, DpiGuardError> {
    let mut rng = rand::thread_rng();
    let grease_type = ECH_GREASE_TYPES[rng.gen_range(0..ECH_GREASE_TYPES.len())];
    let payload_len = rng.gen_range(8..=32);
    let mut payload = Vec::with_capacity(payload_len);
    for _ in 0..payload_len {
        payload.push(rng.gen::<u8>());
    }
    crate::fragmentation::inject_hidden_sni_in_unknown_ext(record, &payload, grease_type)
        .map_err(|e| DpiGuardError::OutOfRange(format!("ECH GREASE inject failed: {e}")))
}

/// Always-on ECH GREASE with the *real* ECH extension type (`0xFE0D`) and a
/// random-length random payload (2026 roadmap #3). Real browsers do exactly
/// this ("ECH GREASE") on every hello even without real ECH: servers that
/// don't implement ECH ignore the extension, while an observer can no
/// longer classify flows by "has ECH / has no ECH". Payload size mimics a
/// plausible ECHClientHello (enc 32 B + sealed inner hello).
pub fn inject_ech_grease_fe0d(record: &[u8]) -> Result<Vec<u8>, DpiGuardError> {
    let mut rng = rand::thread_rng();
    let payload_len = rng.gen_range(64..=160);
    let mut payload = Vec::with_capacity(payload_len);
    for _ in 0..payload_len {
        payload.push(rng.gen::<u8>());
    }
    crate::fragmentation::inject_hidden_sni_in_unknown_ext(record, &payload, ECH_EXTENSION_TYPE)
        .map_err(|e| DpiGuardError::OutOfRange(format!("ECH 0xFE0D GREASE inject failed: {e}")))
}

/// Build outer ClientHello with benign SNI for ECH
/// outer SNI = public name (e.g., cloudflare-ech.com), inner = real (encrypted in real ECH)
pub fn build_outer_sni_for_ech(
    real_record: &[u8],
    public_name: &str,
) -> Result<Vec<u8>, DpiGuardError> {
    crate::fragmentation::front_sni_with_benign(real_record, public_name.as_bytes())
}

/// Check if ClientHello already contains ECH extension
pub fn has_ech_extension(record: &[u8]) -> bool {
    // Scan for extension type 0xFE0D
    if record.len() < 50 {
        return false;
    }
    // Rough scan: look for FE0D in extension area
    record
        .windows(2)
        .any(|w| u16::from_be_bytes([w[0], w[1]]) == ECH_EXTENSION_TYPE)
}

// --- Real ECH (2026 roadmap #5) -------------------------------------------

/// Fully parsed `ECHConfig` entry — everything [`seal_real_ech_hello`]
/// needs beyond the `public_name` that [`parse_ech_config_from_https_record`]
/// extracts.
#[derive(Debug, Clone)]
pub struct EchConfigDetailed {
    pub config_id: u8,
    pub kem_id: u16,
    pub public_key: Vec<u8>,
    /// Advertised `(kdf_id, aead_id)` pairs.
    pub cipher_suites: Vec<(u16, u16)>,
    pub maximum_name_length: u8,
    pub public_name: String,
    /// The `ECHConfigContents` bytes (everything after version+length);
    /// per draft-ietf-tls-esni this is the HPKE `info` parameter.
    pub contents: Vec<u8>,
    /// The full raw entry (version + length + contents).
    pub raw: Vec<u8>,
}

/// Like [`parse_ech_config_from_https_record`] but decodes every field the
/// HPKE sealing path needs (config id, KEM id, public key, cipher suites).
/// Same fail-open contract: malformed input returns `Err`, never panics.
pub fn parse_ech_config_detailed(record: &[u8]) -> Result<EchConfigDetailed, DpiGuardError> {
    let mut pos = 0usize;
    while pos < record.len() {
        let (version, after_version) =
            read_u16(record, pos).ok_or_else(|| trunc("ECHConfig version"))?;
        let (length, after_length) =
            read_u16(record, after_version).ok_or_else(|| trunc("ECHConfig length"))?;
        let length = length as usize;
        let contents_end = after_length
            .checked_add(length)
            .ok_or_else(|| DpiGuardError::OutOfRange("ECHConfig length overflow".into()))?;
        let contents = record
            .get(after_length..contents_end)
            .ok_or_else(|| trunc("ECHConfig contents"))?;

        if version == ECH_EXTENSION_TYPE {
            let mut cfg = parse_ech_config_contents_detailed(contents)?;
            cfg.raw = record[pos..contents_end].to_vec();
            return Ok(cfg);
        }
        pos = contents_end;
    }
    Err(DpiGuardError::OutOfRange(
        "no supported (0xfe0d) ECHConfig found in ECHConfigList".into(),
    ))
}

fn parse_ech_config_contents_detailed(c: &[u8]) -> Result<EchConfigDetailed, DpiGuardError> {
    let config_id = *c.first().ok_or_else(|| trunc("config_id"))?;
    let (kem_id, pos) = read_u16(c, 1).ok_or_else(|| trunc("kem_id"))?;

    let (pk_len, pos) = read_u16(c, pos).ok_or_else(|| trunc("public_key length"))?;
    let pk_len = pk_len as usize;
    let pk_end = pos
        .checked_add(pk_len)
        .ok_or_else(|| DpiGuardError::OutOfRange("public_key length overflow".into()))?;
    if pk_end > c.len() {
        return Err(trunc("public_key bytes"));
    }
    let public_key = c[pos..pk_end].to_vec();

    let (cs_len, pos) = read_u16(c, pk_end).ok_or_else(|| trunc("cipher_suites length"))?;
    let cs_len = cs_len as usize;
    let cs_end = pos
        .checked_add(cs_len)
        .ok_or_else(|| DpiGuardError::OutOfRange("cipher_suites length overflow".into()))?;
    if cs_end > c.len() {
        return Err(trunc("cipher_suites bytes"));
    }
    if !cs_len.is_multiple_of(4) {
        return Err(DpiGuardError::OutOfRange(
            "cipher_suites length not a multiple of 4".into(),
        ));
    }
    let mut cipher_suites = Vec::with_capacity(cs_len / 4);
    let mut i = pos;
    while i < cs_end {
        let (kdf, j) = read_u16(c, i).ok_or_else(|| trunc("kdf_id"))?;
        let (aead, k) = read_u16(c, j).ok_or_else(|| trunc("aead_id"))?;
        cipher_suites.push((kdf, aead));
        i = k;
    }

    let maximum_name_length = *c.get(cs_end).ok_or_else(|| trunc("maximum_name_length"))?;
    let public_name_len = *c
        .get(cs_end + 1)
        .ok_or_else(|| trunc("public_name length"))? as usize;
    let name_start = cs_end + 2;
    let name_end = name_start
        .checked_add(public_name_len)
        .ok_or_else(|| DpiGuardError::OutOfRange("public_name length overflow".into()))?;
    let name_bytes = c
        .get(name_start..name_end)
        .ok_or_else(|| trunc("public_name bytes"))?;
    let public_name = String::from_utf8_lossy(name_bytes).into_owned();
    if public_name.is_empty() {
        return Err(DpiGuardError::OutOfRange(
            "empty ECHConfig public_name".into(),
        ));
    }

    Ok(EchConfigDetailed {
        config_id,
        kem_id,
        public_key,
        cipher_suites,
        maximum_name_length,
        public_name,
        contents: c.to_vec(),
        raw: Vec::new(), // filled by parse_ech_config_detailed
    })
}

/// One-byte body of the ECH extension inside ClientHelloInner
/// (RFC 9849 §5.1).
pub const ECH_CLIENT_INNER: u8 = 0x01;

/// HPKE `info` for ECH (RFC 9849 §6.1): `"tls ech" || 0x00 || ECHConfig`,
/// where ECHConfig is the raw version+length+contents entry of the list.
fn ech_hpke_info(cfg_raw: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + cfg_raw.len());
    v.extend_from_slice(b"tls ech");
    v.push(0);
    v.extend_from_slice(cfg_raw);
    v
}

/// Build the EncodedClientHelloInner plaintext (RFC 9849 §5.1 + §6.1.3)
/// from an outer-template hello: real SNI restored, empty legacy_session_id,
/// the one-byte inner ECH marker extension, TLS 1.3 `supported_versions`
/// (added when absent), and every outer extension except the stale
/// ECH/NestedCloak ones. Trailing zero padding: first fill the name up to
/// `maximum_name_length`, then round the whole thing up to a multiple of 32.
fn build_encoded_inner(
    record: &[u8],
    real_sni: &[u8],
    maximum_name_length: u8,
) -> Result<Vec<u8>, DpiGuardError> {
    let info = crate::fragmentation::parse_client_hello(record)?;
    let exts = crate::fragmentation::list_extensions(record)?;
    // ClientHello body starts at offset 9 (5-byte record header + 4-byte
    // handshake header); parse_client_hello already validated the layout.
    let mut out = Vec::with_capacity(record.len() + 64);
    out.extend_from_slice(&record[9..43]); // legacy_version + random
    out.push(0); // empty legacy_session_id — mandatory for the inner hello
    let cs_lo = info.cipher_suites_off - 2;
    out.extend_from_slice(&record[cs_lo..info.cipher_suites_off + info.cipher_suites_len]);
    let comp_len_off = info.cipher_suites_off + info.cipher_suites_len;
    let comp_len = record[comp_len_off] as usize;
    out.extend_from_slice(&record[comp_len_off..comp_len_off + 1 + comp_len]);

    let mut ext_list: Vec<u8> = Vec::new();
    // Inner ECH marker extension: type 0xFE0D, body 0x01.
    ext_list.extend_from_slice(&[0xFE, 0x0D, 0x00, 0x01, ECH_CLIENT_INNER]);
    // server_name with the real hostname.
    let n = real_sni.len();
    ext_list.extend_from_slice(&0x0000u16.to_be_bytes());
    ext_list.extend_from_slice(&((5 + n) as u16).to_be_bytes());
    ext_list.extend_from_slice(&((3 + n) as u16).to_be_bytes());
    ext_list.push(0); // host_name type
    ext_list.extend_from_slice(&(n as u16).to_be_bytes());
    ext_list.extend_from_slice(real_sni);
    // Remaining outer extensions, minus anything ECH-related.
    let mut has_supported_versions = false;
    for e in &exts {
        if matches!(
            e.ext_type,
            0x0000 | 0xFE0D | crate::sni_mutations::NESTED_HIDDEN_EXT_TYPE
        ) {
            continue;
        }
        if e.ext_type == 0x002B {
            has_supported_versions = true;
        }
        ext_list.extend_from_slice(&e.ext_type.to_be_bytes());
        ext_list.extend_from_slice(&((e.body_end - e.body_start) as u16).to_be_bytes());
        ext_list.extend_from_slice(&record[e.body_start..e.body_end]);
    }
    if !has_supported_versions {
        // TLS 1.3 is mandatory inside ECH; add supported_versions = [0x0304].
        ext_list.extend_from_slice(&[0x00, 0x2B, 0x00, 0x03, 0x02, 0x03, 0x04]);
    }
    let ext_len = u16::try_from(ext_list.len()).map_err(|_| {
        DpiGuardError::OutOfRange("ECH inner extensions exceed the u16 wire limit".into())
    })?;
    out.extend_from_slice(&ext_len.to_be_bytes());
    out.extend_from_slice(&ext_list);

    // Zero padding (RFC 9849 §6.1.3): hide the name length, then align the
    // total to 32 bytes.
    let mut pad = (maximum_name_length as usize).saturating_sub(real_sni.len());
    pad += (32 - ((out.len() + pad) % 32)) % 32;
    out.extend(std::iter::repeat_n(0u8, pad));
    Ok(out)
}

/// Real (non-GREASE) ECH per RFC 9849 (2026 roadmap #5): seal the real SNI
/// inside an EncodedClientHelloInner and send the outer hello under the
/// ECHConfig's `public_name`. A DPI sees only the public_name; the real
/// name exists solely inside the HPKE-sealed `payload` of the `0xFE0D`
/// extension.
///
/// Wire format (verified against BoringSSL and NSS):
///   * extension body: `kdf_id u16 | aead_id u16 | config_id u8
///     | u16(enc_len) | enc | u16(payload_len) | payload`
///   * AAD (§5.2): the outer ClientHello body — the hello minus its 5-byte
///     record header and 4-byte handshake header — with the payload bytes
///     zeroed
///   * HPKE info (§6.1): `"tls ech" || 0x00 || ECHConfig.raw`
///   * plaintext (§5.1): ClientHelloInner with empty session id, the inner
///     marker extension, TLS 1.3 `supported_versions`, zero-padded to a
///     multiple of 32 bytes
///
/// Supported cipher stack (all implemented in `hpke.rs`): KEM
/// X25519/HKDF-SHA256 (`0x0020`), AEAD ChaCha20Poly1305 (`0x0003`). Configs
/// that don't advertise that suite return `Err` — the caller fails open to
/// the non-ECH hello.
///
/// `ikm_seed` makes the ephemeral key deterministic (tests); `None` uses a
/// random one.
///
/// Note: the destination server must support ECH, and a spec-conformant
/// TLS 1.3 handshake from here on needs an endpoint that cooperates with
/// this sealed hello (relay mode); a stock browser cannot complete a
/// handshake it did not initiate. The evasion value stands on its own: the
/// real name never appears in plaintext on the wire.
pub fn seal_real_ech_hello(
    record: &[u8],
    real_sni: &[u8],
    cfg: &EchConfigDetailed,
    ikm_seed: Option<[u8; 32]>,
) -> Result<Vec<u8>, DpiGuardError> {
    if cfg.kem_id != crate::hpke::KEM_ID_X25519 {
        return Err(DpiGuardError::OutOfRange(format!(
            "ECH KEM 0x{:04X} unsupported (need X25519 0x0020)",
            cfg.kem_id
        )));
    }
    if !cfg.cipher_suites.iter().any(|(kdf, aead)| {
        *kdf == crate::hpke::KDF_ID_SHA256 && *aead == crate::hpke::AEAD_ID_CHACHA20_POLY1305
    }) {
        return Err(DpiGuardError::OutOfRange(
            "ECH config offers no HKDF-SHA256/ChaCha20Poly1305 cipher suite".into(),
        ));
    }
    if real_sni.is_empty() {
        return Err(DpiGuardError::SniNotFound);
    }
    if cfg.maximum_name_length != 0 && real_sni.len() > cfg.maximum_name_length as usize {
        return Err(DpiGuardError::OutOfRange(format!(
            "SNI longer than ECH maximum_name_length ({})",
            cfg.maximum_name_length
        )));
    }
    if cfg.public_key.len() != 32 {
        return Err(DpiGuardError::OutOfRange(format!(
            "ECH public key is {} bytes, need 32 (X25519)",
            cfg.public_key.len()
        )));
    }
    let mut pk_rm = [0u8; 32];
    pk_rm.copy_from_slice(&cfg.public_key);

    // 1. EncodedClientHelloInner plaintext (RFC 9849 §5.1 + §6.1.3).
    let plaintext = build_encoded_inner(record, real_sni, cfg.maximum_name_length)?;

    // 2. HPKE base mode. Info = "tls ech" || 0x00 || ECHConfig.raw.
    let (enc, shared_secret) = crate::hpke::kem_encapsulate(&pk_rm, ikm_seed)?;
    let info = ech_hpke_info(&cfg.raw);
    let (key, nonce) = crate::hpke::key_schedule(
        &shared_secret,
        &info,
        crate::hpke::KEM_ID_X25519,
        crate::hpke::KDF_ID_SHA256,
        crate::hpke::AEAD_ID_CHACHA20_POLY1305,
    )?;

    // 3. Outer hello: visible SNI = public_name, stale 0xFE0D removed, and
    //    any NestedCloak hidden extension (0xFF01) stripped too — a cloaked
    //    input hello would otherwise leak the real name in plaintext here.
    let mut outer =
        crate::fragmentation::front_sni_with_benign(record, cfg.public_name.as_bytes())?;
    outer = crate::fragmentation::remove_extension(&outer, ECH_EXTENSION_TYPE)?;
    outer = crate::fragmentation::remove_extension(
        &outer,
        crate::sni_mutations::NESTED_HIDDEN_EXT_TYPE,
    )?;

    // 4. Extension body with a zeroed payload placeholder:
    //    kdf_id u16 | aead_id u16 | config_id u8 | u16(enc_len) | enc
    //    | u16(payload_len) | payload(zeros).
    let ct_len = plaintext
        .len()
        .checked_add(16)
        .ok_or_else(|| DpiGuardError::OutOfRange("ECH ciphertext length overflow".into()))?;
    let ct_len_u16 = u16::try_from(ct_len).map_err(|_| {
        DpiGuardError::OutOfRange("ECH ciphertext exceeds the u16 wire limit".into())
    })?;
    let mut ext_body = Vec::with_capacity(9 + enc.len() + ct_len);
    ext_body.extend_from_slice(&crate::hpke::KDF_ID_SHA256.to_be_bytes());
    ext_body.extend_from_slice(&crate::hpke::AEAD_ID_CHACHA20_POLY1305.to_be_bytes());
    ext_body.push(cfg.config_id);
    ext_body.extend_from_slice(&(enc.len() as u16).to_be_bytes());
    ext_body.extend_from_slice(&enc);
    ext_body.extend_from_slice(&ct_len_u16.to_be_bytes());
    ext_body.extend(std::iter::repeat_n(0u8, ct_len));
    let mut hello = crate::fragmentation::inject_hidden_sni_in_unknown_ext(
        &outer,
        &ext_body,
        ECH_EXTENSION_TYPE,
    )?;

    // 5. AAD (RFC 9849 §5.2): the outer ClientHello body (the hello minus
    //    the 5-byte record header and 4-byte handshake header) with the
    //    payload bytes zeroed — verified against BoringSSL/NSS behaviour.
    let exts = crate::fragmentation::list_extensions(&hello)?;
    let ech = exts
        .iter()
        .find(|e| e.ext_type == ECH_EXTENSION_TYPE)
        .ok_or(DpiGuardError::SniNotFound)?;
    let payload_off = ech.body_start + 7 + enc.len() + 2;
    let mut aad = hello[9..].to_vec();
    let aad_off = payload_off - 9;
    for b in aad[aad_off..aad_off + ct_len].iter_mut() {
        *b = 0;
    }

    // 6. Seal and patch the ciphertext into the placeholder.
    let sealed = crate::hpke::chacha20_poly1305_seal(&key, &nonce, &aad, &plaintext);
    hello[payload_off..payload_off + sealed.len()].copy_from_slice(&sealed);
    Ok(hello)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fragmentation::encode_client_hello;

    #[test]
    fn ech_grease_injection_grows_record() {
        let record = encode_client_hello("example.com");
        let with_grease = inject_ech_grease_ext(&record).unwrap();
        assert!(with_grease.len() > record.len());
    }

    #[test]
    fn outer_sni_for_ech_replaces_sni() {
        let record = encode_client_hello("real.example.com");
        let outer = build_outer_sni_for_ech(&record, "public.example.com").unwrap();
        let (s, e) = crate::fragmentation::calculate_smart_split_points(&outer).unwrap();
        assert_eq!(&outer[s..e], b"public.example.com");
    }

    #[test]
    fn detects_ech_extension_presence() {
        let record = encode_client_hello("example.com");
        assert!(!has_ech_extension(&record));
        // Manually inject FE0D
        let mut fake = record.clone();
        fake.extend_from_slice(&[0xFE, 0x0D, 0x00, 0x00]);
        assert!(has_ech_extension(&fake));
    }

    /// Hand-encode one real ECHConfig (version 0xfe0d) so the parser can
    /// be checked against an actual wire-format record instead of a stub.
    fn encode_ech_config(public_name: &str) -> Vec<u8> {
        let public_key = [0xABu8; 32]; // X25519 public key length, content irrelevant here
        let cipher_suites = [0x00, 0x01, 0x00, 0x01]; // one (kdf_id, aead_id) pair
        let mut contents = Vec::new();
        contents.push(0x01); // config_id
        contents.extend_from_slice(&0x0020u16.to_be_bytes()); // kem_id (X25519, RFC 9180)
        contents.extend_from_slice(&(public_key.len() as u16).to_be_bytes());
        contents.extend_from_slice(&public_key);
        contents.extend_from_slice(&(cipher_suites.len() as u16).to_be_bytes());
        contents.extend_from_slice(&cipher_suites);
        contents.push(128); // maximum_name_length
        contents.push(public_name.len() as u8);
        contents.extend_from_slice(public_name.as_bytes());
        contents.extend_from_slice(&0u16.to_be_bytes()); // empty extensions

        let mut entry = Vec::new();
        entry.extend_from_slice(&ECH_EXTENSION_TYPE.to_be_bytes()); // version 0xfe0d
        entry.extend_from_slice(&(contents.len() as u16).to_be_bytes());
        entry.extend_from_slice(&contents);
        entry
    }

    #[test]
    fn parses_real_ech_config_public_name() {
        let list = encode_ech_config("public-fronting.example.com");
        let cfg = parse_ech_config_from_https_record(&list).unwrap();
        assert_eq!(cfg.public_name, "public-fronting.example.com");
        assert_eq!(cfg.raw, list);
    }

    #[test]
    fn skips_unknown_version_entries_in_the_list() {
        // An old/future draft version (0xfe0a) the parser doesn't decode,
        // followed by a real 0xfe0d entry — the list scan must skip the
        // first and still find the second.
        let mut unknown = Vec::new();
        unknown.extend_from_slice(&0xFE0Au16.to_be_bytes());
        unknown.extend_from_slice(&4u16.to_be_bytes());
        unknown.extend_from_slice(&[0u8; 4]);

        let mut list = unknown;
        list.extend_from_slice(&encode_ech_config("cloudflare-ech.com"));

        let cfg = parse_ech_config_from_https_record(&list).unwrap();
        assert_eq!(cfg.public_name, "cloudflare-ech.com");
    }

    #[test]
    fn truncated_record_is_rejected_not_panicking() {
        let list = encode_ech_config("example.com");
        for cut in [0, 1, 2, 3, 4, 10] {
            let truncated = &list[..cut.min(list.len())];
            assert!(parse_ech_config_from_https_record(truncated).is_err());
        }
    }

    #[test]
    fn record_with_only_unsupported_versions_errs() {
        let mut unknown = Vec::new();
        unknown.extend_from_slice(&0xFE0Au16.to_be_bytes());
        unknown.extend_from_slice(&2u16.to_be_bytes());
        unknown.extend_from_slice(&[0u8; 2]);
        assert!(parse_ech_config_from_https_record(&unknown).is_err());
    }

    #[test]
    fn ech_grease_fe0d_uses_the_real_type_and_grows_record() {
        let record = encode_client_hello("example.com");
        let with_grease = inject_ech_grease_fe0d(&record).unwrap();
        assert!(with_grease.len() > record.len());
        let exts = crate::fragmentation::list_extensions(&with_grease).unwrap();
        assert!(exts.iter().any(|e| e.ext_type == ECH_EXTENSION_TYPE));
        // Structurally valid: record length matches the body.
        let rec_len = u16::from_be_bytes([with_grease[3], with_grease[4]]) as usize;
        assert_eq!(5 + rec_len, with_grease.len());
    }

    /// Hand-encode an ECHConfig the sealing path can consume.
    fn encode_detailed_config(public_name: &str, config_id: u8, suite: (u16, u16)) -> Vec<u8> {
        let mut contents = Vec::new();
        contents.push(config_id);
        contents.extend_from_slice(&0x0020u16.to_be_bytes()); // KEM X25519
        contents.extend_from_slice(&32u16.to_be_bytes());
        contents.extend_from_slice(&[0x11u8; 32]); // X25519 public key
        contents.extend_from_slice(&4u16.to_be_bytes());
        contents.extend_from_slice(&suite.0.to_be_bytes());
        contents.extend_from_slice(&suite.1.to_be_bytes());
        contents.push(128); // maximum_name_length
        contents.push(public_name.len() as u8);
        contents.extend_from_slice(public_name.as_bytes());
        contents.extend_from_slice(&0u16.to_be_bytes()); // empty extensions

        let mut entry = Vec::new();
        entry.extend_from_slice(&ECH_EXTENSION_TYPE.to_be_bytes());
        entry.extend_from_slice(&(contents.len() as u16).to_be_bytes());
        entry.extend_from_slice(&contents);
        entry
    }

    #[test]
    fn parses_detailed_ech_config_fields() {
        let raw = encode_detailed_config("cloudflare-ech.com", 7, (0x0001, 0x0003));
        let cfg = parse_ech_config_detailed(&raw).unwrap();
        assert_eq!(cfg.config_id, 7);
        assert_eq!(cfg.kem_id, 0x0020);
        assert_eq!(cfg.public_key.len(), 32);
        assert_eq!(cfg.cipher_suites, vec![(0x0001, 0x0003)]);
        assert_eq!(cfg.maximum_name_length, 128);
        assert_eq!(cfg.public_name, "cloudflare-ech.com");
        assert_eq!(cfg.raw, raw);
        assert!(!cfg.contents.is_empty());
        // Truncation fails cleanly.
        for cut in [0, 2, 4, 6, 30, 40] {
            assert!(parse_ech_config_detailed(&raw[..cut.min(raw.len())]).is_err());
        }
    }

    #[test]
    fn real_ech_seal_hides_sni_and_is_deterministic() {
        let record = encode_client_hello("secret.example.com");
        let raw = encode_detailed_config("public.example", 7, (0x0001, 0x0003));
        let cfg = parse_ech_config_detailed(&raw).unwrap();

        let seed = [0x42u8; 32];
        let sealed = seal_real_ech_hello(&record, b"secret.example.com", &cfg, Some(seed)).unwrap();

        // Outer SNI is the ECH public_name.
        let (s, e) = crate::fragmentation::calculate_smart_split_points(&sealed).unwrap();
        assert_eq!(&sealed[s..e], b"public.example");
        // Real name appears nowhere in the sealed hello.
        assert!(!sealed.windows(18).any(|w| w == b"secret.example.com"));
        // The ECH extension is present and begins with the config id.
        let exts = crate::fragmentation::list_extensions(&sealed).unwrap();
        let ech = exts
            .iter()
            .find(|x| x.ext_type == ECH_EXTENSION_TYPE)
            .unwrap();
        // RFC 9849 layout: kdf u16 | aead u16 | config_id u8 | enc | payload.
        assert_eq!(
            &sealed[ech.body_start..ech.body_start + 5],
            [0x00, 0x01, 0x00, 0x03, 7]
        );
        // enc is 32 bytes (X25519) after kdf + aead + config_id + u16 length.
        let enc_len =
            u16::from_be_bytes([sealed[ech.body_start + 5], sealed[ech.body_start + 6]]) as usize;
        assert_eq!(enc_len, 32);
        // All length fields add up; sealing is deterministic under a seed.
        let rec_len = u16::from_be_bytes([sealed[3], sealed[4]]) as usize;
        assert_eq!(5 + rec_len, sealed.len());
        let again = seal_real_ech_hello(&record, b"secret.example.com", &cfg, Some(seed)).unwrap();
        assert_eq!(sealed, again);
        // A different ephemeral seed changes the ciphertext.
        let other =
            seal_real_ech_hello(&record, b"secret.example.com", &cfg, Some([7u8; 32])).unwrap();
        assert_ne!(sealed, other);
    }

    /// Server-side round trip (RFC 9849): re-derive the shared secret from
    /// the same deterministic seed, rebuild the AAD exactly like BoringSSL
    /// and NSS do (outer ClientHello body with the payload zeroed), open
    /// the AEAD and recover an EncodedClientHelloInner that carries the
    /// real SNI, the inner marker, and zero padding to a multiple of 32.
    /// This proves the seal is decryptable by a real ECH server, not
    /// merely well-formed.
    #[test]
    fn real_ech_sealed_payload_decrypts_to_inner_hello() {
        let record = encode_client_hello("secret.example.com");
        let raw = encode_detailed_config("public.example", 7, (0x0001, 0x0003));
        let cfg = parse_ech_config_detailed(&raw).unwrap();
        let seed = [0x42u8; 32];
        let sealed = seal_real_ech_hello(&record, b"secret.example.com", &cfg, Some(seed)).unwrap();

        // Recompute the server side of the same exchange.
        let mut pk_rm = [0u8; 32];
        pk_rm.copy_from_slice(&cfg.public_key);
        let (enc, ss) = crate::hpke::kem_encapsulate(&pk_rm, Some(seed)).unwrap();
        let mut info = Vec::new();
        info.extend_from_slice(b"tls ech");
        info.push(0);
        info.extend_from_slice(&cfg.raw);
        let (key, nonce) = crate::hpke::key_schedule(
            &ss,
            &info,
            crate::hpke::KEM_ID_X25519,
            crate::hpke::KDF_ID_SHA256,
            crate::hpke::AEAD_ID_CHACHA20_POLY1305,
        )
        .unwrap();

        // Pull the ECH extension out of the sealed outer hello.
        let exts = crate::fragmentation::list_extensions(&sealed).unwrap();
        let ech = exts
            .iter()
            .find(|x| x.ext_type == ECH_EXTENSION_TYPE)
            .unwrap();
        let body = &sealed[ech.body_start..ech.body_end];
        // Body: kdf(2) + aead(2) + config(1) + u16(enc_len) + enc
        //     + u16(payload_len) + payload.
        let enc_len = u16::from_be_bytes([body[5], body[6]]) as usize;
        let payload_pos = 7 + enc_len + 2;
        let payload_len = u16::from_be_bytes([body[7 + enc_len], body[8 + enc_len]]) as usize;
        assert_eq!(enc.len(), enc_len);
        assert_eq!(payload_pos + payload_len, body.len());
        let payload = &body[payload_pos..];

        // AAD: ClientHello body (hello minus record+handshake headers) with
        // the payload region zeroed.
        let mut aad = sealed[9..].to_vec();
        let aad_off = ech.body_start + payload_pos - 9;
        for b in aad[aad_off..aad_off + payload_len].iter_mut() {
            *b = 0;
        }

        // Decrypt; the plaintext is the EncodedClientHelloInner.
        let inner = crate::hpke::chacha20_poly1305_open(&key, &nonce, &aad, payload).unwrap();
        // Real SNI inside, cover name nowhere.
        assert!(inner.windows(18).any(|w| w == b"secret.example.com"));
        assert!(!inner.windows(14).any(|w| w == b"public.example"));
        // Inner marker extension 0xFE0D with one-byte body 0x01.
        assert!(inner
            .windows(5)
            .any(|w| w == [0xFE, 0x0D, 0x00, 0x01, 0x01]));
        // supported_versions present (0x002B).
        assert!(inner.windows(2).any(|w| w == [0x00, 0x2B]));
        // Empty legacy_session_id: byte 34 of the ClientHello body.
        assert_eq!(inner[34], 0);
        // Zero padding to a multiple of 32 bytes (RFC 9849 §6.1.3).
        assert_eq!(inner.len() % 32, 0);
        assert!(inner[inner.len() - 8..].iter().all(|&b| b == 0));
    }

    #[test]
    fn real_ech_rejects_unusable_configs_and_names() {
        let record = encode_client_hello("secret.example.com");

        // Config without the ChaCha20Poly1305 suite.
        let raw = encode_detailed_config("public.example", 1, (0x0001, 0x0001));
        let cfg = parse_ech_config_detailed(&raw).unwrap();
        assert!(seal_real_ech_hello(&record, b"secret.example.com", &cfg, None).is_err());

        // Wrong KEM id.
        let mut bad_kem = encode_detailed_config("public.example", 1, (0x0001, 0x0003));
        bad_kem[6] = 0x00; // kem_id low byte -> 0x0000 (unsupported KEM)
        let cfg = parse_ech_config_detailed(&bad_kem).unwrap();
        assert!(seal_real_ech_hello(&record, b"secret.example.com", &cfg, None).is_err());

        // maximum_name_length exceeded.
        let raw = encode_detailed_config("public.example", 1, (0x0001, 0x0003));
        let mut cfg = parse_ech_config_detailed(&raw).unwrap();
        cfg.maximum_name_length = 4;
        assert!(seal_real_ech_hello(&record, b"secret.example.com", &cfg, None).is_err());

        // Empty SNI.
        let raw = encode_detailed_config("public.example", 1, (0x0001, 0x0003));
        let cfg = parse_ech_config_detailed(&raw).unwrap();
        assert!(seal_real_ech_hello(&record, b"", &cfg, None).is_err());
    }
}
