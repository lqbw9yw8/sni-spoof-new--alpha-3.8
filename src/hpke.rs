//! hpke — pure-Rust HPKE base-mode primitives for real ECH sealing. [UNTESTED]
//!
//! Implements exactly the slice of RFC 9180 that ECH (draft-ietf-tls-esni,
//! extension `0xFE0D`) needs:
//!   * DHKEM(X25519, HKDF-SHA256) — kem_id `0x0020` (RFC 7748 + RFC 9180 §7.1)
//!   * KDF HKDF-SHA256 — kdf_id `0x0001` (RFC 5869, on top of `sha2`)
//!   * AEAD ChaCha20Poly1305 — aead_id `0x0003` (RFC 8439)
//!
//! No external crypto crate is added to the dependency tree: X25519, HMAC,
//! HKDF, ChaCha20 and Poly1305 are implemented here and unit-tested against
//! the official RFC test vectors. `#![deny(unsafe_code)]` applies crate-wide.
//!
//! Security note: this code is written for correctness and readability, not
//! for being constant-time. It protects the real SNI from a passive or
//! stateless DPI observer, which is this tool's threat model; it is not a
//! general-purpose crypto library.

use crate::error::DpiGuardError;
use sha2::{Digest, Sha256};

pub const KEM_ID_X25519: u16 = 0x0020;
pub const KDF_ID_SHA256: u16 = 0x0001;
pub const AEAD_ID_CHACHA20_POLY1305: u16 = 0x0003;

// ---------------------------------------------------------------------------
// X25519 (RFC 7748) — 5x51-bit limbs, Montgomery ladder per the RFC body.
// ---------------------------------------------------------------------------

const MASK51: u64 = (1u64 << 51) - 1;

/// p = 2^255 - 19, little-endian bytes (for final canonical reduction).
const P_BYTES: [u8; 32] = {
    let mut p = [0xffu8; 32];
    p[0] = 0xed;
    p[31] = 0x7f;
    p
};

#[derive(Clone, Copy)]
struct Fe([u64; 5]);

impl Fe {
    const ZERO: Fe = Fe([0; 5]);
    const ONE: Fe = Fe([1, 0, 0, 0, 0]);
    /// (486662 - 2) / 4 for the Montgomery ladder.
    const A24: Fe = Fe([121665, 0, 0, 0, 0]);

    /// Decode a u-coordinate: little-endian, top bit masked (RFC 7748 §5).
    fn from_bytes(b: &[u8; 32]) -> Fe {
        let mut w = [0u8; 32];
        w.copy_from_slice(b);
        w[31] &= 127;
        // Manual byte array construction avoids try_into().unwrap() panic paths
        // while keeping the same bit layout; slice ranges are fixed length.
        Fe([
            u64::from_le_bytes([w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]]) & MASK51,
            (u64::from_le_bytes([w[6], w[7], w[8], w[9], w[10], w[11], w[12], w[13]]) >> 3)
                & MASK51,
            (u64::from_le_bytes([w[12], w[13], w[14], w[15], w[16], w[17], w[18], w[19]]) >> 6)
                & MASK51,
            (u64::from_le_bytes([w[19], w[20], w[21], w[22], w[23], w[24], w[25], w[26]]) >> 1)
                & MASK51,
            (u64::from_le_bytes([w[24], w[25], w[26], w[27], w[28], w[29], w[30], w[31]]) >> 12)
                & MASK51,
        ])
    }

    fn add(&self, o: &Fe) -> Fe {
        Fe([
            self.0[0] + o.0[0],
            self.0[1] + o.0[1],
            self.0[2] + o.0[2],
            self.0[3] + o.0[3],
            self.0[4] + o.0[4],
        ])
    }

    /// a − b mod p.
    ///
    /// The previous version used 64-bit bias constants mislabeled as
    /// "curve25519-donna-c64's fsub"; donna uses 54-bit limbs there, this
    /// field is 5×51-bit, so the biases overflowed (debug panic) and even
    /// without overflow they were not a multiple of p — every X25519/HPKE
    /// result was wrong (audit F-06). The current version canonicalizes
    /// both operands (value < p via `to_bytes`), subtracts limb-wise with
    /// a borrow in i128, and adds p back once when the result went
    /// negative. Correct for *any* input limbs, not just mul outputs.
    /// NOTE: the borrow branch is data-dependent; the ladder operates on
    /// per-connection ephemeral keys and public ECH config values, so this
    /// is acceptable here (documented trade-off, not a secret-key path).
    fn sub(&self, o: &Fe) -> Fe {
        let a = Fe::from_bytes(&self.to_bytes());
        let b = Fe::from_bytes(&o.to_bytes());
        let mut r = [0u64; 5];
        let mut borrow: i128 = 0;
        for (i, (av, bv)) in a.0.iter().zip(b.0.iter()).enumerate() {
            let v = *av as i128 - *bv as i128 - borrow;
            if v < 0 {
                r[i] = (v + (1i128 << 51)) as u64;
                borrow = 1;
            } else {
                r[i] = v as u64;
                borrow = 0;
            }
        }
        if borrow != 0 {
            // The schoolbook borrow chain emits a − b + 2^255 (radix²
            // wrap-around), NOT a − b. Since 2^255 ≡ 19 (mod p), the value
            // to correct is −19 — applied limb-wise with propagation,
            // because r ≥ 19 holds for the VALUE but not necessarily for
            // limb 0 alone (e.g. a = 0, b = 2^192 gives r = 2^255 − 2^192
            // with r[0] == 0 — the first fix subtracted straight from
            // r[0] and panicked on overflow).
            let mut take: i128 = 19;
            for limb in r.iter_mut() {
                let low = take & ((1i128 << 51) - 1);
                let v = *limb as i128 - low;
                if v < 0 {
                    *limb = (v + (1i128 << 51)) as u64;
                    take = 1 + (take >> 51);
                } else {
                    *limb = v as u64;
                    take >>= 51;
                }
            }
            debug_assert_eq!(take, 0, "canonical a−b keeps r ≥ 19");
        }
        Fe(r)
    }

    fn mul(&self, o: &Fe) -> Fe {
        let a = self.0;
        let b = o.0;
        let b19_1 = b[1] as u128 * 19;
        let b19_2 = b[2] as u128 * 19;
        let b19_3 = b[3] as u128 * 19;
        let b19_4 = b[4] as u128 * 19;
        let a0 = a[0] as u128;
        let a1 = a[1] as u128;
        let a2 = a[2] as u128;
        let a3 = a[3] as u128;
        let a4 = a[4] as u128;

        let t0 = a0 * b[0] as u128 + a1 * b19_4 + a2 * b19_3 + a3 * b19_2 + a4 * b19_1;
        let t1 = a0 * b[1] as u128 + a1 * b[0] as u128 + a2 * b19_4 + a3 * b19_3 + a4 * b19_2;
        let t2 = a0 * b[2] as u128 + a1 * b[1] as u128 + a2 * b[0] as u128;
        let t2 = t2 + a3 * b19_4 + a4 * b19_3;
        let t3 = a0 * b[3] as u128 + a1 * b[2] as u128 + a2 * b[1] as u128 + a3 * b[0] as u128;
        let t3 = t3 + a4 * b19_4;
        let t4 = a0 * b[4] as u128 + a1 * b[3] as u128 + a2 * b[2] as u128 + a3 * b[1] as u128;
        let t4 = t4 + a4 * b[0] as u128;

        let mut r = [0u64; 5];
        let c = t0 >> 51;
        r[0] = (t0 & MASK51 as u128) as u64;
        let t1 = t1 + c;
        let c = t1 >> 51;
        r[1] = (t1 & MASK51 as u128) as u64;
        let t2 = t2 + c;
        let c = t2 >> 51;
        r[2] = (t2 & MASK51 as u128) as u64;
        let t3 = t3 + c;
        let c = t3 >> 51;
        r[3] = (t3 & MASK51 as u128) as u64;
        let t4 = t4 + c;
        let c = t4 >> 51;
        r[4] = (t4 & MASK51 as u128) as u64;
        r[0] += c as u64 * 19;
        let c = r[0] >> 51;
        r[0] &= MASK51;
        r[1] += c;
        Fe(r)
    }

    /// Encode to 32 canonical little-endian bytes (fully reduced mod p).
    fn to_bytes(self) -> [u8; 32] {
        // Carry-normalize first: slack limbs (mul/add outputs can reach
        // 2^52+) may encode to a value ≥ 2^256, and the acc window below
        // drops bits ≥ 256 — 2^256 ≡ 38 (mod p), so dropping them shifted
        // results by multiples of 38 (audit F-06, caught by the algebraic
        // property test). One carry chain preserves the value mod p and
        // brings every limb under 2^51.
        let mut n = [0u64; 5];
        let mut c: u128 = 0;
        for (i, limb) in self.0.iter().enumerate() {
            let t = *limb as u128 + c;
            n[i] = (t & MASK51 as u128) as u64;
            c = t >> 51;
        }
        n[0] += (c as u64) * 19;
        let cc = n[0] >> 51;
        n[0] &= MASK51;
        n[1] += cc;
        let t = n;
        // Pack the 5x51-bit limbs into four 64-bit little-endian words
        // using real addition (robust even if a limb transiently exceeds
        // 51 bits — no bit-range collisions, no overflow: every shifted
        // piece below fits in u128).
        let mut acc = [0u128; 5];
        // Pure u128 accumulation: acc[word] receives limb<<shift and CAN
        // hold up to ~102 bits — the fold loop below propagates the ≥64-bit
        // parts. The previous version ALSO pre-placed `v >> (64 - shift)`
        // into acc[word + 1]; since acc[word] never truncated, those high
        // bits were counted twice and every multi-limb encoding was wrong
        // (audit F-06: this is what broke all of X25519).
        for (i, limb) in t.iter().enumerate() {
            let off = 51 * i;
            let word = off / 64;
            let shift = off % 64;
            acc[word] += (*limb as u128) << shift;
        }
        let mut words = [0u64; 4];
        for j in 0..4 {
            acc[j + 1] += acc[j] >> 64;
            words[j] = acc[j] as u64;
        }
        let mut out = [0u8; 32];
        out[0..8].copy_from_slice(&words[0].to_le_bytes());
        out[8..16].copy_from_slice(&words[1].to_le_bytes());
        out[16..24].copy_from_slice(&words[2].to_le_bytes());
        out[24..32].copy_from_slice(&words[3].to_le_bytes());

        // Conditional subtraction of p = 2^255 - 19 (at most twice).
        for _ in 0..2 {
            if bytes_ge_p(&out) {
                bytes_sub_p(&mut out);
            }
        }
        out
    }

    /// self^(p-2) — modular inverse. Square-and-multiply over the bits of
    /// 2^255 - 21; performance is irrelevant on the evasion path.
    fn invert(&self) -> Fe {
        let mut exp = [0u8; 32];
        exp[0] = 0xeb;
        for e in exp.iter_mut().take(31).skip(1) {
            *e = 0xff;
        }
        exp[31] = 0x7f;
        let mut acc = Fe::ONE;
        for i in (0..256).rev() {
            acc = acc.mul(&acc);
            if (exp[i / 8] >> (i % 8)) & 1 == 1 {
                acc = acc.mul(self);
            }
        }
        acc
    }
}

fn bytes_ge_p(a: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        if a[i] > P_BYTES[i] {
            return true;
        }
        if a[i] < P_BYTES[i] {
            return false;
        }
    }
    true // equal
}

fn bytes_sub_p(a: &mut [u8; 32]) {
    let mut borrow: u16 = 0;
    for i in 0..32 {
        let d = (a[i] as u16)
            .wrapping_sub(P_BYTES[i] as u16)
            .wrapping_sub(borrow);
        a[i] = d as u8;
        borrow = u16::from(d > 255);
    }
}

/// X25519 scalar multiplication (RFC 7748 §5). Clamps the scalar, masks the
/// u-coordinate's top bit, runs the Montgomery ladder, returns the encoded
/// u-coordinate of the result.
pub fn x25519(k: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let mut k = *k;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;

    let x1 = Fe::from_bytes(u);
    let mut x2 = Fe::ONE;
    let mut z2 = Fe::ZERO;
    let mut x3 = x1;
    let mut z3 = Fe::ONE;
    let mut swap = 0u64;

    for t in (0..255).rev() {
        let kt = u64::from((k[t / 8] >> (t % 8)) & 1);
        swap ^= kt;
        if swap != 0 {
            std::mem::swap(&mut x2, &mut x3);
            std::mem::swap(&mut z2, &mut z3);
        }
        swap = kt;

        let a = x2.add(&z2);
        let aa = a.mul(&a);
        let b = x2.sub(&z2);
        let bb = b.mul(&b);
        let e = aa.sub(&bb);
        let c = x3.add(&z3);
        let d = x3.sub(&z3);
        let da = d.mul(&a);
        let cb = c.mul(&b);

        x3 = da.add(&cb).mul(&da.add(&cb));
        let dm = da.sub(&cb);
        z3 = x1.mul(&dm.mul(&dm));
        x2 = aa.mul(&bb);
        z2 = e.mul(&aa.add(&Fe::A24.mul(&e)));
    }
    if swap != 0 {
        std::mem::swap(&mut x2, &mut x3);
        std::mem::swap(&mut z2, &mut z3);
    }
    x2.mul(&z2.invert()).to_bytes()
}

/// X25519 base-point multiplication (public-key derivation).
pub fn x25519_base(sk: &[u8; 32]) -> [u8; 32] {
    let mut u = [0u8; 32];
    u[0] = 9;
    x25519(sk, &u)
}

// ---------------------------------------------------------------------------
// HMAC-SHA256 / HKDF (RFC 2104 / RFC 5869)
// ---------------------------------------------------------------------------

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k0 = [0u8; 64];
    if key.len() > 64 {
        let h = Sha256::digest(key);
        k0[..32].copy_from_slice(&h);
    } else {
        k0[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k0[i];
        opad[i] ^= k0[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let ih = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(ih);
    outer.finalize().into()
}

/// HKDF-Extract. An empty salt is the HashLen zero string (RFC 5869 §2.2).
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    hmac_sha256(salt, ikm)
}

pub fn hkdf_expand(prk: &[u8; 32], info: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut t: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;
    while out.len() < len {
        let mut msg = Vec::with_capacity(t.len() + info.len() + 1);
        msg.extend_from_slice(&t);
        msg.extend_from_slice(info);
        msg.push(counter);
        t = hmac_sha256(prk, &msg).to_vec();
        out.extend_from_slice(&t);
        counter += 1;
    }
    out.truncate(len);
    out
}

// ---------------------------------------------------------------------------
// RFC 9180 labeled KDF + KEM + KeySchedule (base mode only)
// ---------------------------------------------------------------------------

const HPKE_V1: &[u8] = b"HPKE-v1";

fn kem_suite_id() -> Vec<u8> {
    let mut v = b"KEM".to_vec();
    v.extend_from_slice(&KEM_ID_X25519.to_be_bytes());
    v
}

fn hpke_suite_id(kem: u16, kdf: u16, aead: u16) -> Vec<u8> {
    let mut v = b"HPKE".to_vec();
    v.extend_from_slice(&kem.to_be_bytes());
    v.extend_from_slice(&kdf.to_be_bytes());
    v.extend_from_slice(&aead.to_be_bytes());
    v
}

fn labeled_extract(suite_id: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut labeled = Vec::with_capacity(HPKE_V1.len() + suite_id.len() + label.len() + ikm.len());
    labeled.extend_from_slice(HPKE_V1);
    labeled.extend_from_slice(suite_id);
    labeled.extend_from_slice(label);
    labeled.extend_from_slice(ikm);
    hkdf_extract(salt, &labeled)
}

fn labeled_expand(
    suite_id: &[u8],
    prk: &[u8; 32],
    label: &[u8],
    info: &[u8],
    len: usize,
) -> Vec<u8> {
    let mut labeled =
        Vec::with_capacity(2 + HPKE_V1.len() + suite_id.len() + label.len() + info.len());
    labeled.extend_from_slice(&(len as u16).to_be_bytes());
    labeled.extend_from_slice(HPKE_V1);
    labeled.extend_from_slice(suite_id);
    labeled.extend_from_slice(label);
    labeled.extend_from_slice(info);
    hkdf_expand(prk, &labeled, len)
}

/// RFC 9180 §7.1.3 DeriveKeyPair for X25519.
pub fn derive_keypair_x25519(ikm: &[u8]) -> ([u8; 32], [u8; 32]) {
    let suite = kem_suite_id();
    let dkp_prk = labeled_extract(&suite, &[], b"dkp_prk", ikm);
    let sk_bytes = labeled_expand(&suite, &dkp_prk, b"sk", &[], 32);
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&sk_bytes);
    let pk = x25519_base(&sk);
    (sk, pk)
}

/// DHKEM(X25519) encapsulation. `ikm_seed` makes the ephemeral keypair
/// deterministic (tests); `None` generates a random one. Returns
/// `(enc, shared_secret)` where `enc` is the ephemeral public key.
pub fn kem_encapsulate(
    pk_rm: &[u8; 32],
    ikm_seed: Option<[u8; 32]>,
) -> Result<([u8; 32], [u8; 32]), DpiGuardError> {
    let ikm: [u8; 32] = match ikm_seed {
        Some(s) => s,
        None => rand::random(),
    };
    let (sk_e, pk_e) = derive_keypair_x25519(&ikm);
    let dh = x25519(&sk_e, pk_rm);
    let suite = kem_suite_id();
    let mut kem_context = Vec::with_capacity(64);
    kem_context.extend_from_slice(&pk_e);
    kem_context.extend_from_slice(pk_rm);
    let eae_prk = labeled_extract(&suite, &[], b"eae_prk", &dh);
    let ss = labeled_expand(&suite, &eae_prk, b"shared_secret", &kem_context, 32);
    let mut shared = [0u8; 32];
    shared.copy_from_slice(&ss);
    Ok((pk_e, shared))
}

/// HPKE base-mode KeySchedule (RFC 9180 §5.1) → `(key, base_nonce)` for
/// ChaCha20Poly1305 (Nk=32, Nn=12). No PSK.
pub fn key_schedule(
    shared_secret: &[u8; 32],
    info: &[u8],
    kem: u16,
    kdf: u16,
    aead: u16,
) -> Result<([u8; 32], [u8; 12]), DpiGuardError> {
    if aead != AEAD_ID_CHACHA20_POLY1305 {
        return Err(DpiGuardError::OutOfRange(format!(
            "unsupported AEAD id 0x{aead:04X} (only ChaCha20Poly1305 0x0003 is implemented)"
        )));
    }
    let suite = hpke_suite_id(kem, kdf, aead);
    let psk_id_hash = labeled_extract(&suite, &[], b"psk_id_hash", &[]);
    let info_hash = labeled_extract(&suite, &[], b"info_hash", info);
    let mut ks_context = Vec::with_capacity(65);
    ks_context.push(0u8); // mode_base
    ks_context.extend_from_slice(&psk_id_hash);
    ks_context.extend_from_slice(&info_hash);
    let secret = labeled_extract(&suite, shared_secret, b"secret", &[]);
    let key = labeled_expand(&suite, &secret, b"key", &ks_context, 32);
    let nonce = labeled_expand(&suite, &secret, b"base_nonce", &ks_context, 12);
    let mut k = [0u8; 32];
    k.copy_from_slice(&key);
    let mut n = [0u8; 12];
    n.copy_from_slice(&nonce);
    Ok((k, n))
}

// ---------------------------------------------------------------------------
// ChaCha20 + Poly1305 (RFC 8439)
// ---------------------------------------------------------------------------

fn qr(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(7);
}

fn le_u32_from_4(b: &[u8]) -> u32 {
    // Safe helper: b is guaranteed length 4 by caller ranges
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut state = [0u32; 16];
    state[0] = 0x6170_7865;
    state[1] = 0x3320_646e;
    state[2] = 0x7962_2d32;
    state[3] = 0x6b20_6574;
    for i in 0..8 {
        let off = i * 4;
        state[4 + i] = le_u32_from_4(&key[off..off + 4]);
    }
    state[12] = counter;
    for i in 0..3 {
        let off = i * 4;
        state[13 + i] = le_u32_from_4(&nonce[off..off + 4]);
    }
    let mut w = state;
    for _ in 0..10 {
        qr(&mut w, 0, 4, 8, 12);
        qr(&mut w, 1, 5, 9, 13);
        qr(&mut w, 2, 6, 10, 14);
        qr(&mut w, 3, 7, 11, 15);
        qr(&mut w, 0, 5, 10, 15);
        qr(&mut w, 1, 6, 11, 12);
        qr(&mut w, 2, 7, 8, 13);
        qr(&mut w, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        out[i * 4..i * 4 + 4].copy_from_slice(&w[i].wrapping_add(state[i]).to_le_bytes());
    }
    out
}

/// ChaCha20 keystream XOR (encryption and decryption are the same op).
pub fn chacha20_xor(key: &[u8; 32], counter: u32, nonce: &[u8; 12], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut block_index = counter;
    let mut pos = 0;
    while pos < data.len() {
        let block = chacha20_block(key, block_index, nonce);
        let take = (data.len() - pos).min(64);
        for i in 0..take {
            out.push(data[pos + i] ^ block[i]);
        }
        pos += take;
        block_index = block_index.wrapping_add(1);
    }
    out
}

fn le_u64_from_8(b: &[u8]) -> u64 {
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// Poly1305 one-time MAC (RFC 8439 §2.5), 44-bit radix with u128 products.
pub fn poly1305_mac(msg: &[u8], key: &[u8; 32]) -> [u8; 16] {
    const MASK44: u128 = (1u128 << 44) - 1;

    // Clamp r (RFC 8439 §2.5).
    let mut rb = [0u8; 16];
    rb.copy_from_slice(&key[..16]);
    rb[3] &= 15;
    rb[7] &= 15;
    rb[11] &= 15;
    rb[15] &= 15;
    rb[4] &= 252;
    rb[8] &= 252;
    rb[12] &= 252;

    let r_lo = le_u64_from_8(&rb[0..8]) as u128;
    let r_hi = le_u64_from_8(&rb[8..16]) as u128;
    let r0 = r_lo & MASK44;
    let r1 = ((r_lo >> 44) | (r_hi << 20)) & MASK44;
    let r2 = r_hi >> 24;

    let mut h0: u128 = 0;
    let mut h1: u128 = 0;
    let mut h2: u128 = 0;

    let mut pos = 0;
    while pos < msg.len() {
        let take = (msg.len() - pos).min(16);
        // Block value = little-endian bytes with a 0x01 appended at the end.
        let mut wide = [0u8; 24];
        wide[..take].copy_from_slice(&msg[pos..pos + take]);
        wide[take] = 1;
        let w0 = le_u64_from_8(&wide[0..8]) as u128;
        let w1 = le_u64_from_8(&wide[8..16]) as u128;
        // wide is 24 bytes: only the low 8 of this high word can be nonzero
        // (the 0x01 pad byte lives at wide[16] when take == 16). The old
        // code called u128::from_le_bytes on an 8-byte slice and panicked
        // (audit F-06); u64 is the correct width here.
        let w2 = le_u64_from_8(&wide[16..24]) as u128;
        let n0 = w0 & MASK44;
        let n1 = ((w0 >> 44) | (w1 << 20)) & MASK44;
        let n2 = (w1 >> 24) | (w2 << 40);
        h0 += n0;
        h1 += n1;
        h2 += n2;

        // h = h * r mod 2^130 - 5.
        // Radix B = 2^44 ⇒ B³ = 2^132 = 4·2^130 ≡ 4·5 = 20 (mod 2^130−5).
        // The first version folded the B³/B⁴ cross terms with ×5 — that is
        // the 2^65-radix coefficient — so every tag was wrong (audit F-06,
        // RFC 8439 §2.5.2 vector). s1/s2 are the pre-multiplied ×20 forms
        // used by poly1305-donna-64.
        let s1 = r1 * 20;
        let s2 = r2 * 20;
        let d0 = h0 * r0 + h1 * s2 + h2 * s1;
        let d1 = h0 * r1 + h1 * r0 + h2 * s2;
        let d2 = h0 * r2 + h1 * r1 + h2 * r0;
        let c = d0 >> 44;
        h0 = d0 & MASK44;
        let d1 = d1 + c;
        let c = d1 >> 44;
        h1 = d1 & MASK44;
        let d2 = d2 + c;
        let c = d2 >> 44;
        h2 = d2 & MASK44;
        h0 += c * 20; // leftover B³ coefficient ≡ 20
        let c = h0 >> 44;
        h0 &= MASK44;
        h1 += c;

        pos += take;
    }

    // Final freeze: full carry, then h mod (2^130 - 5).
    // h2 is the coefficient of B² = 2^88, so every unit of h2 ≥ 2^42 is a
    // 2^130 unit ≡ 5. Fold at the 2^42 boundary (the old code folded
    // h2 >> 44 with ×5 — wrong radix twice over, audit F-06).
    let mut c = h1 >> 44;
    h1 &= MASK44;
    h2 += c;
    c = h2 >> 42;
    h2 &= (1u128 << 42) - 1;
    h0 += c * 5;
    c = h0 >> 44;
    h0 &= MASK44;
    h1 += c;
    c = h1 >> 44;
    h1 &= MASK44;
    h2 += c; // ≤ 1 → h < 2^130 + 1, the g-trick below absorbs it

    // g = h + 5; if g >= 2^130 use g - 2^130, else keep h.
    let g0 = h0 + 5;
    c = g0 >> 44;
    let g0 = g0 & MASK44;
    let g1 = h1 + c;
    c = g1 >> 44;
    let g1 = g1 & MASK44;
    let g2 = h2.wrapping_add(c).wrapping_sub(1u128 << 42);
    let (f0, f1, f2) = if g2 >> 127 == 0 {
        (g0, g1, g2)
    } else {
        (h0, h1, h2)
    };

    // tag = (h + s) mod 2^128
    let hv = (f0) | (f1 << 44) | (f2 << 88);
    let s_lo = le_u64_from_8(&key[16..24]) as u128;
    let s_hi = le_u64_from_8(&key[24..32]) as u128;
    let s = s_lo | (s_hi << 64);
    hv.wrapping_add(s).to_le_bytes()
}

fn poly1305_key_gen(key: &[u8; 32], nonce: &[u8; 12]) -> [u8; 32] {
    let block = chacha20_block(key, 0, nonce);
    let mut k = [0u8; 32];
    k.copy_from_slice(&block[..32]);
    k
}

fn build_mac_data(aad: &[u8], ct: &[u8]) -> Vec<u8> {
    let zeros = |section_len: usize| -> Vec<u8> { vec![0u8; (16 - section_len % 16) % 16] };
    let mut v = Vec::with_capacity(aad.len() + ct.len() + 34);
    v.extend_from_slice(aad);
    v.extend(zeros(aad.len()));
    v.extend_from_slice(ct);
    v.extend(zeros(ct.len()));
    v.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    v.extend_from_slice(&(ct.len() as u64).to_le_bytes());
    v
}

/// AEAD seal (RFC 8439 §2.8): returns ciphertext || 16-byte tag.
pub fn chacha20_poly1305_seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], pt: &[u8]) -> Vec<u8> {
    let otk = poly1305_key_gen(key, nonce);
    let ct = chacha20_xor(key, 1, nonce, pt);
    let tag = poly1305_mac(&build_mac_data(aad, &ct), &otk);
    let mut out = ct;
    out.extend_from_slice(&tag);
    out
}

/// AEAD open: verifies the tag (constant-time compare) and decrypts.
pub fn chacha20_poly1305_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ct_tag: &[u8],
) -> Result<Vec<u8>, DpiGuardError> {
    if ct_tag.len() < 16 {
        return Err(DpiGuardError::OutOfRange(
            "AEAD ciphertext too short".into(),
        ));
    }
    let (ct, tag) = ct_tag.split_at(ct_tag.len() - 16);
    let otk = poly1305_key_gen(key, nonce);
    let expected = poly1305_mac(&build_mac_data(aad, ct), &otk);
    if !crate::integrity::constant_time_eq(tag, &expected) {
        return Err(DpiGuardError::OutOfRange("AEAD tag mismatch".into()));
    }
    Ok(chacha20_xor(key, 1, nonce, ct))
}

// ---------------------------------------------------------------------------
// Hex decoding (for `real_ech_config_hex` in the config)
// ---------------------------------------------------------------------------

pub fn decode_hex(s: &str) -> Result<Vec<u8>, DpiGuardError> {
    let s = s.trim().trim_start_matches("0x");
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if !s.len().is_multiple_of(2) {
        return Err(DpiGuardError::OutOfRange("odd-length hex string".into()));
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for i in (0..bytes.len()).step_by(2) {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, DpiGuardError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(DpiGuardError::OutOfRange("invalid hex digit".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        decode_hex(s).unwrap()
    }

    // --- X25519: RFC 7748 §6.1 test vector 1 ---
    #[test]
    fn x25519_rfc7748_vector_1() {
        let k: [u8; 32] = hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
            .try_into()
            .unwrap();
        let u: [u8; 32] = hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
            .try_into()
            .unwrap();
        let expected = hex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
        assert_eq!(x25519(&k, &u).to_vec(), expected);
    }

    // --- X25519 Diffie-Hellman: RFC 7748 §6.1 (generator vectors) ---
    #[test]
    fn x25519_diffie_hellman_agreement() {
        let a: [u8; 32] = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
            .try_into()
            .unwrap();
        let b: [u8; 32] = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
            .try_into()
            .unwrap();
        let a_pub = x25519_base(&a);
        let b_pub = x25519_base(&b);
        assert_eq!(
            a_pub.to_vec(),
            hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
        assert_eq!(
            b_pub.to_vec(),
            hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        );
        let shared = x25519(&a, &b_pub);
        assert_eq!(shared, x25519(&b, &a_pub));
        assert_eq!(
            shared.to_vec(),
            hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
        );
    }

    // --- HKDF: RFC 5869 test case 1 ---
    #[test]
    fn hkdf_rfc5869_case_1() {
        let ikm = vec![0x0bu8; 22];
        let salt = hex("000102030405060708090a0b0c");
        let info = hex("f0f1f2f3f4f5f6f7f8f9");
        let prk = hkdf_extract(&salt, &ikm);
        assert_eq!(
            prk.to_vec(),
            hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        );
        let okm = hkdf_expand(&prk, &info, 42);
        assert_eq!(
            okm,
            hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
        );
    }

    // --- ChaCha20: RFC 8439 §2.3.2 ---
    #[test]
    fn chacha20_rfc8439_keystream_vector() {
        let key: [u8; 32] = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .try_into()
            .unwrap();
        let nonce: [u8; 12] = hex("000000000000004a00000000").try_into().unwrap();
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you \
                   only one tip for the future, sunscreen would be it.";
        let ct = chacha20_xor(&key, 1, &nonce, pt);
        assert_eq!(
            ct,
            hex(
                "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b\
                 f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8\
                 07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736\
                 5af90bbf74a35be6b40b8eedf2785e42874d"
            )
        );
        // Decryption is the same operation.
        assert_eq!(chacha20_xor(&key, 1, &nonce, &ct), pt.to_vec());
    }

    // --- Poly1305: RFC 8439 §2.5.2 ---
    #[test]
    fn poly1305_rfc8439_tag_vector() {
        let key: [u8; 32] = hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
            .try_into()
            .unwrap();
        let msg = b"Cryptographic Forum Research Group";
        assert_eq!(
            poly1305_mac(msg, &key).to_vec(),
            hex("a8061dc1305136c6c22b8baf0c0127a9")
        );
    }

    // --- AEAD ChaCha20Poly1305: RFC 8439 §2.8.2 ---
    #[test]
    fn aead_rfc8439_seal_vector() {
        let key: [u8; 32] = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
            .try_into()
            .unwrap();
        let nonce: [u8; 12] = hex("070000004041424344454647").try_into().unwrap();
        let aad = hex("50515253c0c1c2c3c4c5c6c7");
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you \
                   only one tip for the future, sunscreen would be it.";
        let sealed = chacha20_poly1305_seal(&key, &nonce, &aad, pt);
        assert_eq!(sealed.len(), pt.len() + 16);
        assert_eq!(
            &sealed[..16],
            hex("d31a8d34648e60db7b86afbc53ef7ec2").as_slice()
        );
        assert_eq!(
            &sealed[sealed.len() - 16..],
            hex("1ae10b594f09e26a7e902ecbd0600691").as_slice()
        );
        // Round-trip + tamper detection.
        assert_eq!(
            chacha20_poly1305_open(&key, &nonce, &aad, &sealed).unwrap(),
            pt.to_vec()
        );
        let mut tampered = sealed.clone();
        tampered[3] ^= 0x80;
        assert!(chacha20_poly1305_open(&key, &nonce, &aad, &tampered).is_err());
        assert!(chacha20_poly1305_open(&key, &nonce, &[], &sealed).is_err());
    }

    // --- RFC 9180 A.1: DeriveKeyPair(ikmE) reproduces the RFC's enc ---
    #[test]
    fn hpke_derive_keypair_rfc9180_a1() {
        let ikm_e = hex("7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234");
        let (_sk, pk) = derive_keypair_x25519(&ikm_e);
        assert_eq!(
            pk.to_vec(),
            hex("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431")
        );
    }

    // --- KEM encapsulation: deterministic under a fixed seed ---
    #[test]
    fn kem_encapsulate_deterministic_and_agrees() {
        let pk_rm = x25519_base(&[0x55u8; 32]);
        let (enc1, ss1) = kem_encapsulate(&pk_rm, Some([7u8; 32])).unwrap();
        let (enc2, ss2) = kem_encapsulate(&pk_rm, Some([7u8; 32])).unwrap();
        assert_eq!(enc1, enc2);
        assert_eq!(ss1, ss2);
        // The receiver side of the same exchange derives the same secret.
        let sk_r = [0x55u8; 32];
        let dh = x25519(&sk_r, &enc1);
        let suite = kem_suite_id();
        let mut kem_context = Vec::new();
        kem_context.extend_from_slice(&enc1);
        kem_context.extend_from_slice(&pk_rm);
        let eae_prk = labeled_extract(&suite, &[], b"eae_prk", &dh);
        let ss_r = labeled_expand(&suite, &eae_prk, b"shared_secret", &kem_context, 32);
        assert_eq!(ss1.to_vec(), ss_r);
    }

    // --- KeySchedule sanity: distinct info → distinct keys ---
    #[test]
    fn key_schedule_produces_usable_material() {
        let ss = [0x42u8; 32];
        let suite = (KEM_ID_X25519, KDF_ID_SHA256, AEAD_ID_CHACHA20_POLY1305);
        let (k1, n1) = key_schedule(&ss, b"info-a", suite.0, suite.1, suite.2).unwrap();
        let (k2, n2) = key_schedule(&ss, b"info-b", suite.0, suite.1, suite.2).unwrap();
        assert_ne!(k1, k2);
        assert_ne!(n1, n2);
        assert!(key_schedule(&ss, b"x", suite.0, suite.1, 0x0001).is_err());
    }

    #[test]
    fn decode_hex_round_trip_and_errors() {
        assert_eq!(decode_hex("00ff10").unwrap(), vec![0x00, 0xFF, 0x10]);
        assert_eq!(decode_hex("0x0A 0b").unwrap(), vec![0x0A, 0x0B]);
        assert!(decode_hex("abc").is_err());
        assert!(decode_hex("zz").is_err());
    }

    // --- Field-arithmetic algebraic properties (audit F-06 regression) ---
    //
    // The first hpke version shipped three independent math bugs (sub bias
    // constants, a ×5 fold that belongs to a different radix, and a
    // double-counting byte encoder). The RFC vectors above pin exact
    // values; these properties add coverage for inputs the vectors do not
    // reach. All comparisons go through `to_bytes` (canonical mod p), so
    // no bignum arithmetic is needed in the test itself.

    /// Deterministic xorshift64* — no new dependency, reproducible.
    struct Xs(u64);
    impl Xs {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x.wrapping_mul(0x2545F4914F6CDD1D)
        }
        fn limb(&mut self, bits: u32) -> u64 {
            self.next() >> (64 - bits)
        }
    }

    fn canon(a: &Fe) -> [u8; 32] {
        a.to_bytes()
    }

    #[test]
    fn fe_algebraic_properties_hold() {
        let mut rng = Xs(0x243F_6A88_85A3_08D3);
        for _ in 0..500 {
            // Mixed slack: some limbs up to 2^52 (mul-output shape), some
            // canonical 2^51 — sub/mul must accept both.
            let a = Fe([
                rng.limb(51),
                rng.limb(52),
                rng.limb(51),
                rng.limb(52),
                rng.limb(51),
            ]);
            let b = Fe([
                rng.limb(52),
                rng.limb(51),
                rng.limb(52),
                rng.limb(51),
                rng.limb(52),
            ]);
            let c = Fe([
                rng.limb(51),
                rng.limb(51),
                rng.limb(52),
                rng.limb(51),
                rng.limb(51),
            ]);

            // Canonical encoding is idempotent and matches re-decode.
            let ea = canon(&a);
            assert_eq!(canon(&Fe::from_bytes(&ea)), ea, "to_bytes idempotent");

            // Commutativity: a·b == b·a.
            assert_eq!(canon(&a.mul(&b)), canon(&b.mul(&a)), "mul commutes");

            // Distributivity: (a+b)·c == a·c + b·c.
            let ab = a.add(&b);
            assert_eq!(
                canon(&ab.mul(&c)),
                canon(&a.mul(&c).add(&c.mul(&b))),
                "(a+b)·c == a·c + b·c"
            );

            // a − a == 0 and a − 0 == a (sub canonicalizes both sides).
            assert_eq!(canon(&a.sub(&a)), [0u8; 32], "a − a == 0");
            assert_eq!(canon(&a.sub(&Fe::ZERO)), ea, "a − 0 == a");

            // (a − b) + b == a — pins the borrow/p-add bookkeeping.
            assert_eq!(canon(&a.sub(&b).add(&b)), ea, "(a−b)+b == a");

            // Multiplicative identity.
            assert_eq!(canon(&a.mul(&Fe::ONE)), ea, "a·1 == a");
        }
    }

    #[test]
    fn fe_sub_borrow_wraps_correctly() {
        // Audit F-06: the borrow chain emits a − b + 2^255, so the fix
        // subtracts 19 when the final borrow is set. Minimal pairs that
        // force the negative branch:
        for (hi_a, hi_b) in [(0u64, 1u64), (1, 2), (5, 9)] {
            let mut a = [0u8; 32];
            a[0] = 9; // small value
            let mut ab = a;
            ab[24] = hi_a as u8; // tweak high limbs
            let mut bb = a;
            bb[24] = hi_b as u8;
            let av = Fe::from_bytes(&ab);
            let bv = Fe::from_bytes(&bb);
            let d = av.sub(&bv);
            // d + b must reassemble a (canonical), whatever the borrow did.
            assert_eq!(
                canon(&d.add(&bv)),
                canon(&av),
                "({hi_a}) − ({hi_b}) + b == a"
            );
        }
        // p − 1 + 1 == p → canonical 0: force a − b where a = 0, b = p−1.
        let mut m1 = [0xffu8; 32];
        m1[0] = 0xec; // p − 1 = 2^255 − 20
        let d = Fe::from_bytes(&[0u8; 32]).sub(&Fe::from_bytes(&m1));
        assert_eq!(canon(&d.add(&Fe::from_bytes(&m1))), [0u8; 32]);
    }
}
