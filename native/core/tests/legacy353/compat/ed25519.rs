//! Ed25519 with tweetnacl 1.0.3 semantics (`nacl-fast.js`).
//!
//! - `nacl.sign.detached.verify(msg, sig, pk)` throws `bad signature size`
//!   then `bad public key size` (nacl-fast.js:2296-2302), and
//!   `crypto_sign_open` never range-checks S: it evaluates `[S]B` with all 256
//!   bits of S, and B has order L, so S + k·L verifies wherever S does. It is
//!   cofactorless, compares the encoding of R, and accepts small-order `A`
//!   and `R`. ed25519-dalek's non-strict `verify` is that equation once S is
//!   reduced mod L, which is what [`tweetnacl_sign_detached_verify`] does.
//!   `primitives::ed25519_verify` alone rejects S ≥ L.
//! - `nacl.sign.detached(msg, sk)` (`crypto_sign`, nacl-fast.js:1989) hashes
//!   the STORED public half `sk[32..64]` into `H(R ‖ A ‖ M)`; it never
//!   re-derives `A` from the seed. `primitives::ed25519_sign` (RFC 8032)
//!   re-derives it, so the two differ (same R, different S) exactly when the
//!   halves of a 64-byte secret disagree.
//! - `nacl.sign.keyPair.fromSecretKey(sk)` (nacl-fast.js:2322) COPIES
//!   `sk[32..64]` as the public key.

use mrenzo_core::primitives::{ed25519_sign, ed25519_verify, sha512};

/// The group order L = 2^252 + 27742317777372353535851937790883648493,
/// little-endian.
pub const ED25519_L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

/// L as little-endian u64 limbs.
const L_LIMBS: [u64; 4] = [0x5812_631a_5cf5_d3ed, 0x14de_f9de_a2f7_9cd6, 0, 0x1000_0000_0000_0000];

/// `s mod L` for a 256-bit little-endian integer. Because s < 2^256 < 16·L,
/// at most 15 subtractions are needed.
pub fn reduce_scalar_mod_l(s: &[u8; 32]) -> [u8; 32] {
    let mut x = [0u64; 4];
    for (i, limb) in x.iter_mut().enumerate() {
        *limb = u64::from_le_bytes(s[i * 8..i * 8 + 8].try_into().expect("8-byte limb"));
    }
    let ge_l = |x: &[u64; 4]| {
        for i in (0..4).rev() {
            if x[i] != L_LIMBS[i] {
                return x[i] > L_LIMBS[i];
            }
        }
        true
    };
    while ge_l(&x) {
        let mut borrow = false;
        for (xi, li) in x.iter_mut().zip(L_LIMBS) {
            let (d1, b1) = xi.overflowing_sub(li);
            let (d2, b2) = d1.overflowing_sub(u64::from(borrow));
            *xi = d2;
            borrow = b1 || b2;
        }
    }
    let mut out = [0u8; 32];
    for (i, limb) in x.iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&limb.to_le_bytes());
    }
    out
}

/// `nacl.sign.detached.verify(msg, sig, publicKey)` once the sizes are known
/// to be right: S is reduced mod L, then the cofactorless dalek check runs.
pub fn tweetnacl_sign_detached_verify(msg: &[u8], sig: &[u8; 64], public_key: &[u8; 32]) -> bool {
    let mut canonical = *sig;
    let s: [u8; 32] = sig[32..].try_into().expect("64-byte signature");
    canonical[32..].copy_from_slice(&reduce_scalar_mod_l(&s));
    ed25519_verify(public_key, msg, &canonical)
}

/// The two size checks `nacl.sign.detached.verify` throws on, in its order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifySizeError {
    /// `Error('bad signature size')` (checked first).
    BadSignatureSize,
    /// `Error('bad public key size')`.
    BadPublicKeySize,
}

impl VerifySizeError {
    /// The tweetnacl message text.
    pub fn message(self) -> &'static str {
        match self {
            VerifySizeError::BadSignatureSize => "bad signature size",
            VerifySizeError::BadPublicKeySize => "bad public key size",
        }
    }
}

impl std::fmt::Display for VerifySizeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for VerifySizeError {}

/// `nacl.sign.detached.verify(msg, sig, publicKey)` including its throws.
pub fn tweetnacl_sign_detached_verify_checked(msg: &[u8], sig: &[u8], public_key: &[u8]) -> Result<bool, VerifySizeError> {
    let sig: &[u8; 64] = sig.try_into().map_err(|_| VerifySizeError::BadSignatureSize)?;
    let public_key: &[u8; 32] = public_key.try_into().map_err(|_| VerifySizeError::BadPublicKeySize)?;
    Ok(tweetnacl_sign_detached_verify(msg, sig, public_key))
}

/// `nacl.sign.detached(msg, secretKey)` for a 64-byte tweetnacl secret
/// (`seed ‖ pub`): the stored pub half `sk[32..64]` goes into `h`.
pub fn tweetnacl_sign_detached(msg: &[u8], secret_key: &[u8; 64]) -> [u8; 64] {
    // d = SHA-512(seed), clamped: a = d[0..32], prefix = d[32..64].
    let mut d = sha512(&secret_key[..32]);
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;
    // r = reduce(SHA-512(prefix ‖ M)).
    let mut buf = Vec::with_capacity(64 + msg.len());
    buf.extend_from_slice(&d[32..]);
    buf.extend_from_slice(msg);
    let r = reduce64(&sha512(&buf));
    // R = pack(r·B). It depends only on (seed, M), so it is byte-identical to
    // the R of the RFC 8032 signer in primitives (which re-derives A — only
    // the S half differs when the stored pub half is not the seed's).
    let mut sm = [0u8; 64];
    sm[..32].copy_from_slice(&ed25519_sign(secret_key, msg)[..32]);
    // h = reduce(SHA-512(R ‖ sk[32..64] ‖ M)).
    buf.clear();
    buf.extend_from_slice(&sm[..32]);
    buf.extend_from_slice(&secret_key[32..]);
    buf.extend_from_slice(msg);
    let h = reduce64(&sha512(&buf));
    // S = (r + h·a) mod L.
    let mut x = [0i64; 64];
    for i in 0..32 {
        x[i] = r[i] as i64;
    }
    for i in 0..32 {
        for j in 0..32 {
            x[i + j] += h[i] as i64 * d[j] as i64;
        }
    }
    sm[32..].copy_from_slice(&mod_l(&mut x));
    sm
}

/// `nacl.sign.keyPair.fromSecretKey(secretKey).publicKey`: a COPY of
/// `sk[32..64]` (no derivation; compare `primitives::ed25519_public_from_secret64`).
pub fn tweetnacl_sign_public_key_from_secret_key(secret_key: &[u8; 64]) -> [u8; 32] {
    secret_key[32..].try_into().expect("32-byte half")
}

/// L as tweetnacl's signed 8-bit limbs.
const L_I64: [i64; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

/// tweetnacl `modL(r, x)`: reduce a 64-limb (8 bits/limb, signed) value mod L.
fn mod_l(x: &mut [i64; 64]) -> [u8; 32] {
    for i in (32..64).rev() {
        let mut carry: i64 = 0;
        let mut j = i - 32;
        while j < i - 12 {
            x[j] += carry - 16 * x[i] * L_I64[j - (i - 32)];
            carry = (x[j] + 128) >> 8; // Math.floor((x[j] + 128) / 256)
            x[j] -= carry * 256;
            j += 1;
        }
        x[j] += carry;
        x[i] = 0;
    }
    let mut carry: i64 = 0;
    for j in 0..32 {
        x[j] += carry - (x[31] >> 4) * L_I64[j];
        carry = x[j] >> 8;
        x[j] &= 255;
    }
    for j in 0..32 {
        x[j] -= carry * L_I64[j];
    }
    let mut r = [0u8; 32];
    for i in 0..32 {
        x[i + 1] += x[i] >> 8;
        r[i] = (x[i] & 255) as u8;
    }
    r
}

/// tweetnacl `reduce(r)` of a 64-byte little-endian value.
fn reduce64(bytes: &[u8; 64]) -> [u8; 32] {
    let mut x = [0i64; 64];
    for (xi, &b) in x.iter_mut().zip(bytes.iter()) {
        *xi = b as i64;
    }
    mod_l(&mut x)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrenzo_core::primitives::{ed25519_keypair_from_seed, ed25519_public_from_secret64};

    fn xorshift(seed: u64) -> impl FnMut() -> u64 {
        let mut x = seed;
        move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        }
    }

    /// Python big-int `x % L` (little-endian hex), including a borrow that
    /// must ripple through L's all-zero limb 2.
    #[test]
    fn reduce_scalar_mod_l_matches_bigint_reference() {
        let cases = [
            ("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010", "0000000000000000000000000000000000000000000000000000000000000000"), // L
            ("ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010", "ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"), // L-1
            ("0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000"), // 0
            ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "1c95988d7431ecd670cf7d73f45befc6feffffffffffffffffffffffffffff0f"), // 2^256-1
            ("0000000000000000000000000000000000000000000000000000000000000030", "26581446cb39db4f53c610ba420c42d6ffffffffffffffffffffffffffffff0f"), // 3*2^252
            ("ea6a67728bce13298f30828c0ba41039010000000000000000000000000000f0", "0700000000000000000000000000000000000000000000000000000000000000"), // 15L+7
            ("daa7ebb934c624b0ac39ef45bdf3bd2901000000000000000000000000000020", "0000000000000000000000000000000001000000000000000000000000000000"), // 2L+2^128
        ];
        for (x, want) in cases {
            let x: [u8; 32] = hex::decode(x).unwrap().try_into().unwrap();
            assert_eq!(hex::encode(reduce_scalar_mod_l(&x)), want, "{}", hex::encode(x));
        }
        assert_eq!(reduce_scalar_mod_l(&ED25519_L), [0u8; 32]);
    }

    /// Byte-wise repeated subtraction, the other shape the ports used.
    fn reduce_by_bytes(s: &[u8; 32]) -> [u8; 32] {
        let mut s = *s;
        let less = |a: &[u8; 32]| {
            for i in (0..32).rev() {
                if a[i] != ED25519_L[i] {
                    return a[i] < ED25519_L[i];
                }
            }
            false
        };
        while !less(&s) {
            let mut borrow = 0i16;
            for (b, l) in s.iter_mut().zip(ED25519_L.iter()) {
                let d = *b as i16 - *l as i16 - borrow;
                borrow = i16::from(d < 0);
                *b = (d + 256 * borrow) as u8;
            }
        }
        s
    }

    #[test]
    fn reduce_scalar_mod_l_agrees_with_tweetnacl_mod_l_and_byte_subtraction() {
        let mut next = xorshift(0x2545_f491_4f6c_dd1d);
        for k in 0..200_000 {
            let mut s = [0u8; 32];
            for c in s.chunks_mut(8) {
                c.copy_from_slice(&next().to_le_bytes());
            }
            if k % 3 == 0 {
                s[31] |= 0xf0;
            }
            let want = reduce_scalar_mod_l(&s);
            let mut x = [0i64; 64];
            for i in 0..32 {
                x[i] = s[i] as i64;
            }
            assert_eq!(mod_l(&mut x), want);
            assert_eq!(reduce_by_bytes(&s), want);
        }
    }

    #[test]
    fn verify_accepts_every_s_plus_k_l_that_fits_like_tweetnacl() {
        let (sk, pk) = ed25519_keypair_from_seed(&[7u8; 32]);
        let msg = b"tweetnacl never range-checks S";
        let sig = tweetnacl_sign_detached(msg, &sk);
        assert!(tweetnacl_sign_detached_verify(msg, &sig, &pk));
        let mut k = 0;
        let mut s: [u8; 32] = sig[32..].try_into().unwrap();
        loop {
            // s += L, stop once it no longer fits in 256 bits.
            let mut carry = 0u16;
            let mut next = [0u8; 32];
            for i in 0..32 {
                let v = u16::from(s[i]) + u16::from(ED25519_L[i]) + carry;
                next[i] = v as u8;
                carry = v >> 8;
            }
            if carry != 0 {
                break;
            }
            s = next;
            k += 1;
            let mut m = sig;
            m[32..].copy_from_slice(&s);
            assert!(tweetnacl_sign_detached_verify(msg, &m, &pk), "S + {k}·L");
            assert!(!mrenzo_core::primitives::ed25519_verify(&pk, msg, &m), "primitives rejects S + {k}·L");
        }
        assert!(k >= 1);
        let mut bad = sig;
        bad[0] ^= 1;
        assert!(!tweetnacl_sign_detached_verify(msg, &bad, &pk));
        assert!(!tweetnacl_sign_detached_verify(b"other", &sig, &pk));
    }

    /// tweetnacl accepts a small-order public key: with A = the identity
    /// point, R = [S]B, so (R = identity, S = 0) verifies EVERY message, in
    /// both the canonical encoding of the identity and the non-canonical one
    /// (y = p + 1). dalek's `verify_strict` rejects both; the primitives
    /// verifier (non-strict) accepts them, and so does the tweetnacl one.
    #[test]
    fn small_order_public_key_verifies_like_tweetnacl() {
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let mut non_canonical = [0xffu8; 32];
        non_canonical[0] = 0xee; // p + 1 = 2^255 - 18
        non_canonical[31] = 0x7f;
        let mut sig = [0u8; 64];
        sig[0] = 1; // R = identity, S = 0
        for pk in [identity, non_canonical] {
            for msg in [&b""[..], b"any message at all"] {
                assert!(mrenzo_core::primitives::ed25519_verify(&pk, msg, &sig));
                assert!(tweetnacl_sign_detached_verify(msg, &sig, &pk));
                let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk).unwrap();
                assert!(vk.verify_strict(msg, &ed25519_dalek::Signature::from_bytes(&sig)).is_err());
            }
        }
    }

    #[test]
    fn checked_verify_throws_in_tweetnacl_order() {
        let (sk, pk) = ed25519_keypair_from_seed(&[3u8; 32]);
        let sig = tweetnacl_sign_detached(b"m", &sk);
        assert_eq!(tweetnacl_sign_detached_verify_checked(b"m", &sig, &pk), Ok(true));
        assert_eq!(tweetnacl_sign_detached_verify_checked(b"x", &sig, &pk), Ok(false));
        assert_eq!(tweetnacl_sign_detached_verify_checked(b"m", &sig[..63], &pk[..31]), Err(VerifySizeError::BadSignatureSize));
        assert_eq!(tweetnacl_sign_detached_verify_checked(b"m", &sig, &pk[..31]), Err(VerifySizeError::BadPublicKeySize));
        assert_eq!(VerifySizeError::BadSignatureSize.to_string(), "bad signature size");
        assert_eq!(VerifySizeError::BadPublicKeySize.to_string(), "bad public key size");
    }

    #[test]
    fn sign_hashes_the_stored_public_half() {
        let (sk, pk) = ed25519_keypair_from_seed(&[9u8; 32]);
        for msg in [&b""[..], b"a", b"key-publish canonical|x|1|2"] {
            // Consistent halves: identical to RFC 8032.
            assert_eq!(tweetnacl_sign_detached(msg, &sk), ed25519_sign(&sk, msg));
            // Mismatched halves: same R, different S (tweetnacl hashes sk[32..]).
            let mut mm = sk;
            mm[32..].copy_from_slice(&[1u8; 32]);
            let t = tweetnacl_sign_detached(msg, &mm);
            let r = ed25519_sign(&mm, msg);
            assert_eq!(t[..32], r[..32]);
            assert_ne!(t[32..], r[32..]);
        }
        assert_eq!(tweetnacl_sign_public_key_from_secret_key(&sk), pk);
        let mut mm = sk;
        mm[32..].copy_from_slice(&[1u8; 32]);
        assert_eq!(tweetnacl_sign_public_key_from_secret_key(&mm), [1u8; 32]);
        assert_eq!(ed25519_public_from_secret64(&mm), pk, "primitives re-derives from the seed");
    }
}
