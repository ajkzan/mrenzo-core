//! Contact discovery without uploading the address book
//! (01-rest-api §9.3, vectors docs/native/vectors/discovery.json).
//!
//! The client learns which of its address-book entries are mr.enzo users,
//! and the server learns neither the entries nor the matches:
//!
//! 1. Each entry becomes an input string ([`email_input`] / [`phone_input`]).
//! 2. The client blinds it ([`blind`]) and the server evaluates the blinded
//!    element with its secret key: RFC 9497 OPRF, suite
//!    `ristretto255-SHA512`, mode `0x00` (OPRF). The server sees a uniformly
//!    random group element; without the server key nobody can compute an
//!    output, so the directory cannot be tested offline.
//! 3. [`finalize`] unblinds and hashes: the 64-byte OPRF output. Its first
//!    16 bytes are the entry's `tag`, its last 32 bytes the AES-256-GCM
//!    `key` of the entry's sealed profile ([`split_output`]).
//! 4. The client asks for the buckets its tags fall in (the first
//!    `prefixBits` bits of the tag, [`bucket`]) and opens, locally, only the
//!    profiles whose tag it holds.
//!
//! Group ops are curve25519-dalek's ristretto255; `HashToGroup` is RFC 9380
//! `hash_to_ristretto255` with `expand_message_xmd(SHA-512)`.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use sha2::{Digest, Sha512};

use crate::rng::Rng;

/// RFC 9497 contextString for mode 0x00 and ristretto255-SHA512.
pub const CONTEXT_STRING: &[u8] = b"OPRFV1-\x00-ristretto255-SHA512";
pub const ELEMENT_BYTES: usize = 32;
pub const OUTPUT_BYTES: usize = 64;
pub const TAG_BYTES: usize = 16;
pub const KEY_BYTES: usize = 32;
/// The most bits a bucket prefix has (the server may use fewer).
pub const MAX_PREFIX_BITS: u8 = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryError {
    /// The input is longer than 65535 bytes, or hashes to the identity.
    InvalidInput,
    /// Not the encoding of a ristretto255 element, or the identity.
    InvalidElement,
    /// A zero or non-canonical scalar.
    InvalidScalar,
}

/// A blinded input: keep `blind` until [`finalize`], send `element`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blinded {
    pub blind: [u8; 32],
    pub element: [u8; ELEMENT_BYTES],
}

// ───────── inputs ─────────

/// `"email:" + the trimmed address, ASCII letters lowercased`; nil without
/// an `@`. ASCII only (as the server and SQLite `LOWER()`), so no platform's
/// Unicode case rules can split a match.
pub fn email_input(raw: &str) -> Option<String> {
    let email = raw.trim().to_ascii_lowercase();
    if !email.contains('@') || email.len() > 320 {
        return None;
    }
    Some(format!("email:{email}"))
}

/// `"phone:" + the ASCII digits` (the server stores numbers the same way);
/// nil without a digit or with more than 20.
pub fn phone_input(raw: &str) -> Option<String> {
    let digits: String = raw.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() || digits.len() > 20 {
        return None;
    }
    Some(format!("phone:{digits}"))
}

// ───────── RFC 9380 / RFC 9497 ─────────

/// `expand_message_xmd(msg, DST, 64)` with SHA-512 (RFC 9380 §5.3.1; one block).
fn expand_message_xmd_64(msg: &[u8], dst: &[u8]) -> [u8; 64] {
    debug_assert!(dst.len() <= 255);
    let mut dst_prime = dst.to_vec();
    dst_prime.push(dst.len() as u8);
    let b0 = Sha512::new()
        .chain_update([0u8; 128]) // Z_pad: SHA-512 block size
        .chain_update(msg)
        .chain_update(64u16.to_be_bytes()) // l_i_b_str
        .chain_update([0u8])
        .chain_update(&dst_prime)
        .finalize();
    let b1 = Sha512::new().chain_update(b0).chain_update([1u8]).chain_update(&dst_prime).finalize();
    b1.into()
}

/// RFC 9497 `HashToGroup` for ristretto255.
pub fn hash_to_group(input: &[u8]) -> RistrettoPoint {
    let mut dst = b"HashToGroup-".to_vec();
    dst.extend_from_slice(CONTEXT_STRING);
    RistrettoPoint::from_uniform_bytes(&expand_message_xmd_64(input, &dst))
}

fn scalar(bytes: &[u8; 32]) -> Result<Scalar, DiscoveryError> {
    let s: Option<Scalar> = Scalar::from_canonical_bytes(*bytes).into();
    match s {
        Some(s) if s != Scalar::ZERO => Ok(s),
        _ => Err(DiscoveryError::InvalidScalar),
    }
}

fn element(bytes: &[u8; ELEMENT_BYTES]) -> Result<RistrettoPoint, DiscoveryError> {
    let point = CompressedRistretto(*bytes).decompress().ok_or(DiscoveryError::InvalidElement)?;
    if point.is_identity() {
        return Err(DiscoveryError::InvalidElement);
    }
    Ok(point)
}

/// `Blind(input)` with a fresh random scalar (64 bytes reduced mod ℓ).
pub fn blind(input: &[u8], rng: &mut dyn Rng) -> Result<Blinded, DiscoveryError> {
    loop {
        let mut wide = [0u8; 64];
        rng.fill(&mut wide);
        let r = Scalar::from_bytes_mod_order_wide(&wide);
        if r != Scalar::ZERO {
            return blind_with(input, &r.to_bytes());
        }
    }
}

/// `Blind(input)` with a given blind (conformance vectors).
pub fn blind_with(input: &[u8], blind: &[u8; 32]) -> Result<Blinded, DiscoveryError> {
    if input.len() > u16::MAX as usize {
        return Err(DiscoveryError::InvalidInput);
    }
    let r = scalar(blind)?;
    let point = hash_to_group(input);
    if point.is_identity() {
        return Err(DiscoveryError::InvalidInput);
    }
    Ok(Blinded { blind: *blind, element: (r * point).compress().to_bytes() })
}

/// The server's `BlindEvaluate`: `sk · blinded` (servers and tests).
pub fn evaluate(sk: &[u8; 32], blinded: &[u8; ELEMENT_BYTES]) -> Result<[u8; ELEMENT_BYTES], DiscoveryError> {
    Ok((scalar(sk)? * element(blinded)?).compress().to_bytes())
}

/// `Finalize(input, blind, evaluatedElement)`:
/// `SHA-512(len(input) ‖ input ‖ len(N) ‖ N ‖ "Finalize")`, `N = blind⁻¹ · evaluated`.
pub fn finalize(input: &[u8], blind: &[u8; 32], evaluated: &[u8; ELEMENT_BYTES]) -> Result<[u8; OUTPUT_BYTES], DiscoveryError> {
    if input.len() > u16::MAX as usize {
        return Err(DiscoveryError::InvalidInput);
    }
    let r = scalar(blind)?;
    let unblinded = (r.invert() * element(evaluated)?).compress().to_bytes();
    let out = Sha512::new()
        .chain_update((input.len() as u16).to_be_bytes())
        .chain_update(input)
        .chain_update((ELEMENT_BYTES as u16).to_be_bytes())
        .chain_update(unblinded)
        .chain_update(b"Finalize")
        .finalize();
    Ok(out.into())
}

// ───────── mr.enzo layout ─────────

/// `(tag, key)`: output bytes 0..16 and 32..64.
pub fn split_output(output: &[u8; OUTPUT_BYTES]) -> ([u8; TAG_BYTES], [u8; KEY_BYTES]) {
    let mut tag = [0u8; TAG_BYTES];
    let mut key = [0u8; KEY_BYTES];
    tag.copy_from_slice(&output[..TAG_BYTES]);
    key.copy_from_slice(&output[32..]);
    (tag, key)
}

/// The first `bits` bits of `tag`, big-endian (`bits` ≤ 16; 0 = the one bucket).
pub fn bucket(tag: &[u8], bits: u8) -> u32 {
    let bits = bits.min(MAX_PREFIX_BITS) as u32;
    if bits == 0 || tag.len() < 2 {
        return 0;
    }
    (u32::from(tag[0]) << 8 | u32::from(tag[1])) >> (16 - bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inputs_normalize() {
        assert_eq!(email_input("  Alice@Example.COM "), Some("email:alice@example.com".into()));
        assert_eq!(email_input("not an address"), None);
        assert_eq!(phone_input("+7 (912) 345-67-89"), Some("phone:79123456789".into()));
        assert_eq!(phone_input("call me"), None);
        assert_eq!(phone_input("123456789012345678901"), None);
    }

    #[test]
    fn buckets_take_the_leading_bits() {
        let tag = [0b1010_1100, 0b0101_0011, 0xFF];
        assert_eq!(bucket(&tag, 0), 0);
        assert_eq!(bucket(&tag, 1), 1);
        assert_eq!(bucket(&tag, 4), 0b1010);
        assert_eq!(bucket(&tag, 16), 0b1010_1100_0101_0011);
        assert_eq!(bucket(&tag, 40), 0b1010_1100_0101_0011, "capped at 16");
    }

    #[test]
    fn bad_elements_and_scalars_are_refused() {
        let mut one = [0u8; 32];
        one[0] = 1;
        let b = blind_with(b"x", &one).unwrap();
        assert_eq!(finalize(b"x", &b.blind, &[0u8; 32]), Err(DiscoveryError::InvalidElement), "identity");
        assert_eq!(finalize(b"x", &b.blind, &[0xFFu8; 32]), Err(DiscoveryError::InvalidElement), "not an encoding");
        assert_eq!(blind_with(b"x", &[0u8; 32]), Err(DiscoveryError::InvalidScalar));
        assert_eq!(blind_with(b"x", &[0xFFu8; 32]), Err(DiscoveryError::InvalidScalar), "non-canonical");
        assert_eq!(evaluate(&one, &[0u8; 32]), Err(DiscoveryError::InvalidElement));
    }
}
