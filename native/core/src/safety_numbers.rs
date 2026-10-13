//! Safety numbers v2 (03-crypto §9, build 349): the number covers every key a
//! peer signs or encrypts with — the X25519 identity AND the Ed25519 signing
//! key of both sides. Conformance: docs/native/vectors/safetyNumbersV2.json
//! (tests/golden_safety_numbers_v2.rs).
//!
//! ```text
//! K_me   = IK_me(32) ‖ ED_me(32);  K_peer = IK_peer(32) ‖ ED_peer(32)
//! (x, y) = bytewise sort of (K_me, K_peer)
//! d      = SHA-512(UTF-8("mrenzo-safety-v2") ‖ x ‖ y [‖ s1 ‖ s2])     s1, s2 = sorted pair seeds (offline pairing)
//! block_i = zero-pad(BE_uint40(d[5i .. 5i+5]) mod 100000, 5), i in 0..6;  number = blocks joined by " "
//! ```
//!
//! The v1 number (SHA-512 over the two X25519 keys only) is gone with the
//! clients that computed it; every number changes on the update and verified
//! records are migrated (05 §10.4).

use crate::primitives::sha512;
use crate::ratchet::b64_strict32;

pub const SAFETY_NUMBER_BLOCKS: usize = 6;
pub const SAFETY_BYTES_PER_BLOCK: usize = 5;
pub const SAFETY_LABEL_V2: &str = "mrenzo-safety-v2";

#[derive(Debug, PartialEq, Eq)]
pub enum SafetyNumberError {
    /// A key or seed is not canonical base64 of exactly 32 bytes.
    InvalidKey,
}

impl std::fmt::Display for SafetyNumberError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid key")
    }
}

impl std::error::Error for SafetyNumberError {}

/// 32-byte identity halves of one side.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdentityPair {
    pub ik: [u8; 32],
    pub ed: [u8; 32],
}

impl IdentityPair {
    pub fn from_b64(ik: &str, ed: &str) -> Result<Self, SafetyNumberError> {
        Ok(IdentityPair {
            ik: b64_strict32(ik).ok_or(SafetyNumberError::InvalidKey)?,
            ed: b64_strict32(ed).ok_or(SafetyNumberError::InvalidKey)?,
        })
    }

    fn bytes(&self) -> [u8; 64] {
        let mut k = [0u8; 64];
        k[..32].copy_from_slice(&self.ik);
        k[32..].copy_from_slice(&self.ed);
        k
    }
}

fn sorted<const N: usize>(a: [u8; N], b: [u8; N]) -> ([u8; N], [u8; N]) {
    if a <= b {
        (a, b)
    } else {
        (b, a)
    }
}

fn render(digest: &[u8; 64]) -> String {
    let mut blocks = Vec::with_capacity(SAFETY_NUMBER_BLOCKS);
    for i in 0..SAFETY_NUMBER_BLOCKS {
        let mut value: u64 = 0;
        for j in 0..SAFETY_BYTES_PER_BLOCK {
            value = value * 256 + u64::from(digest[i * SAFETY_BYTES_PER_BLOCK + j]);
        }
        blocks.push(format!("{:05}", value % 100_000));
    }
    blocks.join(" ")
}

/// The 30-digit number both peers see (order-independent).
pub fn safety_number_v2(me: &IdentityPair, peer: &IdentityPair) -> String {
    let (x, y) = sorted(me.bytes(), peer.bytes());
    let mut input = SAFETY_LABEL_V2.as_bytes().to_vec();
    input.extend_from_slice(&x);
    input.extend_from_slice(&y);
    render(&sha512(&input))
}

/// The in-person pair number: the same construction followed by the two
/// sorted 32-byte pairing seeds.
pub fn pair_safety_number_v2(me: &IdentityPair, my_seed: &[u8; 32], peer: &IdentityPair, peer_seed: &[u8; 32]) -> String {
    let (x, y) = sorted(me.bytes(), peer.bytes());
    let (s1, s2) = sorted(*my_seed, *peer_seed);
    let mut input = SAFETY_LABEL_V2.as_bytes().to_vec();
    for part in [&x[..], &y[..], &s1[..], &s2[..]] {
        input.extend_from_slice(part);
    }
    render(&sha512(&input))
}

/// base64 wrapper used by the FFI.
pub fn safety_number_v2_b64(my_ik: &str, my_ed: &str, peer_ik: &str, peer_ed: &str) -> Result<String, SafetyNumberError> {
    Ok(safety_number_v2(&IdentityPair::from_b64(my_ik, my_ed)?, &IdentityPair::from_b64(peer_ik, peer_ed)?))
}

/// The digits only (what the "first two blocks" entry compares against).
pub fn safety_number_joined(formatted: &str) -> String {
    formatted.chars().filter(|c| c.is_ascii_digit()).collect()
}

/// Canonical standard base64 of exactly 32 bytes.
pub fn is_likely_valid_pubkey(b64: &str) -> bool {
    b64_strict32(b64).is_some()
}
