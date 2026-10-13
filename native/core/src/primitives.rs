//! Primitives, byte-compatible with tweetnacl + @noble/hashes as used by the
//! RN client. See docs/native/vectors/primitives.json.
//!
//! Some helpers here are deliberately STRICTER than the RN client and must
//! not stand in for it on input a peer, the server or RN storage produced:
//! [`b64d`] / [`b64d32`] (strict RFC 4648, unlike tweetnacl-util
//! `decodeBase64` → `compat::b64`), [`ed25519_verify`] (rejects S ≥ L, unlike
//! `nacl.sign.detached.verify` → `compat::ed25519`) and [`ed25519_sign`] /
//! [`ed25519_public_from_secret64`] (re-derive the public half from the seed,
//! unlike tweetnacl, which uses the stored `sk[32..64]` →
//! `compat::ed25519::tweetnacl_sign_detached`). They are for fixtures, for
//! bytes this crate produced itself, and for keys whose halves agree.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use crypto_secretbox::aead::{AeadInPlace, KeyInit};
use crypto_secretbox::{Nonce, Tag, XSalsa20Poly1305};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::rng::Rng;

/// tweetnacl `nacl.scalarMult(k, u)`: X25519 with scalar clamping.
pub fn x25519(k: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::x25519(*k, *u)
}

/// tweetnacl `nacl.scalarMult.base(k)`.
pub fn x25519_base(k: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::x25519(*k, x25519_dalek::X25519_BASEPOINT_BYTES)
}

/// tweetnacl `nacl.box.keyPair()`: the private key is the RAW 32 random bytes
/// (NOT pre-clamped); clamping happens inside every scalar multiplication.
pub fn x25519_keypair(rng: &mut dyn Rng) -> KeyPair {
    let mut priv_ = [0u8; 32];
    rng.fill(&mut priv_);
    KeyPair { public: x25519_base(&priv_), private: priv_ }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyPair {
    pub public: [u8; 32],
    pub private: [u8; 32],
}

/// HKDF-SHA256 with the protocol's fixed salt of 32 zero bytes.
pub fn hkdf_sha256(ikm: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let salt = [0u8; 32];
    let hk = Hkdf::<Sha256>::new(Some(&salt), ikm);
    let mut okm = vec![0u8; len];
    hk.expand(info, &mut okm).expect("HKDF output length within bounds");
    okm
}

pub fn hkdf32(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let v = hkdf_sha256(ikm, info, 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

/// tweetnacl `nacl.secretbox`: output = Poly1305 tag (16) || XSalsa20 ciphertext
/// (libsodium crypto_secretbox_easy layout).
pub fn secretbox_seal(msg: &[u8], nonce: &[u8; 24], key: &[u8; 32]) -> Vec<u8> {
    let cipher = XSalsa20Poly1305::new(key.into());
    let mut buf = msg.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(nonce), b"", &mut buf)
        .expect("secretbox encrypt");
    let mut out = Vec::with_capacity(16 + buf.len());
    out.extend_from_slice(&tag);
    out.extend_from_slice(&buf);
    out
}

/// tweetnacl `nacl.secretbox.open`: None on authentication failure.
pub fn secretbox_open(boxed: &[u8], nonce: &[u8; 24], key: &[u8; 32]) -> Option<Vec<u8>> {
    if boxed.len() < 16 {
        return None;
    }
    let (tag, ct) = boxed.split_at(16);
    let cipher = XSalsa20Poly1305::new(key.into());
    let mut buf = ct.to_vec();
    cipher
        .decrypt_in_place_detached(Nonce::from_slice(nonce), b"", &mut buf, Tag::from_slice(tag))
        .ok()?;
    Some(buf)
}

/// tweetnacl-util `encodeBase64`: RFC 4648 standard alphabet WITH padding.
pub fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// STRICT RFC 4648 decode: standard alphabet, canonical padding, AND zero
/// trailing bits in the last quantum.
///
/// This is NOT tweetnacl-util `decodeBase64`: RN's `atob` discards non-zero
/// trailing bits (`"AB=="` → `[0x00]`), this rejects them. For anything a
/// peer, the server or RN's own storage produced use
/// `compat::b64::tweetnacl_util_decode_base64`; this one is for test
/// fixtures and for base64 this crate encoded itself (the golden tests pin
/// its strictness).
pub fn b64d(s: &str) -> Option<Vec<u8>> {
    STANDARD.decode(s).ok()
}

/// [`b64d`] of exactly 32 bytes (same strictness caveat).
pub fn b64d32(s: &str) -> Option<[u8; 32]> {
    let v = b64d(s)?;
    v.try_into().ok()
}

// ───────── Ed25519 (tweetnacl nacl.sign.*) ─────────
//
// tweetnacl's Ed25519 "secret key" is 64 bytes = seed(32) || publicKey(32);
// that 64-byte form is what the RN client stores and ships in vectors.

pub fn ed25519_keypair_from_seed(seed: &[u8; 32]) -> ([u8; 64], [u8; 32]) {
    let sk = ed25519_dalek::SigningKey::from_bytes(seed);
    let pk = sk.verifying_key().to_bytes();
    let mut secret = [0u8; 64];
    secret[..32].copy_from_slice(seed);
    secret[32..].copy_from_slice(&pk);
    (secret, pk)
}

/// tweetnacl `nacl.sign.keyPair()`: draws a 32-byte seed.
pub fn ed25519_keypair(rng: &mut dyn Rng) -> ([u8; 64], [u8; 32]) {
    let mut seed = [0u8; 32];
    rng.fill(&mut seed);
    ed25519_keypair_from_seed(&seed)
}

/// RFC 8032 Ed25519 signature with the seed `secret64[..32]` (ed25519-dalek).
/// Deterministic.
///
/// Equal to tweetnacl's `nacl.sign.detached(msg, secretKey64)` only when the
/// stored public half `secret64[32..]` is the seed's: dalek re-derives `A`,
/// tweetnacl hashes the stored half, so a 64-byte secret whose halves
/// disagree gives the same R but a different S. The RN-faithful signer is
/// `compat::ed25519::tweetnacl_sign_detached`.
pub fn ed25519_sign(secret64: &[u8; 64], msg: &[u8]) -> [u8; 64] {
    use ed25519_dalek::Signer;
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&secret64[..32]);
    ed25519_dalek::SigningKey::from_bytes(&seed).sign(msg).to_bytes()
}

/// Cofactorless Ed25519 verification (ed25519-dalek's non-strict `verify`):
/// R compared by encoding, small-order `A` and `R` accepted, like tweetnacl —
/// but a non-canonical S (S ≥ L) is REJECTED, where tweetnacl's
/// `nacl.sign.detached.verify` accepts every S + k·L. The RN-faithful
/// verifier is `compat::ed25519::tweetnacl_sign_detached_verify` (it reduces
/// S mod L, then calls this).
///
/// (dalek's `verify_strict` is the same equation plus small-order
/// rejections, so it only ever accepts a subset of this.)
pub fn ed25519_verify(public: &[u8; 32], msg: &[u8], sig: &[u8]) -> bool {
    use ed25519_dalek::Verifier;
    let Ok(sig) = ed25519_dalek::Signature::from_slice(sig) else { return false };
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(public) else { return false };
    vk.verify(msg, &sig).is_ok()
}

/// RE-DERIVE the 32-byte Ed25519 public key from the seed of tweetnacl's
/// 64-byte secret. Not `nacl.sign.keyPair.fromSecretKey`, which COPIES
/// `sk[32..64]` (`compat::ed25519::tweetnacl_sign_public_key_from_secret_key`);
/// the two differ only for a secret whose halves disagree.
pub fn ed25519_public_from_secret64(secret64: &[u8; 64]) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&secret64[..32]);
    ed25519_keypair_from_seed(&seed).1
}

// ───────── NaCl box (tweetnacl nacl.box.*) ─────────

/// tweetnacl `nacl.box.before(theirPub, mySecret)` =
/// HSalsa20(key = X25519(mySecret, theirPub), input = 16 zero bytes).
pub fn box_before(their_pub: &[u8; 32], my_secret: &[u8; 32]) -> [u8; 32] {
    use salsa20::cipher::consts::U10;
    let shared = x25519(my_secret, their_pub);
    let k = salsa20::hsalsa::<U10>(&shared.into(), &[0u8; 16].into());
    let mut out = [0u8; 32];
    out.copy_from_slice(&k);
    out
}

/// tweetnacl `nacl.box(msg, nonce, theirPub, mySecret)`.
pub fn box_seal(msg: &[u8], nonce: &[u8; 24], their_pub: &[u8; 32], my_secret: &[u8; 32]) -> Vec<u8> {
    secretbox_seal(msg, nonce, &box_before(their_pub, my_secret))
}

/// tweetnacl `nacl.box.open(boxed, nonce, theirPub, mySecret)`.
pub fn box_open(boxed: &[u8], nonce: &[u8; 24], their_pub: &[u8; 32], my_secret: &[u8; 32]) -> Option<Vec<u8>> {
    secretbox_open(boxed, nonce, &box_before(their_pub, my_secret))
}

// ───────── Hashes / MACs (@noble/hashes, tweetnacl nacl.hash) ─────────

/// tweetnacl `nacl.hash` = SHA-512.
pub fn sha512(data: &[u8]) -> [u8; 64] {
    use sha2::Digest;
    sha2::Sha512::digest(data).into()
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(data).into()
}

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    use hmac::Mac;
    let mut m = <hmac::Hmac<sha2::Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(msg);
    m.finalize().into_bytes().into()
}

// ───────── Random identifiers (crypto.ts secureUUID / secureRandomB64 / device id) ─────────

/// `secureUUID()`: RFC 4122 v4 from 16 random bytes, LOWERCASE canonical form
/// (callId etc. — the protocol compares them as strings).
pub fn secure_uuid(rng: &mut dyn Rng) -> String {
    let mut b = [0u8; 16];
    rng.fill(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

/// `secureRandomB64(n)`.
pub fn secure_random_b64(rng: &mut dyn Rng, n: usize) -> String {
    let mut b = vec![0u8; n];
    rng.fill(&mut b);
    b64(&b)
}

/// `getStableDeviceId()` value format: 16 random bytes as lowercase hex.
pub fn stable_device_id(rng: &mut dyn Rng) -> String {
    let mut b = [0u8; 16];
    rng.fill(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}
