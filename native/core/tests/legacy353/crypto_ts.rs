//! Ports of the `mobile/src/utils/crypto.ts` helpers that more than one
//! protocol module calls (build 324): `signPayload` (:536-541) and
//! `verifyPayload` (:548-564).

use crate::legacy353::compat::b64::tweetnacl_util_decode_base64;
use crate::legacy353::compat::ed25519::{tweetnacl_sign_detached, tweetnacl_sign_detached_verify};
use mrenzo_core::primitives::{b64, ed25519_sign};

/// Where `signPayload` throws.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignPayloadError {
    /// tweetnacl-util `decodeBase64` → `TypeError('invalid encoding')`.
    InvalidEncoding,
    /// `nacl.sign.detached` → `Error('bad secret key size')` (not 64 bytes).
    BadSecretKeySize,
}

impl std::fmt::Display for SignPayloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SignPayloadError::InvalidEncoding => "invalid encoding",
            SignPayloadError::BadSecretKeySize => "bad secret key size",
        })
    }
}

impl std::error::Error for SignPayloadError {}

fn decode_secret_key(private_key_b64: &str) -> Result<[u8; 64], SignPayloadError> {
    let secret = tweetnacl_util_decode_base64(private_key_b64).ok_or(SignPayloadError::InvalidEncoding)?;
    secret.try_into().map_err(|_| SignPayloadError::BadSecretKeySize)
}

/// `signPayload(payloadUtf8, privateKeyB64)`: base64 of
/// `nacl.sign.detached(decodeUTF8(payload), decodeBase64(privateKeyB64))`,
/// with tweetnacl's signer (the STORED pub half `sk[32..64]` is hashed).
pub fn sign_payload(payload_utf8: &str, private_key_b64: &str) -> Result<String, SignPayloadError> {
    let secret = decode_secret_key(private_key_b64)?;
    Ok(b64(&tweetnacl_sign_detached(payload_utf8.as_bytes(), &secret)))
}

/// APPROXIMATION of [`sign_payload`] that signs with the RFC 8032 signer
/// (`primitives::ed25519_sign`, which re-derives the public half from the
/// seed). Identical for every key tweetnacl generated; different S when the
/// halves of a corrupt 64-byte secret disagree. Kept for `sdp_signing` and
/// `mesh_envelope`, which ship it.
pub fn sign_payload_rfc8032(payload_utf8: &str, private_key_b64: &str) -> Result<String, SignPayloadError> {
    let secret = decode_secret_key(private_key_b64)?;
    Ok(b64(&ed25519_sign(&secret, payload_utf8.as_bytes())))
}

/// `verifyPayload(payloadUtf8, signatureB64, publicKeyB64)`: `false` for an
/// empty signature/key, bad base64, a signature ≠ 64 or key ≠ 32 bytes, or
/// an invalid signature (tweetnacl's accept set: S unreduced). Never throws.
pub fn verify_payload(payload_utf8: &str, signature_b64: &str, public_key_b64: &str) -> bool {
    if signature_b64.is_empty() || public_key_b64.is_empty() {
        return false;
    }
    let Some(signature) = tweetnacl_util_decode_base64(signature_b64) else { return false };
    let Some(public_key) = tweetnacl_util_decode_base64(public_key_b64) else { return false };
    let Ok(signature) = <[u8; 64]>::try_from(signature) else { return false };
    let Ok(public_key) = <[u8; 32]>::try_from(public_key) else { return false };
    tweetnacl_sign_detached_verify(payload_utf8.as_bytes(), &signature, &public_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::legacy353::compat::ed25519::ED25519_L;
    use mrenzo_core::primitives::ed25519_keypair_from_seed;

    #[test]
    fn sign_and_verify_payload() {
        let (sk, pk) = ed25519_keypair_from_seed(&[5u8; 32]);
        let (sk_b64, pk_b64) = (b64(&sk), b64(&pk));
        let sig = sign_payload("fp|1|n|7", &sk_b64).unwrap();
        assert_eq!(sig, sign_payload_rfc8032("fp|1|n|7", &sk_b64).unwrap(), "consistent halves");
        assert!(verify_payload("fp|1|n|7", &sig, &pk_b64));
        assert!(!verify_payload("fp|1|n|8", &sig, &pk_b64));
        assert!(!verify_payload("fp|1|n|7", "", &pk_b64));
        assert!(!verify_payload("fp|1|n|7", &sig, ""));
        assert!(!verify_payload("fp|1|n|7", "!!!!", &pk_b64));
        assert!(!verify_payload("fp|1|n|7", &b64(&[0u8; 63]), &pk_b64));
        assert!(!verify_payload("fp|1|n|7", &sig, &b64(&pk[..31])));
        // S + L still verifies (tweetnacl), and a non-canonical trailing
        // base64 character is still the same signature (atob).
        let mut raw = mrenzo_core::primitives::b64d(&sig).unwrap();
        let mut carry = 0u16;
        for i in 0..32 {
            let v = u16::from(raw[32 + i]) + u16::from(ED25519_L[i]) + carry;
            raw[32 + i] = v as u8;
            carry = v >> 8;
        }
        if carry == 0 {
            assert!(verify_payload("fp|1|n|7", &b64(&raw), &pk_b64));
        }
        let tail = sig.as_bytes()[85];
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let v = alphabet.iter().position(|&c| c == tail).unwrap();
        let mut noncanonical = sig.clone().into_bytes();
        noncanonical[85] = alphabet[v | 0x0f];
        assert!(verify_payload("fp|1|n|7", std::str::from_utf8(&noncanonical).unwrap(), &pk_b64));

        assert_eq!(sign_payload("x", "not base64"), Err(SignPayloadError::InvalidEncoding));
        assert_eq!(sign_payload("x", &pk_b64), Err(SignPayloadError::BadSecretKeySize));
        assert_eq!(sign_payload_rfc8032("x", &pk_b64), Err(SignPayloadError::BadSecretKeySize));
        assert_eq!(SignPayloadError::InvalidEncoding.to_string(), "invalid encoding");
        assert_eq!(SignPayloadError::BadSecretKeySize.to_string(), "bad secret key size");

        let mut mm = sk;
        mm[32..].copy_from_slice(&[2u8; 32]);
        assert_ne!(sign_payload("x", &b64(&mm)), sign_payload_rfc8032("x", &b64(&mm)), "mismatched halves");
    }
}
