//! ML-KEM-768 (FIPS 203) — the post-quantum half of the hybrid session
//! setup (03-crypto §V3.3.1, wire-1.1 §W6). The only module that touches the
//! KEM crate.
//!
//! Every call goes to `libcrux_ml_kem::mlkem768::portable`: the instantiation
//! over the portable vector code and the portable SHA-3. The crate's front
//! functions pick NEON on every `aarch64` target, and its verification
//! statement covers the portable and AVX2 code only — so the choice is made
//! here, in the source, where a build flag cannot undo it. ML-KEM runs once
//! per session setup; its speed does not matter.
//!
//! A device stores the 64-byte seed `d ‖ z`, never the 2400-byte
//! decapsulation key: the key pair is re-derived when it is needed.

use libcrux_ml_kem::mlkem768::{portable, MlKem768Ciphertext, MlKem768PublicKey};

/// Encapsulation key (public), FIPS 203 ML-KEM-768.
pub const EK_LEN: usize = 1184;
/// Ciphertext.
pub const CT_LEN: usize = 1088;
/// Key-generation seed `d ‖ z`.
pub const SEED_LEN: usize = 64;
/// Shared secret.
pub const SS_LEN: usize = 32;
/// Encapsulation randomness `m`.
pub const ENCAPS_RANDOMNESS_LEN: usize = 32;
/// The algorithm byte of a signed KEM prekey and of the session KDF info.
pub const ALG_MLKEM768: u8 = 0x0A;
/// The algorithm name in the bundle and the upload bodies.
pub const ALG_NAME_MLKEM768: &str = "mlkem768";

/// `ML-KEM.KeyGen_internal(d, z)`: the encapsulation key of `seed = d ‖ z`.
pub fn encapsulation_key(seed: &[u8; SEED_LEN]) -> [u8; EK_LEN] {
    *portable::generate_key_pair(*seed).pk()
}

/// The FIPS 203 §7.2 encapsulation-key check (every coefficient reduced).
pub fn validate_encapsulation_key(ek: &[u8; EK_LEN]) -> bool {
    portable::validate_public_key(&MlKem768PublicKey::from(ek))
}

/// `ML-KEM.Encaps_internal(ek, m)` → `(ct, ss)`; `None` for an `ek` that
/// fails the modulus check (never encapsulate to an unvalidated key).
pub fn encapsulate(ek: &[u8; EK_LEN], m: &[u8; ENCAPS_RANDOMNESS_LEN]) -> Option<([u8; CT_LEN], [u8; SS_LEN])> {
    let pk = MlKem768PublicKey::from(ek);
    if !portable::validate_public_key(&pk) {
        return None;
    }
    let (ct, ss) = portable::encapsulate(&pk, *m);
    Some((*ct.as_slice(), ss))
}

/// `ML-KEM.Decaps(dk(seed), ct)`. Never fails: a ciphertext that was not
/// made for this key yields the implicit-rejection secret, which simply
/// derives a session nobody else holds (the envelope MAC then fails).
pub fn decapsulate(seed: &[u8; SEED_LEN], ct: &[u8; CT_LEN]) -> [u8; SS_LEN] {
    let pair = portable::generate_key_pair(*seed);
    portable::decapsulate(pair.private_key(), &MlKem768Ciphertext::from(ct))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_implicit_rejection() {
        let seed = [7u8; SEED_LEN];
        let ek = encapsulation_key(&seed);
        assert!(validate_encapsulation_key(&ek));
        let (ct, ss) = encapsulate(&ek, &[9u8; 32]).unwrap();
        assert_eq!(decapsulate(&seed, &ct), ss);
        let mut bad = ct;
        bad[0] ^= 1;
        assert_ne!(decapsulate(&seed, &bad), ss, "a flipped ciphertext decapsulates to another secret");
        assert_ne!(decapsulate(&[8u8; SEED_LEN], &ct), ss, "another key decapsulates to another secret");
    }

    #[test]
    fn an_unreduced_key_is_refused() {
        // Twelve-bit coefficients of 0xFFF are ≥ q = 3329: the modulus check fails.
        let mut ek = encapsulation_key(&[1u8; SEED_LEN]);
        ek[0] = 0xff;
        ek[1] = 0xff;
        assert!(!validate_encapsulation_key(&ek));
        assert!(encapsulate(&ek, &[0u8; 32]).is_none());
    }
}
