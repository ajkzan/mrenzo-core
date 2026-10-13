//! Sealed identity-key backup slot — line-for-line port of the RN client
//! (build 324):
//! - `mobile/src/utils/crypto.ts:251-331` (`identityBackupSubkey`,
//!   `sealIdentityBackup`, `openIdentityBackup`),
//! - `mobile/src/services/secureStorage.ts:346-351` (`deriveStorageSubkey`),
//! - `mobile/src/store/auth.ts:491-622` (the restore gate and the backfill
//!   re-seal decision that consume the slot).
//!
//! Contract: docs/native/protocol/03-crypto.md ("Sealed identity backup") and
//! the local-data notes of the closed-source app (not published); conformance:
//! docs/native/vectors/identityBackup.json (tests/golden_identity_backup.rs).
//!
//! LOCAL-ONLY: the slot never crosses devices. Native needs it only to adopt
//! the RN slot when it replaces the RN app in place.
//!
//! Faithful to the RN client INCLUDING its quirks, which must not be "fixed"
//! here (the slot on disk was written by RN):
//! - The subkey hashes the MMKV key's hex STRING (`context + mmkvKeyHex`,
//!   string concatenation), not the 16 decoded bytes.
//! - The sealed plaintext is the UTF-8 of the 44-char base64 TEXT of the
//!   X25519 private key, not the raw 32 bytes.
//! - `openIdentityBackup` swallows every failure (bad base64, short blob,
//!   storage not ready, MAC failure, non-UTF-8 plaintext) into `null`.
//! - An empty storage key (`''`) counts as "not ready" (JS falsy check).
//! - `decodeBase64` (tweetnacl-util → atob/Buffer) IGNORES non-zero trailing
//!   bits in the last base64 quantum; `primitives::b64d` (base64 crate
//!   STANDARD) rejects them. This module therefore decodes with `compat::b64`
//!   (the tweetnacl-util regex gate + lenient tail), so a blob the RN client
//!   would open is opened here too.
//! - A slot that opens to the empty string is treated as absent/tampered by
//!   the restore gate (`if (blob && !backup)` / `if (backup)` are falsy checks).

use crate::compat::b64::tweetnacl_util_decode_base64 as ts_decode_base64;
use crate::compat::utf8::tweetnacl_util_encode_utf8;
use crate::primitives::{b64, secretbox_open, secretbox_seal, sha512, x25519_base};
use crate::rng::Rng;

/// `crypto.ts:267` — domain-separation context for the backup subkey.
pub const IDENTITY_BACKUP_CONTEXT: &str = "mrenzo-identity-backup-v1";
/// `auth.ts:43` — MMKV (default namespace) key holding the sealed blob.
pub const IDENTITY_KEY_BACKUP: &str = "identity_key_backup_v1";
/// `auth.ts:51` — MMKV key holding the owning uid (`String(user.id)`).
pub const IDENTITY_KEY_BACKUP_UID: &str = "identity_key_backup_uid";

/// tweetnacl `nacl.secretbox.overheadLength`.
const SECRETBOX_OVERHEAD: usize = 16;
/// tweetnacl `nacl.secretbox.nonceLength` (the literal `24` in crypto.ts).
const NONCE_LEN: usize = 24;

#[derive(Debug, PartialEq, Eq)]
pub enum IdentityBackupError {
    /// `identityBackupSubkey()` throws when secure storage has no key yet.
    StorageNotReady,
}

impl std::fmt::Display for IdentityBackupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Same text as the TS `throw new Error(...)` (crypto.ts:277).
            IdentityBackupError::StorageNotReady => {
                write!(f, "secure storage not ready — cannot derive backup key")
            }
        }
    }
}

impl std::error::Error for IdentityBackupError {}

/// `deriveStorageSubkey(context)` (secureStorage.ts:346-351).
///
/// `encryption_key` is secureStorage's `_encryptionKey`: the 32-char hex
/// STRING from Keychain service `com.mrenzo.mmkv.key`, or `None` before
/// `initSecureStorage()`. JS returns null on a falsy key, so `Some("")` is
/// also "not ready". Output = `SHA-512(UTF-8(context + encryption_key))[0..32]`.
pub fn derive_storage_subkey(context: &str, encryption_key: Option<&str>) -> Option<[u8; 32]> {
    let key = match encryption_key {
        Some(k) if !k.is_empty() => k,
        _ => return None, // if (!_encryptionKey) return null;
    };
    // decodeUTF8(context + _encryptionKey): string concat, then UTF-8 bytes.
    let mut s = String::with_capacity(context.len() + key.len());
    s.push_str(context);
    s.push_str(key);
    let h = sha512(s.as_bytes()); // nacl.hash
    let mut out = [0u8; 32];
    out.copy_from_slice(&h[..32]); // .slice(0, 32)
    Some(out)
}

/// `identityBackupSubkey()` (crypto.ts:269-279): the derived subkey, or the
/// "storage not ready" throw.
pub fn identity_backup_subkey(mmkv_key: Option<&str>) -> Result<[u8; 32], IdentityBackupError> {
    derive_storage_subkey(IDENTITY_BACKUP_CONTEXT, mmkv_key).ok_or(IdentityBackupError::StorageNotReady)
}

/// `sealIdentityBackup(privateKeyB64)` (crypto.ts:282-290).
///
/// Order matters for the RNG contract: the subkey is derived FIRST (a
/// not-ready storage throws before any randomness is drawn), then exactly one
/// 24-byte draw for the nonce. The argument is not validated: whatever string
/// is passed is sealed as its UTF-8 bytes.
///
/// Output: `b64(nonce(24) || tag(16) || XSalsa20(UTF-8(privateKeyB64)))`.
pub fn seal_identity_backup(
    private_key_b64: &str,
    mmkv_key: Option<&str>,
    rng: &mut dyn Rng,
) -> Result<String, IdentityBackupError> {
    let key = identity_backup_subkey(mmkv_key)?; // const key = identityBackupSubkey();
    let mut nonce = [0u8; NONCE_LEN]; // const nonce = nacl.randomBytes(24);
    rng.fill(&mut nonce);
    // nacl.secretbox(decodeUTF8(privateKeyB64), nonce, key)
    let boxed = secretbox_seal(private_key_b64.as_bytes(), &nonce, &key);
    let mut out = Vec::with_capacity(nonce.len() + boxed.len());
    out.extend_from_slice(&nonce); // out.set(nonce);
    out.extend_from_slice(&boxed); // out.set(box, nonce.length);
    Ok(b64(&out)) // encodeBase64(out)
}

/// `openIdentityBackup(blob)` (crypto.ts:319-331): open + AUTHENTICATE a slot.
///
/// `None` on ANY failure (the TS body is wrapped in `try { … } catch { return
/// null }`): invalid base64, `raw.length < 24 + 16`, storage not ready,
/// secretbox MAC failure (tamper / corruption / another device's subkey), or
/// a plaintext that is not valid UTF-8 (`encodeUTF8` throws URIError).
/// `Some("")` is possible (a sealed empty string); callers that mirror
/// auth.ts must treat it as falsy — see [`restore_gate`].
pub fn open_identity_backup(blob: &str, mmkv_key: Option<&str>) -> Option<String> {
    let raw = ts_decode_base64(blob)?; // decodeBase64(blob) — throws → null
    if raw.len() < NONCE_LEN + SECRETBOX_OVERHEAD {
        return None;
    }
    // const nonce = raw.slice(0, 24); const box = raw.slice(24);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&raw[..NONCE_LEN]);
    let boxed = &raw[NONCE_LEN..];

    // identityBackupSubkey() is evaluated as an argument of secretbox.open,
    // i.e. after the length check; a throw there is caught → null.
    let key = identity_backup_subkey(mmkv_key).ok()?;
    let opened = secretbox_open(boxed, &nonce, &key)?; // if (!opened) return null;

    // encodeUTF8(opened) = decodeURIComponent(escape(...)): strict UTF-8, throws → null.
    tweetnacl_util_encode_utf8(opened)
}

/// Outcome of the build-294/316 restore gate (auth.ts:495-549), evaluated only
/// when the Keychain read missed (`!privKey`). Each variant names the log
/// event RN emits so a native adopter can keep the same telemetry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RestoreGate {
    /// No slot (`storage.getString` → undefined or `''`); nothing logged.
    NoSlot,
    /// Slot present but `openIdentityBackup` → null, or it opened to `''`
    /// (falsy): `identity.backup.tampered`. Never adopt.
    Tampered,
    /// Opened, but bound to ANOTHER uid: `identity.backup.uidMismatch`
    /// `{ bound, me }`. Never adopt.
    UidMismatch { bound: String, me: String },
    /// Opened, legacy (no uid recorded) and ownership NOT proven by the
    /// derived public key: `identity.backup.legacyUnproven`
    /// `{ haveDerived, haveKnownPub }`. Never adopt.
    LegacyUnproven { have_derived: bool, have_known_pub: bool },
    /// Adopt this key (then RN re-persists it, derives+uploads its public
    /// half and re-seals the slot with the uid, auth.ts:550-570).
    /// `legacy_accepted` = the unbound-slot path that logged
    /// `identity.backup.legacyAccepted`.
    Adopt { private_key_b64: String, legacy_accepted: bool },
}

/// The restore gate (auth.ts:495-549), as a pure function of what RN reads.
///
/// - `blob` = `storage.getString(IDENTITY_KEY_BACKUP)` (None = undefined).
/// - `slot_uid` = `storage.getString(IDENTITY_KEY_BACKUP_UID)` (None = undefined).
/// - `my_uid` = `String(get().user?.id ?? '')` — decimal id, or `""` with no user.
/// - `known_pub` = `get().user?.publicKey` (None/`""` both falsy).
///
/// Quirks kept: an empty slot uid is "legacy" (not a mismatch); a non-empty
/// slot uid equal to `my_uid` adopts WITHOUT any public-key check; with no
/// user (`my_uid == ""`) a bound slot is always a mismatch.
pub fn restore_gate(
    blob: Option<&str>,
    slot_uid: Option<&str>,
    my_uid: &str,
    known_pub: Option<&str>,
    mmkv_key: Option<&str>,
) -> RestoreGate {
    // let backup = blob ? openIdentityBackup(blob) : null;
    let blob = match blob {
        Some(b) if !b.is_empty() => b,
        _ => return RestoreGate::NoSlot,
    };
    let backup = match open_identity_backup(blob, mmkv_key) {
        Some(b) if !b.is_empty() => b,
        // if (blob && !backup) → identity.backup.tampered; `if (backup)` skipped.
        _ => return RestoreGate::Tampered,
    };
    let slot_uid = slot_uid.unwrap_or(""); // storage.getString(UID) || ''
    if !slot_uid.is_empty() && slot_uid != my_uid {
        return RestoreGate::UidMismatch { bound: slot_uid.to_string(), me: my_uid.to_string() };
    }
    if slot_uid.is_empty() {
        // let derived = ''; try { derived = derivePublicKey(backup); } catch {}
        let derived = derive_public_key(&backup).unwrap_or_default();
        let known_pub = known_pub.unwrap_or(""); // get().user?.publicKey || ''
        if derived.is_empty() || known_pub.is_empty() || derived != known_pub {
            return RestoreGate::LegacyUnproven {
                have_derived: !derived.is_empty(),
                have_known_pub: !known_pub.is_empty(),
            };
        }
        return RestoreGate::Adopt { private_key_b64: backup, legacy_accepted: true };
    }
    RestoreGate::Adopt { private_key_b64: backup, legacy_accepted: false }
}

/// The backfill re-seal decision (auth.ts:616-619), taken when the Keychain
/// DID return `priv_key`:
/// `!existing || openIdentityBackup(existing) !== privKey || existingUid !== meUid`.
///
/// When true RN writes `sealIdentityBackup(privKey)` + `meUid` (a seal throw is
/// logged as `identity.backup.sealFailed` and swallowed). This is also how a
/// raw build-294 slot (the unauthenticated b64 string) migrates: it fails to
/// open, so it is re-sealed.
pub fn backfill_needs_reseal(
    existing: Option<&str>,
    existing_uid: Option<&str>,
    priv_key: &str,
    me_uid: &str,
    mmkv_key: Option<&str>,
) -> bool {
    let existing = match existing {
        Some(e) if !e.is_empty() => e,
        _ => return true, // !existing
    };
    if open_identity_backup(existing, mmkv_key).as_deref() != Some(priv_key) {
        return true;
    }
    existing_uid.unwrap_or("") != me_uid // (getString(UID) || '') !== meUid
}

/// `derivePublicKey(privateKeyB64)` (crypto.ts:64-68):
/// `encodeBase64(nacl.box.keyPair.fromSecretKey(decodeBase64(b64)).publicKey)`.
/// `None` where the TS throws (bad base64, or not exactly 32 bytes).
fn derive_public_key(private_key_b64: &str) -> Option<String> {
    let raw = ts_decode_base64(private_key_b64)?;
    let sk: [u8; 32] = raw.try_into().ok()?; // 'bad secret key size'
    Some(b64(&x25519_base(&sk)))
}

#[cfg(test)]
mod tests {
    use super::ts_decode_base64;

    #[test]
    fn decoder_matches_tweetnacl_util_gate_and_lenient_tail() {
        // primitives.json base64Strictness cases (same accept/reject + bytes).
        assert_eq!(ts_decode_base64("AAAA"), Some(vec![0, 0, 0]));
        assert_eq!(ts_decode_base64("AA=="), Some(vec![0]));
        assert_eq!(ts_decode_base64("AAA="), Some(vec![0, 0]));
        assert_eq!(ts_decode_base64("+/8="), Some(vec![0xfb, 0xff]));
        for bad in ["AAA", "AA", "-_8=", "AAAA\nAAAA", " AAAA", "AAAA="] {
            assert_eq!(ts_decode_base64(bad), None, "{bad:?}");
        }
        // Regex shapes: padding only in the final quantum, never "A===".
        for bad in ["A===", "====", "AA==AAAA", "AAA=AAAA", "AA=A", "=AAA"] {
            assert_eq!(ts_decode_base64(bad), None, "{bad:?}");
        }
        assert_eq!(ts_decode_base64(""), Some(vec![]));
        // atob/Buffer (node, verified): trailing bits are discarded, not rejected.
        assert_eq!(ts_decode_base64("AB=="), Some(vec![0]));
        assert_eq!(ts_decode_base64("AAB="), Some(vec![0, 0]));
    }
}
