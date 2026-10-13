//! X3DH prekeys — line-for-line port of `mobile/src/utils/x3dh.ts` plus the
//! storage-free, network-free policy of `mobile/src/services/x3dhBootstrap.ts`
//! (build 324). Contract: docs/native/protocol/03-crypto.md §11 and
//! 01-rest-api.md §6; conformance: docs/native/vectors/x3dh.json
//! (tests/golden_x3dh.rs).
//!
//! ```text
//! SPK signature = Ed25519-detached(raw 32-byte X25519 SPK pub, identitySigningSecret64)
//! DH1 = X25519(IKa, SPKb)   DH2 = X25519(EKa, IKb)   DH3 = X25519(EKa, SPKb)   DH4 = X25519(EKa, OPKb)
//! SK  = HKDF-SHA256(salt = 0x00×32, ikm = 0xFF×32 ‖ DH1 ‖ DH2 ‖ DH3 [‖ DH4], info = "mr.enzo.x3dh.v1", L = 32)
//! AD  = IKa_pub ‖ IKb_pub                      (sender first, on both sides)
//! ```
//!
//! STATUS in the RN app: SPK/OPK generation + upload is LIVE (bootstrap runs
//! after login); `deriveSharedSecretAs{Sender,Recipient}` have NO production
//! caller — the 1:1 ratchet still bootstraps from the identity key.
//!
//! Faithful to the RN client INCLUDING its quirks, which must not be "fixed"
//! here (that would break interop with RN clients in the field):
//! - The SPK signature covers the RAW 32 X25519 bytes — no libsignal `0x05`
//!   type byte, and not the base64 text.
//! - `verifyBundleSignature` never throws. A falsy `signingKey` (absent, `null`
//!   or `""`) is `false` — and the Go bundle endpoint serves the stale, empty
//!   `users.signing_public_key` column, so against today's server every real
//!   bundle fails verification. Only the signature (64) and signing key (32)
//!   lengths are checked: the SPK pub is verified as a message of ANY length.
//! - `deriveSharedSecretAsSender` checks `myIdentityPriv.length` (throws)
//!   BEFORE drawing, then draws the 32-byte ephemeral BEFORE decoding the
//!   bundle, so a bundle that then throws (`invalid encoding` / `bad p size`)
//!   has still consumed one draw. It decodes every key (IK, SPK, OPK) before
//!   the first scalar multiplication, so an undecodable OPK wins over a short
//!   SPK. It does not verify the SPK signature itself (the caller must).
//! - The OPK branch is keyed on the bundle's `oneTimePreKey` OBJECT being
//!   present, not on its `pubKey`; `usedOneTimePreKeyId` echoes its `keyId`.
//! - `myIdentityPub` is never length-checked or matched to `myIdentityPriv`
//!   on either side: AD is whatever bytes the caller passes, concatenated.
//! - Recipient: no checks beyond tweetnacl `scalarMult` (`bad n size` for the
//!   private operand, checked before `bad p size`). An EMPTY OPK private is
//!   truthy in JS and throws `bad n size` instead of falling back to 3-DH; an
//!   absent one when the sender used an OPK silently yields a different root.
//! - Raw X25519 outputs (not HSalsa20); tweetnacl never rejects low-order
//!   points (an all-zero DH is accepted) and ignores the top bit of `u`.
//! - The TS `utf8()` helper is `charCodeAt` truncation (Latin-1), not UTF-8 —
//!   irrelevant for the ASCII info label.
//! - `generateSignedPreKey` draws the keypair BEFORE tweetnacl checks the
//!   signing key's size (`bad secret key size` after one draw), and tweetnacl
//!   signs with the secret's STORED pub half `sk[32..64]` inside `H(R‖A‖M)`
//!   (`primitives::ed25519_sign` re-derives `A`, hence
//!   `compat::ed25519::tweetnacl_sign_detached`).
//! - tweetnacl's verify accepts a non-reduced `S` (`S + L`), and
//!   tweetnacl-util's `decodeBase64` (strict padded regex, then `atob`)
//!   discards non-zero trailing bits (`…g==` ≡ `…h==`); `primitives` rejects
//!   both, hence `compat::ed25519` and `compat::b64`.
//!
//! Bootstrap quirks (policy helpers at the bottom of this file):
//! - One monotonic `nextKeyId` counter (`?? 1`, so a stored 0 is used as-is)
//!   feeds SPKs and OPK batches. An OPK batch allocates ONE id (`next =
//!   start + 1`) and only jumps to `start + 100` after a successful upload. A
//!   failed upload therefore leaves the next batch overlapping ids
//!   `start+1 … start+99`; if the "failed" request actually landed, the
//!   server's `INSERT OR IGNORE` keeps the first batch's pubs, whose privates
//!   were never stored — first messages using them would be undecryptable.
//! - The SPK (and each OPK private) is stored only after its upload succeeds.
//!   `spkRotatedAt` is written but never read; rotation reads the JSON's
//!   `rotatedAt` through JS coercion (`Date.now() - (obj.rotatedAt || 0)`),
//!   so a non-numeric value (NaN) disables rotation forever.
//! - `getStoredSPKPriv` does no length check and `decodeBase64` coerces with
//!   ToString (`"privKey": null` decodes as base64 "null" = 3 bytes).
//! - `consumeStoredOPKPriv` deletes the entry BEFORE decoding it.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::legacy353::compat::b64::tweetnacl_util_decode_base64 as decode_base64;
use crate::legacy353::compat::ed25519::{tweetnacl_sign_detached as nacl_sign_detached, tweetnacl_sign_detached_verify};
use crate::legacy353::compat::js_value::{to_boolean as js_truthy, to_number_lenient_ties_up_u128_radix as js_to_number, to_string_lenient_ties_up as js_to_string};
#[cfg(test)]
use crate::legacy353::compat::js_number::{number_to_string_ties_up as js_number_to_string, string_to_number_u128_radix as js_string_to_number};
use mrenzo_core::primitives::{b64, hkdf32, x25519, x25519_keypair};
use mrenzo_core::rng::Rng;

/// HKDF info label (`utf8('mr.enzo.x3dh.v1')`, note the dots).
pub const X3DH_INFO: &str = "mr.enzo.x3dh.v1";

// ───────── Types (x3dh.ts) ─────────

/// `SignedPreKey` as carried in a bundle. The Go server also sends
/// `signedPreKey.userId`, which the client ignores (and so does this parser).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedPreKey {
    pub key_id: i64,
    /// base64 X25519.
    pub pub_key: String,
    /// base64 Ed25519 signature over the raw `pub_key` bytes.
    pub signature: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OneTimePreKey {
    pub key_id: i64,
    /// base64 X25519.
    pub pub_key: String,
}

/// `GET /api/x3dh/bundle/:userId`. Field order is the TS interface's; the Go
/// server emits sorted keys and omits `oneTimePreKey` when the pool is empty.
/// `signing_key` is optional because the TS treats absent / `null` / `""`
/// alike (verification fails).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrekeyBundle {
    pub user_id: i64,
    /// base64 X25519 (recipient's long-term IK pub).
    pub identity_key: String,
    /// base64 Ed25519 (verifies the SPK signature).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_key: Option<String>,
    pub signed_pre_key: SignedPreKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub one_time_pre_key: Option<OneTimePreKey>,
}

/// `X3DHHandshake` (sender side).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X3dhHandshake {
    /// Becomes the Double Ratchet root key.
    pub shared_root: [u8; 32],
    /// Sender's ephemeral pub, carried in the first envelope.
    pub ephemeral_pub: [u8; 32],
    /// `myIdentityPub ‖ IKb` — any length (myIdentityPub is unchecked).
    pub associated_data: Vec<u8>,
    pub used_signed_pre_key_id: i64,
    pub used_one_time_pre_key_id: Option<i64>,
}

/// `{ sharedRoot, associatedData }` (recipient side).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X3dhRecipientSecret {
    pub shared_root: [u8; 32],
    /// `senderIdentityPub ‖ myIdentityPub`.
    pub associated_data: Vec<u8>,
}

/// `generateSignedPreKey` result. Serialises in the TS key order
/// `{keyId, privKey, pubKey, signature}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedSignedPreKey {
    pub key_id: i64,
    pub priv_key: String,
    pub pub_key: String,
    pub signature: String,
}

/// `generateOneTimePreKeys` element: `{keyId, privKey, pubKey}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedOneTimePreKey {
    pub key_id: i64,
    pub priv_key: String,
    pub pub_key: String,
}

/// Everything the TS functions throw, with the exact message text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X3dhError {
    /// `deriveSharedSecretAsSender`: `myIdentityPriv.length !== 32`.
    BadIdentityPrivLength,
    /// tweetnacl-util `decodeBase64`: `TypeError('invalid encoding')`.
    InvalidEncoding,
    /// tweetnacl `scalarMult`: scalar (private) operand not 32 bytes.
    BadNSize,
    /// tweetnacl `scalarMult`: point (public) operand not 32 bytes.
    BadPSize,
    /// tweetnacl `sign.detached`: secret key not 64 bytes.
    BadSecretKeySize,
}

impl std::fmt::Display for X3dhError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            X3dhError::BadIdentityPrivLength => "myIdentityPriv must be 32 bytes (X25519 secret)",
            X3dhError::InvalidEncoding => "invalid encoding",
            X3dhError::BadNSize => "bad n size",
            X3dhError::BadPSize => "bad p size",
            X3dhError::BadSecretKeySize => "bad secret key size",
        })
    }
}

impl std::error::Error for X3dhError {}

// ───────── Public functions (x3dh.ts) ─────────

/// `verifyBundleSignature(bundle)`. Never throws; every malformation is `false`.
pub fn verify_bundle_signature(bundle: &PrekeyBundle) -> bool {
    // if (!bundle.signingKey) return false;
    let Some(signing_key) = bundle.signing_key.as_deref().filter(|s| !s.is_empty()) else {
        return false;
    };
    // try { decode ×3 } catch { return false; }
    let Some(signing_pub) = decode_base64(signing_key) else { return false };
    let Some(spk_pub) = decode_base64(&bundle.signed_pre_key.pub_key) else { return false };
    let Some(signature) = decode_base64(&bundle.signed_pre_key.signature) else { return false };
    // signature length first, then the signing key's.
    let Ok(signature) = <[u8; 64]>::try_from(signature) else { return false };
    let Ok(signing_pub) = <[u8; 32]>::try_from(signing_pub) else { return false };
    // Over the raw SPK bytes, whatever their length.
    tweetnacl_sign_detached_verify(&spk_pub, &signature, &signing_pub)
}

/// `deriveSharedSecretAsSender(myIdentityPriv, myIdentityPub, bundle)`.
/// Draws exactly one 32-byte ephemeral (`nacl.box.keyPair()`) unless the
/// identity-private length check throws first.
pub fn derive_shared_secret_as_sender(
    my_identity_priv: &[u8],
    my_identity_pub: &[u8],
    bundle: &PrekeyBundle,
    rng: &mut dyn Rng,
) -> Result<X3dhHandshake, X3dhError> {
    if my_identity_priv.len() != 32 {
        return Err(X3dhError::BadIdentityPrivLength);
    }

    // Ephemeral pair — drawn before the bundle is even decoded.
    let ephemeral = x25519_keypair(rng);

    let ikb = decode_base64(&bundle.identity_key).ok_or(X3dhError::InvalidEncoding)?;
    let spkb = decode_base64(&bundle.signed_pre_key.pub_key).ok_or(X3dhError::InvalidEncoding)?;
    let opkb = match &bundle.one_time_pre_key {
        Some(opk) => Some(decode_base64(&opk.pub_key).ok_or(X3dhError::InvalidEncoding)?),
        None => None,
    };

    let dh1 = scalar_mult(my_identity_priv, &spkb)?;
    let dh2 = scalar_mult(&ephemeral.private, &ikb)?;
    let dh3 = scalar_mult(&ephemeral.private, &spkb)?;
    let dh4 = match &opkb {
        Some(opkb) => Some(scalar_mult(&ephemeral.private, opkb)?),
        None => None,
    };

    let shared_root = derive_root(&dh1, &dh2, &dh3, dh4.as_ref());

    // AD = my IK pub || their IK pub.
    let associated_data = concat(&[my_identity_pub, &ikb]);

    Ok(X3dhHandshake {
        shared_root,
        ephemeral_pub: ephemeral.public,
        associated_data,
        used_signed_pre_key_id: bundle.signed_pre_key.key_id,
        used_one_time_pre_key_id: bundle.one_time_pre_key.as_ref().map(|o| o.key_id),
    })
}

/// `deriveSharedSecretAsRecipient(myIdentityPriv, myIdentityPub,
/// mySignedPreKeyPriv, myOneTimePreKeyPriv, senderIdentityPub,
/// senderEphemeralPub)`. Draws no randomness.
pub fn derive_shared_secret_as_recipient(
    my_identity_priv: &[u8],
    my_identity_pub: &[u8],
    my_signed_pre_key_priv: &[u8],
    my_one_time_pre_key_priv: Option<&[u8]>,
    sender_identity_pub: &[u8],
    sender_ephemeral_pub: &[u8],
) -> Result<X3dhRecipientSecret, X3dhError> {
    let dh1 = scalar_mult(my_signed_pre_key_priv, sender_identity_pub)?;
    let dh2 = scalar_mult(my_identity_priv, sender_ephemeral_pub)?;
    let dh3 = scalar_mult(my_signed_pre_key_priv, sender_ephemeral_pub)?;
    // A Uint8Array is truthy even when empty: Some(&[]) throws, never 3-DH.
    let dh4 = match my_one_time_pre_key_priv {
        Some(opk) => Some(scalar_mult(opk, sender_ephemeral_pub)?),
        None => None,
    };

    let shared_root = derive_root(&dh1, &dh2, &dh3, dh4.as_ref());

    // Same order as the sender: sender's IK pub || my IK pub.
    let associated_data = concat(&[sender_identity_pub, my_identity_pub]);

    Ok(X3dhRecipientSecret { shared_root, associated_data })
}

/// `generateSignedPreKey(ed25519Priv, keyId)`: one 32-byte draw (the X25519
/// keypair), then the signature over the raw pub — which throws
/// `bad secret key size` AFTER the draw when `ed25519_priv` is not tweetnacl's
/// 64-byte `seed ‖ pub`.
pub fn generate_signed_pre_key(
    ed25519_priv: &[u8],
    key_id: i64,
    rng: &mut dyn Rng,
) -> Result<GeneratedSignedPreKey, X3dhError> {
    let kp = x25519_keypair(rng);
    let secret: &[u8; 64] = ed25519_priv.try_into().map_err(|_| X3dhError::BadSecretKeySize)?;
    let signature = nacl_sign_detached(&kp.public, secret);
    Ok(GeneratedSignedPreKey {
        key_id,
        priv_key: b64(&kp.private),
        pub_key: b64(&kp.public),
        signature: b64(&signature),
    })
}

/// `generateOneTimePreKeys(startId, count)`: one 32-byte draw per key,
/// ids `startId + i`; `count ≤ 0` yields nothing and draws nothing.
pub fn generate_one_time_pre_keys(start_id: i64, count: i64, rng: &mut dyn Rng) -> Vec<GeneratedOneTimePreKey> {
    let mut out = Vec::new();
    let mut i: i64 = 0;
    while i < count {
        let kp = x25519_keypair(rng);
        out.push(GeneratedOneTimePreKey {
            key_id: start_id + i,
            priv_key: b64(&kp.private),
            pub_key: b64(&kp.public),
        });
        i += 1;
    }
    out
}

// ───────── Helpers (x3dh.ts + tweetnacl internals) ─────────

/// SK = HKDF-SHA256(zero salt, 0xFF×32 ‖ DH1 ‖ DH2 ‖ DH3 [‖ DH4], info, 32).
fn derive_root(dh1: &[u8; 32], dh2: &[u8; 32], dh3: &[u8; 32], dh4: Option<&[u8; 32]>) -> [u8; 32] {
    let f = [0xffu8; 32];
    let ikm = match dh4 {
        Some(dh4) => concat(&[&f, dh1, dh2, dh3, dh4]),
        None => concat(&[&f, dh1, dh2, dh3]),
    };
    // `utf8()` in x3dh.ts is charCode truncation; the label is pure ASCII.
    hkdf32(&ikm, X3DH_INFO.as_bytes())
}

fn concat(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(parts.iter().map(|p| p.len()).sum());
    for p in parts {
        out.extend_from_slice(p);
    }
    out
}

/// tweetnacl `nacl.scalarMult(n, p)`: `n` checked before `p`; raw X25519.
fn scalar_mult(n: &[u8], p: &[u8]) -> Result<[u8; 32], X3dhError> {
    let n: &[u8; 32] = n.try_into().map_err(|_| X3dhError::BadNSize)?;
    let p: &[u8; 32] = p.try_into().map_err(|_| X3dhError::BadPSize)?;
    Ok(x25519(n, p))
}

// ───────── x3dhBootstrap.ts: storage layout + pure policy ─────────
//
// The orchestration (`ensureX3DHBootstrap` = ensureSPK then ensureOPKs) is
// I/O; what crosses into a native client is the storage layout (for an
// in-place import of the RN app's MMKV), the upload bodies (wire) and the
// decisions, ported below. Flow, for reference:
//   ensureSPK:  if spk_needs_new(raw, now) { id = next_key_id; spk = generate;
//               upload (fail → return, nothing stored); store StoredSpk{rotatedAt: now},
//               spkRotatedAt = now }
//   ensureOPKs: count = GET otp-count (throws → return, even if a refill is pending);
//               if !opk_refill_needed(count, pending) return; start = next_key_id;
//               batch = generate(start, 100); upload (fail → pending = true, return);
//               delete pending; nextKeyId = start + 100; store each `opk:<id>` = privKey.

/// Encrypted MMKV instance id (`lazyEncryptedMMKV({ id: 'mrenzo-x3dh' })`).
/// NB: the file header's `x3dh:` key prefixes are stale; the keys below are real.
pub const MMKV_ID: &str = "mrenzo-x3dh";
/// JSON [`StoredSpk`].
pub const KEY_SPK: &str = "spk:current";
/// `opk:<keyId>` → base64 X25519 private.
pub const KEY_OPK_PREFIX: &str = "opk:";
/// MMKV number: the next key id to allocate.
pub const KEY_NEXT_ID: &str = "nextKeyId";
/// MMKV number, written on every SPK rotation and never read.
pub const KEY_SPK_ROTATED_AT: &str = "spkRotatedAt";
/// MMKV boolean: a failed OPK upload owes a refill (build 295).
pub const KEY_OPK_RETRY: &str = "opkRefillPending";

pub const SPK_ROTATION_INTERVAL_MS: i64 = 7 * 24 * 60 * 60 * 1000;
pub const OPK_LOW_WATERMARK: i64 = 20;
pub const OPK_REFILL_BATCH: i64 = 100;

/// Go endpoints (Bearer). The bundle fetch pops one OPK server-side.
pub const PATH_SPK: &str = "/api/x3dh/spk";
pub const PATH_OTPS: &str = "/api/x3dh/otps";
pub const PATH_OTP_COUNT: &str = "/api/x3dh/otp-count";
pub const PATH_BUNDLE_PREFIX: &str = "/api/x3dh/bundle/";

/// `KEY_OPK_PREFIX + keyId`.
pub fn opk_storage_key(key_id: i64) -> String {
    format!("{KEY_OPK_PREFIX}{key_id}")
}

/// `nextKeyId()`: `cur = stored ?? 1; set(cur + 1); return cur`.
/// Returns `(allocated id, value to store under KEY_NEXT_ID)`.
pub fn next_key_id(stored: Option<i64>) -> (i64, i64) {
    let cur = stored.unwrap_or(1);
    (cur, cur + 1)
}

/// `KEY_NEXT_ID` after a SUCCESSFUL OPK batch upload (`startId + 100`).
pub fn next_key_id_after_opk_upload(start_id: i64) -> i64 {
    start_id + OPK_REFILL_BATCH
}

/// `POST /api/x3dh/spk` body: `JSON.stringify({ keyId, pubKey, signature })`.
pub fn spk_upload_body(key_id: i64, pub_key: &str, signature: &str) -> String {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Body<'a> {
        key_id: i64,
        pub_key: &'a str,
        signature: &'a str,
    }
    serde_json::to_string(&Body { key_id, pub_key, signature }).expect("body serializes")
}

/// `POST /api/x3dh/otps` body: `JSON.stringify({ keys })` with
/// `keys = batch.map((k) => ({ keyId: k.keyId, pubKey: k.pubKey }))`.
pub fn otps_upload_body(batch: &[GeneratedOneTimePreKey]) -> String {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Key<'a> {
        key_id: i64,
        pub_key: &'a str,
    }
    #[derive(Serialize)]
    struct Body<'a> {
        keys: Vec<Key<'a>>,
    }
    let keys = batch.iter().map(|k| Key { key_id: k.key_id, pub_key: &k.pub_key }).collect();
    serde_json::to_string(&Body { keys }).expect("body serializes")
}

/// `StoredSPK` under [`KEY_SPK`]: `{keyId, privKey, pubKey, signature, rotatedAt}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredSpk {
    pub key_id: i64,
    pub priv_key: String,
    pub pub_key: String,
    pub signature: String,
    pub rotated_at: i64,
}

impl StoredSpk {
    /// What `ensureSPK` stores after a successful upload (`rotatedAt: Date.now()`).
    pub fn from_generated(spk: &GeneratedSignedPreKey, now_ms: i64) -> Self {
        StoredSpk {
            key_id: spk.key_id,
            priv_key: spk.priv_key.clone(),
            pub_key: spk.pub_key.clone(),
            signature: spk.signature.clone(),
            rotated_at: now_ms,
        }
    }

    /// `JSON.stringify(stored)`.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("StoredSpk serializes")
    }
}

/// `ensureSPK`'s `needsNew` from the raw `KEY_SPK` string (`None` = unset).
/// `Date.now() - (obj.rotatedAt || 0) > 7 days` with full JS coercion.
pub fn spk_needs_new(raw: Option<&str>, now_ms: i64) -> bool {
    // if (!raw) needsNew = true;
    let Some(raw) = raw.filter(|r| !r.is_empty()) else { return true };
    // JSON.parse throws → catch → needsNew = true.
    let Ok(obj) = serde_json::from_str::<Value>(raw) else { return true };
    let rotated_at = match &obj {
        Value::Null => return true, // null.rotatedAt → TypeError → catch
        Value::Object(m) => m.get("rotatedAt"),
        _ => None, // property of a primitive / array → undefined
    };
    let subtrahend = match rotated_at {
        Some(v) if js_truthy(v) => js_to_number(v),
        _ => 0.0,
    };
    let age = now_ms as f64 - subtrahend;
    age > SPK_ROTATION_INTERVAL_MS as f64
}

/// `ensureOPKs`: refill unless `count >= OPK_LOW_WATERMARK && !pending`.
/// `count` is the parsed `res.count` (`None` = undefined → NaN → refill),
/// compared with JS `>=` coercion (`"25"` counts as 25). A THROWING count
/// fetch is handled by the caller: no refill at all, even when pending.
/// `refill_pending` is `getBoolean(KEY_OPK_RETRY) ?? false`.
// Kept in the TS shape: with NaN counts `!(count >= 20)` is not `count < 20`.
#[allow(clippy::nonminimal_bool)]
pub fn opk_refill_needed(count: Option<&Value>, refill_pending: bool) -> bool {
    let count = count.map_or(f64::NAN, js_to_number);
    !(count >= OPK_LOW_WATERMARK as f64 && !refill_pending)
}

/// `getStoredSPKPriv(keyId)` over the raw `KEY_SPK` string. No length check;
/// `obj.keyId !== keyId` is strict (a string "1" never matches).
pub fn get_stored_spk_priv(raw: Option<&str>, key_id: i64) -> Option<Vec<u8>> {
    let raw = raw.filter(|r| !r.is_empty())?;
    let obj = serde_json::from_str::<Value>(raw).ok()?;
    let Value::Object(m) = obj else {
        // null → TypeError → catch; primitives / arrays → undefined !== keyId.
        return None;
    };
    match m.get("keyId") {
        Some(Value::Number(n)) if n.as_f64() == Some(key_id as f64) => {}
        _ => return None,
    }
    // decodeBase64(obj.privKey): ToString coercion; undefined → "undefined" (invalid).
    let priv_key = m.get("privKey")?;
    decode_base64(&js_to_string(priv_key))
}

/// Outcome of `consumeStoredOPKPriv(keyId)` over the raw `opk:<keyId>` string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpkConsume {
    /// The entry is deleted whenever it was truthy — before decoding.
    pub delete_entry: bool,
    pub priv_key: Option<Vec<u8>>,
}

/// `consumeStoredOPKPriv(keyId)`.
pub fn consume_stored_opk_priv(raw: Option<&str>) -> OpkConsume {
    match raw.filter(|r| !r.is_empty()) {
        None => OpkConsume { delete_entry: false, priv_key: None },
        Some(raw) => OpkConsume { delete_entry: true, priv_key: decode_base64(raw) },
    }
}

// ───────── JS coercions the bootstrap path relies on ─────────
//
// Parsed with serde_json, not JSON.parse: lone-surrogate escapes, numbers
// out of f64 range (`1e400` → Infinity in JS) and nesting deeper than 128
// make serde fail where JS succeeds. None of these can be produced by the
// `JSON.stringify(StoredSPK)` that writes the entry. The coercions are
// `compat::js_value`'s `to_boolean`, `to_string_lenient_ties_up` and
// `to_number_lenient_ties_up_u128_radix`: KNOWN DIVERGENCES from JS on an
// exact decimal tie (Number→String rounds up), on `0x…` literals above 128
// bits (double rounding), and for an object with an own `toString` key
// (renders "[object Object]" where JS throws).

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn js_number_to_string_matches_spec() {
        for (x, s) in [
            (1234.0, "1234"),
            (12.5, "12.5"),
            (1e21, "1e+21"),
            (1.5e-7, "1.5e-7"),
            (1e-7, "1e-7"),
            (0.000001, "0.000001"),
            (123e20, "1.23e+22"),
            (1758800000000.0, "1758800000000"),
            (-0.5, "-0.5"),
            (0.1 + 0.2, "0.30000000000000004"),
        ] {
            assert_eq!(js_number_to_string(x), s);
        }
    }

    #[test]
    fn js_string_to_number_matches_spec() {
        for (s, x) in [
            ("", 0.0),
            ("  \n", 0.0),
            ("0x10", 16.0),
            ("0B101", 5.0),
            ("0o17", 15.0),
            ("1.", 1.0),
            (".5", 0.5),
            ("+.5", 0.5),
            ("-1e3", -1000.0),
            ("007", 7.0),
            ("1.e2", 100.0),
        ] {
            assert_eq!(js_string_to_number(s), x, "{s:?}");
        }
        for s in ["-0x10", "0x", "inf", "nan", "infinity", "1_000", ".", "1e", "e5", "1 2", "\u{85}1"] {
            assert!(js_string_to_number(s).is_nan(), "{s:?}");
        }
    }

    #[test]
    fn decode_base64_like_tweetnacl_util() {
        assert_eq!(decode_base64(""), Some(vec![]));
        assert_eq!(decode_base64("AB=="), Some(vec![0]));
        assert_eq!(decode_base64("AAB="), Some(vec![0, 0]));
        assert_eq!(decode_base64("null"), Some(vec![0x9e, 0xe9, 0x65]));
        for bad in ["A", "AB=", "A===", "====", "AB=C", "AA==AAAA", " AAA", "AA-_"] {
            assert_eq!(decode_base64(bad), None, "{bad:?}");
        }
    }
}

// ═════════════════════════ protocol v3: X3DH v2 (03-crypto §3.1) ═════════════════════════
//
// Strict, typed, network-free. Replaces the RN-compatible derivation above for
// every live session (build 349+); the functions above survive only for the
// `x3dh.json` golden vectors and the unchanged prekey bootstrap bookkeeping.
//
// ```text
// SPK signature = Ed25519(ED, "mrenzo-spk-v2" ‖ raw 32-byte SPK pub)
// DH1 = X25519(IK_A, SPK_B)  DH2 = X25519(EK_A, IK_B)  DH3 = X25519(EK_A, SPK_B)  DH4 = X25519(EK_A, OPK_B)
// any DHi == 0^32 → abort (low-order point)
// SK  = HKDF-SHA256(0^32, 0xFF^32 ‖ DH1 ‖ DH2 ‖ DH3 [‖ DH4], "mrenzo-x3dh-v2", 32)
// AD  = "mrenzo-ad-v3" ‖ IK_A ‖ ED_A ‖ IK_B ‖ ED_B            (initiator first)
// sid = HKDF-SHA256(0^32, SK, "mrenzo-ratchet-session-id-v3", 32)
// RK0 = HKDF-SHA256(0^32, SK, "mrenzo-ratchet-init-v3", 32)
// ```

use mrenzo_core::primitives::{ed25519_sign, KeyPair};

/// HKDF info of the v2 derivation.
pub const X3DH_INFO_V2: &str = "mrenzo-x3dh-v2";
/// Domain label in front of the raw SPK bytes under the v2 signature.
pub const SPK_SIG_LABEL_V2: &str = "mrenzo-spk-v2";
/// First bytes of the associated data of every v3 session.
pub const AD_LABEL_V3: &str = "mrenzo-ad-v3";
pub const SESSION_ID_INFO_V3: &str = "mrenzo-ratchet-session-id-v3";
pub const ROOT_INIT_INFO_V3: &str = "mrenzo-ratchet-init-v3";
/// `AD` length: 12 label bytes + 4 × 32 key bytes.
pub const AD_LEN_V3: usize = 12 + 128;

/// The prekey header `x` a v3 initiator attaches while its session is
/// `initiating` (03 §3.4): who we are, our ephemeral, the prekeys used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrekeyHeader {
    pub ik: [u8; 32],
    pub ed: [u8; 32],
    pub ek: [u8; 32],
    pub spk: i64,
    pub opk: Option<i64>,
}

/// The bundle half of `GET /api/x3dh/bundle/{uid}` (v3: no identity fields;
/// the identity is the caller's pin, never the bundle's).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BundleV2 {
    pub spk_id: i64,
    pub spk_pub: [u8; 32],
    pub spk_sig: [u8; 64],
    pub opk: Option<(i64, [u8; 32])>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X3dhV2Error {
    /// The SPK signature does not verify under the pinned ED (label v2).
    SpkSignature,
    /// A DH output was all-zero (low-order point).
    LowOrder,
    /// The header's identity is not the pinned identity of the sender.
    IdentityMismatch,
    /// A key id outside `[0, 2^53)`.
    BadKeyId,
}

impl std::fmt::Display for X3dhV2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            X3dhV2Error::SpkSignature => "spk-signature",
            X3dhV2Error::LowOrder => "low-order",
            X3dhV2Error::IdentityMismatch => "identity-mismatch",
            X3dhV2Error::BadKeyId => "bad-key-id",
        })
    }
}

impl std::error::Error for X3dhV2Error {}

/// SK → (AD, sid, RK0), shared by both sides.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X3dhV2Secret {
    pub sk: [u8; 32],
    pub ad: Vec<u8>,
    pub sid: [u8; 32],
    pub rk0: [u8; 32],
}

/// Initiator output: the secret, the ephemeral pair (it becomes the first
/// ratchet key), the header to attach and the DH3 the first chain comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X3dhV2Initiation {
    pub secret: X3dhV2Secret,
    pub ek: KeyPair,
    pub header: PrekeyHeader,
    pub spk_pub: [u8; 32],
    pub dh3: [u8; 32],
}

/// The bytes the v2 SPK signature covers: label ‖ raw 32 SPK bytes.
pub fn spk_signed_bytes_v2(spk_pub: &[u8; 32]) -> Vec<u8> {
    let mut m = SPK_SIG_LABEL_V2.as_bytes().to_vec();
    m.extend_from_slice(spk_pub);
    m
}

pub fn sign_spk_v2(ed_secret64: &[u8; 64], spk_pub: &[u8; 32]) -> [u8; 64] {
    ed25519_sign(ed_secret64, &spk_signed_bytes_v2(spk_pub))
}

/// Strict RFC 8032 verification (canonical S, no small-order key).
pub fn verify_spk_v2(ed_pub: &[u8; 32], spk_pub: &[u8; 32], sig: &[u8; 64]) -> bool {
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(ed_pub) else { return false };
    let sig = ed25519_dalek::Signature::from_bytes(sig);
    vk.verify_strict(&spk_signed_bytes_v2(spk_pub), &sig).is_ok()
}

/// A fresh SPK with the v2 signature (one 32-byte draw).
pub fn generate_signed_pre_key_v2(ed_secret64: &[u8; 64], key_id: i64, rng: &mut dyn Rng) -> GeneratedSignedPreKey {
    let kp = x25519_keypair(rng);
    let signature = sign_spk_v2(ed_secret64, &kp.public);
    GeneratedSignedPreKey { key_id, priv_key: b64(&kp.private), pub_key: b64(&kp.public), signature: b64(&signature) }
}

/// `"mrenzo-ad-v3" ‖ IK_A ‖ ED_A ‖ IK_B ‖ ED_B`.
pub fn associated_data_v3(ik_a: &[u8; 32], ed_a: &[u8; 32], ik_b: &[u8; 32], ed_b: &[u8; 32]) -> Vec<u8> {
    let mut ad = Vec::with_capacity(AD_LEN_V3);
    ad.extend_from_slice(AD_LABEL_V3.as_bytes());
    for k in [ik_a, ed_a, ik_b, ed_b] {
        ad.extend_from_slice(k);
    }
    ad
}

const MAX_KEY_ID: i64 = (1i64 << 53) - 1;

fn key_id_ok(id: i64) -> bool {
    (0..=MAX_KEY_ID).contains(&id)
}

fn dh_checked(k: &[u8; 32], p: &[u8; 32]) -> Result<[u8; 32], X3dhV2Error> {
    let out = x25519(k, p);
    if out.iter().fold(0u8, |a, b| a | b) == 0 {
        return Err(X3dhV2Error::LowOrder);
    }
    Ok(out)
}

fn secret_v2(dhs: &[&[u8; 32]], ad: Vec<u8>) -> X3dhV2Secret {
    let mut ikm = vec![0xffu8; 32];
    for d in dhs {
        ikm.extend_from_slice(*d);
    }
    let sk = hkdf32(&ikm, X3DH_INFO_V2.as_bytes());
    let sid = hkdf32(&sk, SESSION_ID_INFO_V3.as_bytes());
    let rk0 = hkdf32(&sk, ROOT_INIT_INFO_V3.as_bytes());
    X3dhV2Secret { sk, ad, sid, rk0 }
}

/// Initiator A → responder B. `peer_ik`/`peer_ed` are B's PINNED identity
/// (never taken from the bundle). Verifies the SPK signature first, then
/// draws exactly one 32-byte ephemeral.
pub fn x3dh_v2_initiate(
    my_ik: &KeyPair,
    my_ed_pub: &[u8; 32],
    peer_ik: &[u8; 32],
    peer_ed: &[u8; 32],
    bundle: &BundleV2,
    rng: &mut dyn Rng,
) -> Result<X3dhV2Initiation, X3dhV2Error> {
    if !key_id_ok(bundle.spk_id) || bundle.opk.is_some_and(|(id, _)| !key_id_ok(id)) {
        return Err(X3dhV2Error::BadKeyId);
    }
    if !verify_spk_v2(peer_ed, &bundle.spk_pub, &bundle.spk_sig) {
        return Err(X3dhV2Error::SpkSignature);
    }
    let ek = x25519_keypair(rng);
    let dh1 = dh_checked(&my_ik.private, &bundle.spk_pub)?;
    let dh2 = dh_checked(&ek.private, peer_ik)?;
    let dh3 = dh_checked(&ek.private, &bundle.spk_pub)?;
    let dh4 = match &bundle.opk {
        Some((_, opk)) => Some(dh_checked(&ek.private, opk)?),
        None => None,
    };
    let ad = associated_data_v3(&my_ik.public, my_ed_pub, peer_ik, peer_ed);
    let secret = match &dh4 {
        Some(d4) => secret_v2(&[&dh1, &dh2, &dh3, d4], ad),
        None => secret_v2(&[&dh1, &dh2, &dh3], ad),
    };
    let header = PrekeyHeader {
        ik: my_ik.public,
        ed: *my_ed_pub,
        ek: ek.public,
        spk: bundle.spk_id,
        opk: bundle.opk.map(|(id, _)| id),
    };
    Ok(X3dhV2Initiation { secret, ek, header, spk_pub: bundle.spk_pub, dh3 })
}

/// Responder side. `pinned_ik`/`pinned_ed` = the pin of the server-stamped
/// sender; the header MUST carry exactly that identity (checked before any
/// DH). `spk` is the SPK the header names (`spk:current` or `spk:old:<id>`),
/// `opk_priv` the consumed OPK when `header.opk` is set.
pub fn x3dh_v2_respond(
    my_ik: &KeyPair,
    my_ed_pub: &[u8; 32],
    spk: &KeyPair,
    opk_priv: Option<&[u8; 32]>,
    header: &PrekeyHeader,
    pinned_ik: &[u8; 32],
    pinned_ed: &[u8; 32],
) -> Result<X3dhV2Secret, X3dhV2Error> {
    let same = |a: &[u8; 32], b: &[u8; 32]| a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0;
    if !same(&header.ik, pinned_ik) || !same(&header.ed, pinned_ed) {
        return Err(X3dhV2Error::IdentityMismatch);
    }
    if !key_id_ok(header.spk) || header.opk.is_some_and(|id| !key_id_ok(id)) || header.opk.is_some() != opk_priv.is_some() {
        return Err(X3dhV2Error::BadKeyId);
    }
    let dh1 = dh_checked(&spk.private, &header.ik)?;
    let dh2 = dh_checked(&my_ik.private, &header.ek)?;
    let dh3 = dh_checked(&spk.private, &header.ek)?;
    let dh4 = match opk_priv {
        Some(opk) => Some(dh_checked(opk, &header.ek)?),
        None => None,
    };
    let ad = associated_data_v3(&header.ik, &header.ed, &my_ik.public, my_ed_pub);
    Ok(match &dh4 {
        Some(d4) => secret_v2(&[&dh1, &dh2, &dh3, d4], ad),
        None => secret_v2(&[&dh1, &dh2, &dh3], ad),
    })
}
