//! Key-publish self-signature — line-for-line port of
//! `mobile/src/services/api.ts:710-745` (`uploadPublicKey`) and the two
//! `mobile/src/utils/crypto.ts` helpers on its path (`signPayload` :536-541,
//! `verifyPayload` :548-564; build 324), plus a mirror of the storage server's
//! acceptance check (`storage/app/routes_keys.py:16,64-79`).
//! Contract: docs/native/protocol/01-rest-api.md §5.2 and 03-crypto.md §2.2;
//! conformance: docs/native/vectors/keyPublish.json (tests/golden_key_publish.rs).
//!
//! ```text
//! POST <STORAGE_BASE>/api/keys/publish
//! canonical = `${publicKey}|${signingPublicKey}|${uid}|${ts}`   (UTF-8)
//! body      = JSON.stringify({publicKey, signingPublicKey, ts: String(ts),
//!                             signature: b64(Ed25519(canonical, signingSecret64))})
//! ```
//!
//! Faithful to the RN client INCLUDING its quirks, which must not be "fixed"
//! here (that would break interop with RN clients / the server in the field):
//! - `ts` is a decimal STRING in the body; the signed text uses the same digits.
//! - A falsy `signingPublicKey` (absent OR `""`) is omitted from the body and
//!   nothing is signed. Signing also needs a truthy signing private key and a
//!   truthy uid — uid `0` publishes unsigned.
//! - `body.ts` is assigned BEFORE `signPayload` runs. When `signPayload`
//!   throws (private key not valid base64, or not 64 bytes) the `catch` keeps
//!   `ts` and the body goes out as `{publicKey, signingPublicKey, ts}` with NO
//!   `signature` — which the server accepts as an unsigned publish.
//! - The client never checks that the stored private key belongs to
//!   `signingPublicKey`; it signs with whatever it holds (the server 401s).
//! - tweetnacl signs with the stored 64-byte secret's PUB HALF (`sk[32..64]`)
//!   inside `H(R‖A‖M)`, not a key re-derived from the seed. A secret whose
//!   halves disagree yields the same `R` but a different `S`.
//!   `primitives::ed25519_sign` re-derives `A`, hence
//!   `compat::ed25519::tweetnacl_sign_detached` (via `crypto_ts::sign_payload`).
//! - tweetnacl's verify accepts a non-reduced `S` (the `S+L` malleation),
//!   small-order public keys (e.g. the identity key, in any encoding) and a
//!   small-order `R`; `primitives::ed25519_verify` rejects `S ≥ L`, so
//!   `compat::ed25519` reduces `S` mod L before calling it (dalek's
//!   non-strict equation then matches tweetnacl's cofactorless,
//!   byte-compared one).
//! - tweetnacl-util `decodeBase64` (strict padded regex, then `atob`) DISCARDS
//!   non-zero trailing bits: `…z46h==` decodes like `…z46g==`.
//!   `primitives::b64d` rejects those; `compat::b64` is the RN decoder.
//!
//! Server mirror ([`server_check_publish_signature`]) is NOT the client's
//! verifier, and is stricter/looser in different places: Python's
//! `base64.b64decode` is lenient (drops non-alphabet characters, stops at the
//! first completing pad, ignores anything after it), while PyNaCl/libsodium
//! verification is strict (rejects `S ≥ L`, small-order `A`/`R`, non-canonical
//! `A`). The freshness window is inclusive: `|now − ts| == 300000` passes.

use serde_json::{Map, Value};

use crate::crypto_ts::{self, SignPayloadError};

/// Storage-service route (`${STORAGE_BASE}/api/keys/publish`).
pub const PUBLISH_PATH: &str = "/api/keys/publish";
/// HTTP method of the publish.
pub const PUBLISH_METHOD: &str = "POST";
/// `SIG_MAX_AGE_MS` (routes_keys.py:16): replay window of the publish signature.
pub const SIG_MAX_AGE_MS: i64 = 5 * 60 * 1000;

/// The request `uploadPublicKey` hands to `request()` (which adds
/// `Content-Type: application/json` and the Bearer token).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishRequest {
    pub method: &'static str,
    pub path: &'static str,
    /// Exact `JSON.stringify(body)` string.
    pub body_json: String,
}

/// What `uploadPublicKey` reads from `useAuthStore.getState()`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AuthSnapshot<'a> {
    /// `st.signingPrivateKey`: b64 of tweetnacl's 64-byte secret (seed ‖ pub).
    pub signing_private_key: Option<&'a str>,
    /// `st.user?.id`.
    pub uid: Option<i64>,
}

/// `signPayload` failures — the TS throws; message text is identical.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignError {
    /// `decodeBase64` → `TypeError('invalid encoding')`.
    InvalidEncoding,
    /// `nacl.sign.detached` → `Error('bad secret key size')` (not 64 bytes).
    BadSecretKeySize,
}

impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignError::InvalidEncoding => write!(f, "invalid encoding"),
            SignError::BadSecretKeySize => write!(f, "bad secret key size"),
        }
    }
}

impl std::error::Error for SignError {}

/// `` `${publicKey}|${signingPublicKey}|${uid}|${ts}` `` (api.ts:733).
pub fn publish_canonical(public_key: &str, signing_public_key: &str, uid: i64, ts: i64) -> String {
    format!("{public_key}|{signing_public_key}|{uid}|{ts}")
}

/// `uploadPublicKey(publicKey, signingPublicKey?)` (api.ts:714-745), minus the
/// network call. `now_ms` is the `Date.now()` the TS reads.
pub fn upload_public_key_request(
    public_key: &str,
    signing_public_key: Option<&str>,
    auth: AuthSnapshot<'_>,
    now_ms: i64,
) -> PublishRequest {
    // const body: Record<string, string> = { publicKey };
    let mut body = Map::new();
    body.insert("publicKey".into(), Value::String(public_key.to_owned()));
    // if (signingPublicKey) body.signingPublicKey = signingPublicKey;
    let signing_public_key = signing_public_key.filter(|s| !s.is_empty());
    if let Some(spk) = signing_public_key {
        body.insert("signingPublicKey".into(), Value::String(spk.to_owned()));
    }
    // try { … if (signPriv && signingPublicKey && uid) { … } } catch {}
    let sign_priv = auth.signing_private_key.filter(|s| !s.is_empty());
    let uid = auth.uid.filter(|&u| u != 0);
    if let (Some(sign_priv), Some(spk), Some(uid)) = (sign_priv, signing_public_key, uid) {
        let ts = now_ms;
        let canonical = publish_canonical(public_key, spk, uid, ts);
        // body.ts is set BEFORE signPayload can throw — it survives the catch.
        body.insert("ts".into(), Value::String(ts.to_string()));
        if let Ok(signature) = sign_payload(&canonical, sign_priv) {
            body.insert("signature".into(), Value::String(signature));
        }
    }
    PublishRequest {
        method: PUBLISH_METHOD,
        path: PUBLISH_PATH,
        body_json: serde_json::to_string(&Value::Object(body)).expect("string map serializes"),
    }
}

/// `signPayload(payloadUtf8, privateKeyB64)` (crypto.ts:536-541), with
/// tweetnacl's signer ([`crypto_ts::sign_payload`]).
pub fn sign_payload(payload_utf8: &str, private_key_b64: &str) -> Result<String, SignError> {
    crypto_ts::sign_payload(payload_utf8, private_key_b64).map_err(|e| match e {
        SignPayloadError::InvalidEncoding => SignError::InvalidEncoding,
        SignPayloadError::BadSecretKeySize => SignError::BadSecretKeySize,
    })
}

/// `verifyPayload(payloadUtf8, signatureB64, publicKeyB64)` (crypto.ts:548-564).
/// Never throws: every malformation is `false`.
pub fn verify_payload(payload_utf8: &str, signature_b64: &str, public_key_b64: &str) -> bool {
    crypto_ts::verify_payload(payload_utf8, signature_b64, public_key_b64)
}

// ───────── storage server mirror (routes_keys.py:64-79) ─────────

/// Outcome of the server's signature gate when it does not reject.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerSignatureCheck {
    /// `signature` absent or `signingPublicKey` falsy: nothing is verified
    /// (rollout grace — `ts` is then ignored entirely).
    Unchecked,
    Verified,
}

/// The server's rejections from this gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerRejection {
    /// 400 `{"detail":"stale publish signature"}` (ts missing or outside ±5 min).
    StalePublishSignature,
    /// 401 `{"detail":"key publish signature invalid"}` (any decode/verify error).
    SignatureInvalid,
}

impl ServerRejection {
    pub fn status(self) -> u16 {
        match self {
            ServerRejection::StalePublishSignature => 400,
            ServerRejection::SignatureInvalid => 401,
        }
    }

    pub fn detail(self) -> &'static str {
        match self {
            ServerRejection::StalePublishSignature => "stale publish signature",
            ServerRejection::SignatureInvalid => "key publish signature invalid",
        }
    }
}

/// The signature gate of `publish_public_key` (routes_keys.py:64-79).
///
/// `ts` is the value AFTER pydantic's `Optional[int]` coercion (the RN body
/// carries it as a decimal string); `jwt_user_id` is the authenticated user id
/// (the server never reads a uid from the body); `now_ms` is
/// `int(time.time() * 1000)`.
pub fn server_check_publish_signature(
    public_key: &str,
    signing_public_key: Option<&str>,
    signature: Option<&str>,
    ts: Option<i64>,
    jwt_user_id: i64,
    now_ms: i64,
) -> Result<ServerSignatureCheck, ServerRejection> {
    // if req.signature is not None and req.signingPublicKey:
    let (Some(signature), Some(spk)) = (signature, signing_public_key.filter(|s| !s.is_empty())) else {
        return Ok(ServerSignatureCheck::Unchecked);
    };
    // if req.ts is None or abs(now_ms - req.ts) > SIG_MAX_AGE_MS: 400
    let Some(ts) = ts else { return Err(ServerRejection::StalePublishSignature) };
    if (now_ms as i128 - ts as i128).abs() > SIG_MAX_AGE_MS as i128 {
        return Err(ServerRejection::StalePublishSignature);
    }
    // canonical = f"{req.publicKey}|{req.signingPublicKey}|{user.user_id}|{req.ts}".encode()
    let canonical = publish_canonical(public_key, spk, jwt_user_id, ts);
    // VerifyKey(b64decode(spk)).verify(canonical, b64decode(sig)); any exception → 401
    let key = server_b64decode(spk).ok_or(ServerRejection::SignatureInvalid)?;
    let key: [u8; 32] = key.try_into().map_err(|_| ServerRejection::SignatureInvalid)?;
    let sig = server_b64decode(signature).ok_or(ServerRejection::SignatureInvalid)?;
    let sig: [u8; 64] = sig.try_into().map_err(|_| ServerRejection::SignatureInvalid)?;
    if libsodium_verify_detached(&sig, canonical.as_bytes(), &key) {
        Ok(ServerSignatureCheck::Verified)
    } else {
        Err(ServerRejection::SignatureInvalid)
    }
}

/// Python 3.12 `base64.b64decode(s)` (validate=False → non-strict
/// `binascii.a2b_base64`) as the storage server runs it. `None` ≡ it raises.
/// Non-ASCII input raises; any other non-alphabet byte is skipped; `=` only
/// counts once two data characters of the quad are in, and a completing pad
/// ends decoding (the rest of the input is ignored); a dangling 1 data
/// character or an unpadded 2/3-character tail raises. Trailing bits are
/// discarded.
pub fn server_b64decode(s: &str) -> Option<Vec<u8>> {
    if !s.is_ascii() {
        return None; // "string argument should contain only ASCII characters"
    }
    let mut out = Vec::with_capacity(s.len() / 4 * 3 + 3);
    let mut quad_pos: u32 = 0;
    let mut leftchar: u8 = 0;
    let mut pads: u32 = 0;
    for &ch in s.as_bytes() {
        if ch == b'=' {
            if quad_pos >= 2 {
                pads += 1;
                if quad_pos + pads >= 4 {
                    return Some(out); // goto done
                }
            }
            continue;
        }
        let Some(v) = b64_value(ch) else { continue };
        pads = 0;
        match quad_pos {
            0 => {
                quad_pos = 1;
                leftchar = v;
            }
            1 => {
                quad_pos = 2;
                out.push((leftchar << 2) | (v >> 4));
                leftchar = v & 0x0f;
            }
            2 => {
                quad_pos = 3;
                out.push((leftchar << 4) | (v >> 2));
                leftchar = v & 0x03;
            }
            _ => {
                quad_pos = 0;
                out.push((leftchar << 6) | v);
                leftchar = 0;
            }
        }
    }
    if quad_pos != 0 {
        return None; // "Incorrect padding" / "cannot be 1 more than a multiple of 4"
    }
    Some(out)
}

fn b64_value(ch: u8) -> Option<u8> {
    match ch {
        b'A'..=b'Z' => Some(ch - b'A'),
        b'a'..=b'z' => Some(ch - b'a' + 26),
        b'0'..=b'9' => Some(ch - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// libsodium `crypto_sign_ed25519_verify_detached` (non-COMPAT build, as
/// bundled by PyNaCl): canonical `S`, `R`/`A` not of small order, `A`
/// canonically encoded, cofactorless equation checked on the `R` encoding.
fn libsodium_verify_detached(sig: &[u8; 64], msg: &[u8], pk: &[u8; 32]) -> bool {
    if !ge25519_is_canonical(pk) {
        return false;
    }
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(pk) else { return false };
    let sig = ed25519_dalek::Signature::from_bytes(sig);
    vk.verify_strict(msg, &sig).is_ok()
}

/// libsodium `ge25519_is_canonical`: false iff the y encoding is ≥ p.
fn ge25519_is_canonical(s: &[u8; 32]) -> bool {
    let top = (s[31] & 0x7f) == 0x7f;
    let middle = s[1..31].iter().all(|&b| b == 0xff);
    !(top && middle && s[0] >= 0xed)
}
