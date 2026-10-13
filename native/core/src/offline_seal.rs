//! Server at-rest offline seal (`OSB1:`) — port of the RN client's
//! `openSealedOffline` (`mobile/src/utils/crypto.ts:300-315`, build 324) and
//! of the two callers that consume its output (`mobile/src/App.tsx:1126-1145`
//! `p2p-pending-sealed`, `App.tsx:1621-1645` storage offline fetch), plus the
//! server-side construction (`internal/server/seal.go` `sealOfflineBlob`) so
//! the producer side can be replayed too.
//! Contract: docs/native/protocol/03-crypto.md §6; conformance:
//! docs/native/vectors/offlineSeal.json (tests/golden_offline_seal.rs).
//!
//! Wire format: `"OSB1:" + b64( ephemeralPub(32) || nonce(24) || box(pt) )`,
//! where `box` = tweetnacl `nacl.box` (tag16 || ct) to the recipient's X25519
//! identity key from the ephemeral secret. The ephemeral key comes FIRST — the
//! opposite of sealed sender's `nonce || ephemeralPub`.
//!
//! Faithful to the RN client INCLUDING its quirks, which must not be "fixed"
//! here (that would diverge from RN clients in the field):
//! - A string WITHOUT the exact, case-sensitive `"OSB1:"` prefix is legacy
//!   plaintext and is returned unchanged — no JSON validation, and the private
//!   key is not even looked at (an empty key still passes legacy blobs).
//! - EVERY failure of a marked blob is `None` (bad base64, < 72 bytes, bad key
//!   base64, key not 32 bytes, box auth failure, invalid UTF-8). Nothing throws.
//! - base64 is decoded with tweetnacl-util's `decodeBase64`: padding and the
//!   standard alphabet are required, but NON-CANONICAL trailing bits in the
//!   last quantum are ACCEPTED (`"AB=="` → `[0x00]`), because the regex only
//!   checks the shape and `atob`/`Buffer.from` discard the spare bits. The
//!   shared `primitives::b64d` rejects those strings, so this module decodes
//!   both the blob and the private key with `compat::b64`.
//! - Storage path: the private key is `(await loadPrivateKey()) || ''`; with no
//!   key every SEALED item fails to open and is ACKED + skipped (deleted from
//!   storage), relying on the WS replay copy.
//! - Storage path: `if (!payload.fromUserId)` is a JS FALSY test, so an inner
//!   `fromUserId` of `0`, `""`, `false` or `null` is overwritten by the outer one.
//! - Pending-sealed path: `__type` is stripped only when it is a string other
//!   than `"p2p-message"`; a `"p2p-message"` or non-string `__type` stays in the
//!   dispatched data, and `__type: ""` dispatches a message of type `""`.

use serde_json::Value;

use crate::compat::b64::tweetnacl_util_decode_base64 as decode_base64;
use crate::compat::js_value::to_boolean;
use crate::compat::utf8::tweetnacl_util_encode_utf8;
use crate::primitives::{b64, box_open, box_seal, x25519_keypair};
use crate::rng::Rng;

/// `OFFLINE_SEAL_MARKER` (crypto.ts:300) / `offlineSealMarker` (seal.go:28).
pub const OFFLINE_SEAL_MARKER: &str = "OSB1:";
/// `nacl.box.overheadLength` (Poly1305 tag).
pub const BOX_OVERHEAD_LENGTH: usize = 16;
/// `32 + 24 + nacl.box.overheadLength`: shortest decoded blob that is tried.
pub const MIN_SEALED_RAW_LEN: usize = 32 + 24 + BOX_OVERHEAD_LENGTH;

/// `isOfflineSealed` (seal.go:37) ≡ the client's `sealed.startsWith("OSB1:")`.
pub fn is_offline_sealed(s: &str) -> bool {
    s.starts_with(OFFLINE_SEAL_MARKER)
}

/// `openSealedOffline(sealed, x25519PrivB64)` (crypto.ts:301-315).
///
/// Legacy (unmarked) input comes back unchanged as `Some`; `None` is the TS
/// `null` ("marked but unopenable" — the caller skips/drops it).
pub fn open_sealed_offline(sealed: &str, x25519_priv_b64: &str) -> Option<String> {
    if !sealed.starts_with(OFFLINE_SEAL_MARKER) {
        return Some(sealed.to_owned()); // legacy plaintext
    }
    // try { … } catch { return null } — every throw below maps to None.
    let raw = decode_base64(&sealed[OFFLINE_SEAL_MARKER.len()..])?;
    if raw.len() < MIN_SEALED_RAW_LEN {
        return None;
    }
    let mut eph_pub = [0u8; 32];
    eph_pub.copy_from_slice(&raw[0..32]);
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&raw[32..56]);
    let ct = &raw[56..];
    // decodeBase64(x25519PrivB64) throws on bad encoding; nacl.box.open throws
    // 'bad secret key size' unless it is exactly 32 bytes.
    let priv_: [u8; 32] = decode_base64(x25519_priv_b64)?.try_into().ok()?;
    let opened = box_open(ct, &nonce, &eph_pub, &priv_)?; // if (!opened) return null
    // encodeUTF8 = decodeURIComponent(escape(..)): URIError on invalid UTF-8.
    tweetnacl_util_encode_utf8(opened)
}

/// Server construction (`sealOfflineBlob`, seal.go:53-76; mirrored in-test by
/// the vector generator). Draws exactly what the server does: 32 bytes for
/// the ephemeral X25519 secret (`box.GenerateKey`, raw/unclamped like
/// `nacl.box.keyPair()`), then 24 bytes of nonce. The Go function also
/// base64-decodes the recipient key (Go `StdEncoding`, which is lenient about
/// `\r`/`\n` and trailing bits) and errors unless it is 32 bytes; here the
/// caller passes the decoded key.
pub fn seal_offline_blob(blob: &[u8], recipient_pub: &[u8; 32], rng: &mut dyn Rng) -> String {
    let eph = x25519_keypair(rng);
    let mut nonce = [0u8; 24];
    rng.fill(&mut nonce);
    let ct = box_seal(blob, &nonce, recipient_pub, &eph.private);
    let mut out = Vec::with_capacity(32 + 24 + ct.len());
    out.extend_from_slice(&eph.public);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    format!("{OFFLINE_SEAL_MARKER}{}", b64(&out))
}

/// `JSON.parse`. Caveats vs JS (none reachable from the Go server's
/// `json.Marshal` output): serde_json rejects lone-surrogate `\u` escapes and
/// out-of-f64-range numbers, keeps integers exact where JS rounds to f64, and
/// keeps document key order where JS hoists integer-like keys. The parsed value
/// is dispatched locally, never re-serialised onto the wire.
fn json_parse(s: &str) -> Result<Value, &'static str> {
    serde_json::from_str(s).map_err(|_| "SyntaxError: JSON.parse")
}

/// Outcome of the `p2p-pending-sealed` WS handler (App.tsx:1126-1145).
#[derive(Clone, Debug, PartialEq)]
pub enum PendingSealed {
    /// `if (!blob) return;` — silently ignored.
    Ignored,
    /// No identity key (`!myPriv`): `pendingSealed.noPriv`, dropped.
    NoPriv,
    /// `openSealedOffline` returned null: `pendingSealed.unsealFailed`, dropped.
    UnsealFailed,
    /// A throw inside the handler's try: `pendingSealed.error`, dropped.
    Error(&'static str),
    /// `signaling.injectLocal({ type: msg_type, data })`.
    Dispatch { msg_type: String, data: Value },
}

/// `pendingSealedHandler(wsMsg)` with `ws_data` = `wsMsg.data` (`None` ≡
/// undefined) and `my_priv` = `useAuthStore.getState().privateKey`.
pub fn handle_pending_sealed(ws_data: Option<&Value>, my_priv: Option<&str>) -> PendingSealed {
    // const blob: string = wsMsg?.data?.blob;  (non-objects have no .blob)
    let blob = ws_data.and_then(|d| d.as_object()).and_then(|o| o.get("blob"));
    let blob = match blob {
        Some(b) if to_boolean(b) => b,
        _ => return PendingSealed::Ignored, // if (!blob) return;
    };
    let my_priv = match my_priv {
        Some(p) if !p.is_empty() => p,
        _ => return PendingSealed::NoPriv, // if (!myPriv) { warn; return; }
    };
    // The field is typed string but unchecked: a truthy non-string reaches
    // openSealedOffline and throws on `sealed.startsWith`.
    let Some(blob) = blob.as_str() else {
        return PendingSealed::Error("TypeError: sealed.startsWith is not a function");
    };
    let Some(opened) = open_sealed_offline(blob, my_priv) else {
        return PendingSealed::UnsealFailed;
    };
    let mut inner = match json_parse(&opened) {
        Ok(v) => v,
        Err(e) => return PendingSealed::Error(e),
    };
    if inner.is_null() {
        return PendingSealed::Error("TypeError: Cannot read property '__type' of null");
    }
    // typeof inner.__type === 'string' ? inner.__type : 'p2p-message'
    let msg_type = match inner.get("__type") {
        Some(Value::String(t)) => t.clone(),
        _ => "p2p-message".to_owned(),
    };
    if msg_type != "p2p-message" {
        // delete inner.__type (only reachable for an object with a string __type)
        if let Value::Object(o) = &mut inner {
            o.shift_remove("__type");
        }
    }
    PendingSealed::Dispatch { msg_type, data: inner }
}

/// Outcome of one item in `fetchAndProcessOfflineMessages` (App.tsx:1621-1650).
#[derive(Clone, Debug, PartialEq)]
pub enum OfflineItem {
    /// Sealed but unopenable: `offline.unsealFailed`, the storage id IS acked
    /// (the storage copy is deleted) and the item skipped.
    UnsealFailedAck,
    /// `handleIncomingP2P(payload, { sendDeliveryAck: false,
    /// isOfflineBacklog: true })`; the id is acked once that returns.
    Deliver(Value),
    /// A throw inside the per-item try: logged, NOT acked (refetched next time).
    Error(&'static str),
}

/// Per-item body of `fetchAndProcessOfflineMessages`. `encrypted_payload` =
/// `m.encryptedPayload`, `outer_from_user_id` = `m.fromUserId` (`None` ≡
/// undefined), `loaded_priv` = `await loadPrivateKey()` (the `|| ''` fallback
/// is applied here).
pub fn process_offline_item(
    encrypted_payload: &str,
    outer_from_user_id: Option<&Value>,
    loaded_priv: Option<&str>,
) -> OfflineItem {
    let my_priv = loaded_priv.unwrap_or(""); // (await loadPrivateKey()) || ''
    let Some(unsealed) = open_sealed_offline(encrypted_payload, my_priv) else {
        return OfflineItem::UnsealFailedAck;
    };
    let mut payload = match json_parse(&unsealed) {
        Ok(v) => v,
        Err(e) => return OfflineItem::Error(e),
    };
    // if (!payload.fromUserId) payload.fromUserId = m.fromUserId;
    match &mut payload {
        Value::Null => return OfflineItem::Error("TypeError: Cannot read property 'fromUserId' of null"),
        Value::Object(o) => {
            if !o.get("fromUserId").is_some_and(to_boolean) {
                match outer_from_user_id {
                    // Existing key keeps its position, a new one is appended.
                    Some(outer) => {
                        o.insert("fromUserId".to_owned(), outer.clone());
                    }
                    // `= undefined`: reads as absent.
                    None => {
                        o.shift_remove("fromUserId");
                    }
                }
            }
        }
        // Primitives: the RN bundle is sloppy-mode (@react-native/babel-preset
        // strictMode:false), so the property write is a silent no-op. Arrays
        // would get an expando property JSON cannot carry; left unchanged.
        _ => {}
    }
    OfflineItem::Deliver(payload)
}

#[cfg(test)]
mod tests {
    use super::decode_base64;

    #[test]
    fn decode_base64_matches_tweetnacl_util() {
        // Shape rules (validateBase64 regex).
        for bad in ["AAA", "AA", "-_8=", "AAAA\nAAAA", " AAAA", "AAAA=", "A===", "=", "AA=A", "AAAA===="] {
            assert_eq!(decode_base64(bad), None, "{bad:?}");
        }
        assert_eq!(decode_base64(""), Some(vec![]));
        assert_eq!(decode_base64("+/8="), Some(vec![0xfb, 0xff]));
        // Non-canonical trailing bits are accepted (node: tweetnacl-util).
        assert_eq!(decode_base64("AB=="), Some(vec![0x00]));
        assert_eq!(decode_base64("AAB="), Some(vec![0x00, 0x00]));
        assert_eq!(decode_base64("QR=="), Some(vec![0x41]));
    }
}
