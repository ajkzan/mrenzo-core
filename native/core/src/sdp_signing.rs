//! Call SDP / DTLS-fingerprint signing, payload v2 (03-crypto §7, 02 §9;
//! build 349). Conformance: docs/native/vectors/sdpSigningV2.json
//! (tests/golden_sdp_signing_v2.rs).
//!
//! ```text
//! payload = fp + "|" + ts + "|" + nonce + "|" + fromUserId + "|" + toUserId + "|" + callId + "|" + type + "|2"
//! sig     = Ed25519(ED_signer, UTF-8(payload))
//! rb      = b64(HKDF-SHA256(0^32, sid, "mrenzo-ratchet-bind-v2|" + payload, 32))
//! ```
//!
//! `toUserId` and `type` stop reflection (a captured offer cannot be replayed
//! to a third party or as an answer), `callId` binds it to one call, and the
//! mandatory `rb` binds it to an authenticated 1:1 session between exactly
//! these two users: a server that swaps the signing key in its
//! directory cannot produce `rb`. Group rooms have no 1:1 session: they sign
//! with `toUserId = callId = roomId` and verify the signature only.
//!
//! The verifier never fetches a key: the signing key is the caller's PINNED
//! one; a failure fails the call and the caller schedules a directory
//! reconcile out of band (03 §5.7).

use serde_json::{json, Map, Value};

use crate::compat::js_string::{cmp_code_units, js_trim};
use crate::primitives::{b64, ed25519_sign};
use crate::ratchet::{b64_strict, session_binding_mac};
use crate::rng::Rng;

/// Exact, case-sensitive line prefix the fingerprint extraction collects.
pub const FINGERPRINT_PREFIX: &str = "a=fingerprint:";
pub const SDP_NONCE_BYTES: usize = 16;
/// `|now − ts| ≤ 60 000 ms`.
pub const SDP_TS_WINDOW_MS: i64 = 60_000;
pub const SDP_PAYLOAD_VERSION: i64 = 2;

/// The canonical fingerprint: every `a=fingerprint:` line (split on `\n`,
/// one trailing `\r` dropped), trimmed, lowercased, de-duplicated, sorted in
/// UTF-16 code-unit order and joined by `|`; "" when there is none (the call
/// must then be refused).
pub fn extract_sdp_fingerprints(sdp: &str) -> String {
    let mut fps: Vec<String> = sdp
        .split('\n')
        .map(|l| l.strip_suffix('\r').unwrap_or(l))
        .filter(|l| l.starts_with(FINGERPRINT_PREFIX))
        .map(|l| js_trim(l).to_lowercase())
        .collect();
    fps.sort_by(|a, b| cmp_code_units(a, b));
    fps.dedup();
    fps.join("|")
}

pub fn payload_v2(fingerprints: &str, ts: i64, nonce: &str, from: i64, to: &str, call_id: &str, sdp_type: &str) -> String {
    format!("{fingerprints}|{ts}|{nonce}|{from}|{to}|{call_id}|{sdp_type}|{SDP_PAYLOAD_VERSION}")
}

/// What a signer puts next to `type`/`sdp`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedSdpV2 {
    pub sig: String,
    pub ts: i64,
    pub nonce: String,
    pub from_user_id: i64,
    pub rb: Option<String>,
}

/// Signs `sdp` (`None` when it carries no fingerprint; no randomness drawn
/// then). `sid` = the live session id with the peer (1:1 calls: required by
/// the verifier; rooms: `None`).
#[allow(clippy::too_many_arguments)]
pub fn sign_sdp_v2(
    sdp: &str,
    sdp_type: &str,
    ed_secret64: &[u8; 64],
    from: i64,
    to: &str,
    call_id: &str,
    sid: Option<&[u8; 32]>,
    now_ms: i64,
    rng: &mut dyn Rng,
) -> Option<SignedSdpV2> {
    let fp = extract_sdp_fingerprints(sdp);
    if fp.is_empty() {
        return None;
    }
    let mut n = [0u8; SDP_NONCE_BYTES];
    rng.fill(&mut n);
    let nonce = b64(&n);
    let payload = payload_v2(&fp, now_ms, &nonce, from, to, call_id, sdp_type);
    let sig = b64(&ed25519_sign(ed_secret64, payload.as_bytes()));
    let rb = sid.map(|s| session_binding_mac(s, &payload));
    Some(SignedSdpV2 { sig, ts: now_ms, nonce, from_user_id: from, rb })
}

/// The `data` object of a signed offer/answer:
/// `{type, sdp, sig, ts, nonce, fromUserId, toUserId, callId, pv:2[, rb]}`.
/// `to` is a uid (1:1) or the room id (rooms, sent as a string).
pub fn sdp_wire_data_v2(sdp_type: &str, sdp: &str, s: &SignedSdpV2, to: &str, call_id: &str) -> Value {
    let mut o = Map::new();
    o.insert("type".into(), json!(sdp_type));
    o.insert("sdp".into(), json!(sdp));
    o.insert("sig".into(), json!(s.sig));
    o.insert("ts".into(), json!(s.ts));
    o.insert("nonce".into(), json!(s.nonce));
    o.insert("fromUserId".into(), json!(s.from_user_id));
    o.insert("toUserId".into(), to.parse::<i64>().map(Value::from).unwrap_or_else(|_| Value::String(to.into())));
    o.insert("callId".into(), json!(call_id));
    o.insert("pv".into(), json!(SDP_PAYLOAD_VERSION));
    if let Some(rb) = &s.rb {
        o.insert("rb".into(), json!(rb));
    }
    Value::Object(o)
}

/// What the receiver expects of this frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SdpExpectV2 {
    /// The peer this call is with (server-stamped / mapped uid).
    pub from: i64,
    /// Us: our uid (1:1) or the room id (rooms).
    pub to: String,
    /// `offer` or `answer` — the frame type it arrived as.
    pub sdp_type: String,
    pub call_id: String,
    /// 1:1 calls: `rb` must match one of `sessions`.
    pub require_rb: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RbCheckV2 {
    /// Rooms: not checked.
    NotRequired,
    /// Matched `sessions[index]` (0 = live, then archived newest first).
    Match { index: usize },
    Missing,
    NoSession,
    Mismatch,
    /// An earlier gate failed.
    NotReached,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SdpVerificationV2 {
    pub ok: bool,
    /// `ok`, `missing-fields`, `pv`, `userId-mismatch`, `to-mismatch`,
    /// `type-mismatch`, `callId-mismatch`, `ts-skew`, `no-fingerprint-in-sdp`,
    /// `peer-signing-key-unavailable`, `signature-mismatch`, `rb-missing`,
    /// `rb-no-session`, `rb-mismatch`.
    pub reason: String,
    pub rb: RbCheckV2,
}

fn fail(reason: &str) -> SdpVerificationV2 {
    SdpVerificationV2 { ok: false, reason: reason.into(), rb: RbCheckV2::NotReached }
}

/// A JSON integer or string rendered as the payload renders it.
fn id_text(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::Number(n) => n.as_i64().map(|i| i.to_string()),
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

/// Verifies one offer/answer `data` object. `peer_ed` = the pinned,
/// confirmed signing key of `expect.from` (`None` → unavailable);
/// `sessions` = the session ids with that peer, live first.
pub fn verify_sdp_v2(data: &Value, expect: &SdpExpectV2, peer_ed: Option<&[u8; 32]>, sessions: &[[u8; 32]], now_ms: i64) -> SdpVerificationV2 {
    let Some(o) = data.as_object() else { return fail("missing-fields") };
    let s = |k: &str| o.get(k).and_then(Value::as_str);
    let (Some(sdp_type), Some(sdp), Some(sig), Some(nonce), Some(call_id)) = (s("type"), s("sdp"), s("sig"), s("nonce"), s("callId")) else {
        return fail("missing-fields");
    };
    let (Some(ts), Some(from), Some(to)) = (o.get("ts").and_then(Value::as_i64), o.get("fromUserId").and_then(Value::as_i64), id_text(o.get("toUserId")))
    else {
        return fail("missing-fields");
    };
    if o.get("pv").and_then(Value::as_i64) != Some(SDP_PAYLOAD_VERSION) {
        return fail("pv");
    }
    if from != expect.from {
        return fail("userId-mismatch");
    }
    if to != expect.to {
        return fail("to-mismatch");
    }
    if sdp_type != expect.sdp_type {
        return fail("type-mismatch");
    }
    if call_id != expect.call_id {
        return fail("callId-mismatch");
    }
    // `abs_diff`: `ts` comes from the wire, and `(now − ts).abs()` overflows
    // for `ts` near `i64::MIN` (a wrapped negative difference passes the window).
    if now_ms.abs_diff(ts) > SDP_TS_WINDOW_MS as u64 {
        return fail("ts-skew");
    }
    let fp = extract_sdp_fingerprints(sdp);
    if fp.is_empty() {
        return fail("no-fingerprint-in-sdp");
    }
    let Some(peer_ed) = peer_ed else { return fail("peer-signing-key-unavailable") };
    let payload = payload_v2(&fp, ts, nonce, from, &to, call_id, sdp_type);
    let sig_ok = b64_strict(sig)
        .and_then(|b| <[u8; 64]>::try_from(b).ok())
        .zip(ed25519_dalek::VerifyingKey::from_bytes(peer_ed).ok())
        .is_some_and(|(sig, vk)| vk.verify_strict(payload.as_bytes(), &ed25519_dalek::Signature::from_bytes(&sig)).is_ok());
    if !sig_ok {
        return fail("signature-mismatch");
    }
    if !expect.require_rb {
        return SdpVerificationV2 { ok: true, reason: "ok".into(), rb: RbCheckV2::NotRequired };
    }
    let Some(rb) = s("rb").filter(|r| !r.is_empty()) else {
        return SdpVerificationV2 { ok: false, reason: "rb-missing".into(), rb: RbCheckV2::Missing };
    };
    if sessions.is_empty() {
        return SdpVerificationV2 { ok: false, reason: "rb-no-session".into(), rb: RbCheckV2::NoSession };
    }
    for (index, sid) in sessions.iter().enumerate() {
        let expected = session_binding_mac(sid, &payload);
        if expected.len() == rb.len() && expected.bytes().zip(rb.bytes()).fold(0u8, |d, (a, b)| d | (a ^ b)) == 0 {
            return SdpVerificationV2 { ok: true, reason: "ok".into(), rb: RbCheckV2::Match { index } };
        }
    }
    SdpVerificationV2 { ok: false, reason: "rb-mismatch".into(), rb: RbCheckV2::Mismatch }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SdpKind {
    Offer,
    Answer,
}

impl SdpKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SdpKind::Offer => "offer",
            SdpKind::Answer => "answer",
        }
    }
}

/// 1:1 call frame: `{"type":"call-offer"|"call-answer","data":{...data}}`
/// (`callId` is already in the signed data).
pub fn call_sdp_frame(kind: SdpKind, data: &Value) -> Value {
    json!({ "type": format!("call-{}", kind.as_str()), "data": data })
}

/// Room frame: `{"type":"offer"|"answer","to":<peerId>,"data":data}`.
pub fn room_sdp_frame(kind: SdpKind, to_peer_id: &str, data: &Value) -> Value {
    json!({ "type": kind.as_str(), "to": to_peer_id, "data": data })
}

/// The duplicate-guard key `"<kind>:<ts>:<nonce>"`; `None` without an SDP,
/// a numeric `ts` or a non-empty `nonce`.
pub fn sdp_seen_key(kind: SdpKind, payload: &Value) -> Option<String> {
    let sdp = payload.get("sdp").and_then(Value::as_str).filter(|s| !s.is_empty())?;
    let _ = sdp;
    let ts = payload.get("ts").and_then(Value::as_i64)?;
    let nonce = payload.get("nonce").and_then(Value::as_str).filter(|n| !n.is_empty())?;
    Some(format!("{}:{ts}:{nonce}", kind.as_str()))
}
