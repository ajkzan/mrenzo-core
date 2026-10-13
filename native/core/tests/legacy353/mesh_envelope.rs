//! Offline-mesh envelope, wire v2 (04-mesh.md; build 349). Conformance:
//! docs/native/vectors/meshV2.json (tests/golden_mesh_v2.rs).
//!
//! Layers:
//! - logical [`MeshEnvelope`] (also the at-rest shape of the pigeon queue);
//! - outer JSON frame `{"v":2,"id","ttl","hops","L"?,"mode","ts","b"}` ([`MeshOuter`]);
//! - inner binary blob `flags | sig_pub | from u64 | [to u64] | [toIdx 8] |
//!   len u16 | payload | sig` ([`encode_inner_blob`] / [`decode_inner_blob`]).
//!
//! Binding v2 (MESH-1): the Ed25519 signature of `from` covers EVERY field
//! the originator sets — a relay may only increment `hops`:
//!
//! ```text
//! "mrenzo-mesh-v2|" + id + "|" + ts + "|" + from.uid + "|" + to + "|" + (toIdx or "-") + "|"
//!   + ttl + "|" + (L or "-") + "|" + mode + "|" + kind + "|" + payload          kind ∈ {msg, ack}
//! ```
//!
//! Numbers are integers in `[0, 2^53)` rendered in decimal; a frame with any
//! other number is rejected. `v:1` frames are dropped at verification. Who
//! may sign for `from.uid` is the receiver's decision (its pinned signing
//! key, 04 §9.2): the signature alone proves only that the embedded `sig_pub`
//! signed it. The msg payload is a padded v3 ratchet envelope; the ACK payload
//! is `id + "." + tag` ([`crate::legacy353::ratchet::mesh_ack_payload`]).

use serde_json::Value;

use crate::legacy353::compat::b64::tweetnacl_util_decode_base64;
use crate::legacy353::compat::ed25519::tweetnacl_sign_detached_verify;
use crate::legacy353::compat::js_number::{
    number_to_bigint_u64, number_to_json_ties_up as js_json_number, to_uint32,
};
use crate::legacy353::compat::js_value::to_boolean as js_truthy;
use crate::legacy353::compat::json::{json_quote as json_str, stringify_ties_up as js_stringify};
use crate::legacy353::compat::utf8::whatwg_text_decode as text_decode;
use crate::legacy353::crypto_ts::{self, SignPayloadError};
use mrenzo_core::primitives::{b64, box_before, secure_uuid, sha512};
use mrenzo_core::rng::Rng;

// ───────── constants (meshCrypto.ts) ─────────

pub const TO_IDX_BYTES: usize = 8;
pub const TO_IDX_EPOCH_MS: f64 = 3_600_000.0;
pub const MESH_WIRE_VERSION: i64 = 2;
/// Domain label of the v2 binding.
pub const MESH_BINDING_LABEL: &str = "mrenzo-mesh-v2";
/// Realtime hop budget for a chat message.
pub const REALTIME_TTL: i64 = 7;
/// Hop budget of an ACK (Spray-and-Wait prune).
pub const PRUNE_TTL: i64 = 4;
/// Discovery beacon budget (exported by the TS module; unused by this port).
pub const DISCOVERY_TTL: i64 = 3;
/// Pigeon `ttl` is SECONDS, not hops (same field, two units).
pub const PIGEON_TTL_SECONDS: i64 = 24 * 60 * 60;
/// Binary Spray-and-Wait copy bound at the source.
pub const SPRAY_INITIAL_L: i64 = 4;

const SIG_PUB_LEN: usize = 32;
const UID_LEN: usize = 8;
const TO_IDX_LEN: usize = TO_IDX_BYTES;
const PAY_LEN_LEN: usize = 2;
const SIG_LEN: usize = 64;

pub const FLAG_PADDED: u8 = 0x01;
pub const FLAG_HAS_TO_IDX: u8 = 0x02;
pub const FLAG_HAS_TO: u8 = 0x04;
pub const FLAG_KIND_ACK: u8 = 0x08;

const PAD_BUCKETS: [usize; 4] = [256, 512, 1024, 2048];

// ───────── errors (the places the TS code THROWS instead of returning null) ─────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeshError {
    /// tweetnacl-util `decodeBase64` → `TypeError('invalid encoding')`.
    InvalidEncoding,
    /// `BigInt(x)` on a non-integer number → RangeError.
    NotAnInteger,
    /// tweetnacl `nacl.sign.detached` → `Error('bad secret key size')`.
    BadSecretKeySize,
}

impl std::fmt::Display for MeshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MeshError::InvalidEncoding => write!(f, "invalid encoding"),
            MeshError::NotAnInteger => write!(f, "cannot be converted to a BigInt because it is not an integer"),
            MeshError::BadSecretKeySize => write!(f, "bad secret key size"),
        }
    }
}

impl std::error::Error for MeshError {}

/// tweetnacl-util 0.15 `decodeBase64(s)` (`compat::b64`): the
/// `validateBase64` regex (standard alphabet, length ≡ 0 mod 4, canonical
/// padding), then `atob(s)`, which ignores the trailing bits. `None` where it
/// throws `TypeError('invalid encoding')`.
pub fn nacl_b64d(s: &str) -> Option<Vec<u8>> {
    tweetnacl_util_decode_base64(s)
}

fn b64d_throw(s: &str) -> Result<Vec<u8>, MeshError> {
    nacl_b64d(s).ok_or(MeshError::InvalidEncoding)
}

// ───────── model ─────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MeshMode {
    Realtime,
    Pigeon,
}

impl MeshMode {
    pub fn as_str(self) -> &'static str {
        match self {
            MeshMode::Realtime => "realtime",
            MeshMode::Pigeon => "pigeon",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MeshKind {
    Msg,
    Ack,
}

impl MeshKind {
    pub fn as_str(self) -> &'static str {
        match self {
            MeshKind::Msg => "msg",
            MeshKind::Ack => "ack",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct MeshFrom {
    /// JS number (see module docs).
    pub uid: f64,
    /// base64 Ed25519 public key (canonical on the binary path).
    pub sig_pub: String,
}

/// `MeshEnvelope` (meshCrypto.ts:408-452). `None` = the JS property is
/// `undefined` (dropped by `JSON.stringify`).
#[derive(Clone, Debug, PartialEq)]
pub struct MeshEnvelope {
    /// Always 1 for anything built here; `unpackMeshOuter` keeps any truthy
    /// outer `v` verbatim (`outer.v || 1`), hence a JSON value.
    pub v: Value,
    pub id: String,
    pub ts: f64,
    pub ttl: f64,
    pub hops: f64,
    pub mode: MeshMode,
    pub from: MeshFrom,
    pub to: f64,
    pub to_idx: Option<String>,
    /// msg: base64 of the padded bytes; ack: the acked message id (raw).
    pub payload: String,
    pub sig: String,
    /// `L` — Spray-and-Wait copy budget.
    pub l: Option<f64>,
    pub padded: Option<bool>,
    /// Absent means msg (built msg envelopes omit it; the decoder always sets it).
    pub kind: Option<MeshKind>,
}

/// `MeshIdentity` (meshCrypto.ts:461-465).
#[derive(Clone, Debug, PartialEq)]
pub struct MeshIdentity {
    pub from_uid: i64,
    /// base64 of tweetnacl's 64-byte Ed25519 secret (seed ‖ pub).
    pub sign_priv_b64: String,
    pub sign_pub_b64: String,
}

/// Fields carried by the inner blob (`decodeInnerBlob`'s return value).
#[derive(Clone, Debug, PartialEq)]
pub struct MeshInner {
    pub from: MeshFrom,
    pub to: f64,
    pub to_idx: Option<String>,
    pub payload: String,
    pub sig: String,
    pub padded: bool,
    pub kind: MeshKind,
}

/// `MeshOuter` (meshCrypto.ts:115-124): the native-mutable wire frame.
#[derive(Clone, Debug, PartialEq)]
pub struct MeshOuter {
    pub v: Value,
    pub id: String,
    pub ttl: f64,
    pub hops: f64,
    pub l: Option<f64>,
    pub mode: MeshMode,
    pub ts: f64,
    /// base64 of the inner blob.
    pub b: String,
}

impl MeshOuter {
    /// `JSON.stringify(outer)`: key order v,id,ttl,hops,L?,mode,ts,b; `L` is
    /// dropped when undefined (ACKs).
    pub fn to_json(&self) -> String {
        let mut o = String::from("{");
        o.push_str(&format!("\"v\":{}", js_stringify(&self.v)));
        o.push_str(&format!(",\"id\":{}", json_str(&self.id)));
        o.push_str(&format!(",\"ttl\":{}", js_json_number(self.ttl)));
        o.push_str(&format!(",\"hops\":{}", js_json_number(self.hops)));
        if let Some(l) = self.l {
            o.push_str(&format!(",\"L\":{}", js_json_number(l)));
        }
        o.push_str(&format!(",\"mode\":{}", json_str(self.mode.as_str())));
        o.push_str(&format!(",\"ts\":{}", js_json_number(self.ts)));
        o.push_str(&format!(",\"b\":{}", json_str(&self.b)));
        o.push('}');
        o
    }
}

impl MeshEnvelope {
    /// `JSON.stringify(env)` — the RN pigeon-queue at-rest shape (MMKV). Keys
    /// in buildMeshEnvelope / buildMeshAck construction order
    /// (v,id,ts,ttl,hops,mode,from,to,toIdx,payload,sig,L,padded,kind; absent
    /// ones dropped). Key order is not load-bearing (read back via JSON.parse).
    pub fn to_json(&self) -> String {
        let mut o = String::from("{");
        o.push_str(&format!("\"v\":{}", js_stringify(&self.v)));
        o.push_str(&format!(",\"id\":{}", json_str(&self.id)));
        o.push_str(&format!(",\"ts\":{}", js_json_number(self.ts)));
        o.push_str(&format!(",\"ttl\":{}", js_json_number(self.ttl)));
        o.push_str(&format!(",\"hops\":{}", js_json_number(self.hops)));
        o.push_str(&format!(",\"mode\":{}", json_str(self.mode.as_str())));
        o.push_str(&format!(
            ",\"from\":{{\"uid\":{},\"sig_pub\":{}}}",
            js_json_number(self.from.uid),
            json_str(&self.from.sig_pub)
        ));
        o.push_str(&format!(",\"to\":{}", js_json_number(self.to)));
        if let Some(t) = &self.to_idx {
            o.push_str(&format!(",\"toIdx\":{}", json_str(t)));
        }
        o.push_str(&format!(",\"payload\":{}", json_str(&self.payload)));
        o.push_str(&format!(",\"sig\":{}", json_str(&self.sig)));
        if let Some(l) = self.l {
            o.push_str(&format!(",\"L\":{}", js_json_number(l)));
        }
        if let Some(p) = self.padded {
            o.push_str(&format!(",\"padded\":{p}"));
        }
        if let Some(k) = self.kind {
            o.push_str(&format!(",\"kind\":{}", json_str(k.as_str())));
        }
        o.push('}');
        o
    }

    /// Legacy (build ≤174) plain-JSON envelope / RN pigeon-queue entry:
    /// `isMeshEnvelope(raw) ? raw : null`.
    ///
    /// The four fields `isMeshEnvelope` does NOT check are normalized: `toIdx`
    /// kept only if a string, `L` only if a number, `padded` = JS truthiness,
    /// `kind` = Ack iff === "ack" (any other present value → Msg). No RN build
    /// ever emitted other types for them; semantics (flags, routing) are
    /// identical, only a re-`JSON.stringify` of such a pathological entry
    /// would differ.
    pub fn from_value(raw: &Value) -> Option<MeshEnvelope> {
        if !is_mesh_envelope(raw) {
            return None;
        }
        let o = raw.as_object()?;
        let num = |k: &str| o.get(k).and_then(Value::as_f64);
        let from = o.get("from")?.as_object()?;
        Some(MeshEnvelope {
            v: o.get("v")?.clone(),
            id: o.get("id")?.as_str()?.to_string(),
            ts: num("ts")?,
            ttl: num("ttl")?,
            hops: num("hops")?,
            mode: if o.get("mode")?.as_str()? == "pigeon" { MeshMode::Pigeon } else { MeshMode::Realtime },
            from: MeshFrom {
                uid: from.get("uid")?.as_f64()?,
                sig_pub: from.get("sig_pub")?.as_str()?.to_string(),
            },
            to: num("to")?,
            to_idx: o.get("toIdx").and_then(Value::as_str).map(str::to_string),
            payload: o.get("payload")?.as_str()?.to_string(),
            sig: o.get("sig")?.as_str()?.to_string(),
            l: num("L"),
            padded: o.get("padded").map(js_truthy),
            kind: o.get("kind").map(|k| if k.as_str() == Some("ack") { MeshKind::Ack } else { MeshKind::Msg }),
        })
    }

    fn is_ack(&self) -> bool {
        self.kind == Some(MeshKind::Ack)
    }
}

// ───────── inner blob ─────────

/// `encodeInnerBlob(env)` (meshCrypto.ts:131-187). Throws where TS throws.
pub fn encode_inner_blob(env: &MeshEnvelope) -> Result<Vec<u8>, MeshError> {
    let sig_pub_bytes = b64d_throw(&env.from.sig_pub)?;
    let sig_bytes = b64d_throw(&env.sig)?;
    // Build 308: ACK payload = RAW UTF-8 of the acked id, msg payload = base64-decoded.
    let payload_bytes = if env.is_ack() { env.payload.as_bytes().to_vec() } else { b64d_throw(&env.payload)? };
    let to_idx_bytes = match &env.to_idx {
        Some(t) if !t.is_empty() => Some(b64d_throw(t)?),
        _ => None,
    };
    let has_to = env.to > 0.0;

    let total_len = 1
        + SIG_PUB_LEN
        + UID_LEN
        + if has_to { UID_LEN } else { 0 }
        + if to_idx_bytes.is_some() { TO_IDX_LEN } else { 0 }
        + PAY_LEN_LEN
        + payload_bytes.len()
        + SIG_LEN;
    let mut out = vec![0u8; total_len];

    let mut flags = 0u8;
    if env.padded == Some(true) {
        flags |= FLAG_PADDED;
    }
    if to_idx_bytes.is_some() {
        flags |= FLAG_HAS_TO_IDX;
    }
    if has_to {
        flags |= FLAG_HAS_TO;
    }
    if env.is_ack() {
        flags |= FLAG_KIND_ACK;
    }
    out[0] = flags;

    let mut p = 1;
    copy_truncated(&mut out[p..p + SIG_PUB_LEN], &sig_pub_bytes);
    p += SIG_PUB_LEN;
    out[p..p + UID_LEN].copy_from_slice(&js_to_big_uint64(env.from.uid)?.to_be_bytes());
    p += UID_LEN;
    if has_to {
        out[p..p + UID_LEN].copy_from_slice(&js_to_big_uint64(env.to)?.to_be_bytes());
        p += UID_LEN;
    }
    if let Some(t) = &to_idx_bytes {
        copy_truncated(&mut out[p..p + TO_IDX_LEN], t);
        p += TO_IDX_LEN;
    }
    // setUint16 = ToUint16: wraps silently above 65535 (corrupt blob; RN quirk).
    out[p..p + PAY_LEN_LEN].copy_from_slice(&(payload_bytes.len() as u16).to_be_bytes());
    p += PAY_LEN_LEN;
    out[p..p + payload_bytes.len()].copy_from_slice(&payload_bytes);
    p += payload_bytes.len();
    copy_truncated(&mut out[p..p + SIG_LEN], &sig_bytes);
    Ok(out)
}

/// `out.set(src.slice(0, N), p)` into a zeroed N-byte field.
fn copy_truncated(dst: &mut [u8], src: &[u8]) {
    let n = dst.len().min(src.len());
    dst[..n].copy_from_slice(&src[..n]);
}

/// `decodeInnerBlob(buf)` (meshCrypto.ts:194-250). None where TS returns null.
pub fn decode_inner_blob(buf: &[u8]) -> Option<MeshInner> {
    if buf.len() < 1 + SIG_PUB_LEN + UID_LEN + PAY_LEN_LEN + SIG_LEN {
        return None;
    }
    let flags = buf[0];
    let mut p = 1;
    let sig_pub_bytes = &buf[p..p + SIG_PUB_LEN];
    p += SIG_PUB_LEN;
    let from_uid = be_u64(&buf[p..p + UID_LEN]) as f64; // Number(bigint): lossy above 2^53
    p += UID_LEN;
    let mut to_uid = 0f64;
    if flags & FLAG_HAS_TO != 0 {
        if p + UID_LEN > buf.len() {
            return None;
        }
        to_uid = be_u64(&buf[p..p + UID_LEN]) as f64;
        p += UID_LEN;
    }
    let mut to_idx = None;
    if flags & FLAG_HAS_TO_IDX != 0 {
        if p + TO_IDX_LEN > buf.len() {
            return None;
        }
        to_idx = Some(b64(&buf[p..p + TO_IDX_LEN]));
        p += TO_IDX_LEN;
    }
    if p + PAY_LEN_LEN > buf.len() {
        return None;
    }
    let pay_len = u16::from_be_bytes([buf[p], buf[p + 1]]) as usize;
    p += PAY_LEN_LEN;
    // (`payLen > 65535` in the TS is dead code: a u16 never exceeds it.)
    if p + pay_len + SIG_LEN > buf.len() {
        return None;
    }
    let payload_bytes = &buf[p..p + pay_len];
    p += pay_len;
    let sig_bytes = &buf[p..p + SIG_LEN]; // trailing bytes after sig are ignored
    let ack = flags & FLAG_KIND_ACK != 0;
    Some(MeshInner {
        from: MeshFrom { uid: from_uid, sig_pub: b64(sig_pub_bytes) },
        to: to_uid,
        to_idx,
        payload: if ack { text_decode(payload_bytes) } else { b64(payload_bytes) },
        sig: b64(sig_bytes),
        padded: flags & FLAG_PADDED != 0,
        kind: if ack { MeshKind::Ack } else { MeshKind::Msg },
    })
}

fn be_u64(b: &[u8]) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(b);
    u64::from_be_bytes(a)
}

// ───────── outer frame ─────────

/// `packMeshOuter(env)` (meshCrypto.ts:258-270).
pub fn pack_mesh_outer(env: &MeshEnvelope) -> Result<MeshOuter, MeshError> {
    let inner = encode_inner_blob(env)?;
    Ok(MeshOuter {
        v: env.v.clone(),
        id: env.id.clone(),
        ttl: env.ttl,
        hops: env.hops,
        l: env.l,
        mode: env.mode,
        ts: env.ts,
        b: b64(&inner),
    })
}

/// `JSON.stringify(packMeshOuter(env))` — the exact frame mesh.ts hands to
/// the native transports (mesh.ts:509,565,960).
pub fn pack_mesh_outer_json(env: &MeshEnvelope) -> Result<String, MeshError> {
    Ok(pack_mesh_outer(env)?.to_json())
}

/// `unpackMeshOuter(outer)` (meshCrypto.ts:273-294). `Ok(None)` = null;
/// `Err` = the TS throws (bad base64 in `b` is decoded outside any try).
pub fn unpack_mesh_outer(outer: &Value) -> Result<Option<MeshEnvelope>, MeshError> {
    // `!outer || typeof outer.b !== 'string' || typeof outer.id !== 'string'`:
    // a non-object has no own `b`/`id`, so only objects get past this.
    let Some(o) = outer.as_object() else { return Ok(None) };
    let (Some(Value::String(b)), Some(Value::String(id))) = (o.get("b"), o.get("id")) else {
        return Ok(None);
    };
    let inner_bytes = b64d_throw(b)?;
    let Some(inner) = decode_inner_blob(&inner_bytes) else { return Ok(None) };
    let num_or = |k: &str, d: f64| match o.get(k) {
        Some(Value::Number(n)) => n.as_f64().unwrap_or(d),
        _ => d,
    };
    let v = o.get("v").cloned().unwrap_or(Value::Null);
    Ok(Some(MeshEnvelope {
        v,
        id: id.clone(),
        ts: num_or("ts", 0.0),
        ttl: num_or("ttl", 0.0),
        hops: num_or("hops", 0.0),
        mode: if o.get("mode").and_then(Value::as_str) == Some("pigeon") { MeshMode::Pigeon } else { MeshMode::Realtime },
        l: match o.get("L") {
            Some(Value::Number(n)) => n.as_f64(),
            _ => None,
        },
        from: inner.from,
        to: inner.to,
        to_idx: inner.to_idx,
        payload: inner.payload,
        sig: inner.sig,
        padded: Some(inner.padded),
        kind: Some(inner.kind),
    }))
}

// ───────── toIdx ─────────

/// `Math.floor(tsMs / 3_600_000)` passed through ToUint32 (`setUint32`).
pub fn to_idx_epoch(ts_ms: f64) -> u32 {
    to_uint32((ts_ms / TO_IDX_EPOCH_MS).floor())
}

/// `computeToIdx(myPrivB64, peerPubB64, tsMs)` (meshCrypto.ts:296-315):
/// b64(SHA-512(box.before(peerPub, myPriv) ‖ be32(epoch))[0..8]); "" on any failure.
pub fn compute_to_idx(my_identity_priv_b64: &str, peer_identity_pub_b64: &str, ts_ms: f64) -> String {
    let (Some(my_priv), Some(peer_pub)) = (nacl_b64d(my_identity_priv_b64), nacl_b64d(peer_identity_pub_b64)) else {
        return String::new();
    };
    let (Ok(my_priv), Ok(peer_pub)) = (<[u8; 32]>::try_from(my_priv), <[u8; 32]>::try_from(peer_pub)) else {
        return String::new();
    };
    let shared = box_before(&peer_pub, &my_priv);
    let mut buf = [0u8; 36];
    buf[..32].copy_from_slice(&shared);
    buf[32..].copy_from_slice(&to_idx_epoch(ts_ms).to_be_bytes());
    b64(&sha512(&buf)[..TO_IDX_BYTES])
}

// ───────── bucket padding ─────────

fn pick_bucket(real_len: usize) -> usize {
    let need = real_len + 4;
    for b in PAD_BUCKETS {
        if need <= b {
            return b;
        }
    }
    need.div_ceil(2048) * 2048
}

/// `padPayload(ratchetJsonString)` (meshCrypto.ts:351-365): be32(len) ‖
/// UTF-8 ‖ random fill (one `nacl.randomBytes(fill)` draw, only when fill > 0).
pub fn pad_payload(ratchet_json: &str, rng: &mut dyn Rng) -> String {
    let bytes = ratchet_json.as_bytes();
    let real_len = bytes.len();
    let bucket = pick_bucket(real_len);
    let mut out = vec![0u8; bucket];
    out[..4].copy_from_slice(&(real_len as u32).to_be_bytes());
    out[4..4 + real_len].copy_from_slice(bytes);
    let fill_start = 4 + real_len;
    if fill_start < bucket {
        rng.fill(&mut out[fill_start..]);
    }
    b64(&out)
}

/// `unpadPayload(paddedBase64)` (meshCrypto.ts:367-379). None where TS
/// returns null (bad base64, < 4 bytes, realLen + 4 > len, realLen > 1 MiB).
pub fn unpad_payload(padded_b64: &str) -> Option<String> {
    let buf = nacl_b64d(padded_b64)?;
    if buf.len() < 4 {
        return None;
    }
    let real_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as u64;
    if real_len + 4 > buf.len() as u64 {
        return None;
    }
    if real_len > 1024 * 1024 {
        return None;
    }
    Some(text_decode(&buf[4..4 + real_len as usize]))
}

// ───────── signing (utils/crypto.ts signPayload / verifyPayload) ─────────

/// `signPayload` with the RFC 8032 signer (see the module docs).
fn sign_payload(payload_utf8: &str, private_key_b64: &str) -> Result<String, MeshError> {
    crypto_ts::sign_payload_rfc8032(payload_utf8, private_key_b64).map_err(|e| match e {
        SignPayloadError::InvalidEncoding => MeshError::InvalidEncoding,
        SignPayloadError::BadSecretKeySize => MeshError::BadSecretKeySize,
    })
}

fn verify_payload(payload_utf8: &str, signature_b64: &str, public_key_b64: &str) -> bool {
    crypto_ts::verify_payload(payload_utf8, signature_b64, public_key_b64)
}

/// tweetnacl `nacl.sign.detached.verify(msg, sig, pub)` (lengths already
/// checked; `compat::ed25519`). tweetnacl's `crypto_sign_open` computes
/// encode([S]B − [h]A) with the raw 256-bit S and compares it to R; it never
/// range-checks S. Since B has order ℓ, [S]B = [S mod ℓ]B, so reducing S
/// (< 2^256 < 16ℓ) and handing the canonical signature to the (cofactorless,
/// non-strict) dalek check accepts exactly what tweetnacl accepts.
pub fn nacl_sign_detached_verify(msg: &[u8], sig: &[u8; 64], public: &[u8; 32]) -> bool {
    tweetnacl_sign_detached_verify(msg, sig, public)
}

/// The signed binding `${id}|${ts}|${from.uid}|${to}|${payload}` with JS
/// Number→String for the numbers (meshCrypto.ts:521,569,597).
pub fn signed_binding(env: &MeshEnvelope) -> String {
    binding_v2(
        &env.id,
        env.ts,
        env.from.uid,
        env.to,
        env.to_idx.as_deref(),
        env.ttl,
        env.l,
        env.mode,
        env.kind.unwrap_or(MeshKind::Msg),
        &env.payload,
    )
}

const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

/// A wire number the binding accepts: an integer in `[0, 2^53)`.
fn int_field(x: f64) -> Option<i64> {
    (x.is_finite() && x.fract() == 0.0 && (0.0..=MAX_SAFE).contains(&x)).then_some(x as i64)
}

#[allow(clippy::too_many_arguments)]
fn binding_v2(
    id: &str,
    ts: f64,
    from_uid: f64,
    to: f64,
    to_idx: Option<&str>,
    ttl: f64,
    l: Option<f64>,
    mode: MeshMode,
    kind: MeshKind,
    payload: &str,
) -> String {
    let n = |x: f64| int_field(x).map_or_else(|| "NaN".to_string(), |i| i.to_string());
    format!(
        "{MESH_BINDING_LABEL}|{id}|{}|{}|{}|{}|{}|{}|{}|{}|{payload}",
        n(ts),
        n(from_uid),
        n(to),
        to_idx.filter(|t| !t.is_empty()).unwrap_or("-"),
        n(ttl),
        l.map_or_else(|| "-".to_string(), n),
        mode.as_str(),
        kind.as_str(),
    )
}

// ───────── builders ─────────

/// `buildMeshEnvelope(...)` (meshCrypto.ts:477-538). `now_ms` = `Date.now()`.
///
/// Draw order: [ratchet init 32 if the store has no state] → ratchet nonce
/// 24 → pad fill → secureUUID 16 (only when `message_id` is None/empty).
/// `Ok(None)` = TS null (missing identity, ratchet failure); `Err` = TS throw
/// (bad signing key — after the ratchet state was already saved).
#[allow(clippy::too_many_arguments)]
pub fn build_mesh_envelope_from_ratchet(
    to_user_id: i64,
    my_identity_priv_b64: &str,
    peer_identity_pub_b64: &str,
    ratchet_json: &str,
    mode: MeshMode,
    me: &MeshIdentity,
    message_id: Option<&str>,
    now_ms: i64,
    rng: &mut dyn Rng,
) -> Result<Option<MeshEnvelope>, MeshError> {
    if me.from_uid == 0 || me.sign_priv_b64.is_empty() || me.sign_pub_b64.is_empty() {
        return Ok(None);
    }
    let payload = pad_payload(ratchet_json, rng);
    let id = match message_id {
        Some(m) if !m.is_empty() => m.to_string(),
        _ => secure_uuid(rng),
    };
    let ts = now_ms as f64;
    let to_idx = compute_to_idx(my_identity_priv_b64, peer_identity_pub_b64, ts);
    let ttl = match mode {
        MeshMode::Pigeon => PIGEON_TTL_SECONDS,
        MeshMode::Realtime => REALTIME_TTL,
    };
    let from_uid = me.from_uid as f64;
    let to = to_user_id as f64;
    let to_idx = if to_idx.is_empty() { None } else { Some(to_idx) };
    let binding = binding_v2(&id, ts, from_uid, to, to_idx.as_deref(), ttl as f64, Some(SPRAY_INITIAL_L as f64), mode, MeshKind::Msg, &payload);
    let sig = sign_payload(&binding, &me.sign_priv_b64)?;
    Ok(Some(MeshEnvelope {
        v: Value::from(MESH_WIRE_VERSION),
        id,
        ts,
        ttl: ttl as f64,
        hops: 0.0,
        mode,
        from: MeshFrom { uid: from_uid, sig_pub: me.sign_pub_b64.clone() },
        to,
        to_idx,
        payload,
        sig,
        l: Some(SPRAY_INITIAL_L as f64),
        padded: Some(true),
        kind: None,
    }))
}

/// `buildMeshAck(toUserId, ackedMessageId, me)` (meshCrypto.ts:559-584).
/// One draw: secureUUID (16). No toIdx, no L, no padded; ttl = PRUNE_TTL,
/// mode realtime, payload = the acked id (raw).
pub fn build_mesh_ack(
    to_user_id: i64,
    acked_message_id: &str,
    me: &MeshIdentity,
    now_ms: i64,
    rng: &mut dyn Rng,
) -> Result<Option<MeshEnvelope>, MeshError> {
    if me.from_uid == 0 || me.sign_priv_b64.is_empty() || me.sign_pub_b64.is_empty() {
        return Ok(None);
    }
    if acked_message_id.is_empty() {
        return Ok(None);
    }
    let id = secure_uuid(rng);
    let ts = now_ms as f64;
    let from_uid = me.from_uid as f64;
    let to = to_user_id as f64;
    let payload = acked_message_id.to_string();
    let binding = binding_v2(&id, ts, from_uid, to, None, PRUNE_TTL as f64, None, MeshMode::Realtime, MeshKind::Ack, &payload);
    let sig = sign_payload(&binding, &me.sign_priv_b64)?;
    Ok(Some(MeshEnvelope {
        v: Value::from(MESH_WIRE_VERSION),
        id,
        ts,
        ttl: PRUNE_TTL as f64,
        hops: 0.0,
        mode: MeshMode::Realtime,
        from: MeshFrom { uid: from_uid, sig_pub: me.sign_pub_b64.clone() },
        to,
        to_idx: None,
        payload,
        sig,
        l: None,
        padded: None,
        kind: Some(MeshKind::Ack),
    }))
}

// ───────── receive-side checks ─────────

/// `verifyMeshEnvelope(env)` (meshCrypto.ts:594-599). Does NOT check that
/// `sig_pub` belongs to `from.uid` (mesh.ts pins that separately).
pub fn verify_mesh_envelope(env: &MeshEnvelope) -> bool {
    if !is_wire_version(&env.v) {
        return false;
    }
    if env.id.is_empty() || env.from.sig_pub.is_empty() || env.sig.is_empty() {
        return false;
    }
    let ints = [Some(env.ts), Some(env.from.uid), Some(env.to), Some(env.ttl), Some(env.hops), env.l];
    if ints.iter().flatten().any(|x| int_field(*x).is_none()) {
        return false;
    }
    verify_payload(&signed_binding(env), &env.sig, &env.from.sig_pub)
}

/// `isMeshEnvelope(raw)` (meshCrypto.ts:606-618) — the legacy / pigeon-queue guard.
pub fn is_mesh_envelope(raw: &Value) -> bool {
    let Some(o) = raw.as_object() else { return false };
    let is_num = |v: Option<&Value>| matches!(v, Some(Value::Number(_)));
    let is_str = |v: Option<&Value>| matches!(v, Some(Value::String(_)));
    o.get("v").is_some_and(is_wire_version)
        && is_str(o.get("id"))
        && is_num(o.get("ts"))
        && is_num(o.get("ttl"))
        && is_num(o.get("hops"))
        && matches!(o.get("mode").and_then(Value::as_str), Some("realtime") | Some("pigeon"))
        && o.get("from").and_then(Value::as_object).is_some_and(|f| is_num(f.get("uid")) && is_str(f.get("sig_pub")))
        && is_num(o.get("to"))
        && is_str(o.get("payload"))
        && is_str(o.get("sig"))
}

/// `v === MESH_WIRE_VERSION` (strict: the number 1; `1.0` in JSON is the same JS number).
fn is_wire_version(v: &Value) -> bool {
    matches!(v, Value::Number(n) if n.as_f64() == Some(MESH_WIRE_VERSION as f64))
}

// ───────── JS semantics helpers (the rest come from `compat`) ─────────

/// `setBigUint64(p, BigInt(x))`: RangeError for non-integers, else x mod 2^64.
fn js_to_big_uint64(x: f64) -> Result<u64, MeshError> {
    number_to_bigint_u64(x).ok_or(MeshError::NotAnInteger)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Expected strings produced by Node (V8) `String(x)`.
    #[test]
    fn js_number_formatting_matches_v8() {
        let cases: [(f64, &str); 15] = [
            (1758800000000.0, "1758800000000"),
            (1.5, "1.5"),
            (1e21, "1e+21"),
            (1e-7, "1e-7"),
            (123e-20, "1.23e-18"),
            (0.000001, "0.000001"),
            (18446744073709551615u64 as f64, "18446744073709552000"),
            (9007199254740994.0, "9007199254740994"),
            (0.1 + 0.2, "0.30000000000000004"),
            (-0.0, "0"),
            (5e-324, "5e-324"),
            (f64::MAX, "1.7976931348623157e+308"),
            (123456789012345680000.0, "123456789012345680000"),
            (1e20, "100000000000000000000"),
            (12.3456789, "12.3456789"),
        ];
        for (x, want) in cases {
            assert_eq!(crate::legacy353::compat::js_number::number_to_string_ties_up(x), want, "{x:e}");
        }
        assert_eq!(crate::legacy353::compat::js_number::number_to_string_ties_up(-1001.0), "-1001");
        assert_eq!(js_json_number(f64::NAN), "null");
    }

    /// Expected strings produced by Node `new TextDecoder().decode(...)`.
    #[test]
    fn text_decoder_matches_whatwg() {
        let cases: [(&[u8], &str); 12] = [
            (&[0xef, 0xbb, 0xbf, 0x41], "A"),
            (&[0xef, 0xbb, 0xbf, 0xef, 0xbb, 0xbf, 0x41], "\u{feff}A"),
            (&[0xc0, 0xaf], "\u{fffd}\u{fffd}"),
            (&[0xe0, 0x80], "\u{fffd}\u{fffd}"),
            (&[0xf0, 0x80, 0x80], "\u{fffd}\u{fffd}\u{fffd}"),
            (&[0xed, 0xa0, 0x80], "\u{fffd}\u{fffd}\u{fffd}"),
            (&[0xf4, 0x90, 0x80, 0x80], "\u{fffd}\u{fffd}\u{fffd}\u{fffd}"),
            (&[0xe2, 0x82], "\u{fffd}"),
            (&[0x41, 0xe2, 0x82], "A\u{fffd}"),
            (&[0xfe], "\u{fffd}"),
            (&[0xc3], "\u{fffd}"),
            (&[0xe2, 0x82, 0x82, 0x41], "\u{2082}A"),
        ];
        for (b, want) in cases {
            assert_eq!(text_decode(b), want, "{b:02x?}");
        }
    }

    #[test]
    fn js_integer_conversions() {
        assert_eq!(to_uint32(-1.0), u32::MAX);
        assert_eq!(to_uint32(4294967296.0 + 5.0), 5);
        assert_eq!(to_uint32(f64::NAN), 0);
        assert_eq!(to_uint32(f64::INFINITY), 0);
        assert_eq!(js_to_big_uint64(-1.0), Ok(u64::MAX));
        assert_eq!(js_to_big_uint64(18446744073709551616.0), Ok(0));
        // Node: BigInt.asUintN(64, BigInt(3*2**64+8192)) === 8192n
        assert_eq!(js_to_big_uint64(18446744073709551616.0 * 3.0 + 8192.0), Ok(8192));
        assert_eq!(js_to_big_uint64(1e300), Ok(0));
        assert_eq!(js_to_big_uint64(1.5), Err(MeshError::NotAnInteger));
        assert_eq!(js_to_big_uint64(f64::NAN), Err(MeshError::NotAnInteger));
    }

    #[test]
    fn js_stringify_orders_index_keys_first() {
        let v: Value = serde_json::from_str(r#"{"b":1,"2":2,"a":[1.0,-0.0,1e21],"1":"x","01":3}"#).unwrap();
        // Node: JSON.stringify(JSON.parse(same)) →
        assert_eq!(js_stringify(&v), r#"{"1":"x","2":2,"b":1,"a":[1,0,1e+21],"01":3}"#);
    }
}
