//! The mesh at wire level 2 (wire-1.1 §W8; 04-mesh.md «Mesh at level 2»).
//!
//! `mesh_envelope` is the 1.0.0 envelope and its lenient decoder. This module
//! is what a level-2 node RECEIVES with, and what it adds:
//!
//! - [`frame_check`] — one strict check of a received frame: canonical form
//!   (no duplicate JSON key, integers that are integers, canonical base64,
//!   exact flags, no bytes after the signature), the per-kind profile, the
//!   Ed25519 signature verified strictly, the replay window. Its result is
//!   the only thing a node may act on, relay or mark as seen;
//! - [`Frame::seen_key`] — the duplicate key is a hash of the SIGNED content,
//!   never the bare id, so an invalid copy cannot suppress the valid frame;
//! - [`forward_hops`] / [`forwarded_json`] — the forward rule that touches no
//!   signed field: a relay writes only `hops`, and re-serializes the frame;
//! - named kinds (`flags` bit `0x80`): `ptt` (a push-to-talk segment, never
//!   relayed, never queued), `ctl` (the control carrier for a peer reachable
//!   only by radio) and names a later release may add;
//! - the blind ACK (no uid, no long-term key on the air);
//! - the courier capsule `c` — outside the v2 binding (a 1.0.0 node must
//!   still verify the frame), but signed by the frame's own signer, so every
//!   node can tell the sender's capsule from one a bystander attached;
//! - the link hello and the per-link admission budgets;
//! - [`SeenSet`] — what a node remembers about the frames it verified (the
//!   signed budget, the `hops` it relayed the frame with, the verified
//!   capsule), so that the two things NO frame signature covers (`hops`, and
//!   whether a copy still carries its capsule) can neither suppress a relay
//!   nor part a frame from its capsule.
//!
//! Every frame a 1.0.0 client originates passes the check. A 1.0.0 client
//! fails the signature of every named frame (it rebuilds the binding with
//! kind `msg`), which is why the names `msg` and `ack` are reserved.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use serde_json::Value;

use crate::mesh_envelope::{is_courier_shape, MeshEnvelope, MeshFrom, MeshKind, MeshMode, MESH_BINDING_LABEL, MSG_PAYLOAD_MAX, TO_IDX_BYTES};
use crate::primitives::{b64, box_before, box_open, box_seal, ed25519_keypair_from_seed, ed25519_sign, secure_uuid, sha256, sha512, x25519_keypair};
use crate::ptt::{ptt_id_bytes, ptt_id_text};
use crate::rng::Rng;
use crate::strict_json::{self, MAX_SAFE_INT};

pub const MAX_FRAME_BYTES: usize = 131_072;
pub const MAX_ID_BYTES: usize = 128;

/// A frame id: 1..128 bytes, no `|` (the separator of the signed binding) and
/// no control character. Clients make ids from UUIDs; a receiver treats an id
/// as a machine string (a NUL or a line break inside one cuts C strings and
/// forges log lines), so a frame with such an id is not worth relaying either.
pub fn is_frame_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= MAX_ID_BYTES && !id.bytes().any(|b| b == b'|' || b < 0x20 || b == 0x7f)
}
/// A frame that claims more relay hops than this is rejected.
pub const MAX_HOPS: u64 = 16;
/// 24 h of pigeon life plus one hour of clock skew.
pub const REPLAY_PAST_MS: i64 = (86_400 + 3_600) * 1000;
pub const REPLAY_FUTURE_MS: i64 = 300_000;
pub const REALTIME_TTL_MAX: u64 = 7;
pub const PIGEON_TTL_MAX: u64 = 86_400;
pub const ACK_TTL_MAX: u64 = 4;
pub const L_MAX: u64 = 4;
pub const ACK_PAYLOAD_MAX: usize = 256;

pub const FLAGS_MSG: u8 = 0x03;
pub const FLAGS_ACK: u8 = 0x08;
pub const FLAGS_NAMED: u8 = 0x80;
pub const FLAGS_NAMED_TO: u8 = 0x82;
const FLAG_HAS_TO_IDX: u8 = 0x02;

pub const NAME_MAX: usize = 8;
pub const NAME_PTT: &str = "ptt";
pub const NAME_CTL: &str = "ctl";
/// `msg` and `ack` as NAMES would reproduce the 1.0.0 binding strings.
pub const RESERVED_NAMES: [&str; 2] = ["msg", "ack"];
pub const PTT_BODY_MAX: usize = 16_384;
pub const CTL_BODY_MAX: usize = 8192;
pub const CTL_TTL_MAX: u64 = 1;
/// A frame of a name this node does not know is relayed only up to this size.
pub const UNKNOWN_RELAY_PAYLOAD_MAX: usize = 2048;

const SIG_PUB_LEN: usize = 32;
const UID_LEN: usize = 8;
const SIG_LEN: usize = 64;

// ───────────────────────────── the verified frame ─────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FrameKind {
    Msg,
    /// The 1.0.0 ACK: `id.tag`, signed with the recipient's identity key.
    Ack,
    /// The blind ACK: `from.uid == 0`, a one-time key.
    AckBlind,
    Ptt,
    Ctl,
    /// A named kind this build does not know: verified, relayed within
    /// bounds, never acted on.
    Named(String),
}

impl FrameKind {
    /// The kind string inside the signed binding.
    pub fn binding_kind(&self) -> &str {
        match self {
            FrameKind::Msg => "msg",
            FrameKind::Ack | FrameKind::AckBlind => "ack",
            FrameKind::Ptt => NAME_PTT,
            FrameKind::Ctl => NAME_CTL,
            FrameKind::Named(n) => n,
        }
    }

    /// `msg` | `ack` | `ack2` | `ptt` | `ctl` | `named`.
    pub fn label(&self) -> &'static str {
        match self {
            FrameKind::Msg => "msg",
            FrameKind::Ack => "ack",
            FrameKind::AckBlind => "ack2",
            FrameKind::Ptt => "ptt",
            FrameKind::Ctl => "ctl",
            FrameKind::Named(_) => "named",
        }
    }

    pub fn is_named(&self) -> bool {
        matches!(self, FrameKind::Ptt | FrameKind::Ctl | FrameKind::Named(_))
    }
}

/// A frame that passed [`frame_check`] (or [`frame_parse`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub id: String,
    pub ts: u64,
    pub ttl: u64,
    pub hops: u64,
    pub l: Option<u64>,
    pub mode: MeshMode,
    pub kind: FrameKind,
    pub from_uid: u64,
    pub sig_pub: [u8; 32],
    pub to_idx: Option<[u8; TO_IDX_BYTES]>,
    /// The inner payload bytes: a padded envelope (`msg`), the ACK text, or
    /// `nlen ‖ name ‖ body` (named).
    pub payload: Vec<u8>,
    pub sig: [u8; 64],
    /// The courier capsule: only on a `msg`, and only when the frame's own
    /// signer made it for this frame ([`courier_capsule_verifies`]) — from
    /// every parser of this module. Anything else is absent.
    pub courier: Option<String>,
    /// `b64(SHA-256(inner blob)[0..16])`.
    pub seen_key: String,
    /// The inner blob, canonical base64 (what a relay forwards unchanged).
    pub b: String,
}

impl Frame {
    /// The body of a named frame (after `nlen ‖ name`); the whole payload otherwise.
    pub fn body(&self) -> &[u8] {
        match &self.kind {
            // The check proved `payload.len() ≥ 1 + nlen`.
            k if k.is_named() => self.payload.get(1 + k.binding_kind().len()..).unwrap_or(&[]),
            _ => &self.payload,
        }
    }

    /// The 1.0.0 envelope record of a `msg` or an ACK (what the lenient
    /// decoder returns for a canonical frame); `None` for a named frame.
    pub fn to_legacy_envelope(&self) -> Option<MeshEnvelope> {
        let (payload, padded, kind) = match self.kind {
            FrameKind::Msg => (b64(&self.payload), true, MeshKind::Msg),
            FrameKind::Ack | FrameKind::AckBlind => (String::from_utf8(self.payload.clone()).ok()?, false, MeshKind::Ack),
            _ => return None,
        };
        Some(MeshEnvelope {
            v: Value::from(2),
            id: self.id.clone(),
            ts: self.ts as f64,
            ttl: self.ttl as f64,
            hops: self.hops as f64,
            mode: self.mode,
            from: MeshFrom { uid: self.from_uid as f64, sig_pub: b64(&self.sig_pub) },
            to: 0.0,
            to_idx: self.to_idx.map(|t| b64(&t)),
            payload,
            sig: b64(&self.sig),
            l: self.l.map(|l| l as f64),
            padded: Some(padded),
            kind: Some(kind),
            courier: self.courier.clone(),
        })
    }
}

/// The v2 binding (03 §V3.9.1) from exact integers. `to` is always 0 on the
/// air; `payload_text` is the ACK text, or the base64 of every payload byte.
#[allow(clippy::too_many_arguments)]
pub fn binding(id: &str, ts: u64, from_uid: u64, to_idx: Option<&[u8; TO_IDX_BYTES]>, ttl: u64, l: Option<u64>, mode: MeshMode, kind: &str, payload_text: &str) -> String {
    format!(
        "{MESH_BINDING_LABEL}|{id}|{ts}|{from_uid}|0|{}|{ttl}|{}|{}|{kind}|{payload_text}",
        to_idx.map_or_else(|| "-".to_string(), |t| b64(t)),
        l.map_or_else(|| "-".to_string(), |l| l.to_string()),
        mode.as_str(),
    )
}

fn is_name(name: &[u8]) -> bool {
    (1..=NAME_MAX).contains(&name.len()) && name.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

struct Inner<'a> {
    flags: u8,
    sig_pub: [u8; 32],
    from_uid: u64,
    to_idx: Option<[u8; TO_IDX_BYTES]>,
    payload: &'a [u8],
    sig: [u8; 64],
}

/// The inner blob in its one canonical layout:
/// `flags ‖ sig_pub[32] ‖ from u64 ‖ [toIdx 8] ‖ len u16 ‖ payload ‖ sig[64]`,
/// exact length, flags one of the four values.
fn parse_inner(blob: &[u8]) -> Result<Inner<'_>, &'static str> {
    let flags = *blob.first().ok_or("blob")?;
    if !matches!(flags, FLAGS_MSG | FLAGS_ACK | FLAGS_NAMED | FLAGS_NAMED_TO) {
        return Err("flags");
    }
    let has_to_idx = flags & FLAG_HAS_TO_IDX != 0;
    let head = 1 + SIG_PUB_LEN + UID_LEN + if has_to_idx { TO_IDX_BYTES } else { 0 } + 2;
    if blob.len() < head + SIG_LEN {
        return Err("blob");
    }
    let mut p = 1;
    let sig_pub: [u8; 32] = blob[p..p + SIG_PUB_LEN].try_into().map_err(|_| "blob")?;
    p += SIG_PUB_LEN;
    let from_uid = u64::from_be_bytes(blob[p..p + UID_LEN].try_into().map_err(|_| "blob")?);
    p += UID_LEN;
    let to_idx = if has_to_idx {
        let t: [u8; TO_IDX_BYTES] = blob[p..p + TO_IDX_BYTES].try_into().map_err(|_| "blob")?;
        p += TO_IDX_BYTES;
        Some(t)
    } else {
        None
    };
    let len = u16::from_be_bytes([blob[p], blob[p + 1]]) as usize;
    p += 2;
    // Exact: nothing may follow the signature (1.0.0 ignores trailing bytes,
    // which would let anyone mint a second blob for the same signed frame).
    if blob.len() != p + len + SIG_LEN {
        return Err("blob");
    }
    let payload = &blob[p..p + len];
    let sig: [u8; 64] = blob[p + len..].try_into().map_err(|_| "blob")?;
    Ok(Inner { flags, sig_pub, from_uid, to_idx, payload, sig })
}

fn parse(bytes: &[u8], verify: bool) -> Result<Frame, &'static str> {
    // 1. Size, UTF-8, one JSON object, no duplicate key.
    if bytes.len() > MAX_FRAME_BYTES {
        return Err("size");
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "utf8")?;
    let o = strict_json::parse_object(text).ok_or("json")?;
    // 2. Outer fields: exact types, exact integers.
    if o.get("v").and_then(strict_json::uint) != Some(2) {
        return Err("v");
    }
    let id = o.get("id").and_then(Value::as_str).filter(|i| is_frame_id(i)).ok_or("id")?;
    let int = |k: &str| o.get(k).and_then(strict_json::uint).ok_or("number");
    let (ttl, hops, ts) = (int("ttl")?, int("hops")?, int("ts")?);
    let l = match o.get("L") {
        None => None,
        Some(v) => Some(strict_json::uint(v).ok_or("number")?),
    };
    if hops > MAX_HOPS {
        return Err("hops");
    }
    let mode = match o.get("mode").and_then(Value::as_str) {
        Some("realtime") => MeshMode::Realtime,
        Some("pigeon") => MeshMode::Pigeon,
        _ => return Err("mode"),
    };
    // 3. The inner blob, canonical.
    let b = o.get("b").and_then(Value::as_str).ok_or("b64")?;
    let blob = strict_json::b64(b).ok_or("b64")?;
    let inner = parse_inner(&blob)?;
    let uid_ok = |uid: u64, zero_ok: bool| (uid >= 1 || zero_ok) && uid <= MAX_SAFE_INT;
    // 4. The profile of the kind.
    let l_ok = |l: Option<u64>| l.is_some_and(|l| (1..=L_MAX).contains(&l));
    let kind = match inner.flags {
        FLAGS_MSG => {
            if !uid_ok(inner.from_uid, false) {
                return Err("from");
            }
            let ttl_ok = match mode {
                MeshMode::Realtime => ttl <= REALTIME_TTL_MAX,
                MeshMode::Pigeon => (1..=PIGEON_TTL_MAX).contains(&ttl),
            };
            if !ttl_ok || !l_ok(l) || inner.payload.is_empty() {
                return Err("profile");
            }
            FrameKind::Msg
        }
        FLAGS_ACK => {
            if !uid_ok(inner.from_uid, true) {
                return Err("from");
            }
            // The ACK payload is text inside the binding: it must be exactly
            // the bytes signed (strict UTF-8, no BOM for a decoder to strip).
            let text = std::str::from_utf8(inner.payload).map_err(|_| "profile")?;
            if mode != MeshMode::Realtime || ttl > ACK_TTL_MAX || l.is_some() || text.is_empty() || text.len() > ACK_PAYLOAD_MAX || text.starts_with('\u{feff}') {
                return Err("profile");
            }
            if inner.from_uid == 0 {
                if text.len() != 24 || strict_json::b64_n::<16>(text).is_none() {
                    return Err("profile");
                }
                FrameKind::AckBlind
            } else {
                FrameKind::Ack
            }
        }
        _ => {
            if !uid_ok(inner.from_uid, false) {
                return Err("from");
            }
            let nlen = *inner.payload.first().ok_or("name")? as usize;
            let name = inner.payload.get(1..1 + nlen).filter(|n| is_name(n)).ok_or("name")?;
            // `is_name` proved ASCII.
            let name = std::str::from_utf8(name).map_err(|_| "name")?;
            if RESERVED_NAMES.contains(&name) {
                return Err("name");
            }
            let body_len = inner.payload.len() - 1 - nlen;
            if mode != MeshMode::Realtime {
                return Err("profile");
            }
            match name {
                NAME_PTT => {
                    if inner.flags != FLAGS_NAMED_TO || ttl != 0 || l.is_some() || body_len == 0 || body_len > PTT_BODY_MAX {
                        return Err("profile");
                    }
                    FrameKind::Ptt
                }
                NAME_CTL => {
                    if inner.flags != FLAGS_NAMED_TO || ttl > CTL_TTL_MAX || l.is_some() || body_len == 0 || body_len > CTL_BODY_MAX {
                        return Err("profile");
                    }
                    FrameKind::Ctl
                }
                other => {
                    if ttl > REALTIME_TTL_MAX || !(l.is_none() || l_ok(l)) {
                        return Err("profile");
                    }
                    FrameKind::Named(other.to_string())
                }
            }
        }
    };
    // 5. The signature, strict (canonical S, no small-order key).
    if verify {
        let payload_text = match kind {
            FrameKind::Ack | FrameKind::AckBlind => String::from_utf8(inner.payload.to_vec()).map_err(|_| "profile")?,
            _ => b64(inner.payload),
        };
        let signed = binding(id, ts, inner.from_uid, inner.to_idx.as_ref(), ttl, l, mode, kind.binding_kind(), &payload_text);
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&inner.sig_pub).map_err(|_| "signature")?;
        vk.verify_strict(signed.as_bytes(), &ed25519_dalek::Signature::from_bytes(&inner.sig)).map_err(|_| "signature")?;
    }
    // `c` is outside the v2 binding, so it carries its own signature by the
    // frame's signer. A capsule that does not verify is ABSENT — never a
    // reason to reject the frame (a relay that mangles it must not be able
    // to stop the radio delivery) and never something to store or pass on
    // (a bystander's junk capsule must not be able to take the place of the
    // sender's in a courier store). The check needs nothing but the frame's
    // own fields, so it runs whether or not `verify` asked for the FRAME
    // signature: no entry point of this module returns a capsule that is
    // only of the right shape.
    let courier = match kind {
        FrameKind::Msg => o
            .get("c")
            .and_then(Value::as_str)
            .filter(|c| is_courier_shape(c))
            .filter(|c| courier_capsule_verifies(c, id, ts, inner.from_uid, &inner.sig_pub, &blob))
            .map(str::to_string),
        _ => None,
    };
    Ok(Frame {
        id: id.to_string(),
        ts,
        ttl,
        hops,
        l,
        mode,
        kind,
        from_uid: inner.from_uid,
        sig_pub: inner.sig_pub,
        to_idx: inner.to_idx,
        payload: inner.payload.to_vec(),
        sig: inner.sig,
        courier,
        seen_key: b64(&sha256(&blob)[..16]),
        b: b.to_string(),
    })
}

/// Steps 1–5 of the strict check (wire-1.1 §W8.2): everything but the replay
/// window. For frames a node made itself and for a server that applies its
/// own freshness rule.
pub fn frame_parse(bytes: &[u8]) -> Result<Frame, &'static str> {
    parse(bytes, true)
}

/// Steps 1–4 only: structure and profile, WITHOUT the frame's signature.
/// Never a basis for acting on a frame; it exists for the 1.0.0-shaped
/// `unpack` entry point, whose caller verifies in a second call. The capsule
/// is checked here too (its `csig` under the embedded `sig_pub`): what the
/// caller's second call then proves is the frame, and the capsule it was
/// handed is already the signer's own or absent.
pub fn frame_parse_unverified(bytes: &[u8]) -> Result<Frame, &'static str> {
    parse(bytes, false)
}

/// The strict frame check. `Err` carries the reason (for the log); nothing
/// may be recorded as seen for a frame that fails it.
pub fn frame_check(bytes: &[u8], now_ms: i64) -> Result<Frame, &'static str> {
    let frame = frame_parse(bytes)?;
    // 6. The replay window (`ts` < 2^53: the subtractions cannot overflow).
    let ts = frame.ts as i64;
    if now_ms.saturating_sub(ts) > REPLAY_PAST_MS || ts.saturating_sub(now_ms) > REPLAY_FUTURE_MS {
        return Err("window");
    }
    Ok(frame)
}

/// What a node needs BEFORE any signature work (§W8.3 step 2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peek {
    /// The same key [`frame_check`] would report for this inner blob.
    pub seen_key: String,
    /// The frame says it is a `ptt` segment (which admission budget to charge).
    pub claims_ptt: bool,
    /// The frame carries a `c` of capsule shape (NOT verified): a duplicate
    /// with one may still be a capsule upgrade (§W8.3 step 2).
    pub carries_capsule: bool,
    /// The outer `hops` as written (NOT verified, and never signed): an
    /// integer in `[0, 16]`, else `None`. A duplicate from whose `hops` the
    /// frame would be relayed may still be a relay upgrade.
    pub hops: Option<u64>,
}

/// The seen key of a frame without verifying it: bounded input, one JSON
/// object, a canonical `b`. `None` for anything else (charge the general
/// budget and drop).
pub fn frame_peek(bytes: &[u8]) -> Option<Peek> {
    if bytes.len() > MAX_FRAME_BYTES {
        return None;
    }
    let o = strict_json::parse_object(std::str::from_utf8(bytes).ok()?)?;
    let blob = strict_json::b64(o.get("b")?.as_str()?)?;
    // flags ‖ sig_pub ‖ from ‖ toIdx ‖ len ‖ nlen ‖ "ptt"
    let name_at = 1 + SIG_PUB_LEN + UID_LEN + TO_IDX_BYTES + 2;
    let claims_ptt = blob.first() == Some(&FLAGS_NAMED_TO) && blob.get(name_at..name_at + 4) == Some(&[3, b'p', b't', b't'][..]);
    let carries_capsule = o.get("c").and_then(Value::as_str).is_some_and(is_courier_shape);
    let hops = o.get("hops").and_then(strict_json::uint).filter(|h| *h <= MAX_HOPS);
    Some(Peek { seen_key: b64(&sha256(&blob)[..16]), claims_ptt, carries_capsule, hops })
}

// ───────────────────────────── forward rule ─────────────────────────────

/// The forward rule (wire-1.1 §W8.4): `Some(hops + 1)` when a frame with
/// these SIGNED `ttl` / `L` and this received `hops` is relayed, `None` when
/// it is not.
///
/// ```text
/// forward iff  hops < ttl  AND  ( L absent  OR  floor(L / 2^(hops+1)) ≥ 1 )
/// ```
pub fn forward_hops(ttl: u64, hops: u64, l: Option<u64>) -> Option<u64> {
    if hops >= ttl {
        return None;
    }
    let next = hops.checked_add(1)?;
    if let Some(l) = l {
        // A shift of 64 or more is floor(L / 2^k) = 0.
        if u32::try_from(next).ok().and_then(|k| l.checked_shr(k)).unwrap_or(0) < 1 {
            return None;
        }
    }
    Some(next)
}

/// The frame a relay re-emits for a VERIFIED frame, or `None` when it does
/// not relay it. A canonical re-serialization — the eight known keys with
/// `hops` incremented, and `c` when it is the sender's own capsule; every other outer key
/// is dropped, so nobody can hang unsigned ballast on somebody's valid frame.
/// A frame of a name this build does not know is relayed only with `L`
/// present and a payload of at most 2048 bytes.
pub fn forwarded_json(frame: &Frame) -> Option<String> {
    if !is_relayable_kind(frame) {
        return None;
    }
    let hops = forward_hops(frame.ttl, frame.hops, frame.l)?;
    Some(outer_json(&frame.id, frame.ttl, hops, frame.l, frame.mode, frame.ts, &frame.b, frame.courier.as_deref()))
}

/// A frame of a name this build does not know is relayed only when it is
/// small and L-bounded; every other kind is relayed by the forward rule alone.
fn is_relayable_kind(frame: &Frame) -> bool {
    !matches!(frame.kind, FrameKind::Named(_)) || (frame.l.is_some() && frame.payload.len() <= UNKNOWN_RELAY_PAYLOAD_MAX)
}

/// `{"v":2,"id","ttl","hops"[,"L"],"mode","ts","b"[,"c"]}`.
#[allow(clippy::too_many_arguments)]
fn outer_json(id: &str, ttl: u64, hops: u64, l: Option<u64>, mode: MeshMode, ts: u64, b: &str, c: Option<&str>) -> String {
    let mut o = format!("{{\"v\":2,\"id\":{},\"ttl\":{ttl},\"hops\":{hops}", Value::String(id.to_string()));
    if let Some(l) = l {
        o.push_str(&format!(",\"L\":{l}"));
    }
    // `b` and `c` are base64: nothing in them needs JSON escaping.
    o.push_str(&format!(",\"mode\":\"{}\",\"ts\":{ts},\"b\":\"{b}\"", mode.as_str()));
    if let Some(c) = c {
        o.push_str(&format!(",\"c\":\"{c}\""));
    }
    o.push('}');
    o
}

// ───────────────────────────── addressing ─────────────────────────────

/// The rotating recipient tag (04 §8) from raw keys:
/// `SHA-512(box.before(peerPub, myPriv) ‖ BE32(floor(ts / 3 600 000)))[0..8]`.
pub fn to_idx_bytes(my_identity_priv: &[u8; 32], peer_identity_pub: &[u8; 32], ts_ms: u64) -> [u8; TO_IDX_BYTES] {
    let shared = box_before(peer_identity_pub, my_identity_priv);
    let mut buf = [0u8; 36];
    buf[..32].copy_from_slice(&shared);
    // ts < 2^53, so the epoch fits a u32 many times over.
    buf[32..].copy_from_slice(&((ts_ms / 3_600_000) as u32).to_be_bytes());
    let mut out = [0u8; TO_IDX_BYTES];
    out.copy_from_slice(&sha512(&buf)[..TO_IDX_BYTES]);
    out
}

/// «Addressed to me» for a frame from `from.uid`: its tag equals the tag
/// computed with the cached identity key OF THAT SENDER (not «of anyone I
/// know»: the tag is sender-bound). Constant time.
pub fn to_idx_matches(frame: &Frame, my_identity_priv: &[u8; 32], sender_identity_pub: &[u8; 32]) -> bool {
    let Some(tag) = &frame.to_idx else { return false };
    let mine = to_idx_bytes(my_identity_priv, sender_identity_pub, frame.ts);
    tag.iter().zip(mine.iter()).fold(0u8, |d, (a, b)| d | (a ^ b)) == 0
}

/// The v3 envelope text of a verified `msg`: the payload is ALWAYS padded
/// (`BE32(len) ‖ text ‖ fill`) and always unpadded here. `None` for a
/// payload that is not that, or not UTF-8.
pub fn msg_envelope(frame: &Frame) -> Option<String> {
    if frame.kind != FrameKind::Msg || frame.payload.len() < 4 || frame.payload.len() > MSG_PAYLOAD_MAX {
        return None;
    }
    let p = &frame.payload;
    let len = u32::from_be_bytes([p[0], p[1], p[2], p[3]]) as usize;
    let text = p.get(4..)?.get(..len)?;
    String::from_utf8(text.to_vec()).ok()
}

// ───────────────────────────── builders ─────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildError {
    /// A name outside `^[a-z0-9]{1,8}$`, or reserved.
    Name,
    /// An id that is empty, over 128 bytes, or contains `|`.
    Id,
    /// A payload, body or envelope over its limit (never a wrapped length).
    TooLarge,
    /// The frame would not pass this build's own strict check.
    Profile,
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            BuildError::Name => "mesh: bad kind name",
            BuildError::Id => "mesh: bad frame id",
            BuildError::TooLarge => "mesh: payload too large",
            BuildError::Profile => "mesh: frame violates its profile",
        })
    }
}

/// Who signs a frame: the uid on the air and tweetnacl's 64-byte secret.
#[derive(Clone, Copy)]
pub struct Signer<'a> {
    pub uid: u64,
    pub ed_secret64: &'a [u8; 64],
}

#[allow(clippy::too_many_arguments)]
fn build_frame(
    flags: u8,
    kind: &str,
    signer: Signer<'_>,
    to_idx: Option<[u8; TO_IDX_BYTES]>,
    payload: &[u8],
    payload_text: Option<&str>,
    id: &str,
    ttl: u64,
    l: Option<u64>,
    ts: u64,
) -> Result<String, BuildError> {
    if !is_frame_id(id) {
        return Err(BuildError::Id);
    }
    let len = u16::try_from(payload.len()).map_err(|_| BuildError::TooLarge)?;
    let mut sig_pub = [0u8; 32];
    sig_pub.copy_from_slice(&signer.ed_secret64[32..]);
    let text = payload_text.map_or_else(|| b64(payload), str::to_string);
    let signed = binding(id, ts, signer.uid, to_idx.as_ref(), ttl, l, MeshMode::Realtime, kind, &text);
    let sig = ed25519_sign(signer.ed_secret64, signed.as_bytes());
    let mut blob = Vec::with_capacity(1 + 32 + 8 + 8 + 2 + payload.len() + 64);
    blob.push(flags);
    blob.extend_from_slice(&sig_pub);
    blob.extend_from_slice(&signer.uid.to_be_bytes());
    if let Some(t) = &to_idx {
        blob.extend_from_slice(t);
    }
    blob.extend_from_slice(&len.to_be_bytes());
    blob.extend_from_slice(payload);
    blob.extend_from_slice(&sig);
    let json = outer_json(id, ttl, 0, l, MeshMode::Realtime, ts, &b64(&blob), None);
    // A builder never emits what the receiver side of this same build rejects.
    frame_parse(json.as_bytes()).map(|_| json).map_err(|_| BuildError::Profile)
}

/// A realtime frame of a named kind: `payload = BE8(nlen) ‖ name ‖ body`.
/// With `to_idx` the flags are `0x82`, without `0x80`.
#[allow(clippy::too_many_arguments)]
pub fn build_named_frame(
    name: &str,
    body: &[u8],
    signer: Signer<'_>,
    to_idx: Option<[u8; TO_IDX_BYTES]>,
    id: &str,
    ttl: u64,
    l: Option<u64>,
    ts: u64,
) -> Result<String, BuildError> {
    if !is_name(name.as_bytes()) || RESERVED_NAMES.contains(&name) {
        return Err(BuildError::Name);
    }
    let mut payload = Vec::with_capacity(1 + name.len() + body.len());
    payload.push(name.len() as u8);
    payload.extend_from_slice(name.as_bytes());
    payload.extend_from_slice(body);
    let flags = if to_idx.is_some() { FLAGS_NAMED_TO } else { FLAGS_NAMED };
    build_frame(flags, name, signer, to_idx, &payload, None, id, ttl, l, ts)
}

// ── ptt ──

pub const PTT_BODY_VERSION: u8 = 0x01;
pub const PTT_SFLAG_LAST: u8 = 0x01;
pub const PTT_SFLAG_HAS_KEY: u8 = 0x02;
pub const PTT_KEY_WIRE_MAX: usize = 8192;

/// One push-to-talk segment as a mesh `ptt` frame carries it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PttSegment {
    pub ptt_id: String,
    pub tx: [u8; 16],
    pub seq: u32,
    /// A copy of the chunk's own LAST flag; the two MUST agree after the
    /// chunk is opened (the chunk's is the authenticated one).
    pub last: bool,
    /// The v3 envelope of the key plaintext, while the sender attaches it.
    pub key_wire: Option<String>,
    pub chunk: Vec<u8>,
}

/// The body of a mesh `ptt` frame:
/// `0x01 ‖ sflags ‖ tx[16] ‖ BE16(seq) ‖ [BE16(wlen) ‖ w] ‖ chunk`.
pub fn ptt_body(tx: &[u8; 16], seq: u32, last: bool, key_wire: Option<&str>, chunk: &[u8]) -> Result<Vec<u8>, BuildError> {
    let seq = u16::try_from(seq).map_err(|_| BuildError::Profile)?;
    let mut body = vec![PTT_BODY_VERSION, if last { PTT_SFLAG_LAST } else { 0 } | if key_wire.is_some() { PTT_SFLAG_HAS_KEY } else { 0 }];
    body.extend_from_slice(tx);
    body.extend_from_slice(&seq.to_be_bytes());
    if let Some(w) = key_wire {
        if w.is_empty() || w.len() > PTT_KEY_WIRE_MAX {
            return Err(BuildError::TooLarge);
        }
        body.extend_from_slice(&(w.len() as u16).to_be_bytes());
        body.extend_from_slice(w.as_bytes());
    }
    body.extend_from_slice(chunk);
    if body.len() > PTT_BODY_MAX {
        return Err(BuildError::TooLarge);
    }
    Ok(body)
}

/// A mesh `ptt` frame for segment `seq` of transmission `ptt_id`, addressed
/// by the rotating tag. Signed `ttl` 0 (no relay rule forwards it), realtime
/// (never queued), no `L`, no `c`; outer id `<pttId>.<seq>`.
#[allow(clippy::too_many_arguments)]
pub fn build_ptt_frame(
    signer: Signer<'_>,
    my_identity_priv: &[u8; 32],
    peer_identity_pub: &[u8; 32],
    ptt_id: &str,
    seq: u32,
    last: bool,
    key_wire: Option<&str>,
    chunk: &[u8],
    now_ms: u64,
) -> Result<String, BuildError> {
    let tx = ptt_id_bytes(ptt_id).ok_or(BuildError::Id)?;
    let body = ptt_body(&tx, seq, last, key_wire, chunk)?;
    let to_idx = to_idx_bytes(my_identity_priv, peer_identity_pub, now_ms);
    build_named_frame(NAME_PTT, &body, signer, Some(to_idx), &format!("{ptt_id}.{seq}"), 0, None, now_ms)
}

/// The segment of a verified `ptt` frame. `None`: another kind, a body that
/// is not the canonical layout, or an outer id that is not `<pttId>.<seq>`
/// of the body.
pub fn ptt_parse(frame: &Frame) -> Option<PttSegment> {
    if frame.kind != FrameKind::Ptt {
        return None;
    }
    let body = frame.body();
    if body.len() < 2 + 16 + 2 || body[0] != PTT_BODY_VERSION || body[1] & !(PTT_SFLAG_LAST | PTT_SFLAG_HAS_KEY) != 0 {
        return None;
    }
    let tx: [u8; 16] = body[2..18].try_into().ok()?;
    let seq = u16::from_be_bytes([body[18], body[19]]) as u32;
    let mut p = 20;
    let key_wire = if body[1] & PTT_SFLAG_HAS_KEY != 0 {
        let wlen = u16::from_be_bytes([*body.get(p)?, *body.get(p + 1)?]) as usize;
        p += 2;
        if wlen == 0 || wlen > PTT_KEY_WIRE_MAX {
            return None;
        }
        let w = std::str::from_utf8(body.get(p..p + wlen)?).ok()?.to_string();
        p += wlen;
        Some(w)
    } else {
        None
    };
    let chunk = body.get(p..)?.to_vec();
    let ptt_id = ptt_id_text(&tx);
    // A transmission id is a UUIDv4, and the frame id names this segment.
    ptt_id_bytes(&ptt_id)?;
    if chunk.is_empty() || frame.id != format!("{ptt_id}.{seq}") {
        return None;
    }
    Some(PttSegment { ptt_id, tx, seq, last: body[1] & PTT_SFLAG_LAST != 0, key_wire, chunk })
}

// ── ctl ──

/// A mesh `ctl` frame: the v3 envelope of a ctl-class plaintext for a peer
/// reachable only by radio. `ttl` 0 or 1, realtime, no `L`, no `c`; the
/// outer id is the `messageId` (= the inner `id`).
#[allow(clippy::too_many_arguments)]
pub fn build_ctl_frame(
    signer: Signer<'_>,
    my_identity_priv: &[u8; 32],
    peer_identity_pub: &[u8; 32],
    message_id: &str,
    envelope_wire: &str,
    ttl: u64,
    now_ms: u64,
) -> Result<String, BuildError> {
    if envelope_wire.is_empty() || envelope_wire.len() > CTL_BODY_MAX {
        return Err(BuildError::TooLarge);
    }
    let to_idx = to_idx_bytes(my_identity_priv, peer_identity_pub, now_ms);
    build_named_frame(NAME_CTL, envelope_wire.as_bytes(), signer, Some(to_idx), message_id, ttl, None, now_ms)
}

/// The envelope text of a verified `ctl` frame.
pub fn ctl_parse(frame: &Frame) -> Option<String> {
    if frame.kind != FrameKind::Ctl {
        return None;
    }
    String::from_utf8(frame.body().to_vec()).ok()
}

// ── blind ACK ──

/// The payload of a blind ACK: `b64(SHA-256(UTF-8(id))[0..16])`.
pub fn ack2_payload(acked_id: &str) -> String {
    b64(&sha256(acked_id.as_bytes())[..16])
}

/// The one-time public key a blind ACK for this seed is signed with.
pub fn ack2_public(seed: &[u8; 32]) -> [u8; 32] {
    ed25519_keypair_from_seed(seed).1
}

/// The blind ACK frame for `acked_id` (wire-1.1 §W8.5): `from.uid` 0, the
/// one-time key of `seed` (= `ratchet::mesh_ack_seed(sid, id)`), `ttl` 4,
/// realtime, no `L`, a fresh UUID as the outer id (16 bytes drawn).
pub fn build_ack2(seed: &[u8; 32], acked_id: &str, now_ms: u64, rng: &mut dyn Rng) -> Result<String, BuildError> {
    if acked_id.is_empty() {
        return Err(BuildError::Id);
    }
    let (secret, _) = ed25519_keypair_from_seed(seed);
    let payload = ack2_payload(acked_id);
    let id = secure_uuid(rng);
    build_frame(FLAGS_ACK, "ack", Signer { uid: 0, ed_secret64: &secret }, None, payload.as_bytes(), Some(&payload), &id, ACK_TTL_MAX, None, now_ms)
}

/// The author's test: this verified frame is the blind ACK for `acked_id`
/// made by a holder of the session whose key is `expected_public`. Only the
/// author can tell — to every other node a forged blind ACK looks the same,
/// which is why an ACK never prunes anything on a relay or a courier.
pub fn ack2_matches(frame: &Frame, expected_public: &[u8; 32], acked_id: &str) -> bool {
    let same_key = frame.sig_pub.iter().zip(expected_public).fold(0u8, |d, (a, b)| d | (a ^ b)) == 0;
    frame.kind == FrameKind::AckBlind && same_key && frame.payload == ack2_payload(acked_id).as_bytes()
}

// ───────────────────────────── courier capsule ─────────────────────────────

pub const COURIER_VERSION: u8 = 0x01;
pub const COURIER_SIG_LABEL: &str = "mrenzo-courier-v1";
pub const COURIER_NONCE_LABEL: &str = "mrenzo-courier-nonce-v1";
/// The boxed plaintext: `0x01 ‖ BE64(to)`.
const COURIER_PT_LEN: usize = 1 + 8;
/// `crypto_box` of it: 16 bytes of tag.
const COURIER_BOX_LEN: usize = COURIER_PT_LEN + 16;
const COURIER_EPH_LEN: usize = 32;
/// `0x01 ‖ kid ‖ eph_pub[32] ‖ box[25] ‖ csig[64]`.
pub const COURIER_CAPSULE_BYTES: usize = 2 + COURIER_EPH_LEN + COURIER_BOX_LEN + SIG_LEN;

/// What `csig` signs: this exact frame together with this exact sealed
/// recipient (`sealed` = `eph_pub ‖ box`). The recipient uid is inside the
/// box, so the string names nothing a bystander does not already see — and
/// anyone can check it.
pub fn courier_csig_message(id: &str, ts: u64, from_uid: u64, kid: u8, inner_blob: &[u8], sealed: &[u8]) -> String {
    format!("{COURIER_SIG_LABEL}|{id}|{ts}|{from_uid}|{kid}|{}|{}", b64(&sha256(inner_blob)), b64(&sha256(sealed)))
}

fn courier_nonce(eph_pub: &[u8; 32], courier_pub: &[u8; 32]) -> [u8; 24] {
    // The ephemeral key is used once, so a nonce derived from it is unique.
    let mut m = COURIER_NONCE_LABEL.as_bytes().to_vec();
    m.extend_from_slice(eph_pub);
    m.extend_from_slice(courier_pub);
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&sha256(&m)[..24]);
    nonce
}

/// A capsule of the one layout this level knows, split into its fields.
struct Capsule {
    kid: u8,
    eph_pub: [u8; 32],
    /// `eph_pub ‖ box`: what `csig` covers.
    sealed: Vec<u8>,
    csig: [u8; 64],
}

impl Capsule {
    /// `None` for anything but canonical base64 of exactly 123 bytes that
    /// starts with the version byte.
    fn parse(c: &str) -> Option<Capsule> {
        let raw = strict_json::b64(c)?;
        if raw.len() != COURIER_CAPSULE_BYTES || raw[0] != COURIER_VERSION {
            return None;
        }
        let sealed_end = 2 + COURIER_EPH_LEN + COURIER_BOX_LEN;
        Some(Capsule {
            kid: raw[1],
            eph_pub: raw[2..2 + COURIER_EPH_LEN].try_into().ok()?,
            sealed: raw[2..sealed_end].to_vec(),
            csig: raw[sealed_end..].try_into().ok()?,
        })
    }

    fn boxed(&self) -> &[u8] {
        // `sealed` is exactly `eph_pub ‖ box` (`parse` built it).
        self.sealed.get(COURIER_EPH_LEN..).unwrap_or(&[])
    }

    fn signed_by(&self, id: &str, ts: u64, from_uid: u64, sig_pub: &[u8; 32], inner_blob: &[u8]) -> bool {
        let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(sig_pub) else { return false };
        let msg = courier_csig_message(id, ts, from_uid, self.kid, inner_blob, &self.sealed);
        vk.verify_strict(msg.as_bytes(), &ed25519_dalek::Signature::from_bytes(&self.csig)).is_ok()
    }
}

/// The capsule `c` for the `msg` frame whose inner blob is `inner_blob`
/// (wire-1.1 §W8.7): the recipient uid sealed to the server's courier key,
/// and the sender's signature over this frame and that sealed recipient.
/// 32 bytes drawn (the ephemeral key).
#[allow(clippy::too_many_arguments)]
pub fn courier_capsule_build(
    courier_pub: &[u8; 32],
    kid: u8,
    to_uid: u64,
    id: &str,
    ts: u64,
    from_uid: u64,
    ed_secret64: &[u8; 64],
    inner_blob: &[u8],
    rng: &mut dyn Rng,
) -> String {
    let eph = x25519_keypair(rng);
    let mut pt = Vec::with_capacity(COURIER_PT_LEN);
    pt.push(COURIER_VERSION);
    pt.extend_from_slice(&to_uid.to_be_bytes());
    let mut sealed = eph.public.to_vec();
    sealed.extend_from_slice(&box_seal(&pt, &courier_nonce(&eph.public, courier_pub), courier_pub, &eph.private));
    let csig = ed25519_sign(ed_secret64, courier_csig_message(id, ts, from_uid, kid, inner_blob, &sealed).as_bytes());
    let mut c = vec![COURIER_VERSION, kid];
    c.extend_from_slice(&sealed);
    c.extend_from_slice(&csig);
    b64(&c)
}

/// The capsule was made by the signer of this frame, for this frame: `csig`
/// verifies (strictly) under the frame's own `sig_pub` over the frame's id,
/// timestamp, sender, inner blob and the sealed recipient. Needs no secret —
/// every relay and courier runs it, which is what keeps a bystander's
/// capsule out of the courier stores and off the air.
pub fn courier_capsule_verifies(c: &str, id: &str, ts: u64, from_uid: u64, sig_pub: &[u8; 32], inner_blob: &[u8]) -> bool {
    Capsule::parse(c).is_some_and(|capsule| capsule.signed_by(id, ts, from_uid, sig_pub, inner_blob))
}

/// The capsule of a 1.0.0-shaped envelope RECORD: `Some` only when the
/// envelope's own signer made it for exactly the frame this record packs to.
///
/// The record is what the 1.0.0-shaped entry points exchange with the host
/// (unpack, the queue JSON, pack), and its `courier` is just a string: one a
/// stranger's frame was unpacked into, one read back from a stored queue, one
/// the host filled in. This is the single check all of those doors run, in
/// both directions, so a capsule that is merely of the right shape neither
/// comes out of the core nor goes back onto the air or into a queue through
/// it. It says nothing about the FRAME signature (that is `frame_parse`).
pub fn envelope_capsule(env: &MeshEnvelope) -> Option<String> {
    let c = env.courier.as_deref()?;
    if env.kind == Some(MeshKind::Ack) {
        return None;
    }
    // The numbers of a record are `f64` (the 1.0.0 model): only exact
    // integers name a frame anybody could have signed a capsule for.
    let exact = |f: f64| ((0.0..=MAX_SAFE_INT as f64).contains(&f) && f.fract() == 0.0).then_some(f as u64);
    let (ts, from_uid) = (exact(env.ts)?, exact(env.from.uid)?);
    let sig_pub = strict_json::b64_n::<32>(&env.from.sig_pub)?;
    let blob = crate::mesh_envelope::encode_inner_blob(env).ok()?;
    courier_capsule_verifies(c, &env.id, ts, from_uid, &sig_pub, &blob).then(|| c.to_string())
}

/// The recipient a courier frame names, as the SERVER establishes it: the
/// frame is a `msg` whose capsule its own signer made (checked again here,
/// whatever produced the `Frame`), the capsule is for key `kid`, and the box
/// opens under the courier private key. `None` otherwise. (Reference for the
/// Go implementation; the vectors pin it.)
pub fn courier_open(frame: &Frame, kid: u8, courier_priv: &[u8; 32]) -> Option<u64> {
    if frame.kind != FrameKind::Msg {
        return None;
    }
    let capsule = Capsule::parse(frame.courier.as_deref()?)?;
    let blob = strict_json::b64(&frame.b)?;
    if capsule.kid != kid || !capsule.signed_by(&frame.id, frame.ts, frame.from_uid, &frame.sig_pub, &blob) {
        return None;
    }
    let courier_pub = crate::primitives::x25519_base(courier_priv);
    let pt = box_open(capsule.boxed(), &courier_nonce(&capsule.eph_pub, &courier_pub), &capsule.eph_pub, courier_priv)?;
    if pt.len() != COURIER_PT_LEN || pt[0] != COURIER_VERSION {
        return None;
    }
    let to_uid = u64::from_be_bytes(pt[1..].try_into().ok()?);
    (1..=MAX_SAFE_INT).contains(&to_uid).then_some(to_uid)
}

/// The object the server routes for an accepted courier frame, as if `from`
/// had sent it: exactly what the 1.0.0 WS drain sends plus `transport`. No
/// `type`, no `action` — with either, a 1.0.0 receiver drops the frame.
pub fn courier_routed_json(to_uid: u64, message_id: &str, envelope: &str) -> String {
    format!(
        "{{\"toUserId\":{to_uid},\"messageId\":{},\"text\":{},\"encrypted\":true,\"transport\":\"mesh-courier\"}}",
        Value::String(message_id.to_string()),
        Value::String(envelope.to_string())
    )
}

// ───────────────────────────── link hello and admission ─────────────────────────────

/// The wire level a link hello announces (this build).
pub const LINK_LEVEL: u32 = 2;
pub const HELLO_NAME_MAX_UTF16: usize = 64;
pub const HELLO_MAX_BYTES: usize = 512;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkHello {
    pub name: Option<String>,
    /// The peer's wire level: 1 when it announces none (a 1.0.0 node).
    pub w: u32,
}

/// `{"hello":1,"name":"<handle>","w":2}` (BLE) / `{"hello":1,"w":2}` (MPC).
/// A 1.0.0 BLE node reads only `name`; a 1.0.0 MPC node counts the frame as
/// one malformed frame.
pub fn link_hello_json(name: Option<&str>) -> String {
    match name {
        Some(n) => format!("{{\"hello\":1,\"name\":{},\"w\":{LINK_LEVEL}}}", Value::String(n.to_string())),
        None => format!("{{\"hello\":1,\"w\":{LINK_LEVEL}}}"),
    }
}

/// A link hello; `None` when the frame is not one (no `hello` key). The hint
/// is unauthenticated on purpose: it gates airtime (named frames go only to
/// links that announced `w ≥ 2`), never trust.
pub fn link_hello_parse(bytes: &[u8]) -> Option<LinkHello> {
    if bytes.len() > HELLO_MAX_BYTES {
        return None;
    }
    let o = strict_json::parse_object(std::str::from_utf8(bytes).ok()?)?;
    o.get("hello")?;
    let name = o
        .get("name")
        .and_then(Value::as_str)
        .filter(|n| !n.is_empty() && n.encode_utf16().count() <= HELLO_NAME_MAX_UTF16)
        .map(str::to_string);
    let w = o.get("w").and_then(strict_json::uint).filter(|w| *w >= 2).map_or(1, |w| w.min(65_535) as u32);
    Some(LinkHello { name, w })
}

/// The general budget of a link: 30 new frames per 60 s (the 1.0.0 numbers).
pub const GENERAL_FRAMES: usize = 30;
pub const GENERAL_WINDOW_MS: i64 = 60_000;
/// The `ptt` budget of a link: a bucket of 8 refilled at one token a second.
pub const PTT_BURST: i64 = 8;
pub const PTT_REFILL_MS: i64 = 1000;
/// Link hellos one link may send per window, OUTSIDE the frame budget:
/// frames cannot starve the hello and a hello cannot eat frame slots.
pub const HELLO_PER_WINDOW: usize = 4;

/// Admission state of one radio link (wire-1.1 §W7.2, §W8.3 step 2). A frame
/// that is not a verified duplicate is charged BEFORE its signature is
/// checked — to the `ptt` bucket when it claims to be a `ptt` segment, else
/// to the general window — and dropped unverified when that budget is empty.
/// A `ptt` frame is never relayed, so its sender is the link's own peer: junk
/// that claims `ptt` can only burn the bucket of the link it came in on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkBudget {
    general: VecDeque<i64>,
    hello: VecDeque<i64>,
    /// Milli-tokens.
    ptt: i64,
    ptt_at: i64,
}

impl LinkBudget {
    pub fn new(now_ms: i64) -> LinkBudget {
        LinkBudget { general: VecDeque::new(), hello: VecDeque::new(), ptt: PTT_BURST * PTT_REFILL_MS, ptt_at: now_ms }
    }

    /// One slot of `window` with room for `limit` entries per
    /// [`GENERAL_WINDOW_MS`]. An entry dated after `now` is from before the
    /// clock was set back and ages out at once.
    fn slot(window: &mut VecDeque<i64>, limit: usize, now_ms: i64) -> bool {
        while window.front().is_some_and(|t| now_ms.saturating_sub(*t) >= GENERAL_WINDOW_MS || *t > now_ms) {
            window.pop_front();
        }
        if window.len() >= limit {
            return false;
        }
        window.push_back(now_ms);
        true
    }

    /// Charges one link hello: 4 per window, in an allowance of its own.
    /// `false`: past the allowance — the hello is ignored and costs one
    /// general slot like any other frame.
    pub fn admit_hello(&mut self, now_ms: i64) -> bool {
        if Self::slot(&mut self.hello, HELLO_PER_WINDOW, now_ms) {
            return true;
        }
        let _ = Self::slot(&mut self.general, GENERAL_FRAMES, now_ms);
        false
    }

    /// Charges one frame; `false` = drop it without verifying.
    pub fn admit(&mut self, claims_ptt: bool, now_ms: i64) -> bool {
        if claims_ptt {
            // A clock that steps back refills nothing.
            let elapsed = now_ms.saturating_sub(self.ptt_at).max(0);
            self.ptt = self.ptt.saturating_add(elapsed).min(PTT_BURST * PTT_REFILL_MS);
            self.ptt_at = now_ms;
            if self.ptt < PTT_REFILL_MS {
                return false;
            }
            self.ptt -= PTT_REFILL_MS;
            return true;
        }
        Self::slot(&mut self.general, GENERAL_FRAMES, now_ms)
    }
}

// ───────────────────────────── the seen set ─────────────────────────────

/// Frames a node remembers by default (the 1.0.0 radio kept 1000 ids).
pub const SEEN_CAPACITY: usize = 2000;

/// Radios a node keeps apart. A frame is relayed on the transport it was
/// heard on and on no other (§W8.4: no MPC↔BLE bridging), so «this node
/// relayed the frame» is a fact per radio — a LANE, numbered by the host
/// (iOS: 0 = MultipeerConnectivity, 1 = Bluetooth LE). Lanes `0..MAX_LANES`
/// exist; a call that names any other lane does nothing (the frame is a
/// duplicate, nothing is recorded).
pub const MAX_LANES: usize = 4;

/// What [`SeenSet::admit`] says about a frame BEFORE any signature work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// Not seen: charge the link and run the check.
    New,
    /// Verified before, and this copy can add nothing: drop it, free.
    Duplicate,
    /// Verified before, but this copy may still change what an UNSIGNED
    /// field decides (see [`SeenSet`]): charge the link, run the check, and
    /// then do only what [`SeenSet::record`] returns.
    Upgrade,
}

/// One frame to put on the air, and the radio to put it on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Emission {
    pub lane: u8,
    /// Rebuilt canonically like [`forwarded_json`] does.
    pub frame: String,
}

/// What [`SeenSet::record`] says to do with a frame that passed the check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recorded {
    /// The first verified copy of this frame on ANY lane: act on it
    /// (deliver, the ACK rules, the relay and courier stores). `false` for
    /// every later copy: it is never delivered, acknowledged or stored a
    /// second time.
    pub first: bool,
    /// The frames to emit now, in lane order (named kinds only to links
    /// that announced `w ≥ 2`): at most one per lane. On the lane of this
    /// copy, a relay of it; on any lane where the node relayed earlier,
    /// that emission once more when this copy brought the capsule — with
    /// the `hops` of the earlier emission, not those of this copy. Every
    /// one of them carries the verified capsule when the set knows one,
    /// also when the copy in hand has none.
    pub forward: Vec<Emission>,
    /// This copy brought the first VERIFIED capsule for a frame seen
    /// without one: the relay-store entry of the frame takes `c`, and a
    /// courier node puts the frame into its courier store. Independent of
    /// `forward`: the capsule is kept even when nothing is emitted now.
    pub capsule_upgrade: bool,
}

/// What this node did with a frame on one lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lane {
    /// Nothing yet: a copy from whose `hops` the frame may be relayed
    /// still is (a relay upgrade).
    Idle,
    /// Relayed, with these `hops` (`hops + 1` of the copy it relayed).
    Relayed(u64),
    /// Transmitted by the node itself — its own frame, or a stored one it
    /// flushes ([`SeenSet::mark_own`]): never relayed here, and re-sent
    /// only by whatever sent it (the queue), never by the set.
    Sent,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SeenEntry {
    /// The SIGNED budget of the frame (the same on every valid copy).
    ttl: u64,
    l: Option<u64>,
    /// This kind is relayed at all (an unknown name may be too large for it).
    relayable: bool,
    /// A `msg`: the only kind that carries a capsule.
    msg: bool,
    lanes: [Lane; MAX_LANES],
    /// The first verified capsule seen for the frame, on whatever lane.
    /// Kept as text, not as a flag: an emission must be able to carry it
    /// when the copy that triggers the emission has none. Shared, so
    /// copying the set is cheap.
    capsule: Option<Arc<str>>,
}

/// The frames a node VERIFIED, keyed by [`Frame::seen_key`] (the signed
/// content, never the bare id), with the two facts an unsigned field decides
/// (wire-1.1 §W8.3):
///
/// - **`hops` is covered by no signature.** A copy with an inflated `hops`
///   is a valid frame that nobody relays. If the first copy heard decided
///   for good, anybody in range could stop the nodes around it from relaying
///   a frame by sending such a copy first. So the set remembers, per lane,
///   whether THIS node relayed the frame and with which `hops`: a later copy
///   from whose `hops` it would be relayed is admitted once more (a relay
///   upgrade).
/// - **A capsule may be missing from a copy** (a 1.0.0 carrier rebuilds the
///   frame without it; anybody can strip it). The set remembers the verified
///   capsule itself: a later copy that claims one is admitted once more (a
///   capsule upgrade), and from then on the capsule belongs to the frame.
///
/// The two levers are independent, and so are the two memories. Whatever
/// order the copies arrive in, and on whichever radios — the capsule on a
/// copy whose `hops` allow no relay, a relayable copy without the capsule —
/// **every emission made once a verified capsule is known carries it**, and
/// on every lane where the node relayed before it knew the capsule it emits
/// the frame once more, with the capsule, at the `hops` it relayed with
/// there (the `hops` of the copy that brought the capsule are as unsigned as
/// any, and decide nothing).
///
/// **Lanes.** «Acted on» and the capsule are facts of the node; «relayed» is
/// a fact of each radio. A node with two radios that hears a frame on the
/// first relays it there — and a copy on the second radio is still a relay
/// upgrade THERE, or a neighbour reachable only by that radio would never
/// get it. A radio with nobody to pass the frame on to (`can_relay` false)
/// relays nothing and is not marked: a copy that comes when somebody is
/// there still goes.
///
/// A node therefore emits one frame at most twice per lane, and only a copy
/// that passed the whole check — signature of the frame, signature of the
/// capsule — can cause any emission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeenSet {
    map: HashMap<String, SeenEntry>,
    /// Insertion order = age.
    order: VecDeque<String>,
    capacity: usize,
}

impl Default for SeenSet {
    fn default() -> SeenSet {
        SeenSet::new(SEEN_CAPACITY)
    }
}

impl SeenSet {
    /// `capacity` frames are remembered (at least 16); beyond it the oldest go.
    pub fn new(capacity: usize) -> SeenSet {
        SeenSet { map: HashMap::new(), order: VecDeque::new(), capacity: capacity.max(16) }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn contains(&self, seen_key: &str) -> bool {
        self.map.contains_key(seen_key)
    }

    /// Forgets everything (handle rotation, the radios stopped): senders
    /// flush again and a recipient must be able to answer a frame it already
    /// has with its ACK once more.
    pub fn clear(&mut self) {
        self.map.clear();
        self.order.clear();
    }

    /// The decision before any signature work (§W8.3 step 2), for a copy
    /// heard on `lane`. `can_relay`: that radio has somebody to pass the
    /// frame on to right now (a link other than the one the copy came in
    /// on) — without one a relay upgrade buys nothing and is not admitted.
    /// Nothing of an unverified copy is USED: its claims only buy the check.
    pub fn admit(&self, peek: &Peek, lane: u8, can_relay: bool) -> Admission {
        let here = usize::from(lane);
        if here >= MAX_LANES {
            return Admission::Duplicate;
        }
        let Some(e) = self.map.get(&peek.seen_key) else { return Admission::New };
        let capsule_upgrade = e.msg && e.capsule.is_none() && peek.carries_capsule;
        let relay_upgrade = can_relay && e.relayable && e.lanes[here] == Lane::Idle && peek.hops.is_some_and(|h| forward_hops(e.ttl, h, e.l).is_some());
        if capsule_upgrade || relay_upgrade {
            Admission::Upgrade
        } else {
            Admission::Duplicate
        }
    }

    fn insert(&mut self, key: &str, entry: SeenEntry) {
        if self.map.insert(key.to_string(), entry).is_none() {
            self.order.push_back(key.to_string());
            while self.order.len() > self.capacity {
                if let Some(old) = self.order.pop_front() {
                    self.map.remove(&old);
                }
            }
        }
    }

    /// Records a frame that PASSED [`frame_check`], heard on `lane`, and
    /// says what to do with it (§W8.3 steps 4–6). `can_relay` as in
    /// [`SeenSet::admit`]: with `false` nothing is relayed on this lane and
    /// the lane stays open for a later copy.
    pub fn record(&mut self, frame: &Frame, lane: u8, can_relay: bool) -> Recorded {
        let here = usize::from(lane);
        if here >= MAX_LANES {
            return Recorded { first: false, forward: Vec::new(), capsule_upgrade: false };
        }
        let relayable = is_relayable_kind(frame);
        // The `hops` THIS copy would be relayed with, by the forward rule.
        let next = if relayable && can_relay { forward_hops(frame.ttl, frame.hops, frame.l) } else { None };
        // Every field but `hops` and `c` is signed, so it is the same on
        // every copy that passed the check: an emission is rebuilt from the
        // copy in hand, with the hops and the capsule the SET decides.
        let emit = |on: u8, hops: u64, c: Option<&str>| Emission { lane: on, frame: outer_json(&frame.id, frame.ttl, hops, frame.l, frame.mode, frame.ts, &frame.b, c) };
        // `courier` is `Some` only on a `msg`, and only when its `csig` verified.
        let capsule: Option<Arc<str>> = frame.courier.as_deref().map(Arc::from);
        match self.map.get_mut(&frame.seen_key) {
            None => {
                let mut lanes = [Lane::Idle; MAX_LANES];
                let mut forward = Vec::new();
                if let Some(h) = next {
                    lanes[here] = Lane::Relayed(h);
                    forward.push(emit(lane, h, capsule.as_deref()));
                }
                self.insert(&frame.seen_key, SeenEntry { ttl: frame.ttl, l: frame.l, relayable, msg: frame.kind == FrameKind::Msg, lanes, capsule });
                Recorded { first: true, forward, capsule_upgrade: false }
            }
            Some(e) => {
                let capsule_upgrade = e.capsule.is_none() && capsule.is_some();
                if capsule_upgrade {
                    // Kept whether or not anything goes on the air now: the
                    // copy that brings the capsule may be one nobody relays.
                    e.capsule = capsule;
                }
                let mut forward = Vec::new();
                for (on, state) in (0u8..).zip(e.lanes.iter_mut()) {
                    match *state {
                        // Not relayed on the lane of this copy yet: its
                        // `hops` decide (a relay upgrade), and the emission
                        // carries the capsule the set knows, whether this
                        // copy has it or not.
                        Lane::Idle if on == lane => {
                            if let Some(h) = next {
                                *state = Lane::Relayed(h);
                                forward.push(emit(on, h, e.capsule.as_deref()));
                            }
                        }
                        // Relayed there already: once more, and only to send
                        // the capsule after the copy that travelled without
                        // it — at the `hops` of that emission, whatever this
                        // copy claims and whichever radio it came in on (the
                        // frame is on that radio already: this bridges nothing).
                        Lane::Relayed(h) if capsule_upgrade => forward.push(emit(on, h, e.capsule.as_deref())),
                        _ => {}
                    }
                }
                Recorded { first: false, forward, capsule_upgrade }
            }
        }
    }

    /// Records a frame this node TRANSMITS ITSELF — its own, or a stored one
    /// it is about to flush — before it goes on the air: on every lane its
    /// echo is a duplicate and it is never relayed back. A capsule that
    /// arrives later for it is still reported (`capsule_upgrade`, for the
    /// stores), but the set re-emits nothing: whatever sent the frame sends
    /// it again. `false` when the bytes are not a frame this build would
    /// accept.
    pub fn mark_own(&mut self, frame_bytes: &[u8]) -> bool {
        let Ok(frame) = frame_parse(frame_bytes) else { return false };
        let capsule: Option<Arc<str>> = frame.courier.as_deref().map(Arc::from);
        let sent = |lanes: &mut [Lane; MAX_LANES]| {
            for lane in lanes.iter_mut().filter(|l| **l == Lane::Idle) {
                *lane = Lane::Sent;
            }
        };
        match self.map.get_mut(&frame.seen_key) {
            Some(e) => {
                // Lanes this node relayed on keep their `hops`.
                sent(&mut e.lanes);
                if e.capsule.is_none() {
                    e.capsule = capsule;
                }
            }
            None => {
                let mut lanes = [Lane::Idle; MAX_LANES];
                sent(&mut lanes);
                let entry = SeenEntry { ttl: frame.ttl, l: frame.l, relayable: is_relayable_kind(&frame), msg: frame.kind == FrameKind::Msg, lanes, capsule };
                self.insert(&frame.seen_key, entry);
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_rule_table() {
        // (ttl, hops, L) → forwarded hops
        for (ttl, hops, l, want) in [
            (7, 0, Some(4), Some(1)),
            (7, 1, Some(4), Some(2)),
            (7, 2, Some(4), None),
            (7, 0, Some(1), None),
            (7, 0, Some(2), Some(1)),
            (7, 1, Some(2), None),
            (4, 0, None, Some(1)),
            (4, 3, None, Some(4)),
            (4, 4, None, None),
            (0, 0, None, None),
            (1, 0, None, Some(1)),
            (1, 1, None, None),
            (86_400, 1, Some(4), Some(2)),
            (86_400, 16, None, Some(17)),
            (u64::MAX, u64::MAX - 1, None, Some(u64::MAX)),
            (u64::MAX, 70, Some(u64::MAX), None),
            (u64::MAX, 62, Some(u64::MAX), Some(63)),
        ] {
            assert_eq!(forward_hops(ttl, hops, l), want, "ttl {ttl} hops {hops} L {l:?}");
        }
    }

    #[test]
    fn budgets() {
        let mut b = LinkBudget::new(0);
        assert!((0..30).all(|i| b.admit(false, i)));
        assert!(!b.admit(false, 30), "the 31st general frame in a minute");
        assert!((0..8).all(|_| b.admit(true, 30)), "a transmission does not touch the general budget");
        assert!(!b.admit(true, 30));
        assert!(b.admit(true, 1030) && !b.admit(true, 1030), "one token a second");
        assert!(b.admit(false, 60_000), "the window slides");
        let mut c = LinkBudget::new(1_000_000);
        for _ in 0..8 {
            c.admit(true, 1_000_000);
        }
        assert!(!c.admit(true, 0), "a clock stepping back refills nothing");
        // The hello has an allowance of its own; past it a hello costs a frame slot.
        let mut h = LinkBudget::new(0);
        assert!((0..4).all(|_| h.admit_hello(0)) && !h.admit_hello(0), "four hellos a window");
        assert!((0..29).all(|_| h.admit(false, 1)) && !h.admit(false, 1), "the fifth hello took one general slot");
        assert!(h.admit_hello(60_000), "the allowance slides with the window");
    }

    #[test]
    fn hello() {
        assert_eq!(link_hello_json(Some("A1B2C3D4")), r#"{"hello":1,"name":"A1B2C3D4","w":2}"#);
        assert_eq!(link_hello_json(None), r#"{"hello":1,"w":2}"#);
        assert_eq!(link_hello_parse(br#"{"hello":1,"name":"A1B2C3D4","w":2}"#), Some(LinkHello { name: Some("A1B2C3D4".into()), w: 2 }));
        assert_eq!(link_hello_parse(br#"{"hello":1,"name":"old"}"#), Some(LinkHello { name: Some("old".into()), w: 1 }), "a 1.0.0 hello");
        assert_eq!(link_hello_parse(br#"{"hello":1,"w":"2"}"#).unwrap().w, 1);
        assert_eq!(link_hello_parse(br#"{"hello":1,"w":1e9}"#).unwrap().w, 1);
        assert_eq!(link_hello_parse(br#"{"hello":1,"w":70000}"#).unwrap().w, 65_535);
        assert!(link_hello_parse(br#"{"id":"x"}"#).is_none());
        assert!(link_hello_parse(br#"{"hello":1,"hello":1}"#).is_none());
    }
}
