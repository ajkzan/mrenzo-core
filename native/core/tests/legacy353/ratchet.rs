//! 1:1 Double Ratchet, protocol v3 (build 349; docs/native/protocol/03-crypto.md §3).
//!
//! Every session starts from X3DH v2 (`crate::legacy353::x3dh::x3dh_v2_*`), so it is
//! authenticated to BOTH identity keys; there is no other constructor. Each
//! message is MAC'd over `AD ‖ header ‖ ct` with a key derived per message,
//! and the MAC is checked in constant time before anything is opened.
//! Conformance: docs/native/vectors/ratchetV3.json, ratchetV3Negative.json,
//! skippedCap.json (tests/golden_ratchet_v3.rs).
//!
//! ```text
//! (next_chain, mk) = KDF_CK(chain)                       HKDF info "mrenzo-ratchet-chain-v1" / "…-msg-v1"
//! (k_enc, k_mac)   = HKDF-SHA256(0^32, mk, "mrenzo-ratchet-msg-keys-v3", 64)
//! ct               = nonce(24) ‖ secretbox(UTF-8 typed plaintext, nonce, k_enc)
//! hdr              = 0x03 ‖ dh ‖ BE64(pn) ‖ BE64(n) ‖ xflag ‖ [ik ‖ ed ‖ ek ‖ BE64(spk) ‖ BE64(opk | 2^64−1)]
//! mac              = HMAC-SHA256(k_mac, AD ‖ hdr ‖ ct)
//! ```
//!
//! The RN-compatible v2 ratchet (`initAsSender`/`initAsRecipient`, the Hermes
//! envelope parser, the RN at-rest importer) is gone: no client still speaks
//! it (build 349 replaces every earlier build).

use serde::{Deserialize, Serialize};

use crate::legacy353::plaintext::parse_typed_plaintext;
use mrenzo_core::primitives::{b64, hkdf32, hkdf_sha256, hmac_sha256, secretbox_open, secretbox_seal, x25519, x25519_keypair, KeyPair};
use mrenzo_core::rng::Rng;
use crate::legacy353::x3dh::{PrekeyHeader, X3dhV2Initiation, X3dhV2Secret, AD_LEN_V3};

pub const KDF_INFO_RATCHET: &str = "mrenzo-ratchet-step-v1";
pub const KDF_INFO_CHAIN: &str = "mrenzo-ratchet-chain-v1";
pub const KDF_INFO_MSG: &str = "mrenzo-ratchet-msg-v1";
pub const KDF_INFO_MSG_KEYS: &str = "mrenzo-ratchet-msg-keys-v3";
/// `rb` of a call offer/answer (03 §7): `HKDF(sid, "mrenzo-ratchet-bind-v2|" + payload)`.
pub const KDF_INFO_BIND: &str = "mrenzo-ratchet-bind-v2";
/// Key of the mesh ACK tag (04 §12): `HKDF(sid, "mrenzo-mesh-ack-v2")`.
pub const KDF_INFO_MESH_ACK: &str = "mrenzo-mesh-ack-v2";
pub const WIRE_VERSION: u64 = 3;
pub const HEADER_VERSION_BYTE: u8 = 0x03;
/// A single message may skip at most this many positions of one chain.
pub const MAX_SKIP_PER_MESSAGE: i64 = 1000;
/// Skipped keys kept per session; beyond it the oldest are evicted.
pub const MAX_SKIPPED_TOTAL: usize = 2000;
/// Skipped keys older than this are dropped on load and save.
pub const SKIPPED_TTL_MS: i64 = 14 * 24 * 60 * 60 * 1000;
/// Largest integer every client can carry (JSON numbers < 2^53).
pub const MAX_WIRE_INT: u64 = (1u64 << 53) - 1;
const OPK_ABSENT: u64 = u64::MAX;

// ───────────────────────────── envelope ─────────────────────────────

/// A parsed v3 envelope (03 §3.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub dh: [u8; 32],
    pub pn: u64,
    pub n: u64,
    /// `nonce ‖ secretbox`.
    pub ct: Vec<u8>,
    pub mac: [u8; 32],
    pub x: Option<PrekeyHeader>,
}

/// Why a wire string is not a v3 envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    /// A JSON object whose `v` is anything but the integer 3: an envelope of
    /// an older build («Сообщение отправлено старой версией приложения»).
    Legacy,
    /// Not JSON, not an object, no `v`, or a v3 of the wrong shape.
    NotEnvelope,
}

#[derive(Deserialize)]
struct WireX {
    ik: String,
    ed: String,
    ek: String,
    spk: u64,
    #[serde(default)]
    opk: Option<u64>,
}

#[derive(Deserialize)]
struct WireEnvelope {
    v: u64,
    dh: String,
    pn: u64,
    n: u64,
    ct: String,
    mac: String,
    #[serde(default)]
    x: Option<WireX>,
}

/// Strict standard base64 with padding and canonical trailing bits.
pub fn b64_strict(s: &str) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    STANDARD.decode(s).ok()
}

pub fn b64_strict32(s: &str) -> Option<[u8; 32]> {
    b64_strict(s)?.try_into().ok()
}

impl Envelope {
    /// Typed parse. `v` must be the integer 3; counters and key ids integers
    /// in `[0, 2^53)`; every base64 field canonical and of its exact length;
    /// unknown keys are ignored; a duplicate key is `NotEnvelope`.
    pub fn parse(wire: &str) -> Result<Envelope, EnvelopeError> {
        let value: serde_json::Value = serde_json::from_str(wire).map_err(|_| EnvelopeError::NotEnvelope)?;
        let obj = value.as_object().ok_or(EnvelopeError::NotEnvelope)?;
        let v = obj.get("v").ok_or(EnvelopeError::NotEnvelope)?;
        if v.as_u64() != Some(WIRE_VERSION) || !v.is_u64() {
            return Err(EnvelopeError::Legacy);
        }
        let w: WireEnvelope = serde_json::from_str(wire).map_err(|_| EnvelopeError::NotEnvelope)?;
        let bad = EnvelopeError::NotEnvelope;
        if w.v != WIRE_VERSION || w.pn > MAX_WIRE_INT || w.n > MAX_WIRE_INT {
            return Err(bad);
        }
        let dh = b64_strict32(&w.dh).ok_or(bad)?;
        let ct = b64_strict(&w.ct).ok_or(bad)?;
        if ct.len() < 24 + 16 {
            return Err(bad);
        }
        let mac = b64_strict32(&w.mac).ok_or(bad)?;
        let x = match w.x {
            None => None,
            Some(x) => {
                if x.spk > MAX_WIRE_INT || x.opk.is_some_and(|o| o > MAX_WIRE_INT) {
                    return Err(bad);
                }
                Some(PrekeyHeader {
                    ik: b64_strict32(&x.ik).ok_or(bad)?,
                    ed: b64_strict32(&x.ed).ok_or(bad)?,
                    ek: b64_strict32(&x.ek).ok_or(bad)?,
                    spk: x.spk as i64,
                    opk: x.opk.map(|o| o as i64),
                })
            }
        };
        Ok(Envelope { dh, pn: w.pn, n: w.n, ct, mac, x })
    }

    /// Exact wire text: `{"v":3,"dh","pn","n","ct","mac"[,"x":{"ik","ed","ek","spk"[,"opk"]}]}`.
    pub fn to_wire(&self) -> String {
        let mut s = format!(
            "{{\"v\":3,\"dh\":\"{}\",\"pn\":{},\"n\":{},\"ct\":\"{}\",\"mac\":\"{}\"",
            b64(&self.dh),
            self.pn,
            self.n,
            b64(&self.ct),
            b64(&self.mac)
        );
        if let Some(x) = &self.x {
            s.push_str(&format!(
                ",\"x\":{{\"ik\":\"{}\",\"ed\":\"{}\",\"ek\":\"{}\",\"spk\":{}",
                b64(&x.ik),
                b64(&x.ed),
                b64(&x.ek),
                x.spk
            ));
            if let Some(opk) = x.opk {
                s.push_str(&format!(",\"opk\":{opk}"));
            }
            s.push('}');
        }
        s.push('}');
        s
    }

    /// The authenticated header bytes (03 §3.3).
    pub fn header_bytes(&self) -> Vec<u8> {
        header_bytes(&self.dh, self.pn, self.n, self.x.as_ref())
    }
}

pub fn header_bytes(dh: &[u8; 32], pn: u64, n: u64, x: Option<&PrekeyHeader>) -> Vec<u8> {
    let mut h = Vec::with_capacity(1 + 32 + 16 + 1 + 112);
    h.push(HEADER_VERSION_BYTE);
    h.extend_from_slice(dh);
    h.extend_from_slice(&pn.to_be_bytes());
    h.extend_from_slice(&n.to_be_bytes());
    match x {
        None => h.push(0),
        Some(x) => {
            h.push(1);
            h.extend_from_slice(&x.ik);
            h.extend_from_slice(&x.ed);
            h.extend_from_slice(&x.ek);
            h.extend_from_slice(&(x.spk as u64).to_be_bytes());
            h.extend_from_slice(&x.opk.map_or(OPK_ABSENT, |o| o as u64).to_be_bytes());
        }
    }
    h
}

// ───────────────────────────── state ─────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Init,
    Resp,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkippedKey {
    pub dh: [u8; 32],
    pub n: u64,
    pub mk: [u8; 32],
    pub at: i64,
}

/// One v3 session (03 §3.7). Identity private keys never enter it: the
/// responder's first ratchet key is the SPK.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Session {
    pub role: Role,
    pub sid: [u8; 32],
    pub ad: Vec<u8>,
    pub root_key: [u8; 32],
    pub my_dh: KeyPair,
    /// Our sending ratchet key before the last DH step (reset binding, §5.5).
    pub prev_my_dh_pub: Option<[u8; 32]>,
    pub peer_dh: [u8; 32],
    /// Responder only: the initiator's ephemeral (session match, §5.3).
    pub peer_ek: Option<[u8; 32]>,
    pub send_chain_key: Option<[u8; 32]>,
    pub send_count: u64,
    pub recv_chain_key: Option<[u8; 32]>,
    pub recv_count: u64,
    pub prev_send_count: u64,
    /// Insertion order = age.
    pub skipped: Vec<SkippedKey>,
    /// Initiator only, while `initiating`: attached to every message sent.
    pub x: Option<PrekeyHeader>,
    pub peer_ik: [u8; 32],
    pub peer_ed: [u8; 32],
    pub created_at: i64,
    /// First inbound decrypt of an initiator session.
    pub confirmed_at: Option<i64>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RatchetError {
    /// One message asked to skip more than [`MAX_SKIP_PER_MESSAGE`] keys.
    TooManySkippedKeys,
    /// No sending chain (a responder session that never received).
    NoSendChain,
}

impl std::fmt::Display for RatchetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RatchetError::TooManySkippedKeys => write!(f, "ratchet: too many skipped keys"),
            RatchetError::NoSendChain => write!(f, "ratchet: no sending chain"),
        }
    }
}

fn kdf_rk(root_key: &[u8; 32], dh_out: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(root_key);
    ikm[32..].copy_from_slice(dh_out);
    let okm = hkdf_sha256(&ikm, KDF_INFO_RATCHET.as_bytes(), 64);
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    a.copy_from_slice(&okm[..32]);
    b.copy_from_slice(&okm[32..]);
    (a, b)
}

fn kdf_ck(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    (hkdf32(chain_key, KDF_INFO_CHAIN.as_bytes()), hkdf32(chain_key, KDF_INFO_MSG.as_bytes()))
}

/// `(k_enc, k_mac)` of one message key.
pub fn message_keys(mk: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let okm = hkdf_sha256(mk, KDF_INFO_MSG_KEYS.as_bytes(), 64);
    let mut e = [0u8; 32];
    let mut m = [0u8; 32];
    e.copy_from_slice(&okm[..32]);
    m.copy_from_slice(&okm[32..]);
    (e, m)
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// Initiator state from an X3DH v2 initiation (03 §3.2).
pub fn initiate(init: &X3dhV2Initiation, peer_ik: &[u8; 32], peer_ed: &[u8; 32], now_ms: i64) -> Session {
    let (root_key, send_chain) = kdf_rk(&init.secret.rk0, &init.dh3);
    Session {
        role: Role::Init,
        sid: init.secret.sid,
        ad: init.secret.ad.clone(),
        root_key,
        my_dh: init.ek.clone(),
        prev_my_dh_pub: None,
        peer_dh: init.spk_pub,
        peer_ek: None,
        send_chain_key: Some(send_chain),
        send_count: 0,
        recv_chain_key: None,
        recv_count: 0,
        prev_send_count: 0,
        skipped: Vec::new(),
        x: Some(init.header),
        peer_ik: *peer_ik,
        peer_ed: *peer_ed,
        created_at: now_ms,
        confirmed_at: None,
    }
}

/// Responder state (before its first decrypt): the SPK is the first ratchet key.
pub fn respond(secret: &X3dhV2Secret, spk: &KeyPair, header: &PrekeyHeader, now_ms: i64) -> Session {
    Session {
        role: Role::Resp,
        sid: secret.sid,
        ad: secret.ad.clone(),
        root_key: secret.rk0,
        my_dh: spk.clone(),
        prev_my_dh_pub: None,
        peer_dh: [0u8; 32],
        peer_ek: Some(header.ek),
        send_chain_key: None,
        send_count: 0,
        recv_chain_key: None,
        recv_count: 0,
        prev_send_count: 0,
        skipped: Vec::new(),
        x: None,
        peer_ik: header.ik,
        peer_ed: header.ed,
        created_at: now_ms,
        confirmed_at: None,
    }
}

/// Both halves of a DH step (recv chain, fresh key, send chain).
fn dh_ratchet(state: &Session, peer_dh: &[u8; 32], rng: &mut dyn Rng) -> Session {
    let recv_dh = x25519(&state.my_dh.private, peer_dh);
    let (root1, recv_chain) = kdf_rk(&state.root_key, &recv_dh);
    let mut next = state.clone();
    next.root_key = root1;
    next.peer_dh = *peer_dh;
    next.recv_chain_key = Some(recv_chain);
    next.recv_count = 0;
    next.prev_send_count = state.send_count;

    let new_dh = x25519_keypair(rng);
    let send_dh = x25519(&new_dh.private, peer_dh);
    let (root2, send_chain) = kdf_rk(&next.root_key, &send_dh);
    next.root_key = root2;
    next.prev_my_dh_pub = Some(state.my_dh.public);
    next.my_dh = new_dh;
    next.send_chain_key = Some(send_chain);
    next.send_count = 0;
    next
}

fn prune_skipped(skipped: &mut Vec<SkippedKey>, now_ms: i64) {
    skipped.retain(|k| now_ms.saturating_sub(k.at) <= SKIPPED_TTL_MS);
    if skipped.len() > MAX_SKIPPED_TOTAL {
        let excess = skipped.len() - MAX_SKIPPED_TOTAL;
        skipped.drain(..excess);
    }
}

/// Encrypts one typed plaintext (03 §3.5; the caller builds it). The prekey
/// header rides along while the session is `initiating` (`x` present).
pub fn encrypt(state: &Session, plaintext: &str, now_ms: i64, rng: &mut dyn Rng) -> Result<(Session, Envelope), RatchetError> {
    let mut next = state.clone();
    let chain = next.send_chain_key.ok_or(RatchetError::NoSendChain)?;
    let (next_chain, mk) = kdf_ck(&chain);
    let (k_enc, k_mac) = message_keys(&mk);
    let mut nonce = [0u8; 24];
    rng.fill(&mut nonce);
    let mut ct = nonce.to_vec();
    ct.extend_from_slice(&secretbox_seal(plaintext.as_bytes(), &nonce, &k_enc));
    let (pn, n) = (next.prev_send_count, next.send_count);
    let x = next.x;
    let hdr = header_bytes(&next.my_dh.public, pn, n, x.as_ref());
    let mac = mac_over(&k_mac, &next.ad, &hdr, &ct);
    next.send_chain_key = Some(next_chain);
    next.send_count += 1;
    prune_skipped(&mut next.skipped, now_ms);
    let dh = next.my_dh.public;
    Ok((next, Envelope { dh, pn, n, ct, mac, x }))
}

fn mac_over(k_mac: &[u8; 32], ad: &[u8], hdr: &[u8], ct: &[u8]) -> [u8; 32] {
    let mut m = Vec::with_capacity(ad.len() + hdr.len() + ct.len());
    m.extend_from_slice(ad);
    m.extend_from_slice(hdr);
    m.extend_from_slice(ct);
    hmac_sha256(k_mac, &m)
}

/// MAC first (constant time), then the box, then the typed plaintext.
fn open_with(mk: &[u8; 32], ad: &[u8], env: &Envelope) -> Option<String> {
    let (k_enc, k_mac) = message_keys(mk);
    let expected = mac_over(&k_mac, ad, &env.header_bytes(), &env.ct);
    if !ct_eq(&expected, &env.mac) {
        return None;
    }
    let nonce: [u8; 24] = env.ct[..24].try_into().ok()?;
    let pt = secretbox_open(&env.ct[24..], &nonce, &k_enc)?;
    let text = String::from_utf8(pt).ok()?;
    parse_typed_plaintext(&text)?;
    Some(text)
}

fn skip_recv_keys(mut state: Session, until: u64, now_ms: i64) -> Result<Session, RatchetError> {
    let Some(mut chain) = state.recv_chain_key else { return Ok(state) };
    if until > state.recv_count && (until - state.recv_count) as i64 > MAX_SKIP_PER_MESSAGE {
        return Err(RatchetError::TooManySkippedKeys);
    }
    while state.recv_count < until {
        let (next_chain, mk) = kdf_ck(&chain);
        state.skipped.push(SkippedKey { dh: state.peer_dh, n: state.recv_count, mk, at: now_ms });
        chain = next_chain;
        state.recv_count += 1;
    }
    state.recv_chain_key = Some(chain);
    Ok(state)
}

/// Decrypts `env` under `state`. `Ok(None)`: authentication failure (wrong
/// session, forged, replayed, tampered header or body, bad typed plaintext);
/// the caller keeps the old state. `Err`: a message that asks for more than
/// [`MAX_SKIP_PER_MESSAGE`] skipped keys (not counted as a failure).
pub fn decrypt(state: &Session, env: &Envelope, now_ms: i64, rng: &mut dyn Rng) -> Result<Option<(Session, String)>, RatchetError> {
    let mut next = state.clone();
    prune_skipped(&mut next.skipped, now_ms);
    if let Some(i) = next.skipped.iter().position(|k| k.dh == env.dh && k.n == env.n) {
        let mk = next.skipped[i].mk;
        let Some(pt) = open_with(&mk, &next.ad, env) else { return Ok(None) };
        next.skipped.remove(i);
        confirm(&mut next, now_ms);
        return Ok(Some((next, pt)));
    }
    if env.dh != next.peer_dh {
        next = skip_recv_keys(next, env.pn, now_ms)?;
        next = dh_ratchet(&next, &env.dh, rng);
    }
    next = skip_recv_keys(next, env.n, now_ms)?;
    let Some(chain) = next.recv_chain_key else { return Ok(None) };
    if env.n < next.recv_count {
        return Ok(None); // a spent position of the current chain
    }
    let (next_chain, mk) = kdf_ck(&chain);
    let Some(pt) = open_with(&mk, &next.ad, env) else { return Ok(None) };
    next.recv_chain_key = Some(next_chain);
    next.recv_count += 1;
    prune_skipped(&mut next.skipped, now_ms);
    confirm(&mut next, now_ms);
    Ok(Some((next, pt)))
}

/// The first inbound message of an initiator session: the peer holds the
/// session, so the prekey header stops (`initiating` → `active`).
fn confirm(state: &mut Session, now_ms: i64) {
    if state.role == Role::Init && state.x.is_some() {
        state.x = None;
        state.confirmed_at = Some(now_ms);
    }
}

/// True when `(env.dh, env.n)` is a position this session already used, so
/// the envelope can only be a replay (03 §5.4).
pub fn is_spent_position(state: &Session, env: &Envelope) -> bool {
    if state.skipped.iter().any(|k| k.dh == env.dh && k.n == env.n) {
        return false;
    }
    env.dh == state.peer_dh && env.n < state.recv_count
}

/// `rb` of a call offer/answer: `b64(HKDF(sid, "mrenzo-ratchet-bind-v2|" + payload))`.
pub fn session_binding_mac(sid: &[u8; 32], payload: &str) -> String {
    b64(&hkdf32(sid, format!("{KDF_INFO_BIND}|{payload}").as_bytes()))
}

/// The mesh ACK payload `id + "." + b64(HMAC(k_ack, id))[..16]` (04 §12).
pub fn mesh_ack_payload(sid: &[u8; 32], message_id: &str) -> String {
    let k_ack = hkdf32(sid, KDF_INFO_MESH_ACK.as_bytes());
    let tag = b64(&hmac_sha256(&k_ack, message_id.as_bytes()));
    format!("{message_id}.{}", &tag[..16])
}

/// Constant-time check of an ACK payload against one session id.
pub fn mesh_ack_matches(sid: &[u8; 32], payload: &str) -> Option<String> {
    let (id, tag) = payload.rsplit_once('.')?;
    if id.is_empty() || tag.len() != 16 {
        return None;
    }
    let expected = mesh_ack_payload(sid, id);
    ct_eq(expected.as_bytes(), payload.as_bytes()).then(|| id.to_string())
}

// ───────────────────────────── at rest (03 §3.7) ─────────────────────────────

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireSkipped {
    dh: String,
    n: u64,
    mk: String,
    at: i64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireHeaderX {
    ik: String,
    ed: String,
    ek: String,
    spk: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    opk: Option<u64>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WireSession {
    v: u64,
    role: String,
    sid: String,
    ad: String,
    root_key: String,
    #[serde(rename = "myDHPub")]
    my_dh_pub: String,
    #[serde(rename = "myDHPriv")]
    my_dh_priv: String,
    #[serde(rename = "prevMyDHPub")]
    prev_my_dh_pub: Option<String>,
    #[serde(rename = "peerDH")]
    peer_dh: String,
    peer_ek: Option<String>,
    send_chain_key: Option<String>,
    send_count: u64,
    recv_chain_key: Option<String>,
    recv_count: u64,
    prev_send_count: u64,
    skipped: Vec<WireSkipped>,
    x: Option<WireHeaderX>,
    peer_ik: String,
    peer_ed: String,
    created_at: i64,
    confirmed_at: Option<i64>,
}

impl Session {
    pub fn to_json(&self) -> String {
        let k = |o: &Option<[u8; 32]>| o.map(|k| b64(&k));
        let w = WireSession {
            v: WIRE_VERSION,
            role: match self.role {
                Role::Init => "init".into(),
                Role::Resp => "resp".into(),
            },
            sid: b64(&self.sid),
            ad: b64(&self.ad),
            root_key: b64(&self.root_key),
            my_dh_pub: b64(&self.my_dh.public),
            my_dh_priv: b64(&self.my_dh.private),
            prev_my_dh_pub: k(&self.prev_my_dh_pub),
            peer_dh: b64(&self.peer_dh),
            peer_ek: k(&self.peer_ek),
            send_chain_key: k(&self.send_chain_key),
            send_count: self.send_count,
            recv_chain_key: k(&self.recv_chain_key),
            recv_count: self.recv_count,
            prev_send_count: self.prev_send_count,
            skipped: self
                .skipped
                .iter()
                .map(|s| WireSkipped { dh: b64(&s.dh), n: s.n, mk: b64(&s.mk), at: s.at })
                .collect(),
            x: self.x.map(|x| WireHeaderX {
                ik: b64(&x.ik),
                ed: b64(&x.ed),
                ek: b64(&x.ek),
                spk: x.spk as u64,
                opk: x.opk.map(|o| o as u64),
            }),
            peer_ik: b64(&self.peer_ik),
            peer_ed: b64(&self.peer_ed),
            created_at: self.created_at,
            confirmed_at: self.confirmed_at,
        };
        serde_json::to_string(&w).expect("session serializes")
    }

    /// Strict at-rest parse; skipped keys past the TTL are dropped here.
    pub fn from_json(json: &str, now_ms: i64) -> Option<Session> {
        let w: WireSession = serde_json::from_str(json).ok()?;
        if w.v != WIRE_VERSION {
            return None;
        }
        let k32 = |s: &str| b64_strict32(s);
        let ok32 = |o: &Option<String>| -> Option<Option<[u8; 32]>> {
            match o {
                None => Some(None),
                Some(s) => Some(Some(b64_strict32(s)?)),
            }
        };
        let ad = b64_strict(&w.ad)?;
        if ad.len() != AD_LEN_V3 {
            return None;
        }
        let role = match w.role.as_str() {
            "init" => Role::Init,
            "resp" => Role::Resp,
            _ => return None,
        };
        let mut skipped = Vec::with_capacity(w.skipped.len());
        for s in &w.skipped {
            skipped.push(SkippedKey { dh: k32(&s.dh)?, n: s.n, mk: k32(&s.mk)?, at: s.at });
        }
        let x = match &w.x {
            None => None,
            Some(x) => Some(PrekeyHeader {
                ik: k32(&x.ik)?,
                ed: k32(&x.ed)?,
                ek: k32(&x.ek)?,
                spk: i64::try_from(x.spk).ok()?,
                opk: match x.opk {
                    None => None,
                    Some(o) => Some(i64::try_from(o).ok()?),
                },
            }),
        };
        let mut s = Session {
            role,
            sid: k32(&w.sid)?,
            ad,
            root_key: k32(&w.root_key)?,
            my_dh: KeyPair { public: k32(&w.my_dh_pub)?, private: k32(&w.my_dh_priv)? },
            prev_my_dh_pub: ok32(&w.prev_my_dh_pub)?,
            peer_dh: k32(&w.peer_dh)?,
            peer_ek: ok32(&w.peer_ek)?,
            send_chain_key: ok32(&w.send_chain_key)?,
            send_count: w.send_count,
            recv_chain_key: ok32(&w.recv_chain_key)?,
            recv_count: w.recv_count,
            prev_send_count: w.prev_send_count,
            skipped,
            x,
            peer_ik: k32(&w.peer_ik)?,
            peer_ed: k32(&w.peer_ed)?,
            created_at: w.created_at,
            confirmed_at: w.confirmed_at,
        };
        prune_skipped(&mut s.skipped, now_ms);
        Some(s)
    }
}
