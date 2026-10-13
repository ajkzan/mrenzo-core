//! «Рация» — push-to-talk media (wire-1.1 §W7.2; 03-crypto §V3.18).
//!
//! One transmission = one random key `K`, delivered once inside the 1:1
//! ratchet (`{"t":"ptt","id":"<pttId>","ptt":{"v":1,"k","codec","sr"}}`), and
//! a run of audio chunks sealed under it. The same chunk bytes travel online
//! (`ptt-chunk.data`) and on the mesh (a `ptt` frame body).
//!
//! ```text
//! chunk   = nonce(24, random) ‖ secretbox(K, nonce, pt)
//! pt      = "P1" ‖ flags(1) ‖ BE32(seq) ‖ BE16(padLen) ‖ packets ‖ 0x00^padLen
//! packets = ( BE16(len) ‖ packet[len] )*      1 ≤ len ≤ 4096, ≤ 512 packets; none only with LAST
//! flags   : bit0 LAST; every other bit 0
//! len(pt) : a multiple of 256, ≤ 16 384;  padLen ≤ 255;  seq < 4096
//! ```
//!
//! - `K` binds a chunk to its transmission; `seq` inside the box stops
//!   reordering and splicing.
//! - LAST is inside the box: the end of a transmission is authenticated, so
//!   a server (online) or a relay cannot cut a transmission and have it look
//!   finished.
//! - The padding hides the size of the encoded audio, which with a variable
//!   bitrate codec is a known side channel for what was said.
//!
//! [`PttReceiver`] is the receive-side state both platforms share: keys and
//! played sequence numbers are held per `(sender uid, transmission)`, and a
//! sequence number is recorded only AFTER its chunk authenticated.

use std::collections::{HashMap, VecDeque};

use serde_json::{Map, Value};

use crate::primitives::{b64, secretbox_open, secretbox_seal};
use crate::rng::Rng;
use crate::strict_json;

pub const PTT_VERSION: u64 = 1;
pub const CHUNK_MAGIC: [u8; 2] = [0x50, 0x31]; // "P1"
pub const FLAG_LAST: u8 = 0x01;
/// magic(2) ‖ flags(1) ‖ seq(4) ‖ padLen(2).
pub const CHUNK_HEADER_LEN: usize = 9;
pub const CHUNK_PAD_BUCKET: usize = 256;
pub const CHUNK_PLAINTEXT_MAX: usize = 16_384;
pub const PACKET_MAX: usize = 4096;
pub const PACKETS_MAX: usize = 512;
/// Sequence numbers of one transmission are `0..SEQ_LIMIT`.
pub const SEQ_LIMIT: u32 = 4096;
pub const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
pub const SAMPLE_RATE_MIN: u64 = 8000;
pub const SAMPLE_RATE_MAX: u64 = 48_000;
/// Transmissions held per sender / in total by one [`PttReceiver`].
pub const RX_PER_SENDER: usize = 8;
pub const RX_TOTAL: usize = 32;

// ───────────────────────────── transmission id ─────────────────────────────

/// The 16 bytes of a lowercase canonical UUIDv4, or `None` for any other text.
pub fn ptt_id_bytes(ptt_id: &str) -> Option<[u8; 16]> {
    let b = ptt_id.as_bytes();
    if b.len() != 36 {
        return None;
    }
    let mut out = [0u8; 16];
    let mut k = 0;
    let mut i = 0;
    while i < 36 {
        if matches!(i, 8 | 13 | 18 | 23) {
            if b[i] != b'-' {
                return None;
            }
            i += 1;
            continue;
        }
        let nib = |c: u8| match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        };
        // i + 1 < 36: a hex pair never straddles a hyphen position.
        out[k] = (nib(b[i])? << 4) | nib(b[i + 1])?;
        k += 1;
        i += 2;
    }
    // Version 4, RFC 4122 variant: what `secure_uuid` writes.
    ((out[6] & 0xf0) == 0x40 && (out[8] & 0xc0) == 0x80).then_some(out)
}

/// The canonical text of 16 transmission-id bytes (any bytes: the caller
/// compares the result with a validated id).
pub fn ptt_id_text(tx: &[u8; 16]) -> String {
    let h: String = tx.iter().map(|x| format!("{x:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

// ───────────────────────────── key plaintext ─────────────────────────────

/// The `ptt` object of the key plaintext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PttKey {
    pub k: [u8; 32],
    pub codec: String,
    pub sr: u32,
}

/// `^[a-z0-9-]{1,16}$`.
pub fn is_codec(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=16).contains(&b.len()) && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

impl PttKey {
    pub fn is_valid(&self) -> bool {
        is_codec(&self.codec) && (SAMPLE_RATE_MIN..=SAMPLE_RATE_MAX).contains(&(self.sr as u64))
    }

    /// Strict on the fields it knows; unknown keys are ignored.
    pub fn from_value(v: &Value) -> Option<PttKey> {
        let o = v.as_object()?;
        if o.get("v").and_then(strict_json::uint) != Some(PTT_VERSION) {
            return None;
        }
        let k: [u8; 32] = strict_json::b64_n(o.get("k")?.as_str()?)?;
        let codec = o.get("codec")?.as_str().filter(|c| is_codec(c))?.to_string();
        let sr = o.get("sr").and_then(strict_json::uint).filter(|s| (SAMPLE_RATE_MIN..=SAMPLE_RATE_MAX).contains(s))?;
        Some(PttKey { k, codec, sr: sr as u32 })
    }

    /// Key order: v, k, codec, sr.
    pub fn to_value(&self) -> Value {
        let mut o = Map::new();
        o.insert("v".into(), Value::from(PTT_VERSION));
        o.insert("k".into(), Value::String(b64(&self.k)));
        o.insert("codec".into(), Value::String(self.codec.clone()));
        o.insert("sr".into(), Value::from(self.sr));
        Value::Object(o)
    }
}

// ───────────────────────────── chunks ─────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chunk {
    pub seq: u32,
    pub last: bool,
    pub packets: Vec<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealError {
    /// `seq ≥ 4096`.
    Seq,
    /// A packet of 0 or more than 4096 bytes, more than 512 packets, or none without LAST.
    Packets,
    /// The framed packets do not fit 16 384 bytes.
    TooLarge,
}

impl std::fmt::Display for SealError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SealError::Seq => "ptt-seq",
            SealError::Packets => "ptt-packets",
            SealError::TooLarge => "ptt-too-large",
        })
    }
}

/// The padded chunk plaintext (exposed for the vectors).
pub fn chunk_plaintext(seq: u32, last: bool, packets: &[Vec<u8>]) -> Result<Vec<u8>, SealError> {
    if seq >= SEQ_LIMIT {
        return Err(SealError::Seq);
    }
    if packets.len() > PACKETS_MAX || (packets.is_empty() && !last) || packets.iter().any(|p| p.is_empty() || p.len() > PACKET_MAX) {
        return Err(SealError::Packets);
    }
    let framed: usize = packets.iter().map(|p| 2 + p.len()).sum();
    let unpadded = CHUNK_HEADER_LEN + framed;
    let total = unpadded.div_ceil(CHUNK_PAD_BUCKET) * CHUNK_PAD_BUCKET;
    if total > CHUNK_PLAINTEXT_MAX {
        return Err(SealError::TooLarge);
    }
    let pad = total - unpadded; // < 256
    let mut pt = Vec::with_capacity(total);
    pt.extend_from_slice(&CHUNK_MAGIC);
    pt.push(if last { FLAG_LAST } else { 0 });
    pt.extend_from_slice(&seq.to_be_bytes());
    pt.extend_from_slice(&(pad as u16).to_be_bytes());
    for p in packets {
        pt.extend_from_slice(&(p.len() as u16).to_be_bytes());
        pt.extend_from_slice(p);
    }
    pt.resize(total, 0);
    Ok(pt)
}

/// Seals one chunk (24 random bytes drawn for the nonce).
pub fn seal_chunk(key: &[u8; 32], seq: u32, last: bool, packets: &[Vec<u8>], rng: &mut dyn Rng) -> Result<Vec<u8>, SealError> {
    let pt = chunk_plaintext(seq, last, packets)?;
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill(&mut nonce);
    let mut out = nonce.to_vec();
    out.extend_from_slice(&secretbox_seal(&pt, &nonce, key));
    Ok(out)
}

/// Parses an authenticated chunk plaintext; `None` for any deviation from
/// the one canonical framing.
fn parse_chunk_plaintext(pt: &[u8]) -> Option<Chunk> {
    if pt.len() < CHUNK_PAD_BUCKET || pt.len() > CHUNK_PLAINTEXT_MAX || pt.len() % CHUNK_PAD_BUCKET != 0 {
        return None;
    }
    if pt[..2] != CHUNK_MAGIC || pt[2] & !FLAG_LAST != 0 {
        return None;
    }
    let last = pt[2] & FLAG_LAST != 0;
    let seq = u32::from_be_bytes([pt[3], pt[4], pt[5], pt[6]]);
    let pad = u16::from_be_bytes([pt[7], pt[8]]) as usize;
    if seq >= SEQ_LIMIT || pad >= CHUNK_PAD_BUCKET || CHUNK_HEADER_LEN + pad > pt.len() {
        return None;
    }
    let end = pt.len() - pad;
    if pt[end..].iter().any(|b| *b != 0) {
        return None;
    }
    let mut packets = Vec::new();
    let mut p = CHUNK_HEADER_LEN;
    while p < end {
        if end - p < 2 || packets.len() == PACKETS_MAX {
            return None;
        }
        let len = u16::from_be_bytes([pt[p], pt[p + 1]]) as usize;
        p += 2;
        if len == 0 || len > PACKET_MAX || end - p < len {
            return None;
        }
        packets.push(pt[p..p + len].to_vec());
        p += len;
    }
    if packets.is_empty() && !last {
        return None;
    }
    Some(Chunk { seq, last, packets })
}

/// Opens one chunk under `key`. `None`: wrong size, MAC failure, or a
/// plaintext that is not the canonical `P1` framing.
pub fn open_chunk(key: &[u8; 32], chunk: &[u8]) -> Option<Chunk> {
    let min = NONCE_LEN + TAG_LEN + CHUNK_PAD_BUCKET;
    if chunk.len() < min || chunk.len() > NONCE_LEN + TAG_LEN + CHUNK_PLAINTEXT_MAX {
        return None;
    }
    if (chunk.len() - NONCE_LEN - TAG_LEN) % CHUNK_PAD_BUCKET != 0 {
        return None;
    }
    let nonce: [u8; NONCE_LEN] = chunk[..NONCE_LEN].try_into().ok()?;
    let pt = secretbox_open(&chunk[NONCE_LEN..], &nonce, key)?;
    parse_chunk_plaintext(&pt)
}

// ───────────────────────────── receiver state ─────────────────────────────

/// What [`PttReceiver::open`] did with one chunk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RxOpen {
    /// Authenticated and new: play `packets`. `first` = the first chunk of
    /// this transmission that opened (the moment to send the one ACK);
    /// `complete` = the LAST chunk has now been seen.
    Opened { last: bool, packets: Vec<Vec<u8>>, first: bool, complete: bool },
    /// Authenticated, and already played.
    Duplicate,
    /// No key for this `(sender, transmission)` yet.
    NoKey,
    /// Not authentic under the key of this transmission, the wrong sequence
    /// number, a chunk after the LAST one, or a LAST below a number already
    /// played. Nothing was recorded.
    Rejected,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Transmission {
    key: [u8; 32],
    /// One bit per sequence number played.
    seen: Vec<u64>,
    opened: u32,
    /// The highest sequence number played so far.
    max_seq: Option<u32>,
    last_seq: Option<u32>,
}

/// Keys and played sequence numbers per `(sender uid, transmission id)`.
/// Never keyed by the bare transmission id: it is in clear on the air, and a
/// second sender must not be able to occupy or exhaust somebody's stream.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PttReceiver {
    map: HashMap<(i64, [u8; 16]), Transmission>,
    /// Insertion order = age.
    order: VecDeque<(i64, [u8; 16])>,
}

impl PttReceiver {
    pub fn new() -> PttReceiver {
        PttReceiver::default()
    }

    pub fn has_key(&self, from_uid: i64, tx: &[u8; 16]) -> bool {
        self.map.contains_key(&(from_uid, *tx))
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Installs the key of a transmission whose key plaintext authenticated
    /// under the session with `from_uid`. A key already installed is kept
    /// (the first authenticated one wins). The sender's oldest transmission
    /// goes when it holds [`RX_PER_SENDER`], the oldest overall at [`RX_TOTAL`].
    pub fn install_key(&mut self, from_uid: i64, tx: &[u8; 16], key: &[u8; 32]) -> bool {
        let id = (from_uid, *tx);
        if self.map.contains_key(&id) {
            return false;
        }
        while self.order.iter().filter(|(uid, _)| *uid == from_uid).count() >= RX_PER_SENDER {
            let Some(pos) = self.order.iter().position(|(uid, _)| *uid == from_uid) else { break };
            if let Some(old) = self.order.remove(pos) {
                self.map.remove(&old);
            }
        }
        while self.order.len() >= RX_TOTAL {
            let Some(old) = self.order.pop_front() else { break };
            self.map.remove(&old);
        }
        self.map.insert(id, Transmission { key: *key, seen: vec![0u64; (SEQ_LIMIT as usize) / 64], opened: 0, max_seq: None, last_seq: None });
        self.order.push_back(id);
        true
    }

    /// Opens `chunk`, which its carrier says is number `seq` of the
    /// transmission. The sequence number is recorded only after the chunk
    /// authenticated and named the same `seq` inside the box.
    pub fn open(&mut self, from_uid: i64, tx: &[u8; 16], seq: u32, chunk: &[u8]) -> RxOpen {
        let Some(t) = self.map.get_mut(&(from_uid, *tx)) else { return RxOpen::NoKey };
        let Some(c) = open_chunk(&t.key, chunk) else { return RxOpen::Rejected };
        if c.seq != seq {
            return RxOpen::Rejected;
        }
        // `c.seq < SEQ_LIMIT` (the parser checked): the index is in range.
        let (word, bit) = ((c.seq / 64) as usize, 1u64 << (c.seq % 64));
        if t.seen[word] & bit != 0 {
            return RxOpen::Duplicate;
        }
        // An authenticated end is final: nothing may follow it, and a second
        // LAST with another number is the sender contradicting itself.
        if t.last_seq.is_some_and(|l| c.seq > l || c.last) {
            return RxOpen::Rejected;
        }
        // The same rule from the other side: an end below a number already
        // played is not the end of what was heard. Whatever order the chunks
        // arrive in, a complete transmission is exactly `0..=last_seq`.
        if c.last && t.max_seq.is_some_and(|m| m > c.seq) {
            return RxOpen::Rejected;
        }
        t.seen[word] |= bit;
        t.max_seq = Some(t.max_seq.map_or(c.seq, |m| m.max(c.seq)));
        let first = t.opened == 0;
        t.opened += 1;
        if c.last {
            t.last_seq = Some(c.seq);
        }
        RxOpen::Opened { last: c.last, packets: c.packets, first, complete: t.last_seq.is_some() }
    }

    /// The authenticated final sequence number, once the LAST chunk opened.
    pub fn last_seq(&self, from_uid: i64, tx: &[u8; 16]) -> Option<u32> {
        self.map.get(&(from_uid, *tx)).and_then(|t| t.last_seq)
    }

    /// Chunks of this transmission that opened so far.
    pub fn opened(&self, from_uid: i64, tx: &[u8; 16]) -> u32 {
        self.map.get(&(from_uid, *tx)).map_or(0, |t| t.opened)
    }

    /// Forgets one transmission (it ended, or it timed out).
    pub fn forget(&mut self, from_uid: i64, tx: &[u8; 16]) {
        let id = (from_uid, *tx);
        self.map.remove(&id);
        self.order.retain(|k| *k != id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::StreamRng;

    #[test]
    fn id_text_and_bytes_round_trip() {
        let id = "0f8fad5b-d9cb-469f-a165-70867728950e";
        let tx = ptt_id_bytes(id).unwrap();
        assert_eq!(ptt_id_text(&tx), id);
        for bad in ["", "0F8FAD5B-D9CB-469F-A165-70867728950E", "0f8fad5bd9cb469fa16570867728950e", "0f8fad5b-d9cb-169f-a165-70867728950e", "0f8fad5b-d9cb-469f-c165-70867728950e", "0f8fad5b-d9cb-469f-a165-70867728950", "0f8fad5b-d9cb-469f-a165-70867728950é"] {
            assert!(ptt_id_bytes(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn every_chunk_is_a_multiple_of_the_bucket() {
        let key = [3u8; 32];
        let mut r = StreamRng::new("ptt/unit");
        for sizes in [vec![1usize], vec![40, 41, 39], vec![245], vec![246], vec![4096, 4096, 4096]] {
            let packets: Vec<Vec<u8>> = sizes.iter().map(|n| vec![0xab; *n]).collect();
            let chunk = seal_chunk(&key, 5, false, &packets, &mut r).unwrap();
            assert_eq!((chunk.len() - 40) % 256, 0, "{sizes:?}");
            assert_eq!(open_chunk(&key, &chunk), Some(Chunk { seq: 5, last: false, packets }));
        }
        let end = seal_chunk(&key, 6, true, &[], &mut r).unwrap();
        assert_eq!(end.len(), 40 + 256);
        assert_eq!(open_chunk(&key, &end), Some(Chunk { seq: 6, last: true, packets: vec![] }));
        assert_eq!(seal_chunk(&key, 6, false, &[], &mut r), Err(SealError::Packets));
        assert_eq!(seal_chunk(&key, 4096, true, &[], &mut r), Err(SealError::Seq));
        assert_eq!(seal_chunk(&key, 0, false, &[vec![1; 4097]], &mut r), Err(SealError::Packets));
        assert_eq!(seal_chunk(&key, 0, false, &vec![vec![1; 4096]; 4], &mut r), Err(SealError::TooLarge));
    }

    #[test]
    fn a_second_sender_cannot_use_up_a_transmission() {
        let tx = [9u8; 16];
        let (alice_key, mallory_key) = ([1u8; 32], [2u8; 32]);
        let mut r = StreamRng::new("ptt/rx");
        let mut rx = PttReceiver::new();
        assert!(rx.install_key(1001, &tx, &alice_key));
        // Mallory (another pinned contact) reuses the id, with her own key.
        assert!(rx.install_key(1003, &tx, &mallory_key));
        let a0 = seal_chunk(&alice_key, 0, false, &[vec![7; 30]], &mut r).unwrap();
        let m0 = seal_chunk(&mallory_key, 0, false, &[vec![8; 30]], &mut r).unwrap();
        // Her chunk presented as Alice's: not authentic under Alice's key, nothing recorded.
        assert_eq!(rx.open(1001, &tx, 0, &m0), RxOpen::Rejected);
        assert!(matches!(rx.open(1003, &tx, 0, &m0), RxOpen::Opened { first: true, .. }));
        assert!(matches!(rx.open(1001, &tx, 0, &a0), RxOpen::Opened { first: true, complete: false, .. }), "Alice's segment still plays");
        assert_eq!(rx.open(1001, &tx, 0, &a0), RxOpen::Duplicate);
        assert_eq!(rx.open(1001, &tx, 1, &a0), RxOpen::Rejected, "the carrier's number must be the one in the box");
        assert_eq!(rx.open(1002, &tx, 0, &a0), RxOpen::NoKey);
    }

    #[test]
    fn the_end_is_final() {
        let (tx, key) = ([4u8; 16], [5u8; 32]);
        let mut r = StreamRng::new("ptt/end");
        let mut rx = PttReceiver::new();
        rx.install_key(7, &tx, &key);
        let c = |seq, last, r: &mut StreamRng| seal_chunk(&key, seq, last, &[vec![1; 10]], r).unwrap();
        assert!(matches!(rx.open(7, &tx, 2, &c(2, true, &mut r)), RxOpen::Opened { last: true, complete: true, .. }));
        assert_eq!(rx.last_seq(7, &tx), Some(2));
        assert!(matches!(rx.open(7, &tx, 1, &c(1, false, &mut r)), RxOpen::Opened { complete: true, .. }), "an earlier chunk may still arrive");
        assert_eq!(rx.open(7, &tx, 3, &c(3, false, &mut r)), RxOpen::Rejected, "nothing follows the end");
        assert_eq!(rx.open(7, &tx, 0, &c(0, true, &mut r)), RxOpen::Rejected, "a second end");
        // The other order: a number already played, then an "end" below it.
        let other = [6u8; 16];
        rx.install_key(7, &other, &key);
        assert!(matches!(rx.open(7, &other, 5, &c(5, false, &mut r)), RxOpen::Opened { complete: false, .. }));
        assert_eq!(rx.open(7, &other, 2, &c(2, true, &mut r)), RxOpen::Rejected, "an end below what was already played");
        assert_eq!(rx.last_seq(7, &other), None, "…records nothing");
        assert!(matches!(rx.open(7, &other, 2, &c(2, false, &mut r)), RxOpen::Opened { .. }), "the number itself is still free");
        assert!(matches!(rx.open(7, &other, 5, &c(5, true, &mut r)), RxOpen::Duplicate), "a played number stays played");
        assert!(matches!(rx.open(7, &other, 6, &c(6, true, &mut r)), RxOpen::Opened { last: true, complete: true, .. }));
    }

    #[test]
    fn the_state_is_bounded() {
        let mut rx = PttReceiver::new();
        for i in 0..20u8 {
            rx.install_key(1, &[i; 16], &[0u8; 32]);
        }
        assert_eq!(rx.len(), RX_PER_SENDER);
        assert!(!rx.has_key(1, &[0u8; 16]) && rx.has_key(1, &[19u8; 16]));
        for uid in 2..40 {
            rx.install_key(uid, &[1u8; 16], &[0u8; 32]);
        }
        assert_eq!(rx.len(), RX_TOTAL);
    }
}
