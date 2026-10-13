//! Reactions inside E2E (wire-1.1 §W7.3, §W7.4; 03-crypto §V3.16.4, §V3.7.6).
//!
//! A reaction is a STATE, not an event: the sender's full set of emoji for
//! one message, `{"t":"react","id","to","e":[…],"ts"}`. The receiver keeps a
//! last-writer-wins register per `(conversation, message, user)` ordered by
//! `(ts, id)`, so duplicates and reordering — normal between the WebSocket
//! replay and the HTTP backlog — change nothing.
//!
//! 1:1 — the plaintext travels in the `ctl` carrier under the pair's ratchet.
//!
//! Groups and channels — a reaction must not make every reacting subscriber
//! a Sender-Keys sender to every other one, so it is sealed under a key bound
//! to the POST, derived from material every reader of the post already has:
//!
//! ```text
//! mk   = HKDF(ck_ctr, "mrenzo-sender-msg")                     the post's message key
//! rk   = HKDF(mk, "mrenzo-sender-rx-v1")                       post reaction key
//! k_u  = HKDF(rk, "mrenzo-grx-v1|" + groupId + "|" + postId + "|" + reactorUid)
//! blob = "rx1:" + b64( nonce(24) ‖ secretbox(k_u, nonce, UTF-8 react JSON) )
//! ```
//!
//! Attribution in a group rests on the server-stamped user id and on
//! possession of `rk` (stated in 03 §V3.7.6): weaker than the `sk2`
//! signature of a post, accepted for emoji.

use crate::plaintext::{classify, Classified, Soft, TypedPlaintext};
use crate::primitives::{b64, hkdf32, secretbox_open, secretbox_seal};
use crate::rng::Rng;
use crate::strict_json;

/// HKDF info: post message key → post reaction key.
pub const RX_KEY_INFO: &str = "mrenzo-sender-rx-v1";
/// Label of the per-reactor key info.
pub const GRX_LABEL: &str = "mrenzo-grx-v1";
/// Prefix of a group reaction blob.
pub const BLOB_PREFIX: &str = "rx1:";
pub const BLOB_MAX_BYTES: usize = 1024;
pub const TARGET_MAX_BYTES: usize = 128;
pub const EMOJI_MAX_COUNT: usize = 3;
pub const EMOJI_MAX_BYTES: usize = 64;
/// The serialized plaintext is padded to a multiple of this — after `e` has
/// been counted at its longest ([`E_JSON_MAX`]), see [`pad_reserve`].
pub const PAD_BLOCK: usize = 64;
/// The longest JSON text of `e`: `["…","…","…"]` with three entries of 64
/// bytes (202 bytes).
pub const E_JSON_MAX: usize = 2 + EMOJI_MAX_COUNT * (EMOJI_MAX_BYTES + 2) + (EMOJI_MAX_COUNT - 1);
/// A state stamped further ahead than this is ignored and not stored.
pub const FUTURE_LIMIT_MS: i64 = 24 * 60 * 60 * 1000;

/// One entry of `e`: 1..64 UTF-8 bytes, no control character, no `"` and no
/// `\`. Whether it is an emoji this device can draw is the host's check
/// against its own table. The two ASCII exclusions are what makes the JSON
/// text of an entry exactly its bytes between two quotes — nothing in it is
/// ever escaped — so the length of `e` on the wire is a function of the byte
/// lengths alone, and the padding can hide it ([`pad_reserve`]).
pub fn is_emoji_entry(s: &str) -> bool {
    (1..=EMOJI_MAX_BYTES).contains(&s.len()) && !s.chars().any(|c| c.is_control() || c == '"' || c == '\\')
}

/// The JSON length of a valid `e` as this core writes it.
pub fn e_json_len(e: &[String]) -> usize {
    2 + e.iter().map(|s| s.len() + 2).sum::<usize>() + e.len().saturating_sub(1)
}

/// How many bytes shorter than the longest `e` this one is on the wire. A
/// reaction is padded as if they were there: the padded length is that of
/// the same plaintext with `e` at [`E_JSON_MAX`], rounded up to
/// [`PAD_BLOCK`], so it depends on the ids, `ts` and `caps` — never on
/// which emoji, how many, or whether the state is a removal. (Padding only
/// to the next block does not give that: a ZWJ sequence or three long
/// entries cross a 64-byte boundary that `❤️` and `[]` do not.)
pub fn pad_reserve(e: &[String]) -> usize {
    E_JSON_MAX.saturating_sub(e_json_len(e))
}

/// The content rules of a `react` plaintext (also enforced by the parser).
pub fn is_valid_react(to: &str, e: &[String], ts: u64) -> bool {
    !to.is_empty()
        && to.len() <= TARGET_MAX_BYTES
        && e.len() <= EMOJI_MAX_COUNT
        && e.iter().all(|s| is_emoji_entry(s))
        && e.iter().enumerate().all(|(i, s)| !e[..i].contains(s))
        && (1..=strict_json::MAX_SAFE_INT).contains(&ts)
}

// ───────────────────────────── the register ─────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegisterDecision {
    /// Newer than what is stored: apply and store `(ts, id)` as received.
    Apply,
    /// Not newer (a duplicate or an older state): ignore.
    Keep,
    /// Stamped more than 24 h ahead of this device's clock: ignore, store nothing.
    TooFarAhead,
}

/// Last-writer-wins on the sender's RAW `(ts, id)`, `id` compared as bytes.
/// No clamping: a clamp at receive time would hand the later-arriving of two
/// reordered states of a fast clock the larger value, and the older state
/// would win for good.
pub fn register_decide(stored: Option<(u64, &str)>, new_ts: u64, new_id: &str, now_ms: i64) -> RegisterDecision {
    if new_ts as i128 > now_ms as i128 + FUTURE_LIMIT_MS as i128 {
        return RegisterDecision::TooFarAhead;
    }
    match stored {
        Some((ts, id)) if (new_ts, new_id.as_bytes()) <= (ts, id.as_bytes()) => RegisterDecision::Keep,
        _ => RegisterDecision::Apply,
    }
}

// ───────────────────────────── groups and channels ─────────────────────────────

/// `rk` from the post's message key.
pub fn post_reaction_key(message_key: &[u8; 32]) -> [u8; 32] {
    hkdf32(message_key, RX_KEY_INFO.as_bytes())
}

/// `k_u`; `None` when an id could not have been written by a client (empty,
/// over 128 bytes, or containing the separator).
pub fn reactor_key(rk: &[u8; 32], group_id: &str, post_id: &str, reactor_uid: i64) -> Option<[u8; 32]> {
    let ok = |s: &str| !s.is_empty() && s.len() <= TARGET_MAX_BYTES && !s.contains('|');
    if !ok(group_id) || !ok(post_id) || reactor_uid <= 0 {
        return None;
    }
    Some(hkdf32(rk, format!("{GRX_LABEL}|{group_id}|{post_id}|{reactor_uid}").as_bytes()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupReactionError {
    /// The react content breaks §W7.3, or `to` is not the post.
    Content,
    /// A group or post id that cannot be bound into the key.
    Ids,
    /// The blob would exceed 1024 bytes.
    TooLong,
}

impl std::fmt::Display for GroupReactionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            GroupReactionError::Content => "reaction-content",
            GroupReactionError::Ids => "reaction-ids",
            GroupReactionError::TooLong => "reaction-too-long",
        })
    }
}

/// Seals this user's reaction state for one post (24 random bytes drawn).
/// The plaintext is the padded `react` JSON without `caps`; its length — and
/// so the blob's — does not depend on `e` ([`pad_reserve`]).
#[allow(clippy::too_many_arguments)]
pub fn group_reaction_seal(
    rk: &[u8; 32],
    group_id: &str,
    post_id: &str,
    my_uid: i64,
    id: &str,
    e: &[String],
    ts: u64,
    rng: &mut dyn Rng,
) -> Result<String, GroupReactionError> {
    if id.is_empty() || !is_valid_react(post_id, e, ts) {
        return Err(GroupReactionError::Content);
    }
    let key = reactor_key(rk, group_id, post_id, my_uid).ok_or(GroupReactionError::Ids)?;
    let pt = TypedPlaintext::React { id: id.into(), to: post_id.into(), e: e.to_vec(), ts };
    let json = crate::plaintext::build(&pt, &Soft::default(), Some(PAD_BLOCK)).ok_or(GroupReactionError::Content)?;
    let mut nonce = [0u8; 24];
    rng.fill(&mut nonce);
    let mut raw = nonce.to_vec();
    raw.extend_from_slice(&secretbox_seal(json.as_bytes(), &nonce, &key));
    let blob = format!("{BLOB_PREFIX}{}", b64(&raw));
    if blob.len() > BLOB_MAX_BYTES {
        return Err(GroupReactionError::TooLong);
    }
    Ok(blob)
}

/// One user's reaction state for a post.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupReaction {
    pub id: String,
    pub e: Vec<String>,
    pub ts: u64,
}

/// Opens the blob the server stored for `(post_id, reactor_uid)`. `None`:
/// not an `rx1:` blob, not sealed under this post's key for this user (a row
/// re-attributed to another user, post or group does not open), or not a
/// `react` state for this post.
pub fn group_reaction_open(rk: &[u8; 32], group_id: &str, post_id: &str, reactor_uid: i64, blob: &str) -> Option<GroupReaction> {
    if blob.len() > BLOB_MAX_BYTES {
        return None;
    }
    let raw = strict_json::b64(blob.strip_prefix(BLOB_PREFIX)?)?;
    if raw.len() < 24 + 16 {
        return None;
    }
    let key = reactor_key(rk, group_id, post_id, reactor_uid)?;
    let nonce: [u8; 24] = raw[..24].try_into().ok()?;
    let pt = secretbox_open(&raw[24..], &nonce, &key)?;
    let text = String::from_utf8(pt).ok()?;
    match classify(&text) {
        Classified::Typed(p) => match p.pt {
            TypedPlaintext::React { id, to, e, ts } if to == post_id => Some(GroupReaction { id, e, ts }),
            _ => None,
        },
        Classified::Unsupported(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fast_clock_cannot_invert_the_register() {
        // States A then B from a clock 3 h fast, delivered B then A.
        let now = 1_790_000_000_000i64;
        let (a, b) = ((now as u64 + 10_800_000, "rx-a"), (now as u64 + 10_800_001, "rx-b"));
        assert_eq!(register_decide(None, b.0, b.1, now), RegisterDecision::Apply);
        assert_eq!(register_decide(Some(b), a.0, a.1, now), RegisterDecision::Keep, "the older state arrives later and loses");
        assert_eq!(register_decide(Some(b), b.0, b.1, now), RegisterDecision::Keep, "a duplicate");
        assert_eq!(register_decide(Some(a), a.0, "rx-b", now), RegisterDecision::Apply, "same ts: the larger id wins");
        assert_eq!(register_decide(None, now as u64 + FUTURE_LIMIT_MS as u64 + 1, "x", now), RegisterDecision::TooFarAhead);
        assert_eq!(register_decide(None, u64::MAX, "x", i64::MAX), RegisterDecision::TooFarAhead, "no overflow at the extremes");
    }

    #[test]
    fn emoji_entries() {
        assert!(is_emoji_entry("❤️") && is_emoji_entry("👨‍👩‍👧‍👦") && is_emoji_entry("ok"));
        assert!(!is_emoji_entry("") && !is_emoji_entry("a\nb") && !is_emoji_entry("\u{7f}") && !is_emoji_entry(&"é".repeat(33)));
        assert!(!is_emoji_entry("a\"b") && !is_emoji_entry("a\\b"), "nothing JSON would escape");
        // The JSON length of `e` is a function of the byte lengths alone.
        for e in [vec![], vec!["❤️".to_string()], vec!["👨‍👩‍👧‍👦".to_string(), "/".to_string()], vec!["é".repeat(32), "x".repeat(64), "🏴󠁧󠁢󠁥󠁮󠁧󠁿".to_string()]] {
            assert!(is_valid_react("m1", &e, 1));
            assert_eq!(e_json_len(&e), serde_json::to_string(&e).unwrap().len(), "{e:?}");
            assert_eq!(e_json_len(&e) + pad_reserve(&e), E_JSON_MAX);
        }
        assert_eq!((E_JSON_MAX, e_json_len(&["x".repeat(64), "y".repeat(64), "z".repeat(64)]), pad_reserve(&[])), (202, 202, 200));
        assert!(is_valid_react("m1", &[], 1));
        assert!(!is_valid_react("m1", &["a".into(), "a".into()], 1), "the set has no duplicates");
        assert!(!is_valid_react("", &[], 1) && !is_valid_react("m1", &[], 0));
        assert!(!is_valid_react("m1", &["1".into(), "2".into(), "3".into(), "4".into()], 1));
    }
}
