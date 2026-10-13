//! The push hint `mz` for the Notification Service Extension (wire-1.1
//! §W7.8; 03-crypto §V3.20).
//!
//! Hidden chats require «Скрывать отправителя», and such pushes carry no
//! ids — so the extension could not know which chat a push belongs to. For a
//! token registered with `nse:1` the server adds one key to the alert
//! payload, readable only on the device:
//!
//! ```text
//! mz   = "OSB1:" + b64( eph_pub[32] ‖ nonce[24] ‖ crypto_box(hint, nonce, IK_recipient, eph_priv) )     the offline seal (03 §6)
//! hint = {"from":<uid>[,"mid":"<messageId>"]}       1:1
//!      | {"ch":"<channelId>"[,"mid":"<messageId>"]}  rooms and channels
//! ```
//!
//! The extension opens it with the identity private key and decides what to
//! show. It is STATELESS on purpose: it never touches a session — a second
//! process stepping a ratchet would desync it from the app's.

use serde_json::Value;

use crate::offline_seal::{is_offline_sealed, open_sealed_offline, seal_offline_blob};
use crate::rng::Rng;
use crate::strict_json;

/// The key of the hint in the push payload.
pub const PAYLOAD_KEY: &str = "mz";
pub const HINT_MAX_BYTES: usize = 512;
pub const CHANNEL_ID_MAX_BYTES: usize = 64;
pub const MESSAGE_ID_MAX_BYTES: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PushHint {
    /// A 1:1 message from `from`.
    Direct { from: i64, mid: Option<String> },
    /// A post in room or channel `ch`.
    Channel { ch: String, mid: Option<String> },
}

impl PushHint {
    fn is_valid(&self) -> bool {
        let mid_ok = |m: &Option<String>| m.as_deref().is_none_or(|m| (1..=MESSAGE_ID_MAX_BYTES).contains(&m.len()));
        match self {
            PushHint::Direct { from, mid } => (1..=strict_json::MAX_SAFE_INT as i64).contains(from) && mid_ok(mid),
            PushHint::Channel { ch, mid } => (1..=CHANNEL_ID_MAX_BYTES).contains(&ch.len()) && mid_ok(mid),
        }
    }

    /// `{"from":…[,"mid":…]}` / `{"ch":…[,"mid":…]}`.
    pub fn to_json(&self) -> String {
        let mut o = serde_json::Map::new();
        let mid = match self {
            PushHint::Direct { from, mid } => {
                o.insert("from".into(), Value::from(*from));
                mid
            }
            PushHint::Channel { ch, mid } => {
                o.insert("ch".into(), Value::String(ch.clone()));
                mid
            }
        };
        if let Some(m) = mid {
            o.insert("mid".into(), Value::String(m.clone()));
        }
        Value::Object(o).to_string()
    }

    /// Strict: exactly one of `from` / `ch`; unknown keys ignored.
    pub fn parse(json: &str) -> Option<PushHint> {
        if json.len() > HINT_MAX_BYTES {
            return None;
        }
        let o = strict_json::parse_object(json)?;
        let mid = match o.get("mid") {
            None => None,
            Some(m) => Some(m.as_str()?.to_string()),
        };
        let hint = match (o.get("from"), o.get("ch")) {
            (Some(from), None) => PushHint::Direct { from: strict_json::uint(from)? as i64, mid },
            (None, Some(ch)) => PushHint::Channel { ch: ch.as_str()?.to_string(), mid },
            _ => return None,
        };
        hint.is_valid().then_some(hint)
    }
}

/// What the server does (reference for the vectors; Go seals with its own
/// `sealOfflineBlob`): 32 bytes drawn for the ephemeral key, then 24 for the
/// nonce. `None` for a hint that breaks the rules above.
pub fn push_hint_seal(hint: &PushHint, recipient_identity_pub: &[u8; 32], rng: &mut dyn Rng) -> Option<String> {
    hint.is_valid().then(|| seal_offline_blob(hint.to_json().as_bytes(), recipient_identity_pub, rng))
}

/// Opens `mz` with the device's identity private key. `None`: not an `OSB1:`
/// blob (an unmarked string is NOT accepted here — a hint is always sealed),
/// not sealed to this key, or not a hint.
pub fn push_hint_open(mz: &str, x25519_priv_b64: &str) -> Option<PushHint> {
    if !is_offline_sealed(mz) || mz.len() > 2 * HINT_MAX_BYTES {
        return None;
    }
    PushHint::parse(&open_sealed_offline(mz, x25519_priv_b64)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::{b64, x25519_keypair};
    use crate::rng::StreamRng;

    #[test]
    fn seal_open_and_the_strict_shape() {
        let me = x25519_keypair(&mut StreamRng::new("mz/me"));
        let other = x25519_keypair(&mut StreamRng::new("mz/other"));
        let hint = PushHint::Direct { from: 1001, mid: Some("m-1".into()) };
        let mz = push_hint_seal(&hint, &me.public, &mut StreamRng::new("mz/seal")).unwrap();
        assert_eq!(push_hint_open(&mz, &b64(&me.private)), Some(hint));
        assert_eq!(push_hint_open(&mz, &b64(&other.private)), None, "sealed to another key");
        assert_eq!(push_hint_open(r#"{"from":1001}"#, &b64(&me.private)), None, "an unsealed hint is never accepted");
        let ch = PushHint::Channel { ch: "abc-def-ghi-jkl".into(), mid: None };
        assert_eq!(PushHint::parse(&ch.to_json()), Some(ch));
        for bad in [
            r#"{"from":1001,"ch":"x"}"#,
            r#"{}"#,
            r#"{"from":0}"#,
            r#"{"from":1.0}"#,
            r#"{"from":"1001"}"#,
            r#"{"ch":""}"#,
            r#"{"ch":7}"#,
            r#"{"from":1,"mid":""}"#,
            r#"{"from":1,"mid":5}"#,
            r#"{"from":1,"from":2}"#,
            r#"[1]"#,
        ] {
            assert!(PushHint::parse(bad).is_none(), "{bad}");
        }
        assert!(push_hint_seal(&PushHint::Direct { from: -1, mid: None }, &me.public, &mut StreamRng::new("x")).is_none());
    }
}
