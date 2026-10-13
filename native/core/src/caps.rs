//! Capabilities (wire-1.1 §W4; 03-crypto §V3.16): the wire level a client
//! implements as a receiver, plus feature tokens.
//!
//! ```text
//! caps      = {"v":<level 2..65535>,"f":["pq","ptt"]}          `f` sorted, omitted when empty
//! statement = {"v":1,"uid":…,"caps":{…},"ts":…,"sig":"<b64 64>"}
//! canonical = "mrenzo-caps-v1|" + uid + "|" + caps.v + "|" + join(",", caps.f) + "|" + ts
//! sig       = Ed25519(ED_uid, UTF-8(canonical))                 strict, under the PINNED key of uid
//! ```
//!
//! In band, `caps` rides as an optional top-level key of every typed
//! plaintext of a 1:1 session; a 1.0.0 receiver ignores it. It is parsed
//! leniently there — a malformed `caps` is an absent `caps`, never a broken
//! message — and strictly inside a statement, which this client signs itself.

use serde_json::{Map, Value};

use crate::primitives::{b64, ed25519_sign};
use crate::strict_json;

/// The level this core implements.
pub const WIRE_LEVEL: u16 = 2;
/// Lowest level that may be announced (level 1 = 1.0.0, never announced).
pub const MIN_LEVEL: u64 = 2;
pub const MAX_LEVEL: u64 = 65_535;
/// At most this many tokens are kept from a received `f`.
pub const MAX_FLAGS: usize = 32;
/// KEM prekeys are published and confirmed by the server (§W6).
pub const FLAG_PQ: &str = "pq";
/// «Рация» is on and transmissions are accepted (§W7.2).
pub const FLAG_PTT: &str = "ptt";
pub const STATEMENT_LABEL: &str = "mrenzo-caps-v1";
pub const STATEMENT_VERSION: u64 = 1;
pub const STATEMENT_MAX_BYTES: usize = 1024;
/// A statement dated further ahead than this is refused.
pub const STATEMENT_FUTURE_MS: i64 = 5 * 60 * 1000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Caps {
    pub v: u16,
    /// Sorted (byte order), unique, each `^[a-z0-9][a-z0-9-]{0,15}$`.
    pub f: Vec<String>,
}

/// `^[a-z0-9][a-z0-9-]{0,15}$`.
pub fn is_flag(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=16).contains(&b.len())
        && b[0] != b'-'
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

impl Caps {
    /// `None` for a level outside `[2, 65535]` or a token of the wrong shape.
    pub fn new(v: u64, flags: &[&str]) -> Option<Caps> {
        if !(MIN_LEVEL..=MAX_LEVEL).contains(&v) || flags.iter().any(|f| !is_flag(f)) {
            return None;
        }
        let mut f: Vec<String> = flags.iter().map(|s| s.to_string()).collect();
        f.sort();
        f.dedup();
        (f.len() <= MAX_FLAGS).then_some(Caps { v: v as u16, f })
    }

    /// What this build announces, with the given feature tokens.
    pub fn own(flags: &[&str]) -> Option<Caps> {
        Caps::new(WIRE_LEVEL as u64, flags)
    }

    pub fn has(&self, flag: &str) -> bool {
        self.f.iter().any(|f| f == flag)
    }

    /// The lenient in-band parse (§W4.1): not an object, `v` missing, not an
    /// integer or out of range → `None`. Entries of `f` that are not tokens
    /// are skipped, duplicates collapse, at most [`MAX_FLAGS`] are kept (in
    /// array order, before sorting); unknown keys are ignored.
    pub fn from_value_lenient(v: &Value) -> Option<Caps> {
        let o = v.as_object()?;
        let level = strict_json::uint(o.get("v")?).filter(|l| (MIN_LEVEL..=MAX_LEVEL).contains(l))?;
        let mut f: Vec<String> = Vec::new();
        if let Some(Value::Array(items)) = o.get("f") {
            for item in items {
                if f.len() == MAX_FLAGS {
                    break;
                }
                if let Value::String(s) = item {
                    if is_flag(s) && !f.iter().any(|x| x == s) {
                        f.push(s.clone());
                    }
                }
            }
        }
        f.sort();
        Some(Caps { v: level as u16, f })
    }

    /// The strict form a statement must carry: exactly what [`Caps::to_json`]
    /// writes (tokens valid, sorted, unique; `f` absent or non-empty).
    fn from_value_strict(v: &Value) -> Option<Caps> {
        let o = v.as_object()?;
        let level = strict_json::uint(o.get("v")?).filter(|l| (MIN_LEVEL..=MAX_LEVEL).contains(l))?;
        let mut f = Vec::new();
        match o.get("f") {
            None => {}
            Some(Value::Array(items)) if !items.is_empty() && items.len() <= MAX_FLAGS => {
                for item in items {
                    let s = item.as_str().filter(|s| is_flag(s))?;
                    if f.last().is_some_and(|prev: &String| prev.as_str() >= s) {
                        return None;
                    }
                    f.push(s.to_string());
                }
            }
            Some(_) => return None,
        }
        o.keys().all(|k| k == "v" || k == "f").then_some(Caps { v: level as u16, f })
    }

    pub fn to_value(&self) -> Value {
        let mut o = Map::new();
        o.insert("v".into(), Value::from(self.v));
        if !self.f.is_empty() {
            o.insert("f".into(), Value::Array(self.f.iter().map(|s| Value::String(s.clone())).collect()));
        }
        Value::Object(o)
    }

    /// `{"v":2,"f":["pq","ptt"]}`; `{"v":2}` without tokens.
    pub fn to_json(&self) -> String {
        self.to_value().to_string()
    }

    /// Parses caps JSON text leniently (hosts keep it as text).
    pub fn parse_lenient(json: &str) -> Option<Caps> {
        Caps::from_value_lenient(&strict_json::parse(json)?)
    }
}

// ───────────────────────────── published statement ─────────────────────────────

pub fn statement_canonical(uid: u64, caps: &Caps, ts: u64) -> String {
    format!("{STATEMENT_LABEL}|{uid}|{}|{}|{ts}", caps.v, caps.f.join(","))
}

/// The statement JSON this client publishes (`POST /api/caps`).
pub fn statement_sign(ed_secret64: &[u8; 64], uid: u64, caps: &Caps, ts: u64) -> String {
    let sig = ed25519_sign(ed_secret64, statement_canonical(uid, caps, ts).as_bytes());
    format!("{{\"v\":1,\"uid\":{uid},\"caps\":{},\"ts\":{ts},\"sig\":\"{}\"}}", caps.to_json(), b64(&sig))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StatementCheck {
    /// Verified: record `caps`, remember `ts` as the newest accepted.
    Ok { caps: Caps, ts: u64 },
    /// Not a statement (shape, size, duplicate key, non-canonical caps).
    Malformed,
    /// Signed for another uid.
    WrongUid,
    /// Dated more than 5 minutes ahead of `now`.
    Future,
    /// Older than the newest statement already accepted under this pin.
    Stale,
    BadSignature,
}

/// Verifies a statement served for `expect_uid` under that user's PINNED
/// signing key. `min_ts` = the `ts` of the newest statement already accepted
/// for this pin (0 = none): the server can replay an old statement, and this
/// is what makes that only a delay.
pub fn statement_verify(json: &str, expect_uid: u64, pinned_ed: &[u8; 32], min_ts: u64, now_ms: i64) -> StatementCheck {
    if json.len() > STATEMENT_MAX_BYTES {
        return StatementCheck::Malformed;
    }
    let Some(o) = strict_json::parse_object(json) else { return StatementCheck::Malformed };
    let int = |k: &str| o.get(k).and_then(strict_json::uint);
    let (Some(v), Some(uid), Some(ts)) = (int("v"), int("uid"), int("ts")) else { return StatementCheck::Malformed };
    let Some(caps) = o.get("caps").and_then(Caps::from_value_strict) else { return StatementCheck::Malformed };
    let Some(sig) = o.get("sig").and_then(Value::as_str).and_then(strict_json::b64_n::<64>) else {
        return StatementCheck::Malformed;
    };
    if v != STATEMENT_VERSION || uid == 0 || ts == 0 {
        return StatementCheck::Malformed;
    }
    if uid != expect_uid {
        return StatementCheck::WrongUid;
    }
    // `ts` < 2^53 and the bound below is far from i64::MAX: no overflow.
    if ts as i64 > now_ms.saturating_add(STATEMENT_FUTURE_MS) {
        return StatementCheck::Future;
    }
    if ts < min_ts {
        return StatementCheck::Stale;
    }
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(pinned_ed) else { return StatementCheck::BadSignature };
    let sig = ed25519_dalek::Signature::from_bytes(&sig);
    if vk.verify_strict(statement_canonical(uid, &caps, ts).as_bytes(), &sig).is_err() {
        return StatementCheck::BadSignature;
    }
    StatementCheck::Ok { caps, ts }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn lenient_parse_never_fails_a_message() {
        let c = Caps::from_value_lenient(&json!({"v":2,"f":["ptt","pq","pq","BAD","-x",7,"a-b"],"extra":1})).unwrap();
        assert_eq!(c, Caps { v: 2, f: vec!["a-b".into(), "pq".into(), "ptt".into()] });
        assert_eq!(c.to_json(), r#"{"v":2,"f":["a-b","pq","ptt"]}"#);
        assert_eq!(Caps::from_value_lenient(&json!({"v":2})).unwrap().to_json(), r#"{"v":2}"#);
        assert_eq!(Caps::from_value_lenient(&json!({"v":3,"f":"pq"})).unwrap().f.len(), 0);
        for bad in [json!(2), json!({"f":["pq"]}), json!({"v":1}), json!({"v":65536}), json!({"v":2.0}), json!({"v":"2"}), json!(null)] {
            assert!(Caps::from_value_lenient(&bad).is_none(), "{bad}");
        }
        let many: Vec<String> = (0..40).map(|i| format!("f{i}")).collect();
        assert_eq!(Caps::from_value_lenient(&json!({"v":2,"f":many})).unwrap().f.len(), MAX_FLAGS);
    }

    #[test]
    fn flags_have_one_shape() {
        for ok in ["pq", "ptt", "a", "0", "a-b-c", "abcdefghijklmnop"] {
            assert!(is_flag(ok), "{ok}");
        }
        for bad in ["", "-a", "A", "a_b", "abcdefghijklmnopq", "é", "a b"] {
            assert!(!is_flag(bad), "{bad}");
        }
    }
}
