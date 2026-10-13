//! «Найти рядом» — the token exchange object (wire-1.1 §W7.1; 03 §V3.16.5).
//!
//! ```text
//! invite  {"v":1,"op":"invite","ns":"<b64 16>","exp":<ms>}                 soft key on a visible `chat`
//! accept  {"v":1,"op":"accept","ns":…,"exp":…,"tok":"<b64 1..2048 B>"}     t:"nearby" in `ctl` / mesh `ctl`
//! token   {"v":1,"op":"token", "ns":…,"exp":…,"tok":…}                     same
//! stop    {"v":1,"op":"stop",  "ns":…[,"why":"<reason>"]}                  same
//! ```
//!
//! The core never looks inside `tok` (an archived `NIDiscoveryToken` on iOS).
//! Strict: `v` is 1, every field of the op is present and well formed, and a
//! field another op owns is not there. Unknown keys are ignored.

use serde_json::{Map, Value};

use crate::primitives::b64;
use crate::strict_json;

pub const NEARBY_VERSION: u64 = 1;
pub const NS_BYTES: usize = 16;
pub const TOKEN_MAX_BYTES: usize = 2048;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NearbyOp {
    Invite { ns: [u8; NS_BYTES], exp: u64 },
    Accept { ns: [u8; NS_BYTES], exp: u64, tok: Vec<u8> },
    Token { ns: [u8; NS_BYTES], exp: u64, tok: Vec<u8> },
    Stop { ns: [u8; NS_BYTES], why: Option<String> },
}

/// `^[a-z][a-z-]{0,15}$` (informational: declined, ended, timeout…).
pub fn is_why(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=16).contains(&b.len()) && b[0].is_ascii_lowercase() && b.iter().all(|c| c.is_ascii_lowercase() || *c == b'-')
}

impl NearbyOp {
    pub fn op(&self) -> &'static str {
        match self {
            NearbyOp::Invite { .. } => "invite",
            NearbyOp::Accept { .. } => "accept",
            NearbyOp::Token { .. } => "token",
            NearbyOp::Stop { .. } => "stop",
        }
    }

    pub fn ns(&self) -> &[u8; NS_BYTES] {
        match self {
            NearbyOp::Invite { ns, .. } | NearbyOp::Accept { ns, .. } | NearbyOp::Token { ns, .. } | NearbyOp::Stop { ns, .. } => ns,
        }
    }

    /// The builder's own validity: what [`NearbyOp::from_value`] would accept.
    pub fn is_valid(&self) -> bool {
        match self {
            NearbyOp::Invite { exp, .. } => (1..=strict_json::MAX_SAFE_INT).contains(exp),
            NearbyOp::Accept { exp, tok, .. } | NearbyOp::Token { exp, tok, .. } => {
                (1..=strict_json::MAX_SAFE_INT).contains(exp) && (1..=TOKEN_MAX_BYTES).contains(&tok.len())
            }
            NearbyOp::Stop { why, .. } => why.as_deref().is_none_or(is_why),
        }
    }

    pub fn from_value(v: &Value) -> Option<NearbyOp> {
        let o = v.as_object()?;
        if o.get("v").and_then(strict_json::uint) != Some(NEARBY_VERSION) {
            return None;
        }
        let ns: [u8; NS_BYTES] = strict_json::b64_n(o.get("ns")?.as_str()?)?;
        let exp = || -> Option<u64> { o.get("exp").and_then(strict_json::uint).filter(|e| *e >= 1) };
        let tok = || -> Option<Vec<u8>> {
            let t = strict_json::b64(o.get("tok")?.as_str()?)?;
            (1..=TOKEN_MAX_BYTES).contains(&t.len()).then_some(t)
        };
        let has = |k: &str| o.contains_key(k);
        match o.get("op")?.as_str()? {
            "invite" if !has("tok") && !has("why") => Some(NearbyOp::Invite { ns, exp: exp()? }),
            "accept" if !has("why") => Some(NearbyOp::Accept { ns, exp: exp()?, tok: tok()? }),
            "token" if !has("why") => Some(NearbyOp::Token { ns, exp: exp()?, tok: tok()? }),
            "stop" if !has("tok") && !has("exp") => {
                let why = match o.get("why") {
                    None => None,
                    Some(Value::String(s)) if is_why(s) => Some(s.clone()),
                    Some(_) => return None,
                };
                Some(NearbyOp::Stop { ns, why })
            }
            _ => None,
        }
    }

    /// Key order: v, op, ns, exp, tok, why.
    pub fn to_value(&self) -> Value {
        let mut o = Map::new();
        o.insert("v".into(), Value::from(NEARBY_VERSION));
        o.insert("op".into(), Value::String(self.op().into()));
        o.insert("ns".into(), Value::String(b64(self.ns())));
        match self {
            NearbyOp::Invite { exp, .. } => {
                o.insert("exp".into(), Value::from(*exp));
            }
            NearbyOp::Accept { exp, tok, .. } | NearbyOp::Token { exp, tok, .. } => {
                o.insert("exp".into(), Value::from(*exp));
                o.insert("tok".into(), Value::String(b64(tok)));
            }
            NearbyOp::Stop { why, .. } => {
                if let Some(w) = why {
                    o.insert("why".into(), Value::String(w.clone()));
                }
            }
        }
        Value::Object(o)
    }

    pub fn to_json(&self) -> String {
        self.to_value().to_string()
    }

    pub fn parse(json: &str) -> Option<NearbyOp> {
        NearbyOp::from_value(&strict_json::parse(json)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn each_op_has_exactly_its_fields() {
        let ns = b64(&[7u8; 16]);
        let ok = [
            json!({"v":1,"op":"invite","ns":ns,"exp":5}),
            json!({"v":1,"op":"accept","ns":ns,"exp":5,"tok":"AQ=="}),
            json!({"v":1,"op":"token","ns":ns,"exp":5,"tok":"AQ==","future":true}),
            json!({"v":1,"op":"stop","ns":ns}),
            json!({"v":1,"op":"stop","ns":ns,"why":"timeout"}),
        ];
        for v in &ok {
            let op = NearbyOp::from_value(v).unwrap_or_else(|| panic!("{v}"));
            assert!(op.is_valid());
            assert_eq!(NearbyOp::parse(&op.to_json()).as_ref(), Some(&op));
        }
        let bad = [
            json!({"v":2,"op":"invite","ns":ns,"exp":5}),
            json!({"v":1,"op":"invite","ns":ns}),
            json!({"v":1,"op":"invite","ns":ns,"exp":0}),
            json!({"v":1,"op":"invite","ns":ns,"exp":5,"tok":"AQ=="}),
            json!({"v":1,"op":"invite","ns":b64(&[7u8; 15]),"exp":5}),
            json!({"v":1,"op":"accept","ns":ns,"exp":5}),
            json!({"v":1,"op":"accept","ns":ns,"exp":5,"tok":""}),
            json!({"v":1,"op":"accept","ns":ns,"exp":5,"tok":"AR=="}),
            json!({"v":1,"op":"token","ns":ns,"exp":5,"tok":b64(&[0u8; 2049])}),
            json!({"v":1,"op":"stop","ns":ns,"exp":5}),
            json!({"v":1,"op":"stop","ns":ns,"why":"Bad"}),
            json!({"v":1,"op":"verify","ns":ns}),
            json!([1]),
        ];
        for v in &bad {
            assert!(NearbyOp::from_value(v).is_none(), "{v}");
        }
    }
}
