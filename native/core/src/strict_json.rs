//! JSON for everything wire level 2 parses (wire-1.1 §W3.2, §W8.2): the
//! serde_json grammar, but an object with a duplicate key — at any depth —
//! is not JSON at all.
//!
//! Two parsers that disagree about which occurrence of a repeated key counts
//! (`NSJSONSerialization` keeps the first, serde the last) can be shown two
//! different messages under one signature. Rejecting the
//! document removes the question.
//!
//! Numbers follow the protocol rule: an integer is a JSON number written
//! without fraction or exponent, in `[0, 2^53)`. [`uint`] is the only way a
//! level-2 parser reads one — no `f64`, no cast.

use std::fmt;

use serde::de::{DeserializeSeed, Deserializer, Error as DeError, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

/// Largest integer every client can carry exactly.
pub const MAX_SAFE_INT: u64 = (1u64 << 53) - 1;

struct Strict;

impl<'de> DeserializeSeed<'de> for Strict {
    type Value = Value;

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        d.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value without duplicate keys")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }

    fn visit_f64<E: DeError>(self, v: f64) -> Result<Value, E> {
        Number::from_f64(v).map(Value::Number).ok_or_else(|| E::custom("non-finite number"))
    }

    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }

    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut out = Vec::new();
        while let Some(v) = seq.next_element_seed(Strict)? {
            out.push(v);
        }
        Ok(Value::Array(out))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut out = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if out.contains_key(&key) {
                return Err(A::Error::custom("duplicate key"));
            }
            let v = map.next_value_seed(Strict)?;
            out.insert(key, v);
        }
        Ok(Value::Object(out))
    }
}

/// Parses `text`; `None` for anything that is not one JSON value, nests
/// deeper than serde's limit (128), holds a number outside `f64`, or repeats
/// a key inside one object.
pub fn parse(text: &str) -> Option<Value> {
    let mut de = serde_json::Deserializer::from_str(text);
    let value = Strict.deserialize(&mut de).ok()?;
    de.end().ok()?;
    Some(value)
}

/// [`parse`] that also requires a top-level object.
pub fn parse_object(text: &str) -> Option<Map<String, Value>> {
    match parse(text)? {
        Value::Object(m) => Some(m),
        _ => None,
    }
}

/// A protocol integer: written without fraction or exponent, in `[0, 2^53)`.
pub fn uint(v: &Value) -> Option<u64> {
    v.as_u64().filter(|n| *n <= MAX_SAFE_INT)
}

/// Strict standard base64 (padding, canonical trailing bits).
pub fn b64(s: &str) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    STANDARD.decode(s).ok()
}

/// [`b64`] of exactly `N` bytes.
pub fn b64_n<const N: usize>(s: &str) -> Option<[u8; N]> {
    b64(s)?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicates_are_rejected_at_every_depth() {
        assert!(parse(r#"{"a":1,"b":{"c":[{"d":1}]}}"#).is_some());
        assert!(parse(r#"{"a":1,"a":2}"#).is_none());
        assert!(parse(r#"{"a":{"b":1,"b":1}}"#).is_none());
        assert!(parse(r#"[{"x":null,"x":null}]"#).is_none());
        // An escaped spelling of the same key is the same key.
        assert!(parse(r#"{"a":1,"\u0061":2}"#).is_none());
    }

    #[test]
    fn grammar_edges() {
        assert!(parse("").is_none());
        assert!(parse("{} x").is_none());
        assert!(parse("{\"a\":1e400}").is_none(), "outside f64");
        assert!(parse(&"[".repeat(200)).is_none(), "deeper than the recursion limit");
        assert!(parse(r#"{"a":"\ud800"}"#).is_none(), "lone surrogate");
        assert!(parse_object("[]").is_none());
    }

    #[test]
    fn integers_are_integers() {
        let v = parse(r#"{"a":7,"b":7.0,"c":7e0,"d":-1,"e":9007199254740991,"f":9007199254740992,"g":18446744073709551616}"#).unwrap();
        assert_eq!(uint(&v["a"]), Some(7));
        assert_eq!(uint(&v["b"]), None);
        assert_eq!(uint(&v["c"]), None);
        assert_eq!(uint(&v["d"]), None);
        assert_eq!(uint(&v["e"]), Some(MAX_SAFE_INT));
        assert_eq!(uint(&v["f"]), None);
        assert_eq!(uint(&v["g"]), None);
    }
}
