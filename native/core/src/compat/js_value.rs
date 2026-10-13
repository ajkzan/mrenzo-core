//! ECMAScript coercions (ToBoolean, ToString, ToNumber) of a value that came
//! out of `JSON.parse`, held as a `serde_json::Value`.
//!
//! A JSON value has no functions, so ToPrimitive of an object can only go
//! two ways: `Object.prototype.toString` ("[object Object]"), or — when the
//! object carries its OWN `toString` key, which is then a non-callable data
//! property — `OrdinaryToPrimitive` falls through to `valueOf` (returns the
//! object) and throws a TypeError ([`NotPrimitive`]). Arrays go through
//! `Array.prototype.join(",")` (null elements → ""), which applies ToString
//! to every other element and so propagates that TypeError.
//!
//! Faithful: [`to_string`], [`to_number`]. Two approximations modules
//! shipped (and pin) are kept as separately named functions:
//! [`to_string_lenient`] renders an own-`toString` object as
//! "[object Object]" instead of throwing (`sealed_sender`, whose callers end
//! in the same outcome either way), and [`to_string_lenient_ties_up`] /
//! [`to_number_lenient_ties_up_u128_radix`] additionally use the ties-up
//! Number→String and u128 radix approximations of `js_number` (`x3dh`,
//! `sender_keys`).

use serde_json::{Number, Value};

use crate::compat::js_number::{number_to_string, number_to_string_ties_up, string_to_number, string_to_number_u128_radix};

/// The f64 a JSON number is in JS (`serde_json` keeps integers exact; JS
/// rounds them to the nearest double, which `as_f64` does too).
pub fn number_value(n: &Number) -> f64 {
    n.as_f64().unwrap_or(f64::NAN)
}

/// ToBoolean (`!x`, `x || y`, `if (x)`). JSON cannot carry NaN or
/// `undefined`, so falsy = `null`, `false`, `0`/`-0`, `""`.
pub fn to_boolean(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => {
            let x = number_value(n);
            x != 0.0 && !x.is_nan()
        }
        Value::String(s) => !s.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

/// [`to_boolean`] of a property read (`None` = absent = `undefined`, falsy).
pub fn to_boolean_opt(v: Option<&Value>) -> bool {
    v.is_some_and(to_boolean)
}

/// The TypeError ToPrimitive throws for an object with an own `toString`
/// data property ("Cannot convert object to primitive value").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotPrimitive;

impl std::fmt::Display for NotPrimitive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TypeError: Cannot convert object to primitive value")
    }
}

impl std::error::Error for NotPrimitive {}

/// ECMAScript `ToString(v)` (`String(v)`, template literals, `regex.test(v)`,
/// `atob(v)`).
pub fn to_string(v: &Value) -> Result<String, NotPrimitive> {
    to_string_core(v, number_to_string, true)
}

/// APPROXIMATION of [`to_string`]: an object with an own `toString` key
/// renders as "[object Object]" instead of throwing. Numbers are exact JS.
pub fn to_string_lenient(v: &Value) -> String {
    to_string_core(v, number_to_string, false).unwrap_or_default() // `Err` only with the flag set
}

/// APPROXIMATION of [`to_string`]: as [`to_string_lenient`], and numbers go
/// through `js_number::number_to_string_ties_up`.
pub fn to_string_lenient_ties_up(v: &Value) -> String {
    to_string_core(v, number_to_string_ties_up, false).unwrap_or_default() // `Err` only with the flag set
}

fn to_string_core(v: &Value, number: fn(f64) -> String, own_to_string_throws: bool) -> Result<String, NotPrimitive> {
    Ok(match v {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => number(number_value(n)),
        Value::String(s) => s.clone(),
        Value::Array(items) => {
            // Array.prototype.join(","): null (and undefined) elements render as "".
            let mut parts = Vec::with_capacity(items.len());
            for item in items {
                parts.push(if item.is_null() { String::new() } else { to_string_core(item, number, own_to_string_throws)? });
            }
            parts.join(",")
        }
        Value::Object(o) => {
            if own_to_string_throws && o.contains_key("toString") {
                return Err(NotPrimitive);
            }
            "[object Object]".into()
        }
    })
}

/// ECMAScript `ToNumber(v)` (`Number(v)`, arithmetic) of a property read
/// (`None` = `undefined` → NaN).
pub fn to_number(v: Option<&Value>) -> Result<f64, NotPrimitive> {
    Ok(match v {
        None => f64::NAN,
        Some(Value::Null) => 0.0,
        Some(Value::Bool(b)) => f64::from(u8::from(*b)),
        Some(Value::Number(n)) => number_value(n),
        Some(Value::String(s)) => string_to_number(s),
        Some(compound @ (Value::Array(_) | Value::Object(_))) => string_to_number(&to_string(compound)?),
    })
}

/// APPROXIMATION of [`to_number`]: compounds go through
/// [`to_string_lenient_ties_up`] and strings through
/// `js_number::string_to_number_u128_radix`.
pub fn to_number_lenient_ties_up_u128_radix(v: &Value) -> f64 {
    match v {
        Value::Null => 0.0,
        Value::Bool(b) => f64::from(u8::from(*b)),
        Value::Number(n) => number_value(n),
        Value::String(s) => string_to_number_u128_radix(s),
        Value::Array(_) | Value::Object(_) => string_to_number_u128_radix(&to_string_lenient_ties_up(v)),
    }
}

#[cfg(test)]
mod tests {
    // The tie constants are exact doubles, written out in full on purpose.
    #![allow(clippy::excessive_precision)]

    use super::*;
    use serde_json::json;

    #[test]
    fn to_boolean_matches_js() {
        for (v, want) in [
            (json!(null), false),
            (json!(false), false),
            (json!(true), true),
            (json!(0), false),
            (json!(-0.0), false),
            (json!(0.0), false),
            (json!(1e-300), true),
            (json!(-1), true),
            (json!(""), false),
            (json!("0"), true),
            (json!(" "), true),
            (json!([]), true),
            (json!({}), true),
        ] {
            assert_eq!(to_boolean(&v), want, "{v}");
            assert_eq!(to_boolean_opt(Some(&v)), want, "{v}");
        }
        assert!(!to_boolean_opt(None));
    }

    #[test]
    fn to_string_matches_js() {
        // Expected strings from Node `String(JSON.parse(...))`.
        for (v, want) in [
            (json!(null), "null"),
            (json!(true), "true"),
            (json!(1001), "1001"),
            (json!(1.5), "1.5"),
            (json!(-0.0), "0"),
            (json!(1e21), "1e+21"),
            (json!(158508.102783203125), "158508.10278320312"),
            (json!("x"), "x"),
            (json!([]), ""),
            (json!([null]), ""),
            (json!(["<b64>"]), "<b64>"),
            (json!([[["x"]]]), "x"),
            (json!([1, null, [2, "x"], {}]), "1,,2,x,[object Object]"),
            (json!({"a": 1}), "[object Object]"),
            (json!({"valueOf": 1}), "[object Object]"),
        ] {
            assert_eq!(to_string(&v).as_deref(), Ok(want), "{v}");
            assert_eq!(to_string_lenient(&v), want, "{v}");
        }
        for v in [json!({"toString": 1}), json!({"toString": null}), json!([1, {"toString": "x"}])] {
            assert_eq!(to_string(&v), Err(NotPrimitive), "{v}");
            assert!(to_string_lenient(&v).contains("[object Object]"), "{v}");
        }
        assert_eq!(to_string_lenient_ties_up(&json!([158508.102783203125])), "158508.10278320313");
        assert_eq!(to_string_lenient_ties_up(&json!({"toString": 1})), "[object Object]");
    }

    #[test]
    fn to_number_matches_js() {
        for (v, want) in [
            (json!(null), 0.0),
            (json!(true), 1.0),
            (json!(false), 0.0),
            (json!(" 0x3E9 "), 1001.0),
            (json!("1001"), 1001.0),
            (json!(""), 0.0),
            (json!([]), 0.0),
            (json!([7]), 7.0),
            (json!([[" 12 "]]), 12.0),
            (json!(2.5), 2.5),
        ] {
            assert_eq!(to_number(Some(&v)), Ok(want), "{v}");
            assert_eq!(to_number_lenient_ties_up_u128_radix(&v), want, "{v}");
        }
        for v in [json!("x"), json!([1, 2]), json!({}), json!("0x")] {
            assert!(to_number(Some(&v)).unwrap().is_nan(), "{v}");
            assert!(to_number_lenient_ties_up_u128_radix(&v).is_nan(), "{v}");
        }
        assert!(to_number(None).unwrap().is_nan());
        assert_eq!(to_number(Some(&json!({"toString": 1}))), Err(NotPrimitive));
        assert!(to_number_lenient_ties_up_u128_radix(&json!({"toString": 1})).is_nan());
    }
}
