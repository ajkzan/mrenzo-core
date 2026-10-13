//! `JSON.stringify` / `JSON.parse` pieces with JS semantics.
//!
//! - Stringify: `QuoteJSONString` (ES2019 well-formed), the
//!   `[[OwnPropertyKeys]]` order of a parsed object (array-index keys
//!   ascending first, then the rest in creation order), and `JSON.stringify`
//!   of a `JSON.parse` result held as a `serde_json::Value`.
//! - Parse: Hermes 0.14.1's `JSON.parse` grammar, depth rule and UTF-16
//!   strings, as a validating scanner of a top-level OBJECT that reports its
//!   direct members ([`hermes_parse_top_level_object`]). This is the parser
//!   the RN client actually runs; the V8-grammar parsers some modules carry
//!   (with their own depth caps) are documented divergences of those modules.

use serde_json::{Map, Value};

use crate::compat::js_number::{is_str_decimal_literal, number_to_json, number_to_json_ties_up};
use crate::compat::js_value::number_value;

// ───────── JSON.stringify ─────────

/// `QuoteJSONString(s)` appended to `out`: `"` `\` and C0 controls escaped
/// (short forms for \b \t \n \f \r, otherwise lowercase `\u00xx`), everything
/// else raw — including DEL, U+2028/U+2029 and all non-ASCII. For a Rust
/// string (no lone surrogates) this is byte-identical to
/// `serde_json::to_string(s)`.
pub fn quote_json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// [`quote_json_string`] as a new string.
pub fn json_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    quote_json_string(s, &mut out);
    out
}

/// [`quote_json_string`] of a JS string given as UTF-16 code units: a paired
/// surrogate is written as its character, a LONE surrogate as `\udxxx`
/// (ES2019 well-formed `JSON.stringify`).
pub fn quote_json_string_utf16(units: &[u16], out: &mut String) {
    out.push('"');
    let mut i = 0;
    while i < units.len() {
        let u = units[i];
        match u {
            0x08 => out.push_str("\\b"),
            0x09 => out.push_str("\\t"),
            0x0a => out.push_str("\\n"),
            0x0c => out.push_str("\\f"),
            0x0d => out.push_str("\\r"),
            0x22 => out.push_str("\\\""),
            0x5c => out.push_str("\\\\"),
            0x00..=0x1f => out.push_str(&format!("\\u{u:04x}")),
            0xd800..=0xdbff if units.get(i + 1).is_some_and(|n| (0xdc00..=0xdfff).contains(n)) => {
                let cp = 0x10000 + (((u as u32) - 0xd800) << 10) + ((units[i + 1] as u32) - 0xdc00);
                // cp is in U+10000..=U+10FFFF by construction; the fallback is unreachable
                // and exists so that no input can make this function panic.
                out.push(char::from_u32(cp).unwrap_or(char::REPLACEMENT_CHARACTER));
                i += 1;
            }
            0xd800..=0xdfff => out.push_str(&format!("\\u{u:04x}")),
            _ => out.push(char::from_u32(u as u32).unwrap_or(char::REPLACEMENT_CHARACTER)),
        }
        i += 1;
    }
    out.push('"');
}

/// The array index a property key denotes ("0" … "4294967294", canonical
/// decimal, no sign or leading zero), if any.
pub fn array_index(key: &str) -> Option<u32> {
    array_index_units(key.bytes().map(u32::from), key.len())
}

/// [`array_index`] of a key given as UTF-16 code units.
pub fn array_index_utf16(key: &[u16]) -> Option<u32> {
    array_index_units(key.iter().map(|&u| u32::from(u)), key.len())
}

fn array_index_units(units: impl Iterator<Item = u32> + Clone, len: usize) -> Option<u32> {
    const ZERO: u32 = b'0' as u32;
    const NINE: u32 = b'9' as u32;
    if len == 0 || len > 10 || !units.clone().all(|u| (ZERO..=NINE).contains(&u)) {
        return None;
    }
    let mut digits = units;
    if len > 1 && digits.clone().next() == Some(ZERO) {
        return None;
    }
    let n = digits.by_ref().fold(0u64, |acc, u| acc * 10 + u64::from(u - ZERO));
    (n <= 4_294_967_294).then_some(n as u32)
}

/// `[[OwnPropertyKeys]]` of an object created by `JSON.parse` (or a literal):
/// array-index keys ascending, then every other key in creation order —
/// the order `JSON.stringify`, `Object.keys` and `for…in` enumerate. `map`
/// holds the keys in creation order (serde_json `preserve_order`).
pub fn own_property_keys(map: &Map<String, Value>) -> Vec<(&String, &Value)> {
    let mut indices: Vec<(u32, &String, &Value)> = Vec::new();
    let mut rest: Vec<(&String, &Value)> = Vec::new();
    for (k, v) in map {
        match array_index(k) {
            Some(n) => indices.push((n, k, v)),
            None => rest.push((k, v)),
        }
    }
    indices.sort_by_key(|e| e.0);
    indices.into_iter().map(|(_, k, v)| (k, v)).chain(rest).collect()
}

/// `JSON.stringify(v)` of a `JSON.parse` result: JS number formatting
/// (every number is an f64: 1001.0 → "1001", 1e21 → "1e+21"), array-index
/// keys first, [`quote_json_string`] escaping.
pub fn stringify(v: &Value) -> String {
    let mut out = String::new();
    write_value(v, &mut out, number_to_json);
    out
}

/// APPROXIMATION of [`stringify()`] whose numbers go through
/// `js_number::number_to_string_ties_up` (exact decimal ties rounded up).
/// Kept for `mesh_envelope` and `sender_keys`, which pin it.
pub fn stringify_ties_up(v: &Value) -> String {
    let mut out = String::new();
    write_value(v, &mut out, number_to_json_ties_up);
    out
}

fn write_value(v: &Value, out: &mut String, number: fn(f64) -> String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&number(number_value(n))),
        Value::String(s) => quote_json_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out, number);
            }
            out.push(']');
        }
        Value::Object(m) => {
            out.push('{');
            for (i, (k, item)) in own_property_keys(m).into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                quote_json_string(k, out);
                out.push(':');
                write_value(item, out, number);
            }
            out.push('}');
        }
    }
}

// ───────── Hermes JSON.parse ─────────
//
// An iterative (no recursion) validator of Hermes' JSON grammar over the
// whole input that records the direct members of the top-level object.
// Strings are decoded to UTF-16 code units so lone surrogate escapes survive
// exactly as they do in a JS string. Two places differ from V8 (and from
// serde_json): the nesting cap (see HERMES_JSON_MAX_DEPTH) and the number
// lexer (see `hermes_number_end`). Numbers that overflow f64 (`1e400`) are
// ±Infinity, duplicate keys are all reported (JS keeps the LAST value).

/// Deepest value Hermes' `JSON.parse` accepts (top-level value = depth 1).
/// Its parser decrements a 512 budget on entry to every value (scalar or
/// container) and raises `RangeError: Maximum nesting level in JSON parser
/// exceeded` when it reaches 0, i.e. a value at depth 512 throws. Measured
/// on Hermes 0.14.1 (the engine in mobile/ios/Podfile.lock) and 0.75.4:
/// `[`×511 `]`×511 parses, `[`×512 does not; `[`×510 `1` `]`×510 parses,
/// `[`×511 `1` does not; the same for objects and mixes, independent of the
/// JS call-stack depth. V8 has no such limit.
pub const HERMES_JSON_MAX_DEPTH: usize = 511;

/// A direct member of the top-level object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HermesMember {
    /// The key as UTF-16 code units.
    pub key: Vec<u16>,
    /// Byte offset of the member's value (its first non-whitespace byte).
    pub start: usize,
}

impl HermesMember {
    /// `key === name`.
    pub fn key_is(&self, name: &str) -> bool {
        self.key.iter().copied().eq(name.encode_utf16())
    }
}

/// JSON whitespace (not JS whitespace): SPACE, TAB, LF, CR.
fn is_json_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r')
}

/// Index of the first non-JSON-whitespace byte at or after `i`.
pub fn skip_json_ws(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && is_json_ws(b[i]) {
        i += 1;
    }
    i
}

fn hex4(b: &[u8], i: usize) -> Option<u16> {
    let h = b.get(i..i + 4)?;
    let s = std::str::from_utf8(h).ok()?;
    if !s.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    u16::from_str_radix(s, 16).ok()
}

/// The JSON string token starting at `s[i] == '"'`: (decoded UTF-16 units,
/// index after the closing quote); `None` on a syntax error.
pub fn hermes_parse_string(s: &str, mut i: usize) -> Option<(Vec<u16>, usize)> {
    let b = s.as_bytes();
    debug_assert_eq!(b[i], b'"');
    i += 1;
    let mut out = Vec::new();
    loop {
        let c = *b.get(i)?;
        match c {
            b'"' => return Some((out, i + 1)),
            b'\\' => {
                let e = *b.get(i + 1)?;
                i += 2;
                let unit = match e {
                    b'"' => 0x22,
                    b'\\' => 0x5c,
                    b'/' => 0x2f,
                    b'b' => 0x08,
                    b'f' => 0x0c,
                    b'n' => 0x0a,
                    b'r' => 0x0d,
                    b't' => 0x09,
                    b'u' => {
                        let u = hex4(b, i)?;
                        i += 4;
                        u
                    }
                    _ => return None,
                };
                out.push(unit);
            }
            0x00..=0x1f => return None,
            _ => {
                let ch = s[i..].chars().next()?;
                let mut buf = [0u16; 2];
                out.extend_from_slice(ch.encode_utf16(&mut buf));
                i += ch.len_utf8();
            }
        }
    }
}

/// End of the number token at `b[i]` as Hermes' JSON lexer reads it (`b[i]`
/// is '-' or a digit — the only characters that start one). NOT the RFC
/// 8259 grammar V8 uses: Hermes greedily takes the run of `[-+.eE0-9]`,
/// rejects a '0' followed by a digit at its very start, and hands the run to
/// strtod, which must consume all of it. So `1.`, `0.e1`, `-.5`, `-01`, `-00`
/// PARSE on device (V8: throw) while `.5`, `01`, `+1`, `1e`, `1.5.` do not.
/// Verified against Hermes 0.14.1 on all 299,592 strings of length <= 6
/// over `-+.eE019`.
pub fn hermes_number_end(b: &[u8], i: usize) -> Option<usize> {
    let mut j = i;
    while j < b.len() && matches!(b[j], b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9') {
        j += 1;
    }
    let t = &b[i..j];
    if t[0] == b'0' && t.len() > 1 && t[1].is_ascii_digit() {
        return None;
    }
    // "strtod consumes all of it" is exactly the StrDecimalLiteral grammar
    // without `Infinity` (the run cannot contain letters other than e/E).
    is_str_decimal_literal(t).then_some(j)
}

fn parse_literal(b: &[u8], i: usize) -> Option<usize> {
    for lit in [&b"true"[..], b"false", b"null"] {
        if b[i..].starts_with(lit) {
            return Some(i + lit.len());
        }
    }
    None
}

#[derive(Clone, Copy, PartialEq)]
enum Frame {
    Arr,
    Obj,
}

/// `(key, index after ':')`, or None on a syntax error.
fn parse_key(s: &str, i: usize) -> Option<(Vec<u16>, usize)> {
    let b = s.as_bytes();
    let i = skip_json_ws(b, i);
    if b.get(i) != Some(&b'"') {
        return None;
    }
    let (key, i) = hermes_parse_string(s, i)?;
    let i = skip_json_ws(b, i);
    if b.get(i) != Some(&b':') {
        return None;
    }
    Some((key, i + 1))
}

/// Hermes `JSON.parse(s)` succeeded AND produced an object → its direct
/// members in source order (duplicates kept; JS semantics = the LAST one
/// wins). Anything else → `None`: a SyntaxError, the nesting RangeError, or
/// a top-level value that is not an object.
pub fn hermes_parse_top_level_object(s: &str) -> Option<Vec<HermesMember>> {
    let b = s.as_bytes();
    let mut i = skip_json_ws(b, 0);
    if b.get(i) != Some(&b'{') {
        return None;
    }
    let mut members: Vec<HermesMember> = Vec::new();
    let mut stack: Vec<Frame> = Vec::new();
    // Key of the member currently being parsed at depth 1.
    let mut pending_key: Option<Vec<u16>> = None;

    'value: loop {
        // A value starts here at depth stack.len() + 1 (Hermes' parseValue
        // entry): past the cap the whole JSON.parse throws RangeError.
        if stack.len() >= HERMES_JSON_MAX_DEPTH {
            return None;
        }
        i = skip_json_ws(b, i);
        if stack.len() == 1 {
            // A direct member value of the top-level object starts here.
            // The key always precedes its member value; `?` instead of a panic if it ever did not.
            let key = pending_key.take()?;
            members.push(HermesMember { key, start: i });
        }
        match *b.get(i)? {
            open @ (b'{' | b'[') => {
                i = skip_json_ws(b, i + 1);
                let close = if open == b'{' { b'}' } else { b']' };
                if b.get(i) == Some(&close) {
                    i += 1; // empty container: a complete value
                } else if open == b'{' {
                    stack.push(Frame::Obj);
                    let (key, j) = parse_key(s, i)?;
                    if stack.len() == 1 {
                        pending_key = Some(key);
                    }
                    i = j;
                    continue 'value;
                } else {
                    stack.push(Frame::Arr);
                    continue 'value;
                }
            }
            b'"' => i = hermes_parse_string(s, i)?.1,
            b'-' | b'0'..=b'9' => i = hermes_number_end(b, i)?,
            b't' | b'f' | b'n' => i = parse_literal(b, i)?,
            _ => return None,
        }
        // A value just completed: close containers / take the next element.
        loop {
            i = skip_json_ws(b, i);
            match stack.last() {
                None => {
                    return (i == b.len()).then_some(members);
                }
                Some(Frame::Arr) => match *b.get(i)? {
                    b',' => {
                        i += 1;
                        continue 'value;
                    }
                    b']' => {
                        i += 1;
                        stack.pop();
                    }
                    _ => return None,
                },
                Some(Frame::Obj) => match *b.get(i)? {
                    b',' => {
                        let (key, j) = parse_key(s, i + 1)?;
                        if stack.len() == 1 {
                            pending_key = Some(key);
                        }
                        i = j;
                        continue 'value;
                    }
                    b'}' => {
                        i += 1;
                        stack.pop();
                    }
                    _ => return None,
                },
            }
        }
    }
}

/// End of the (already validated) object or array starting at `b[i]`.
pub fn skip_json_container(b: &[u8], i: usize) -> usize {
    let mut depth = 0usize;
    let mut j = i;
    loop {
        match b[j] {
            b'"' => {
                j = skip_json_string(b, j);
                continue;
            }
            b'{' | b'[' => depth += 1,
            b'}' | b']' => {
                depth -= 1;
                if depth == 0 {
                    return j + 1;
                }
            }
            _ => {}
        }
        j += 1;
    }
}

fn skip_json_string(b: &[u8], mut i: usize) -> usize {
    i += 1;
    loop {
        match b[i] {
            b'"' => return i + 1,
            b'\\' => i += 2,
            _ => i += 1,
        }
    }
}

/// The JS value of a scalar member (`typeof` + value), read from an input
/// [`hermes_parse_top_level_object`] accepted.
#[derive(Clone, Debug, PartialEq)]
pub enum HermesScalar {
    /// `typeof === 'string'` (UTF-16, lone surrogates possible).
    String(Vec<u16>),
    /// `typeof === 'number'`: the correctly rounded double (±Infinity on overflow).
    Number(f64),
    /// `true` / `false`.
    Bool(bool),
    Null,
    /// An object or array.
    Compound,
}

/// Read the member value that starts at `start` in a validated document.
/// Total: a `start` or a token the validator would not have produced reads
/// as `Compound` (not a scalar) instead of panicking.
pub fn hermes_scalar_at(s: &str, start: usize) -> HermesScalar {
    let b = s.as_bytes();
    match b.get(start).copied() {
        Some(b'"') => hermes_parse_string(s, start).map_or(HermesScalar::Compound, |(v, _)| HermesScalar::String(v)),
        Some(b'-' | b'0'..=b'9') => {
            // strtod and Rust's parser are both correctly rounded and accept
            // every token the lexer lets through ("1.", "-.5", "-01", "0.e1").
            hermes_number_end(b, start)
                .and_then(|end| s.get(start..end))
                .and_then(|token| token.parse::<f64>().ok())
                .map_or(HermesScalar::Compound, HermesScalar::Number)
        }
        Some(b't') => HermesScalar::Bool(true),
        Some(b'f') => HermesScalar::Bool(false),
        Some(b'n') => HermesScalar::Null,
        _ => HermesScalar::Compound,
    }
}

#[cfg(test)]
mod tests {
    // The tie constants are exact doubles, written out in full on purpose.
    #![allow(clippy::excessive_precision)]

    use super::*;
    use serde_json::json;

    #[test]
    fn quote_matches_serde_json_for_every_rust_string() {
        let mut all = String::new();
        for cp in (0..0x3000u32).chain(0xd7f0..0xe010).chain(0xfff0..0x10010).chain(0x10fff0..=0x10ffff) {
            if let Some(c) = char::from_u32(cp) {
                all.push(c);
                let one = c.to_string();
                assert_eq!(json_quote(&one), serde_json::to_string(&one).unwrap(), "U+{cp:04X}");
                let units: Vec<u16> = one.encode_utf16().collect();
                let mut u = String::new();
                quote_json_string_utf16(&units, &mut u);
                assert_eq!(u, json_quote(&one), "U+{cp:04X}");
            }
        }
        assert_eq!(json_quote(&all), serde_json::to_string(&all).unwrap());
        assert_eq!(json_quote("\u{1}\u{7f}\u{2028}\"\\/"), "\"\\u0001\u{7f}\u{2028}\\\"\\\\/\"");
    }

    #[test]
    fn quote_utf16_escapes_lone_surrogates() {
        let mut out = String::new();
        quote_json_string_utf16(&[0xd800, 0x78, 0xdc00, 0xd83d, 0xde00, 0xdbff], &mut out);
        // Node: JSON.stringify("\ud800x\udc00\ud83d\ude00\udbff")
        assert_eq!(out, "\"\\ud800x\\udc00\u{1F600}\\udbff\"");
    }

    #[test]
    fn array_index_keys() {
        for (k, want) in [
            ("0", Some(0)),
            ("7", Some(7)),
            ("4294967294", Some(4_294_967_294)),
            ("4294967295", None),
            ("4294967296", None),
            ("99999999999", None),
            ("01", None),
            ("00", None),
            ("+1", None),
            ("-1", None),
            ("1.0", None),
            ("", None),
            ("1e3", None),
            (" 1", None),
        ] {
            assert_eq!(array_index(k), want, "{k:?}");
            let units: Vec<u16> = k.encode_utf16().collect();
            assert_eq!(array_index_utf16(&units), want, "{k:?}");
        }
        assert_eq!(array_index_utf16(&[0x31, 0xd800]), None);
    }

    #[test]
    fn stringify_orders_index_keys_first_and_formats_numbers_like_js() {
        let v: Value = serde_json::from_str(r#"{"b":1,"2":2,"a":[1.0,-0.0,1e21],"1":"x","01":3,"4294967295":4,"0":null}"#).unwrap();
        // Node: JSON.stringify(JSON.parse(same)) →
        assert_eq!(stringify(&v), r#"{"0":null,"1":"x","2":2,"b":1,"a":[1,0,1e+21],"01":3,"4294967295":4}"#);
        assert_eq!(stringify_ties_up(&v), stringify(&v));
        let keys: Vec<&str> = own_property_keys(v.as_object().unwrap()).into_iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["0", "1", "2", "b", "a", "01", "4294967295"]);
        let tie = json!({"x": [158508.102783203125], "s": "\u{0}é"});
        assert_eq!(stringify(&tie), "{\"x\":[158508.10278320312],\"s\":\"\\u0000é\"}");
        assert_eq!(stringify_ties_up(&tie), "{\"x\":[158508.10278320313],\"s\":\"\\u0000é\"}");
    }

    fn members(s: &str) -> Option<Vec<(String, HermesScalar)>> {
        let m = hermes_parse_top_level_object(s)?;
        Some(m.into_iter().map(|m| (String::from_utf16_lossy(&m.key), hermes_scalar_at(s, m.start))).collect())
    }

    #[test]
    fn hermes_top_level_object_members() {
        let got = members(r#" {"v":2, "dh":"a\u00e9\ud800", "n":1e0, "v":-0.5e1, "x":[{"y":1}], "t":true, "z":null, "i":1e400} "#).unwrap();
        assert_eq!(
            got,
            vec![
                ("v".into(), HermesScalar::Number(2.0)),
                ("dh".into(), HermesScalar::String(vec![0x61, 0xe9, 0xd800])),
                ("n".into(), HermesScalar::Number(1.0)),
                ("v".into(), HermesScalar::Number(-5.0)),
                ("x".into(), HermesScalar::Compound),
                ("t".into(), HermesScalar::Bool(true)),
                ("z".into(), HermesScalar::Null),
                ("i".into(), HermesScalar::Number(f64::INFINITY)),
            ]
        );
        // Hermes' strtod lexer accepts what V8 rejects.
        for (tok, x) in [("1.", 1.0), ("-.5", -0.5), ("-01", -1.0), ("-00", -0.0), ("0.e1", 0.0)] {
            let doc = format!("{{\"a\":{tok}}}");
            assert_eq!(members(&doc), Some(vec![("a".into(), HermesScalar::Number(x))]), "{tok}");
        }
        for bad in [r#"{"a":.5}"#, r#"{"a":01}"#, r#"{"a":+1}"#, r#"{"a":1e}"#, r#"{"a":1.5.}"#, "[]", "1", "null", "\"x\"", "{", "{\"a\"}", "{\"a\":1,}", "{} x", "{\"a\":\"\u{1}\"}"] {
            assert_eq!(hermes_parse_top_level_object(bad), None, "{bad:?}");
        }
        assert_eq!(members("{}"), Some(vec![]));
        assert!(HermesMember { key: vec![0x76], start: 0 }.key_is("v"));
    }

    fn chain(depth: usize, inner: &str) -> String {
        format!("{}{inner}{}", "[".repeat(depth), "]".repeat(depth))
    }

    #[test]
    fn hermes_depth_cap_is_exact() {
        // The top-level object is depth 1, so `"x":<chain>` puts the chain's
        // outermost array at depth 2.
        let doc = |chain: String| format!("{{\"x\":{chain}}}");
        let rows = [
            (chain(510, ""), true),        // innermost [] at depth 511
            (chain(511, ""), false),       // innermost [] at depth 512
            (chain(509, "1"), true),       // scalar at 511
            (chain(510, "1"), false),      // scalar at 512
            (chain(509, "{}"), true),      // {} at 511
            (chain(510, "{}"), false),     // {} at 512
            (chain(508, "[1,2]"), true),   // scalars at 511
            (chain(509, "[1,2]"), false),  // its scalars at 512
            (chain(100_000, ""), false),   // bounded work, no recursion
        ];
        for (i, (c, ok)) in rows.into_iter().enumerate() {
            assert_eq!(hermes_parse_top_level_object(&doc(c)).is_some(), ok, "row {i}");
        }
        let objs = |depth: usize, inner: &str| format!("{}{inner}{}", "{\"k\":".repeat(depth), "}".repeat(depth));
        assert!(hermes_parse_top_level_object(&objs(510, "null")).is_some());
        assert!(hermes_parse_top_level_object(&objs(511, "null")).is_none());
    }

    /// Every string of length 1..=6 over `-+.eE019` as `"x":[<s>]`: the set
    /// Hermes 0.14.1 accepts is exactly 8307 strings (sha256 over them in
    /// this enumeration order, each + "\n"; the same digest as
    /// tests/golden_legacy_box.rs, which measures it through decryptMessage).
    #[test]
    fn hermes_number_lexer_exhaustively() {
        const AL: [char; 8] = ['-', '+', '.', 'e', 'E', '0', '1', '9'];
        fn walk(prefix: &mut String, left: usize, f: &mut dyn FnMut(&str)) {
            if left == 0 {
                return;
            }
            for c in AL {
                prefix.push(c);
                f(prefix);
                walk(prefix, left - 1, f);
                prefix.pop();
            }
        }
        let (mut total, mut accepted, mut digest_input) = (0usize, 0usize, String::new());
        walk(&mut String::new(), 6, &mut |t| {
            total += 1;
            let doc = format!("{{\"x\":[{t}]}}");
            if hermes_parse_top_level_object(&doc).is_some() {
                accepted += 1;
                digest_input.push_str(t);
                digest_input.push('\n');
                // Every accepted token is a number Rust's parser reads.
                if t.starts_with(['-', '0', '1', '9']) && !t.contains(',') {
                    let end = hermes_number_end(t.as_bytes(), 0);
                    if end == Some(t.len()) {
                        assert!(t.parse::<f64>().is_ok(), "{t}");
                    }
                }
            }
        });
        assert_eq!(total, 299_592);
        assert_eq!(accepted, 8307);
        assert_eq!(
            hex::encode(crate::primitives::sha256(digest_input.as_bytes())),
            "220e8e046b782510a850fcd3d890eab00715c345fbd99f9e02ec7ac800ad968c"
        );
    }

    #[test]
    fn skip_json_container_finds_the_matching_close() {
        let s = r#"[{"a":"]}\"["},[1,[2]]] tail"#;
        assert_eq!(skip_json_container(s.as_bytes(), 0), s.find(" tail").unwrap());
        assert_eq!(skip_json_ws(b"  \t\r\nx", 0), 5);
    }
}
