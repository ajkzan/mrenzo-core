//! ECMAScript string primitives the ports rely on.

use std::cmp::Ordering;

/// `StrWhiteSpaceChar` = WhiteSpace ∪ LineTerminator: what
/// `String.prototype.trim` and `StringToNumber` strip, and exactly the
/// RegExp `\s` class. TAB, LF, VT, FF, CR, SPACE, NBSP, U+1680,
/// U+2000–U+200A, LS, PS, U+202F, U+205F, U+3000 and ZWNBSP (U+FEFF).
/// Not Rust's `char::is_whitespace`: JS includes U+FEFF and excludes U+0085
/// (NEL), U+180E and U+200B. Verified against V8 (Node 22, Unicode 16) and
/// Hermes 0.14.1 over the BMP.
pub fn is_js_whitespace(c: char) -> bool {
    matches!(
        c,
        '\u{0009}'..='\u{000D}'
            | '\u{0020}'
            | '\u{00A0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200A}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202F}'
            | '\u{205F}'
            | '\u{3000}'
            | '\u{FEFF}'
    )
}

/// `String.prototype.trim()`.
pub fn js_trim(s: &str) -> &str {
    s.trim_matches(is_js_whitespace)
}

/// The order of JS `<` on two strings and of `Array.prototype.sort()`'s
/// default comparator: UTF-16 code units, not code points (so U+FFFF sorts
/// AFTER U+10000, whose lead surrogate is 0xD800).
pub fn cmp_code_units(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whitespace_is_exactly_the_ecmascript_set() {
        let expected: Vec<u32> = [0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0xa0, 0x1680]
            .into_iter()
            .chain(0x2000..=0x200a)
            .chain([0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff])
            .collect();
        let got: Vec<u32> = (0..=0x10ffffu32).filter_map(char::from_u32).filter(|&c| is_js_whitespace(c)).map(u32::from).collect();
        assert_eq!(got, expected);
        // The differences from Rust's notion, spelled out.
        assert!(is_js_whitespace('\u{feff}') && !'\u{feff}'.is_whitespace());
        assert!(!is_js_whitespace('\u{85}') && '\u{85}'.is_whitespace());
        assert!(!is_js_whitespace('\u{200b}') && !is_js_whitespace('\u{180e}'));
    }

    #[test]
    fn trim_and_code_unit_order() {
        assert_eq!(js_trim("\u{feff}\u{a0} a b\u{3000}\n"), "a b");
        assert_eq!(js_trim("\u{85}x\u{85}"), "\u{85}x\u{85}");
        assert_eq!(js_trim(""), "");
        assert_eq!(cmp_code_units("\u{ffff}", "\u{10000}"), Ordering::Greater);
        assert_eq!("\u{ffff}".cmp("\u{10000}"), Ordering::Less, "code point order differs");
        assert_eq!(cmp_code_units("a", "ab"), Ordering::Less);
        assert_eq!(cmp_code_units("B", "a"), Ordering::Less);
        assert_eq!(cmp_code_units("x", "x"), Ordering::Equal);
    }
}
