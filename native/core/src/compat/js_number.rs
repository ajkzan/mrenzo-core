//! ECMAScript Number conversions: `Number::toString(10)`, the JSON number
//! form, `StringToNumber`, ToInt32 / ToUint32 and `BigInt(…)` followed by
//! `DataView.setBig(U)Int64`.
//!
//! Two approximations that modules shipped (and pin in their tests) are kept
//! as separately named functions; they are NOT the JS behaviour:
//! - [`number_to_string_ties_up`]: Rust's shortest `{:e}` digits, which round
//!   an EXACT decimal tie upward where JS picks the even digit
//!   (158508.102783203125 → JS "158508.10278320312", this "…313"). Used by
//!   `mesh_envelope`, `sender_keys` and `x3dh`.
//! - [`string_to_number_f64_radix`] (`sealed_sender`) and
//!   [`string_to_number_u128_radix`] (`sender_keys`, `x3dh`): `0x`/`0o`/`0b`
//!   literals rounded by f64 accumulation (from 53 bits, resp. above 128
//!   bits) instead of once, correctly. Decimal inputs are identical.

use crate::compat::js_string::js_trim;

// ───────── Number → String ─────────

/// `Number::toString(x)` (radix 10; what `String(x)`, template literals,
/// `Array.prototype.join` and `JSON.stringify` use for finite numbers).
/// Shortest round-trip digits; among those the closest to `x`; an EXACT tie
/// between two closest candidates takes the EVEN last digit (ECMA-262 note,
/// V8 and Hermes' dtoa both do this): 1758800000842.53125 →
/// "1758800000842.5312". Plain notation for 1e-7 ≤ |x| < 1e21, else
/// `d.ddde±N`. Total: NaN, ±Infinity and -0 ("0") included.
pub fn number_to_string(x: f64) -> String {
    format_number(x, shortest_digits_ties_even)
}

/// [`number_to_string`] as `JSON.stringify` writes a number: non-finite → `null`.
pub fn number_to_json(x: f64) -> String {
    if x.is_finite() {
        number_to_string(x)
    } else {
        "null".into()
    }
}

/// APPROXIMATION of [`number_to_string`] (see the module docs): identical
/// except on exact decimal ties, which it rounds upward. Kept only because
/// the modules that use it pin its output; do not use it in new code.
pub fn number_to_string_ties_up(x: f64) -> String {
    format_number(x, shortest_digits_rust)
}

/// [`number_to_string_ties_up`] in its `JSON.stringify` form (non-finite → `null`).
pub fn number_to_json_ties_up(x: f64) -> String {
    if x.is_finite() {
        number_to_string_ties_up(x)
    } else {
        "null".into()
    }
}

/// Number::toString steps 1-4 and 6-10 around a digit generator that
/// returns (digits without trailing zeros, n) with x = 0.d1…dk × 10^n.
fn format_number(x: f64, digits_of: fn(f64) -> (String, i32)) -> String {
    if x.is_nan() {
        return "NaN".into();
    }
    if x == 0.0 {
        return "0".into(); // also -0
    }
    if x.is_infinite() {
        return if x > 0.0 { "Infinity" } else { "-Infinity" }.into();
    }
    if x < 0.0 {
        return format!("-{}", format_number(-x, digits_of));
    }
    let (digits, n) = digits_of(x);
    if digits.is_empty() || !digits.is_ascii() {
        return "NaN".into(); // unreachable for a finite non-zero x; keeps the slices below total
    }
    let k = digits.len() as i32;
    if k <= n && n <= 21 {
        format!("{digits}{}", "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{digits}", "0".repeat((-n) as usize))
    } else {
        let e = n - 1;
        let sign = if e >= 0 { '+' } else { '-' };
        if k == 1 {
            format!("{digits}e{sign}{}", e.abs())
        } else {
            format!("{}.{}e{sign}{}", &digits[..1], &digits[1..], e.abs())
        }
    }
}

/// Split `{:e}` output into (digits, n) with x = 0.d1…dk × 10^n.
fn split_lower_exp(sci: &str) -> (String, i32) {
    // `{:e}` of a finite non-zero number always has the form `d[.ddd]e[-]N`
    // (the callers handle NaN, 0 and ±Infinity first); the fallbacks are
    // unreachable and exist so that no input can make this function panic.
    let (mantissa, exp) = sci.split_once('e').unwrap_or((sci, "0"));
    let digits: String = mantissa.chars().filter(|&c| c != '.').collect();
    (digits, exp.parse::<i32>().unwrap_or(0).saturating_add(1))
}

/// Rust's shortest round-trip digits (ties broken upward).
fn shortest_digits_rust(x: f64) -> (String, i32) {
    split_lower_exp(&format!("{x:e}"))
}

/// ECMAScript digit choice. Rust's `{:e}` fixes the minimal k; the
/// exact-mode rendering at that same k is the k-digit decimal closest to x
/// with ties to even, and it is taken whenever it round-trips.
fn shortest_digits_ties_even(x: f64) -> (String, i32) {
    let shortest = format!("{x:e}");
    let k = shortest.split_once('e').map_or(shortest.as_str(), |(mantissa, _)| mantissa).bytes().filter(u8::is_ascii_digit).count().max(1);
    let nearest = format!("{x:.prec$e}", prec = k - 1);
    let sci = if nearest.parse::<f64>() == Ok(x) { nearest } else { shortest };
    let (digits, n) = split_lower_exp(&sci);
    // Never fires for a minimal k (a trailing 0 would mean k - 1 digits
    // round-trip); kept so the invariant "no trailing zeros" is explicit.
    (digits.trim_end_matches('0').to_string(), n)
}

// ───────── String → Number ─────────

/// `StrDecimalLiteral` without `Infinity`, i.e. what `StringToNumber` parses
/// as a decimal after trimming:
/// `[+-]? (D+ (. D*)? | . D+) ([eE] [+-]? D+)?` (no numeric separators).
/// The same predicate is "C strtod consumes the whole token", which Hermes'
/// JSON number lexer relies on (see `json`).
pub fn is_str_decimal_literal(b: &[u8]) -> bool {
    let mut i = 0;
    let digits = |i: &mut usize| {
        let start = *i;
        while *i < b.len() && b[*i].is_ascii_digit() {
            *i += 1;
        }
        *i - start
    };
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        i += 1;
    }
    let mut mantissa_digits = digits(&mut i);
    if i < b.len() && b[i] == b'.' {
        i += 1;
        mantissa_digits += digits(&mut i);
    }
    if mantissa_digits == 0 {
        return false;
    }
    if i < b.len() && (b[i] == b'e' || b[i] == b'E') {
        i += 1;
        if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
            i += 1;
        }
        if digits(&mut i) == 0 {
            return false;
        }
    }
    i == b.len()
}

/// ECMAScript `StringToNumber(s)` (what `Number(s)`, unary `+`, `<` and
/// `==` apply to strings): trims JS whitespace; "" → 0; `0x`/`0o`/`0b`
/// literals (no sign) correctly rounded at any length; `[+-]Infinity`;
/// decimal literals correctly rounded; everything else NaN.
pub fn string_to_number(s: &str) -> f64 {
    string_to_number_with(s, radix_correctly_rounded)
}

/// APPROXIMATION of [`string_to_number`]: a `0x`/`0o`/`0b` literal is
/// accumulated in f64 digit by digit (exact below 2^53, then double
/// rounding). Kept for `sealed_sender`, where the value is only compared
/// with a clock.
pub fn string_to_number_f64_radix(s: &str) -> f64 {
    string_to_number_with(s, radix_f64_accumulate)
}

/// APPROXIMATION of [`string_to_number`]: a `0x`/`0o`/`0b` literal is exact
/// up to 128 bits (then rounded once), and accumulated in f64 above that.
/// Kept for `sender_keys` and `x3dh`.
pub fn string_to_number_u128_radix(s: &str) -> f64 {
    string_to_number_with(s, radix_u128_then_f64)
}

fn string_to_number_with(s: &str, radix_value: fn(&str, u32) -> f64) -> f64 {
    let t = js_trim(s);
    if t.is_empty() {
        return 0.0;
    }
    let b = t.as_bytes();
    if b.len() >= 2 && b[0] == b'0' {
        let radix = match b[1] {
            b'x' | b'X' => 16,
            b'o' | b'O' => 8,
            b'b' | b'B' => 2,
            _ => 0,
        };
        if radix != 0 {
            let digits = &t[2..];
            if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
                return f64::NAN;
            }
            return radix_value(digits, radix);
        }
    }
    match t {
        "Infinity" | "+Infinity" => return f64::INFINITY,
        "-Infinity" => return f64::NEG_INFINITY,
        _ => {}
    }
    if !is_str_decimal_literal(b) {
        return f64::NAN;
    }
    t.parse::<f64>().unwrap_or(f64::NAN) // correctly rounded, like JS
}

/// Valid, non-empty radix-2^k digits, correctly rounded to the nearest
/// double (ties to even) at ANY length, as V8/Hermes do. The digits are a
/// plain bit string: keep the top 64 significant bits, OR everything below
/// into a sticky bit.
fn radix_correctly_rounded(digits: &str, radix: u32) -> f64 {
    debug_assert!(matches!(radix, 2 | 8 | 16));
    let bits_per_digit = radix.trailing_zeros();
    let mut mant: u64 = 0; // leading significant bits (at most 64)
    let mut nbits: u32 = 0;
    let mut dropped: i32 = 0; // significant bits below `mant`
    let mut sticky = false; // any 1 among the dropped bits
    for c in digits.chars() {
        let Some(d) = c.to_digit(radix) else { return f64::NAN };
        for i in (0..bits_per_digit).rev() {
            let bit = u64::from((d >> i) & 1);
            if nbits == 0 && bit == 0 {
                continue; // leading zero
            }
            if nbits < 64 {
                mant = (mant << 1) | bit;
                nbits += 1;
            } else {
                dropped += 1;
                sticky |= bit == 1;
            }
        }
    }
    if nbits <= 53 {
        return mant as f64; // exact (dropped == 0 here)
    }
    let shift = nbits - 53;
    let rem = mant & ((1u64 << shift) - 1);
    let half = 1u64 << (shift - 1);
    let mut m = mant >> shift;
    if rem > half || (rem == half && (sticky || m & 1 == 1)) {
        m += 1; // m ≤ 2^53: still exact as f64
    }
    // m ≤ 2^53 times an exact power of two: exact, or +Infinity past f64::MAX.
    let e = shift as i32 + dropped;
    if e > 1023 {
        return f64::INFINITY;
    }
    m as f64 * f64::from_bits(((e + 1023) as u64) << 52)
}

fn radix_f64_accumulate(digits: &str, radix: u32) -> f64 {
    digits.chars().fold(0.0, |acc, c| acc * f64::from(radix) + f64::from(c.to_digit(radix).unwrap_or(0)))
}

fn radix_u128_then_f64(digits: &str, radix: u32) -> f64 {
    match u128::from_str_radix(digits, radix) {
        Ok(v) => v as f64,
        // > 128 bits (the digits are valid, so only overflow fails).
        Err(_) => radix_f64_accumulate(digits, radix),
    }
}

// ───────── integer conversions ─────────

/// ECMAScript ToInt32 (what `x & 0xff`, `x | 0` apply to a number).
pub fn to_int32(x: f64) -> i32 {
    if !x.is_finite() {
        return 0;
    }
    let m = x.trunc().rem_euclid(4_294_967_296.0);
    (m as u64 as u32) as i32
}

/// ECMAScript ToUint32 (what `DataView.setUint32` / `>>> 0` apply).
pub fn to_uint32(x: f64) -> u32 {
    if !x.is_finite() {
        return 0;
    }
    const M: f64 = 4_294_967_296.0;
    (((x.trunc() % M) + M) % M) as u32
}

/// `BigInt(x)` for a Number followed by `DataView.setBigInt64` /
/// `setBigUint64` (both store x mod 2^64): the 64 stored bits, or `None`
/// where `BigInt(x)` throws RangeError (NaN, ±Infinity, non-integers).
pub fn number_to_bigint_u64(x: f64) -> Option<u64> {
    if !x.is_finite() || x.fract() != 0.0 {
        return None;
    }
    let a = x.abs();
    // An integral double ≥ 2^127 is a multiple of 2^75, i.e. 0 mod 2^64.
    let m = if a < 2f64.powi(127) { (a as u128) as u64 } else { 0 };
    Some(if x < 0.0 { m.wrapping_neg() } else { m })
}

/// `BigInt(s)` for a string (StringIntegerLiteral: trimmed; "" → 0;
/// optional sign on decimals only; `0x`/`0o`/`0b` without sign) followed by
/// a 64-bit `setBig(U)Int64` store. `None` = SyntaxError.
pub fn string_to_bigint_u64(s: &str) -> Option<u64> {
    let t = js_trim(s);
    if t.is_empty() {
        return Some(0);
    }
    let b = t.as_bytes();
    if b.len() >= 2 && b[0] == b'0' {
        let radix = match b[1] {
            b'x' | b'X' => 16,
            b'o' | b'O' => 8,
            b'b' | b'B' => 2,
            _ => 0,
        };
        if radix != 0 {
            let digits = &t[2..];
            if digits.is_empty() {
                return None;
            }
            let mut acc = 0u64;
            for c in digits.chars() {
                acc = acc.wrapping_mul(u64::from(radix)).wrapping_add(u64::from(c.to_digit(radix)?));
            }
            return Some(acc);
        }
    }
    let (neg, digits) = match b[0] {
        b'+' => (false, &t[1..]),
        b'-' => (true, &t[1..]),
        _ => (false, t),
    };
    if digits.is_empty() || !digits.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let mut acc = 0u64;
    for c in digits.bytes() {
        acc = acc.wrapping_mul(10).wrapping_add(u64::from(c - b'0'));
    }
    Some(if neg { acc.wrapping_neg() } else { acc })
}

#[cfg(test)]
mod tests {
    // The tie constants are exact doubles, written out in full on purpose.
    #![allow(clippy::excessive_precision)]

    use super::*;

    fn xorshift(seed: u64) -> impl FnMut() -> u64 {
        let mut x = seed;
        move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        }
    }

    /// Independent oracle for the ECMAScript digit choice (the
    /// sealed_sender formulation): detect an exact tie on the full decimal
    /// expansion of x and resolve it to the even neighbour.
    fn oracle_digits(x: f64) -> (String, i32) {
        let (digits, n) = split_lower_exp(&format!("{x:e}"));
        let (exact, exact_n) = split_lower_exp(&format!("{x:.766e}"));
        let exact = exact.trim_end_matches('0');
        let k = digits.len();
        if exact.len() != k + 1 || !exact.ends_with('5') {
            return (digits, n);
        }
        let round_trips = |d: &str, n: i32| format!("{d}e{}", n - d.len() as i32).parse::<f64>() == Ok(x);
        let lo = exact[..k].to_string();
        let mut hi = lo.clone().into_bytes();
        let mut carry = true;
        for b in hi.iter_mut().rev() {
            if *b == b'9' {
                *b = b'0';
            } else {
                *b += 1;
                carry = false;
                break;
            }
        }
        let hi_n = if carry {
            hi.insert(0, b'1');
            exact_n + 1
        } else {
            exact_n
        };
        let hi = String::from_utf8(hi).unwrap();
        let (lo, hi) = (lo.trim_end_matches('0').to_string(), hi.trim_end_matches('0').to_string());
        let lo_even = (exact.as_bytes()[k - 1] - b'0') % 2 == 0;
        match (round_trips(&lo, exact_n), round_trips(&hi, hi_n)) {
            (true, true) if lo_even => (lo, exact_n),
            (true, true) => (hi, hi_n),
            (true, false) => (lo, exact_n),
            (false, true) => (hi, hi_n),
            (false, false) => (digits, n),
        }
    }

    /// Expected strings produced by Node (V8) `String(x)`.
    #[test]
    fn number_to_string_matches_v8() {
        let cases: &[(f64, &str)] = &[
            (1758800000000.0, "1758800000000"),
            (1.5, "1.5"),
            (1e21, "1e+21"),
            (1e-7, "1e-7"),
            (1.5e-7, "1.5e-7"),
            (123e-20, "1.23e-18"),
            (123e20, "1.23e+22"),
            (0.000001, "0.000001"),
            (18446744073709551615u64 as f64, "18446744073709552000"),
            (9007199254740994.0, "9007199254740994"),
            (0.1 + 0.2, "0.30000000000000004"),
            (-0.0, "0"),
            (-0.5, "-0.5"),
            (-1001.0, "-1001"),
            (5e-324, "5e-324"),
            (f64::MAX, "1.7976931348623157e+308"),
            (123456789012345680000.0, "123456789012345680000"),
            (1e20, "100000000000000000000"),
            (12.3456789, "12.3456789"),
            (f64::NAN, "NaN"),
            (f64::INFINITY, "Infinity"),
            (f64::NEG_INFINITY, "-Infinity"),
            // Exact ties: the even digit (Rust's `{:e}` would round up).
            (158508.102783203125, "158508.10278320312"),
            (1758800000842.53125, "1758800000842.5312"),
            (2135157283105460.25, "2135157283105460.2"),
            (75391648701562.625, "75391648701562.62"),
            (1205236121730522.25, "1205236121730522.2"),
        ];
        for &(x, want) in cases {
            assert_eq!(number_to_string(x), want, "{x:e}");
        }
        assert_eq!(number_to_json(f64::NAN), "null");
        assert_eq!(number_to_json(f64::NEG_INFINITY), "null");
        assert_eq!(number_to_json(-0.0), "0");
        assert_eq!(number_to_json(1e21), "1e+21");
    }

    #[test]
    fn ties_up_variant_differs_only_on_exact_ties() {
        for (x, even, up) in [
            (158508.102783203125, "158508.10278320312", "158508.10278320313"),
            (2135157283105460.25, "2135157283105460.2", "2135157283105460.3"),
            (75391648701562.625, "75391648701562.62", "75391648701562.63"),
            (1205236121730522.25, "1205236121730522.2", "1205236121730522.3"),
        ] {
            assert_eq!(number_to_string(x), even);
            assert_eq!(number_to_string_ties_up(x), up);
            assert_eq!(number_to_string_ties_up(-x), format!("-{up}"));
            assert_eq!(number_to_json_ties_up(x), up);
        }
        assert_eq!(number_to_json_ties_up(f64::INFINITY), "null");
        for x in [0.0, -0.0, 1.5, 1e21, 1e-7, f64::NAN, f64::INFINITY, 5e-324, 0.1 + 0.2] {
            assert_eq!(number_to_string_ties_up(x), number_to_string(x), "{x:e}");
        }
    }

    #[test]
    fn number_to_string_agrees_with_the_tie_oracle() {
        let mut next = xorshift(0x9e37_79b9_7f4a_7c15);
        let mut xs: Vec<f64> = Vec::new();
        for _ in 0..60_000 {
            xs.push(f64::from_bits(next()));
            xs.push(f32::from_bits(next() as u32) as f64);
            let m = (next() >> 11) as f64;
            xs.push(m / 2f64.powi((next() % 40) as i32));
        }
        let (mut ties, mut checked) = (0, 0);
        for x in xs.into_iter().filter(|x| x.is_finite() && *x != 0.0) {
            let a = x.abs();
            let want = oracle_digits(a);
            assert_eq!(shortest_digits_ties_even(a), want, "{a:e}");
            let rust = shortest_digits_rust(a);
            if rust != want {
                ties += 1;
            }
            checked += 1;
        }
        assert!(checked > 150_000);
        assert!(ties > 100, "the dyadic inputs must exercise exact ties ({ties})");
    }

    #[test]
    fn decimal_literal_grammar_is_rusts_float_grammar_without_words() {
        // Every string of length ≤ 6 over the characters that matter.
        fn walk(prefix: &mut String, left: usize, f: &mut dyn FnMut(&str)) {
            if left == 0 {
                return;
            }
            for c in ['-', '+', '.', 'e', 'E', '0', '1', 'x'] {
                prefix.push(c);
                f(prefix);
                walk(prefix, left - 1, f);
                prefix.pop();
            }
        }
        let mut n = 0;
        walk(&mut String::new(), 6, &mut |t| {
            assert_eq!(is_str_decimal_literal(t.as_bytes()), t.parse::<f64>().is_ok(), "{t:?}");
            n += 1;
        });
        assert_eq!(n, 299_592);
        for (t, ok) in [("1.", true), (".5", true), ("-.5", true), ("+0.e1", true), (".", false), ("1e", false), ("e5", false), ("Infinity", false), ("1_0", false)] {
            assert_eq!(is_str_decimal_literal(t.as_bytes()), ok, "{t:?}");
        }
    }

    #[test]
    fn string_to_number_matches_spec() {
        for (s, x) in [
            ("", 0.0),
            ("  \n", 0.0),
            ("0x10", 16.0),
            ("0X1f", 31.0),
            ("0B101", 5.0),
            ("0o17", 15.0),
            ("1.", 1.0),
            (".5", 0.5),
            ("+.5", 0.5),
            ("-1e3", -1000.0),
            ("007", 7.0),
            ("1.e2", 100.0),
            ("\u{feff} 42 \u{3000}", 42.0),
            ("Infinity", f64::INFINITY),
            ("+Infinity", f64::INFINITY),
            ("-Infinity", f64::NEG_INFINITY),
            ("1e400", f64::INFINITY),
            ("-1e400", f64::NEG_INFINITY),
            ("0x1fffffffffffff", 9007199254740991.0),
        ] {
            for f in [string_to_number, string_to_number_f64_radix, string_to_number_u128_radix] {
                assert_eq!(f(s), x, "{s:?}");
            }
        }
        for f in [string_to_number, string_to_number_f64_radix, string_to_number_u128_radix] {
            assert!(f("-0").is_sign_negative() && f("-0") == 0.0);
            for s in ["-0x10", "0x", "0b", "0o8", "0xg", "0x+1", "inf", "nan", "infinity", "1_000", ".", "1e", "e5", "1 2", "\u{85}1", "+-1", "--1", "Infinityx"] {
                assert!(f(s).is_nan(), "{s:?}");
            }
        }
    }

    #[test]
    fn radix_rounding_variants_are_pinned() {
        // 2^57 + 17: exact in u128 and correctly rounded (→ 2^57 + 32), but
        // f64 accumulation rounds 2^53 + 1 down first (→ 2^57).
        let a = format!("0x2{}11", "0".repeat(12));
        assert_eq!(string_to_number(&a), 2f64.powi(57) + 32.0);
        assert_eq!(string_to_number_u128_radix(&a), 2f64.powi(57) + 32.0);
        assert_eq!(string_to_number_f64_radix(&a), 2f64.powi(57));
        // 2^140 + 2^87 + 1 (141 bits): correct rounding goes up to 2^140 + 2^88;
        // both approximations accumulate in f64 above 128 bits and lose the
        // tie-breaking bit (→ 2^140).
        let mut digits = vec![b'0'; 36];
        digits[0] = b'1';
        digits[35 - 21] = b'8';
        digits[35] = b'1';
        let b = format!("0x{}", String::from_utf8(digits).unwrap());
        assert_eq!(string_to_number(&b), 2f64.powi(140) + 2f64.powi(88));
        assert_eq!(string_to_number_u128_radix(&b), 2f64.powi(140));
        assert_eq!(string_to_number_f64_radix(&b), 2f64.powi(140));
        // Past f64::MAX.
        let huge = format!("0x1{}", "0".repeat(256));
        assert_eq!(string_to_number(&huge), f64::INFINITY);
    }

    #[test]
    fn correctly_rounded_radix_matches_exact_u128_rounding() {
        // Below 128 bits `u128 as f64` is a single correct rounding: the
        // bit-string algorithm must agree with it everywhere.
        let mut next = xorshift(0xdead_beef_cafe_f00d);
        for _ in 0..100_000 {
            let v = (u128::from(next()) << 64 | u128::from(next())) >> (next() % 128);
            for (radix, s) in [(16, format!("{v:x}")), (8, format!("{v:o}")), (2, format!("{v:b}"))] {
                assert_eq!(radix_correctly_rounded(&s, radix), v as f64, "{s} radix {radix}");
            }
        }
    }

    #[test]
    fn integer_conversions() {
        assert_eq!(to_uint32(-1.0), u32::MAX);
        assert_eq!(to_uint32(4294967296.0 + 5.0), 5);
        assert_eq!(to_uint32(f64::NAN), 0);
        assert_eq!(to_uint32(f64::INFINITY), 0);
        assert_eq!(to_uint32(-0.5), 0);
        assert_eq!(to_int32(4294967295.0), -1);
        assert_eq!(to_int32(2147483648.0), i32::MIN);
        assert_eq!(to_int32(-1.5), -1);
        assert_eq!(to_int32(f64::NEG_INFINITY), 0);
        assert_eq!(to_int32(258.0) & 0xff, 2);
        assert_eq!(number_to_bigint_u64(-1.0), Some(u64::MAX));
        assert_eq!(number_to_bigint_u64(-0.0), Some(0));
        assert_eq!(number_to_bigint_u64(18446744073709551616.0), Some(0));
        // Node: BigInt.asUintN(64, BigInt(3*2**64+8192)) === 8192n
        assert_eq!(number_to_bigint_u64(18446744073709551616.0 * 3.0 + 8192.0), Some(8192));
        assert_eq!(number_to_bigint_u64(1e300), Some(0));
        assert_eq!(number_to_bigint_u64(1.5), None);
        assert_eq!(number_to_bigint_u64(f64::NAN), None);
        assert_eq!(number_to_bigint_u64(f64::INFINITY), None);
    }

    /// The other formulation the ports used (sealed_sender): the low 64 bits
    /// of m·2^e taken from the IEEE fields.
    fn low64_from_fields(x: f64) -> u64 {
        let neg = x < 0.0;
        let bits = x.abs().to_bits();
        let exp = ((bits >> 52) & 0x7ff) as i32;
        if exp == 0 {
            return 0;
        }
        let m = (bits & ((1u64 << 52) - 1)) | (1u64 << 52);
        let e = exp - 1075;
        let mag = if e >= 64 {
            0
        } else if e >= 0 {
            m << e
        } else {
            m >> (-e)
        };
        if neg {
            mag.wrapping_neg()
        } else {
            mag
        }
    }

    #[test]
    fn number_to_bigint_agrees_with_the_ieee_field_formulation() {
        let mut next = xorshift(0x1234_5678_9abc_def1);
        for _ in 0..200_000 {
            let raw = f64::from_bits(next());
            let x = if raw.is_finite() { raw.trunc() } else { raw };
            let want = if x.is_finite() && x.fract() == 0.0 { Some(low64_from_fields(x)) } else { None };
            assert_eq!(number_to_bigint_u64(x), want, "{x:e}");
            let small = (next() as i64 >> (next() % 64)) as f64;
            assert_eq!(number_to_bigint_u64(small), Some(low64_from_fields(small)), "{small}");
        }
    }

    #[test]
    fn string_to_bigint_matches_js() {
        for (s, want) in [
            ("", Some(0)),
            ("  ", Some(0)),
            ("1001", Some(1001)),
            (" 0x3e9 ", Some(1001)),
            ("0B11", Some(3)),
            ("0o17", Some(15)),
            ("+5", Some(5)),
            ("-1", Some(u64::MAX)),
            ("18446744073709551617", Some(1)),
            ("0x1ffffffffffffffff", Some(u64::MAX)),
            ("0x", None),
            ("-0x1", None),
            ("1.5", None),
            ("1e3", None),
            ("+", None),
            ("1 2", None),
            ("Infinity", None),
            ("0xg", None),
        ] {
            assert_eq!(string_to_bigint_u64(s), want, "{s:?}");
        }
    }
}
