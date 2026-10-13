//! tweetnacl-util 0.15.1 `decodeBase64` exactly as the RN client runs it.
//!
//! ```js
//! function validateBase64(s) {
//!   if (!/^(?:[A-Za-z0-9+\/]{2}[A-Za-z0-9+\/]{2})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$/.test(s))
//!     throw new TypeError('invalid encoding');
//! }
//! decodeBase64 = function (s) { validateBase64(s); var i, d = atob(s), b = new Uint8Array(d.length); … }
//! ```
//!
//! The regex admits the standard alphabet only, a length that is a multiple
//! of 4, and `=` padding only as the canonical `xx==` / `xxx=` tail of the
//! final quantum. `atob` (WHATWG forgiving-base64) then DISCARDS the unused
//! low bits of that final quantum instead of rejecting them, so `"AB=="`
//! decodes like `"AA=="` and `"ERF="` like `"ERE="`. Hermes has `atob` and
//! the app has no `Buffer` polyfill, so the atob branch is the one that runs
//! (the Buffer branch would give the same bytes after the regex gate anyway).
//!
//! `primitives::b64d` is strict RFC 4648 (non-zero trailing bits rejected):
//! it is NOT this function and must not stand in for it on anything a peer,
//! the server or RN's own storage produced.
//!
//! Both `regex.test(x)` and `atob(x)` coerce a non-string argument with
//! ToString first; callers that can see non-strings coerce with
//! [`crate::compat::js_value`] and pass the resulting string here.

/// Sextet value of a standard-alphabet character; `None` for anything else
/// (including `=`, `-`, `_`, whitespace, non-ASCII and lone surrogates).
fn sextet(unit: u32) -> Option<u32> {
    match unit {
        0x41..=0x5a => Some(unit - 0x41),      // A-Z
        0x61..=0x7a => Some(unit - 0x61 + 26), // a-z
        0x30..=0x39 => Some(unit - 0x30 + 52), // 0-9
        0x2b => Some(62),                      // +
        0x2f => Some(63),                      // /
        _ => None,
    }
}

/// The regex gate and the forgiving decode in one pass over code units.
/// UTF-8 bytes of a non-ASCII character are never alphabet characters, so a
/// `&str` can be scanned as bytes: any non-ASCII input is rejected, exactly
/// as the regex rejects it (the length test cannot change that outcome).
fn decode_units<T: Copy + Into<u32>>(s: &[T]) -> Option<Vec<u8>> {
    if s.len() % 4 != 0 {
        return None;
    }
    const EQ: u32 = 0x3d; // '='
    let groups = s.len() / 4;
    let mut out = Vec::with_capacity(groups * 3);
    for (gi, g) in s.chunks_exact(4).enumerate() {
        let last = gi + 1 == groups;
        let pad = if last && g[2].into() == EQ && g[3].into() == EQ {
            2
        } else if last && g[3].into() == EQ {
            1
        } else {
            0
        };
        let mut acc = 0u32;
        for &unit in &g[..4 - pad] {
            acc = (acc << 6) | sextet(unit.into())?;
        }
        match pad {
            0 => out.extend_from_slice(&[(acc >> 16) as u8, (acc >> 8) as u8, acc as u8]),
            1 => out.extend_from_slice(&[(acc >> 10) as u8, (acc >> 2) as u8]), // low 2 bits dropped
            _ => out.push((acc >> 4) as u8),                                    // low 4 bits dropped
        }
    }
    Some(out)
}

/// tweetnacl-util `decodeBase64(s)`. `None` ≡ it throws
/// `TypeError('invalid encoding')`.
pub fn tweetnacl_util_decode_base64(s: &str) -> Option<Vec<u8>> {
    decode_units(s.as_bytes())
}

/// [`tweetnacl_util_decode_base64`] on a JS string given as UTF-16 code
/// units (it may hold lone surrogates, which are simply invalid).
pub fn tweetnacl_util_decode_base64_utf16(units: &[u16]) -> Option<Vec<u8>> {
    decode_units(units)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
    use base64::engine::DecodePaddingMode;
    use base64::Engine;

    /// Independent model: the regex, written out, then forgiving-base64.
    fn reference(s: &str) -> Option<Vec<u8>> {
        let b = s.as_bytes();
        let alpha = |c: u8| c.is_ascii_alphanumeric() || c == b'+' || c == b'/';
        if !s.is_ascii() || b.len() % 4 != 0 {
            return None;
        }
        let n = b.len();
        let body_ok = |end: usize| b[..end].iter().all(|&c| alpha(c));
        let valid = if n == 0 {
            true
        } else if b[n - 2] == b'=' && b[n - 1] == b'=' {
            body_ok(n - 2)
        } else if b[n - 1] == b'=' {
            body_ok(n - 1)
        } else {
            body_ok(n)
        };
        if !valid {
            return None;
        }
        let mut out = Vec::new();
        let (mut acc, mut bits) = (0u32, 0u32);
        for &c in b.iter().filter(|&&c| c != b'=') {
            let v = match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'+' => 62,
                _ => 63,
            } as u32;
            acc = (acc << 6) | v;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
                acc &= (1 << bits) - 1;
            }
        }
        Some(out)
    }

    /// Second oracle: the base64 crate configured as regex + atob.
    fn crate_oracle(s: &str) -> Option<Vec<u8>> {
        const LENIENT: GeneralPurpose = GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            GeneralPurposeConfig::new()
                .with_decode_allow_trailing_bits(true)
                .with_decode_padding_mode(DecodePaddingMode::RequireCanonical),
        );
        LENIENT.decode(s).ok()
    }

    fn all_strings(alphabet: &[&str], max_len: usize) -> Vec<String> {
        let mut all = vec![String::new()];
        let mut layer = vec![String::new()];
        for _ in 0..max_len {
            layer = layer.iter().flat_map(|p| alphabet.iter().map(move |a| format!("{p}{a}"))).collect();
            all.extend(layer.iter().cloned());
        }
        all
    }

    #[test]
    fn pinned_cases() {
        assert_eq!(tweetnacl_util_decode_base64(""), Some(vec![]));
        assert_eq!(tweetnacl_util_decode_base64("AAAA"), Some(vec![0, 0, 0]));
        assert_eq!(tweetnacl_util_decode_base64("+/8="), Some(vec![0xfb, 0xff]));
        assert_eq!(tweetnacl_util_decode_base64("null"), Some(vec![0x9e, 0xe9, 0x65]));
        // Non-zero trailing bits are discarded, not rejected (atob).
        assert_eq!(tweetnacl_util_decode_base64("AB=="), Some(vec![0x00]));
        assert_eq!(tweetnacl_util_decode_base64("AP=="), Some(vec![0x00]));
        assert_eq!(tweetnacl_util_decode_base64("AAB="), Some(vec![0x00, 0x00]));
        assert_eq!(tweetnacl_util_decode_base64("QR=="), Some(vec![0x41]));
        assert_eq!(tweetnacl_util_decode_base64("ERF="), Some(vec![0x11, 0x11]));
        for bad in [
            "A", "AA", "AAA", "AB=", "A===", "====", "=", "AA=A", "=AAA", "AAAA=", "AAAA====", "AA==AAAA", "AAA=AAAA",
            "-_8=", "AA-_", "AAAA\nAAAA", " AAAA", "AAAA ", "AAA\u{e9}",
        ] {
            assert_eq!(tweetnacl_util_decode_base64(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn matches_regex_model_exhaustively_on_short_strings() {
        let mut n = 0;
        for alphabet in [&["A", "B", "Q", "/", "+", "=", "-", " "][..], &["A", "=", "\u{e9}", "\n", "P"][..]] {
            for s in all_strings(alphabet, 6) {
                let got = tweetnacl_util_decode_base64(&s);
                assert_eq!(got, reference(&s), "{s:?}");
                assert_eq!(got, crate_oracle(&s), "{s:?}");
                n += 1;
            }
        }
        assert!(n > 300_000);
    }

    #[test]
    fn matches_regex_model_on_random_padded_strings() {
        let pool = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..100_000 {
            let len = (next() % 13) as usize * 4;
            let mut s: Vec<u8> = (0..len).map(|_| pool[(next() % 64) as usize]).collect();
            if len > 0 {
                match next() % 4 {
                    0 => s[len - 1] = b'=',
                    1 => {
                        s[len - 1] = b'=';
                        s[len - 2] = b'=';
                    }
                    2 => {
                        let k = next() as usize % len;
                        s[k] = b'=';
                    }
                    _ => {}
                }
            }
            let s = String::from_utf8(s).unwrap();
            assert_eq!(tweetnacl_util_decode_base64(&s), reference(&s), "{s:?}");
        }
    }

    #[test]
    fn utf16_variant_agrees_and_rejects_lone_surrogates() {
        for s in all_strings(&["A", "g", "=", "\u{e9}", "\u{1F600}"], 5) {
            let units: Vec<u16> = s.encode_utf16().collect();
            assert_eq!(tweetnacl_util_decode_base64_utf16(&units), tweetnacl_util_decode_base64(&s), "{s:?}");
        }
        assert_eq!(tweetnacl_util_decode_base64_utf16(&[0x41, 0x41, 0x41, 0xd800]), None);
        assert_eq!(tweetnacl_util_decode_base64_utf16(&[0x41, 0x41, 0xdc00, 0x3d]), None);
        assert_eq!(tweetnacl_util_decode_base64_utf16(&[0x41, 0x42, 0x3d, 0x3d]), Some(vec![0]));
    }

    #[test]
    fn primitives_b64d_is_strict_and_is_not_this_function() {
        // The documented trap: primitives::b64d rejects what RN accepts.
        for (s, bytes) in [("AB==", vec![0u8]), ("AAB=", vec![0, 0]), ("ERF=", vec![0x11, 0x11])] {
            assert_eq!(crate::primitives::b64d(s), None, "{s}");
            assert_eq!(tweetnacl_util_decode_base64(s), Some(bytes), "{s}");
        }
        // On canonical input both agree.
        for s in ["", "AA==", "AAA=", "AAAA", "+/8=", "ERE="] {
            assert_eq!(crate::primitives::b64d(s), tweetnacl_util_decode_base64(s), "{s}");
        }
    }
}
