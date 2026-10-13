//! Bytes → string decoders the RN client uses. They are different
//! behaviours and stay separate functions.

/// tweetnacl-util `encodeUTF8(arr)` = `decodeURIComponent(escape(s))`:
/// STRICT UTF-8 (RFC 3629) or a `URIError` (`None`): overlong forms, UTF-8
/// encoded surrogates, code points above U+10FFFF and truncated sequences
/// all throw; a BOM is kept as U+FEFF. Exactly `String::from_utf8`.
pub fn tweetnacl_util_encode_utf8(bytes: Vec<u8>) -> Option<String> {
    String::from_utf8(bytes).ok()
}

/// WHATWG `new TextDecoder().decode(bytes)` (UTF-8, not fatal): LOSSY —
/// each maximal invalid subpart becomes U+FFFD — and ONE leading BOM is
/// stripped.
pub fn whatwg_text_decode(bytes: &[u8]) -> String {
    let body = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF][..]).unwrap_or(bytes);
    String::from_utf8_lossy(body).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Expected strings produced by Node `new TextDecoder().decode(...)`.
    #[test]
    fn text_decoder_matches_whatwg() {
        let cases: [(&[u8], &str); 12] = [
            (&[0xef, 0xbb, 0xbf, 0x41], "A"),
            (&[0xef, 0xbb, 0xbf, 0xef, 0xbb, 0xbf, 0x41], "\u{feff}A"),
            (&[0xc0, 0xaf], "\u{fffd}\u{fffd}"),
            (&[0xe0, 0x80], "\u{fffd}\u{fffd}"),
            (&[0xf0, 0x80, 0x80], "\u{fffd}\u{fffd}\u{fffd}"),
            (&[0xed, 0xa0, 0x80], "\u{fffd}\u{fffd}\u{fffd}"),
            (&[0xf4, 0x90, 0x80, 0x80], "\u{fffd}\u{fffd}\u{fffd}\u{fffd}"),
            (&[0xe2, 0x82], "\u{fffd}"),
            (&[0x41, 0xe2, 0x82], "A\u{fffd}"),
            (&[0xfe], "\u{fffd}"),
            (&[0xc3], "\u{fffd}"),
            (&[0xe2, 0x82, 0x82, 0x41], "\u{2082}A"),
        ];
        for (b, want) in cases {
            assert_eq!(whatwg_text_decode(b), want, "{b:02x?}");
        }
    }

    /// decodeURIComponent(escape(..)) outcomes (Node and Hermes agree).
    #[test]
    fn encode_utf8_is_strict() {
        let table: &[(&[u8], Option<&str>)] = &[
            (&[], Some("")),
            (&[0x00], Some("\u{0}")),
            (&[0xc2, 0x80], Some("\u{80}")),
            (&[0xc0, 0x80], None), // overlong
            (&[0xed, 0xa0, 0x80], None), // UTF-8-encoded surrogate
            (&[0xef, 0xbb, 0xbf, 0x41], Some("\u{feff}A")), // BOM kept (unlike TextDecoder)
            (&[0xf4, 0x8f, 0xbf, 0xbf], Some("\u{10ffff}")),
            (&[0xf4, 0x90, 0x80, 0x80], None),
            (&[0xe2, 0x82], None), // truncated
            (&[0x80], None),
            (b"%25", Some("%25")),
        ];
        for (bytes, want) in table {
            assert_eq!(tweetnacl_util_encode_utf8(bytes.to_vec()).as_deref(), *want, "{bytes:02x?}");
        }
    }
}
