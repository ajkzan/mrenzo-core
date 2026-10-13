//! JavaScript / tweetnacl compatibility layer: ONE implementation per distinct
//! behaviour of the RN client's runtime that the protocol ports rely on.
//!
//! Engine contract ("what RN does" means exactly this, pinned by the app's
//! lockfiles, build 324):
//! - JS engine: Hermes 0.14.1 (`mobile/ios/Podfile.lock`). Its `JSON.parse`
//!   lexes numbers with strtod and caps nesting (see [`json`]); everything
//!   else used here (Number→String, StringToNumber, ToString, `trim`, the
//!   RegExp `\s` class, `atob`) follows ECMA-262 / WHATWG and agrees with V8.
//! - tweetnacl 1.0.3 (`nacl-fast.js`): Ed25519 sign/verify ([`ed25519`]).
//! - tweetnacl-util 0.15.1 (`nacl-util.js`): `decodeBase64` ([`b64`]),
//!   `encodeUTF8` / `decodeUTF8` ([`utf8`]).
//!
//! Rules of this layer:
//! - Every function names the JS behaviour it models, and callers use it
//!   instead of a private copy. Each module keeps only thin adapters that map
//!   a throw to its own error type.
//! - Two copies that model DIFFERENT behaviours stay separate functions. That
//!   includes the approximations some modules historically shipped and whose
//!   tests pin them: e.g. [`js_number::number_to_string_ties_up`] (rounds an
//!   exact decimal tie upward, where JS takes the even digit) is not merged
//!   into [`js_number::number_to_string`]. Such variants say so in their docs;
//!   switching a caller to the faithful one is a behaviour change with its own
//!   failing test first.
//! - The strict helpers in [`mrenzo_core::primitives`] (`b64d`, `ed25519_verify`,
//!   `ed25519_sign`) are NOT what RN does; they are for fixtures and for bytes
//!   this crate produced itself.

pub mod b64;
pub mod ed25519;
pub mod js_number;
pub mod js_string;
pub mod js_value;
pub mod json;
pub mod utf8;

/// `compareBytes(a, b)` as written in `safetyNumbers.ts` and `contactPair.ts`:
/// the difference of the first differing byte (unsigned), else of the
/// lengths. Only its sign is ever used (`<= 0` picks `a` first), which is
/// the lexicographic order of `<[u8]>::cmp`.
pub fn ts_compare_bytes(a: &[u8], b: &[u8]) -> i64 {
    for (x, y) in a.iter().zip(b) {
        if x != y {
            return i64::from(*x) - i64::from(*y);
        }
    }
    a.len() as i64 - b.len() as i64
}

#[cfg(test)]
mod tests {
    use super::ts_compare_bytes;

    /// The code (no tests, no comments) of every `.rs` file under `src/`
    /// except `primitives.rs`.
    fn production_sources() -> Vec<(String, String)> {
        fn walk(dir: &std::path::Path, out: &mut Vec<(String, String)>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") && !path.ends_with("primitives.rs") {
                    let text = std::fs::read_to_string(&path).unwrap();
                    // Code only: drop the test module, comment lines and trailing comments.
                    let code = text.split("#[cfg(test)]\nmod tests").next().unwrap();
                    let body: Vec<&str> = code
                        .lines()
                        .filter(|l| !l.trim_start().starts_with("//"))
                        .map(|l| l.split(" // ").next().unwrap())
                        .collect();
                    out.push((path.display().to_string(), body.join("\n")));
                }
            }
        }
        let mut out = Vec::new();
        walk(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut out);
        assert!(out.len() > 15);
        out
    }

    /// Occurrences of `ident` not preceded by an identifier character.
    fn uses(body: &str, ident: &str) -> usize {
        body.match_indices(ident)
            .filter(|(i, _)| !body[..*i].chars().next_back().is_some_and(|c| c.is_alphanumeric() || c == '_'))
            .count()
    }

    /// The strict primitives that caused the live divergences must not stand
    /// in for RN behaviour in the RN-compatible modules: no `b64d` / `b64d32`
    /// outside `primitives.rs`, and `ed25519_verify` only behind
    /// `compat::ed25519::tweetnacl_sign_detached_verify`. Protocol-v3 code is
    /// strict on purpose and decodes with `ratchet::b64_strict*` and dalek's
    /// `verify_strict` directly. (A source lint
    /// instead of clippy's `disallowed-methods`, which would also fire on the
    /// golden tests' fixture decoding.)
    #[test]
    fn strict_primitives_stay_out_of_production_code() {
        for (path, body) in production_sources() {
            for ident in ["b64d(", "b64d32("] {
                assert_eq!(uses(&body, ident), 0, "{path} uses primitives::{ident}…) — use compat::b64");
            }
            if !path.ends_with("compat/ed25519.rs") {
                assert_eq!(uses(&body, "ed25519_verify"), 0, "{path} uses primitives::ed25519_verify — use compat::ed25519");
            }
        }
    }

    #[test]
    fn ts_compare_bytes_sign_is_lexicographic_order() {
        let cases: &[(&[u8], &[u8], i64)] = &[
            (b"", b"", 0),
            (b"a", b"", 1),
            (b"", b"a", -1),
            (&[0x01, 0xff], &[0x02], -1),
            (&[0xff], &[0x00, 0x00], 255),
            (&[1, 2, 3], &[1, 2, 3, 4], -1),
            (&[1, 2, 9], &[1, 2, 3, 4], 6),
        ];
        for &(a, b, want) in cases {
            assert_eq!(ts_compare_bytes(a, b), want, "{a:?} vs {b:?}");
            assert_eq!(ts_compare_bytes(a, b).signum(), a.cmp(b) as i64, "{a:?} vs {b:?}");
        }
    }
}
