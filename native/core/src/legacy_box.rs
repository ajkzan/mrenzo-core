//! Pre-ratchet static box `{n,c}` — line-for-line port of
//! `mobile/src/utils/crypto.ts` (`computeSharedKey`, `clearSharedKey`,
//! `clearAllSharedKeys`, `encryptMessage`, `decryptMessage`; build 324).
//! Wire contract: docs/native/protocol/03-crypto.md §4; conformance:
//! docs/native/vectors/legacyBox.json (tests/golden_legacy_box.rs).
//!
//! ```text
//! k    = nacl.box.before(peerPub, myPriv)          // HSalsa20(X25519), symmetric
//! wire = JSON.stringify({n: b64(nonce24), c: b64(tag16 || ct)})
//! ```
//!
//! Faithful to the RN client INCLUDING its quirks, which must not be "fixed"
//! here (that would break interop with RN clients in the field):
//! - The shared-key cache is keyed by the NUMERIC peer id only. A cache hit
//!   returns the cached key without even decoding the key arguments, so a
//!   rotated peer (or own) key is ignored until `clear_shared_key(peer_id)`.
//! - `encryptMessage` draws the 24-byte nonce BEFORE encoding the text.
//! - `decryptMessage` never throws: every failure (bad JSON, missing field,
//!   bad base64, wrong nonce length, short box, bad tag, non-UTF-8 plaintext)
//!   is `null`. An authenticated EMPTY plaintext is `""`, not `null`.
//! - Base64 is tweetnacl-util's `decodeBase64` as it runs on Hermes: the strict
//!   padded regex, then `atob`, which DISCARDS non-zero trailing bits (so
//!   "AB==" decodes like "AA=="). `primitives::b64d` rejects those; this
//!   module uses `compat::b64` (the UTF-16 form, since a JSON string may hold
//!   lone surrogates).
//! - `decodeBase64` coerces its argument with ToString (regex `.test` and
//!   `atob` both do), so a JSON field that is not a string is not rejected by
//!   type: `["<b64>"]` (any chain of single-element arrays around a string)
//!   stringifies to the string itself and DECRYPTS on device; `null`/`true`
//!   stringify to valid 4-char base64 (3 bytes) that later fail the length
//!   checks. RN runs tweetnacl-util's browser (`atob`) branch — Hermes has
//!   `atob` and the app has no `Buffer` polyfill (see mobile/src/services/api.ts).
//! - `JSON.parse` semantics, not serde's: lone-surrogate `\uD800` escapes and
//!   out-of-range numbers (`1e400` → Infinity) elsewhere in the object are
//!   accepted; duplicate keys → last one wins. The grammar is the app's
//!   engine's (Hermes 0.14.1, mobile/ios/Podfile.lock), NOT V8's, in two
//!   places: (a) Hermes' `JSON.parse` throws `RangeError: Maximum nesting
//!   level in JSON parser exceeded` as soon as ANY value sits at depth >= 512
//!   (top-level value = depth 1), anywhere in the document → null (V8 has no
//!   such limit); (b) its number lexer is strtod-based, so `1.`, `-.5`, `-01`
//!   parse (V8 rejects them). The parser is `compat::json`'s Hermes scanner.

use std::collections::HashMap;

use crate::compat::b64::{tweetnacl_util_decode_base64, tweetnacl_util_decode_base64_utf16};
use crate::compat::json::{hermes_parse_string, hermes_parse_top_level_object, skip_json_container, skip_json_ws};
use crate::compat::utf8::tweetnacl_util_encode_utf8;
use crate::primitives::{b64, box_before, secretbox_open, secretbox_seal};
use crate::rng::Rng;

/// `nacl.box.nonceLength`.
pub const NONCE_LEN: usize = 24;

/// The exceptions `computeSharedKey` can throw, with the TS message text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LegacyBoxError {
    /// tweetnacl-util `decodeBase64`: `TypeError('invalid encoding')`.
    InvalidEncoding,
    /// `nacl.box.before`: `Error('bad public key size')` (checked first).
    BadPublicKeySize,
    /// `nacl.box.before`: `Error('bad secret key size')`.
    BadSecretKeySize,
}

impl std::fmt::Display for LegacyBoxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            LegacyBoxError::InvalidEncoding => "invalid encoding",
            LegacyBoxError::BadPublicKeySize => "bad public key size",
            LegacyBoxError::BadSecretKeySize => "bad secret key size",
        })
    }
}

impl std::error::Error for LegacyBoxError {}

/// The module-level `sharedKeyCache` of crypto.ts (`Map<number, Uint8Array>`).
/// JS peer ids are integer uids; `i64` stands in for the JS number key.
#[derive(Clone, Debug, Default)]
pub struct SharedKeyCache {
    map: HashMap<i64, [u8; 32]>,
}

impl SharedKeyCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// `computeSharedKey(myPrivateKeyB64, peerPublicKeyB64, peerId)`.
    /// Cache hit → the cached key, arguments NOT inspected (quirk, see module
    /// docs). Miss → decode own private key, then peer public key (each may
    /// throw 'invalid encoding'), then `nacl.box.before(peerPub, myPriv)`
    /// (public key size checked before secret key size). Errors do not
    /// populate the cache.
    pub fn compute_shared_key(
        &mut self,
        my_private_key_b64: &str,
        peer_public_key_b64: &str,
        peer_id: i64,
    ) -> Result<[u8; 32], LegacyBoxError> {
        if let Some(cached) = self.map.get(&peer_id) {
            return Ok(*cached);
        }

        let my_private_key = tweetnacl_util_decode_base64(my_private_key_b64).ok_or(LegacyBoxError::InvalidEncoding)?;
        let peer_public_key = tweetnacl_util_decode_base64(peer_public_key_b64).ok_or(LegacyBoxError::InvalidEncoding)?;
        let peer_public_key: [u8; 32] = peer_public_key.try_into().map_err(|_| LegacyBoxError::BadPublicKeySize)?;
        let my_private_key: [u8; 32] = my_private_key.try_into().map_err(|_| LegacyBoxError::BadSecretKeySize)?;
        let shared_key = box_before(&peer_public_key, &my_private_key);

        self.map.insert(peer_id, shared_key);
        Ok(shared_key)
    }

    /// `clearSharedKey(peerId)`.
    pub fn clear_shared_key(&mut self, peer_id: i64) {
        self.map.remove(&peer_id);
    }

    /// `clearAllSharedKeys()` (also what `deletePrivateKey()` does to the cache).
    pub fn clear_all_shared_keys(&mut self) {
        self.map.clear();
    }
}

/// `encryptMessage(text, sharedKey)`. Draws exactly one 24-byte nonce (before
/// the text is encoded, as in TS). A `&str` is always valid UTF-8, so the
/// `decodeUTF8` URIError on lone UTF-16 surrogates cannot arise here.
pub fn encrypt_message(text: &str, shared_key: &[u8; 32], rng: &mut dyn Rng) -> String {
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill(&mut nonce);
    let message_bytes = text.as_bytes();
    let ciphertext = secretbox_seal(message_bytes, &nonce, shared_key);
    // JSON.stringify({n, c}): base64 never needs escaping, key order n then c.
    format!("{{\"n\":\"{}\",\"c\":\"{}\"}}", b64(&nonce), b64(&ciphertext))
}

/// `decryptMessage(encryptedStr, sharedKey)`: `None` exactly where TS returns
/// `null` (it never throws — the whole body is inside `try { } catch { null }`).
pub fn decrypt_message(encrypted_str: &str, shared_key: &[u8; 32]) -> Option<String> {
    // JSON.parse(...) then `encrypted.n` / `encrypted.c`: anything but a
    // well-formed top-level object makes the property reads yield undefined
    // (or throw on null) → null.
    let members = hermes_parse_top_level_object(encrypted_str)?;
    let field = |key: u16| members.iter().rev().find(|m| m.key.len() == 1 && m.key[0] == key);

    // decodeBase64(encrypted.n): a missing field is `undefined`, whose ToString
    // "undefined" fails the regex → throw → null.
    let n = field(b'n' as u16)?;
    let nonce = tweetnacl_util_decode_base64_utf16(&js_to_string(encrypted_str.as_bytes(), n.start)?)?;
    let c = field(b'c' as u16)?;
    let ciphertext = tweetnacl_util_decode_base64_utf16(&js_to_string(encrypted_str.as_bytes(), c.start)?)?;

    // nacl.box.open.after = nacl.secretbox.open: checkLengths throws 'bad nonce
    // size' (→ null); a box shorter than 16 bytes or a bad tag returns null.
    let nonce: [u8; NONCE_LEN] = nonce.try_into().ok()?;
    let plaintext = secretbox_open(&ciphertext, &nonce, shared_key)?;

    // `if (!plaintext) return null` — an empty Uint8Array is truthy, so an
    // empty plaintext is "". encodeUTF8 = decodeURIComponent(escape(..)):
    // throws URIError on anything that is not strict UTF-8 → null.
    tweetnacl_util_encode_utf8(plaintext)
}

/// Build 325 `openLegacyBoxEdit`: the shared key is derived from the peer's
/// CURRENT public key (never the per-peer-id `SharedKeyCache`, which is not
/// invalidated on peer-key-rotated), then `decryptMessage`. `None` on any
/// key decoding / size error or where decryptMessage returns null.
pub fn open_with_current_key(box_json: &str, peer_public_key_b64: &str, my_private_key_b64: &str) -> Option<String> {
    let peer: [u8; 32] = tweetnacl_util_decode_base64(peer_public_key_b64)?.try_into().ok()?;
    let mine: [u8; 32] = tweetnacl_util_decode_base64(my_private_key_b64)?.try_into().ok()?;
    decrypt_message(box_json, &box_before(&peer, &mine))
}

// ───────── ToString of a JSON.parse'd member (raw-token form) ─────────

fn units(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

/// ECMAScript ToString of the (validated) JSON value at `b[i]`, as used by
/// `regex.test(v)` and `atob(v)` inside decodeBase64. `None` only for numbers:
/// a JS number stringifies to at most 21 base64-alphabet characters (digits,
/// or "1e+21"-style), which can never decode to the 24-byte nonce or a
/// >= 16-byte box, so the outcome is null whatever the exact digits are.
///
/// Arrays: `String([x]) === String(x)` except that join renders a null
/// element as ""; `String([]) === ""`; two or more elements put a ',' in the
/// result, which the base64 regex rejects whatever the elements are. Linear
/// time: descend the chain of single-element arrays once, then check that
/// every level closes right after its only element. The JSON depth cap
/// bounds the chain to 509 arrays; Hermes' recursive `join` has no counter
/// of its own, only the native stack (measured: 640 levels fit on the 1 MB
/// RN JS thread, 5469 on 8 MB), so within the cap it does not throw in
/// practice (a native-stack overflow there would be engine/stack specific
/// and is not modelled).
fn js_to_string(b: &[u8], mut i: usize) -> Option<Vec<u16>> {
    let mut depth = 0usize;
    // Descend `[ [ [ x` while the array is non-empty.
    // The document was validated by `hermes_parse_top_level_object`, so every
    // index below exists; `get` + `?` keeps that from being a panic if it ever
    // did not (this text is chosen by a peer).
    while b.get(i) == Some(&b'[') {
        let first = skip_json_ws(b, i + 1);
        if b.get(first) == Some(&b']') {
            break; // innermost value is an empty array
        }
        depth += 1;
        i = first;
    }
    let (inner, end) = match *b.get(i)? {
        b'"' => {
            let s = std::str::from_utf8(b.get(i..)?).ok()?;
            let (v, n) = hermes_parse_string(s, 0)?;
            (v, i + n)
        }
        b'[' => (Vec::new(), skip_json_ws(b, i + 1) + 1), // [] → ""
        b'n' => (if depth > 0 { Vec::new() } else { units("null") }, i + 4),
        b't' => (units("true"), i + 4),
        b'f' => (units("false"), i + 5),
        b'{' => (units("[object Object]"), skip_json_container(b, i)),
        _ => return None, // number, see above
    };
    let mut j = end;
    for _ in 0..depth {
        j = skip_json_ws(b, j);
        if *b.get(j)? != b']' {
            return Some(units(",")); // ≥ 2 elements at this level
        }
        j += 1;
    }
    Some(inner)
}
