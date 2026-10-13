//! Attachment encryption and the file envelope — line-for-line port of
//! `mobile/src/utils/crypto.ts:690-789` (`encryptFileBase64`,
//! `decryptFileBase64`, `buildFileEnvelope`, `parseFileEnvelope`) plus the pure
//! post-download step of `mobile/src/services/api.ts:1199-1257` (build 324).
//! Contract: docs/native/protocol/03-crypto.md §8; conformance:
//! docs/native/vectors/files.json (tests/golden_files.rs).
//!
//! Construction: a fresh 32-byte key is drawn, THEN a 24-byte nonce, and the
//! file bytes are sealed with `nacl.secretbox` (tag16 ‖ XSalsa20 ciphertext).
//! The server stores those raw ciphertext bytes; key and nonce only travel
//! inside the ratchet-encrypted file envelope JSON.
//!
//! Faithful to the RN client INCLUDING its quirks (do not "fix" them here):
//! - Base64 is decoded exactly like tweetnacl-util `decodeBase64`
//!   (`compat::b64`): the validation regex rejects unpadded / URL-safe /
//!   whitespace input, but non-zero trailing bits ARE accepted ("AB=="
//!   decodes like "AA=="). This is deliberately more lenient than
//!   `primitives::b64d`.
//! - `encryptFileBase64` throws on invalid base64 BEFORE drawing any
//!   randomness; `decryptFileBase64` never throws (every failure is `null`).
//! - An empty file decrypts to `""` (Some), but the download path in api.ts
//!   treats `""` as falsy and throws "decryption failed": a 0-byte attachment
//!   can be sent by RN but never opened by RN ([`decrypt_downloaded_file`]).
//! - The envelope parser is JavaScript: `id`/`k`/`n` only need to be truthy and
//!   are coerced with `String()` (numbers → JS number formatting, `true` →
//!   "true", `[]` → "", `{}` → "[object Object]", an object with its own
//!   `toString` key throws → null); `s`/`d` accept any JSON number including
//!   `1e400` (= Infinity) and `-0`.
//! - The builder is `JSON.stringify`: undefined optionals are omitted, numbers
//!   use JS formatting (`256`, `3.5`, `1e+21`), NaN/±Infinity become `null`
//!   (`compat::json` / `compat::js_number`).
//! - The envelope parser is a V8-grammar `JSON.parse` port with a nesting cap
//!   of 128 (`MAX_JSON_DEPTH`); Hermes (the RN engine) lexes numbers with
//!   strtod and throws once a value sits at depth 512 (`compat::json`). Real
//!   envelopes are flat JSON that both accept identically.

use std::collections::HashMap;

use crate::compat::b64::tweetnacl_util_decode_base64;
use crate::compat::js_number::{number_to_json as json_number, number_to_string as js_number_to_string};
use crate::compat::json::quote_json_string as json_quote;
use crate::primitives::{b64, secretbox_open, secretbox_seal};
use crate::rng::Rng;

/// `nacl.secretbox.keyLength`.
pub const FILE_KEY_LEN: usize = 32;
/// `nacl.secretbox.nonceLength`.
pub const FILE_NONCE_LEN: usize = 24;
/// `parseFileEnvelope` default when `m` is not a string.
pub const DEFAULT_MIME_TYPE: &str = "application/octet-stream";

/// `EncryptedFile` from crypto.ts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedFile {
    pub ciphertext_b64: String,
    pub key_b64: String,
    pub nonce_b64: String,
}

/// The same result as raw bytes (what a native uploader actually sends: the
/// server stores and serves the raw ciphertext).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedFileBytes {
    /// Poly1305 tag (16) ‖ XSalsa20 ciphertext.
    pub ciphertext: Vec<u8>,
    pub key: [u8; FILE_KEY_LEN],
    pub nonce: [u8; FILE_NONCE_LEN],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileError {
    /// tweetnacl-util `TypeError('invalid encoding')`.
    InvalidEncoding,
    /// api.ts `new Error('decryption failed')`.
    DecryptionFailed,
}

impl std::fmt::Display for FileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileError::InvalidEncoding => write!(f, "invalid encoding"),
            FileError::DecryptionFailed => write!(f, "decryption failed"),
        }
    }
}

impl std::error::Error for FileError {}

// ───────── content encryption (crypto.ts:707-738) ─────────

/// Byte-level core of `encryptFileBase64`: draws key (32) then nonce (24).
pub fn encrypt_file(plaintext: &[u8], rng: &mut dyn Rng) -> EncryptedFileBytes {
    let mut key = [0u8; FILE_KEY_LEN];
    rng.fill(&mut key);
    let mut nonce = [0u8; FILE_NONCE_LEN];
    rng.fill(&mut nonce);
    let ciphertext = secretbox_seal(plaintext, &nonce, &key);
    EncryptedFileBytes { ciphertext, key, nonce }
}

/// `encryptFileBase64(plaintextB64)`. Throws (Err) on input tweetnacl-util
/// rejects, before any random bytes are drawn.
pub fn encrypt_file_base64(plaintext_b64: &str, rng: &mut dyn Rng) -> Result<EncryptedFile, FileError> {
    let plaintext = nacl_util_decode_base64(plaintext_b64)?;
    let e = encrypt_file(&plaintext, rng);
    Ok(EncryptedFile { ciphertext_b64: b64(&e.ciphertext), key_b64: b64(&e.key), nonce_b64: b64(&e.nonce) })
}

/// `decryptFileBase64(ciphertextB64, keyB64, nonceB64)`: `None` for bad base64,
/// a key ≠ 32 or nonce ≠ 24 bytes, a box shorter than 16 bytes, or an
/// authentication failure. An empty file yields `Some("")`.
pub fn decrypt_file_base64(ciphertext_b64: &str, key_b64: &str, nonce_b64: &str) -> Option<String> {
    let ciphertext = nacl_util_decode_base64(ciphertext_b64).ok()?;
    decrypt_file(&ciphertext, key_b64, nonce_b64).map(|p| b64(&p))
}

/// `decryptFileBase64` on raw ciphertext bytes (the server serves raw bytes;
/// key and nonce come base64-encoded from the file envelope).
pub fn decrypt_file(ciphertext: &[u8], key_b64: &str, nonce_b64: &str) -> Option<Vec<u8>> {
    let key = nacl_util_decode_base64(key_b64).ok()?;
    let nonce = nacl_util_decode_base64(nonce_b64).ok()?;
    let key: [u8; FILE_KEY_LEN] = key.try_into().ok()?;
    let nonce: [u8; FILE_NONCE_LEN] = nonce.try_into().ok()?;
    secretbox_open(ciphertext, &nonce, &key)
}

/// The pure tail of `downloadDecryptedChatFile` (api.ts:1240-1248): the raw
/// downloaded bytes are decrypted and `if (!plaintextB64) throw new Error
/// ('decryption failed')`. As built this also rejects a correctly decrypted
/// EMPTY file, because `""` is falsy.
pub fn decrypt_downloaded_file(ciphertext: &[u8], key_b64: &str, nonce_b64: &str) -> Result<Vec<u8>, FileError> {
    match decrypt_file(ciphertext, key_b64, nonce_b64) {
        Some(p) if !p.is_empty() => Ok(p),
        _ => Err(FileError::DecryptionFailed),
    }
}

// ───────── file envelope (crypto.ts:747-789) ─────────

/// `FileEnvelope` from crypto.ts. Numbers are JS numbers (`f64`).
#[derive(Clone, Debug, PartialEq)]
pub struct FileEnvelope {
    pub placeholder: String,
    pub file_id: String,
    pub key: String,
    pub nonce: String,
    pub mime_type: String,
    pub file_name: Option<String>,
    pub file_size: Option<f64>,
    pub duration: Option<f64>,
}

/// `buildFileEnvelope(env)` = `JSON.stringify({p,id,k,n,m,fn,s,d})` with
/// undefined fields omitted. The result is the ratchet plaintext.
pub fn build_file_envelope(env: &FileEnvelope) -> String {
    let mut out = String::with_capacity(96 + env.placeholder.len() + env.key.len() + env.nonce.len());
    out.push_str("{\"p\":");
    json_quote(&env.placeholder, &mut out);
    out.push_str(",\"id\":");
    json_quote(&env.file_id, &mut out);
    out.push_str(",\"k\":");
    json_quote(&env.key, &mut out);
    out.push_str(",\"n\":");
    json_quote(&env.nonce, &mut out);
    out.push_str(",\"m\":");
    json_quote(&env.mime_type, &mut out);
    if let Some(name) = &env.file_name {
        out.push_str(",\"fn\":");
        json_quote(name, &mut out);
    }
    if let Some(size) = env.file_size {
        out.push_str(",\"s\":");
        out.push_str(&json_number(size));
    }
    if let Some(d) = env.duration {
        out.push_str(",\"d\":");
        out.push_str(&json_number(d));
    }
    out.push('}');
    out
}

/// `parseFileEnvelope(text)`: `None` wherever the TS returns `null`, including
/// every case where `JSON.parse` or `String()` throws.
///
/// Representation limit: JS strings may hold lone UTF-16 surrogates (e.g. from
/// a `"\ud800"` escape); Rust `String` cannot, so they come back as U+FFFD.
pub fn parse_file_envelope(text: &str) -> Option<FileEnvelope> {
    let o = json_parse(text)?;
    // `if (!o || typeof o !== 'object') return null;` — arrays pass this gate
    // and then fail the `o.id` check below (they have no such property).
    let members: &[(Vec<u16>, Js)] = match &o {
        Js::Obj(m) => m,
        Js::Arr(_) => &[],
        _ => return None,
    };
    let id = prop(members, "id");
    let k = prop(members, "k");
    let n = prop(members, "n");
    if !truthy(id) || !truthy(k) || !truthy(n) {
        return None;
    }
    let placeholder = match prop(members, "p") {
        Some(Js::Str(s)) => utf16_lossy(s),
        _ => String::new(),
    };
    let file_id = utf16_lossy(&js_string_coerce(id?)?);
    let key = utf16_lossy(&js_string_coerce(k?)?);
    let nonce = utf16_lossy(&js_string_coerce(n?)?);
    let mime_type = match prop(members, "m") {
        Some(Js::Str(s)) => utf16_lossy(s),
        _ => DEFAULT_MIME_TYPE.to_string(),
    };
    let file_name = match prop(members, "fn") {
        Some(Js::Str(s)) => Some(utf16_lossy(s)),
        _ => None,
    };
    let file_size = match prop(members, "s") {
        Some(Js::Num(x)) => Some(*x),
        _ => None,
    };
    let duration = match prop(members, "d") {
        Some(Js::Num(x)) => Some(*x),
        _ => None,
    };
    Some(FileEnvelope { placeholder, file_id, key, nonce, mime_type, file_name, file_size, duration })
}

// ───────── tweetnacl-util decodeBase64 ─────────

/// tweetnacl-util `decodeBase64` (`compat::b64`); throws
/// `TypeError('invalid encoding')`.
fn nacl_util_decode_base64(s: &str) -> Result<Vec<u8>, FileError> {
    tweetnacl_util_decode_base64(s).ok_or(FileError::InvalidEncoding)
}

// ───────── JSON.parse + the JS coercions parseFileEnvelope relies on ─────────

/// A `JSON.parse` result. Strings are UTF-16 code units, as in JS.
#[derive(Debug)]
enum Js {
    Null,
    Bool(bool),
    Num(f64),
    Str(Vec<u16>),
    Arr(Vec<Js>),
    /// Own properties; a duplicate key overwrites the earlier value in place.
    Obj(Vec<(Vec<u16>, Js)>),
}

/// Nesting bound of this port's parser (JS engines differ; RN never emits
/// nested envelopes, so anything this deep is adversarial and yields `None`).
const MAX_JSON_DEPTH: usize = 128;

fn prop<'a>(members: &'a [(Vec<u16>, Js)], name: &str) -> Option<&'a Js> {
    members.iter().find(|(k, _)| k.iter().copied().eq(name.encode_utf16())).map(|(_, v)| v)
}

/// JS truthiness (`undefined` = `None`).
fn truthy(v: Option<&Js>) -> bool {
    match v {
        None | Some(Js::Null) => false,
        Some(Js::Bool(b)) => *b,
        Some(Js::Num(x)) => *x != 0.0 && !x.is_nan(),
        Some(Js::Str(s)) => !s.is_empty(),
        Some(Js::Arr(_)) | Some(Js::Obj(_)) => true,
    }
}

/// `String(v)` for a JSON value; `None` = the TypeError thrown when an object
/// has an own (necessarily non-callable) `toString` property.
fn js_string_coerce(v: &Js) -> Option<Vec<u16>> {
    Some(match v {
        Js::Null => "null".encode_utf16().collect(),
        Js::Bool(true) => "true".encode_utf16().collect(),
        Js::Bool(false) => "false".encode_utf16().collect(),
        Js::Num(x) => js_number_to_string(*x).encode_utf16().collect(),
        Js::Str(s) => s.clone(),
        // Array.prototype.toString → join(","): null elements become "".
        Js::Arr(items) => {
            let mut out = Vec::new();
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(u16::from(b','));
                }
                if !matches!(item, Js::Null) {
                    out.extend(js_string_coerce(item)?);
                }
            }
            out
        }
        Js::Obj(members) => {
            if prop(members, "toString").is_some() {
                return None;
            }
            "[object Object]".encode_utf16().collect()
        }
    })
}

fn utf16_lossy(s: &[u16]) -> String {
    String::from_utf16_lossy(s)
}

/// ECMAScript `JSON.parse` (no reviver). `None` wherever it throws.
fn json_parse(text: &str) -> Option<Js> {
    let mut p = JsonParser { src: text, i: 0 };
    let v = p.value(0)?;
    p.ws();
    (p.i == text.len()).then_some(v)
}

struct JsonParser<'a> {
    src: &'a str,
    i: usize,
}

impl JsonParser<'_> {
    fn peek(&self) -> Option<u8> {
        self.src.as_bytes().get(self.i).copied()
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn eat(&mut self, c: u8) -> Option<()> {
        (self.peek()? == c).then(|| self.i += 1)
    }

    fn value(&mut self, depth: usize) -> Option<Js> {
        self.ws();
        match self.peek()? {
            b'{' => self.object(depth + 1),
            b'[' => self.array(depth + 1),
            b'"' => self.string().map(Js::Str),
            b't' => self.literal("true", Js::Bool(true)),
            b'f' => self.literal("false", Js::Bool(false)),
            b'n' => self.literal("null", Js::Null),
            b'-' | b'0'..=b'9' => self.number(),
            _ => None,
        }
    }

    fn literal(&mut self, word: &str, v: Js) -> Option<Js> {
        self.src[self.i..].starts_with(word).then(|| {
            self.i += word.len();
            v
        })
    }

    fn object(&mut self, depth: usize) -> Option<Js> {
        if depth > MAX_JSON_DEPTH {
            return None;
        }
        self.eat(b'{')?;
        let mut members: Vec<(Vec<u16>, Js)> = Vec::new();
        let mut index: HashMap<Vec<u16>, usize> = HashMap::new();
        self.ws();
        if self.eat(b'}').is_some() {
            return Some(Js::Obj(members));
        }
        loop {
            self.ws();
            if self.peek()? != b'"' {
                return None;
            }
            let key = self.string()?;
            self.ws();
            self.eat(b':')?;
            let v = self.value(depth)?;
            match index.get(&key) {
                Some(&at) => members[at].1 = v,
                None => {
                    index.insert(key.clone(), members.len());
                    members.push((key, v));
                }
            }
            self.ws();
            match self.peek()? {
                b',' => self.i += 1,
                b'}' => {
                    self.i += 1;
                    return Some(Js::Obj(members));
                }
                _ => return None,
            }
        }
    }

    fn array(&mut self, depth: usize) -> Option<Js> {
        if depth > MAX_JSON_DEPTH {
            return None;
        }
        self.eat(b'[')?;
        let mut items = Vec::new();
        self.ws();
        if self.eat(b']').is_some() {
            return Some(Js::Arr(items));
        }
        loop {
            items.push(self.value(depth)?);
            self.ws();
            match self.peek()? {
                b',' => self.i += 1,
                b']' => {
                    self.i += 1;
                    return Some(Js::Arr(items));
                }
                _ => return None,
            }
        }
    }

    fn digits(&mut self) -> usize {
        let start = self.i;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.i += 1;
        }
        self.i - start
    }

    /// `-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?`, rounded to the nearest
    /// double; overflow gives ±Infinity, as in JS.
    fn number(&mut self) -> Option<Js> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        match self.peek()? {
            b'0' => self.i += 1,
            b'1'..=b'9' => {
                self.digits();
            }
            _ => return None,
        }
        if self.peek() == Some(b'.') {
            self.i += 1;
            if self.digits() == 0 {
                return None;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if self.digits() == 0 {
                return None;
            }
        }
        self.src[start..self.i].parse::<f64>().ok().map(Js::Num)
    }

    fn string(&mut self) -> Option<Vec<u16>> {
        self.eat(b'"')?;
        let mut out: Vec<u16> = Vec::new();
        loop {
            match self.peek()? {
                b'"' => {
                    self.i += 1;
                    return Some(out);
                }
                b'\\' => {
                    self.i += 1;
                    let esc = self.peek()?;
                    self.i += 1;
                    let unit = match esc {
                        b'"' => 0x22,
                        b'\\' => 0x5c,
                        b'/' => 0x2f,
                        b'b' => 0x08,
                        b'f' => 0x0c,
                        b'n' => 0x0a,
                        b'r' => 0x0d,
                        b't' => 0x09,
                        b'u' => {
                            let hex = self.src.as_bytes().get(self.i..self.i + 4)?;
                            let mut u: u16 = 0;
                            for &h in hex {
                                u = (u << 4) | (char::from(h).to_digit(16)? as u16);
                            }
                            self.i += 4;
                            u
                        }
                        _ => return None,
                    };
                    out.push(unit);
                }
                0x00..=0x1f => return None,
                c if c < 0x80 => {
                    out.push(u16::from(c));
                    self.i += 1;
                }
                _ => {
                    let ch = self.src[self.i..].chars().next()?;
                    let mut buf = [0u16; 2];
                    out.extend_from_slice(ch.encode_utf16(&mut buf));
                    self.i += ch.len_utf8();
                }
            }
        }
    }
}
