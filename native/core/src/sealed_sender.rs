//! Sealed Sender — line-for-line port of `mobile/src/services/sealedEnvelope.ts`
//! (build 324: `sealEnvelope`, `openEnvelope`, `verifyCert`,
//! `canonicalSignedPayload`), the pure decision logic of
//! `mobile/src/services/sealedSender.ts` (`verifyCertWithRefresh`, cache
//! constants), the wire glue of `ChatScreen.tsx:896-940` (send) and
//! `App.tsx:1040-1100` (receive), and the Go issuer
//! `internal/sealedsender/sealedsender.go` (`IssueCert` / `signedPayload`) as a
//! test and tooling stand-in.
//!
//! Contract: docs/native/protocol/03-crypto.md §5. Conformance:
//! docs/native/vectors/sealedSender.json (tests/golden_sealed_sender.rs).
//!
//! The certificate travels as an UNTYPED JavaScript value: `openEnvelope` only
//! checks that `inner.cert` is truthy, and `verifyCert` feeds its fields through
//! JS coercions (`Date.now() > x`, `BigInt(x)`, `DataView.setBigInt64`,
//! tweetnacl-util `decodeBase64`). Certificates are therefore modelled as
//! `serde_json::Value` and every coercion is reproduced, because a native
//! receiver that is stricter than RN (or laxer) silently diverges from RN
//! receivers in the field.
//!
//! Quirks reproduced on purpose (do NOT fix here — see the report / Q6):
//! - Signed payload = BE64(uid) ‖ BE64(exp) ‖ the sender_pub BASE64 TEXT.
//!   A non-ASCII sender_pub makes RN throw (buffer sized by UTF-16 length) →
//!   `false`, although the Go server signs UTF-8 bytes of any string.
//! - `uid` / `expires_at_ms` accept any JS value that `BigInt()` accepts
//!   ("1001", " 0x3e9 ", [1001], 1.001e3, true …) and are then wrapped modulo
//!   2^64 by `setBigInt64`. Consequence: a cert whose `expires_at_ms` is
//!   re-encoded as `exp + 2^64` passes the `Date.now() >` check forever while
//!   still carrying a valid signature (expiry bypass for any cert holder).
//! - Expiry check is `now > exp` (a cert is still valid AT its expiry ms).
//! - `sender_pub` is never compared with anything (only signed).
//! - `sig` goes through JS `ToString` (an array `["<b64>"]` verifies).
//! - tweetnacl-util base64 accepts non-zero trailing bits (atob), and
//!   tweetnacl Ed25519 verify accepts a non-canonical S (S + k·L).
//! - Blob = b64(nonce(24) ‖ ephemeralPub(32) ‖ box) — nonce FIRST (OSB1 is the
//!   opposite). Ephemeral keypair (32 bytes) is drawn BEFORE the nonce (24).
//! - `ratchet` holds the ratchet envelope JSON TEXT despite the TS parameter
//!   name `ratchetCiphertextB64`.
//!
//! Residual, documented divergences of this port (inputs only a malicious
//! sender who can already box to us could produce; RN keeps them, Rust drops):
//! JSON numbers overflowing f64 (JSON.parse → ±Infinity), lone-surrogate
//! `\uD800` escapes (not representable in a Rust `String`), and nesting deeper
//! than [`MAX_JSON_DEPTH`]. [`js_json_parse`] follows V8's number grammar,
//! not Hermes' strtod lexer (`compat::json`), so `1.` / `-.5` are rejected.
//!
//! JS semantics come from `compat`: base64 (`compat::b64`), Ed25519 verify
//! (`compat::ed25519`), JSON.stringify and key order (`compat::json`) and the
//! coercions (`compat::js_value::to_string_lenient`, which does not model the
//! own-`toString` TypeError, and `compat::js_number::string_to_number_f64_radix`,
//! whose long `0x…` rounding cannot change a clock comparison).

use serde_json::{Map, Number, Value};

use crate::compat::b64::tweetnacl_util_decode_base64;
use crate::compat::js_value::{to_boolean_opt, to_string_lenient};
use crate::compat::json::{own_property_keys, quote_json_string, stringify};
use crate::compat::utf8::tweetnacl_util_encode_utf8;
use crate::primitives::{b64, box_open, box_seal, ed25519_sign, x25519_keypair};
use crate::rng::Rng;

/// `NONCE_LEN` (sealedEnvelope.ts).
pub const NONCE_LEN: usize = 24;
/// `EPHEM_PUB_LEN` (sealedEnvelope.ts).
pub const EPHEM_PUB_LEN: usize = 32;
/// `openEnvelope` rejects decoded blobs shorter than nonce + ephemeral pub + Poly1305 tag.
pub const MIN_BLOB_LEN: usize = NONCE_LEN + EPHEM_PUB_LEN + 16;
/// Go `DefaultCertValidity` (sealedsender.go:54).
pub const CERT_VALIDITY_MS: i64 = 24 * 60 * 60 * 1000;
/// Client soft TTL of the cached server verifying key (sealedSender.ts:81).
pub const SERVER_KEY_REFRESH_MS: i64 = 24 * 60 * 60 * 1000;
/// Client re-issues its cert when less than this remains (sealedSender.ts:82).
pub const CERT_EARLY_REFRESH_MS: i64 = 60 * 60 * 1000;
/// Client refetches a delivery token when less than this remains (sealedSender.ts:192).
pub const TOKEN_EARLY_REFRESH_MS: i64 = 5 * 60 * 1000;
/// Nesting limit of [`js_json_parse`] (JSON.parse has none; a limit keeps a
/// hostile blob from overflowing the native stack).
///
/// 64, not the 512 it was: the parser is recursive, and at depth 512 it
/// needs more than 128 KB of stack in a release build and more than 512 KB in
/// a debug build — the whole stack of a secondary thread on iOS. Anyone who
/// knows a recipient's identity key can seal a blob whose inner JSON nests
/// that deep, so that was a remote crash in a debug build and a thin margin
/// in a release one (`tests/hostile_input.rs` runs on a 512 KB stack). The
/// inner object of a sealed envelope nests three levels.
pub const MAX_JSON_DEPTH: usize = 64;

/// Typed certificate as the Go server issues it (`Cert`, sealedsender.go:59-64).
/// Receivers must keep the raw `Value` (see module docs); this type is for
/// issuing and for building a cert to seal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedSenderCert {
    pub uid: i64,
    pub expires_at_ms: i64,
    pub sender_pub: String,
    pub sig: String,
}

impl SealedSenderCert {
    /// The JSON object in Go field order: uid, expires_at_ms, sender_pub, sig.
    pub fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("uid".into(), Value::from(self.uid));
        m.insert("expires_at_ms".into(), Value::from(self.expires_at_ms));
        m.insert("sender_pub".into(), Value::String(self.sender_pub.clone()));
        m.insert("sig".into(), Value::String(self.sig.clone()));
        Value::Object(m)
    }
}

/// `SealedEnvelopeInner` as returned by `openEnvelope`.
#[derive(Clone, Debug, PartialEq)]
pub struct SealedEnvelopeInner {
    /// `inner.cert` — whatever truthy JSON value the sender put there.
    pub cert: Value,
    /// `inner.ratchet` — the ratchet envelope JSON text.
    pub ratchet: String,
    /// The whole parsed inner object (JS property order), including keys RN ignores.
    pub object: Value,
}

/// Result of [`verify_cert_with_refresh`] (`{ ok, refreshed }`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CertCheck {
    pub ok: bool,
    pub refreshed: bool,
}

// ───────── sealedEnvelope.ts ─────────

/// `sealEnvelope(cert, ratchetCiphertextB64, recipientIdentityPubB64)`.
///
/// `None` where TS returns null. Draws nothing when the recipient key is not
/// 32 bytes of valid base64; otherwise draws the ephemeral keypair (32) and then
/// the nonce (24).
///
/// Also `None`, with nothing drawn, for an inner object [`open_envelope`]
/// would refuse — a certificate nested [`MAX_JSON_DEPTH`] levels or deeper
/// (it sits one level inside `{cert, ratchet}`). The core never seals what a
/// receiver running the same core cannot open; a certificate the server
/// issues nests one level.
pub fn seal_envelope(
    cert: &Value,
    ratchet_ciphertext_b64: &str,
    recipient_identity_pub_b64: &str,
    rng: &mut dyn Rng,
) -> Option<String> {
    let recipient_pub = tweetnacl_util_decode_base64(recipient_identity_pub_b64)?;
    let recipient_pub: [u8; EPHEM_PUB_LEN] = recipient_pub.try_into().ok()?;
    let plaintext = inner_plaintext_json(cert, ratchet_ciphertext_b64);
    js_json_parse(&plaintext)?;
    let ephem = x25519_keypair(rng);
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill(&mut nonce);
    let ct = box_seal(plaintext.as_bytes(), &nonce, &recipient_pub, &ephem.private);
    let mut blob = Vec::with_capacity(NONCE_LEN + EPHEM_PUB_LEN + ct.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ephem.public);
    blob.extend_from_slice(&ct);
    Some(b64(&blob))
}

/// `JSON.stringify({ cert, ratchet })` — the exact boxed plaintext.
pub fn inner_plaintext_json(cert: &Value, ratchet: &str) -> String {
    let mut out = String::from("{\"cert\":");
    out.push_str(&stringify(cert));
    out.push_str(",\"ratchet\":");
    quote_json_string(ratchet, &mut out);
    out.push('}');
    out
}

/// `openEnvelope(myIdentityPrivB64, blobB64)`. `None` wherever TS returns null
/// (including every path where it throws inside its try/catch).
pub fn open_envelope(my_identity_priv_b64: &str, blob_b64: &str) -> Option<SealedEnvelopeInner> {
    let my_priv = tweetnacl_util_decode_base64(my_identity_priv_b64)?;
    let blob = tweetnacl_util_decode_base64(blob_b64)?;
    if blob.len() < MIN_BLOB_LEN {
        return None;
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&blob[..NONCE_LEN]);
    let mut ephem_pub = [0u8; EPHEM_PUB_LEN];
    ephem_pub.copy_from_slice(&blob[NONCE_LEN..NONCE_LEN + EPHEM_PUB_LEN]);
    // nacl.box.open throws 'bad secret key size' unless the key is 32 bytes.
    let my_priv: [u8; 32] = my_priv.try_into().ok()?;
    let plaintext = box_open(&blob[NONCE_LEN + EPHEM_PUB_LEN..], &nonce, &ephem_pub, &my_priv)?;
    // tweetnacl-util encodeUTF8 = decodeURIComponent(escape(..)): throws on
    // malformed / overlong / surrogate UTF-8, exactly what from_utf8 rejects.
    let json = tweetnacl_util_encode_utf8(plaintext)?;
    let object = js_json_parse(&json)?;
    // if (!inner || typeof inner.ratchet !== 'string' || !inner.cert) return null;
    // (non-object truthy values have no own `ratchet` → null as well)
    let Value::Object(map) = &object else { return None };
    let ratchet = match map.get("ratchet") {
        Some(Value::String(s)) => s.clone(),
        _ => return None,
    };
    let cert = map.get("cert");
    if !to_boolean_opt(cert) {
        return None;
    }
    let cert = cert.cloned().unwrap_or(Value::Null);
    Some(SealedEnvelopeInner { cert, ratchet, object })
}

/// `verifyCert(cert, verifyingKeyB64)` with `Date.now()` = `now_ms`
/// (build 349: strict).
///
/// `uid` and `expires_at_ms` MUST be JSON integers in `[0, 2^53)`; each is
/// parsed ONCE as an `i64` and the same values feed both the expiry check and
/// the signed payload `BE64(uid) ‖ BE64(exp) ‖ ASCII(sender_pub)`. Any other
/// shape (a float, a string, `exp + 2^64` re-encodings, a negative) is
/// `false`: the RN coercions that let an expired certificate verify forever
/// are gone.
pub fn verify_cert(cert: &Value, verifying_key_b64: &str, now_ms: i64) -> bool {
    const MAX_SAFE: u64 = (1u64 << 53) - 1;
    let Value::Object(c) = cert else { return false };
    let int = |k: &str| match c.get(k) {
        Some(Value::Number(n)) if n.is_u64() => n.as_u64().filter(|v| *v <= MAX_SAFE).map(|v| v as i64),
        _ => None,
    };
    let (Some(uid), Some(exp)) = (int("uid"), int("expires_at_ms")) else { return false };
    if now_ms > exp {
        return false;
    }
    let (Some(Value::String(sender_pub)), Some(Value::String(sig))) = (c.get("sender_pub"), c.get("sig")) else { return false };
    if !sender_pub.is_ascii() {
        return false;
    }
    let (Some(public), Some(sig)) = (crate::ratchet::b64_strict32(verifying_key_b64), crate::ratchet::b64_strict(sig)) else { return false };
    let Ok(sig) = <[u8; 64]>::try_from(sig) else { return false };
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&public) else { return false };
    vk.verify_strict(&go_signed_payload(uid, exp, sender_pub), &ed25519_dalek::Signature::from_bytes(&sig)).is_ok()
}

/// `canonicalSignedPayload(uid, expMs, senderPubB64)` for typed inputs:
/// BE int64(uid) ‖ BE int64(exp_ms) ‖ UTF-8(sender_pub). `None` where TS throws:
/// a non-ASCII sender_pub overflows the buffer sized by its UTF-16 length.
pub fn canonical_signed_payload(uid: i64, exp_ms: i64, sender_pub_b64: &str) -> Option<Vec<u8>> {
    if !sender_pub_b64.is_ascii() {
        return None;
    }
    Some(go_signed_payload(uid, exp_ms, sender_pub_b64))
}

// ───────── sealedSender.ts (pure parts) ─────────

/// `verifyCertWithRefresh(cert)` (sealedSender.ts:252-272). `get_server_verifying_key(force)`
/// stands for `getServerVerifyingKey(force)`: cached/soft-TTL key for `false`,
/// a forced refetch for `true`; `None` = null.
pub fn verify_cert_with_refresh(
    cert: &Value,
    now_ms: i64,
    get_server_verifying_key: &mut dyn FnMut(bool) -> Option<String>,
) -> CertCheck {
    let server_key = match get_server_verifying_key(false) {
        Some(k) if !k.is_empty() => k,
        _ => return CertCheck { ok: false, refreshed: false },
    };
    if verify_cert(cert, &server_key, now_ms) {
        return CertCheck { ok: true, refreshed: false };
    }
    match get_server_verifying_key(true) {
        Some(refreshed) if !refreshed.is_empty() && refreshed != server_key => {
            CertCheck { ok: verify_cert(cert, &refreshed, now_ms), refreshed: true }
        }
        _ => CertCheck { ok: false, refreshed: false },
    }
}

// ───────── wire glue (ChatScreen.tsx send, App.tsx receive) ─────────

/// The frame ChatScreen sends: `JSON.stringify({type:'p2p-sealed',
/// data:{toUserId, messageId, blob, deliveryToken}})`.
pub fn p2p_sealed_frame(to_user_id: i64, message_id: &str, blob: &str, delivery_token: &str) -> String {
    let mut data = Map::new();
    data.insert("toUserId".into(), Value::from(to_user_id));
    data.insert("messageId".into(), Value::String(message_id.into()));
    data.insert("blob".into(), Value::String(blob.into()));
    data.insert("deliveryToken".into(), Value::String(delivery_token.into()));
    let mut frame = Map::new();
    frame.insert("type".into(), Value::String("p2p-sealed".into()));
    frame.insert("data".into(), Value::Object(data));
    js_json_stringify(&Value::Object(frame))
}

/// App.tsx `sealedInboxHandler`: turns an inbound `p2p-sealed` frame into the
/// `data` of the `p2p-message` it injects locally, or `None` where the handler
/// returns early (missing blob/messageId/private key, open failure, cert
/// rejected). `verify` stands for `verifyCertWithRefresh(cert).ok`.
///
/// `fromUserId` is `inner.cert.uid` VERBATIM (it may be a string or an array if
/// the sender re-encoded a valid cert); `ts` is copied only when present.
pub fn sealed_inbox_to_p2p_message(
    ws_msg: &Value,
    my_identity_priv_b64: &str,
    verify: &mut dyn FnMut(&Value) -> bool,
) -> Option<Value> {
    // const data = wsMsg?.data || {};
    let data = ws_msg.get("data").filter(|d| to_boolean_opt(Some(d))).and_then(Value::as_object);
    let field = |k: &str| data.and_then(|m| m.get(k));
    let blob = field("blob");
    let message_id = field("messageId");
    if !to_boolean_opt(blob) || !to_boolean_opt(message_id) {
        return None;
    }
    if my_identity_priv_b64.is_empty() {
        return None; // sealed.noPriv
    }
    // decodeBase64 coerces a non-string blob with ToString (regex test + atob).
    let inner = open_envelope(my_identity_priv_b64, &js_to_string(blob))?; // sealed.openFailed
    if !verify(&inner.cert) {
        return None; // sealed.certInvalid
    }
    let mut m = Map::new();
    if let Some(uid) = inner.cert.get("uid") {
        m.insert("fromUserId".into(), uid.clone());
    }
    m.insert("fromUsername".into(), Value::String(String::new()));
    m.insert("fromDisplayName".into(), Value::String(String::new()));
    m.insert("messageId".into(), message_id.cloned().unwrap_or(Value::Null));
    m.insert("type".into(), Value::String("text".into()));
    m.insert("text".into(), Value::String(inner.ratchet));
    m.insert("encrypted".into(), Value::Bool(true));
    m.insert("transport".into(), Value::String("sealed".into()));
    if let Some(ts) = field("ts") {
        m.insert("ts".into(), ts.clone());
    }
    Some(Value::Object(m))
}

// ───────── Go issuer (internal/sealedsender/sealedsender.go) ─────────

/// Go `signedPayload`: BE uint64(uid) ‖ BE uint64(exp) ‖ []byte(senderPub) (UTF-8, any length).
pub fn go_signed_payload(uid: i64, exp_ms: i64, sender_pub: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16 + sender_pub.len());
    buf.extend_from_slice(&uid.to_be_bytes());
    buf.extend_from_slice(&exp_ms.to_be_bytes());
    buf.extend_from_slice(sender_pub.as_bytes());
    buf
}

/// Go `Signer.IssueCert(uid, senderIdentityPubB64)` with `time.Now()` = `now_ms`.
/// `server_secret64` is the 64-byte seed‖pub Ed25519 key. Errors carry the Go text.
pub fn issue_cert(server_secret64: &[u8; 64], uid: i64, sender_pub_b64: &str, now_ms: i64) -> Result<SealedSenderCert, &'static str> {
    if uid <= 0 {
        return Err("sealed-sender: uid must be positive");
    }
    if sender_pub_b64.is_empty() {
        return Err("sealed-sender: sender pub must not be empty");
    }
    let exp = now_ms.saturating_add(CERT_VALIDITY_MS);
    let sig = ed25519_sign(server_secret64, &go_signed_payload(uid, exp, sender_pub_b64));
    Ok(SealedSenderCert { uid, expires_at_ms: exp, sender_pub: sender_pub_b64.into(), sig: b64(&sig) })
}

// ───────── JavaScript value semantics over serde_json::Value ─────────

/// JS `ToString(v)` (undefined → "undefined").
fn js_to_string(v: Option<&Value>) -> String {
    match v {
        None => "undefined".into(),
        Some(v) => to_string_lenient(v),
    }
}

/// `JSON.stringify(v)` byte-for-byte: JS number formatting (all numbers are
/// f64: 1001.0 → "1001", 1e21 → "1e+21", 2^53+1 → "9007199254740992"), array
/// index keys first, lowercase `\u00xx` escapes, no escaping of `/`, DEL or
/// U+2028/2029.
pub fn js_json_stringify(v: &Value) -> String {
    stringify(v)
}

/// `JSON.parse(s)` → `Value` with JS semantics: every number is the f64
/// JSON.parse would produce (stored as i64/u64 when integral), duplicate keys
/// keep the first position and the last value, and objects are re-ordered the
/// way a JS object enumerates. `None` where JSON.parse throws, plus the
/// documented divergences (±Infinity numbers, lone surrogates, depth).
pub fn js_json_parse(s: &str) -> Option<Value> {
    let mut p = JsonParser { s, b: s.as_bytes(), i: 0 };
    let v = p.value(0)?;
    p.ws();
    (p.i == p.b.len()).then_some(v)
}

struct JsonParser<'a> {
    s: &'a str,
    b: &'a [u8],
    i: usize,
}

impl JsonParser<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn value(&mut self, depth: usize) -> Option<Value> {
        self.ws();
        match self.peek()? {
            b'{' => self.object(depth + 1),
            b'[' => self.array(depth + 1),
            b'"' => self.string().map(Value::String),
            b't' => self.literal("true", Value::Bool(true)),
            b'f' => self.literal("false", Value::Bool(false)),
            b'n' => self.literal("null", Value::Null),
            b'-' | b'0'..=b'9' => self.number(),
            _ => None,
        }
    }

    fn literal(&mut self, word: &str, v: Value) -> Option<Value> {
        if self.b[self.i..].starts_with(word.as_bytes()) {
            self.i += word.len();
            Some(v)
        } else {
            None
        }
    }

    fn object(&mut self, depth: usize) -> Option<Value> {
        if depth > MAX_JSON_DEPTH {
            return None;
        }
        self.i += 1;
        let mut map = Map::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Some(Value::Object(map));
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return None;
            }
            let k = self.string()?;
            self.ws();
            if self.peek() != Some(b':') {
                return None;
            }
            self.i += 1;
            let v = self.value(depth)?;
            map.insert(k, v); // duplicate: value replaced, first position kept (as in JS)
            self.ws();
            match self.peek()? {
                b',' => self.i += 1,
                b'}' => {
                    self.i += 1;
                    break;
                }
                _ => return None,
            }
        }
        let ordered = own_property_keys(&map).into_iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        Some(Value::Object(ordered))
    }

    fn array(&mut self, depth: usize) -> Option<Value> {
        if depth > MAX_JSON_DEPTH {
            return None;
        }
        self.i += 1;
        let mut out = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Some(Value::Array(out));
        }
        loop {
            out.push(self.value(depth)?);
            self.ws();
            match self.peek()? {
                b',' => self.i += 1,
                b']' => {
                    self.i += 1;
                    return Some(Value::Array(out));
                }
                _ => return None,
            }
        }
    }

    fn hex4(&mut self) -> Option<u32> {
        let h = self.s.get(self.i..self.i + 4)?;
        if !h.bytes().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        self.i += 4;
        u32::from_str_radix(h, 16).ok()
    }

    fn string(&mut self) -> Option<String> {
        self.i += 1; // opening quote
        let mut out = String::new();
        loop {
            let start = self.i;
            while matches!(self.peek(), Some(c) if c != b'"' && c != b'\\' && c >= 0x20) {
                self.i += 1;
            }
            out.push_str(&self.s[start..self.i]); // stops only on ASCII → char boundary
            match self.peek()? {
                b'"' => {
                    self.i += 1;
                    return Some(out);
                }
                b'\\' => {
                    self.i += 1;
                    let e = self.peek()?;
                    self.i += 1;
                    let c = match e {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{C}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let hi = self.hex4()?;
                            if (0xD800..0xDC00).contains(&hi) {
                                // Needs a following \uDC00-\uDFFF; a lone surrogate is
                                // legal for JSON.parse but not representable here.
                                if self.b.get(self.i..self.i + 2) != Some(b"\\u".as_slice()) {
                                    return None;
                                }
                                self.i += 2;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return None;
                                }
                                char::from_u32(0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00))?
                            } else {
                                char::from_u32(hi)? // None for a lone low surrogate
                            }
                        }
                        _ => return None,
                    };
                    out.push(c);
                }
                _ => return None, // raw control character
            }
        }
    }

    fn number(&mut self) -> Option<Value> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        match self.peek()? {
            b'0' => self.i += 1,
            b'1'..=b'9' => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.i += 1;
                }
            }
            _ => return None,
        }
        if self.peek() == Some(b'.') {
            self.i += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return None;
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.i += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return None;
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.i += 1;
            }
        }
        let x: f64 = self.s[start..self.i].parse().ok()?;
        if !x.is_finite() {
            return None; // JSON.parse yields ±Infinity: not representable (documented)
        }
        Some(js_number_value(x))
    }
}

/// Store an f64 so that `as_f64()` returns it exactly and integral values stay
/// convenient (`as_i64` / `as_u64`). -0 stays a float (falsy, prints "0").
fn js_number_value(x: f64) -> Value {
    const TWO_63: f64 = 9_223_372_036_854_775_808.0;
    const TWO_64: f64 = 18_446_744_073_709_551_616.0;
    if x.fract() == 0.0 && !(x == 0.0 && x.is_sign_negative()) {
        if (0.0..TWO_64).contains(&x) {
            return Value::from(x as u64);
        }
        if (-TWO_63..0.0).contains(&x) {
            return Value::from(x as i64);
        }
    }
    Number::from_f64(x).map(Value::Number).unwrap_or(Value::Null)
}
