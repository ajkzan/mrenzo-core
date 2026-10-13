//! Group Sender Keys — line-for-line port of the RN client (build 324):
//! - `mobile/src/utils/senderKeys.ts` (chain, encrypt/decrypt, at-rest JSON),
//! - `mobile/src/services/senderKeyStore.ts` (SKDM build/ingest, MMKV layout),
//! - `mobile/src/services/senderKeyChannel.ts` (`sk1:` wrapper,
//!   `tryDecryptFromGroup`, `encryptForGroup`).
//!
//! Contract: docs/native/protocol/03-crypto.md §10; conformance:
//! docs/native/vectors/senderKeys.json (tests/golden_sender_keys.rs).
//!
//! Pure logic: storage (MMKV `mrenzo-sender-keys`), the in-memory
//! "already distributed" set and the WS transport are the caller's; every
//! function returns what the TS would have written/sent instead.
//!
//! Faithful to the RN code INCLUDING its quirks — do not "fix" them here:
//! - The chain step is `HMAC-SHA256(ck, 0x02)`; the `"mrenzo-sender-chain"`
//!   constant is dead. Message key = `HKDF(ck, salt ZERO32, "mrenzo-sender-msg")`.
//! - The signature covers `encodeCounter(ctr) || ct` but NOT the nonce, and
//!   `encodeCounter` is lossy for non-integer / non-number / >= 2^64 counters.
//! - No skipped-message keys: any `ctr` below the stored counter is rejected.
//! - The envelope is `JSON.parse(..) as any`, so the TS runs JS coercions on
//!   whatever the wire holds: `ctr` may be a string/null/array and the stored
//!   counter then becomes e.g. `"11"` (string concatenation). [`JsValue`]
//!   models exactly the JS values those code paths can produce.
//! - Several inputs THROW out of `tryDecryptFromGroup` instead of yielding the
//!   placeholder (`sk1:null`, wrong-length `sig`/`n`/`signingPub`, invalid
//!   UTF-8 plaintext). Those are `Err` here, `null` returns are `Ok(None)`.
//! - `encryptForGroup` returns the plaintext UNENCRYPTED when the channel id,
//!   the member list or the self id is empty/zero, and SKDMs (which carry the
//!   chain key) are sent as a plaintext `p2p-message` payload.
//! - Ed25519 verification accepts a non-canonical `S` (`S + k·L`), like
//!   tweetnacl (`compat::ed25519`); base64 ignores non-zero trailing bits,
//!   like tweetnacl-util/atob (`compat::b64`, after ToString — see
//!   `js_decode_base64`).
//!
//! KNOWN DIVERGENCES from RN (none reachable from an honest peer; pinned in
//! `tests/golden_sender_keys.rs::known_divergences_json_parse_edge_cases`):
//! - `sk1:` bodies, SKDMs and MMKV blobs are parsed with serde_json, not
//!   JSON.parse. Lone-surrogate escapes, numbers that overflow f64 (`1e400`)
//!   and nesting deeper than 128 are rejected (corrupt placeholder) even in
//!   fields the TS never reads. RN decrypts those messages. For
//!   `"ctr":1e400`, RN hangs forever in the ratchet loop. Non-integer
//!   literals may also differ from JSON.parse by 1 ULP (no `float_roundtrip`).
//! - `encrypt_group_message` signs with dalek, which derives the public half
//!   from the seed. tweetnacl hashes `signingPriv[32..]` instead. The two
//!   differ only for a corrupt at-rest sender blob whose halves disagree.
//! - [`JsValue`] coerces with `compat`'s approximations: Number→String
//!   `number_to_string_ties_up` (exact decimal ties round up; JS takes the
//!   even digit), StringToNumber `string_to_number_u128_radix` (`0x…`
//!   literals above 128 bits double-round), and ToString of an object with an
//!   own `toString` key yields "[object Object]" where RN throws.


use serde_json::Value;

use crate::compat::b64::tweetnacl_util_decode_base64;
use crate::compat::ed25519::tweetnacl_sign_detached_verify;
use crate::compat::js_number::{number_to_json_ties_up, number_to_string_ties_up, string_to_number_u128_radix, to_int32};
use crate::compat::js_string::cmp_code_units;
use crate::compat::js_value::to_string_lenient_ties_up;
use crate::compat::json::{json_quote as json_str, stringify_ties_up};
use crate::compat::utf8::tweetnacl_util_encode_utf8;
use crate::primitives::{b64, ed25519_keypair, ed25519_sign, hkdf32, hmac_sha256, secretbox_open, secretbox_seal};
use crate::rng::Rng;

pub const CHAIN_KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
/// `MSG_KEY_INFO` — HKDF info for the per-message key.
pub const MSG_KEY_INFO: &str = "mrenzo-sender-msg";
/// `RATCHET_INFO` — declared in senderKeys.ts but NEVER used by the derivation.
pub const RATCHET_INFO_UNUSED: &str = "mrenzo-sender-chain";
/// senderKeyChannel.ts `ENVELOPE_PREFIX`.
/// `sk2:` + JSON (build 349; `sk1:` posts are rejected).
pub const ENVELOPE_PREFIX: &str = "sk2:";
/// Domain label of the `sk2` signature: `"mrenzo-sk2|" + groupId + "|" + senderUid + "|" ‖ BE64(ctr) ‖ ct`.
pub const SK2_LABEL: &str = "mrenzo-sk2";
/// SKDM / envelope version.
pub const SK_VERSION: f64 = 2.0;

/// Who a group post is attributed to: the channel it arrived in and the
/// server-stamped sender. Both are covered by the `sk2` signature, so a post
/// re-sent under another sender or into another group fails verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SkContext<'a> {
    pub group_id: &'a str,
    pub sender_uid: i64,
}

/// The bytes the `sk2` signature covers.
pub fn sk2_signed_payload(ctx: &SkContext<'_>, ctr_be: &[u8; 8], ct: &[u8]) -> Vec<u8> {
    let mut m = format!("{SK2_LABEL}|{}|{}|", ctx.group_id, ctx.sender_uid).into_bytes();
    m.extend_from_slice(ctr_be);
    m.extend_from_slice(ct);
    m
}
/// MMKV instance id (lazyEncryptedMMKV) holding every sender-key blob.
pub const STORAGE_ID: &str = "mrenzo-sender-keys";
/// p2p-message `action` that carries an SKDM.
pub const SKDM_ACTION: &str = "sender-key-distribution";
/// Placeholder for a corrupt / undecryptable `sk1:` message.
pub const PLACEHOLDER_UNDECRYPTABLE: &str = "🔒 (не удалось расшифровать)";
/// Placeholder when no SKDM state exists for (group, sender).
pub const PLACEHOLDER_AWAITING_KEY: &str = "🔒 (ожидание ключа)";

// ───────────────────────────── JS value model ─────────────────────────────

/// The JS value a TS `counter: number` / envelope field actually holds.
///
/// The counter is typed `number`, but it is fed from `JSON.parse(..) as any`
/// (wire envelopes, SKDMs, MMKV blobs) and only ever touched with JS operators
/// (`<`, `+ 1`, `++`, `& 0xff`, `||`, template literals), so strings, `null`,
/// `undefined`, `NaN` and JSON arrays/objects all flow through it in the field.
/// Honest RN peers only ever produce `Number(0.0, 1.0, 2.0, …)`.
#[derive(Clone, Debug)]
pub enum JsValue {
    Undefined,
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    /// A JSON array or object, exactly as `JSON.parse` produced it.
    Compound(Value),
}

impl PartialEq for JsValue {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (JsValue::Undefined, JsValue::Undefined) | (JsValue::Null, JsValue::Null) => true,
            (JsValue::Bool(a), JsValue::Bool(b)) => a == b,
            (JsValue::Number(a), JsValue::Number(b)) => a == b || (a.is_nan() && b.is_nan()),
            (JsValue::String(a), JsValue::String(b)) => a == b,
            (JsValue::Compound(a), JsValue::Compound(b)) => a == b,
            _ => false,
        }
    }
}

impl From<f64> for JsValue {
    fn from(n: f64) -> Self {
        JsValue::Number(n)
    }
}

impl From<u64> for JsValue {
    fn from(n: u64) -> Self {
        JsValue::Number(n as f64)
    }
}

impl JsValue {
    /// A property read on a `JSON.parse` result (`None` = absent = `undefined`).
    pub fn from_json(v: Option<&Value>) -> JsValue {
        match v {
            None => JsValue::Undefined,
            Some(Value::Null) => JsValue::Null,
            Some(Value::Bool(b)) => JsValue::Bool(*b),
            Some(Value::Number(n)) => JsValue::Number(n.as_f64().unwrap_or(f64::NAN)),
            Some(Value::String(s)) => JsValue::String(s.clone()),
            Some(c) => JsValue::Compound(c.clone()),
        }
    }

    /// `JSON.stringify(x)` as a property value; `None` = `undefined` (key omitted).
    pub fn to_json_text(&self) -> Option<String> {
        match self {
            JsValue::Undefined => None,
            JsValue::Null => Some("null".into()),
            JsValue::Bool(b) => Some(b.to_string()),
            JsValue::Number(n) => Some(number_to_json_ties_up(*n)),
            JsValue::String(s) => Some(json_str(s)),
            JsValue::Compound(v) => Some(stringify_ties_up(v)),
        }
    }

    /// `String(x)` / template-literal interpolation.
    pub fn to_js_string(&self) -> String {
        match self {
            JsValue::Undefined => "undefined".into(),
            JsValue::Null => "null".into(),
            JsValue::Bool(b) => b.to_string(),
            JsValue::Number(n) => number_to_string_ties_up(*n),
            JsValue::String(s) => s.clone(),
            JsValue::Compound(v) => to_string_lenient_ties_up(v),
        }
    }

    /// `Number(x)` (ToNumber; objects go through ToPrimitive → string).
    pub fn to_number(&self) -> f64 {
        match self {
            JsValue::Undefined => f64::NAN,
            JsValue::Null => 0.0,
            JsValue::Bool(b) => {
                if *b {
                    1.0
                } else {
                    0.0
                }
            }
            JsValue::Number(n) => *n,
            JsValue::String(s) => string_to_number_u128_radix(s),
            // Always through the string form (as before the compat move), so a
            // hand-built `Compound(null/bool)` keeps its old NaN rather than
            // taking the scalar ToNumber.
            JsValue::Compound(v) => string_to_number_u128_radix(&to_string_lenient_ties_up(v)),
        }
    }

    /// JS truthiness (`!x`, `x || y`, `x ? a : b`).
    pub fn truthy(&self) -> bool {
        match self {
            JsValue::Undefined | JsValue::Null => false,
            JsValue::Bool(b) => *b,
            JsValue::Number(n) => !(*n == 0.0 || n.is_nan()),
            JsValue::String(s) => !s.is_empty(),
            JsValue::Compound(_) => true,
        }
    }

    /// ToPrimitive: arrays/objects become their string form (valueOf is not primitive).
    fn to_primitive(&self) -> JsValue {
        match self {
            JsValue::Compound(v) => JsValue::String(to_string_lenient_ties_up(v)),
            other => other.clone(),
        }
    }

    /// `a < b` (Abstract Relational Comparison; `undefined` result → false).
    pub fn js_lt(&self, other: &JsValue) -> bool {
        let (pa, pb) = (self.to_primitive(), other.to_primitive());
        if let (JsValue::String(a), JsValue::String(b)) = (&pa, &pb) {
            return cmp_code_units(a, b).is_lt();
        }
        pa.to_number() < pb.to_number()
    }

    /// `x + 1`: string concatenation when x's primitive is a string.
    pub fn js_plus_one(&self) -> JsValue {
        match self.to_primitive() {
            JsValue::String(s) => JsValue::String(format!("{s}1")),
            p => JsValue::Number(p.to_number() + 1.0),
        }
    }

    /// `x === 1`.
    fn is_version(&self) -> bool {
        matches!(self, JsValue::Number(n) if *n == SK_VERSION)
    }
}

/// `obj.key` on a `JSON.parse` result. Reading a property of `null` throws a
/// TypeError; primitives/arrays simply have no such property (`undefined`).
pub(crate) fn prop(obj: &Value, key: &'static str) -> Result<JsValue, SenderKeyError> {
    match obj {
        Value::Null => Err(SenderKeyError::NullPropertyRead(key)),
        Value::Object(m) => Ok(JsValue::from_json(m.get(key))),
        _ => Ok(JsValue::Undefined),
    }
}

/// tweetnacl-util `decodeBase64(x)`: `validateBase64` runs its regex on
/// `String(x)`, then `atob` decodes it (`compat::b64`: non-zero trailing
/// bits are IGNORED, "AB==" → 00). `None` = the TS throws.
pub(crate) fn js_decode_base64(x: &JsValue) -> Option<Vec<u8>> {
    tweetnacl_util_decode_base64(&x.to_js_string())
}

/// tweetnacl `nacl.sign.detached.verify` once the size checks have passed
/// (`compat::ed25519`): S is used unreduced, so every `S + k·L` that fits in
/// 32 bytes verifies wherever S does (a path adversary can re-encode any
/// signature 15 ways).
pub(crate) fn tweetnacl_verify(public: &[u8; 32], msg: &[u8], sig: &[u8]) -> bool {
    // Every caller checks the size first; a wrong size is simply not a signature.
    let Ok(sig): Result<&[u8; 64], _> = sig.try_into() else { return false };
    tweetnacl_sign_detached_verify(msg, sig, public)
}

// ───────────────────────────── errors ─────────────────────────────

/// Everything the TS code THROWS (as opposed to returning `null`).
/// `Display` is the JS message (V8 wording for engine-generated TypeErrors).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SenderKeyError {
    /// encryptGroupMessage on a state whose signingPriv is not 64 bytes.
    EncryptNeedsSigningKey,
    /// buildSKDM on a verify-only (recipient) state.
    SkdmNeedsSigningKey,
    /// ingestSKDM `payload.v !== 1`; carries `String(payload.v)`.
    SkdmUnsupportedVersion(String),
    SkdmMissingFields,
    SkdmInvalidBase64,
    SkdmKeyLengthMismatch,
    /// tweetnacl `sign.detached.verify`: signature is not 64 bytes.
    BadSignatureSize,
    /// tweetnacl `sign.detached.verify`: signing public key is not 32 bytes.
    BadPublicKeySize,
    /// tweetnacl `secretbox.open`: nonce is not 24 bytes.
    BadNonceSize,
    /// tweetnacl-util `encodeUTF8` → `URIError` on non-UTF-8 plaintext.
    MalformedUtf8,
    /// TypeError: property read on `null` (e.g. wire `sk1:null`).
    NullPropertyRead(&'static str),
    /// tweetnacl-util `decodeBase64` TypeError (only escapes from deserialise).
    InvalidEncoding,
    /// `JSON.parse` SyntaxError (only escapes from deserialise).
    JsonSyntax,
}

impl SenderKeyError {
    /// The JS error class the TS would throw.
    pub fn js_class(&self) -> &'static str {
        match self {
            SenderKeyError::MalformedUtf8 => "URIError",
            SenderKeyError::NullPropertyRead(_) | SenderKeyError::InvalidEncoding => "TypeError",
            SenderKeyError::JsonSyntax => "SyntaxError",
            _ => "Error",
        }
    }
}

impl std::fmt::Display for SenderKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SenderKeyError::EncryptNeedsSigningKey => {
                write!(f, "encryptGroupMessage requires the signing private key (sender, not recipient)")
            }
            SenderKeyError::SkdmNeedsSigningKey => {
                write!(f, "buildSKDM requires the SIGNING privateKey — only senders create SKDMs")
            }
            SenderKeyError::SkdmUnsupportedVersion(v) => write!(f, "unsupported SKDM version {v}"),
            SenderKeyError::SkdmMissingFields => write!(f, "SKDM missing required fields"),
            SenderKeyError::SkdmInvalidBase64 => write!(f, "SKDM has invalid base64"),
            SenderKeyError::SkdmKeyLengthMismatch => write!(f, "SKDM key length mismatch"),
            SenderKeyError::BadSignatureSize => write!(f, "bad signature size"),
            SenderKeyError::BadPublicKeySize => write!(f, "bad public key size"),
            SenderKeyError::BadNonceSize => write!(f, "bad nonce size"),
            SenderKeyError::MalformedUtf8 => write!(f, "URI malformed"),
            SenderKeyError::NullPropertyRead(k) => write!(f, "Cannot read properties of null (reading '{k}')"),
            SenderKeyError::InvalidEncoding => write!(f, "invalid encoding"),
            SenderKeyError::JsonSyntax => write!(f, "JSON.parse: syntax error"),
        }
    }
}

// ───────────────────────────── state + envelope ─────────────────────────────

/// `SenderKeyState`. Byte fields are `Vec` because the at-rest importer
/// (`deserialiseSenderKey`) accepts any decoded length, exactly like the TS.
#[derive(Clone, Debug, PartialEq)]
pub struct SenderKeyState {
    /// 32 bytes in every state this module creates.
    pub chain_key: Vec<u8>,
    /// Ed25519 verifying key (32 bytes).
    pub signing_pub: Vec<u8>,
    /// tweetnacl 64-byte `seed || pub` for the sender; EMPTY for recipients.
    pub signing_priv: Vec<u8>,
    pub counter: JsValue,
}

/// `SenderKeyEnvelope` as produced by `encryptGroupMessage` (`v` is always 1).
#[derive(Clone, Debug, PartialEq)]
pub struct SenderKeyEnvelope {
    pub ct: String,
    pub n: String,
    /// The sender's counter at encryption time (a `Number` for honest senders).
    pub ctr: JsValue,
    pub sig: String,
}

impl SenderKeyEnvelope {
    /// `JSON.stringify(envelope)` — key order v, ct, n, ctr, sig (`ctr` is
    /// omitted when undefined, `null` when NaN).
    pub fn to_json(&self) -> String {
        let mut out = String::from("{\"v\":2");
        if let Some(c) = self.ctr.to_json_text() {
            out.push_str(&format!(",\"ctr\":{c}"));
        }
        out.push_str(&format!(",\"n\":{},\"ct\":{},\"sig\":{}}}", json_str(&self.n), json_str(&self.ct), json_str(&self.sig)));
        out
    }

    /// `wrapEnvelope(env)` = `"sk1:" + JSON.stringify(env)` — the channel message text.
    pub fn to_wire(&self) -> String {
        wrap_envelope(self)
    }
}

// ───────────────────────────── utils/senderKeys.ts ─────────────────────────────

/// `generateSenderKey()`: draws the chain key (32) FIRST, then the Ed25519 seed (32).
pub fn generate_sender_key(rng: &mut dyn Rng) -> SenderKeyState {
    let mut chain_key = vec![0u8; CHAIN_KEY_LEN];
    rng.fill(&mut chain_key);
    let (secret64, public) = ed25519_keypair(rng);
    SenderKeyState {
        chain_key,
        signing_pub: public.to_vec(),
        signing_priv: secret64.to_vec(),
        counter: JsValue::Number(0.0),
    }
}

/// `buildRecipientSenderKey(chainKey, signingPub, startCounter = 0)`:
/// verify-only state. `JsValue::Undefined` takes the default 0.
pub fn build_recipient_sender_key(chain_key: Vec<u8>, signing_pub: Vec<u8>, start_counter: JsValue) -> SenderKeyState {
    let counter = match start_counter {
        JsValue::Undefined => JsValue::Number(0.0),
        c => c,
    };
    SenderKeyState { chain_key, signing_pub, signing_priv: Vec::new(), counter }
}

/// `ratchetSenderKey(sck)` = `HMAC-SHA256(key = sck, msg = 0x02)`.
pub fn ratchet_sender_key(sck: &[u8]) -> [u8; 32] {
    hmac_sha256(sck, &[0x02])
}

/// `deriveMessageKey(sck)` = `HKDF-SHA256(ikm = sck, salt = ZERO32, "mrenzo-sender-msg", 32)`.
pub fn derive_message_key(sck: &[u8]) -> [u8; 32] {
    hkdf32(sck, MSG_KEY_INFO.as_bytes())
}

/// `encodeCounter(n)`: "8-byte big-endian", computed with JS `& 0xff` and
/// `Math.floor(/ 256)` on `Number(n)` — exact BE64 for integers in
/// [0, 2^53], two's complement for negatives, and LOSSY otherwise
/// (`1.5` → be64(1), `NaN`/`undefined`/`"x"` → zeros, `2^64 + k` ≡ `k`).
pub fn encode_counter(n: &JsValue) -> [u8; 8] {
    let mut out = [0u8; 8];
    let mut val = n.to_number();
    for i in (0..8).rev() {
        out[i] = (to_int32(val) & 0xff) as u8;
        val = (val / 256.0).floor();
    }
    out
}

/// `encryptGroupMessage(state, plaintext)`. Draws the 24-byte nonce (only
/// after the signing-key check). Signs `encodeCounter(ctr) || ct`.
pub fn encrypt_group_message(
    state: &SenderKeyState,
    plaintext: &str,
    ctx: &SkContext<'_>,
    rng: &mut dyn Rng,
) -> Result<(SenderKeyState, SenderKeyEnvelope), SenderKeyError> {
    let Ok(secret64) = <[u8; 64]>::try_from(state.signing_priv.as_slice()) else {
        return Err(SenderKeyError::EncryptNeedsSigningKey);
    };
    let message_key = derive_message_key(&state.chain_key);
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill(&mut nonce);
    let ct = secretbox_seal(plaintext.as_bytes(), &nonce, &message_key);

    let signed_payload = sk2_signed_payload(ctx, &encode_counter(&state.counter), &ct);
    // NOTE: tweetnacl hashes secret64[32..] as the public key; ed25519_sign
    // re-derives it from the seed. Identical for every keypair tweetnacl made.
    let signature = ed25519_sign(&secret64, &signed_payload);

    let envelope = SenderKeyEnvelope { ct: b64(&ct), n: b64(&nonce), ctr: state.counter.clone(), sig: b64(&signature) };
    let next = SenderKeyState {
        chain_key: ratchet_sender_key(&state.chain_key).to_vec(),
        signing_pub: state.signing_pub.clone(),
        signing_priv: state.signing_priv.clone(),
        counter: state.counter.js_plus_one(),
    };
    Ok((next, envelope))
}

/// `decryptGroupMessage(state, env)` where `env` is whatever `JSON.parse`
/// returned. `Ok(None)` = the TS returns `null`; `Err` = the TS throws.
///
/// Walks the chain from `state.counter` up to `env.ctr` (no skipped-key
/// store). The walk is bounded by [`MAX_DECRYPT_WALK`] steps: the RN code had
/// no bound, so a far-future `ctr` — or a counter at 2^53, where `i + 1 == i`
/// — made it loop for ever; the callers in `group_chains` already refuse such
/// envelopes, and the bound here makes that a property of this function.
pub fn decrypt_group_message(
    state: &SenderKeyState,
    env: &Value,
    ctx: &SkContext<'_>,
) -> Result<Option<(SenderKeyState, String)>, SenderKeyError> {
    Ok(decrypt_group_message_keyed(state, env, ctx)?.map(|(next, plaintext, _)| (next, plaintext)))
}

/// Most chain steps one envelope may ask for (= `group_chains::MAX_CHAIN_WALK`).
pub const MAX_DECRYPT_WALK: u32 = 2000;

/// [`decrypt_group_message`] that also returns the message key the envelope
/// opened under (the post reaction key is derived from it, wire-1.1 §W7.4).
pub fn decrypt_group_message_keyed(
    state: &SenderKeyState,
    env: &Value,
    ctx: &SkContext<'_>,
) -> Result<Option<(SenderKeyState, String, [u8; 32])>, SenderKeyError> {
    if !prop(env, "v")?.is_version() {
        return Ok(None);
    }
    // Past the `v === 1` gate `env` is a JSON object: property reads cannot throw.
    let (Some(signature), Some(ct), Some(nonce)) = (
        js_decode_base64(&prop(env, "sig")?),
        js_decode_base64(&prop(env, "ct")?),
        js_decode_base64(&prop(env, "n")?),
    ) else {
        return Ok(None);
    };
    let ctr = prop(env, "ctr")?;

    let signed_payload = sk2_signed_payload(ctx, &encode_counter(&ctr), &ct);
    if signature.len() != 64 {
        return Err(SenderKeyError::BadSignatureSize);
    }
    let signing_pub: [u8; 32] = state.signing_pub.as_slice().try_into().map_err(|_| SenderKeyError::BadPublicKeySize)?;
    if !tweetnacl_verify(&signing_pub, &signed_payload, &signature) {
        return Ok(None);
    }

    if ctr.js_lt(&state.counter) {
        return Ok(None);
    }
    let mut chain_key = state.chain_key.clone();
    let mut i = state.counter.clone();
    let mut walked = 0u32;
    while i.js_lt(&ctr) {
        walked += 1;
        if walked > MAX_DECRYPT_WALK {
            return Ok(None);
        }
        chain_key = ratchet_sender_key(&chain_key).to_vec();
        i = JsValue::Number(i.to_number() + 1.0);
    }

    let message_key = derive_message_key(&chain_key);
    let nonce: [u8; NONCE_LEN] = nonce.as_slice().try_into().map_err(|_| SenderKeyError::BadNonceSize)?;
    let Some(opened) = secretbox_open(&ct, &nonce, &message_key) else {
        return Ok(None);
    };

    let next = SenderKeyState {
        chain_key: ratchet_sender_key(&chain_key).to_vec(),
        signing_pub: state.signing_pub.clone(),
        signing_priv: state.signing_priv.clone(),
        counter: ctr.js_plus_one(),
    };
    let plaintext = tweetnacl_util_encode_utf8(opened).ok_or(SenderKeyError::MalformedUtf8)?;
    Ok(Some((next, plaintext, message_key)))
}

/// `serialiseSenderKey(state)` — the MMKV blob (`sender:<g>` / `recv:<g>:<uid>`):
/// `{"chainKey":b64,"signingPub":b64,"signingPriv":b64|"","counter":…}`.
pub fn serialise_sender_key(state: &SenderKeyState) -> String {
    let priv_b64 = if state.signing_priv.is_empty() { String::new() } else { b64(&state.signing_priv) };
    let mut out = format!(
        "{{\"chainKey\":{},\"signingPub\":{},\"signingPriv\":{}",
        json_str(&b64(&state.chain_key)),
        json_str(&b64(&state.signing_pub)),
        json_str(&priv_b64)
    );
    if let Some(c) = state.counter.to_json_text() {
        out.push_str(&format!(",\"counter\":{c}"));
    }
    out.push('}');
    out
}

/// `deserialiseSenderKey(json)` — imports an RN MMKV blob. No length checks
/// (like the TS); a falsy `signingPriv` yields an empty (verify-only) key.
pub fn deserialise_sender_key(json: &str) -> Result<SenderKeyState, SenderKeyError> {
    let o: Value = serde_json::from_str(json).map_err(|_| SenderKeyError::JsonSyntax)?;
    let chain_key = js_decode_base64(&prop(&o, "chainKey")?).ok_or(SenderKeyError::InvalidEncoding)?;
    let signing_pub = js_decode_base64(&prop(&o, "signingPub")?).ok_or(SenderKeyError::InvalidEncoding)?;
    let priv_v = prop(&o, "signingPriv")?;
    let signing_priv =
        if priv_v.truthy() { js_decode_base64(&priv_v).ok_or(SenderKeyError::InvalidEncoding)? } else { Vec::new() };
    let counter = prop(&o, "counter")?;
    Ok(SenderKeyState { chain_key, signing_pub, signing_priv, counter })
}

// ───────────────────────────── services/senderKeyStore.ts ─────────────────────────────

/// `KEY_SENDER(groupId)` — our outgoing state.
pub fn storage_key_sender(group_id: &str) -> String {
    format!("sender:{group_id}")
}

/// `KEY_RECV(groupId, senderUserId)` — state built from that sender's SKDM.
pub fn storage_key_recv(group_id: &str, sender_user_id: i64) -> String {
    format!("recv:{group_id}:{sender_user_id}")
}

/// `getIncomingSenderKey` minus the MMKV read: `raw` is `storage.getString(..)`.
/// Missing/empty/corrupt blob → `None`.
pub fn load_incoming_sender_key(raw: Option<&str>) -> Option<SenderKeyState> {
    match raw {
        Some(r) if !r.is_empty() => deserialise_sender_key(r).ok(),
        _ => None,
    }
}

/// `getOrCreateOutgoingSenderKey` minus the MMKV I/O. `raw` is the stored
/// `sender:<g>` blob. Returns the state and, when a fresh one was generated
/// (missing or corrupt blob; draws 64 bytes), the blob the TS persists
/// immediately under `sender:<g>`.
pub fn get_or_create_outgoing_sender_key(raw: Option<&str>, rng: &mut dyn Rng) -> (SenderKeyState, Option<String>) {
    if let Some(r) = raw.filter(|r| !r.is_empty()) {
        if let Ok(state) = deserialise_sender_key(r) {
            return (state, None);
        }
    }
    let fresh = generate_sender_key(rng);
    let blob = serialise_sender_key(&fresh);
    (fresh, Some(blob))
}

/// `SKDM` payload (`v` is always 1).
#[derive(Clone, Debug, PartialEq)]
pub struct Skdm {
    pub group_id: String,
    /// b64 32-byte chain key — the CURRENT chain key, not the initial one.
    pub chain_key: String,
    pub signing_pub: String,
    /// The sender's current counter (`state.counter`, any JS value).
    pub start_counter: JsValue,
    /// The sender's uid (must equal the server-stamped sender, 03 §10).
    pub from: i64,
}

impl Skdm {
    /// `JSON.stringify(skdm)`: key order v, groupId, chainKey, signingPub, startCounter.
    pub fn to_json(&self) -> String {
        let mut out = format!(
            "{{\"v\":2,\"groupId\":{},\"chainKey\":{},\"signingPub\":{}",
            json_str(&self.group_id),
            json_str(&self.chain_key),
            json_str(&self.signing_pub)
        );
        if let Some(c) = self.start_counter.to_json_text() {
            out.push_str(&format!(",\"startCounter\":{c}"));
        }
        out.push_str(&format!(",\"from\":{}}}", self.from));
        out
    }
}

/// `buildSKDM(groupId, state)`; throws for verify-only states (empty signingPriv only).
pub fn build_skdm(group_id: &str, state: &SenderKeyState, from: i64) -> Result<Skdm, SenderKeyError> {
    if state.signing_priv.is_empty() {
        return Err(SenderKeyError::SkdmNeedsSigningKey);
    }
    Ok(Skdm {
        group_id: group_id.to_string(),
        chain_key: b64(&state.chain_key),
        signing_pub: b64(&state.signing_pub),
        start_counter: state.counter.clone(),
        from,
    })
}

// ───────────────────────────── services/senderKeyChannel.ts ─────────────────────────────

/// `unwrapEnvelope(raw)`.
#[derive(Clone, Debug, PartialEq)]
pub enum Unwrapped {
    /// No `sk1:` prefix: legacy plaintext.
    Plain,
    /// Prefix + JSON.parse succeeded (ANY JSON value, not necessarily an object).
    Envelope(Value),
    /// Prefix present but JSON.parse threw.
    Corrupt,
}

/// `wrapEnvelope(env)` = `"sk1:" + JSON.stringify(env)`.
pub fn wrap_envelope(env: &SenderKeyEnvelope) -> String {
    format!("{ENVELOPE_PREFIX}{}", env.to_json())
}

/// `unwrapEnvelope(raw)` (case-sensitive prefix; JSON.parse of the rest).
pub fn unwrap_envelope(raw: &str) -> Unwrapped {
    let Some(body) = raw.strip_prefix(ENVELOPE_PREFIX) else {
        return Unwrapped::Plain;
    };
    match serde_json::from_str::<Value>(body) {
        Ok(v) => Unwrapped::Envelope(v),
        Err(_) => Unwrapped::Corrupt,
    }
}

