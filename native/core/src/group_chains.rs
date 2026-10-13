//! Group Sender Keys — build-325 semantics on top of the build-324 primitives
//! in [`crate::sender_keys`] (which stay untouched and pinned by
//! `senderKeys.json`). Port of the RN client's group sender-key code:
//! - `services/senderKeyStore.ts` — chain sets (`recv:` + `recvprev:`),
//!   `ingestSKDM` rules, the `sender-v2:` outgoing-chain gate;
//! - `services/senderKeyChannel.ts` — `openWithChains` (walk bound, per-sender
//!   walk budget charged only after the signature verifies, size exceptions
//!   → failure), `tryDecryptFromGroup`, `receiveGroupMessages` (counter order,
//!   failed-walk memo), `encryptForGroup` (SKDM snapshot at the message
//!   counter, 4000-byte refusal before the chain advances).
//!
//! Conformance: docs/native/vectors/senderKeysV2.json
//! (tests/golden_sender_keys_v2.rs), produced by running the 325 TypeScript.
//!
//! Pure logic: MMKV-equivalent storage, the plaintext cache and the
//! transport are the caller's. Every function takes the stored strings and
//! returns what the TS would have written.
//!
//! Deliberate difference from `sender_keys::encrypt_for_group` (324): there is
//! no "empty member list → return the plaintext" path here. Encryption never
//! yields plaintext; a caller without a member list must fail closed.

use std::collections::HashMap;

use serde_json::Value;

use crate::compat::json::json_quote;
use crate::primitives::{b64, secretbox_open, sha256};
use crate::rng::Rng;
use crate::compat::utf8::tweetnacl_util_encode_utf8;
use crate::reactions::post_reaction_key;
use crate::sender_keys::{
    build_recipient_sender_key, build_skdm, decrypt_group_message_keyed, derive_message_key, deserialise_sender_key,
    encrypt_group_message, generate_sender_key, js_decode_base64, prop, ratchet_sender_key, serialise_sender_key,
    sk2_signed_payload, tweetnacl_verify, unwrap_envelope, wrap_envelope, JsValue, SenderKeyError, SenderKeyState, SkContext,
    Skdm, Unwrapped, NONCE_LEN, PLACEHOLDER_AWAITING_KEY, PLACEHOLDER_UNDECRYPTABLE,
};

/// senderKeyStore.ts `MAX_CHAIN_WALK`.
pub const MAX_CHAIN_WALK: f64 = 2000.0;
/// senderKeyStore.ts `MAX_PREVIOUS_CHAINS`.
pub const MAX_PREVIOUS_CHAINS: usize = 3;
/// senderKeyChannel.ts `FREE_WALK_STEPS` — walks up to this are not charged.
pub const FREE_WALK_STEPS: f64 = 32.0;
/// senderKeyChannel.ts `WALK_BUDGET_PER_SENDER` (per sender, per batch).
pub const WALK_BUDGET_PER_SENDER: f64 = 2.0 * MAX_CHAIN_WALK;
/// senderKeyChannel.ts `MAX_GROUP_WIRE_BYTES` (server limit on channel text).
pub const MAX_GROUP_WIRE_BYTES: usize = 4000;
/// senderKeyChannel.ts `TOO_LONG_CODE`.
pub const TOO_LONG_CODE: &str = "GROUP_MESSAGE_TOO_LONG";
/// `Number.MAX_SAFE_INTEGER`.
const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

fn is_safe_integer(n: f64) -> bool {
    n.is_finite() && n.trunc() == n && n.abs() <= MAX_SAFE_INTEGER
}

// ───────────────────────────── storage keys ─────────────────────────────

/// `KEY_SENDER_V2(groupId)` — tag of the last outgoing blob build ≥325 wrote.
pub fn storage_key_sender_v2(group_id: &str) -> String {
    format!("sender-v2:{group_id}")
}

/// `KEY_RECV_PREV(groupId, senderUserId)` — previous chains, newest first.
pub fn storage_key_recv_prev(group_id: &str, sender_user_id: i64) -> String {
    format!("recvprev:{group_id}:{sender_user_id}")
}

/// `forgetGroup` (325): keys to delete — `sender:<g>`, `sender-v2:<g>`,
/// `ptidx:<g>`, then every key of `all_keys` starting with `recv:<g>:`,
/// `recvprev:<g>:`, `recvskip:<g>:` (native skipped keys), `pt:<g>:` or
/// `ptfail:<g>:`.
pub fn forget_group_keys_v2<'a>(group_id: &str, all_keys: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let prefixes = [
        format!("recv:{group_id}:"),
        format!("recvprev:{group_id}:"),
        format!("recvskip:{group_id}:"),
        format!("pt:{group_id}:"),
        format!("ptfail:{group_id}:"),
    ];
    let mut out = vec![format!("sender:{group_id}"), storage_key_sender_v2(group_id), format!("ptidx:{group_id}")];
    out.extend(all_keys.into_iter().filter(|k| prefixes.iter().any(|p| k.starts_with(p.as_str()))).map(str::to_string));
    out
}

// ───────────────────────────── outgoing chain ─────────────────────────────

/// `blobTag(blob)` = first 32 hex chars of SHA-256(UTF-8 blob).
pub fn blob_tag(blob: &str) -> String {
    let h = sha256(blob.as_bytes());
    h[..16].iter().map(|b| format!("{b:02x}")).collect()
}

/// `getOutgoingSenderKey`: the stored `sender:<g>` chain, only when
/// `sender-v2:<g>` holds its tag (a ≤324 build that touched the chain leaked
/// it in a plaintext SKDM, so it reads as absent).
pub fn load_outgoing(blob: Option<&str>, tag: Option<&str>) -> Option<SenderKeyState> {
    let raw = blob.filter(|b| !b.is_empty())?;
    if tag != Some(blob_tag(raw).as_str()) {
        return None;
    }
    deserialise_sender_key(raw).ok()
}

/// `writeOutgoing`: `(sender:<g> blob, sender-v2:<g> tag)`.
pub fn store_outgoing(state: &SenderKeyState) -> (String, String) {
    let blob = serialise_sender_key(state);
    let tag = blob_tag(&blob);
    (blob, tag)
}

/// `getOrCreateOutgoingSenderKey`: the usable stored chain, or a fresh one
/// (64 bytes drawn) plus the `(blob, tag)` the TS persists right away.
pub fn get_or_create_outgoing(
    blob: Option<&str>,
    tag: Option<&str>,
    rng: &mut dyn Rng,
) -> (SenderKeyState, Option<(String, String)>) {
    if let Some(s) = load_outgoing(blob, tag) {
        return (s, None);
    }
    let fresh = generate_sender_key(rng);
    let write = store_outgoing(&fresh);
    (fresh, Some(write))
}

/// Why [`encrypt_outgoing`] refused.
#[derive(Clone, Debug, PartialEq)]
pub enum GroupEncryptError {
    /// `buildSKDM` / `encryptGroupMessage` threw (a verify-only / corrupt state).
    Key(SenderKeyError),
    /// The `sk1:` wire would exceed [`MAX_GROUP_WIRE_BYTES`]; the chain did
    /// NOT advance (the nonce was still drawn, like the TS).
    TooLong { wire_len: usize },
}

/// A successful group encryption.
#[derive(Clone, Debug, PartialEq)]
pub struct OutgoingEncrypted {
    pub wire: String,
    /// The advanced chain: persist it (see [`store_outgoing`]) BEFORE sending.
    pub next: SenderKeyState,
    /// SKDM snapshot at THIS message's counter — what `distributeSKDMIfNeeded`
    /// hands to members that have not been served yet.
    pub skdm: Skdm,
    /// The post reaction key `rk` of this post (wire-1.1 §W7.4): store it
    /// sealed beside the post's cached plaintext.
    pub reaction_key: [u8; 32],
}

/// `rk` of the post the NEXT [`encrypt_outgoing`] on `state` will seal — or,
/// called with the state a post was sealed from, of that post.
pub fn outgoing_reaction_key(state: &SenderKeyState) -> [u8; 32] {
    post_reaction_key(&derive_message_key(&state.chain_key))
}

/// The version `N` of a text that starts with `sk<N>:` (1..9 decimal digits,
/// no leading zero); `None` for anything else. A post with `N > 2` comes from
/// a newer build: the host shows «обновите приложение», never the
/// undecryptable placeholder (wire-1.1 §W3.6).
pub fn envelope_prefix_version(raw: &str) -> Option<u32> {
    let rest = raw.strip_prefix("sk")?;
    let digits = rest.split(':').next().filter(|d| rest.len() > d.len())?;
    if digits.is_empty() || digits.len() > 9 || digits.starts_with('0') || !digits.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// The version of a post this build cannot read because it is NEWER.
fn newer_version(raw: &str) -> Option<u32> {
    envelope_prefix_version(raw).filter(|v| *v > 2)
}

/// `encryptForGroup` minus distribution/storage: snapshot the SKDM, encrypt,
/// refuse an over-long wire without advancing.
pub fn encrypt_outgoing(
    group_id: &str,
    my_uid: i64,
    state: &SenderKeyState,
    plaintext: &str,
    rng: &mut dyn Rng,
) -> Result<OutgoingEncrypted, GroupEncryptError> {
    let skdm = build_skdm(group_id, state, my_uid).map_err(GroupEncryptError::Key)?;
    let ctx = SkContext { group_id, sender_uid: my_uid };
    let (next, env) = encrypt_group_message(state, plaintext, &ctx, rng).map_err(GroupEncryptError::Key)?;
    let wire = wrap_envelope(&env);
    // Pure ASCII (base64 + JSON digits), so JS `.length` == bytes.
    if wire.len() > MAX_GROUP_WIRE_BYTES {
        return Err(GroupEncryptError::TooLong { wire_len: wire.len() });
    }
    Ok(OutgoingEncrypted { wire, next, skdm, reaction_key: outgoing_reaction_key(state) })
}

// ───────────────────────────── incoming chain sets ─────────────────────────────

/// Every chain held for one (group, sender): `chains[0]` is current, the
/// rest are chains the sender rotated away from, newest first.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct ChainSet {
    pub chains: Vec<SenderKeyState>,
}

/// What `saveIncomingSenderChains` writes. `recvprev: None` = delete that key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainSetWrite {
    pub recv: String,
    pub recvprev: Option<String>,
}

impl ChainSet {
    /// `getIncomingSenderChains` from the stored `recv:` / `recvprev:` strings.
    /// A missing or corrupt current chain means NO chains (previous ignored);
    /// unreadable previous entries are skipped.
    pub fn from_storage(recv: Option<&str>, recvprev: Option<&str>) -> ChainSet {
        let Some(raw) = recv.filter(|r| !r.is_empty()) else { return ChainSet::default() };
        let Ok(current) = deserialise_sender_key(raw) else { return ChainSet::default() };
        let mut chains = vec![current];
        if let Some(prev) = recvprev.filter(|p| !p.is_empty()) {
            if let Ok(Value::Array(blobs)) = serde_json::from_str::<Value>(prev) {
                for b in &blobs {
                    // deserialiseSenderKey(b) runs JSON.parse(String(b)).
                    if let Ok(s) = deserialise_sender_key(&JsValue::from_json(Some(b)).to_js_string()) {
                        chains.push(s);
                    }
                }
            }
        }
        ChainSet { chains }
    }

    /// `saveIncomingSenderChains`: `None` for an empty set (nothing written).
    pub fn to_storage(&self) -> Option<ChainSetWrite> {
        let (current, previous) = self.chains.split_first()?;
        let previous: Vec<String> =
            previous.iter().take(MAX_PREVIOUS_CHAINS).map(|s| json_quote(&serialise_sender_key(s))).collect();
        Some(ChainSetWrite {
            recv: serialise_sender_key(current),
            recvprev: if previous.is_empty() { None } else { Some(format!("[{}]", previous.join(","))) },
        })
    }

    pub fn current(&self) -> Option<&SenderKeyState> {
        self.chains.first()
    }

    pub fn is_empty(&self) -> bool {
        self.chains.is_empty()
    }

    /// `chainSetFingerprint` — the failed-walk memo key.
    pub fn fingerprint(&self) -> String {
        self.chains.iter().map(|c| b64(&c.signing_pub)).collect::<Vec<_>>().join(",")
    }
}

// ───────────────────────────── SKDM ingest ─────────────────────────────

/// `parseSKDMPlaintext`: the plaintext of a ratchet-decrypted SKDM frame, if
/// it is a JSON object (not an array).
pub fn parse_skdm_plaintext(plaintext: &str) -> Option<Value> {
    match serde_json::from_str::<Value>(plaintext) {
        Ok(v @ Value::Object(_)) => Some(v),
        _ => None,
    }
}

/// `ingestSKDM` (325) validation failures; `Display` = the TS message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IngestError {
    UnsupportedVersion(String),
    MissingFields,
    InvalidStartCounter,
    InvalidBase64,
    KeyLengthMismatch,
    /// `from` is not the server-stamped sender of the SKDM.
    FromMismatch,
    /// The signing key already belongs to another sender of this group.
    DuplicateSigningPub,
}

impl std::fmt::Display for IngestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IngestError::UnsupportedVersion(v) => write!(f, "unsupported SKDM version {v}"),
            IngestError::MissingFields => write!(f, "SKDM missing required fields"),
            IngestError::InvalidStartCounter => write!(f, "SKDM has invalid startCounter"),
            IngestError::InvalidBase64 => write!(f, "SKDM has invalid base64"),
            IngestError::KeyLengthMismatch => write!(f, "SKDM key length mismatch"),
            IngestError::FromMismatch => write!(f, "SKDM from mismatch"),
            IngestError::DuplicateSigningPub => write!(f, "SKDM signing key belongs to another sender"),
        }
    }
}

/// A validated SKDM.
#[derive(Clone, Debug, PartialEq)]
pub struct ValidSkdm {
    pub group_id: String,
    pub chain_key: Vec<u8>,
    pub signing_pub: Vec<u8>,
    pub start_counter: f64,
}

/// The validation half of `ingestSKDM`. Load the chain set for
/// (`group_id`, sender) with the result, then call [`ingest_skdm_v2`].
pub fn validate_skdm(payload: &Value, from_uid: i64) -> Result<ValidSkdm, IngestError> {
    let obj = match payload {
        Value::Object(m) => Some(m),
        _ => None,
    };
    let v = JsValue::from_json(obj.and_then(|m| m.get("v")));
    if !matches!(v, JsValue::Number(n) if n == 2.0) {
        return Err(IngestError::UnsupportedVersion(v.to_js_string()));
    }
    if obj.and_then(|m| m.get("from")).and_then(Value::as_i64) != Some(from_uid) {
        return Err(IngestError::FromMismatch);
    }
    // `v == 2` was read from the object, so there is one.
    let Some(obj) = obj else { return Err(IngestError::MissingFields) };
    let str_field = |k: &str| match obj.get(k) {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    };
    let (Some(group_id), Some(chain_key), Some(signing_pub)) =
        (str_field("groupId"), str_field("chainKey"), str_field("signingPub"))
    else {
        return Err(IngestError::MissingFields);
    };
    let start_counter = match obj.get("startCounter") {
        None | Some(Value::Null) => 0.0,
        Some(Value::Number(n)) => n.as_f64().unwrap_or(f64::NAN),
        Some(_) => f64::NAN,
    };
    if !is_safe_integer(start_counter) || start_counter < 0.0 {
        return Err(IngestError::InvalidStartCounter);
    }
    let (Some(chain_key), Some(signing_pub)) = (
        js_decode_base64(&JsValue::String(chain_key)),
        js_decode_base64(&JsValue::String(signing_pub)),
    ) else {
        return Err(IngestError::InvalidBase64);
    };
    if chain_key.len() != 32 || signing_pub.len() != 32 {
        return Err(IngestError::KeyLengthMismatch);
    }
    Ok(ValidSkdm { group_id, chain_key, signing_pub, start_counter })
}

/// Why an SKDM did or did not change the chain set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IngestAction {
    /// First chain for this sender (or the stored one was unreadable).
    Installed,
    /// A new chain: it became current, the old current moved to previous.
    Rotated,
    /// Same chain, but past the walk bound or not matching the copy walked
    /// forward: the SKDM's copy replaced ours (latest wins).
    Replaced,
    /// Same chain, our copy kept (older/equal/matching newer SKDM).
    KeptCurrent,
    /// A chain the sender already rotated away from: ignored.
    IgnoredPrevious,
}

#[derive(Clone, Debug, PartialEq)]
pub struct IngestOutcome {
    pub action: IngestAction,
    /// The state now current for (group, sender) — `ingestSKDM`'s return.
    pub current: SenderKeyState,
    /// The chain set after ingest.
    pub set: ChainSet,
    /// `Some` exactly when the TS calls saveIncomingSenderChains.
    pub write: Option<ChainSetWrite>,
}

fn bytes_equal(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// `keepCurrentCopy(current, chainKey, startCounter)`.
fn keep_current_copy(current: &SenderKeyState, chain_key: &[u8], start: f64) -> bool {
    let cur = current.counter.to_number();
    if start <= cur {
        return true;
    }
    let steps = start - cur;
    if steps > MAX_CHAIN_WALK {
        return false;
    }
    let mut key = current.chain_key.clone();
    let mut i = 0.0;
    while i < steps {
        key = ratchet_sender_key(&key).to_vec();
        i += 1.0;
    }
    bytes_equal(&key, chain_key)
}

/// `ingestSKDM` (325) for an SKDM already validated by [`validate_skdm`],
/// against the chain set stored for (`skdm.group_id`, sender).
pub fn ingest_skdm_v2(set: &ChainSet, skdm: &ValidSkdm) -> IngestOutcome {
    let current = set.chains.first();
    let previous = set.chains.get(1..).unwrap_or(&[]);
    if let Some(cur) = current {
        if previous.iter().any(|c| bytes_equal(&c.signing_pub, &skdm.signing_pub)) {
            return IngestOutcome { action: IngestAction::IgnoredPrevious, current: cur.clone(), set: set.clone(), write: None };
        }
    }
    let same_as_current = current.is_some_and(|c| bytes_equal(&c.signing_pub, &skdm.signing_pub));
    if let Some(cur) = current.filter(|_| same_as_current) {
        if keep_current_copy(cur, &skdm.chain_key, skdm.start_counter) {
            return IngestOutcome { action: IngestAction::KeptCurrent, current: cur.clone(), set: set.clone(), write: None };
        }
    }
    let state = build_recipient_sender_key(
        skdm.chain_key.clone(),
        skdm.signing_pub.clone(),
        JsValue::Number(skdm.start_counter),
    );
    let mut chains = vec![state.clone()];
    let action = match current {
        None => IngestAction::Installed,
        Some(_) if same_as_current => IngestAction::Replaced,
        Some(cur) => {
            chains.push(cur.clone());
            IngestAction::Rotated
        }
    };
    chains.extend(previous.iter().cloned());
    let written = ChainSet { chains };
    let write = written.to_storage();
    // What a reload would see: previous truncated to MAX_PREVIOUS_CHAINS.
    let mut set_after = written;
    set_after.chains.truncate(1 + MAX_PREVIOUS_CHAINS);
    IngestOutcome { action, current: state, set: set_after, write }
}

// ───────────────────────────── decrypt ─────────────────────────────

/// `openWithChains` result.
// Built once per call and consumed at once: the size difference between the cases costs nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq)]
pub enum OpenResult {
    NoState,
    /// `walked`: a verified long walk was spent and it still failed (final
    /// under this chain set). `over_budget`: skipped only for the budget.
    Failed { walked: bool, over_budget: bool },
    /// `state` replaces `chains[index]`; `message_key` = the key the
    /// envelope opened under (the post reaction key comes from it).
    Opened { plaintext: String, state: SenderKeyState, index: usize, message_key: [u8; 32] },
}

/// Ed25519 over be64(ctr) ‖ ct under `state.signing_pub` (`signatureMatches`);
/// any size problem is `false`. `ctr` is a non-negative safe integer here.
fn signature_matches(state: &SenderKeyState, env: &Value, ctr: f64, ctx: &SkContext<'_>) -> bool {
    let (Ok(ct_v), Ok(sig_v)) = (prop(env, "ct"), prop(env, "sig")) else { return false };
    let (Some(ct), Some(sig)) = (js_decode_base64(&ct_v), js_decode_base64(&sig_v)) else { return false };
    let Ok(public): Result<[u8; 32], _> = state.signing_pub.as_slice().try_into() else { return false };
    if sig.len() != 64 {
        return false;
    }
    let signed = sk2_signed_payload(ctx, &(ctr as u64).to_be_bytes(), &ct);
    tweetnacl_verify(&public, &signed, &sig)
}

/// `openWithChains(chains, env, budget)`. Pure; `budget` (steps left for
/// this sender in this batch) is decremented for verified long walks.
pub fn open_with_chains(set: &ChainSet, env: &Value, mut budget: Option<&mut f64>, ctx: &SkContext<'_>) -> OpenResult {
    if set.chains.is_empty() {
        return OpenResult::NoState;
    }
    let ctr = match env {
        Value::Object(m) => match m.get("ctr") {
            Some(Value::Number(n)) => n.as_f64().unwrap_or(f64::NAN),
            _ => f64::NAN,
        },
        _ => f64::NAN,
    };
    if !is_safe_integer(ctr) || ctr < 0.0 {
        return OpenResult::Failed { walked: false, over_budget: false };
    }
    let (mut walked, mut over_budget) = (false, false);
    for (i, state) in set.chains.iter().enumerate() {
        let steps = ctr - state.counter.to_number();
        if steps > MAX_CHAIN_WALK {
            continue;
        }
        if let Some(left) = budget.as_deref_mut() {
            if steps > FREE_WALK_STEPS {
                if !signature_matches(state, env, ctr, ctx) {
                    continue;
                }
                if steps > *left {
                    over_budget = true;
                    continue;
                }
                *left -= steps;
                walked = true;
            }
        }
        if let Ok(Some((next, plaintext, message_key))) = decrypt_group_message_keyed(state, env, ctx) {
            return OpenResult::Opened { plaintext, state: next, index: i, message_key };
        }
    }
    OpenResult::Failed { walked, over_budget }
}

/// Which branch `tryDecryptFromGroup` took.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupDecryptKind {
    /// No `sk1:` prefix: legacy plaintext, shown verbatim.
    Plain,
    /// `sk1:` + unparseable JSON.
    Corrupt,
    /// No chain from this sender yet ("ожидание ключа").
    AwaitingKey,
    /// Not openable under any chain held.
    Failed,
    Opened,
}

#[derive(Clone, Debug, PartialEq)]
pub struct GroupDecrypt {
    pub kind: GroupDecryptKind,
    /// What to display (plaintext, the raw legacy text or a placeholder).
    pub text: String,
    /// `false` only for [`GroupDecryptKind::Plain`].
    pub encrypted: bool,
    /// `Some` when the chain advanced — persist it.
    pub write: Option<ChainSetWrite>,
    pub set: ChainSet,
}

/// `tryDecryptFromGroup(channelId, senderId, raw)` (325): stateful single
/// decrypt against the sender's chain set, no walk budget.
pub fn decrypt_with_chains(set: &ChainSet, raw: &str, ctx: &SkContext<'_>) -> GroupDecrypt {
    let done = |kind, text: &str, encrypted| GroupDecrypt { kind, text: text.to_string(), encrypted, write: None, set: set.clone() };
    let env = match unwrap_envelope(raw) {
        Unwrapped::Plain => return done(GroupDecryptKind::Plain, PLACEHOLDER_UNDECRYPTABLE, true),
        Unwrapped::Corrupt => return done(GroupDecryptKind::Corrupt, PLACEHOLDER_UNDECRYPTABLE, true),
        Unwrapped::Envelope(env) => env,
    };
    match open_with_chains(set, &env, None, ctx) {
        OpenResult::NoState => done(GroupDecryptKind::AwaitingKey, PLACEHOLDER_AWAITING_KEY, true),
        OpenResult::Failed { .. } => done(GroupDecryptKind::Failed, PLACEHOLDER_UNDECRYPTABLE, true),
        OpenResult::Opened { plaintext, state, index, .. } => {
            let mut next = set.clone();
            next.chains[index] = state;
            let write = next.to_storage();
            GroupDecrypt { kind: GroupDecryptKind::Opened, text: plaintext, encrypted: true, write, set: next }
        }
    }
}

// ───────────────────────────── batch receive ─────────────────────────────

/// One message handed to [`receive_batch`] (the caller has already looked
/// up its plaintext cache and failed-walk memo).
#[derive(Clone, Debug, PartialEq)]
pub struct BatchItem {
    pub sender_id: i64,
    /// `m.e2eRaw ?? m.text`.
    pub raw: String,
    /// `m.type === 'system'`.
    pub is_system: bool,
    /// `getGroupPlaintext(channelId, m.id, m.senderId)`.
    pub cached_plaintext: Option<String>,
    /// `getGroupDecryptFailure(channelId, m.id, m.senderId)`.
    pub failed_under: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum BatchItemResult {
    /// Shown as-is (system row or legacy plaintext).
    Unchanged,
    /// From the plaintext cache.
    Cached(String),
    /// Opened now: store the plaintext (`saveGroupPlaintexts`) BEFORE the chain writes.
    Opened(String),
    /// Final placeholder (corrupt envelope, or our own envelope without a
    /// cached plaintext); `e2eRaw` is dropped.
    Placeholder(String),
    /// Placeholder and keep the raw envelope for a retry (`e2eRaw` set).
    /// `memo_fingerprint`: persist it as this message's failed-walk memo.
    Pending { text: String, memo_fingerprint: Option<String> },
}

#[derive(Clone, Debug, PartialEq)]
pub struct BatchOutcome {
    /// One per input item, in input order.
    pub results: Vec<BatchItemResult>,
    /// `saveIncomingSenderChains` for every sender whose chain advanced,
    /// sorted by sender id. Persist after the plaintexts.
    pub writes: Vec<(i64, ChainSetWrite)>,
}

/// `receiveGroupMessages` (325) minus the storage lookups: opens each
/// sender's envelopes in counter order under a per-sender walk budget.
/// `load_chains(sender)` is called at most once per sender.
pub fn receive_batch(
    items: &[BatchItem],
    self_user_id: i64,
    group_id: &str,
    mut load_chains: impl FnMut(i64) -> ChainSet,
) -> BatchOutcome {
    let mut results: Vec<BatchItemResult> = vec![BatchItemResult::Unchanged; items.len()];
    let mut to_open: Vec<(usize, i64, f64, Value)> = Vec::new();
    for (i, m) in items.iter().enumerate() {
        if m.is_system {
            continue;
        }
        if let Some(c) = &m.cached_plaintext {
            results[i] = BatchItemResult::Cached(c.clone());
            continue;
        }
        let env = match unwrap_envelope(&m.raw) {
            // No `sk2:` prefix: plaintext or an older build's post — never shown as text.
            Unwrapped::Plain | Unwrapped::Corrupt => {
                results[i] = BatchItemResult::Placeholder(PLACEHOLDER_UNDECRYPTABLE.into());
                continue;
            }
            Unwrapped::Envelope(env) => env,
        };
        if self_user_id != 0 && m.sender_id == self_user_id {
            results[i] = BatchItemResult::Placeholder(PLACEHOLDER_UNDECRYPTABLE.into());
            continue;
        }
        let ctr = match &env {
            Value::Object(o) => match o.get("ctr") {
                Some(Value::Number(n)) => n.as_f64().unwrap_or(MAX_SAFE_INTEGER),
                _ => MAX_SAFE_INTEGER,
            },
            _ => MAX_SAFE_INTEGER,
        };
        to_open.push((i, m.sender_id, ctr, env));
    }
    to_open.sort_by(|a, b| {
        a.1.cmp(&b.1).then(a.2.partial_cmp(&b.2).unwrap_or(std::cmp::Ordering::Equal)).then(a.0.cmp(&b.0))
    });

    struct SenderState {
        set: ChainSet,
        budget: f64,
        fingerprint: String,
        advanced: bool,
    }
    let mut senders: HashMap<i64, SenderState> = HashMap::new();
    for (i, sender, _, env) in to_open {
        let st = senders.entry(sender).or_insert_with(|| {
            let set = load_chains(sender);
            let fingerprint = set.fingerprint();
            SenderState { set, budget: WALK_BUDGET_PER_SENDER, fingerprint, advanced: false }
        });
        let res = if !st.set.is_empty() && items[i].failed_under.as_deref() == Some(st.fingerprint.as_str()) {
            OpenResult::Failed { walked: false, over_budget: false }
        } else {
            open_with_chains(&st.set, &env, Some(&mut st.budget), &SkContext { group_id, sender_uid: sender })
        };
        results[i] = match res {
            OpenResult::Opened { plaintext, state, index, .. } => {
                st.set.chains[index] = state;
                st.advanced = true;
                BatchItemResult::Opened(plaintext)
            }
            OpenResult::NoState => BatchItemResult::Pending { text: PLACEHOLDER_AWAITING_KEY.into(), memo_fingerprint: None },
            OpenResult::Failed { walked, over_budget } => BatchItemResult::Pending {
                text: PLACEHOLDER_UNDECRYPTABLE.into(),
                memo_fingerprint: (walked && !over_budget).then(|| st.fingerprint.clone()),
            },
        };
    }
    let mut writes: Vec<(i64, ChainSetWrite)> = senders
        .into_iter()
        .filter(|(_, s)| s.advanced)
        .filter_map(|(id, s)| s.set.to_storage().map(|w| (id, w)))
        .collect();
    writes.sort_by_key(|(id, _)| *id);
    BatchOutcome { results, writes }
}

/// Convenience for the sorted-open helpers: `(ctr as the batch sorts it)`.
pub fn envelope_sort_counter(raw: &str) -> Option<f64> {
    match unwrap_envelope(raw) {
        Unwrapped::Envelope(Value::Object(o)) => Some(match o.get("ctr") {
            Some(Value::Number(n)) => n.as_f64().unwrap_or(MAX_SAFE_INTEGER),
            _ => MAX_SAFE_INTEGER,
        }),
        Unwrapped::Envelope(_) => Some(MAX_SAFE_INTEGER),
        _ => None,
    }
}

// ───────────────────────────── SKDM transport v2 ─────────────────────────────

/// senderKeyChannel.ts `SKDM_TRANSPORT_VERSION`.
pub const SKDM_TRANSPORT_VERSION: u32 = 3;

/// The frame `distributeSKDMIfNeeded` (325) hands to `signaling.send`:
/// `{"type":"p2p-message","data":{"toUserId":M,"messageId":…,
/// "action":"sender-key-distribution","skdmTransport":2,"skdm":<ratchet wire>}}`.
/// `ratchet_wire` is the 1:1 Double Ratchet v=2 wire JSON whose plaintext is
/// `Skdm::to_json()`; the chain key never crosses the server in the clear.
pub fn skdm_v2_frame_json(to_user_id: i64, message_id: &str, ratchet_wire: &str) -> String {
    format!(
        "{{\"type\":\"p2p-message\",\"data\":{{\"toUserId\":{to_user_id},\"messageId\":{},\"action\":{},\"skdmTransport\":{SKDM_TRANSPORT_VERSION},\"skdm\":{}}}}}",
        json_quote(message_id),
        json_quote(crate::sender_keys::SKDM_ACTION),
        json_quote(ratchet_wire)
    )
}

// ───────────────────────────── skipped message keys (native, 2026-09-30) ─────────────────────────────
//
// The 325 receiver keeps NO skipped keys: an envelope whose counter is below
// the chain's is lost for good. Two senders of one account (the app and its
// Share Extension) can post counters N and N+1 in either order, and a group
// history read newest page first opens later counters before earlier ones —
// both lose messages under the 325 rule. Like Signal's sender keys, the
// receiver now keeps the message keys it walked past:
//
// - a key is stored only when the envelope that made the walk OPENED (a
//   forged or corrupt envelope stores nothing and moves nothing);
// - a stored key opens an envelope only after that chain's Ed25519 signature
//   over be64(ctr) ‖ ct verifies, and it is used once (deleted on use);
// - at most `MAX_SKIPPED_KEYS` per (group, sender), oldest counters dropped
//   first, and none older than `SKIPPED_KEY_TTL_MS`.
//
// The keys live in their own store entry (`recvskip:<g>:<uid>`), not in the
// chain blobs: the `recv:` / `recvprev:` at-rest format (and the RN golden
// vectors pinned on it) is unchanged. With no stored keys every function
// here behaves exactly like its 325 counterpart.

/// At most this many stored message keys per (group, sender).
pub const MAX_SKIPPED_KEYS: usize = 2000;
/// A stored message key older than this is dropped (30 days).
pub const SKIPPED_KEY_TTL_MS: i64 = 30 * 24 * 60 * 60 * 1000;
/// `recvskip:<g>:<uid>` — the skipped keys of one sender.
pub fn storage_key_recv_skip(group_id: &str, sender_user_id: i64) -> String {
    format!("recvskip:{group_id}:{sender_user_id}")
}

/// One stored message key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkippedKey {
    /// b64 signing public key of the chain it belongs to.
    pub chain: String,
    pub counter: u64,
    pub message_key: [u8; 32],
    /// When it was stored (Unix ms).
    pub stored_at_ms: i64,
}

/// The skipped keys of one (group, sender).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct SkippedKeys {
    pub keys: Vec<SkippedKey>,
}

impl SkippedKeys {
    /// From the stored JSON `{"v":1,"k":[{"p":chain,"c":ctr,"m":b64 key,"t":ms}…]}`;
    /// anything unreadable is an empty set (the keys are an optimisation).
    pub fn from_storage(raw: Option<&str>) -> SkippedKeys {
        let Some(raw) = raw.filter(|r| !r.is_empty()) else { return SkippedKeys::default() };
        let Ok(Value::Object(o)) = serde_json::from_str::<Value>(raw) else { return SkippedKeys::default() };
        let Some(Value::Array(list)) = o.get("k") else { return SkippedKeys::default() };
        let mut keys = Vec::with_capacity(list.len());
        for item in list {
            let Value::Object(e) = item else { continue };
            let (Some(Value::String(chain)), Some(Value::Number(c)), Some(Value::String(m))) = (e.get("p"), e.get("c"), e.get("m"))
            else {
                continue;
            };
            let Some(counter) = c.as_u64() else { continue };
            let Some(bytes) = js_decode_base64(&JsValue::String(m.clone())) else { continue };
            let Ok(message_key): Result<[u8; 32], _> = bytes.as_slice().try_into() else { continue };
            let stored_at_ms = e.get("t").and_then(Value::as_i64).unwrap_or(0);
            keys.push(SkippedKey { chain: chain.clone(), counter, message_key, stored_at_ms });
        }
        SkippedKeys { keys }
    }

    /// The JSON to store; `None` when empty (delete the entry).
    pub fn to_storage(&self) -> Option<String> {
        if self.keys.is_empty() {
            return None;
        }
        let items: Vec<String> = self
            .keys
            .iter()
            .map(|k| {
                format!(
                    "{{\"p\":{},\"c\":{},\"m\":{},\"t\":{}}}",
                    json_quote(&k.chain),
                    k.counter,
                    json_quote(&b64(&k.message_key)),
                    k.stored_at_ms
                )
            })
            .collect();
        Some(format!("{{\"v\":1,\"k\":[{}]}}", items.join(",")))
    }

    fn position(&self, chain: &str, counter: u64) -> Option<usize> {
        self.keys.iter().position(|k| k.counter == counter && k.chain == chain)
    }

    /// Stores the keys of counters `from..to` of the chain whose key at `from`
    /// is `chain_key_at_from`, then prunes.
    fn add_walk(&mut self, chain: &str, chain_key_at_from: &[u8], from: u64, to: u64, now_ms: i64) {
        let mut key = chain_key_at_from.to_vec();
        for counter in from..to {
            if self.position(chain, counter).is_none() {
                self.keys.push(SkippedKey {
                    chain: chain.to_string(),
                    counter,
                    message_key: derive_message_key(&key),
                    stored_at_ms: now_ms,
                });
            }
            key = ratchet_sender_key(&key).to_vec();
        }
        self.prune(now_ms);
    }

    /// Drops expired keys, then the oldest counters beyond the cap.
    pub fn prune(&mut self, now_ms: i64) {
        self.keys.retain(|k| k.stored_at_ms <= 0 || now_ms <= 0 || now_ms - k.stored_at_ms <= SKIPPED_KEY_TTL_MS);
        if self.keys.len() > MAX_SKIPPED_KEYS {
            self.keys.sort_by(|a, b| a.stored_at_ms.cmp(&b.stored_at_ms).then(a.counter.cmp(&b.counter)));
            let excess = self.keys.len() - MAX_SKIPPED_KEYS;
            self.keys.drain(..excess);
        }
    }

    /// Keeps only keys of chains still in `set` (a rotated-away chain beyond
    /// `MAX_PREVIOUS_CHAINS` can never be used again).
    pub fn retain_chains(&mut self, set: &ChainSet) {
        let alive: Vec<String> = set.chains.iter().map(|c| b64(&c.signing_pub)).collect();
        self.keys.retain(|k| alive.contains(&k.chain));
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// Opens `env` (counter `ctr`) with a stored key of `state`'s chain, after the
/// chain's signature verifies. `Some(plaintext)` consumed the key.
fn open_with_skipped(
    state: &SenderKeyState,
    skipped: &mut SkippedKeys,
    env: &Value,
    ctr: f64,
    ctx: &SkContext<'_>,
) -> Option<(String, [u8; 32])> {
    if !is_safe_integer(ctr) || ctr < 0.0 {
        return None;
    }
    let chain = b64(&state.signing_pub);
    let pos = skipped.position(&chain, ctr as u64)?;
    if !signature_matches(state, env, ctr, ctx) {
        return None;
    }
    let ct = js_decode_base64(&prop(env, "ct").ok()?)?;
    let nonce: [u8; NONCE_LEN] = js_decode_base64(&prop(env, "n").ok()?)?.as_slice().try_into().ok()?;
    let message_key = skipped.keys[pos].message_key;
    let opened = secretbox_open(&ct, &nonce, &message_key)?;
    let plaintext = tweetnacl_util_encode_utf8(opened)?;
    skipped.keys.remove(pos);
    Some((plaintext, message_key))
}

/// [`open_with_chains`] plus the skipped keys: an envelope below a chain's
/// counter opens with its stored key; one that walks the chain forward
/// stores the keys it passed (only when it opened). `skipped` is updated in
/// place; the caller persists it with the chain write.
pub fn open_with_chains_skipping(
    set: &ChainSet,
    skipped: &mut SkippedKeys,
    env: &Value,
    mut budget: Option<&mut f64>,
    now_ms: i64,
    ctx: &SkContext<'_>,
) -> OpenResult {
    if set.chains.is_empty() {
        return OpenResult::NoState;
    }
    let ctr = match env {
        Value::Object(m) => match m.get("ctr") {
            Some(Value::Number(n)) => n.as_f64().unwrap_or(f64::NAN),
            _ => f64::NAN,
        },
        _ => f64::NAN,
    };
    if !is_safe_integer(ctr) || ctr < 0.0 {
        return OpenResult::Failed { walked: false, over_budget: false };
    }
    let (mut walked, mut over_budget) = (false, false);
    for (i, state) in set.chains.iter().enumerate() {
        let current = state.counter.to_number();
        if ctr < current {
            if let Some((plaintext, message_key)) = open_with_skipped(state, skipped, env, ctr, ctx) {
                return OpenResult::Opened { plaintext, state: state.clone(), index: i, message_key };
            }
            continue;
        }
        let steps = ctr - current;
        if steps > MAX_CHAIN_WALK {
            continue;
        }
        if let Some(left) = budget.as_deref_mut() {
            if steps > FREE_WALK_STEPS {
                if !signature_matches(state, env, ctr, ctx) {
                    continue;
                }
                if steps > *left {
                    over_budget = true;
                    continue;
                }
                *left -= steps;
                walked = true;
            }
        }
        if let Ok(Some((next, plaintext, message_key))) = decrypt_group_message_keyed(state, env, ctx) {
            if is_safe_integer(current) && current >= 0.0 && steps >= 1.0 {
                skipped.add_walk(&b64(&state.signing_pub), &state.chain_key, current as u64, ctr as u64, now_ms);
            }
            return OpenResult::Opened { plaintext, state: next, index: i, message_key };
        }
    }
    OpenResult::Failed { walked, over_budget }
}

/// [`decrypt_with_chains`] with skipped keys. Returns the decrypt and the
/// skipped-key JSON to store when it changed (`Some(None)` = delete).
pub fn decrypt_with_chains_skipping(
    set: &ChainSet,
    skipped: &SkippedKeys,
    raw: &str,
    now_ms: i64,
    ctx: &SkContext<'_>,
) -> (GroupDecrypt, Option<Option<String>>) {
    let done = |kind, text: &str, encrypted| GroupDecrypt { kind, text: text.to_string(), encrypted, write: None, set: set.clone() };
    let env = match unwrap_envelope(raw) {
        Unwrapped::Plain => return (done(GroupDecryptKind::Plain, PLACEHOLDER_UNDECRYPTABLE, true), None),
        Unwrapped::Corrupt => return (done(GroupDecryptKind::Corrupt, PLACEHOLDER_UNDECRYPTABLE, true), None),
        Unwrapped::Envelope(env) => env,
    };
    let mut keys = skipped.clone();
    match open_with_chains_skipping(set, &mut keys, &env, None, now_ms, ctx) {
        OpenResult::NoState => (done(GroupDecryptKind::AwaitingKey, PLACEHOLDER_AWAITING_KEY, true), None),
        OpenResult::Failed { .. } => (done(GroupDecryptKind::Failed, PLACEHOLDER_UNDECRYPTABLE, true), None),
        OpenResult::Opened { plaintext, state, index, .. } => {
            let mut next = set.clone();
            next.chains[index] = state;
            let write = next.to_storage();
            keys.retain_chains(&next);
            let skip_write = if keys != *skipped { Some(keys.to_storage()) } else { None };
            (GroupDecrypt { kind: GroupDecryptKind::Opened, text: plaintext, encrypted: true, write, set: next }, skip_write)
        }
    }
}

/// [`BatchOutcome`] plus the skipped keys to store per sender.
#[derive(Clone, Debug, PartialEq)]
pub struct BatchOutcomeSkipping {
    pub results: Vec<BatchItemResult>,
    pub writes: Vec<(i64, ChainSetWrite)>,
    /// `(sender, JSON or None = delete)` for every sender whose keys changed.
    pub skipped_writes: Vec<(i64, Option<String>)>,
    /// One per input item: the post reaction key `rk` of an item that was
    /// `Opened` in this call (wire-1.1 §W7.4) — store it with the plaintext.
    pub reaction_keys: Vec<Option<[u8; 32]>>,
    /// One per input item: `Some(N)` when the text is an `sk<N>:` envelope of
    /// a NEWER build (`N > 2`). Its result is the undecryptable placeholder
    /// for a 1.0.0-shaped caller; a level-2 host shows «обновите приложение».
    pub newer_versions: Vec<Option<u32>>,
}

/// [`receive_batch`] with skipped keys: identical results while no key is
/// stored; below-counter envelopes open with their stored keys.
pub fn receive_batch_skipping(
    items: &[BatchItem],
    self_user_id: i64,
    group_id: &str,
    now_ms: i64,
    mut load: impl FnMut(i64) -> (ChainSet, SkippedKeys),
) -> BatchOutcomeSkipping {
    let mut results: Vec<BatchItemResult> = vec![BatchItemResult::Unchanged; items.len()];
    let mut reaction_keys: Vec<Option<[u8; 32]>> = vec![None; items.len()];
    let mut newer_versions: Vec<Option<u32>> = vec![None; items.len()];
    let mut to_open: Vec<(usize, i64, f64, Value)> = Vec::new();
    for (i, m) in items.iter().enumerate() {
        if m.is_system {
            continue;
        }
        if let Some(c) = &m.cached_plaintext {
            results[i] = BatchItemResult::Cached(c.clone());
            continue;
        }
        let env = match unwrap_envelope(&m.raw) {
            // No `sk2:` prefix: plaintext or another build's post — never shown as text.
            Unwrapped::Plain | Unwrapped::Corrupt => {
                results[i] = BatchItemResult::Placeholder(PLACEHOLDER_UNDECRYPTABLE.into());
                newer_versions[i] = newer_version(&m.raw);
                continue;
            }
            Unwrapped::Envelope(env) => env,
        };
        if self_user_id != 0 && m.sender_id == self_user_id {
            results[i] = BatchItemResult::Placeholder(PLACEHOLDER_UNDECRYPTABLE.into());
            continue;
        }
        let ctr = match &env {
            Value::Object(o) => match o.get("ctr") {
                Some(Value::Number(n)) => n.as_f64().unwrap_or(MAX_SAFE_INTEGER),
                _ => MAX_SAFE_INTEGER,
            },
            _ => MAX_SAFE_INTEGER,
        };
        to_open.push((i, m.sender_id, ctr, env));
    }
    to_open.sort_by(|a, b| {
        a.1.cmp(&b.1).then(a.2.partial_cmp(&b.2).unwrap_or(std::cmp::Ordering::Equal)).then(a.0.cmp(&b.0))
    });

    struct SenderState {
        set: ChainSet,
        skipped: SkippedKeys,
        skipped_before: SkippedKeys,
        budget: f64,
        fingerprint: String,
        advanced: bool,
    }
    let mut senders: HashMap<i64, SenderState> = HashMap::new();
    for (i, sender, _, env) in to_open {
        let st = senders.entry(sender).or_insert_with(|| {
            let (set, skipped) = load(sender);
            let fingerprint = set.fingerprint();
            SenderState {
                set,
                skipped_before: skipped.clone(),
                skipped,
                budget: WALK_BUDGET_PER_SENDER,
                fingerprint,
                advanced: false,
            }
        });
        let res = if !st.set.is_empty() && items[i].failed_under.as_deref() == Some(st.fingerprint.as_str()) {
            OpenResult::Failed { walked: false, over_budget: false }
        } else {
            open_with_chains_skipping(&st.set, &mut st.skipped, &env, Some(&mut st.budget), now_ms, &SkContext { group_id, sender_uid: sender })
        };
        results[i] = match res {
            OpenResult::Opened { plaintext, state, index, message_key } => {
                if st.set.chains[index] != state {
                    st.set.chains[index] = state;
                    st.advanced = true;
                }
                reaction_keys[i] = Some(post_reaction_key(&message_key));
                BatchItemResult::Opened(plaintext)
            }
            OpenResult::NoState => BatchItemResult::Pending { text: PLACEHOLDER_AWAITING_KEY.into(), memo_fingerprint: None },
            OpenResult::Failed { walked, over_budget } => BatchItemResult::Pending {
                text: PLACEHOLDER_UNDECRYPTABLE.into(),
                memo_fingerprint: (walked && !over_budget).then(|| st.fingerprint.clone()),
            },
        };
    }
    let mut writes: Vec<(i64, ChainSetWrite)> = Vec::new();
    let mut skipped_writes: Vec<(i64, Option<String>)> = Vec::new();
    for (id, mut s) in senders {
        if s.advanced {
            if let Some(w) = s.set.to_storage() {
                writes.push((id, w));
            }
        }
        s.skipped.retain_chains(&s.set);
        if s.skipped != s.skipped_before {
            skipped_writes.push((id, s.skipped.to_storage()));
        }
    }
    writes.sort_by_key(|(id, _)| *id);
    skipped_writes.sort_by_key(|(id, _)| *id);
    BatchOutcomeSkipping { results, writes, skipped_writes, reaction_keys, newer_versions }
}
