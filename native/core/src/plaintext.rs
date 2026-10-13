//! Typed plaintext of protocol v3 (03-crypto §V3.3.5; wire-1.1 §W3.2): the
//! ONLY thing a receiver renders or acts on. Everything that used to ride in
//! clear next to the ciphertext (message id, edit target, quoted reply,
//! forwarded-from name, disappearing timer, story reference) is inside the
//! authenticated box.
//!
//! ```text
//! level 1 (1.0.0)
//! {"t":"chat","id","body":"<text>","reply"?:{"id","text","name"},"fwd"?:{"name"},"expire"?:N,"story"?:{"id","type","action","content"?},"nearby"?:{invite}}
//! {"t":"file","id","body":{FileEnvelope[,"st":{sticker}]},"reply"?,"fwd"?,"expire"?}
//! {"t":"edit","id","editOf","body":"<text>"}
//! {"t":"skdm","id","body":{SKDM v2}}
//! {"t":"hello","id"}
//! level 2 (1.1) — never in a field a 1.0.0 client feeds to its ratchet
//! {"t":"react","id","to","e":[…],"ts"}
//! {"t":"nearby","id","nearby":{accept | token | stop}}
//! {"t":"ptt","id","ptt":{"v":1,"k","codec","sr"}}
//! any kind, optional and lenient: "alt":"<fallback text>", "caps":{"v","f"}, "p":"<spaces>"
//! chat / file, optional and lenient: "silent":true — «Отправить без звука» (wire-1.1 §W7.9)
//! ```
//!
//! [`classify`] is the level-2 entry point. An authenticated plaintext is
//! either a kind this core knows that satisfies its rules ([`Classified::Typed`])
//! or it is [`Classified::Unsupported`] — a result, not an error: the ratchet
//! step that carried it is consumed and nothing is counted. A 1.0.0 core
//! returned `None` here from inside the decrypt, which made every unknown `t`
//! a counted decrypt failure (three of them reset the session).
//!
//! Mandatory for every kind: a JSON object of at most 48 KiB with no
//! duplicate key at any depth, `t` a string, `id` a non-empty string.
//! Level-1 kinds keep their 1.0.0 rules: required fields of the right JSON
//! type, no field another `t` owns, `reply.text` ≤ 100 UTF-16 units, `expire`
//! an integer in `[1, 2^53)`. Unknown top-level keys are ignored; a malformed
//! soft key (`caps`, `alt`, `nearby` on a chat, `silent` on a chat or a file)
//! is an absent one.

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::caps::Caps;
use crate::nearby::NearbyOp;
use crate::ptt::{ptt_id_bytes, PttKey};
use crate::reactions::{is_valid_react, pad_reserve};
use crate::strict_json;

pub const REPLY_TEXT_MAX_UTF16: usize = 100;
/// A typed plaintext longer than this is not parsed (it cannot have crossed
/// a 64 KB WebSocket frame or a mesh payload).
pub const MAX_PLAINTEXT_BYTES: usize = 48 * 1024;
/// `alt` longer than this (UTF-16 units) is treated as absent.
pub const ALT_MAX_UTF16: usize = 256;
const MAX_INT: u64 = (1u64 << 53) - 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    pub id: String,
    pub text: String,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoryRef {
    pub id: String,
    pub story_type: String,
    pub action: String,
    pub content: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum TypedPlaintext {
    Chat { id: String, body: String, reply: Option<Reply>, fwd: Option<String>, expire: Option<u64>, story: Option<StoryRef> },
    /// `body` is the FileEnvelope JSON object (03 §8.3).
    File { id: String, body: Map<String, Value>, reply: Option<Reply>, fwd: Option<String>, expire: Option<u64> },
    Edit { id: String, edit_of: String, body: String },
    /// `body` is the SKDM v2 object (03 §10).
    Skdm { id: String, body: Map<String, Value> },
    Hello { id: String },
    /// Level 2: the sender's full emoji set for message `to` (empty = removed).
    React { id: String, to: String, e: Vec<String>, ts: u64 },
    /// Level 2: accept / token / stop of a «Найти рядом» exchange.
    Nearby { id: String, nearby: NearbyOp },
    /// Level 2: the key of one push-to-talk transmission (`id` = the pttId).
    Ptt { id: String, ptt: PttKey },
}

impl TypedPlaintext {
    pub fn id(&self) -> &str {
        match self {
            TypedPlaintext::Chat { id, .. }
            | TypedPlaintext::File { id, .. }
            | TypedPlaintext::Edit { id, .. }
            | TypedPlaintext::Skdm { id, .. }
            | TypedPlaintext::Hello { id }
            | TypedPlaintext::React { id, .. }
            | TypedPlaintext::Nearby { id, .. }
            | TypedPlaintext::Ptt { id, .. } => id,
        }
    }

    /// The wire level that introduced this kind (1 = 1.0.0).
    pub fn level(&self) -> u8 {
        match self {
            TypedPlaintext::React { .. } | TypedPlaintext::Nearby { .. } | TypedPlaintext::Ptt { .. } => 2,
            _ => 1,
        }
    }

    /// A step the peer may never decrypt (wire-1.1 §W3.5): a control frame a
    /// 1.0.0 peer drops unread, a transmission nobody heard, an edit the
    /// server dropped. `chat`, `file`, `skdm` and `hello` are universal.
    pub fn is_lossy(&self) -> bool {
        matches!(self, TypedPlaintext::React { .. } | TypedPlaintext::Nearby { .. } | TypedPlaintext::Ptt { .. } | TypedPlaintext::Edit { .. })
    }

    pub fn kind(&self) -> &'static str {
        match self {
            TypedPlaintext::Chat { .. } => "chat",
            TypedPlaintext::File { .. } => "file",
            TypedPlaintext::Edit { .. } => "edit",
            TypedPlaintext::Skdm { .. } => "skdm",
            TypedPlaintext::Hello { .. } => "hello",
            TypedPlaintext::React { .. } => "react",
            TypedPlaintext::Nearby { .. } => "nearby",
            TypedPlaintext::Ptt { .. } => "ptt",
        }
    }

    /// The exact JSON text of the kind's own keys (order: t, id, editOf,
    /// body, reply, fwd, expire, story | to, e, ts | nearby | ptt) — for a
    /// level-1 kind byte for byte what 1.0.0 writes. [`build`] adds soft keys.
    pub fn to_json(&self) -> String {
        serde_json::to_string(&Value::Object(self.to_map())).expect("typed plaintext serializes")
    }

    fn to_map(&self) -> Map<String, Value> {
        let reply_v = |r: &Option<Reply>| r.as_ref().map(|r| json!({"id": r.id, "text": r.text, "name": r.name}));
        let mut o = Map::new();
        o.insert("t".into(), Value::String(self.kind().into()));
        o.insert("id".into(), Value::String(self.id().into()));
        match self {
            TypedPlaintext::Chat { body, reply, fwd, expire, story, .. } => {
                o.insert("body".into(), Value::String(body.clone()));
                put_common(&mut o, reply_v(reply), fwd, expire);
                if let Some(s) = story {
                    let mut so = Map::new();
                    so.insert("id".into(), Value::String(s.id.clone()));
                    so.insert("type".into(), Value::String(s.story_type.clone()));
                    so.insert("action".into(), Value::String(s.action.clone()));
                    if let Some(c) = &s.content {
                        so.insert("content".into(), Value::String(c.clone()));
                    }
                    o.insert("story".into(), Value::Object(so));
                }
            }
            TypedPlaintext::File { body, reply, fwd, expire, .. } => {
                o.insert("body".into(), Value::Object(body.clone()));
                put_common(&mut o, reply_v(reply), fwd, expire);
            }
            TypedPlaintext::Edit { edit_of, body, .. } => {
                o.insert("editOf".into(), Value::String(edit_of.clone()));
                o.insert("body".into(), Value::String(body.clone()));
            }
            TypedPlaintext::Skdm { body, .. } => {
                o.insert("body".into(), Value::Object(body.clone()));
            }
            TypedPlaintext::Hello { .. } => {}
            TypedPlaintext::React { to, e, ts, .. } => {
                o.insert("to".into(), Value::String(to.clone()));
                o.insert("e".into(), Value::Array(e.iter().map(|s| Value::String(s.clone())).collect()));
                o.insert("ts".into(), Value::from(*ts));
            }
            TypedPlaintext::Nearby { nearby, .. } => {
                o.insert("nearby".into(), nearby.to_value());
            }
            TypedPlaintext::Ptt { ptt, .. } => {
                o.insert("ptt".into(), ptt.to_value());
            }
        }
        o
    }
}

fn put_common(o: &mut Map<String, Value>, reply: Option<Value>, fwd: &Option<String>, expire: &Option<u64>) {
    if let Some(r) = reply {
        o.insert("reply".into(), r);
    }
    if let Some(f) = fwd {
        o.insert("fwd".into(), json!({ "name": f }));
    }
    if let Some(e) = expire {
        o.insert("expire".into(), Value::from(*e));
    }
}

/// JS `s.slice(0, n)` in UTF-16 units, backed off so no surrogate pair is split.
pub fn utf16_prefix(s: &str, n: usize) -> String {
    let mut used = 0;
    let mut out = String::new();
    for ch in s.chars() {
        let w = ch.len_utf16();
        if used + w > n {
            break;
        }
        used += w;
        out.push(ch);
    }
    out
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WReply {
    id: String,
    text: String,
    name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WFwd {
    name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WStory {
    id: String,
    #[serde(rename = "type")]
    story_type: String,
    action: String,
    #[serde(default)]
    content: Option<String>,
}

// ───────────────────────────── level-2 classification ─────────────────────────────

/// The optional keys valid on every kind (wire-1.1 §W3.2), parsed leniently.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Soft {
    /// The sender's capabilities (attached to every plaintext of a 1:1 session).
    pub caps: Option<Caps>,
    /// A plain-text fallback a receiver shows when it does not know `t`.
    pub alt: Option<String>,
    /// On a `chat` only: a «Найти рядом» invite riding on a visible message.
    pub nearby: Option<NearbyOp>,
    /// On a `chat` or a `file`: the sender chose «Отправить без звука»
    /// (wire-1.1 §W7.9). The authenticated copy of the outer hint `silent`:
    /// what the recipient's phone trusts when it decides about a sound
    /// itself (a notice it posts, a message that came over the mesh). Only
    /// JSON `true` sets it; a 1.0.0 client ignores the key (R2).
    pub silent: bool,
}

/// A kind this core knows, with its soft keys.
#[derive(Clone, Debug, PartialEq)]
pub struct Parsed {
    pub pt: TypedPlaintext,
    pub soft: Soft,
}

/// What can be said about an authenticated plaintext this core does not
/// understand: enough to show «обновите приложение» under the right id.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Unsupported {
    pub t: Option<String>,
    pub id: Option<String>,
    pub alt: Option<String>,
    pub caps: Option<Caps>,
}

// Built once per call and consumed at once: the size difference between the cases costs nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq)]
pub enum Classified {
    Typed(Parsed),
    Unsupported(Unsupported),
}

fn soft_alt(o: &Map<String, Value>) -> Option<String> {
    let s = o.get("alt")?.as_str()?;
    (!s.is_empty() && s.encode_utf16().count() <= ALT_MAX_UTF16).then(|| s.to_string())
}

fn soft_caps(o: &Map<String, Value>) -> Option<Caps> {
    o.get("caps").and_then(Caps::from_value_lenient)
}

/// `"silent": true` and nothing else: any other value is an absent key.
fn soft_silent(o: &Map<String, Value>) -> bool {
    o.get("silent") == Some(&Value::Bool(true))
}

/// A level-1 optional field: absent and JSON `null` are the same (as the
/// 1.0.0 `Option<…>` fields read them).
fn opt<'a>(o: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    o.get(key).filter(|v| !v.is_null())
}

/// The strict part: `None` = this object is not a valid plaintext of a kind
/// this core knows.
fn known_kind(o: &Map<String, Value>, t: &str, id: &str) -> Option<TypedPlaintext> {
    let id = id.to_string();
    // Level-2 kinds own none of the level-1 fields: with one of them the
    // sender meant something this version does not know.
    const LEVEL1_FIELDS: [&str; 6] = ["body", "editOf", "reply", "fwd", "expire", "story"];
    match t {
        "react" | "nearby" | "ptt" if LEVEL1_FIELDS.iter().any(|k| o.contains_key(*k)) => return None,
        "react" => {
            let to = o.get("to")?.as_str()?.to_string();
            let e: Vec<String> = o.get("e")?.as_array()?.iter().map(|v| v.as_str().map(str::to_string)).collect::<Option<_>>()?;
            let ts = o.get("ts").and_then(strict_json::uint)?;
            return is_valid_react(&to, &e, ts).then_some(TypedPlaintext::React { id, to, e, ts });
        }
        "nearby" => {
            let nearby = NearbyOp::from_value(o.get("nearby")?)?;
            // An invite is a visible message; it never travels as a control kind.
            return (!matches!(nearby, NearbyOp::Invite { .. })).then_some(TypedPlaintext::Nearby { id, nearby });
        }
        "ptt" => {
            ptt_id_bytes(&id)?;
            let ptt = PttKey::from_value(o.get("ptt")?)?;
            return Some(TypedPlaintext::Ptt { id, ptt });
        }
        _ => {}
    }

    // Level 1: the 1.0.0 rules, field for field.
    let edit_of = match opt(o, "editOf") {
        None => None,
        Some(v) => Some(v.as_str()?.to_string()),
    };
    let body = opt(o, "body");
    let reply = match opt(o, "reply") {
        None => None,
        Some(v) => {
            let r: WReply = serde_json::from_value(v.clone()).ok()?;
            if r.id.is_empty() || r.text.encode_utf16().count() > REPLY_TEXT_MAX_UTF16 {
                return None;
            }
            Some(Reply { id: r.id, text: r.text, name: r.name })
        }
    };
    let fwd = match opt(o, "fwd") {
        None => None,
        Some(v) => Some(serde_json::from_value::<WFwd>(v.clone()).ok()?.name),
    };
    let expire = match opt(o, "expire") {
        None => None,
        // `as_u64`: a JSON integer; `5.0` or `5e0` is not one.
        Some(v) => Some(v.as_u64().filter(|e| (1..=MAX_INT).contains(e))?),
    };
    let story = match opt(o, "story") {
        None => None,
        Some(v) => Some(serde_json::from_value::<WStory>(v.clone()).ok()?),
    };
    match t {
        "chat" => {
            let Some(Value::String(body)) = body else { return None };
            if edit_of.is_some() {
                return None;
            }
            let story = match story {
                None => None,
                Some(s) => {
                    if s.id.is_empty() || s.action.is_empty() {
                        return None;
                    }
                    Some(StoryRef { id: s.id, story_type: s.story_type, action: s.action, content: s.content })
                }
            };
            Some(TypedPlaintext::Chat { id, body: body.clone(), reply, fwd, expire, story })
        }
        "file" => {
            let Some(Value::Object(body)) = body else { return None };
            if edit_of.is_some() || story.is_some() {
                return None;
            }
            Some(TypedPlaintext::File { id, body: body.clone(), reply, fwd, expire })
        }
        "edit" => {
            let Some(Value::String(body)) = body else { return None };
            let edit_of = edit_of.filter(|e| !e.is_empty())?;
            if reply.is_some() || fwd.is_some() || expire.is_some() || story.is_some() || body.is_empty() {
                return None;
            }
            Some(TypedPlaintext::Edit { id, edit_of, body: body.clone() })
        }
        "skdm" => {
            let Some(Value::Object(body)) = body else { return None };
            if reply.is_some() || fwd.is_some() || expire.is_some() || edit_of.is_some() || story.is_some() {
                return None;
            }
            Some(TypedPlaintext::Skdm { id, body: body.clone() })
        }
        "hello" => {
            if body.is_some() || reply.is_some() || fwd.is_some() || expire.is_some() || edit_of.is_some() || story.is_some() {
                return None;
            }
            Some(TypedPlaintext::Hello { id })
        }
        _ => None,
    }
}

/// Classifies an authenticated plaintext (wire-1.1 §W3.1–§W3.2). Never
/// fails: what is not a known kind is [`Classified::Unsupported`], with
/// whatever of `t`, `id`, `alt` and `caps` can be read.
pub fn classify(text: &str) -> Classified {
    let none = || Classified::Unsupported(Unsupported::default());
    if text.len() > MAX_PLAINTEXT_BYTES {
        return none();
    }
    let Some(o) = strict_json::parse_object(text) else { return none() };
    let t = o.get("t").and_then(Value::as_str);
    let id = o.get("id").and_then(Value::as_str).filter(|i| !i.is_empty());
    let (alt, caps) = (soft_alt(&o), soft_caps(&o));
    let unsupported = |alt: Option<String>, caps: Option<Caps>| {
        Classified::Unsupported(Unsupported { t: t.map(str::to_string), id: id.map(str::to_string), alt, caps })
    };
    let (Some(t), Some(id)) = (t, id) else { return unsupported(alt, caps) };
    match known_kind(&o, t, id) {
        Some(pt) => {
            let nearby = match &pt {
                TypedPlaintext::Chat { .. } => {
                    o.get("nearby").and_then(NearbyOp::from_value).filter(|n| matches!(n, NearbyOp::Invite { .. }))
                }
                _ => None,
            };
            // Only what announces itself with an alert can be sent without a sound.
            let silent = matches!(&pt, TypedPlaintext::Chat { .. } | TypedPlaintext::File { .. }) && soft_silent(&o);
            Classified::Typed(Parsed { pt, soft: Soft { caps, alt, nearby, silent } })
        }
        None => unsupported(alt, caps),
    }
}

/// [`classify`] of decrypted bytes: not UTF-8 is unsupported too.
pub fn classify_bytes(bytes: &[u8]) -> Classified {
    match std::str::from_utf8(bytes) {
        Ok(text) => classify(text),
        Err(_) => Classified::Unsupported(Unsupported::default()),
    }
}

/// The known kind of `text`, soft keys dropped; `None` for anything else.
/// (The 1.0.0 entry point; it now also returns the level-2 kinds.)
pub fn parse_typed_plaintext(text: &str) -> Option<TypedPlaintext> {
    match classify(text) {
        Classified::Typed(p) => Some(p.pt),
        Classified::Unsupported(_) => None,
    }
}

/// The exact JSON to encrypt: the kind's own keys, then `nearby` (an invite,
/// on a chat), `silent` (written only when set, so a message sent the
/// ordinary way is byte for byte what it was), `alt`, `caps`, and — with
/// `pad_block` — a `p` of spaces that
/// brings the UTF-8 length to a multiple of the block (so the envelope
/// length does not tell one small plaintext from another). `None` when the
/// result would not classify back to exactly this (an invalid field, an
/// invite or `silent` on a kind that cannot carry it).
///
/// A `react` is padded as if `e` had its longest legal encoding
/// (`reactions::pad_reserve`): `p` is always written, and the padded length
/// is the same for every `e` — an emoji, three long ones, a removal.
pub fn build(pt: &TypedPlaintext, soft: &Soft, pad_block: Option<usize>) -> Option<String> {
    let mut o = pt.to_map();
    if let Some(n) = &soft.nearby {
        o.insert("nearby".into(), n.to_value());
    }
    if soft.silent {
        o.insert("silent".into(), Value::Bool(true));
    }
    if let Some(alt) = &soft.alt {
        o.insert("alt".into(), Value::String(alt.clone()));
    }
    if let Some(caps) = &soft.caps {
        o.insert("caps".into(), caps.to_value());
    }
    let mut json = serde_json::to_string(&Value::Object(o)).ok()?;
    if let Some(block) = pad_block.filter(|b| *b > 1) {
        // What the padding must cover besides the text itself: for a `react`,
        // the bytes by which its `e` is shorter than the longest one.
        let reserve = match pt {
            TypedPlaintext::React { e, .. } => Some(pad_reserve(e)),
            _ => None,
        };
        if reserve.is_some() || json.len() % block != 0 {
            // `,"p":""` costs 7 bytes; the spaces make up the rest.
            let total = (json.len() + reserve.unwrap_or(0) + 7).div_ceil(block) * block;
            let spaces = total - json.len() - 7;
            json.pop();
            json.push_str(",\"p\":\"");
            json.extend(std::iter::repeat_n(' ', spaces));
            json.push_str("\"}");
        }
    }
    match classify(&json) {
        Classified::Typed(p) if p.pt == *pt && p.soft == *soft => Some(json),
        _ => None,
    }
}

/// The outer-frame agreement rules of 03 §3.5 for a `p2p-message` (also
/// mesh and sealed): outer `messageId` == inner `id`; the outer `action`
/// matches `t`. `story_action_outer`/`story_id_outer` are the outer hints.
pub fn outer_matches_p2p(pt: &TypedPlaintext, outer_message_id: &str, outer_action: Option<&str>, outer_story_id: Option<&str>) -> bool {
    if pt.id() != outer_message_id {
        return false;
    }
    match (outer_action, pt) {
        (None, TypedPlaintext::Chat { story: None, .. }) | (None, TypedPlaintext::File { .. }) => true,
        (Some("sender-key-distribution"), TypedPlaintext::Skdm { .. }) => true,
        (Some("session-hello"), TypedPlaintext::Hello { .. }) => true,
        (Some(action), TypedPlaintext::Chat { story: Some(s), .. }) => s.action == action && outer_story_id == Some(s.id.as_str()),
        _ => false,
    }
}

/// `message-edit`: outer `messageId` == inner `editOf`, `t` == edit.
pub fn outer_matches_edit(pt: &TypedPlaintext, outer_message_id: &str) -> bool {
    matches!(pt, TypedPlaintext::Edit { edit_of, .. } if edit_of == outer_message_id)
}

/// The `ctl` carrier (wire-1.1 §W5): a control kind whose `id` is the
/// frame's `messageId`. A message kind in `ctl` is a mismatch — a message
/// must arrive as a message.
pub fn outer_matches_ctl(pt: &TypedPlaintext, outer_message_id: &str) -> bool {
    matches!(pt, TypedPlaintext::React { .. } | TypedPlaintext::Nearby { .. }) && pt.id() == outer_message_id
}

/// A mesh `ctl` frame (wire-1.1 §W8.6): the mesh allow-list of 1.1 is
/// `nearby` only (a reaction needs store-and-forward, which a realtime mesh
/// frame is not).
pub fn outer_matches_mesh_ctl(pt: &TypedPlaintext, frame_id: &str) -> bool {
    matches!(pt, TypedPlaintext::Nearby { .. }) && pt.id() == frame_id
}

/// `ptt-start.wire` and the `w` of a mesh `ptt` frame: the key plaintext of
/// exactly this transmission.
pub fn outer_matches_ptt(pt: &TypedPlaintext, ptt_id: &str) -> bool {
    matches!(pt, TypedPlaintext::Ptt { .. }) && pt.id() == ptt_id
}

// ───────────────────────────── level-2 frames ─────────────────────────────

/// The action of every `ctl` frame. A 1.0.0 SERVER already treats
/// `session-hello` as session control — stored offline, block-filtered, no
/// alert push, no contact auto-add — so the frame is right against the old
/// server binary too.
pub const CTL_ACTION: &str = "session-hello";
/// Longest `ctl` field.
pub const CTL_MAX_BYTES: usize = 8192;

/// A `messageId` a `ctl` frame may carry (wire-1.1 §W5.1): 1..128 characters
/// of `[A-Za-z0-9_-]` — exactly what the server's duplicate claim can key
/// (`db.IdempotentMessageID`). A frame under any other id is routed and
/// stored every time it is sent, so the sender side refuses to make one.
pub fn is_ctl_message_id(id: &str) -> bool {
    (1..=128).contains(&id.len()) && id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

/// The `ctl` frame (wire-1.1 §W5.1):
/// `{"type":"p2p-message","data":{"toUserId","messageId","action":"session-hello","ctl":"<v3 envelope>"}}`.
/// There is NO `text` key: a 1.0.0 client drops a `p2p-message` without
/// `text` before its ratchet, so the level-2 plaintext inside never reaches
/// a parser that would count it as a decrypt failure.
pub fn ctl_frame_json(to_user_id: i64, message_id: &str, envelope_wire: &str) -> String {
    format!(
        "{{\"type\":\"p2p-message\",\"data\":{{\"toUserId\":{to_user_id},\"messageId\":{},\"action\":\"{CTL_ACTION}\",\"ctl\":{}}}}}",
        Value::String(message_id.to_string()),
        Value::String(envelope_wire.to_string())
    )
}

/// `{"type":"ptt-start","data":{"pttId","toUserId","wire":"<v3 envelope>"}}`
/// — a frame type a 1.0.0 client does not know and ignores.
pub fn ptt_start_frame_json(to_user_id: i64, ptt_id: &str, envelope_wire: &str) -> String {
    format!(
        "{{\"type\":\"ptt-start\",\"data\":{{\"pttId\":{},\"toUserId\":{to_user_id},\"wire\":{}}}}}",
        Value::String(ptt_id.to_string()),
        Value::String(envelope_wire.to_string())
    )
}
