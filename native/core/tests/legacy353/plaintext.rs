//! Typed plaintext of protocol v3 (03-crypto §3.5): the ONLY thing a receiver
//! renders or acts on. Everything that used to ride in clear next to the
//! ciphertext (message id, edit target, quoted reply, forwarded-from name,
//! disappearing timer, story reference) is inside the authenticated box.
//!
//! ```text
//! {"t":"chat","id","body":"<text>","reply"?:{"id","text","name"},"fwd"?:{"name"},"expire"?:N,"story"?:{"id","type","action","content"?}}
//! {"t":"file","id","body":{FileEnvelope},"reply"?,"fwd"?,"expire"?}
//! {"t":"edit","id","editOf","body":"<text>"}
//! {"t":"skdm","id","body":{SKDM v2}}
//! {"t":"hello","id"}
//! ```
//!
//! Parse is strict: known `t`, required fields of the right JSON type, no
//! field another `t` owns, no duplicate key, `reply.text` ≤ 100 UTF-16 units,
//! `expire` an integer in `[1, 2^53)`. Unknown keys are ignored.

use serde::Deserialize;
use serde_json::{json, Map, Value};

pub const REPLY_TEXT_MAX_UTF16: usize = 100;
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
}

impl TypedPlaintext {
    pub fn id(&self) -> &str {
        match self {
            TypedPlaintext::Chat { id, .. }
            | TypedPlaintext::File { id, .. }
            | TypedPlaintext::Edit { id, .. }
            | TypedPlaintext::Skdm { id, .. }
            | TypedPlaintext::Hello { id } => id,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            TypedPlaintext::Chat { .. } => "chat",
            TypedPlaintext::File { .. } => "file",
            TypedPlaintext::Edit { .. } => "edit",
            TypedPlaintext::Skdm { .. } => "skdm",
            TypedPlaintext::Hello { .. } => "hello",
        }
    }

    /// The exact JSON text (key order: t, id, editOf, body, reply, fwd, expire, story).
    pub fn to_json(&self) -> String {
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
        }
        serde_json::to_string(&Value::Object(o)).expect("typed plaintext serializes")
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

#[derive(Deserialize)]
struct W {
    t: String,
    id: String,
    #[serde(default, rename = "editOf")]
    edit_of: Option<String>,
    #[serde(default)]
    body: Option<Value>,
    #[serde(default)]
    reply: Option<WReply>,
    #[serde(default)]
    fwd: Option<WFwd>,
    #[serde(default)]
    expire: Option<u64>,
    #[serde(default)]
    story: Option<WStory>,
}

/// Strict parse; `None` for anything that is not a valid typed plaintext.
pub fn parse_typed_plaintext(text: &str) -> Option<TypedPlaintext> {
    let w: W = serde_json::from_str(text).ok()?;
    if w.id.is_empty() {
        return None;
    }
    if w.expire.is_some_and(|e| e == 0 || e > MAX_INT) {
        return None;
    }
    let reply = match w.reply {
        None => None,
        Some(r) => {
            if r.id.is_empty() || r.text.encode_utf16().count() > REPLY_TEXT_MAX_UTF16 {
                return None;
            }
            Some(Reply { id: r.id, text: r.text, name: r.name })
        }
    };
    let fwd = w.fwd.map(|f| f.name);
    let only_common = |edit_of: &Option<String>, story: &Option<WStory>| edit_of.is_none() && story.is_none();
    match w.t.as_str() {
        "chat" => {
            let Some(Value::String(body)) = w.body else { return None };
            if w.edit_of.is_some() {
                return None;
            }
            let story = match w.story {
                None => None,
                Some(s) => {
                    if s.id.is_empty() || s.action.is_empty() {
                        return None;
                    }
                    Some(StoryRef { id: s.id, story_type: s.story_type, action: s.action, content: s.content })
                }
            };
            Some(TypedPlaintext::Chat { id: w.id, body, reply, fwd, expire: w.expire, story })
        }
        "file" => {
            let Some(Value::Object(body)) = w.body else { return None };
            if !only_common(&w.edit_of, &w.story) {
                return None;
            }
            Some(TypedPlaintext::File { id: w.id, body, reply, fwd, expire: w.expire })
        }
        "edit" => {
            let Some(Value::String(body)) = w.body else { return None };
            let edit_of = w.edit_of.filter(|e| !e.is_empty())?;
            if reply.is_some() || fwd.is_some() || w.expire.is_some() || w.story.is_some() || body.is_empty() {
                return None;
            }
            Some(TypedPlaintext::Edit { id: w.id, edit_of, body })
        }
        "skdm" => {
            let Some(Value::Object(body)) = w.body else { return None };
            if reply.is_some() || fwd.is_some() || w.expire.is_some() || !only_common(&w.edit_of, &w.story) {
                return None;
            }
            Some(TypedPlaintext::Skdm { id: w.id, body })
        }
        "hello" => {
            if w.body.is_some() || reply.is_some() || fwd.is_some() || w.expire.is_some() || !only_common(&w.edit_of, &w.story) {
                return None;
            }
            Some(TypedPlaintext::Hello { id: w.id })
        }
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
