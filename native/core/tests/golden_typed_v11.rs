//! Wire level 2, the plaintext layer (wire-1.1 §W3–§W5): typedV11.json (soft
//! keys, the level-2 kinds, classification, outer agreement),
//! unsupportedV11.json (an authenticated unknown kind is an outcome, never a
//! failure; stale positions; the aux; the skip budget) and capsV11.json (the
//! signed capability statement). See tests/common for the write/verify mode.

mod common;

use common::*;
use mrenzo_core::caps::{self, Caps, StatementCheck};
use mrenzo_core::nearby::NearbyOp;
use mrenzo_core::plaintext::*;
use mrenzo_core::primitives::b64;
use mrenzo_core::ptt::PttKey;
use mrenzo_core::ratchet::Envelope;
use mrenzo_core::rng::StreamRng;
use mrenzo_core::session_set::{PeerSessions, SetDecrypt, SetEncryptError, SetOpen, LOSSY_RUN_MAX};
use serde_json::{json, Map, Value};

fn chat(id: &str, body: &str) -> TypedPlaintext {
    TypedPlaintext::Chat { id: id.into(), body: body.into(), reply: None, fwd: None, expire: None, story: None }
}

fn own_caps() -> Caps {
    Caps::own(&["pq", "ptt"]).unwrap()
}

fn class_json(c: &Classified) -> Value {
    match c {
        Classified::Typed(p) => json!({
            "class": "typed", "t": p.pt.kind(), "id": p.pt.id(), "level": p.pt.level(), "lossy": p.pt.is_lossy(),
            "own": p.pt.to_json(),
            "caps": p.soft.caps.as_ref().map(|c| c.to_json()),
            "alt": p.soft.alt,
            "nearbyInvite": p.soft.nearby.as_ref().map(|n| n.to_json()),
        }),
        Classified::Unsupported(u) => json!({
            "class": "unsupported", "t": u.t, "id": u.id, "alt": u.alt, "caps": u.caps.as_ref().map(|c| c.to_json()),
        }),
    }
}

#[test]
fn typed_v11_vectors() {
    let ns = [0x11u8; 16];
    let invite = NearbyOp::Invite { ns, exp: 1_790_000_300_000 };
    let accept = NearbyOp::Accept { ns, exp: 1_790_000_300_000, tok: vec![0xa5; 40] };
    let stop = NearbyOp::Stop { ns, why: Some("ended".into()) };
    let ptt_id = "0f8fad5b-d9cb-469f-a165-70867728950e";
    let key = PttKey { k: [0x42; 32], codec: "opus".into(), sr: 16_000 };

    // ── caps ──
    let canonical: Vec<Value> = [vec![], vec!["pq"], vec!["ptt", "pq"]]
        .iter()
        .map(|flags| json!({"flags": flags, "json": Caps::own(flags).unwrap().to_json()}))
        .collect();
    assert_eq!(canonical[2]["json"], r#"{"v":2,"f":["pq","ptt"]}"#, "tokens are sorted");
    assert_eq!(canonical[0]["json"], r#"{"v":2}"#, "f is omitted when empty");
    let lenient: Vec<Value> = [
        r#"{"v":2,"f":["pq","ptt"]}"#,
        r#"{"v":2}"#,
        r#"{"v":7,"f":["ptt","pq","pq","BAD","-x",7,"x-1"],"future":true}"#,
        r#"{"v":2,"f":"pq"}"#,
        r#"{"v":1}"#,
        r#"{"v":65536}"#,
        r#"{"v":2.0}"#,
        r#"{"v":"2"}"#,
        r#"{"f":["pq"]}"#,
        r#"["pq"]"#,
        r#"2"#,
    ]
    .iter()
    .map(|text| json!({"in": text, "out": Caps::parse_lenient(text).map(|c| c.to_json())}))
    .collect();
    assert_eq!(lenient[2]["out"], r#"{"v":7,"f":["pq","ptt","x-1"]}"#);
    assert!(lenient[4]["out"].is_null() && lenient[6]["out"].is_null() && lenient[9]["out"].is_null());

    // ── builders ──
    let soft = |nearby: Option<NearbyOp>, alt: Option<&str>| Soft { caps: Some(own_caps()), alt: alt.map(str::to_string), nearby, silent: false };
    let mut built: Vec<Value> = Vec::new();
    let mut add = |name: &str, pt: &TypedPlaintext, s: &Soft, pad: Option<usize>| -> String {
        let json = build(pt, s, pad).unwrap_or_else(|| panic!("{name} builds"));
        built.push(json!({"name": name, "own": pt.to_json(), "padBlock": pad, "json": json}));
        json
    };
    let plain = add("chat", &chat("m-1", "Привет"), &Soft::default(), None);
    assert_eq!(plain, chat("m-1", "Привет").to_json(), "without soft keys the bytes are those of 1.0.0");
    let with_caps = add("chat+caps", &chat("m-1", "Привет"), &soft(None, None), None);
    assert_eq!(with_caps, r#"{"t":"chat","id":"m-1","body":"Привет","caps":{"v":2,"f":["pq","ptt"]}}"#);
    let invite_json = add("chat+nearby invite+alt+caps", &chat("m-2", "Давай найдёмся"), &soft(Some(invite.clone()), Some("fallback")), None);
    assert!(invite_json.ends_with(r#""alt":"fallback","caps":{"v":2,"f":["pq","ptt"]}}"#), "order: own keys, nearby, alt, caps");
    add("hello+caps", &TypedPlaintext::Hello { id: "h-1".into() }, &soft(None, None), None);
    let react = TypedPlaintext::React { id: "rx-1".into(), to: "m-1".into(), e: vec!["❤️".into()], ts: 1_790_000_000_000 };
    let react_json = add("react", &react, &soft(None, None), Some(64));
    assert_eq!(react_json.len() % 64, 0);
    let removed = TypedPlaintext::React { id: "rx-2".into(), to: "m-1".into(), e: vec![], ts: 1_790_000_000_001 };
    let removed_json = add("react removed", &removed, &soft(None, None), Some(64));
    assert_eq!(react_json.len(), removed_json.len(), "an emoji and a removal have one length");
    // The padded length is that of the longest legal `e`, whatever `e` is — it depends on the
    // ids, `ts` and `caps` only. (Padding to the NEXT block did not give that: with these caps a
    // ZWJ sequence landed one block above ❤️, and with other caps a flag did.)
    let longest: Vec<String> = ["a", "b", "c"].iter().map(|c| c.repeat(64)).collect();
    let es: Vec<Vec<String>> = vec![
        vec![],
        vec!["❤️".into()],
        vec!["👨‍👩‍👧‍👦".into()],
        vec!["👩‍❤️‍💋‍👨".into()],
        vec!["🏴󠁧󠁢󠁥󠁮󠁧󠁿".into()],
        vec!["👍".into(), "🔥".into(), "👨‍👩‍👧‍👦".into()],
        longest.clone(),
    ];
    for caps in [None, Some(Caps::own(&["pq"]).unwrap()), Some(Caps::own(&["pq", "ptt"]).unwrap())] {
        let keys = Soft { caps: caps.clone(), ..Default::default() };
        let react_of = |e: &Vec<String>| TypedPlaintext::React { id: "rx-0f8fad5b-d9cb-469f-a165-70867728950e".into(), to: "7c9e6679-7425-40de-944b-e07fc1f90ae7".into(), e: e.clone(), ts: 1_790_000_000_000 };
        let lens: Vec<usize> = es.iter().map(|e| build(&react_of(e), &keys, Some(64)).expect("builds").len()).collect();
        let unpadded_longest = build(&react_of(&longest), &keys, None).unwrap().len();
        assert!(lens.iter().all(|l| *l == lens[0]), "caps {caps:?}: {lens:?}");
        assert_eq!(lens[0], (unpadded_longest + 7).div_ceil(64) * 64, "the smallest multiple of 64 that holds the longest e and an empty p");
        for e in &es {
            let json = build(&react_of(e), &keys, Some(64)).unwrap();
            assert!(json.contains(",\"p\":\"") && json.ends_with("\"}"), "p is always written, last");
            assert!(matches!(classify(&json), Classified::Typed(p) if p.pt == react_of(e) && p.soft == keys));
        }
    }
    let longest_json = add("react, the longest e", &TypedPlaintext::React { id: "rx-3".into(), to: "m-1".into(), e: longest.clone(), ts: 1_790_000_000_002 }, &soft(None, None), Some(64));
    assert_eq!(longest_json.len(), react_json.len());
    add("nearby accept", &TypedPlaintext::Nearby { id: "nb-1".into(), nearby: accept.clone() }, &soft(None, None), None);
    add("nearby stop", &TypedPlaintext::Nearby { id: "nb-2".into(), nearby: stop.clone() }, &soft(None, None), None);
    let ptt_json = add("ptt", &TypedPlaintext::Ptt { id: ptt_id.into(), ptt: key.clone() }, &soft(None, None), None);
    // What a builder must refuse.
    assert!(build(&TypedPlaintext::Nearby { id: "x".into(), nearby: invite.clone() }, &Soft::default(), None).is_none(), "an invite is a chat, never a control kind");
    assert!(build(&TypedPlaintext::Hello { id: "x".into() }, &Soft { nearby: Some(invite.clone()), ..Default::default() }, None).is_none(), "an invite rides only on a chat");
    assert!(build(&chat("x", "b"), &Soft { nearby: Some(accept.clone()), ..Default::default() }, None).is_none(), "only an invite rides on a chat");
    assert!(build(&chat("x", "b"), &Soft { alt: Some("é".repeat(257)), ..Default::default() }, None).is_none(), "alt over 256 UTF-16 units");
    assert!(build(&TypedPlaintext::Ptt { id: "not-a-uuid".into(), ptt: key.clone() }, &Soft::default(), None).is_none());
    assert!(build(&TypedPlaintext::React { id: "r".into(), to: "".into(), e: vec![], ts: 1 }, &Soft::default(), None).is_none());

    // ── classification ──
    let cases: Vec<(&str, String)> = vec![
        ("chat as 1.0.0 writes it", plain.clone()),
        ("chat with caps", with_caps.clone()),
        ("chat with an invite", invite_json.clone()),
        ("react", react_json.clone()),
        ("ptt", ptt_json.clone()),
        ("soft keys malformed: absent, never a failure", r#"{"t":"chat","id":"m","body":"b","caps":{"v":"2"},"alt":7,"nearby":{"v":1,"op":"accept"},"p":5}"#.into()),
        ("unknown top-level keys are ignored", r#"{"t":"hello","id":"h","future":{"a":[1,2]}}"#.into()),
        ("unknown t", r#"{"t":"poll","id":"p-1","q":"?","alt":"Опрос","caps":{"v":3,"f":["polls"]}}"#.into()),
        ("unknown t, no id", r#"{"t":"poll"}"#.into()),
        ("known t, missing body", r#"{"t":"chat","id":"m"}"#.into()),
        ("known t, a field another kind owns", r#"{"t":"hello","id":"h","body":"b"}"#.into()),
        ("level-2 kind with a level-1 field", r#"{"t":"react","id":"r","to":"m","e":[],"ts":5,"body":"x"}"#.into()),
        ("react: four emoji", r#"{"t":"react","id":"r","to":"m","e":["1","2","3","4"],"ts":5}"#.into()),
        ("react: a duplicate in the set", r#"{"t":"react","id":"r","to":"m","e":["a","a"],"ts":5}"#.into()),
        ("react: ts not an integer", r#"{"t":"react","id":"r","to":"m","e":[],"ts":5.0}"#.into()),
        ("nearby kind carrying an invite", format!(r#"{{"t":"nearby","id":"n","nearby":{}}}"#, invite.to_json())),
        ("ptt: id is not a UUIDv4", format!(r#"{{"t":"ptt","id":"abc","ptt":{}}}"#, key.to_value())),
        ("ptt: sample rate out of range", format!(r#"{{"t":"ptt","id":"{ptt_id}","ptt":{{"v":1,"k":"{}","codec":"opus","sr":4000}}}}"#, b64(&key.k))),
        ("duplicate key at the top", r#"{"t":"chat","id":"m","id":"m","body":"b"}"#.into()),
        ("duplicate key in depth", r#"{"t":"file","id":"m","body":{"fileId":"a","fileId":"b"}}"#.into()),
        ("not an object", r#"["chat"]"#.into()),
        ("not JSON", "hello".into()),
        ("empty id", r#"{"t":"chat","id":"","body":"b"}"#.into()),
    ];
    let mut classified: Vec<Value> = Vec::new();
    for (name, text) in &cases {
        let c = classify(text);
        // The 1.0.0-shaped entry point agrees: a kind or nothing.
        assert_eq!(parse_typed_plaintext(text).is_some(), matches!(c, Classified::Typed(_)), "{name}");
        classified.push(json!({"name": name, "plaintext": text, "result": class_json(&c)}));
    }
    let class = |i: usize| classified[i]["result"]["class"].as_str().unwrap().to_string();
    assert!((0..7).all(|i| class(i) == "typed"));
    assert!((7..cases.len()).all(|i| class(i) == "unsupported"));
    assert!(classified[5]["result"]["caps"].is_null() && classified[5]["result"]["alt"].is_null() && classified[5]["result"]["nearbyInvite"].is_null());
    assert_eq!(classified[7]["result"], json!({"class":"unsupported","t":"poll","id":"p-1","alt":"Опрос","caps":"{\"v\":3,\"f\":[\"polls\"]}"}));
    assert_eq!(classified[8]["result"]["id"], Value::Null);
    let too_long = format!(r#"{{"t":"chat","id":"m","body":"{}"}}"#, "x".repeat(MAX_PLAINTEXT_BYTES));
    assert!(matches!(classify(&too_long), Classified::Unsupported(u) if u == Unsupported::default()), "over 48 KiB: not parsed at all");
    assert!(matches!(classify_bytes(&[0xff, 0xfe]), Classified::Unsupported(u) if u == Unsupported::default()), "not UTF-8");

    // ── outer agreement: each kind is accepted by exactly one carrier check ──
    let mut outer: Vec<Value> = Vec::new();
    let edit = TypedPlaintext::Edit { id: "e-1".into(), edit_of: "m-1".into(), body: "fixed".into() };
    for (name, pt, id) in [
        ("chat", chat("m-1", "b"), "m-1"),
        ("hello", TypedPlaintext::Hello { id: "h-1".into() }, "h-1"),
        ("edit", edit.clone(), "m-1"),
        ("react", react.clone(), "rx-1"),
        ("nearby accept", TypedPlaintext::Nearby { id: "nb-1".into(), nearby: accept.clone() }, "nb-1"),
        ("ptt", TypedPlaintext::Ptt { id: ptt_id.into(), ptt: key.clone() }, ptt_id),
    ] {
        let row = json!({
            "kind": name, "outerId": id,
            "p2p(no action)": outer_matches_p2p(&pt, id, None, None),
            "p2p(session-hello)": outer_matches_p2p(&pt, id, Some("session-hello"), None),
            "edit": outer_matches_edit(&pt, id),
            "ctl": outer_matches_ctl(&pt, id),
            "meshCtl": outer_matches_mesh_ctl(&pt, id),
            "ptt": outer_matches_ptt(&pt, id),
            "ctl(other id)": outer_matches_ctl(&pt, "other"),
        });
        let accepted = ["p2p(no action)", "p2p(session-hello)", "edit", "ctl", "ptt"].iter().filter(|k| row[**k] == true).count();
        assert_eq!(accepted, 1, "{name} belongs to exactly one carrier");
        assert_eq!(row["ctl(other id)"], false);
        outer.push(row);
    }
    assert_eq!(outer[3]["ctl"], true);
    assert_eq!(outer[3]["meshCtl"], false, "a reaction is not on the mesh allow-list");
    assert_eq!(outer[4]["meshCtl"], true);
    assert_eq!(outer[5]["ptt"], true);

    let mut v = header_v11(
        "typedV11",
        &[
            "Mandatory for every kind: a JSON object ≤ 48 KiB, no duplicate key at any depth, \"t\" a string, \"id\" a non-empty string. Everything else that authenticates is `unsupported` — an outcome, never a decrypt failure.",
            "Soft keys on every kind, parsed leniently (malformed = absent): caps {\"v\":2..65535,\"f\":[tokens]}, alt (≤ 256 UTF-16 units), p (padding, ignored); on a chat: nearby with op invite.",
            "Serialization: the kind's own keys (for a level-1 kind byte for byte what 1.0.0 writes), then nearby, alt, caps, p. A react is padded with \"p\":\"<spaces>\" to a multiple of 64 UTF-8 bytes.",
            "Level-2 kinds (react, nearby, ptt) never carry body, editOf, reply, fwd, expire or story, and never travel in a field a 1.0.0 client feeds to its ratchet (the outer table: one carrier per kind).",
        ],
    );
    v.insert("caps".into(), json!({"canonical": canonical, "lenient": lenient}));
    v.insert("built".into(), Value::Array(built));
    v.insert("classified".into(), Value::Array(classified));
    v.insert("outer".into(), Value::Array(outer));
    check_or_write("typedV11.json", &Value::Object(v));
}

fn state_json(set: &PeerSessions) -> Value {
    serde_json::from_str(&set.live().unwrap().session.to_json()).unwrap()
}

fn open_label(o: &SetOpen) -> &'static str {
    match o {
        SetOpen::Typed { .. } => "typed",
        SetOpen::Unsupported { .. } => "unsupported",
        SetOpen::Stale => "stale",
        SetOpen::NoSession => "noSession",
        SetOpen::Failed => "failed",
        SetOpen::NeedsResponder => "needsResponder",
        SetOpen::TooManySkipped => "tooManySkipped",
    }
}

#[test]
fn unsupported_and_stale_vectors() {
    let mut t = linked("v11/u");
    let now = T0 + 1000;
    let mut steps: Vec<Value> = Vec::new();

    // Alice (a later build) sends a kind this build does not know.
    let poll = r#"{"t":"poll","id":"p-1","q":"Куда идём?","opts":["А","Б"],"alt":"Опрос: Куда идём?","caps":{"v":3,"f":["polls"]}}"#;
    let w_poll = t.sa.encrypt(poll, now, &mut StreamRng::new("v11/u/poll")).unwrap().to_wire();
    let before = t.sb.clone();
    let out = t.sb.open(&Envelope::parse(&w_poll).unwrap(), now, &mut StreamRng::new("v11/u/b1"));
    let SetOpen::Unsupported { raw, what, by } = &out else { panic!("{out:?}") };
    assert_eq!(raw.as_deref(), Some(poll), "the authenticated text is handed to the host to keep");
    assert_eq!((what.t.as_deref(), what.id.as_deref(), what.alt.as_deref()), (Some("poll"), Some("p-1"), Some("Опрос: Куда идём?")));
    assert_eq!(what.caps.as_ref().unwrap().v, 3);
    assert!(!by.promoted && !by.created);
    assert_ne!(t.sb, before, "the ratchet step IS consumed");
    steps.push(json!({"op": "open", "by": "bob", "wire": w_poll, "rngLabel": "v11/u/b1", "nowMs": now, "outcome": "unsupported",
        "raw": raw, "t": what.t, "id": what.id, "alt": what.alt, "caps": what.caps.as_ref().map(|c| c.to_json()), "stateAfter": state_json(&t.sb)}));
    // The 1.0.0-shaped entry point: `Opened` with the raw text (its caller's own typed parse then fails, uncounted).
    let mut legacy = before.clone();
    assert!(matches!(legacy.decrypt(&Envelope::parse(&w_poll).unwrap(), now, &mut StreamRng::new("v11/u/b1")), SetDecrypt::Opened { plaintext, .. } if plaintext == poll));
    assert_eq!(legacy.entries[0].session, t.sb.entries[0].session, "same state either way");

    // The session is intact: the next ordinary message opens.
    let chat1 = build(&chat("m-1", "после опроса"), &Soft { caps: Some(own_caps()), ..Default::default() }, None).unwrap();
    let w_chat = t.sa.encrypt(&chat1, now + 1, &mut StreamRng::new("v11/u/chat")).unwrap().to_wire();
    let out = t.sb.open(&Envelope::parse(&w_chat).unwrap(), now + 1, &mut StreamRng::new("v11/u/b2"));
    assert!(matches!(&out, SetOpen::Typed { plaintext, parsed, .. } if *plaintext == chat1 && parsed.soft.caps == Some(own_caps())));
    steps.push(json!({"op": "open", "by": "bob", "wire": w_chat, "rngLabel": "v11/u/b2", "nowMs": now + 1, "outcome": "typed", "plaintext": chat1}));

    // Stale 1: a duplicate on the CURRENT receiving chain.
    let dup = t.sb.open(&Envelope::parse(&w_poll).unwrap(), now + 2, &mut StreamRng::new("v11/u/dup1"));
    assert_eq!(dup, SetOpen::Stale);
    assert!(t.sb.is_stale(&Envelope::parse(&w_poll).unwrap()));
    steps.push(json!({"op": "open", "by": "bob", "wire": w_poll, "nowMs": now + 2, "outcome": "stale", "why": "a position of the current chain below its counter"}));

    // A DH step in both directions.
    let w_b = t.sb.encrypt(&chat("b-1", "ответ").to_json(), now + 3, &mut StreamRng::new("v11/u/b-send")).unwrap().to_wire();
    assert!(matches!(t.sa.open(&Envelope::parse(&w_b).unwrap(), now + 3, &mut StreamRng::new("v11/u/a-recv-reply")), SetOpen::Typed { .. }));
    let w_a2 = t.sa.encrypt(&chat("m-2", "новая цепочка").to_json(), now + 4, &mut StreamRng::new("v11/u/a2")).unwrap().to_wire();
    let no_aux_before = PeerSessions { aux_enabled: false, ..t.sb.clone() };
    assert!(matches!(t.sb.open(&Envelope::parse(&w_a2).unwrap(), now + 4, &mut StreamRng::new("v11/u/b3")), SetOpen::Typed { .. }));
    let aux = t.sb.aux_json();
    assert_eq!(t.sb.entries[0].aux.retired.len(), 2, "both ratchet keys Alice has left so far (her ephemeral, then the first reply key) are remembered");
    steps.push(json!({"op": "dhStep", "note": "Bob replied, Alice answered on a new ratchet key; Bob's aux now names the key he retired", "auxAfter": aux}));

    // Stale 2: the same duplicate AFTER the DH step — the reactions blocker.
    let dup = t.sb.open(&Envelope::parse(&w_poll).unwrap(), now + 5, &mut StreamRng::new("v11/u/dup2"));
    assert_eq!(dup, SetOpen::Stale, "a duplicate across a DH step is stale, not a counted failure");
    assert!(t.sb.is_stale(&Envelope::parse(&w_poll).unwrap()));
    steps.push(json!({"op": "open", "by": "bob", "wire": w_poll, "nowMs": now + 5, "outcome": "stale", "why": "its ratchet key is in the retired list of the aux"}));
    // The aux survives the host's storage round trip.
    let reloaded = PeerSessions::from_rows_aux(&t.sb.rows(), Some(&aux), now + 5);
    assert_eq!(reloaded.aux_json(), aux);
    assert_eq!(reloaded.clone().open(&Envelope::parse(&w_poll).unwrap(), now + 5, &mut StreamRng::new("x")), SetOpen::Stale);
    // Without an aux (a host that keeps none, or 1.0.0): the cross-chain replay is a counted failure.
    let mut no_aux = no_aux_before;
    assert!(matches!(no_aux.open(&Envelope::parse(&w_a2).unwrap(), now + 4, &mut StreamRng::new("v11/u/b3")), SetOpen::Typed { .. }));
    assert_eq!(no_aux.open(&Envelope::parse(&w_poll).unwrap(), now + 5, &mut StreamRng::new("v11/u/dup2")), SetOpen::Failed);
    assert!(!no_aux.is_stale(&Envelope::parse(&w_poll).unwrap()));
    steps.push(json!({"op": "open", "by": "bob (no aux)", "wire": w_poll, "nowMs": now + 5, "outcome": "failed", "why": "without the aux a cross-chain replay cannot be told from a forgery"}));
    // A forgery is still a failure: one flipped ciphertext bit on the live chain.
    let mut forged: Value = serde_json::from_str(&w_a2).unwrap();
    forged["n"] = json!(forged["n"].as_u64().unwrap() + 1);
    assert_eq!(t.sb.open(&Envelope::parse(&forged.to_string()).unwrap(), now + 6, &mut StreamRng::new("x")), SetOpen::Failed);
    // A reload from garbage aux is an empty aux, not an error.
    for bad in ["", "{", "[]", r#"{"v":2,"s":{}}"#, r#"{"v":1,"s":7}"#, r#"{"v":1,"s":{"x":{"r":["AAAA"],"l":-1}}}"#] {
        assert_eq!(PeerSessions::from_rows_aux(&t.sb.rows(), Some(bad), now).entries[0].aux, Default::default(), "{bad}");
    }

    // ── the skip budget (§W3.5) ──
    let react = |i: u32| build(&TypedPlaintext::React { id: format!("rx-{i}"), to: "m-1".into(), e: vec!["👍".into()], ts: 1_790_000_000_000 + i as u64 }, &Soft::default(), Some(64)).unwrap();
    let mut r = StreamRng::new("v11/u/budget");
    let mut last = String::new();
    for i in 0..LOSSY_RUN_MAX {
        last = t.sa.encrypt_counted(&react(i), true, now + 10, &mut r).unwrap().to_wire();
    }
    let at_limit = t.sa.clone();
    assert_eq!(t.sa.encrypt_counted(&react(999), true, now + 10, &mut r).unwrap_err(), SetEncryptError::SkipBudget);
    assert_eq!(t.sa, at_limit, "a refused step consumes nothing");
    assert!(t.sa.aux_json().contains("\"l\":256"));
    // One universal message resets the run, and the receiver — who saw none of the 256 — still opens it.
    let hello = TypedPlaintext::Hello { id: "h-2".into() }.to_json();
    let w_hello = t.sa.encrypt_counted(&hello, false, now + 11, &mut r).unwrap().to_wire();
    assert!(t.sa.encrypt_counted(&react(1000), true, now + 11, &mut r).is_ok());
    let out = t.sb.open(&Envelope::parse(&w_hello).unwrap(), now + 12, &mut StreamRng::new("v11/u/b-budget"));
    assert_eq!(open_label(&out), "typed", "256 skipped positions are inside the receiver's 1000-step bound");
    // And one of the skipped control frames still opens late, from its stored key.
    assert_eq!(open_label(&t.sb.open(&Envelope::parse(&last).unwrap(), now + 13, &mut StreamRng::new("x"))), "typed");
    // Without an aux nothing is counted (the 1.0.0 behaviour).
    let mut free = PeerSessions { aux_enabled: false, ..at_limit };
    assert!(free.encrypt_counted(&react(1), true, now, &mut r).is_ok());
    assert!(t.sa.note_peer_progress(&t.sa.live().unwrap().session.sid.clone()));

    let mut v = header_v11(
        "unsupportedV11",
        &[
            "Keys and prekeys = x3dhV2.json; the session is set up by tests/common `linked(\"v11/u\")` (Alice initiates with the OPK, one hello each way, both sides keep an aux).",
            "open order per session: a stored skipped key for (dh, n); the current chain with n below its counter → stale; a ratchet key in the aux's retired list → stale; else the chain walk or DH step, failed when the MAC does not verify.",
            "Outcomes: typed / unsupported advance the ratchet and are never counted; stale never counts; failed is the only counted one. Precedence over candidate sessions: typed/unsupported > stale > tooManySkipped > failed.",
            "aux = {\"v\":1,\"s\":{\"<sid b64>\":{\"r\":[\"<b64 8-byte prefix of a retired peer ratchet key>\",…],\"l\":<lossy run>}}} — kept by the host beside the session rows, never inside the session JSON.",
            "Skip budget: react, nearby, ptt and edit are lossy; at 256 lossy steps in a row the next one is refused (skip-budget) until a universal message (chat, file, skdm, hello) is sent.",
        ],
    );
    v.insert("keys".into(), json!({"alice": t.a.json(), "bob": t.b.json()}));
    v.insert("bobStateBefore".into(), state_json(&before));
    v.insert("steps".into(), Value::Array(steps));
    v.insert("skipBudget".into(), json!({"lossyRunMax": LOSSY_RUN_MAX, "refusal": "skip-budget", "lossyKinds": ["react", "nearby", "ptt", "edit"], "universalKinds": ["chat", "file", "skdm", "hello"]}));
    check_or_write("unsupportedV11.json", &Value::Object(v));
}

#[test]
fn caps_statement_vectors() {
    let (a, b) = (alice(), bob());
    let caps = Caps::own(&["pq"]).unwrap();
    let ts = T0 as u64;
    let statement = caps::statement_sign(&a.ed_secret, a.uid as u64, &caps, ts);
    let canonical = caps::statement_canonical(a.uid as u64, &caps, ts);
    assert_eq!(canonical, format!("mrenzo-caps-v1|1001|2|pq|{ts}"));
    let verify = |json: &str, uid: i64, ed: &[u8; 32], min_ts: u64, now: i64| caps::statement_verify(json, uid as u64, ed, min_ts, now);
    assert_eq!(verify(&statement, a.uid, &a.ed_pub, 0, T0), StatementCheck::Ok { caps: caps.clone(), ts });

    let label = |c: &StatementCheck| match c {
        StatementCheck::Ok { .. } => "ok",
        StatementCheck::Malformed => "malformed",
        StatementCheck::WrongUid => "wrongUid",
        StatementCheck::Future => "future",
        StatementCheck::Stale => "stale",
        StatementCheck::BadSignature => "badSignature",
    };
    let mut cases: Vec<Value> = Vec::new();
    let mut case = |name: &str, json: &str, uid: i64, ed: &[u8; 32], min_ts: u64, now: i64, want: &str| {
        let got = verify(json, uid, ed, min_ts, now);
        assert_eq!(label(&got), want, "{name}");
        cases.push(json!({"name": name, "statement": json, "expectUid": uid, "pinnedEdB64": b64(ed), "minTs": min_ts, "nowMs": now, "expect": want}));
    };
    case("valid", &statement, a.uid, &a.ed_pub, 0, T0, "ok");
    case("valid at the newest accepted ts", &statement, a.uid, &a.ed_pub, ts, T0, "ok");
    case("served for another user", &statement, b.uid, &b.ed_pub, 0, T0, "wrongUid");
    case("not signed by the pinned key", &statement, a.uid, &b.ed_pub, 0, T0, "badSignature");
    case("replayed below the newest accepted ts", &statement, a.uid, &a.ed_pub, ts + 1, T0, "stale");
    case("dated more than 5 minutes ahead", &statement, a.uid, &a.ed_pub, 0, T0 - 300_001, "future");
    case("5 minutes ahead exactly is accepted", &statement, a.uid, &a.ed_pub, 0, T0 - 300_000, "ok");
    let tampered = statement.replace(r#""f":["pq"]"#, r#""f":["pq","ptt"]"#);
    case("a flag added after signing", &tampered, a.uid, &a.ed_pub, 0, T0, "badSignature");
    let level = statement.replace(r#""caps":{"v":2,"#, r#""caps":{"v":3,"#);
    case("the level raised after signing", &level, a.uid, &a.ed_pub, 0, T0, "badSignature");
    let unsorted = caps::statement_sign(&a.ed_secret, a.uid as u64, &Caps::own(&["pq", "ptt"]).unwrap(), ts).replace(r#"["pq","ptt"]"#, r#"["ptt","pq"]"#);
    case("caps not in canonical form", &unsorted, a.uid, &a.ed_pub, 0, T0, "malformed");
    case("duplicate key", &statement.replacen("{\"v\":1,", "{\"v\":1,\"v\":1,", 1), a.uid, &a.ed_pub, 0, T0, "malformed");
    case("another statement version", &statement.replacen("{\"v\":1,", "{\"v\":2,", 1), a.uid, &a.ed_pub, 0, T0, "malformed");
    case("not JSON", "caps", a.uid, &a.ed_pub, 0, T0, "malformed");
    let big = format!("{}{}", statement, " ".repeat(1024));
    case("over 1 KiB", &big, a.uid, &a.ed_pub, 0, T0, "malformed");
    // The extremes of `now` cannot overflow.
    assert_eq!(label(&verify(&statement, a.uid, &a.ed_pub, 0, i64::MAX)), "ok");
    assert_eq!(label(&verify(&statement, a.uid, &a.ed_pub, 0, i64::MIN)), "future");

    let mut v = header_v11(
        "capsV11",
        &[
            "statement = {\"v\":1,\"uid\",\"caps\":{\"v\",\"f\"},\"ts\",\"sig\"}; canonical = \"mrenzo-caps-v1|\" + uid + \"|\" + caps.v + \"|\" + join(\",\", caps.f) + \"|\" + ts; sig = Ed25519(ED_uid, UTF-8(canonical)), verified strictly under the PINNED signing key of uid.",
            "Accepted when: the shape is canonical (no duplicate key, ≤ 1 KiB, caps sorted and unique), uid is the expected peer, ts ≤ now + 5 min, ts ≥ the newest ts already accepted under this pin, and the signature verifies.",
            "A statement is an optimisation: the server can withhold or replay it, never forge it. The same caps object rides in band on every plaintext of a 1:1 session.",
        ],
    );
    v.insert("keys".into(), json!({"alice": a.json(), "bob": b.json()}));
    v.insert("statement".into(), json!({"uid": a.uid, "capsJson": caps.to_json(), "ts": ts, "canonical": canonical, "json": statement}));
    v.insert("cases".into(), Value::Array(cases));
    check_or_write("capsV11.json", &Value::Object(v));
}

/// A `ctl` frame's id is one the server's duplicate claim can key
/// (`db.IdempotentMessageID` at 781eee60: 1..128 of `[A-Za-z0-9_-]`).
#[test]
fn a_ctl_message_id_is_one_the_server_can_key() {
    for ok in ["rx-0f8fad5b-d9cb-469f-a165-70867728950e", "a", "A_b-9", &"x".repeat(128)] {
        assert!(mrenzo_core::plaintext::is_ctl_message_id(ok), "{ok}");
    }
    for bad in ["", "rx 1", "rx.1", "rx|1", "rx/1", "ид", "rx\n", &"x".repeat(129)] {
        assert!(!mrenzo_core::plaintext::is_ctl_message_id(bad), "{bad}");
    }
}

/// The must-have test of the reactions plan: decrypt, a DH step in both
/// directions, the same control frame delivered again (WS replay + HTTP
/// backlog) → nothing a host counts, no archived session.
#[test]
fn a_duplicate_control_frame_never_looks_like_a_failure() {
    let mut t = linked("v11/dup");
    let react = build(&TypedPlaintext::React { id: "rx-1".into(), to: "m-1".into(), e: vec!["🔥".into()], ts: 5 }, &Soft::default(), Some(64)).unwrap();
    let wire = t.sa.encrypt_counted(&react, true, T0, &mut StreamRng::new("v11/dup/rx")).unwrap().to_wire();
    let env = Envelope::parse(&wire).unwrap();
    assert!(matches!(t.sb.open(&env, T0, &mut StreamRng::new("d1")), SetOpen::Typed { .. }));
    let mut map = Map::new();
    for round in 0..3 {
        // A full round trip: both sides step their DH ratchet.
        let w = t.sb.encrypt(&chat(&format!("b{round}"), "x").to_json(), T0, &mut StreamRng::new(&format!("d/b{round}"))).unwrap().to_wire();
        assert!(matches!(t.sa.open(&Envelope::parse(&w).unwrap(), T0, &mut StreamRng::new(&format!("d/a{round}"))), SetOpen::Typed { .. }));
        let w = t.sa.encrypt(&chat(&format!("a{round}"), "x").to_json(), T0, &mut StreamRng::new(&format!("d/a-send{round}"))).unwrap().to_wire();
        assert!(matches!(t.sb.open(&Envelope::parse(&w).unwrap(), T0, &mut StreamRng::new(&format!("d/b-recv{round}"))), SetOpen::Typed { .. }));
        let before = t.sb.clone();
        let again = t.sb.open(&env, T0, &mut StreamRng::new("d/dup"));
        assert_eq!(again, SetOpen::Stale, "round {round}");
        assert_eq!(t.sb, before, "a stale envelope changes nothing");
        map.insert(format!("round{round}"), json!(open_label(&again)));
    }
    assert_eq!(t.sb.entries.len(), 1, "no session was archived");
}

/// «Отправить без звука» (wire-1.1 §W7.9): the authenticated copy of the
/// outer hint is a soft key of a message. A message sent the ordinary way
/// is byte for byte the 1.0.0 plaintext; only JSON `true` on a `chat` or a
/// `file` counts; no other kind can be built with it.
#[test]
fn silent_is_a_soft_key_of_a_message_and_of_nothing_else() {
    let silent = Soft { silent: true, ..Default::default() };
    let pt = chat("m1", "тихо");
    // Without the choice nothing is written: the 1.0.0 bytes.
    assert_eq!(build(&pt, &Soft::default(), None).unwrap(), pt.to_json());
    assert_eq!(pt.to_json(), r#"{"t":"chat","id":"m1","body":"тихо"}"#);
    // With it: one more top-level key, after the kind's own.
    let json = build(&pt, &silent, None).unwrap();
    assert_eq!(json, r#"{"t":"chat","id":"m1","body":"тихо","silent":true}"#);
    assert!(matches!(classify(&json), Classified::Typed(p) if p.pt == pt && p.soft == silent));
    // Beside the other soft keys, and under the padding.
    let all = Soft { caps: Some(own_caps()), alt: Some("alt".into()), nearby: None, silent: true };
    let padded = build(&pt, &all, Some(64)).unwrap();
    assert_eq!(padded.len() % 64, 0);
    assert!(matches!(classify(&padded), Classified::Typed(p) if p.soft == all));
    // A file carries it too.
    let mut body = Map::new();
    body.insert("kind".into(), json!("image"));
    let file = TypedPlaintext::File { id: "f1".into(), body, reply: None, fwd: None, expire: None };
    assert!(build(&file, &silent, None).unwrap().ends_with(r#","silent":true}"#));
    // Anything but `true` is an absent key — and the message is still a message.
    for other in [r#""true""#, "1", "false", "null", "[true]", r#"{"v":true}"#] {
        let text = format!(r#"{{"t":"chat","id":"m1","body":"тихо","silent":{other}}}"#);
        assert!(matches!(classify(&text), Classified::Typed(p) if p.pt == pt && !p.soft.silent), "{other}");
    }
    // An edit, a hello, a key hand-over and the control kinds announce nothing: read as absent, never built.
    let quiet_nothing = [
        TypedPlaintext::Edit { id: "e1".into(), edit_of: "m1".into(), body: "правка".into() },
        TypedPlaintext::Hello { id: "h1".into() },
        TypedPlaintext::React { id: "r1".into(), to: "m1".into(), e: vec!["👍".into()], ts: 5 },
    ];
    for pt in quiet_nothing {
        assert!(build(&pt, &silent, None).is_none(), "{}", pt.kind());
        let mut o: Map<String, Value> = serde_json::from_str(&pt.to_json()).unwrap();
        o.insert("silent".into(), json!(true));
        let read = classify(&Value::Object(o).to_string());
        assert!(matches!(&read, Classified::Typed(p) if p.pt == pt && !p.soft.silent), "{}: {read:?}", pt.kind());
    }
}
