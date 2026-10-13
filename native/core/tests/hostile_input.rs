//! Hostile input (wire-1.1 §W9): nothing a peer, a relay or the server can
//! send may panic the core, and no mutation of an authenticated field may
//! come out as authentic.
//!
//! There is no fuzzing crate in the tree, so this is a deterministic
//! mutation corpus driven by the golden PRNG: for every parser the seeds are
//! valid inputs (built here with the core's own builders, or taken from the
//! golden vectors) and the mutations are truncation at every length, bit
//! flips, random insertions, deletions and duplications, duplicated JSON
//! keys, every JSON leaf replaced by a number extreme (`-1`, `2^53`, `2^63`,
//! `2^64`, `1e400`, `1.5`, `7e0`), by another type, by a lone surrogate, by
//! deep nesting and by a megabyte string, plus invalid UTF-8.
//!
//! Every case runs under `catch_unwind` on a thread with a 512 KB stack (the
//! size of a secondary thread on iOS): a panic fails the test with the
//! offending input, and unbounded recursion aborts it.

mod common;

use std::panic::{catch_unwind, AssertUnwindSafe};

use common::*;
use mrenzo_core::caps::{self, Caps};
use mrenzo_core::group_chains::{self as gc, ChainSet, SkippedKeys};
use mrenzo_core::mesh_envelope::{self as mesh, MeshIdentity, MeshMode};
use mrenzo_core::mesh_v11::{self, Signer};
use mrenzo_core::nearby::NearbyOp;
use mrenzo_core::plaintext::{self, build, classify, classify_bytes, Soft, TypedPlaintext};
use mrenzo_core::primitives::{b64, secretbox_seal};
use mrenzo_core::ptt::{self, PttKey, PttReceiver};
use mrenzo_core::ratchet::{Envelope, Session};
use mrenzo_core::reactions;
use mrenzo_core::rng::{Rng, StreamRng};
use mrenzo_core::sdp_signing::{self, SdpExpectV2, SdpKind};
use mrenzo_core::sender_keys::{self as sk, SkContext};
use mrenzo_core::session_set::{PeerSessions, SetDecrypt, SetOpen};
use mrenzo_core::x3dh::{generate_kem_pre_key, KemKind};
use mrenzo_core::{contact_pair, files, legacy_box, offline_seal, push_hint, ratchet_reset, sealed_sender, sticker, strict_json};
use serde_json::{json, Value};

// ───────────────────────────── the corpus machinery ─────────────────────────────

/// Runs `body` on a 512 KB stack; a panic or an overflow fails the test.
fn on_small_stack(body: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new().stack_size(512 * 1024).spawn(body).unwrap().join().expect("a hostile-input case panicked");
    // `cargo test -- --nocapture` shows how large the corpus is.
    eprintln!("hostile input: {} cases so far", CASES.load(std::sync::atomic::Ordering::Relaxed));
}

static CASES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Runs one case; a panic is reported with the parser and the input.
fn case<T>(parser: &str, input: &[u8], f: impl FnOnce() -> T) -> T {
    CASES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(v) => v,
        Err(_) => panic!("{parser} PANICKED on {} bytes: {}", input.len(), String::from_utf8_lossy(&input[..input.len().min(400)])),
    }
}

struct Mutator {
    rng: StreamRng,
}

impl Mutator {
    fn new(label: &str) -> Mutator {
        Mutator { rng: StreamRng::new(&format!("hostile/{label}")) }
    }

    fn below(&mut self, n: usize) -> usize {
        let mut b = [0u8; 8];
        self.rng.fill(&mut b);
        (u64::from_be_bytes(b) % n.max(1) as u64) as usize
    }

    /// Byte-level mutants: truncations (every length for short seeds, a
    /// sample for long ones), single-bit flips, insertions, deletions,
    /// duplicated ranges.
    fn bytes(&mut self, seed: &[u8], budget: usize) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        if seed.len() <= budget {
            out.extend((0..seed.len()).map(|n| seed[..n].to_vec()));
        } else {
            out.extend((0..budget).map(|_| seed[..self.below(seed.len())].to_vec()));
        }
        for _ in 0..budget {
            if seed.is_empty() {
                break;
            }
            let mut m = seed.to_vec();
            let i = self.below(m.len());
            m[i] ^= 1 << self.below(8);
            out.push(m);
            let mut m = seed.to_vec();
            let (i, n) = (self.below(m.len() + 1), 1 + self.below(4));
            let junk: Vec<u8> = (0..n).map(|_| self.below(256) as u8).collect();
            m.splice(i..i, junk);
            out.push(m);
            let mut m = seed.to_vec();
            let i = self.below(m.len());
            let j = (i + 1 + self.below(8)).min(m.len());
            m.drain(i..j);
            out.push(m);
            let mut m = seed.to_vec();
            let i = self.below(m.len());
            let j = (i + 1 + self.below(16)).min(m.len());
            let dup = m[i..j].to_vec();
            m.splice(j..j, dup);
            out.push(m);
        }
        out.push(vec![]);
        out.push(vec![0xff, 0xfe, 0xfd]);
        out.push([seed, &[0xc3, 0x28]].concat());
        out
    }
}

/// What a JSON leaf (or subtree) is replaced with — raw tokens, so that
/// values serde would never write (a lone surrogate, `1e400`) are covered.
fn hostile_tokens() -> Vec<String> {
    let mut t: Vec<String> = [
        "-1", "0", "9007199254740992", "9223372036854775808", "18446744073709551616", "-9223372036854775809", "1e400", "-1e400", "1.5", "7e0",
        "1E2", "0.0", "null", "true", "false", "\"\"", "\"\\ud800\"", "\"\\u0000\"", "\"\u{feff}x\"", "[]", "{}", "[null]", "{\"a\":{\"a\":1,\"a\":2}}",
        "\"AAAA\"", "\"====\"", "\"A\"",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    t.push(format!("{}1{}", "[".repeat(200), "]".repeat(200)));
    t.push(format!("{}1{}", "{\"a\":".repeat(600), "}".repeat(600)));
    t
}

const MARK: &str = "\u{1}MUT\u{1}";

fn replace_at(v: &Value, path: &[String], with: &Value) -> Value {
    match (v, path.split_first()) {
        (_, None) => with.clone(),
        (Value::Object(o), Some((k, rest))) => {
            let mut o = o.clone();
            if let Some(child) = o.get(k).cloned() {
                o.insert(k.clone(), replace_at(&child, rest, with));
            }
            Value::Object(o)
        }
        (Value::Array(a), Some((k, rest))) => {
            let mut a = a.clone();
            if let Some(i) = k.parse::<usize>().ok().filter(|i| *i < a.len()) {
                a[i] = replace_at(&a[i], rest, with);
            }
            Value::Array(a)
        }
        (other, _) => other.clone(),
    }
}

fn paths(v: &Value, prefix: &mut Vec<String>, out: &mut Vec<Vec<String>>) {
    if !prefix.is_empty() {
        out.push(prefix.clone());
    }
    match v {
        Value::Object(o) => {
            for (k, child) in o {
                prefix.push(k.clone());
                paths(child, prefix, out);
                prefix.pop();
            }
        }
        Value::Array(a) => {
            for (i, child) in a.iter().enumerate().take(4) {
                prefix.push(i.to_string());
                paths(child, prefix, out);
                prefix.pop();
            }
        }
        _ => {}
    }
}

/// Structural mutants of a JSON text: every value replaced by every hostile
/// token, every top-level key removed and duplicated, the whole document
/// wrapped, one megabyte string — then the byte-level mutants on top.
fn json_mutants(m: &mut Mutator, seed: &str, byte_budget: usize) -> Vec<Vec<u8>> {
    let v: Value = serde_json::from_str(seed).expect("a JSON seed");
    let mut all = Vec::new();
    paths(&v, &mut Vec::new(), &mut all);
    let marked = Value::String(MARK.to_string());
    let quoted_mark = serde_json::to_string(&marked).unwrap();
    let mut out: Vec<Vec<u8>> = Vec::new();
    for path in all.iter().take(48) {
        let template = replace_at(&v, path, &marked).to_string();
        for token in hostile_tokens() {
            out.push(template.replacen(&quoted_mark, &token, 1).into_bytes());
        }
    }
    if let Value::Object(o) = &v {
        for (k, child) in o {
            let mut without = o.clone();
            without.shift_remove(k);
            out.push(Value::Object(without).to_string().into_bytes());
            // The same key twice, with the same and with another value.
            let pair = format!("{}:{}", serde_json::to_string(k).unwrap(), child);
            out.push(seed.replacen('{', &format!("{{{pair},"), 1).into_bytes());
            out.push(seed.replacen('{', &format!("{{{}:0,", serde_json::to_string(k).unwrap()), 1).into_bytes());
        }
        if let Some((k, _)) = o.iter().next() {
            let mut big = o.clone();
            big.insert(k.clone(), Value::String("x".repeat(1024 * 1024)));
            out.push(Value::Object(big).to_string().into_bytes());
        }
    }
    out.push(format!("[{seed}]").into_bytes());
    out.push(format!("{seed}{seed}").into_bytes());
    out.push(format!("{}{seed}{}", "[".repeat(100_000), "]".repeat(100_000)).into_bytes());
    out.push(b"null".to_vec());
    out.extend(m.bytes(seed.as_bytes(), byte_budget));
    out
}

fn text(bytes: &[u8]) -> Option<&str> {
    std::str::from_utf8(bytes).ok()
}

// ───────────────────────────── 1:1 envelopes and sessions ─────────────────────────────

#[test]
fn envelopes_and_sessions() {
    on_small_stack(|| {
        let t = linked("hostile/session");
        let mut sender = t.sa.clone();
        let plain = build(&TypedPlaintext::Chat { id: "m".into(), body: "секрет".into(), reply: None, fwd: None, expire: None, story: None }, &Soft::default(), None).unwrap();
        let wire = sender.encrypt(&plain, T0, &mut StreamRng::new("hostile/enc")).unwrap().to_wire();
        // A prekey message with a KEM header (the largest header there is).
        let p = prekeys(&t.b, "v3/bob-spk", "v3/bob-opk");
        let kem = generate_kem_pre_key(&t.b.ed_secret, 42, KemKind::OneTime, &mut StreamRng::new("hostile/kem"));
        let mut init = PeerSessions::default();
        init.initiate_pq(&t.a.ik, &t.a.ed_pub, &t.b.ik.public, &t.b.ed_pub, &p.bundle(true), &kem.public(), T0, &mut StreamRng::new("hostile/x")).unwrap();
        let prekey_wire = init.encrypt(&plain, T0, &mut StreamRng::new("hostile/pk")).unwrap().to_wire();

        let original = Envelope::parse(&wire).unwrap();
        let mut m = Mutator::new("envelope");
        let mut opened_identical = 0;
        for mutant in json_mutants(&mut m, &wire, 300) {
            case("Envelope::parse + PeerSessions::open/decrypt/is_stale", &mutant, || {
                let Some(s) = text(&mutant) else { return };
                let _ = Envelope::parse(s);
                let Ok(env) = Envelope::parse_v11(s) else { return };
                let mut set = t.sb.clone();
                let _ = set.is_stale(&env);
                let _ = set.is_spent(&env);
                match set.open(&env, T0, &mut StreamRng::new("hostile/open")) {
                    SetOpen::Typed { plaintext, .. } => {
                        assert_eq!(env, original, "a mutated envelope authenticated");
                        assert_eq!(plaintext, plain);
                        opened_identical += 1;
                    }
                    SetOpen::Unsupported { .. } => panic!("a mutated envelope authenticated as unsupported"),
                    SetOpen::Stale | SetOpen::Failed | SetOpen::NoSession | SetOpen::NeedsResponder | SetOpen::TooManySkipped => {}
                }
                // The 1.0.0-shaped entry point agrees.
                let legacy = t.sb.clone().decrypt(&env, T0, &mut StreamRng::new("hostile/open"));
                assert_eq!(matches!(legacy, SetDecrypt::Opened { .. }), env == original);
            });
        }
        assert!(opened_identical > 0, "sanity: the corpus contains mutants that leave the envelope intact (an added key)");

        // The prekey path: header fields, the KEM id and ciphertext.
        let original = Envelope::parse(&prekey_wire).unwrap();
        let mut m = Mutator::new("prekey");
        for mutant in json_mutants(&mut m, &prekey_wire, 60) {
            case("respond_and_open", &mutant, || {
                let Some(env) = text(&mutant).and_then(|s| Envelope::parse(s).ok()) else { return };
                let mut set = PeerSessions::default();
                for kem_seed in [Some((&kem.seed, kem.kind)), None] {
                    let opk = env.x.and_then(|x| x.opk).map(|_| &p.opk.private);
                    if let Ok(SetOpen::Typed { .. } | SetOpen::Unsupported { .. }) =
                        set.respond_and_open(&env, &t.b.ik, &t.b.ed_pub, &p.spk, opk, kem_seed, &t.a.ik.public, &t.a.ed_pub, T0, &mut StreamRng::new("hostile/resp"))
                    {
                        assert_eq!(env, original, "a mutated prekey message authenticated");
                    }
                }
            });
        }

        // At rest: the session JSON and the aux.
        let state = t.sb.live().unwrap().session.to_json();
        let mut m = Mutator::new("state");
        for mutant in json_mutants(&mut m, &state, 200) {
            case("Session::from_json", &mutant, || {
                if let Some(s) = text(&mutant).and_then(|s| Session::from_json(s, T0)) {
                    let _ = s.to_json();
                }
            });
        }
        let mut busy = t.sb.clone();
        for i in 0..3 {
            let w = sender.encrypt(&plain, T0, &mut StreamRng::new(&format!("hostile/a{i}"))).unwrap().to_wire();
            assert!(matches!(busy.open(&Envelope::parse(&w).unwrap(), T0, &mut StreamRng::new(&format!("hostile/b{i}"))), SetOpen::Typed { .. }));
        }
        let aux = busy.aux_json();
        let mut m = Mutator::new("aux");
        for mutant in json_mutants(&mut m, &aux, 200) {
            case("PeerSessions::from_rows_aux", &mutant, || {
                let set = PeerSessions::from_rows_aux(&busy.rows(), text(&mutant), T0);
                assert_eq!(set.entries.len(), busy.entries.len(), "the aux never costs a session");
                let _ = set.aux_json();
            });
        }
    });
}

// ───────────────────────────── typed plaintext and its objects ─────────────────────────────

#[test]
fn typed_plaintexts_and_soft_keys() {
    on_small_stack(|| {
        let caps = Caps::own(&["pq", "ptt"]).unwrap();
        let soft = Soft { caps: Some(caps.clone()), alt: Some("alt".into()), nearby: None, silent: false };
        let invite = NearbyOp::Invite { ns: [1; 16], exp: 99 };
        // A `file` body as it is on the wire: the FileEnvelope JSON (03 §8.3), `kind`, the soft key `st`.
        let mut file = serde_json::Map::new();
        for (k, v) in [("p", json!("📎")), ("id", json!("f")), ("k", json!(b64(&[1u8; 32]))), ("n", json!(b64(&[2u8; 24]))), ("m", json!("image/png")), ("s", json!(1234))] {
            file.insert(k.into(), v);
        }
        file.insert("kind".into(), json!("image"));
        file.insert("st".into(), json!({"v":1,"id":"a".repeat(64),"pack":"0123456789abcdef01234567","e":"😀","w":512,"h":512}));
        let seeds: Vec<String> = vec![
            build(&TypedPlaintext::Chat { id: "m".into(), body: "b".into(), reply: Some(plaintext::Reply { id: "r".into(), text: "t".into(), name: "n".into() }), fwd: Some("f".into()), expire: Some(5), story: Some(plaintext::StoryRef { id: "s".into(), story_type: "photo".into(), action: "story-reply".into(), content: Some("c".into()) }) }, &Soft { nearby: Some(invite), silent: true, ..soft.clone() }, Some(64)).unwrap(),
            build(&TypedPlaintext::File { id: "m".into(), body: file, reply: None, fwd: None, expire: None }, &soft, None).unwrap(),
            build(&TypedPlaintext::Edit { id: "e".into(), edit_of: "m".into(), body: "b".into() }, &soft, None).unwrap(),
            build(&TypedPlaintext::Hello { id: "h".into() }, &soft, None).unwrap(),
            build(&TypedPlaintext::React { id: "rx".into(), to: "m".into(), e: vec!["❤️".into(), "👍".into()], ts: 5 }, &soft, Some(64)).unwrap(),
            build(&TypedPlaintext::Nearby { id: "nb".into(), nearby: NearbyOp::Accept { ns: [2; 16], exp: 7, tok: vec![9; 33] } }, &soft, None).unwrap(),
            build(&TypedPlaintext::Ptt { id: "0f8fad5b-d9cb-469f-a165-70867728950e".into(), ptt: PttKey { k: [3; 32], codec: "opus".into(), sr: 16_000 } }, &soft, None).unwrap(),
        ];
        for (i, seed) in seeds.iter().enumerate() {
            let mut m = Mutator::new(&format!("typed/{i}"));
            for mutant in json_mutants(&mut m, seed, 150) {
                case("plaintext::classify (+ every outer check, sticker_ref_parse, caps, nearby)", &mutant, || {
                    let c = classify_bytes(&mutant);
                    let Some(s) = text(&mutant) else { return };
                    assert_eq!(classify(s), c);
                    if let plaintext::Classified::Typed(p) = &c {
                        // Whatever classifies as typed serializes and reads back as itself.
                        let again = build(&p.pt, &p.soft, None).expect("a typed plaintext rebuilds");
                        assert_eq!(classify(&again), c, "{again}");
                        for id in ["m", "", p.pt.id()] {
                            let _ = plaintext::outer_matches_p2p(&p.pt, id, Some("session-hello"), Some("s"));
                            let _ = plaintext::outer_matches_edit(&p.pt, id);
                            let _ = plaintext::outer_matches_ctl(&p.pt, id);
                            let _ = plaintext::outer_matches_mesh_ctl(&p.pt, id);
                            let _ = plaintext::outer_matches_ptt(&p.pt, id);
                        }
                        if let TypedPlaintext::File { body, .. } = &p.pt {
                            let _ = sticker::sticker_ref_parse(&Value::Object(body.clone()).to_string());
                            let _ = files::parse_file_envelope(&Value::Object(body.clone()).to_string());
                        }
                    }
                    let _ = Caps::parse_lenient(s);
                    let _ = NearbyOp::parse(s);
                    let _ = sticker::sticker_ref_parse(s);
                    let _ = files::parse_file_envelope(s);
                    let _ = strict_json::parse(s);
                });
            }
        }
        // The capability statement.
        let a = alice();
        let statement = caps::statement_sign(&a.ed_secret, a.uid as u64, &caps, T0 as u64);
        let mut m = Mutator::new("caps");
        for mutant in json_mutants(&mut m, &statement, 200) {
            case("caps::statement_verify", &mutant, || {
                let Some(s) = text(&mutant) else { return };
                for now in [T0, i64::MIN, i64::MAX, 0] {
                    if let caps::StatementCheck::Ok { caps: got, ts } = caps::statement_verify(s, a.uid as u64, &a.ed_pub, 0, now) {
                        assert_eq!((got, ts), (caps.clone(), T0 as u64), "a mutated statement verified with other content");
                    }
                }
            });
        }
    });
}

// ───────────────────────────── mesh ─────────────────────────────

/// The two things no frame signature covers — `hops`, and whether a copy
/// still carries its capsule — used TOGETHER by a bystander, in every order,
/// on a node with two radios (wire-1.1 §W8.3). The alphabet is one frame in
/// twelve copies: with the sender's capsule, stripped of it, or with a
/// bystander's; at `hops` 0 and 1 (relayed), 2 (the L budget spent) and 16
/// (inflated). Each copy is heard on one of two lanes, on a radio that has
/// somebody to pass it on to or has not. Every sequence of up to four copies
/// on one always-connected radio, and of up to three over both radios in
/// both states, runs on a fresh node.
///
/// Whatever arrives, in whatever order:
/// - the node acts on the frame exactly once, whatever the lane;
/// - on each lane it emits the frame at most twice, and only this frame;
/// - a lane has relayed exactly when a copy that may be relayed was heard on
///   it while it had somebody to pass it on to;
/// - once the sender's capsule was heard — on any lane — every later
///   emission carries it, and on every lane the node had relayed on before
///   it emits once more, with the capsule, at the `hops` it relayed with
///   there (never at the upgrading copy's);
/// - a bystander's capsule is never emitted.
#[test]
fn seen_set_orderings() {
    use mesh_v11::{Admission, Frame, Peek, SeenSet};
    let (a, b, c) = (alice(), bob(), carol());
    let me = MeshIdentity { from_uid: a.uid, sign_priv_b64: b64(&a.ed_secret), sign_pub_b64: b64(&a.ed_pub) };
    let wire = r#"{"v":3,"dh":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","pn":0,"n":0,"ct":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","mac":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}"#;
    let env = mesh::build_mesh_envelope_from_ratchet(0, &b64(&a.ik.private), &b64(&b.ik.public), wire, MeshMode::Realtime, &me, Some("m-seen"), T0, &mut StreamRng::new("hostile/seen")).unwrap().unwrap();
    let blob = mesh::encode_inner_blob(&env).unwrap();
    let courier_pub = mrenzo_core::primitives::x25519_base(&[7u8; 32]);
    let capsule = mesh_v11::courier_capsule_build(&courier_pub, 1, b.uid as u64, &env.id, T0 as u64, a.uid as u64, &a.ed_secret, &blob, &mut StreamRng::new("hostile/seen-cap"));
    let junk = mesh_v11::courier_capsule_build(&courier_pub, 1, c.uid as u64, &env.id, T0 as u64, a.uid as u64, &c.ed_secret, &blob, &mut StreamRng::new("hostile/seen-junk"));
    let stripped = mesh::pack_mesh_outer_json(&env).unwrap();
    let with = |cap: &str| mesh::pack_mesh_outer_json(&mesh::MeshEnvelope { courier: Some(cap.to_string()), ..env.clone() }).unwrap();

    // The twelve copies, each checked ONCE (the sequences below then cost no signature work).
    struct Copy {
        peek: Peek,
        frame: Frame,
        genuine: bool,
        relayable: bool,
    }
    let mut copies: Vec<Copy> = Vec::new();
    for (json, genuine) in [(with(&capsule), true), (stripped.clone(), false), (with(&junk), false)] {
        for hops in [0u64, 1, 2, 16] {
            let json = json.replacen("\"hops\":0", &format!("\"hops\":{hops}"), 1);
            let frame = mesh_v11::frame_check(json.as_bytes(), T0).unwrap();
            assert_eq!(frame.courier.as_deref(), genuine.then_some(capsule.as_str()), "only the sender's capsule survives the check");
            let relayable = mesh_v11::forward_hops(frame.ttl, hops, frame.l).is_some();
            assert_eq!(relayable, hops < 2, "L 4: relayed from hops 0 and 1");
            copies.push(Copy { peek: mesh_v11::frame_peek(json.as_bytes()).unwrap(), frame, genuine, relayable });
        }
    }
    let with_c = format!(",\"c\":\"{capsule}\"}}");

    // One arrival: which copy, on which lane, and whether that radio can pass it on.
    #[derive(Clone, Copy, Debug)]
    struct Heard {
        copy: usize,
        lane: u8,
        can_relay: bool,
    }
    let run = |seq: &[Heard]| {
        let mut seen = SeenSet::new(16);
        let (mut firsts, mut capsule_upgrades) = (0, 0);
        // Per lane: the hops the node relayed with, and how often it emitted.
        let mut relayed: [Option<u64>; 2] = [None, None];
        let mut emissions = [0u32; 2];
        let mut last_has_capsule = [false; 2];
        let mut heard_capsule = false;
        let mut heard_relayable = [false; 2];
        for h in seq {
            let copy = &copies[h.copy];
            let lane = usize::from(h.lane);
            let before = relayed;
            let mut out = Vec::new();
            if seen.admit(&copy.peek, h.lane, h.can_relay) != Admission::Duplicate {
                let r = seen.record(&copy.frame, h.lane, h.can_relay);
                firsts += usize::from(r.first);
                capsule_upgrades += usize::from(r.capsule_upgrade);
                assert!(!r.capsule_upgrade || (copy.genuine && !r.first), "{seq:?}: a capsule upgrade without the sender's capsule");
                out = r.forward;
            }
            heard_capsule |= copy.genuine;
            heard_relayable[lane] |= copy.relayable && h.can_relay;
            let mut lanes_now = Vec::new();
            for e in &out {
                let on = usize::from(e.lane);
                assert!(on < 2 && !lanes_now.contains(&on), "{seq:?}: one emission per lane at most");
                lanes_now.push(on);
                let peek = mesh_v11::frame_peek(e.frame.as_bytes()).expect("an emission is a frame");
                assert_eq!(peek.seen_key, copy.peek.seen_key, "{seq:?}: an emission of another frame");
                // Never the bystander's capsule; the sender's from the moment it was heard.
                assert_eq!(e.frame.ends_with(&with_c), heard_capsule, "{seq:?}: {}", e.frame);
                assert_eq!(peek.carries_capsule, heard_capsule, "{seq:?}: {}", e.frame);
                match before[on] {
                    // The first emission on a lane is a relay of THIS copy, heard on that lane.
                    None => {
                        assert_eq!((on, peek.hops), (lane, Some(copy.frame.hops + 1)), "{seq:?}: {}", e.frame);
                        relayed[on] = peek.hops;
                    }
                    // A second one repeats the hops of the first, whatever this copy says — and only for the capsule.
                    Some(hops) => assert!(peek.hops == Some(hops) && copy.genuine, "{seq:?}: {}", e.frame),
                }
                emissions[on] += 1;
                last_has_capsule[on] = peek.carries_capsule;
            }
            for on in 0..2 {
                assert!(emissions[on] <= 2, "{seq:?}: emitted a third time on lane {on}");
                assert_eq!(heard_relayable[on], relayed[on].is_some(), "{seq:?}: lane {on} relays exactly when a relayable copy was heard on it with somebody to pass it on to");
                if heard_capsule && relayed[on].is_some() {
                    assert!(last_has_capsule[on], "{seq:?}: lane {on} never emitted the sender's capsule");
                }
            }
        }
        assert_eq!(firsts, 1, "{seq:?}: acted on once");
        assert!(capsule_upgrades <= 1, "{seq:?}");
    };
    // Every sequence of 1..=max_len symbols of `alphabet`.
    let all_sequences = |alphabet: &[Heard], max_len: usize| -> usize {
        let mut count = 0;
        let mut idx = vec![0usize];
        while idx.len() <= max_len {
            count += 1;
            run(&idx.iter().map(|i| alphabet[*i]).collect::<Vec<_>>());
            // Count in base `alphabet.len()`, then one symbol longer.
            let mut k = idx.len();
            loop {
                if k == 0 {
                    idx = vec![0; idx.len() + 1];
                    break;
                }
                k -= 1;
                idx[k] += 1;
                if idx[k] < alphabet.len() {
                    break;
                }
                idx[k] = 0;
            }
        }
        count
    };
    let one_radio: Vec<Heard> = (0..copies.len()).map(|copy| Heard { copy, lane: 0, can_relay: true }).collect();
    assert_eq!(all_sequences(&one_radio, 4), 12 + 144 + 1728 + 20_736);
    let two_radios: Vec<Heard> = (0..copies.len()).flat_map(|copy| [(0, true), (0, false), (1, true), (1, false)].map(|(lane, can_relay)| Heard { copy, lane, can_relay })).collect();
    assert_eq!(all_sequences(&two_radios, 3), 48 + 2304 + 110_592);

    // The two orderings of the review, spelled out (copies: 0..4 genuine, 4..8 stripped, by hops 0, 1, 2, 16).
    for order in [[3usize, 4, 0], [4, 3, 0]] {
        let mut seen = SeenSet::new(16);
        let mut out: Vec<String> = Vec::new();
        for i in order {
            if seen.admit(&copies[i].peek, 0, true) != Admission::Duplicate {
                out.extend(seen.record(&copies[i].frame, 0, true).forward.into_iter().map(|e| e.frame));
            }
        }
        let last = mesh_v11::frame_check(out.last().expect("relayed").as_bytes(), T0).expect("a re-emitted frame is valid");
        assert_eq!((last.courier.as_deref(), last.hops), (Some(capsule.as_str()), 1), "{order:?}");
        assert_eq!(seen.admit(&copies[0].peek, 0, true), Admission::Duplicate, "{order:?}: the sender's own copy has nothing left to add");
    }
}

#[test]
fn mesh_frames() {
    on_small_stack(|| {
        let (a, b) = (alice(), bob());
        let signer = Signer { uid: a.uid as u64, ed_secret64: &a.ed_secret };
        let me = MeshIdentity { from_uid: a.uid, sign_priv_b64: b64(&a.ed_secret), sign_pub_b64: b64(&a.ed_pub) };
        let wire = r#"{"v":3,"dh":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","pn":0,"n":0,"ct":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","mac":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}"#;
        let env = mesh::build_mesh_envelope_from_ratchet(0, &b64(&a.ik.private), &b64(&b.ik.public), wire, MeshMode::Pigeon, &me, Some("m-1"), T0, &mut StreamRng::new("hostile/mesh")).unwrap().unwrap();
        let blob = mesh::encode_inner_blob(&env).unwrap();
        let courier_key = [7u8; 32];
        let courier_pub = mrenzo_core::primitives::x25519_base(&courier_key);
        let capsule = mesh_v11::courier_capsule_build(&courier_pub, 1, b.uid as u64, &env.id, T0 as u64, a.uid as u64, &a.ed_secret, &blob, &mut StreamRng::new("hostile/cap"));
        let chunk = ptt::seal_chunk(&[1; 32], 0, true, &[vec![5; 30]], &mut StreamRng::new("hostile/chunk")).unwrap();
        let seeds: Vec<String> = vec![
            mesh::pack_mesh_outer_json(&mesh::MeshEnvelope { courier: Some(capsule), ..env.clone() }).unwrap(),
            mesh::pack_mesh_outer_json(&mesh::build_mesh_ack(0, "m-1.tagtagtagtagtagx", &me, T0, &mut StreamRng::new("hostile/ack")).unwrap().unwrap()).unwrap(),
            mesh_v11::build_ack2(&[2; 32], "m-1", T0 as u64, &mut StreamRng::new("hostile/ack2")).unwrap(),
            mesh_v11::build_ptt_frame(signer, &a.ik.private, &b.ik.public, "0f8fad5b-d9cb-469f-a165-70867728950e", 0, true, Some(wire), &chunk, T0 as u64).unwrap(),
            mesh_v11::build_ctl_frame(signer, &a.ik.private, &b.ik.public, "nb-1", wire, 1, T0 as u64).unwrap(),
            mesh_v11::build_named_frame("poll9", b"body", signer, None, "u-1", 7, Some(4), T0 as u64).unwrap(),
        ];
        // One node's seen set over the whole corpus, the mutants arriving on two radios in turn:
        // whatever arrives, in whatever order, a frame is re-emitted at most twice per lane (once,
        // and once more for the sender's capsule), and once the node has verified a capsule for a
        // frame, everything it emits of that frame carries it.
        let mut seen = mesh_v11::SeenSet::new(64);
        let mut emitted: std::collections::HashMap<(String, u8), u32> = std::collections::HashMap::new();
        let mut known_capsule: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        let mut arrivals = 0u32;
        for (i, seed) in seeds.iter().enumerate() {
            let original = mesh_v11::frame_check(seed.as_bytes(), T0).unwrap();
            let mut m = Mutator::new(&format!("mesh/{i}"));
            for mutant in json_mutants(&mut m, seed, 40) {
                case("mesh_v11::frame_check / frame_peek / forwarded_json / parsers + the 1.0.0 decoder", &mutant, || {
                    let _ = mesh_v11::frame_peek(&mutant);
                    let _ = seen.mark_own(&mutant[..mutant.len().min(64)]);
                    if let Some(peek) = mesh_v11::frame_peek(&mutant) {
                        arrivals += 1;
                        // Lanes 0 and 1 in turn, a lane that does not exist now and then, a radio with nobody on it now and then.
                        let (lane, can_relay) = ([0u8, 1, 0, 1, 4][arrivals as usize % 5], arrivals % 7 != 0);
                        if seen.admit(&peek, lane, can_relay) != mesh_v11::Admission::Duplicate {
                            assert!(usize::from(lane) < mesh_v11::MAX_LANES, "a lane that does not exist admitted a frame");
                            if let Ok(f) = mesh_v11::frame_check(&mutant, T0) {
                                assert_eq!(f.seen_key, peek.seen_key, "the peeked key is the checked key");
                                let r = seen.record(&f, lane, can_relay);
                                if let Some(c) = &f.courier {
                                    known_capsule.entry(f.seen_key.clone()).or_insert_with(|| c.clone());
                                }
                                for e in &r.forward {
                                    let out = mesh_v11::frame_check(e.frame.as_bytes(), T0).expect("a re-emitted frame is valid");
                                    assert_eq!(out.seen_key, f.seen_key, "a re-emission of another frame");
                                    assert_eq!(out.courier.as_ref(), known_capsule.get(&f.seen_key), "an emission carries the capsule exactly when the node has verified one");
                                    let n = emitted.entry((f.seen_key.clone(), e.lane)).or_default();
                                    *n += 1;
                                    assert!(*n <= 2, "a frame was re-emitted a third time on one lane");
                                }
                                assert!(can_relay || r.forward.iter().all(|e| e.lane != lane), "relayed on a radio with nobody to pass the frame on to");
                                assert!(!r.capsule_upgrade || f.courier.is_some());
                            }
                        }
                    }
                    let _ = mesh_v11::link_hello_parse(&mutant);
                    // The 1.0.0-shaped parse checks no FRAME signature, but a capsule it returns is the signer's own.
                    if let Ok(f) = mesh_v11::frame_parse_unverified(&mutant) {
                        assert!(f.courier.is_none() || mesh_v11::courier_capsule_verifies(f.courier.as_deref().unwrap_or(""), &f.id, f.ts, f.from_uid, &f.sig_pub, &strict_json::b64(&f.b).unwrap_or_default()), "a shape-only capsule left the parser");
                        if let Some(e) = f.to_legacy_envelope() {
                            assert_eq!(mesh_v11::envelope_capsule(&e), f.courier, "the record door disagrees with the parser about the capsule");
                        }
                    }
                    for now in [T0, i64::MIN, i64::MAX] {
                        let _ = mesh_v11::frame_check(&mutant, now);
                    }
                    if let Ok(f) = mesh_v11::frame_check(&mutant, T0) {
                        // The capsule carries the sender's own signature: a changed one is absent, never accepted.
                        assert!(f.courier.is_none() || f.courier == original.courier, "a mutated capsule was kept");
                        // Only `hops` and unknown outer keys are outside every signature.
                        assert_eq!(
                            (&f.id, f.ts, f.ttl, f.l, f.mode, &f.kind, f.from_uid, f.sig_pub, f.to_idx, &f.payload, &f.seen_key),
                            (&original.id, original.ts, original.ttl, original.l, original.mode, &original.kind, original.from_uid, original.sig_pub, original.to_idx, &original.payload, &original.seen_key),
                            "a mutated signed field verified"
                        );
                        let _ = mesh_v11::forwarded_json(&f).map(|j| mesh_v11::frame_check(j.as_bytes(), T0).expect("a forwarded frame is valid"));
                        let _ = (mesh_v11::ptt_parse(&f), mesh_v11::ctl_parse(&f), mesh_v11::msg_envelope(&f));
                        let _ = mesh_v11::to_idx_matches(&f, &b.ik.private, &a.ik.public);
                        let _ = mesh_v11::courier_open(&f, 1, &courier_key);
                        let _ = mesh_v11::ack2_matches(&f, &[0; 32], "m-1");
                    }
                    // The 1.0.0 decoder, which every 1.0.0 call site still reaches through the FFI.
                    if let Some(v) = text(&mutant).and_then(|s| serde_json::from_str::<Value>(s).ok()) {
                        if let Ok(Some(e)) = mesh::unpack_mesh_outer(&v) {
                            let _ = mesh::verify_mesh_envelope(&e);
                            let _ = mesh::signed_binding(&e);
                            let _ = mesh::unpad_payload(&e.payload);
                            let _ = mesh::pack_mesh_outer_json(&e);
                            let _ = e.to_json();
                        }
                        let _ = mesh::MeshEnvelope::from_value(&v);
                    }
                });
            }
            // Byte-level mutants of the INNER blob, re-wrapped in a valid outer frame.
            let inner = strict_json::b64(&original.b).unwrap();
            let mut m = Mutator::new(&format!("mesh-inner/{i}"));
            for mutant in m.bytes(&inner, 120) {
                let frame = seed.replacen(&original.b, &b64(&mutant), 1);
                case("mesh_v11::frame_check (inner blob)", frame.as_bytes(), || {
                    let _ = mesh_v11::frame_peek(frame.as_bytes());
                    if mutant != inner {
                        assert!(mesh_v11::frame_check(frame.as_bytes(), T0).is_err(), "a mutated inner blob verified");
                    }
                    let _ = mesh::decode_inner_blob(&mutant);
                });
            }
        }
        // Named bodies: frames that VERIFY and carry arbitrary bodies (a hostile, but pinned, sender).
        let mut m = Mutator::new("ptt-body");
        let tx = ptt::ptt_id_bytes("0f8fad5b-d9cb-469f-a165-70867728950e").unwrap();
        let body = mesh_v11::ptt_body(&tx, 3, false, Some(wire), &chunk).unwrap();
        for (n, mutant) in m.bytes(&body, 200).into_iter().enumerate() {
            if mutant.is_empty() || mutant.len() > mesh_v11::PTT_BODY_MAX {
                continue;
            }
            let frame = mesh_v11::build_named_frame("ptt", &mutant, signer, Some([1; 8]), &format!("0f8fad5b-d9cb-469f-a165-70867728950e.{}", n % 5), 0, None, T0 as u64).unwrap();
            case("mesh_v11::ptt_parse", &mutant, || {
                let f = mesh_v11::frame_check(frame.as_bytes(), T0).unwrap();
                if let Some(seg) = mesh_v11::ptt_parse(&f) {
                    let mut rx = PttReceiver::new();
                    rx.install_key(1, &seg.tx, &[1; 32]);
                    let _ = rx.open(1, &seg.tx, seg.seq, &seg.chunk);
                }
            });
        }
        // The capsule field on its own.
        let frame = mesh_v11::frame_check(seeds[0].as_bytes(), T0).unwrap();
        let raw = strict_json::b64(frame.courier.as_deref().unwrap()).unwrap();
        let mut m = Mutator::new("capsule");
        for mutant in m.bytes(&raw, 150) {
            case("mesh_v11::courier_open", &mutant, || {
                let f = mesh_v11::Frame { courier: Some(b64(&mutant)), ..frame.clone() };
                let opened = mesh_v11::courier_open(&f, 1, &courier_key);
                assert!(opened.is_none() || mutant == raw, "a mutated capsule opened");
            });
        }
        // Budgets and the forward rule at the extremes.
        let mut budget = mesh_v11::LinkBudget::new(i64::MAX);
        for now in [i64::MIN, -1, 0, i64::MAX, i64::MIN] {
            let _ = (budget.admit(true, now), budget.admit(false, now));
        }
        for x in [0u64, 1, 16, 17, 63, 64, 65, u64::MAX - 1, u64::MAX] {
            for y in [0u64, 1, 4, 63, 64, u64::MAX] {
                let _ = (mesh_v11::forward_hops(x, y, Some(x)), mesh_v11::forward_hops(y, x, None), mesh_v11::to_idx_bytes(&[1; 32], &[2; 32], x));
            }
        }
    });
}

// ───────────────────────────── push-to-talk, reactions, stickers ─────────────────────────────

#[test]
fn media_and_feature_parsers() {
    on_small_stack(|| {
        // PTT: the sealed chunk, and plaintexts a holder of K could have sealed.
        let key = [4u8; 32];
        let chunk = ptt::seal_chunk(&key, 9, false, &[vec![1; 40], vec![2; 41]], &mut StreamRng::new("hostile/ptt")).unwrap();
        let mut m = Mutator::new("ptt");
        for mutant in m.bytes(&chunk, 400) {
            case("ptt::open_chunk", &mutant, || {
                assert!(ptt::open_chunk(&key, &mutant).is_none() || mutant == chunk, "a mutated chunk opened");
            });
        }
        let pt = ptt::chunk_plaintext(9, true, &[vec![1; 40], vec![2; 41]]).unwrap();
        let mut m = Mutator::new("ptt-pt");
        for mutant in m.bytes(&pt, 400) {
            let sealed = [vec![0u8; 24], secretbox_seal(&mutant, &[0u8; 24], &key)].concat();
            case("ptt chunk plaintext parser", &mutant, || {
                if let Some(c) = ptt::open_chunk(&key, &sealed) {
                    // Whatever parses is canonical: re-framing it gives the same bytes back.
                    assert_eq!(ptt::chunk_plaintext(c.seq, c.last, &c.packets).unwrap(), mutant);
                }
                let mut rx = PttReceiver::new();
                rx.install_key(1, &[0; 16], &key);
                for seq in [0, 9, u32::MAX] {
                    let _ = rx.open(1, &[0; 16], seq, &sealed);
                }
            });
        }
        for id in ["", "0f8fad5b-d9cb-469f-a165-70867728950e", "0f8fad5b-d9cb-469f-a165-70867728950é", "0f8fad5b-d9cb-469f-a165-70867728950", "ÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿ"] {
            case("ptt::ptt_id_bytes", id.as_bytes(), || ptt::ptt_id_bytes(id));
        }

        // Group reactions: the blob as stored by the server, and what a member could seal inside.
        let rk = [5u8; 32];
        let blob = reactions::group_reaction_seal(&rk, "g-1", "p-1", 7, "rx-1", &["🔥".to_string()], 5, &mut StreamRng::new("hostile/rx")).unwrap();
        let mut m = Mutator::new("rx");
        for mutant in m.bytes(blob.as_bytes(), 300) {
            case("reactions::group_reaction_open", &mutant, || {
                let Some(s) = text(&mutant) else { return };
                for (g, p, uid) in [("g-1", "p-1", 7i64), ("", "p-1", 7), ("g-1", "p|1", 7), ("g-1", "p-1", -1), ("g-1", "p-1", i64::MAX)] {
                    if let Some(r) = reactions::group_reaction_open(&rk, g, p, uid, s) {
                        assert_eq!((r.id.as_str(), r.ts), ("rx-1", 5), "a mutated blob opened with other content");
                    }
                }
            });
        }
        for (ts, now) in [(0u64, 0i64), (u64::MAX, i64::MIN), (u64::MAX, i64::MAX), (1, i64::MIN)] {
            let _ = reactions::register_decide(Some((u64::MAX, "\u{10ffff}")), ts, "", now);
        }

        // Stickers: the PNG walk.
        let png = {
            let chunk = |kind: &[u8; 4], data: &[u8]| [&(data.len() as u32).to_be_bytes()[..], kind, data, &[0u8; 4]].concat();
            [&[0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a][..], &chunk(b"IHDR", &[0, 0, 2, 0, 0, 0, 2, 0, 8, 6, 0, 0, 0]), &chunk(b"IDAT", &[1; 300]), &chunk(b"tEXt", b"k\0v"), &chunk(b"IEND", &[])].concat()
        };
        let padded = sticker::sticker_pad_png(&png).unwrap();
        for (label, seed) in [("png", &png), ("padded", &padded)] {
            let mut m = Mutator::new(label);
            for mutant in m.bytes(seed, 250) {
                case("sticker::png_info / pad / strip / id", &mutant, || {
                    let info = sticker::png_info(&mutant);
                    let (stripped, id, repadded) = (sticker::sticker_strip_padding(&mutant), sticker::sticker_canonical_id(&mutant), sticker::sticker_pad_png(&mutant));
                    assert_eq!((stripped.is_some(), id.is_some()), (info.is_some(), info.is_some()));
                    if let (Some(s), Some(r)) = (&stripped, &repadded) {
                        assert_eq!(&sticker::sticker_strip_padding(r).unwrap(), s, "pad then strip is the identity on canonical bytes");
                    }
                });
            }
        }
        // Lengths that claim more than the buffer, at every chunk boundary.
        for at in [8usize, 33, 345, 360] {
            for len in [0xffff_ffffu32, 0x7fff_ffff, 0x0010_0000, png.len() as u32] {
                let mut p = png.clone();
                if at + 4 <= p.len() {
                    p[at..at + 4].copy_from_slice(&len.to_be_bytes());
                    case("sticker::png_info (length)", &p, || sticker::png_info(&p));
                }
            }
        }
    });
}

// ───────────────────────────── groups, calls, sealed and offline, the rest ─────────────────────────────

#[test]
fn group_call_and_sealed_parsers() {
    on_small_stack(|| {
        let (a, b) = (alice(), bob());
        // Sender keys: the `sk2:` post, the SKDM, the stored chain blobs.
        let state = sk::generate_sender_key(&mut StreamRng::new("hostile/sk"));
        let post = gc::encrypt_outgoing("g-1", a.uid, &state, "пост", &mut StreamRng::new("hostile/post")).unwrap();
        let skdm_json = post.skdm.to_json();
        let set = gc::ingest_skdm_v2(&ChainSet::default(), &gc::validate_skdm(&serde_json::from_str(&skdm_json).unwrap(), a.uid).unwrap()).set;
        let ctx = SkContext { group_id: "g-1", sender_uid: a.uid };
        let body = post.wire.strip_prefix("sk2:").unwrap();
        let mut m = Mutator::new("sk2");
        for mutant in json_mutants(&mut m, body, 150) {
            case("group_chains::decrypt_with_chains / receive_batch_skipping", &mutant, || {
                let Some(s) = text(&mutant) else { return };
                for raw in [format!("sk2:{s}"), s.to_string(), format!("sk3:{s}")] {
                    let out = gc::decrypt_with_chains(&set, &raw, &ctx);
                    assert!(out.kind != gc::GroupDecryptKind::Opened || out.text == "пост", "a mutated post opened with other text");
                    let item = gc::BatchItem { sender_id: a.uid, raw: raw.clone(), is_system: false, cached_plaintext: None, failed_under: None };
                    let batch = gc::receive_batch_skipping(&[item.clone(), item], b.uid, "g-1", T0, |_| (set.clone(), SkippedKeys::default()));
                    assert!(batch.results.iter().all(|r| !matches!(r, gc::BatchItemResult::Opened(t) if t != "пост")));
                    let _ = gc::envelope_prefix_version(&raw);
                    let _ = gc::envelope_sort_counter(&raw);
                }
            });
        }
        let mut m = Mutator::new("skdm");
        for mutant in json_mutants(&mut m, &skdm_json, 150) {
            case("group_chains::validate_skdm / ingest", &mutant, || {
                let Some(v) = text(&mutant).and_then(gc::parse_skdm_plaintext) else { return };
                if let Ok(valid) = gc::validate_skdm(&v, a.uid) {
                    let out = gc::ingest_skdm_v2(&set, &valid);
                    // A chain installed from a hostile SKDM, then a post against it.
                    let _ = gc::decrypt_with_chains(&out.set, &post.wire, &ctx);
                }
            });
        }
        let stored = set.to_storage().unwrap();
        let mut m = Mutator::new("chains");
        for mutant in json_mutants(&mut m, &stored.recv, 100) {
            case("ChainSet::from_storage / deserialise_sender_key / SkippedKeys", &mutant, || {
                let s = text(&mutant);
                let loaded = ChainSet::from_storage(s, s);
                let _ = gc::decrypt_with_chains(&loaded, &post.wire, &ctx);
                let _ = loaded.fingerprint();
                let _ = s.map(sk::deserialise_sender_key);
                let _ = SkippedKeys::from_storage(s).to_storage();
            });
        }

        // Calls: the signed SDP `data` object.
        let sdp = "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\na=fingerprint:sha-256 AB:CD:EF\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n";
        let signed = sdp_signing::sign_sdp_v2(sdp, "offer", &a.ed_secret, a.uid, "1002", "call-1", Some(&[8; 32]), T0, &mut StreamRng::new("hostile/sdp")).unwrap();
        let data = sdp_signing::sdp_wire_data_v2("offer", sdp, &signed, "1002", "call-1").to_string();
        let expect = SdpExpectV2 { from: a.uid, to: "1002".into(), sdp_type: "offer".into(), call_id: "call-1".into(), require_rb: true };
        assert!(sdp_signing::verify_sdp_v2(&serde_json::from_str(&data).unwrap(), &expect, Some(&a.ed_pub), &[[8; 32]], T0).ok);
        let original: Value = serde_json::from_str(&data).unwrap();
        let mut m = Mutator::new("sdp");
        for mutant in json_mutants(&mut m, &data, 150) {
            case("sdp_signing::verify_sdp_v2", &mutant, || {
                let Some(v) = text(&mutant).and_then(|s| serde_json::from_str::<Value>(s).ok()) else { return };
                for now in [T0, i64::MIN, i64::MAX] {
                    let r = sdp_signing::verify_sdp_v2(&v, &expect, Some(&a.ed_pub), &[[8; 32]], now);
                    if r.ok {
                        // Every signed field is what was signed (extra keys do not matter). Of the SDP
                        // the signature covers the DTLS fingerprint lines — the thing a call is bound to.
                        for k in ["type", "sig", "ts", "nonce", "fromUserId", "callId", "pv", "rb"] {
                            assert_eq!(v.get(k), original.get(k), "verify_sdp_v2 accepted a changed `{k}`");
                        }
                        let fp = |x: &Value| sdp_signing::extract_sdp_fingerprints(x["sdp"].as_str().unwrap_or(""));
                        assert_eq!(fp(&v), fp(&original), "verify_sdp_v2 accepted another fingerprint");
                    }
                }
                let _ = sdp_signing::sdp_seen_key(SdpKind::Offer, &v);
                if let Some(s) = v.get("sdp").and_then(Value::as_str) {
                    let _ = sdp_signing::extract_sdp_fingerprints(s);
                }
            });
        }
        let mut m = Mutator::new("sdp-text");
        for mutant in m.bytes(sdp.as_bytes(), 200) {
            case("sdp_signing::extract_sdp_fingerprints", &mutant, || sdp_signing::extract_sdp_fingerprints(&String::from_utf8_lossy(&mutant)));
        }
        // The signed reset.
        let rr = ratchet_reset::sign(&a.ed_secret, a.uid, b.uid, &[3; 32], T0, &mut StreamRng::new("hostile/rr")).to_json();
        let mut m = Mutator::new("reset");
        for mutant in json_mutants(&mut m, &rr, 150) {
            case("ratchet_reset::parse / verify", &mutant, || {
                let Some(parsed) = text(&mutant).and_then(ratchet_reset::RatchetReset::parse) else { return };
                for now in [T0, i64::MIN, i64::MAX] {
                    let r = ratchet_reset::verify(&a.ed_pub, a.uid, b.uid, &parsed, now);
                    assert!(r != ratchet_reset::ResetVerify::Ok || (parsed.ts == T0 && parsed.dh == [3; 32] && now == T0), "a mutated or out-of-window reset verified");
                }
            });
        }

        // Sealed sender, the offline seal, the push hint, legacy boxes, pairing links.
        let vector = |name: &str| -> Value { serde_json::from_str(&std::fs::read_to_string(format!("{}/../../docs/native/vectors/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()).unwrap() };
        let ss = vector("sealedSender.json");
        let (blob, bob_priv) = (ss["seal"]["blobB64"].as_str().unwrap().to_string(), ss["keys"]["bob"]["x25519PrivB64"].as_str().unwrap().to_string());
        assert!(sealed_sender::open_envelope(&bob_priv, &blob).is_some());
        let mut m = Mutator::new("sealed");
        for mutant in m.bytes(blob.as_bytes(), 250) {
            case("sealed_sender::open_envelope", &mutant, || {
                let Some(s) = text(&mutant) else { return };
                if let Some(inner) = sealed_sender::open_envelope(&bob_priv, s) {
                    let _ = sealed_sender::verify_cert(&inner.cert, ss["serverSigningKey"]["pubB64"].as_str().unwrap_or(""), T0);
                }
            });
        }
        let cert = serde_json::to_string(&ss["cert"]).unwrap();
        let mut m = Mutator::new("cert");
        for mutant in json_mutants(&mut m, &cert, 100) {
            case("sealed_sender::js_json_parse / verify_cert", &mutant, || {
                let Some(v) = text(&mutant).and_then(sealed_sender::js_json_parse) else { return };
                for now in [T0, i64::MIN, i64::MAX] {
                    let _ = sealed_sender::verify_cert(&v, &b64(&a.ed_pub), now);
                }
                let _ = sealed_sender::js_json_stringify(&v);
            });
        }
        let os = vector("offlineSeal.json");
        let (sealed, os_priv) = (os["sealed"].as_str().unwrap().to_string(), os["keys"]["bob"]["x25519PrivB64"].as_str().unwrap().to_string());
        assert!(offline_seal::open_sealed_offline(&sealed, &os_priv).is_some());
        let mut m = Mutator::new("osb1");
        for mutant in m.bytes(sealed.as_bytes(), 250) {
            case("offline_seal::open / process_offline_item / push_hint_open", &mutant, || {
                let Some(s) = text(&mutant) else { return };
                let _ = offline_seal::open_sealed_offline(s, &os_priv);
                let _ = offline_seal::process_offline_item(s, Some(&json!(1001)), Some(&os_priv));
                let _ = offline_seal::handle_pending_sealed(Some(&json!({"sealed": s})), Some(&os_priv));
                assert!(push_hint::push_hint_open(s, &os_priv).is_none(), "an offline blob is not a push hint");
            });
        }
        let inner = os["innerJson"].as_str().map(str::to_string).unwrap_or_else(|| "{\"fromUserId\":1,\"text\":\"x\"}".into());
        let mut m = Mutator::new("offline-inner");
        for mutant in json_mutants(&mut m, &inner, 60) {
            case("offline_seal::process_offline_item (legacy plaintext row)", &mutant, || {
                let Some(s) = text(&mutant) else { return };
                let _ = offline_seal::process_offline_item(s, Some(&json!(1001)), Some(&os_priv));
                if let Ok(v) = serde_json::from_str::<Value>(s) {
                    let _ = offline_seal::handle_pending_sealed(Some(&v), Some(&os_priv));
                }
                let _ = push_hint::PushHint::parse(s);
            });
        }
        let lb = vector("legacyBox.json");
        if let Some(first) = lb["messages"].as_array().and_then(|m| m.first()) {
            let wire = first.as_object().and_then(|o| o.values().find_map(|v| v.as_str().filter(|s| s.starts_with('{')))).unwrap_or("{\"n\":\"AAAA\",\"c\":\"AAAA\"}").to_string();
            let mut m = Mutator::new("legacy-box");
            for mutant in json_mutants(&mut m, &wire, 100) {
                case("legacy_box::open_with_current_key", &mutant, || {
                    let Some(s) = text(&mutant) else { return };
                    let _ = legacy_box::open_with_current_key(s, &b64(&a.ik.public), &b64(&b.ik.private));
                    let _ = legacy_box::decrypt_message(s, &[1; 32]);
                });
            }
        }
        let scan = contact_pair::sign_scan(a.uid, Some("alice".into()), Some("Alice".into()), a.ik.public, &a.ed_secret, [9; 32], T0);
        let link = contact_pair::encode_scan(&scan);
        assert_eq!(contact_pair::decode_pair_url(&link), Some(contact_pair::PairPayload::Scan(scan.clone())), "the seed of the corpus decodes");
        let mut m = Mutator::new("pair");
        for mutant in m.bytes(link.as_bytes(), 300) {
            case("contact_pair::decode_pair_url", &mutant, || {
                if let Some(s) = text(&mutant) {
                    // A scan verifies only with everything its signature covers intact: whatever a
                    // mutant decodes to as a scan names the original uid, keys, seed and time (the
                    // display fields are outside the signature and may differ). A key-less LINK is
                    // unauthenticated by design — it starts a directory lookup, it pins nothing.
                    if let Some(contact_pair::PairPayload::Scan(got)) = contact_pair::decode_pair_url(s) {
                        assert_eq!(
                            (got.uid, &got.ipk, &got.spk, &got.seed, got.ts, &got.sig),
                            (scan.uid, &scan.ipk, &scan.spk, &scan.seed, scan.ts, &scan.sig),
                            "a mutated scan link verified with other signed content"
                        );
                    }
                }
            });
        }
        for id in ["", "abc-def-ghi-jkl", "ABC-DEF-GHI-JKL", "é".repeat(12).as_str(), "a".repeat(100_000).as_str()] {
            case("room_id", id.as_bytes(), || (mrenzo_core::room_id::normalize_room_id(id), mrenzo_core::room_id::is_valid_room_id(id)));
        }
    });
}
