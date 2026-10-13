//! Wire level 2, the feature carriers (wire-1.1 §W7): pttV1.json (the audio
//! chunk and the receiver state), reactGroupV1.json (the post reaction key,
//! the blob, the last-writer-wins register), stickerV1.json (the reference
//! and the PNG padding) and pushHintV1.json (the hint for the Notification
//! Service Extension). See tests/common for the write/verify mode.

mod common;

use common::*;
use mrenzo_core::group_chains::{self as gc, ChainSet, SkippedKeys};
use mrenzo_core::primitives::{b64, secretbox_seal, sha256, x25519_keypair};
use mrenzo_core::ptt::{self, Chunk, PttReceiver, RxOpen};
use mrenzo_core::push_hint::{push_hint_open, push_hint_seal, PushHint};
use mrenzo_core::reactions::{self, RegisterDecision};
use mrenzo_core::rng::StreamRng;
use mrenzo_core::sender_keys::{self as sk, SkContext};
use mrenzo_core::sticker::{self, StickerRef};
use serde_json::{json, Value};

// ───────────────────────────── push-to-talk ─────────────────────────────

/// A chunk whose PLAINTEXT is given byte for byte (to build non-canonical ones).
fn raw_chunk(key: &[u8; 32], pt: &[u8], nonce: [u8; 24]) -> Vec<u8> {
    [nonce.to_vec(), secretbox_seal(pt, &nonce, key)].concat()
}

#[test]
fn ptt_vectors() {
    let key = [0x42u8; 32];
    let ptt_id = "0f8fad5b-d9cb-469f-a165-70867728950e";
    let tx = ptt::ptt_id_bytes(ptt_id).unwrap();
    let packets = |sizes: &[usize]| -> Vec<Vec<u8>> { sizes.iter().enumerate().map(|(i, n)| (0..*n).map(|j| (i * 31 + j) as u8).collect()).collect() };
    let mut cases: Vec<Value> = Vec::new();
    let mut sealed: Vec<Vec<u8>> = Vec::new();
    for (seq, last, sizes) in [(0u32, false, vec![40usize, 37, 41]), (1, false, vec![245]), (2, false, vec![246]), (3, true, vec![12]), (4, true, vec![])] {
        let label = format!("ptt/chunk/{seq}");
        let p = packets(&sizes);
        let chunk = ptt::seal_chunk(&key, seq, last, &p, &mut StreamRng::new(&label)).unwrap();
        let pt = ptt::chunk_plaintext(seq, last, &p).unwrap();
        assert_eq!(pt.len() % 256, 0);
        assert_eq!(chunk.len(), 24 + 16 + pt.len());
        assert_eq!(ptt::open_chunk(&key, &chunk), Some(Chunk { seq, last, packets: p.clone() }));
        cases.push(json!({
            "rngLabel": label, "seq": seq, "last": last, "packetsHex": p.iter().map(|x| hx(x)).collect::<Vec<_>>(),
            "plaintextLen": pt.len(), "plaintextHeadHex": hx(&pt[..9]), "chunkB64": b64(&chunk),
        }));
        sealed.push(chunk);
    }
    assert_eq!(cases[0]["plaintextHeadHex"], "50310000000000007b", "\"P1\", flags 0, seq 0, padLen 123 (9 + 124 + 123 = 256)");
    assert_eq!(cases[1]["plaintextLen"], 256, "9 + 2 + 245 is exactly one bucket");
    assert_eq!(cases[2]["plaintextLen"], 512);
    assert_eq!(cases[4]["plaintextHeadHex"], "5031010000000400f7", "the empty LAST chunk: flags 1, seq 4, padLen 247");

    // ── negatives: one canonical framing, nothing else opens ──
    let nonce = [9u8; 24];
    let good_pt = ptt::chunk_plaintext(7, false, &packets(&[10])).unwrap();
    let mut negatives: Vec<Value> = Vec::new();
    let mut neg = |name: &str, chunk: Vec<u8>, k: &[u8; 32]| {
        assert_eq!(ptt::open_chunk(k, &chunk), None, "{name}");
        negatives.push(json!({"name": name, "keyHex": hx(k), "chunkB64": b64(&chunk)}));
    };
    assert!(ptt::open_chunk(&key, &raw_chunk(&key, &good_pt, nonce)).is_some());
    neg("another key", raw_chunk(&key, &good_pt, nonce), &[0x43; 32]);
    let mut flipped = raw_chunk(&key, &good_pt, nonce);
    *flipped.last_mut().unwrap() ^= 1;
    neg("a flipped ciphertext bit", flipped, &key);
    neg("truncated to less than one bucket", raw_chunk(&key, &good_pt, nonce)[..200].to_vec(), &key);
    let edit = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut pt = good_pt.clone();
        f(&mut pt);
        raw_chunk(&key, &pt, nonce)
    };
    neg("wrong magic", edit(&|pt| pt[1] = 0x32), &key);
    neg("a reserved flag bit", edit(&|pt| pt[2] = 0x02), &key);
    neg("seq of 4096", edit(&|pt| pt[3..7].copy_from_slice(&4096u32.to_be_bytes())), &key);
    neg("a non-zero padding byte", edit(&|pt| *pt.last_mut().unwrap() = 1), &key);
    neg("padLen of 256", edit(&|pt| pt[7..9].copy_from_slice(&256u16.to_be_bytes())), &key);
    neg("padLen one short: the framing does not tile the packets", edit(&|pt| pt[7..9].copy_from_slice(&234u16.to_be_bytes())), &key);
    neg("a zero-length packet", edit(&|pt| pt[9..11].copy_from_slice(&0u16.to_be_bytes())), &key);
    neg("a packet length past the end", edit(&|pt| pt[9..11].copy_from_slice(&4000u16.to_be_bytes())), &key);
    neg("plaintext not a multiple of the bucket", edit(&|pt| pt.truncate(255)), &key);
    neg("no packet without LAST", raw_chunk(&key, &[&[0x50, 0x31, 0, 0, 0, 0, 0, 0, 247][..], &[0u8; 247]].concat(), nonce), &key);

    // ── the receiver: keyed by (sender, transmission), dedupe AFTER authentication ──
    let mut rx = PttReceiver::new();
    assert_eq!(rx.open(1001, &tx, 0, &sealed[0]), RxOpen::NoKey);
    assert!(rx.install_key(1001, &tx, &key));
    assert!(!rx.install_key(1001, &tx, &[1u8; 32]), "the first authenticated key wins");
    let mut script: Vec<Value> = Vec::new();
    let mut step = |rx: &mut PttReceiver, from: i64, seq: u32, chunk: &[u8], note: &str| -> RxOpen {
        let out = rx.open(from, &tx, seq, chunk);
        let label = match &out {
            RxOpen::Opened { first, complete, last, .. } => format!("opened first={first} last={last} complete={complete}"),
            RxOpen::Duplicate => "duplicate".into(),
            RxOpen::NoKey => "noKey".into(),
            RxOpen::Rejected => "rejected".into(),
        };
        script.push(json!({"from": from, "seq": seq, "chunkB64": b64(chunk), "outcome": label, "note": note}));
        out
    };
    // A truncated stream: chunks 0 and 2 arrive, the end never does.
    assert!(matches!(step(&mut rx, 1001, 0, &sealed[0], "first chunk"), RxOpen::Opened { first: true, complete: false, .. }));
    assert_eq!(step(&mut rx, 1001, 1, &sealed[0], "chunk 0 presented as number 1"), RxOpen::Rejected);
    assert!(matches!(step(&mut rx, 1001, 2, &sealed[2], "a gap is allowed"), RxOpen::Opened { first: false, complete: false, .. }));
    assert_eq!(rx.last_seq(1001, &tx), None, "no LAST chunk: the transmission is NOT complete («прервано»), whatever a clear ptt-end says");
    // Another pinned contact who heard the id cannot use up the numbers.
    assert_eq!(step(&mut rx, 1003, 1, &sealed[1], "another sender, no key under that sender"), RxOpen::NoKey);
    let mallory_key = [0x66u8; 32];
    assert!(rx.install_key(1003, &tx, &mallory_key));
    let forged = ptt::seal_chunk(&mallory_key, 1, false, &packets(&[5]), &mut StreamRng::new("ptt/mallory")).unwrap();
    assert_eq!(step(&mut rx, 1001, 1, &forged, "her chunk for seq 1 presented as Alice's: not authentic, nothing recorded"), RxOpen::Rejected);
    assert!(matches!(step(&mut rx, 1001, 1, &sealed[1], "Alice's real seq 1 still plays"), RxOpen::Opened { .. }));
    assert_eq!(step(&mut rx, 1001, 1, &sealed[1], "its duplicate"), RxOpen::Duplicate);
    // The authenticated end.
    assert!(matches!(step(&mut rx, 1001, 3, &sealed[3], "the LAST chunk"), RxOpen::Opened { last: true, complete: true, .. }));
    assert_eq!(rx.last_seq(1001, &tx), Some(3));
    assert_eq!(step(&mut rx, 1001, 4, &sealed[4], "nothing follows the authenticated end"), RxOpen::Rejected);

    let key_obj = ptt::PttKey { k: key, codec: "opus".into(), sr: 16_000 };
    let mut v = header_v11(
        "pttV1",
        &[
            "chunk = nonce(24) ‖ secretbox(K, nonce, pt); pt = \"P1\" ‖ flags(1) ‖ BE32(seq) ‖ BE16(padLen) ‖ packets ‖ 0x00^padLen; packets = (BE16(len) ‖ packet)*, 1 ≤ len ≤ 4096, ≤ 512 packets, none only with LAST.",
            "flags bit0 = LAST (the authenticated end of the transmission), every other bit 0; len(pt) is a multiple of 256 and ≤ 16 384; padLen ≤ 255; seq < 4096. The nonce is the 24 bytes drawn under the case's label.",
            "Receiver state is keyed by (sender uid, transmission id); a sequence number is recorded only after its chunk opened under K and named the same seq inside the box. A transmission is complete only once a LAST chunk opened.",
            "The key travels once per transmission as the typed plaintext {\"t\":\"ptt\",\"id\":<pttId>,\"ptt\":{\"v\":1,\"k\",\"codec\",\"sr\"}} (typedV11.json).",
        ],
    );
    v.insert("keyHex".into(), json!(hx(&key)));
    v.insert("pttId".into(), json!(ptt_id));
    v.insert("txHex".into(), json!(hx(&tx)));
    v.insert("keyObject".into(), key_obj.to_value());
    v.insert("chunks".into(), Value::Array(cases));
    v.insert("negatives".into(), Value::Array(negatives));
    v.insert("receiver".into(), json!({"sender": 1001, "otherSender": 1003, "otherSenderKeyHex": hx(&mallory_key), "steps": script}));
    check_or_write("pttV1.json", &Value::Object(v));
}

// ───────────────────────────── reactions ─────────────────────────────

#[test]
fn group_reaction_vectors() {
    let (group, alice_uid, bob_uid, carol_uid) = ("abc-def-ghi-jkl", 1001i64, 1002i64, 1003i64);
    // Alice posts twice; Bob opens the second post first (the first one's key then comes from the skipped store).
    let state0 = sk::generate_sender_key(&mut StreamRng::new("rx/chain"));
    let post1 = gc::encrypt_outgoing(group, alice_uid, &state0, "первый пост", &mut StreamRng::new("rx/post1")).unwrap();
    let post2 = gc::encrypt_outgoing(group, alice_uid, &post1.next, "второй пост", &mut StreamRng::new("rx/post2")).unwrap();
    assert_eq!(post1.reaction_key, gc::outgoing_reaction_key(&state0), "the sender derives rk from the chain key it seals with");
    assert_ne!(post1.reaction_key, post2.reaction_key);
    let mk1 = sk::derive_message_key(&state0.chain_key);
    assert_eq!(post1.reaction_key, reactions::post_reaction_key(&mk1));

    let skdm = gc::validate_skdm(&serde_json::from_str(&post1.skdm.to_json()).unwrap(), alice_uid).unwrap();
    let set = gc::ingest_skdm_v2(&ChainSet::default(), &skdm).set;
    let items = |raws: &[&str]| -> Vec<gc::BatchItem> {
        raws.iter().map(|r| gc::BatchItem { sender_id: alice_uid, raw: r.to_string(), is_system: false, cached_plaintext: None, failed_under: None }).collect()
    };
    let first = gc::receive_batch_skipping(&items(&[&post2.wire]), bob_uid, group, T0, |_| (set.clone(), SkippedKeys::default()));
    assert_eq!(first.results, vec![gc::BatchItemResult::Opened("второй пост".into())]);
    assert_eq!(first.reaction_keys, vec![Some(post2.reaction_key)], "a reader derives the same rk from the message key");
    let set_after = ChainSet::from_storage(Some(&first.writes[0].1.recv), first.writes[0].1.recvprev.as_deref());
    let skipped_after = SkippedKeys::from_storage(first.skipped_writes[0].1.as_deref());
    let second = gc::receive_batch_skipping(&items(&[&post1.wire]), bob_uid, group, T0, |_| (set_after.clone(), skipped_after.clone()));
    assert_eq!(second.reaction_keys, vec![Some(post1.reaction_key)], "also when the key came from the skipped-key store");

    // Bob reacts to post 1, then removes the reaction.
    let rk = post1.reaction_key;
    let (post_id, ts) = ("9041", 1_790_000_000_000u64);
    let add = reactions::group_reaction_seal(&rk, group, post_id, bob_uid, "rx-1", &["❤️".to_string()], ts, &mut StreamRng::new("rx/blob1")).unwrap();
    let remove = reactions::group_reaction_seal(&rk, group, post_id, bob_uid, "rx-2", &[], ts + 5, &mut StreamRng::new("rx/blob2")).unwrap();
    assert!(add.starts_with("rx1:"));
    assert_eq!(add.len(), remove.len(), "the server cannot tell an add from a removal");
    // …nor one emoji from another, nor one from three: the blob length is that of the longest
    // legal `e` (three entries of 64 bytes) whatever `e` is. A ZWJ family, a flag of tag
    // characters and three long entries all cross the 64-byte boundary that ❤️ does not.
    let longest: Vec<String> = ["a", "b", "c"].iter().map(|c| c.repeat(64)).collect();
    for e in [vec!["👨‍👩‍👧‍👦".to_string()], vec!["👩‍❤️‍💋‍👨".to_string()], vec!["🏴󠁧󠁢󠁥󠁮󠁧󠁿".to_string()], vec!["👍".to_string(), "🔥".to_string(), "👨‍👩‍👧‍👦".to_string()], longest.clone()] {
        let blob = reactions::group_reaction_seal(&rk, group, post_id, bob_uid, "rx-3", &e, ts, &mut StreamRng::new("rx/blob-len")).unwrap();
        assert_eq!(blob.len(), add.len(), "{e:?}");
        assert_eq!(reactions::group_reaction_open(&rk, group, post_id, bob_uid, &blob).unwrap().e, e);
    }
    // The longest ids a group reaction can name still fit the 1024-byte blob with the longest `e`.
    let (long_group, long_post) = ("g".repeat(128), "9".repeat(128));
    let widest = reactions::group_reaction_seal(&rk, &long_group, &long_post, bob_uid, &format!("rx-{}", "f".repeat(36)), &longest, ts, &mut StreamRng::new("rx/blob-wide")).unwrap();
    assert!(widest.len() <= reactions::BLOB_MAX_BYTES, "{}", widest.len());
    assert_eq!(reactions::group_reaction_open(&rk, &long_group, &long_post, bob_uid, &widest).unwrap().e, longest);
    let opened = reactions::group_reaction_open(&rk, group, post_id, bob_uid, &add).unwrap();
    assert_eq!((opened.id.as_str(), opened.e.clone(), opened.ts), ("rx-1", vec!["❤️".to_string()], ts));
    assert!(reactions::group_reaction_open(&rk, group, post_id, bob_uid, &remove).unwrap().e.is_empty());

    let k_u = reactions::reactor_key(&rk, group, post_id, bob_uid).unwrap();
    let mut negatives: Vec<Value> = Vec::new();
    let mut neg = |name: &str, rk: &[u8; 32], g: &str, p: &str, uid: i64, blob: &str| {
        assert_eq!(reactions::group_reaction_open(rk, g, p, uid, blob), None, "{name}");
        negatives.push(json!({"name": name, "rkB64": b64(rk), "groupId": g, "postId": p, "reactorUid": uid, "blob": blob}));
    };
    neg("the row re-attributed to another user", &rk, group, post_id, carol_uid, &add);
    neg("the row moved to another post", &rk, group, "9042", bob_uid, &add);
    neg("the row moved to another group", &rk, "zzz-zzz-zzz-zzz", post_id, bob_uid, &add);
    neg("the reaction key of another post", &post2.reaction_key, group, post_id, bob_uid, &add);
    neg("no prefix", &rk, group, post_id, bob_uid, &add[4..]);
    let mut flipped = add.clone().into_bytes();
    let n = flipped.len();
    flipped[n - 5] = if flipped[n - 5] == b'A' { b'B' } else { b'A' };
    neg("a flipped ciphertext character", &rk, group, post_id, bob_uid, std::str::from_utf8(&flipped).unwrap());
    // Sealed under the right key, but the inside is not a react state for this post.
    let seal_raw = |json: &str| {
        let nonce = [7u8; 24];
        format!("rx1:{}", b64(&[nonce.to_vec(), secretbox_seal(json.as_bytes(), &nonce, &k_u)].concat()))
    };
    neg("a react state that names another post", &rk, group, post_id, bob_uid, &seal_raw(r#"{"t":"react","id":"x","to":"9999","e":[],"ts":5}"#));
    neg("another kind inside", &rk, group, post_id, bob_uid, &seal_raw(r#"{"t":"chat","id":"x","body":"hi"}"#));
    neg("an unknown kind inside", &rk, group, post_id, bob_uid, &seal_raw(r#"{"t":"poll","id":"x"}"#));
    neg("a blob over 1024 bytes", &rk, group, post_id, bob_uid, &format!("rx1:{}", "A".repeat(1024)));
    assert!(reactions::group_reaction_seal(&rk, "a|b", post_id, bob_uid, "x", &[], ts, &mut StreamRng::new("x")).is_err(), "an id that cannot be bound into the key");
    assert!(reactions::group_reaction_seal(&rk, group, post_id, bob_uid, "x", &["a".into(), "a".into()], ts, &mut StreamRng::new("x")).is_err());
    assert!(reactions::group_reaction_seal(&rk, group, post_id, bob_uid, "x", &["\"".into()], ts, &mut StreamRng::new("x")).is_err(), "an entry JSON would escape is not an entry");

    // ── the register (last-writer-wins on the sender's raw (ts, id)) ──
    let now = T0;
    let fast = now as u64 + 3 * 3_600_000; // a clock three hours ahead
    let register: Vec<Value> = [
        ("first state", None, (ts, "rx-1"), RegisterDecision::Apply),
        ("a newer state", Some((ts, "rx-1")), (ts + 5, "rx-2"), RegisterDecision::Apply),
        ("the older state arriving later (WS replay after HTTP backlog)", Some((ts + 5, "rx-2")), (ts, "rx-1"), RegisterDecision::Keep),
        ("a duplicate", Some((ts + 5, "rx-2")), (ts + 5, "rx-2"), RegisterDecision::Keep),
        ("same ts: the larger id wins", Some((ts, "rx-1")), (ts, "rx-2"), RegisterDecision::Apply),
        ("fast clock, B (newer) delivered first", None, (fast + 1, "rx-b"), RegisterDecision::Apply),
        ("fast clock, A (older) delivered second: it loses — no clamping", Some((fast + 1, "rx-b")), (fast, "rx-a"), RegisterDecision::Keep),
        ("more than 24 h ahead: ignored, nothing stored", None, (now as u64 + reactions::FUTURE_LIMIT_MS as u64 + 1, "rx-z"), RegisterDecision::TooFarAhead),
        ("exactly 24 h ahead is accepted", None, (now as u64 + reactions::FUTURE_LIMIT_MS as u64, "rx-y"), RegisterDecision::Apply),
    ]
    .iter()
    .map(|(name, stored, new, want)| {
        assert_eq!(reactions::register_decide(*stored, new.0, new.1, now), *want, "{name}");
        json!({"name": name, "stored": stored.map(|(t, i)| json!({"ts": t, "id": i})), "new": {"ts": new.0, "id": new.1}, "nowMs": now,
               "decision": match want { RegisterDecision::Apply => "apply", RegisterDecision::Keep => "keep", RegisterDecision::TooFarAhead => "tooFarAhead" }})
    })
    .collect();

    let mut v = header_v11(
        "reactGroupV1",
        &[
            "A reaction in a room or channel is sealed under a key bound to the POST, so that reacting never makes a subscriber a Sender-Keys sender: mk = HKDF(ck_ctr, \"mrenzo-sender-msg\") (the post's message key); rk = HKDF(mk, \"mrenzo-sender-rx-v1\"); k_u = HKDF(rk, \"mrenzo-grx-v1|\" + groupId + \"|\" + postId + \"|\" + reactorUid).",
            "blob = \"rx1:\" + b64(nonce(24) ‖ secretbox(k_u, nonce, UTF-8 react JSON)), ≤ 1024 bytes; react JSON = {\"t\":\"react\",\"id\",\"to\":<postId>,\"e\":[…],\"ts\"} padded with \"p\" to a multiple of 64 bytes, no caps. HKDF = HKDF-SHA256, 32-byte zero salt.",
            "rk is derived when a post is sealed (from the chain key about to be used) and when it is opened (from the message key, also one taken from the skipped-key store), and is stored sealed beside the cached plaintext.",
            "Register: last-writer-wins per (room, post, user) on the sender's RAW (ts, id), id compared as bytes; no clamping; a state stamped more than 24 h ahead of the receiver's clock is ignored and not stored.",
            "Attribution rests on the server-stamped user id and on possession of rk — weaker than the sk2 signature of a post, accepted for emoji (03 §V3.7.6).",
        ],
    );
    v.insert("groupId".into(), json!(group));
    v.insert("author".into(), json!({"uid": alice_uid, "chainRngLabel": "rx/chain", "chainKeyB64": b64(&state0.chain_key)}));
    v.insert(
        "posts".into(),
        json!([
            {"rngLabel": "rx/post1", "counter": 0, "wire": post1.wire, "messageKeyB64": b64(&mk1), "rkB64": b64(&post1.reaction_key)},
            {"rngLabel": "rx/post2", "counter": 1, "wire": post2.wire, "rkB64": b64(&post2.reaction_key)},
        ]),
    );
    v.insert(
        "reaction".into(),
        json!({
            "postId": post_id, "reactorUid": bob_uid, "kUB64": b64(&k_u),
            "add": {"rngLabel": "rx/blob1", "id": "rx-1", "e": ["❤️"], "ts": ts, "blob": add},
            "remove": {"rngLabel": "rx/blob2", "id": "rx-2", "e": [], "ts": ts + 5, "blob": remove},
        }),
    );
    v.insert("negatives".into(), Value::Array(negatives));
    v.insert("register".into(), Value::Array(register));
    check_or_write("reactGroupV1.json", &Value::Object(v));
}

/// Foreign `sk<N>:` prefixes (wire-1.1 §W3.6): a post of a NEWER build is
/// reported as such, never as plaintext and never as «не удалось расшифровать».
#[test]
fn a_post_of_a_newer_build_is_not_undecryptable() {
    for (raw, want) in [
        ("sk3:{\"v\":3}", Some(3)),
        ("sk10:whatever", Some(10)),
        ("sk2:{}", Some(2)),
        ("sk1:{}", Some(1)),
        ("sk03:{}", None),
        ("sk:{}", None),
        ("sk3", None),
        ("skx:{}", None),
        ("hello", None),
        ("sk9999999999:x", None),
    ] {
        assert_eq!(gc::envelope_prefix_version(raw), want, "{raw}");
    }
    let item = |raw: &str| gc::BatchItem { sender_id: 7, raw: raw.into(), is_system: false, cached_plaintext: None, failed_under: None };
    let out = gc::receive_batch_skipping(&[item("sk3:{\"future\":1}"), item("sk1:{}"), item("plain text")], 1, "g", T0, |_| Default::default());
    assert_eq!(out.newer_versions, vec![Some(3), None, None]);
    assert!(out.results.iter().all(|r| matches!(r, gc::BatchItemResult::Placeholder(_))), "the 1.0.0-shaped result is unchanged");
    // The chain walk is bounded inside the primitive too (a counter at 2^53, where i + 1 == i).
    let state = sk::SenderKeyState { chain_key: vec![1; 32], signing_pub: vec![2; 32], signing_priv: vec![], counter: sk::JsValue::Number(9_007_199_254_740_992.0) };
    let env = json!({"v": 2, "ctr": 9_007_199_254_740_994.0, "n": b64(&[0u8; 24]), "ct": b64(&[0u8; 32]), "sig": b64(&[0u8; 64])});
    let _ = sk::decrypt_group_message(&state, &env, &SkContext { group_id: "g", sender_uid: 7 }); // returns; it used to spin for ever past the signature check
}

// ───────────────────────────── stickers ─────────────────────────────

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for b in data {
        crc ^= *b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xedb8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

fn chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut c = (data.len() as u32).to_be_bytes().to_vec();
    c.extend_from_slice(kind);
    c.extend_from_slice(data);
    c.extend_from_slice(&crc32(&[kind.as_slice(), data].concat()).to_be_bytes());
    c
}

/// A structurally valid PNG: nothing in the core decodes pixels.
fn png(w: u32, h: u32, idat: &[u8]) -> Vec<u8> {
    let ihdr = [&w.to_be_bytes()[..], &h.to_be_bytes()[..], &[8, 6, 0, 0, 0]].concat();
    [&[0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a][..], &chunk(b"IHDR", &ihdr), &chunk(b"IDAT", idat), &chunk(b"IEND", &[])].concat()
}

#[test]
fn sticker_vectors() {
    let canonical = png(512, 512, b"not really deflate data, and it does not have to be");
    let id = sticker::sticker_canonical_id(&canonical).unwrap();
    assert_eq!(id, hx(&sha256(&canonical)));
    let padded = sticker::sticker_pad_png(&canonical).unwrap();
    assert_eq!(padded.len(), 32_768);
    assert_eq!(sticker::sticker_strip_padding(&padded).unwrap(), canonical);
    assert_eq!(sticker::sticker_canonical_id(&padded).unwrap(), id, "the id is that of the canonical bytes whatever the padding");
    let pad_at = canonical.len() - 12;
    assert_eq!(&padded[pad_at + 4..pad_at + 8], b"mrPd");
    assert_eq!(&padded[padded.len() - 12..], &canonical[pad_at..], "IEND stays last");
    let info = sticker::png_info(&padded).unwrap();
    assert_eq!((info.width, info.height), (512, 512));

    let st = StickerRef { id: id.clone(), pack: Some("0123456789abcdef01234567".into()), emoji: Some("😀".into()), w: 512, h: 512 };
    // The body of the `file` plaintext as it is on the wire: the FileEnvelope JSON of 03 §8.3
    // (short keys; `p` is the placeholder a 1.0.0 peer shows), `kind`, and the soft key `st`.
    let attachment = mrenzo_core::files::FileEnvelope {
        placeholder: "📎".into(),
        file_id: "f-1".into(),
        key: b64(&[1u8; 32]),
        nonce: b64(&[2u8; 24]),
        mime_type: "image/png".into(),
        file_name: None,
        file_size: Some((padded.len() + 16) as f64),
        duration: None,
    };
    let mut body: Value = serde_json::from_str(&mrenzo_core::files::build_file_envelope(&attachment)).unwrap();
    body["kind"] = json!("image");
    body["st"] = st.to_value();
    assert_eq!(sticker::sticker_ref_parse(&body.to_string()), Some(st.clone()));
    assert_eq!(mrenzo_core::files::parse_file_envelope(&body.to_string()), Some(attachment), "the attachment reads the same with `st` in the body");
    let refs: Vec<Value> = [
        ("valid", st.to_value()),
        ("without pack and emoji", json!({"v":1,"id":id,"w":1,"h":512})),
        ("unknown keys are ignored", json!({"v":1,"id":id,"w":512,"h":512,"anim":true})),
        ("another version", json!({"v":2,"id":id,"w":512,"h":512})),
        ("id in upper case", json!({"v":1,"id":id.to_uppercase(),"w":512,"h":512})),
        ("id too short", json!({"v":1,"id":&id[..62],"w":512,"h":512})),
        ("pack not 24 hex", json!({"v":1,"id":id,"pack":"abc","w":512,"h":512})),
        ("emoji with a control character", json!({"v":1,"id":id,"e":"a\u{7}","w":512,"h":512})),
        ("side of 513", json!({"v":1,"id":id,"w":513,"h":512})),
        ("side of 0", json!({"v":1,"id":id,"w":512,"h":0})),
        ("a side that is not an integer", json!({"v":1,"id":id,"w":512.0,"h":512})),
        ("not an object", json!("sticker")),
    ]
    .iter()
    .map(|(name, v)| json!({"name": name, "st": v, "accepted": StickerRef::from_value(v).is_some()}))
    .collect();
    assert_eq!(refs.iter().filter(|r| r["accepted"] == true).count(), 3);

    let iend = canonical.len() - 12;
    let malformed: Vec<Value> = [
        ("empty", vec![]),
        ("the signature only", canonical[..8].to_vec()),
        ("one byte short", canonical[..canonical.len() - 1].to_vec()),
        ("a byte after IEND", [&canonical[..], &[0]].concat()),
        ("IHDR not first", [&canonical[..8], &chunk(b"IDAT", b"x")[..], &canonical[8..]].concat()),
        ("a chunk length past the end", {
            let mut p = canonical.clone();
            p[33..37].copy_from_slice(&0xffff_fff0u32.to_be_bytes());
            p
        }),
        ("two pad chunks", [&canonical[..iend], &chunk(b"mrPd", &[0; 8])[..], &chunk(b"mrPd", &[0; 8])[..], &canonical[iend..]].concat()),
        ("a pad chunk that is not directly before IEND", [&canonical[..iend], &chunk(b"mrPd", &[0; 8])[..], &chunk(b"tEXt", b"k\0v")[..], &canonical[iend..]].concat()),
        ("non-zero padding", [&canonical[..iend], &chunk(b"mrPd", &[0, 0, 1, 0])[..], &canonical[iend..]].concat()),
        ("a pad chunk with a wrong CRC", {
            let mut p = padded.clone();
            let n = p.len();
            p[n - 13] ^= 0xff;
            p
        }),
    ]
    .iter()
    .map(|(name, bytes)| {
        assert!(sticker::png_info(bytes).is_none(), "{name}");
        assert!(sticker::sticker_canonical_id(bytes).is_none() && sticker::sticker_pad_png(bytes).is_none() && sticker::sticker_strip_padding(bytes).is_none());
        json!({"name": name, "pngB64": b64(bytes)})
    })
    .collect();

    let mut v = header_v11(
        "stickerV1",
        &[
            "A sticker is an ordinary encrypted image attachment (t:\"file\", kind image, image/png) whose body carries \"st\":{\"v\":1,\"id\":<64 lowercase hex>,\"pack\"?:<24 lowercase hex>,\"e\"?:<1..64 bytes, no control character>,\"w\",\"h\":1..512}. Any violation = st absent (a plain photo), never a broken message.",
            "id = hex(SHA-256(canonical PNG bytes)). The wire copy may carry ONE private ancillary chunk \"mrPd\" of zero bytes immediately before IEND: padded size = the smallest multiple of 32 768 ≥ canonical size + 12; canonical bytes = the PNG without that chunk.",
            "PNG = 89 50 4E 47 0D 0A 1A 0A ‖ chunk*; chunk = BE32(len) ‖ type[4] ‖ data ‖ CRC32(type ‖ data). The walk checks: signature, IHDR (13 bytes) first, every length inside the buffer, an empty IEND last with nothing after it, at most one mrPd (directly before IEND, zeros, correct CRC), ≤ 1 MiB. No pixel is decoded.",
            "The sample PNG is structurally valid only (its IDAT is not image data); `paddedSha256Hex` pins the padded form without storing 32 KB of zeros.",
        ],
    );
    v.insert("canonicalPngB64".into(), json!(b64(&canonical)));
    v.insert("canonicalLen".into(), json!(canonical.len()));
    v.insert("id".into(), json!(id));
    v.insert("padded".into(), json!({"len": padded.len(), "padDataLen": padded.len() - canonical.len() - 12, "sha256Hex": hx(&sha256(&padded)), "padChunkHeadHex": hx(&padded[pad_at..pad_at + 8]), "padChunkCrcHex": hx(&padded[padded.len() - 16..padded.len() - 12])}));
    v.insert("fileBody".into(), body);
    v.insert("references".into(), Value::Array(refs));
    v.insert("malformedPngs".into(), Value::Array(malformed));
    check_or_write("stickerV1.json", &Value::Object(v));
}

// ───────────────────────────── push hint ─────────────────────────────

#[test]
fn push_hint_vectors() {
    let (a, b) = (alice(), bob());
    let other = x25519_keypair(&mut StreamRng::new("mz/other"));
    let direct = PushHint::Direct { from: a.uid, mid: Some("m-1".into()) };
    let channel = PushHint::Channel { ch: "abc-def-ghi-jkl".into(), mid: None };
    let mz_direct = push_hint_seal(&direct, &b.ik.public, &mut StreamRng::new("mz/direct")).unwrap();
    let mz_channel = push_hint_seal(&channel, &b.ik.public, &mut StreamRng::new("mz/channel")).unwrap();
    assert_eq!(direct.to_json(), r#"{"from":1001,"mid":"m-1"}"#);
    assert_eq!(channel.to_json(), r#"{"ch":"abc-def-ghi-jkl"}"#);
    assert_eq!(push_hint_open(&mz_direct, &b64(&b.ik.private)), Some(direct));
    assert_eq!(push_hint_open(&mz_channel, &b64(&b.ik.private)), Some(channel));
    assert!(mz_direct.len() < 200, "about 170 bytes of the 4 KB push payload");

    let seal_json = |json: &str, label: &str| mrenzo_core::offline_seal::seal_offline_blob(json.as_bytes(), &b.ik.public, &mut StreamRng::new(label));
    let mut negatives: Vec<Value> = Vec::new();
    let mut neg = |name: &str, mz: String, key: &[u8; 32]| {
        assert_eq!(push_hint_open(&mz, &b64(key)), None, "{name}");
        negatives.push(json!({"name": name, "mz": mz, "x25519PrivB64": b64(key)}));
    };
    neg("sealed to another device", mz_direct.clone(), &other.private);
    neg("not sealed at all", r#"{"from":1001}"#.into(), &b.ik.private);
    neg("both from and ch", seal_json(r#"{"from":1001,"ch":"x"}"#, "mz/n1"), &b.ik.private);
    neg("neither", seal_json(r#"{"mid":"m"}"#, "mz/n2"), &b.ik.private);
    neg("from is not an integer", seal_json(r#"{"from":"1001"}"#, "mz/n3"), &b.ik.private);
    neg("from of 0", seal_json(r#"{"from":0}"#, "mz/n4"), &b.ik.private);
    neg("a duplicate key", seal_json(r#"{"from":1001,"from":1002}"#, "mz/n5"), &b.ik.private);
    neg("an empty channel id", seal_json(r#"{"ch":""}"#, "mz/n6"), &b.ik.private);
    neg("a hint over 512 bytes", seal_json(&format!(r#"{{"from":1001,"x":"{}"}}"#, "y".repeat(600)), "mz/n7"), &b.ik.private);
    let mut cut = mz_direct.clone();
    cut.truncate(mz_direct.len() - 8);
    neg("a truncated blob", cut, &b.ik.private);

    let mut v = header_v11(
        "pushHintV1",
        &[
            "For a push token registered with \"nse\":1 the server adds \"mutable-content\":1 and one payload key: mz = \"OSB1:\" + b64(eph_pub[32] ‖ nonce[24] ‖ crypto_box(hint, nonce, IK_recipient, eph_priv)) — the offline seal of offlineSeal.json. Draws: the ephemeral secret (32), then the nonce (24).",
            "hint = {\"from\":<uid>[,\"mid\":<messageId>]} for a 1:1 message, {\"ch\":<channelId>[,\"mid\"]} for a room or channel post. Exactly one of from / ch; unknown keys ignored; a duplicate key, another shape or more than 512 bytes → no hint. A sealed-sender frame carries no mz.",
            "The Notification Service Extension opens mz with the identity private key and rewrites the notification. It MUST NOT read or write session rows or the aux and MUST NOT step a ratchet.",
        ],
    );
    v.insert("keys".into(), json!({"alice": a.json(), "bob": b.json()}));
    v.insert("direct".into(), json!({"rngLabel": "mz/direct", "hintJson": r#"{"from":1001,"mid":"m-1"}"#, "mz": mz_direct}));
    v.insert("channel".into(), json!({"rngLabel": "mz/channel", "hintJson": r#"{"ch":"abc-def-ghi-jkl"}"#, "mz": mz_channel}));
    v.insert("negatives".into(), Value::Array(negatives));
    check_or_write("pushHintV1.json", &Value::Object(v));
}
