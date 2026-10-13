//! Skipped message keys of the Sender Keys receiver (native, 2026-09-30,
//! `group_chains::*_skipping`): out-of-order envelopes of one sender open,
//! a key opens once, forged envelopes store nothing, bounds hold, and with
//! no stored keys the batch behaves exactly like the 325 `receive_batch`
//! (the golden vectors run through both).

use mrenzo_core::group_chains::*;
use mrenzo_core::rng::OsRng;
use mrenzo_core::sender_keys::{
    build_skdm, encrypt_group_message, generate_sender_key, wrap_envelope, JsValue, SenderKeyState, SkContext,
    PLACEHOLDER_UNDECRYPTABLE,
};
use serde_json::Value;

const NOW: i64 = 1_790_000_000_000;
/// Group "g", sender 7 (the sk2 signature covers both).
const CTX: SkContext<'static> = SkContext { group_id: "g", sender_uid: 7 };

/// A sender chain and `n` of its wires (counters 0..n).
fn sender_wires(n: usize) -> (SenderKeyState, Vec<String>) {
    let start = generate_sender_key(&mut OsRng);
    let mut state = start.clone();
    let mut wires = Vec::new();
    for i in 0..n {
        let (next, env) = encrypt_group_message(&state, &format!("m{i}"), &CTX, &mut OsRng).unwrap();
        wires.push(wrap_envelope(&env));
        state = next;
    }
    (start, wires)
}

/// The receiver's chain set built from an SKDM of `sender` (at its counter).
fn receiver_set(sender: &SenderKeyState) -> ChainSet {
    let skdm = build_skdm("g", sender, 7).unwrap();
    let valid = validate_skdm(&serde_json::from_str::<Value>(&skdm.to_json()).unwrap(), 7).unwrap();
    ingest_skdm_v2(&ChainSet::default(), &valid).set
}

fn decrypt(set: &mut ChainSet, keys: &mut SkippedKeys, wire: &str) -> Option<String> {
    let (out, skip) = decrypt_with_chains_skipping(set, keys, wire, NOW, &CTX);
    if out.kind != GroupDecryptKind::Opened {
        return None;
    }
    *set = out.set;
    if let Some(stored) = skip {
        *keys = SkippedKeys::from_storage(stored.as_deref());
    }
    Some(out.text)
}

#[test]
fn out_of_order_envelopes_all_open_once() {
    let (sender, wires) = sender_wires(6);
    let mut set = receiver_set(&sender);
    let mut keys = SkippedKeys::default();
    // Later counters first (the Share Extension's post overtakes the app's).
    assert_eq!(decrypt(&mut set, &mut keys, &wires[3]).as_deref(), Some("m3"));
    assert_eq!(keys.len(), 3, "counters 0, 1, 2 kept");
    assert_eq!(decrypt(&mut set, &mut keys, &wires[1]).as_deref(), Some("m1"));
    assert_eq!(decrypt(&mut set, &mut keys, &wires[0]).as_deref(), Some("m0"));
    assert_eq!(decrypt(&mut set, &mut keys, &wires[2]).as_deref(), Some("m2"));
    assert!(keys.is_empty(), "every stored key is used once");
    assert_eq!(decrypt(&mut set, &mut keys, &wires[1]), None, "a replay finds no key");
    assert_eq!(decrypt(&mut set, &mut keys, &wires[5]).as_deref(), Some("m5"));
    assert_eq!(decrypt(&mut set, &mut keys, &wires[4]).as_deref(), Some("m4"));
    assert_eq!(set.current().unwrap().counter, JsValue::Number(6.0));
}

#[test]
fn the_325_rule_would_have_lost_the_earlier_counter() {
    let (sender, wires) = sender_wires(3);
    let set = receiver_set(&sender);
    let after2 = decrypt_with_chains(&set, &wires[2], &CTX);
    assert_eq!(after2.kind, GroupDecryptKind::Opened);
    // 325: counter 1 is below the chain now and never opens.
    assert_eq!(decrypt_with_chains(&after2.set, &wires[1], &CTX).kind, GroupDecryptKind::Failed);
    // Native: the walk kept it.
    let mut set = set;
    let mut keys = SkippedKeys::default();
    decrypt(&mut set, &mut keys, &wires[2]).unwrap();
    assert_eq!(decrypt(&mut set, &mut keys, &wires[1]).as_deref(), Some("m1"));
}

#[test]
fn a_forged_high_counter_stores_nothing_and_moves_nothing() {
    let (sender, wires) = sender_wires(3);
    let set = receiver_set(&sender);
    let mut env: Value = serde_json::from_str(&wires[2][4..]).unwrap();
    env["ctr"] = Value::from(1500);
    let mut keys = SkippedKeys::default();
    let r = open_with_chains_skipping(&set, &mut keys, &env, Some(&mut WALK_BUDGET_PER_SENDER.clone()), NOW, &CTX);
    assert!(matches!(r, OpenResult::Failed { .. }));
    assert!(keys.is_empty(), "no key stored for an envelope that did not open");
    // A below-counter envelope with a stored key but a bad signature does not open or consume it.
    let mut set2 = set.clone();
    let mut keys2 = SkippedKeys::default();
    decrypt(&mut set2, &mut keys2, &wires[2]).unwrap();
    let mut bad: Value = serde_json::from_str(&wires[0][4..]).unwrap();
    bad["sig"] = serde_json::from_str::<Value>(&wires[1][4..]).unwrap()["sig"].clone();
    let mut probe = keys2.clone();
    assert!(matches!(open_with_chains_skipping(&set2, &mut probe, &bad, None, NOW, &CTX), OpenResult::Failed { .. }));
    assert_eq!(probe, keys2, "a failed signature consumes no key");
}

#[test]
fn keys_are_bounded_by_count_and_age() {
    let (sender, _) = sender_wires(0);
    let mut set = receiver_set(&sender);
    let mut state = sender.clone();
    // Walk 1500 then 1000 more: 2500 skipped, capped at MAX_SKIPPED_KEYS.
    let mut keys = SkippedKeys::default();
    for target in [1500u64, 2501] {
        while state.counter.to_number() < target as f64 {
            state = encrypt_group_message(&state, "x", &CTX, &mut OsRng).unwrap().0;
        }
        let (_, env) = encrypt_group_message(&state, "hit", &CTX, &mut OsRng).unwrap();
        let wire = wrap_envelope(&env);
        assert_eq!(decrypt(&mut set, &mut keys, &wire).as_deref(), Some("hit"));
        state = encrypt_group_message(&state, "x", &CTX, &mut OsRng).unwrap().0;
    }
    assert_eq!(keys.len(), MAX_SKIPPED_KEYS);
    assert!(keys.keys.iter().all(|k| k.counter >= 500), "the oldest counters went first");
    // Age: keys past the TTL are dropped on the next prune.
    let mut aged = keys.clone();
    aged.prune(NOW + SKIPPED_KEY_TTL_MS + 1);
    assert!(aged.is_empty());
}

#[test]
fn storage_round_trip_and_garbage() {
    let (sender, wires) = sender_wires(4);
    let mut set = receiver_set(&sender);
    let mut keys = SkippedKeys::default();
    decrypt(&mut set, &mut keys, &wires[3]).unwrap();
    let stored = keys.to_storage().unwrap();
    assert_eq!(SkippedKeys::from_storage(Some(&stored)), keys);
    assert!(SkippedKeys::from_storage(Some("not json")).is_empty());
    assert!(SkippedKeys::from_storage(Some(r#"{"v":1,"k":[{"p":"x","c":-1,"m":"AA=="}]}"#)).is_empty());
    assert_eq!(SkippedKeys::default().to_storage(), None);
}

#[test]
fn a_rotated_chain_keeps_its_keys_until_it_is_dropped() {
    let (old, old_wires) = sender_wires(3);
    let mut set = receiver_set(&old);
    let mut keys = SkippedKeys::default();
    decrypt(&mut set, &mut keys, &old_wires[2]).unwrap();
    // The sender rotates (a kick): the new chain becomes current.
    let (fresh, fresh_wires) = sender_wires(2);
    let skdm = build_skdm("g", &fresh, 7).unwrap();
    let valid = validate_skdm(&serde_json::from_str::<Value>(&skdm.to_json()).unwrap(), 7).unwrap();
    set = ingest_skdm_v2(&set, &valid).set;
    assert_eq!(decrypt(&mut set, &mut keys, &fresh_wires[1]).as_deref(), Some("m1"));
    // A late envelope of the previous chain still opens with its stored key.
    assert_eq!(decrypt(&mut set, &mut keys, &old_wires[0]).as_deref(), Some("m0"));
}

/// Two copies of the same base SKDM (the app's and the extension's) in
/// either order: the member can open every message from the base on.
#[test]
fn a_repeated_base_snapshot_is_harmless() {
    let (sender, wires) = sender_wires(12);
    let mut at10 = sender.clone();
    for _ in 0..10 {
        at10 = encrypt_group_message(&at10, "x", &CTX, &mut OsRng).unwrap().0;
    }
    let skdm = build_skdm("g", &at10, 7).unwrap();
    let valid = validate_skdm(&serde_json::from_str::<Value>(&skdm.to_json()).unwrap(), 7).unwrap();
    let mut set = ingest_skdm_v2(&ChainSet::default(), &valid).set;
    let mut keys = SkippedKeys::default();
    assert_eq!(decrypt(&mut set, &mut keys, &wires[11]).as_deref(), Some("m11"));
    let again = ingest_skdm_v2(&set, &valid);
    assert_eq!(again.action, IngestAction::KeptCurrent);
    set = again.set;
    assert_eq!(decrypt(&mut set, &mut keys, &wires[10]).as_deref(), Some("m10"));
    assert_eq!(decrypt(&mut set, &mut keys, &wires[9]), None, "nothing before the base");
}

#[test]
fn batch_opens_a_late_page_with_stored_keys() {
    let (sender, wires) = sender_wires(8);
    let set = receiver_set(&sender);
    let item = |w: &String| BatchItem { sender_id: 7, raw: w.clone(), is_system: false, cached_plaintext: None, failed_under: None };
    // The newest page first (6, 7), then the older page (2..5) scrolled up.
    let first = receive_batch_skipping(&[item(&wires[6]), item(&wires[7])], 1, "g", NOW, |_| (set.clone(), SkippedKeys::default()));
    assert_eq!(first.results, vec![BatchItemResult::Opened("m6".into()), BatchItemResult::Opened("m7".into())]);
    let set = ChainSet::from_storage(Some(&first.writes[0].1.recv), first.writes[0].1.recvprev.as_deref());
    let keys = SkippedKeys::from_storage(first.skipped_writes[0].1.as_deref());
    assert_eq!(keys.len(), 6);
    let older: Vec<BatchItem> = wires[2..6].iter().map(item).collect();
    let second = receive_batch_skipping(&older, 1, "g", NOW, |_| (set.clone(), keys.clone()));
    assert_eq!(
        second.results,
        (2..6).map(|i| BatchItemResult::Opened(format!("m{i}"))).collect::<Vec<_>>()
    );
    assert!(second.writes.is_empty(), "no chain moved");
    let left = SkippedKeys::from_storage(second.skipped_writes[0].1.as_deref());
    assert_eq!(left.keys.iter().map(|k| k.counter).collect::<Vec<_>>(), vec![0, 1]);
    // Our own envelope is still a placeholder (its plaintext comes from the sender's cache).
    let own = receive_batch_skipping(&[BatchItem { sender_id: 1, ..item(&wires[0]) }], 1, "g", NOW, |_| (set.clone(), keys.clone()));
    assert_eq!(own.results[0], BatchItemResult::Placeholder(PLACEHOLDER_UNDECRYPTABLE.into()));
}

/// sk2: a post verifies only in the group it was sent to and under
/// the sender that sent it; an sk1 or plaintext post is never text.
#[test]
fn sk2_binds_group_and_sender() {
    let (sender, wires) = sender_wires(2);
    let set = receiver_set(&sender);
    let other_group = SkContext { group_id: "h", ..CTX };
    let other_sender = SkContext { sender_uid: 8, ..CTX };
    assert_eq!(decrypt_with_chains(&set, &wires[0], &other_group).kind, GroupDecryptKind::Failed);
    assert_eq!(decrypt_with_chains(&set, &wires[0], &other_sender).kind, GroupDecryptKind::Failed);
    assert_eq!(decrypt_with_chains(&set, &wires[0], &CTX).kind, GroupDecryptKind::Opened);
    // The batch re-attributes by the server-stamped sender: a re-post under uid 8 fails.
    let item = BatchItem { sender_id: 8, raw: wires[1].clone(), is_system: false, cached_plaintext: None, failed_under: None };
    let out = receive_batch_skipping(&[item], 1, "g", NOW, |_| (set.clone(), SkippedKeys::default()));
    assert!(matches!(out.results[0], BatchItemResult::Pending { .. }));
    // sk1 and plaintext posts.
    let sk1 = wires[0].replacen("sk2:", "sk1:", 1).replacen("\"v\":2", "\"v\":1", 1);
    assert_eq!(decrypt_with_chains(&set, &sk1, &CTX).text, PLACEHOLDER_UNDECRYPTABLE);
    assert_eq!(decrypt_with_chains(&set, "hello", &CTX).text, PLACEHOLDER_UNDECRYPTABLE);
    let v1 = wires[0].replacen("\"v\":2", "\"v\":1", 1);
    assert_eq!(decrypt_with_chains(&set, &v1, &CTX).kind, GroupDecryptKind::Failed);
}

/// SKDM v2 (§7.1): `from` must be the server-stamped sender; v1 is rejected.
#[test]
fn skdm_v2_from_and_version() {
    let (sender, _) = sender_wires(0);
    let skdm: Value = serde_json::from_str(&build_skdm("g", &sender, 7).unwrap().to_json()).unwrap();
    assert_eq!(skdm["v"], 2);
    assert!(validate_skdm(&skdm, 7).is_ok());
    assert_eq!(validate_skdm(&skdm, 8), Err(IngestError::FromMismatch));
    let mut v1 = skdm.clone();
    v1["v"] = Value::from(1);
    assert!(matches!(validate_skdm(&v1, 7), Err(IngestError::UnsupportedVersion(_))));
}
