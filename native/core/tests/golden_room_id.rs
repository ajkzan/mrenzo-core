//! Replays docs/native/vectors/roomId.json — RN `generateRoomId` /
//! `normalizeRoomId` and the server's `validRoomID`.

use mrenzo_core::rng::ReplayRng;
use mrenzo_core::room_id::*;
use serde_json::Value;

fn v() -> Value {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/native/vectors/roomId.json");
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

#[test]
fn generate() {
    for g in v()["generate"].as_array().unwrap() {
        let rng = &g["rng"];
        let draws = rng["draws"].as_array().unwrap().iter().map(|d| hex::decode(d["hex"].as_str().unwrap()).unwrap()).collect();
        let mut r = ReplayRng::new(rng["label"].as_str().unwrap(), draws);
        let id = generate_room_id(&mut r);
        r.assert_exhausted();
        assert_eq!(id, g["roomId"].as_str().unwrap());
        assert!(is_valid_room_id(&id));
    }
}

#[test]
fn normalize() {
    for n in v()["normalize"].as_array().unwrap() {
        let input = n["input"].as_str().unwrap();
        assert_eq!(normalize_room_id(input).as_deref(), n["normalized"].as_str(), "input {input:?}");
    }
}

#[test]
fn validity() {
    for c in v()["validity"].as_array().unwrap() {
        let id = c["id"].as_str().unwrap();
        assert_eq!(is_valid_room_id(id), c["valid"].as_bool().unwrap(), "id {id:?}");
    }
}
