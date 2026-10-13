//! 03-crypto §14 / §16.5: every wire a build ≤ 348 produced is rejected by
//! the v3 core (docs/native/vectors/legacy347/fixtures.json), and v3 output
//! is not accepted by the frozen v2 gate of build 347 either.

use mrenzo_core::contact_pair::decode_pair_url;
use mrenzo_core::group_chains::{validate_skdm, IngestError};
use mrenzo_core::mesh_envelope::{unpack_mesh_outer, verify_mesh_envelope};
use mrenzo_core::ratchet::{Envelope, EnvelopeError};
use mrenzo_core::sdp_signing::{verify_sdp_v2, SdpExpectV2};
use mrenzo_core::sender_keys::{unwrap_envelope, Unwrapped};
use serde_json::Value;

fn fixtures() -> Value {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/native/vectors/legacy347/fixtures.json");
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap()
}

#[test]
fn every_build_347_wire_is_rejected() {
    let f = fixtures();
    assert_eq!(Envelope::parse(s(&f["ratchetV2Wire"])), Err(EnvelopeError::Legacy), "v2 ratchet → placeholder");
    let mesh = unpack_mesh_outer(&serde_json::from_str(s(&f["meshV1OuterJson"])).unwrap()).unwrap().unwrap();
    assert!(!verify_mesh_envelope(&mesh), "mesh v1 is dropped");
    assert_eq!(decode_pair_url(s(&f["pairLinkV1"])), None, "pair link v1");
    assert!(matches!(unwrap_envelope(s(&f["sk1Post"])), Unwrapped::Plain), "an sk1 post is not an sk2 envelope");
    let skdm: Value = serde_json::from_str(s(&f["skdmV1Json"])).unwrap();
    assert!(matches!(validate_skdm(&skdm, 1001), Err(IngestError::UnsupportedVersion(_))));
    assert_eq!(f["skdmTransport2Frame"]["data"]["skdmTransport"], 2, "transport 2 is refused by the pipeline (≠ 3)");
    let offer = &f["callOfferWithoutPvRb"]["data"];
    let expect = SdpExpectV2 { from: 1001, to: "1002".into(), sdp_type: "offer".into(), call_id: "c-1".into(), require_rb: true };
    let r = verify_sdp_v2(offer, &expect, Some(&[1u8; 32]), &[[2u8; 32]], 1_758_800_000_000);
    assert!(!r.ok, "an offer without pv/rb/toUserId: {}", r.reason);
}

/// The frozen v2 gate of build 347 (`RatchetEnvelope::from_wire`, messagePipeline.ts:423-426:
/// `v === 2 && typeof dh/ct === 'string' && typeof n/pn === 'number'`) never
/// takes a v3 envelope: a 347 peer shows nothing decryptable, never a wrong text.
#[test]
fn a_347_core_does_not_accept_v3_output() {
    fn frozen_v2_gate(wire: &str) -> bool {
        let Ok(Value::Object(o)) = serde_json::from_str::<Value>(wire) else { return false };
        o.get("v").and_then(Value::as_f64) == Some(2.0)
            && o.get("dh").is_some_and(Value::is_string)
            && o.get("ct").is_some_and(Value::is_string)
            && o.get("n").is_some_and(Value::is_number)
            && o.get("pn").is_some_and(Value::is_number)
    }
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/native/vectors/ratchetV3.json");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
    let mut checked = 0;
    for step in v["steps"].as_array().unwrap() {
        let wire = s(&step["wire"]);
        assert!(!frozen_v2_gate(wire), "{wire}");
        checked += 1;
    }
    assert!(checked >= 8);
    assert!(frozen_v2_gate(s(&fixtures()["ratchetV2Wire"])), "sanity: the gate takes a v2 wire");
}
