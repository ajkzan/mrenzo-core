//! Replays docs/native/vectors/discovery.json — RFC 9497 Appendix A.1.1
//! (OPRF ristretto255-SHA512) and mr.enzo's contact-discovery layout, as the
//! Go server (internal/discovery) generated them.

use mrenzo_core::discovery::*;
use mrenzo_core::rng::ReplayRng;
use serde_json::Value;

fn v() -> Value {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/native/vectors/discovery.json");
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn h32(v: &Value) -> [u8; 32] {
    hex::decode(v.as_str().unwrap()).unwrap().try_into().unwrap()
}

fn h(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

#[test]
fn rfc9497_oprf_ristretto255_sha512() {
    let v = v();
    let rfc = &v["rfc9497"];
    assert_eq!(hex::encode([b"HashToGroup-".as_slice(), CONTEXT_STRING].concat()), rfc["groupDST"].as_str().unwrap());
    let sk = h32(&rfc["skSm"]);
    for c in rfc["vectors"].as_array().unwrap() {
        let input = h(&c["Input"]);
        let blinded = blind_with(&input, &h32(&c["Blind"])).unwrap();
        assert_eq!(hex::encode(blinded.element), c["BlindedElement"].as_str().unwrap());
        let evaluated = evaluate(&sk, &blinded.element).unwrap();
        assert_eq!(hex::encode(evaluated), c["EvaluationElement"].as_str().unwrap());
        let out = finalize(&input, &blinded.blind, &evaluated).unwrap();
        assert_eq!(hex::encode(out), c["Output"].as_str().unwrap());
    }
}

#[test]
fn mrenzo_inputs_outputs_tags_and_buckets() {
    let v = v();
    let m = &v["mrenzo"];
    let sk = h32(&m["sk"]);
    for c in m["cases"].as_array().unwrap() {
        let raw = c["raw"].as_str().unwrap();
        let input = match c["kind"].as_str().unwrap() {
            "email" => email_input(raw),
            _ => phone_input(raw),
        };
        let want = c["input"].as_str().unwrap();
        assert_eq!(input.as_deref().unwrap_or(""), want, "{raw:?}");
        let Some(input) = input else { continue };
        let blinded = blind_with(input.as_bytes(), &h32(&c["blind"])).unwrap();
        assert_eq!(hex::encode(blinded.element), c["blinded"].as_str().unwrap());
        let evaluated = evaluate(&sk, &blinded.element).unwrap();
        assert_eq!(hex::encode(evaluated), c["evaluated"].as_str().unwrap());
        let out = finalize(input.as_bytes(), &blinded.blind, &h32(&c["evaluated"])).unwrap();
        assert_eq!(hex::encode(out), c["output"].as_str().unwrap());
        let (tag, key) = split_output(&out);
        assert_eq!(hex::encode(tag), c["tag"].as_str().unwrap());
        assert_eq!(hex::encode(key), c["key"].as_str().unwrap());
        assert_eq!(u64::from(bucket(&tag, 4)), c["bucket4"].as_u64().unwrap());
        assert_eq!(u64::from(bucket(&tag, 16)), c["bucket16"].as_u64().unwrap());
    }
}

/// A random blind is 64 drawn bytes reduced mod ℓ; the output does not
/// depend on it.
#[test]
fn a_random_blind_finalizes_to_the_same_output() {
    let v = v();
    let m = &v["mrenzo"];
    let sk = h32(&m["sk"]);
    let case = &m["cases"][0];
    let input = case["input"].as_str().unwrap().as_bytes();
    let mut wide = vec![0x5Au8; 64];
    wide[63] = 0x01;
    let mut rng = ReplayRng::new("blind", vec![wide]);
    let blinded = blind(input, &mut rng).unwrap();
    rng.assert_exhausted();
    let out = finalize(input, &blinded.blind, &evaluate(&sk, &blinded.element).unwrap()).unwrap();
    assert_eq!(hex::encode(out), case["output"].as_str().unwrap());
}
