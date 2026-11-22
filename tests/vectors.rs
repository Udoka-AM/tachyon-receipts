//! Checks `vectors/receipts-v0.json` against this crate and zcash_tachyon.

use serde_json::Value;
use tachyon_receipts::{BundleView, Error, Expect, Network, Opening, Receipt, from_hex, verify};

fn load() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/vectors/receipts-v0.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn h32(v: &Value) -> [u8; 32] {
    from_hex(v.as_str().unwrap()).unwrap().try_into().unwrap()
}

fn network(v: &Value) -> Network {
    match v.as_str().unwrap() {
        "mainnet" => Network::Mainnet,
        "testnet" => Network::Testnet,
        _ => Network::Regtest,
    }
}

#[test]
fn valid_vectors_reproduce() {
    let vectors = load();
    for (i, v) in vectors["valid"].as_array().unwrap().iter().enumerate() {
        let opening = Opening {
            pk: h32(&v["pk"]),
            value: v["value"].as_u64().unwrap(),
            psi: h32(&v["psi"]),
            rcm: h32(&v["rcm"]),
        };
        assert_eq!(
            opening.commitment().unwrap(),
            h32(&v["cm"]),
            "vector {i}: cm"
        );

        let receipt = Receipt {
            network: network(&v["network"]),
            height: u32::try_from(v["height"].as_u64().unwrap()).unwrap(),
            bundle_digest: h32(&v["bundle_digest"]),
            cm: h32(&v["cm"]),
            opening,
            context: from_hex(v["context"].as_str().unwrap()).unwrap(),
        };
        assert_eq!(
            receipt.to_hex(),
            v["receipt"].as_str().unwrap(),
            "vector {i}: encoding"
        );
        assert_eq!(
            Receipt::from_hex(v["receipt"].as_str().unwrap()).unwrap(),
            receipt
        );
    }
}

#[test]
fn decode_invalid_vectors_fail() {
    for v in load()["decode_invalid"].as_array().unwrap() {
        assert!(
            Receipt::from_hex(v["receipt"].as_str().unwrap()).is_err(),
            "{} should not decode",
            v["reason"]
        );
    }
}

#[test]
fn verify_invalid_vectors_fail() {
    for v in load()["verify_invalid"].as_array().unwrap() {
        let receipt = Receipt::from_hex(v["receipt"].as_str().unwrap()).unwrap();
        let bundle = BundleView {
            digest: receipt.bundle_digest,
            tachygrams: [receipt.cm].into(),
        };
        let err = verify(&receipt, &bundle, &Expect::network(receipt.network)).unwrap_err();
        assert_eq!(err, Error::CommitmentMismatch, "{}", v["reason"]);
    }
}
