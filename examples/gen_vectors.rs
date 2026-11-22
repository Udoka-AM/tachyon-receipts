//! Writes `vectors/receipts-v0.json`.
//!
//! Run with `cargo run --example gen_vectors`. Every value is derived from a
//! fixed seed, and the note commitments come from `zcash_tachyon`, so the file
//! is reproducible at the pinned tachyon commit.

#[path = "../tests/common/mod.rs"]
mod common;

use common::{note_to, random_fp_bytes};
use rand::{SeedableRng, rngs::StdRng};
use serde_json::{Value, json};
use tachyon_receipts::{Network, Receipt, to_hex};

const TACHYON_REV: &str = "8919018e6bd07e3c65c86a3ea735cf09c88c5ac7";

fn valid(rng: &mut StdRng, value: u64, network: Network, height: u32, context: &[u8]) -> Value {
    let pk = random_fp_bytes(rng);
    let note = note_to(rng, pk, value);
    let mut digest = [0u8; 32];
    rand::RngCore::fill_bytes(rng, &mut digest);
    let receipt = Receipt::new(&note, network, height, digest, context).expect("valid");
    json!({
        "pk": to_hex(&receipt.opening.pk),
        "value": receipt.opening.value,
        "psi": to_hex(&receipt.opening.psi),
        "rcm": to_hex(&receipt.opening.rcm),
        "cm": to_hex(&receipt.cm),
        "network": format!("{network:?}").to_lowercase(),
        "height": height,
        "bundle_digest": to_hex(&digest),
        "context": to_hex(context),
        "receipt": receipt.to_hex(),
    })
}

fn main() {
    let mut rng = StdRng::seed_from_u64(0x7ac4_0e1f);
    let valid_vectors = vec![
        valid(&mut rng, 0, Network::Testnet, 1, b""),
        valid(&mut rng, 1, Network::Regtest, 2_074, b"sealforge:recount"),
        valid(
            &mut rng,
            12_500_000,
            Network::Testnet,
            4_600_000,
            b"audit:deposit-1042",
        ),
        valid(
            &mut rng,
            2_100_000_000_000_000,
            Network::Mainnet,
            u32::MAX,
            &[0xab; 255],
        ),
    ];

    // Invalid encodings, each built from the third valid receipt with one change.
    let base = Receipt::from_hex(valid_vectors[2]["receipt"].as_str().unwrap()).unwrap();
    let good = base.to_bytes();
    let mut invalid = Vec::new();
    let mut push = |reason: &str, bytes: Vec<u8>| {
        invalid.push(json!({ "reason": reason, "receipt": to_hex(&bytes) }));
    };
    let mut b = good.clone();
    b[0] ^= 1;
    push("bad magic", b);
    let mut b = good.clone();
    b[4] = 1;
    push("unsupported version", b);
    push("truncated", good[..good.len() - 1].to_vec());
    let mut b = good.clone();
    b[74..106].fill(0xff);
    push("non-canonical pk", b);
    let mut b = good.clone();
    let rcm = tachyon_receipts::FIXED_LEN - 33;
    b[rcm..rcm + 32].fill(0);
    push("zero rcm", b);

    // Decodes, but fails verification: the value is one zatoshi higher than
    // the note's, so the opening no longer commits to cm.
    let mut inflated = base.clone();
    inflated.opening.value += 1;
    let verify_invalid = vec![json!({
        "reason": "commitment mismatch (value + 1)",
        "receipt": inflated.to_hex(),
    })];

    let out = json!({
        "format": "tachyon-receipts v0",
        "tachyon_rev": TACHYON_REV,
        "note": "cm is zcash_tachyon's Note::commitment(); bundle_digest values are random stand-ins.",
        "valid": valid_vectors,
        "decode_invalid": invalid,
        "verify_invalid": verify_invalid,
    });
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/vectors/receipts-v0.json");
    std::fs::write(path, serde_json::to_string_pretty(&out).unwrap() + "\n").unwrap();
    println!("wrote {path}");
}
