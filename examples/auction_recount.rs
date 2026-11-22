//! A sealed-bid auction recounted from receipts alone.
//!
//! Run with `cargo run --example auction_recount`.
//!
//! What's real and what isn't: every note and note commitment comes from
//! `zcash_tachyon` at the pinned commit. There is no chain and no proof. Each
//! bundle is stood in for by its digest and the tachygram pairs its actions
//! would publish, which is exactly what `BundleView::from_bundle` reads from a
//! real bundle. When a Tachyon testnet runs, the views come from chain data
//! instead and nothing else changes.

#[path = "../tests/common/mod.rs"]
mod common;

use common::{cm_tachygram, note_to, random_fp_bytes, random_tachygram};
use rand::{RngCore, SeedableRng, rngs::StdRng};
use tachyon_receipts::{BundleView, Expect, Network, Receipt, to_hex, verify_batch};

const ZAT: u64 = 100_000_000;

fn main() {
    let mut rng = StdRng::seed_from_u64(20_261_122);
    let context = b"sealforge:auction:DEMO-7:recount";

    // The escrow's payment key. In sealForge it is owned by the 2-of-3 FROST group.
    let escrow = random_fp_bytes(&mut rng);
    println!("escrow pk  {}", &to_hex(&escrow)[..16]);

    // Seven bids, paid to the escrow across three bundles.
    let bids = [0.12, 0.25, 0.08, 0.31, 0.15, 0.22, 0.10];
    let notes: Vec<_> = bids
        .iter()
        .map(|zec| note_to(&mut rng, escrow, (zec * ZAT as f64).round() as u64))
        .collect();
    let cms: Vec<_> = notes.iter().map(cm_tachygram).collect();

    let groups: [&[usize]; 3] = [&[0, 1, 2], &[3, 4], &[5, 6]];
    let mut bundles = Vec::new();
    for (g, members) in groups.iter().enumerate() {
        let mut digest = [0u8; 32];
        rng.fill_bytes(&mut digest);
        // Each bundle also carries actions that have nothing to do with the auction.
        let mut pairs = vec![(random_tachygram(&mut rng), random_tachygram(&mut rng))];
        pairs.extend(
            members
                .iter()
                .map(|&i| (cms[i], random_tachygram(&mut rng))),
        );
        bundles.push((4_600_000 + g as u32, BundleView::new(digest, pairs)));
    }

    // Each bidder (or the escrow's operator) issues one receipt per bid.
    let mut receipts = Vec::new();
    for (g, members) in groups.iter().enumerate() {
        let (height, view) = &bundles[g];
        for &i in *members {
            receipts.push(
                Receipt::new(&notes[i], Network::Regtest, *height, view.digest, context).unwrap(),
            );
        }
    }
    println!(
        "receipts   {} ({} bytes each)",
        receipts.len(),
        receipts[0].to_bytes().len()
    );

    // Anyone recounts: every receipt must verify, pay the escrow, and be unique.
    let lookup = |d: &[u8; 32]| bundles.iter().map(|(_, v)| v).find(|v| &v.digest == d);
    let expect = Expect::network(Network::Regtest)
        .with_context(context)
        .with_recipient(escrow);
    let total = verify_batch(&receipts, lookup, &expect).expect("honest receipts verify");
    println!(
        "recount    {} bids, {}.{:08} ZEC  ok",
        total.count,
        total.total / ZAT,
        total.total % ZAT
    );

    // What a cheating operator or bidder can't get past.
    let mut inflated = receipts.clone();
    inflated[3].opening.value += ZAT;
    report(
        "bid inflated by 1 ZEC",
        verify_batch(&inflated, lookup, &expect),
    );

    let mut doubled = receipts.clone();
    doubled.push(receipts[0].clone());
    report(
        "one bid counted twice",
        verify_batch(&doubled, lookup, &expect),
    );

    let mut elsewhere = receipts.clone();
    // A real note to the escrow that no bundle ever created.
    let stray = note_to(&mut rng, escrow, ZAT);
    let (h, v) = &bundles[0];
    elsewhere.push(Receipt::new(&stray, Network::Regtest, *h, v.digest, context).unwrap());
    report(
        "receipt for a payment that isn't on chain",
        verify_batch(&elsewhere, lookup, &expect),
    );
}

fn report(case: &str, result: Result<tachyon_receipts::BatchTotal, tachyon_receipts::BatchError>) {
    match result {
        Ok(_) => println!("tampered   {case}: ACCEPTED (bug)"),
        Err(e) => println!("tampered   {case}: refused, {e}"),
    }
}
