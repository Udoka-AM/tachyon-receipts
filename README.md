# tachyon-receipts

Payment receipts for Zcash's Tachyon shielded pool: prove one payment to
someone else without a viewing key.

Tachyon removes viewing keys from the core protocol, so "show me this deposit
arrived" has no answer today. A receipt carries one note's opening and where it
was created. Anyone can check it by recomputing the note commitment with
`zcash_tachyon` and finding it among the bundle's tachygrams. A batch of
receipts is a public recount.

**Status: draft v0, no network.** Notes and commitments are real
`zcash_tachyon` values at commit
[`8919018`](https://github.com/tachyon-zcash/tachyon/tree/8919018e6bd07e3c65c86a3ea735cf09c88c5ac7).
There's no Tachyon testnet to read bundles from yet, so the demo stands in for
each bundle with its digest and output tachygrams, which is what
`BundleView::from_bundle` reads from a real `Bundle`. Unaudited. Not for use
with real funds.

- The format, verification rules and limits: [SPEC.md](SPEC.md)
- Test vectors: [`vectors/receipts-v0.json`](vectors/receipts-v0.json)

## Try it

Needs Rust 1.97 or newer. The toolchain file pins 1.99.0.

```bash
cargo test
cargo run --example auction_recount
```

The recount demo pays seven sealed-bid auction bids to an escrow, issues one
receipt per bid, recounts the total from receipts alone, and shows three
tampered recounts being refused:

```text
receipts   7 (211 bytes each)
recount    7 bids, 1.23000000 ZEC  ok
tampered   bid inflated by 1 ZEC: refused, receipt 3: the opening does not commit to cm
tampered   one bid counted twice: refused, receipt 7: two receipts disclose the same note
tampered   receipt for a payment that isn't on chain: refused, receipt 7: cm is not among the bundle's tachygrams
```

## Use

```rust
use tachyon_receipts::{BundleView, Expect, Network, Receipt, verify};

// The sender or recipient, who both know the note:
let receipt = Receipt::new(&note, Network::Testnet, height, bundle.commitment(), b"invoice-1042")?;
let text = receipt.to_hex();

// The verifier, with the bundle from a node it trusts:
let receipt = Receipt::from_hex(&text)?;
let checked = verify(
    &receipt,
    &BundleView::from_bundle(&bundle),
    &Expect::network(Network::Testnet).with_context(b"invoice-1042"),
)?;
println!("{} zatoshis to {:02x?}", checked.value, &checked.pk[..4]);
```

## What a v0 receipt doesn't do

It doesn't prove the presenter controls the payment key, and once shown it can
be copied. Both need a zero-knowledge receipt, which is the plan for v1. Details
are in [SPEC.md](SPEC.md#limits).

## Layout

| Path | What |
|---|---|
| `src/lib.rs` | Receipt type, encoding, `verify` and `verify_batch` |
| `tests/` | Format, verification and batch tests, plus the vector check |
| `examples/gen_vectors.rs` | Regenerates the test vectors from a fixed seed |
| `examples/auction_recount.rs` | The recount demo |

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
