# Tachyon payment receipts, v0 (draft)

Status: draft for discussion, 22 November 2026. Built on `zcash_tachyon` at
[`8919018`](https://github.com/tachyon-zcash/tachyon/tree/8919018e6bd07e3c65c86a3ea735cf09c88c5ac7)
and the Tachyon book's payment-protocol section at the same commit. Both move
fast, and this draft will follow them.

## Problem

Tachyon removes viewing keys from the core protocol. A recipient's ability to
see a payment lives per channel in the payment protocol, as `(tag, dk)`, and
nothing yet says how one payment is proven to a third party: an auditor, an
exchange's support desk, a merchant, or anyone recounting a public total.

## What a receipt proves

A v0 receipt proves:

> A note of value `v`, paid to payment key `pk`, was created by the bundle
> whose effecting-data digest is `D`.

It does **not** prove that whoever presents it controls `pk`, and it is a
bearer disclosure. Once a receipt has been shown, anyone who saw it can copy the
opening into a receipt with a different context. See [Limits](#limits).

## Encoding

All integers are little-endian. Field elements are the canonical 32-byte
encoding of a Pallas base field element, as `zcash_tachyon` writes them.

| Offset | Size | Field | Notes |
|---:|---:|---|---|
| 0 | 4 | magic | `TRCP` |
| 4 | 1 | version | `0x00` |
| 5 | 1 | network | 0 mainnet, 1 testnet, 2 regtest |
| 6 | 4 | height | Height of the block holding the bundle |
| 10 | 32 | bundle digest `D` | `Bundle::commitment()`, which enters the txid |
| 42 | 32 | `cm` | The note commitment as published |
| 74 | 32 | `pk` | Payment key |
| 106 | 8 | `v` | Value in zatoshis, at most `MAX_MONEY` |
| 114 | 32 | `ψ` | Nullifier trapdoor |
| 146 | 32 | `rcm` | Commitment trapdoor, non-zero |
| 178 | 1 | context length | 0 to 255 |
| 179 | n | context | Free-form label |

A receipt with an empty context is 179 bytes. A decoder MUST reject: wrong
magic, an unknown version or network, truncated input, trailing bytes, any
non-canonical field element, a zero `rcm`, and a value above `MAX_MONEY`.

## Verification

Given a receipt, the bundle it names, and what the verifier expects:

1. **Network.** The receipt's network is the verifier's.
2. **Context and recipient (optional).** If the verifier set an expected
   context or payment key, the receipt matches it.
3. **Opening.** Recompute `cm' = NoteCommit(pk, v, ψ; rcm)` with
   `zcash_tachyon`'s `Note::commitment()`, and require `cm' = cm`.
4. **Bundle.** The receipt's digest equals the supplied bundle's
   `Bundle::commitment()`.
5. **Inclusion.** `cm` is one of the tachygrams the bundle's actions publish.
6. **Chain (outside this crate).** The verifier gets the bundle from a node it
   trusts and checks that its block is final at the stated height.

A **batch** (a recount) verifies every receipt, rejects two receipts with the
same `cm`, and sums the values.

## Why revealing the opening is safe

This follows the Tachyon book's "Note Privacy (OOB)" argument. The sender
already knows `(pk, v, ψ, rcm)` but never `nk`, and every nullifier is derived
from `mk = KDF(ψ, nk)`. A verifier learns what the sender knew, and still
can't compute the note's nullifiers or link the recipient's spends. A receipt
never contains `nk`, `ak`, `dk` or a tag.

## Limits

- **Ownership.** v0 doesn't prove control of `pk`. Opening `pk` would reveal
  `nk`, so ownership needs a zero-knowledge proof.
- **Replay.** The context labels a receipt. It is not replay protection,
  because the opening it reveals can be reused.
- **Privacy of the opening.** A receipt reveals the exact value and `pk`. A
  proof that hides `ψ` and `rcm` and states ranges ("at least x") is future
  work.

All three point to a v1 that proves the receipt statement in zero knowledge
with Ragu, bound to a verifier's challenge.

## Relationship to the payment protocol

Receipts sit after discovery. They don't change how notes are encrypted,
tagged or found, which the payment protocol Valar is developing defines (ML-KEM
addresses, `tag_0 = H(ek)`, `tag_i = H(K, i)`, PIR databases). A wallet that
has found and decrypted a note already holds everything a receipt needs.

## Open questions

1. Should the location be the txid rather than the bundle digest, once the
   Tachyon ZIP 244 update fixes the txid tree?
2. Should a receipt optionally carry the memo plaintext and its tag, so a
   verifier can match it to the in-band data?
3. A human-readable encoding (Bech32m, or a ZIP 321-style URI) for copy and
   paste.
4. Where this belongs: inside the payment-protocol specification, or as a
   separate ZIP.
