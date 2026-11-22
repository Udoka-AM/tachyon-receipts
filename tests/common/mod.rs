#![allow(dead_code, reason = "shared between test files")]

use rand::{Rng, RngCore};
use tachyon_receipts::Opening;
use zakura_udon::field::Field as _;
use zcash_tachyon::{
    Note, Tachygram, keys::PaymentKey, note::CommitmentTrapdoor, nullifier, pasta::Fp, value,
};

/// A uniformly random canonical field element. Pallas p is just above 2^254,
/// so clearing the top two bits always gives a canonical encoding.
pub fn random_fp_bytes(rng: &mut impl RngCore) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    bytes[31] &= 0x3f;
    bytes
}

pub fn fp(bytes: [u8; 32]) -> Fp {
    Fp::from_bytes(bytes).expect("canonical")
}

pub fn random_tachygram(rng: &mut impl RngCore) -> Tachygram {
    Tachygram::from(fp(random_fp_bytes(rng)))
}

pub fn note_to(rng: &mut impl RngCore, pk: [u8; 32], value: u64) -> Note {
    let mut rcm = random_fp_bytes(rng);
    rcm[0] |= 1; // never zero
    Note {
        pk: PaymentKey::from(fp(pk)),
        value: value::Positive::try_from(value).expect("in range"),
        psi: nullifier::Trapdoor::from(fp(random_fp_bytes(rng))),
        rcm: CommitmentTrapdoor::from(fp(rcm)),
    }
}

pub fn random_note(rng: &mut impl Rng) -> Note {
    let pk = random_fp_bytes(rng);
    let value = rng.gen_range(1..2_000_000_000u64);
    note_to(rng, pk, value)
}

pub fn cm_tachygram(note: &Note) -> Tachygram {
    let cm = Opening::from_note(note).commitment().expect("valid note");
    Tachygram::from(fp(cm))
}
