mod common;

use common::{cm_tachygram, note_to, random_fp_bytes, random_note, random_tachygram};
use rand::{SeedableRng, rngs::StdRng};
use tachyon_receipts::{
    BundleView, Error, Expect, MAGIC, Network, Receipt, from_hex, verify, verify_batch,
};

const CONTEXT: &[u8] = b"audit:deposit-1042";

/// A bundle view holding `cm` as one output's pair, among a few other actions.
fn bundle_with(rng: &mut StdRng, cms: &[zcash_tachyon::Tachygram]) -> BundleView {
    let mut digest = [0u8; 32];
    rand::RngCore::fill_bytes(rng, &mut digest);
    let mut pairs = vec![(random_tachygram(rng), random_tachygram(rng))];
    for cm in cms {
        pairs.push((*cm, random_tachygram(rng)));
    }
    pairs.push((random_tachygram(rng), random_tachygram(rng)));
    BundleView::new(digest, pairs)
}

fn setup(seed: u64) -> (StdRng, zcash_tachyon::Note, BundleView, Receipt) {
    let mut rng = StdRng::seed_from_u64(seed);
    let note = random_note(&mut rng);
    let bundle = bundle_with(&mut rng, &[cm_tachygram(&note)]);
    let receipt = Receipt::new(&note, Network::Testnet, 4_600_000, bundle.digest, CONTEXT).unwrap();
    (rng, note, bundle, receipt)
}

#[test]
fn encodes_and_decodes() {
    let (_, _, _, receipt) = setup(1);
    let bytes = receipt.to_bytes();
    assert_eq!(&bytes[..4], &MAGIC);
    assert_eq!(bytes.len(), tachyon_receipts::FIXED_LEN + CONTEXT.len());
    assert_eq!(Receipt::from_bytes(&bytes).unwrap(), receipt);
    assert_eq!(Receipt::from_hex(&receipt.to_hex()).unwrap(), receipt);
}

#[test]
fn verifies_a_genuine_receipt() {
    let (_, note, bundle, receipt) = setup(2);
    let expect = Expect::network(Network::Testnet).with_context(CONTEXT);
    let verified = verify(&receipt, &bundle, &expect).unwrap();
    assert_eq!(verified.value, u64::from(note.value));
    assert_eq!(verified.cm, receipt.cm);
    assert_eq!(verified.height, 4_600_000);
}

#[test]
fn rejects_an_inflated_value() {
    let (_, _, bundle, mut receipt) = setup(3);
    receipt.opening.value += 1;
    let err = verify(&receipt, &bundle, &Expect::network(Network::Testnet)).unwrap_err();
    assert_eq!(err, Error::CommitmentMismatch);
}

#[test]
fn rejects_a_swapped_payment_key() {
    let (mut rng, _, bundle, mut receipt) = setup(4);
    receipt.opening.pk = random_fp_bytes(&mut rng);
    let err = verify(&receipt, &bundle, &Expect::network(Network::Testnet)).unwrap_err();
    assert_eq!(err, Error::CommitmentMismatch);
}

#[test]
fn rejects_a_matching_opening_with_a_forged_cm() {
    // Opening and cm agree, but the note was never created in this bundle.
    let (mut rng, _, bundle, _) = setup(5);
    let other = random_note(&mut rng);
    let forged = Receipt::new(&other, Network::Testnet, 4_600_000, bundle.digest, CONTEXT).unwrap();
    let err = verify(&forged, &bundle, &Expect::network(Network::Testnet)).unwrap_err();
    assert_eq!(err, Error::NotInBundle);
}

#[test]
fn rejects_the_wrong_bundle() {
    let (mut rng, _, _, receipt) = setup(6);
    let other_bundle = bundle_with(&mut rng, &[]);
    let err = verify(&receipt, &other_bundle, &Expect::network(Network::Testnet)).unwrap_err();
    assert_eq!(err, Error::WrongBundle);
}

#[test]
fn checks_network_context_and_recipient() {
    let (mut rng, _, bundle, receipt) = setup(7);
    let mainnet = Expect::network(Network::Mainnet);
    assert_eq!(
        verify(&receipt, &bundle, &mainnet).unwrap_err(),
        Error::WrongNetwork
    );

    let other_context = Expect::network(Network::Testnet).with_context(b"something else");
    assert_eq!(
        verify(&receipt, &bundle, &other_context).unwrap_err(),
        Error::WrongContext
    );

    let other_pk = Expect::network(Network::Testnet).with_recipient(random_fp_bytes(&mut rng));
    assert_eq!(
        verify(&receipt, &bundle, &other_pk).unwrap_err(),
        Error::WrongRecipient
    );

    let right_pk = Expect::network(Network::Testnet).with_recipient(receipt.opening.pk);
    assert!(verify(&receipt, &bundle, &right_pk).is_ok());
}

#[test]
fn rejects_malformed_bytes() {
    let (_, _, _, receipt) = setup(8);
    let good = receipt.to_bytes();

    let mut bad_magic = good.clone();
    bad_magic[0] ^= 1;
    assert_eq!(
        Receipt::from_bytes(&bad_magic).unwrap_err(),
        Error::BadMagic
    );

    let mut bad_version = good.clone();
    bad_version[4] = 9;
    assert_eq!(
        Receipt::from_bytes(&bad_version).unwrap_err(),
        Error::UnsupportedVersion(9)
    );

    let mut bad_network = good.clone();
    bad_network[5] = 7;
    assert_eq!(
        Receipt::from_bytes(&bad_network).unwrap_err(),
        Error::UnknownNetwork(7)
    );

    assert_eq!(
        Receipt::from_bytes(&good[..good.len() - 1]).unwrap_err(),
        Error::Truncated
    );

    let mut trailing = good.clone();
    trailing.push(0);
    assert_eq!(
        Receipt::from_bytes(&trailing).unwrap_err(),
        Error::TrailingBytes
    );

    // pk starts at 4 + 1 + 1 + 4 + 32 + 32 = 74; all-ones is not canonical.
    let mut non_canonical = good.clone();
    non_canonical[74..106].fill(0xff);
    assert_eq!(
        Receipt::from_bytes(&non_canonical).unwrap_err(),
        Error::NonCanonical(tachyon_receipts::Field::Pk)
    );

    // rcm is the 32 bytes before the context length.
    let rcm_start = tachyon_receipts::FIXED_LEN - 1 - 32;
    let mut zero_rcm = good.clone();
    zero_rcm[rcm_start..rcm_start + 32].fill(0);
    assert_eq!(Receipt::from_bytes(&zero_rcm).unwrap_err(), Error::ZeroRcm);

    assert!(from_hex("abc").is_none());
    assert!(Receipt::from_hex("zz").is_err());
}

#[test]
fn refuses_an_oversized_context() {
    let (_, note, bundle, _) = setup(9);
    let long = vec![b'x'; 256];
    let err = Receipt::new(&note, Network::Testnet, 1, bundle.digest, &long).unwrap_err();
    assert_eq!(err, Error::ContextTooLong);
}

#[test]
fn batch_recount_totals_and_catches_duplicates() {
    let mut rng = StdRng::seed_from_u64(10);
    let escrow = random_fp_bytes(&mut rng);
    let values = [100_000u64, 250_000, 175_000];
    let notes: Vec<_> = values
        .iter()
        .map(|v| note_to(&mut rng, escrow, *v))
        .collect();
    let cms: Vec<_> = notes.iter().map(cm_tachygram).collect();
    let bundle_a = bundle_with(&mut rng, &cms[..2]);
    let bundle_b = bundle_with(&mut rng, &cms[2..]);
    let receipts = vec![
        Receipt::new(&notes[0], Network::Testnet, 10, bundle_a.digest, CONTEXT).unwrap(),
        Receipt::new(&notes[1], Network::Testnet, 10, bundle_a.digest, CONTEXT).unwrap(),
        Receipt::new(&notes[2], Network::Testnet, 11, bundle_b.digest, CONTEXT).unwrap(),
    ];
    let bundles = [&bundle_a, &bundle_b];
    let lookup = |d: &[u8; 32]| bundles.iter().copied().find(|b| &b.digest == d);
    let expect = Expect::network(Network::Testnet).with_recipient(escrow);

    let total = verify_batch(&receipts, lookup, &expect).unwrap();
    assert_eq!(total.count, 3);
    assert_eq!(total.total, values.iter().sum::<u64>());

    let mut doubled = receipts.clone();
    doubled.push(receipts[1].clone());
    let err = verify_batch(&doubled, lookup, &expect).unwrap_err();
    assert_eq!((err.index, err.error), (3, Error::DuplicateCommitment));

    let err = verify_batch(&receipts, |_| None, &expect).unwrap_err();
    assert_eq!((err.index, err.error), (0, Error::UnknownBundle));
}
