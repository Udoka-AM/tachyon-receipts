//! Payment receipts for the Tachyon shielded pool.
//!
//! Tachyon has no viewing keys, so there is nothing to hand an auditor that
//! shows "this payment arrived". A [`Receipt`] fills that gap for one note: it
//! carries the note opening `(pk, v, ψ, rcm)` plus where the note was created,
//! and anyone can check it against chain data by recomputing the note
//! commitment and finding it among the bundle's tachygrams.
//!
//! The note commitment and the bundle digest come from `zcash_tachyon`. This
//! crate never reimplements Tachyon cryptography.
//!
//! # What a v0 receipt proves, and what it doesn't
//!
//! It proves that a note of value `v`, paid to payment key `pk`, was created by
//! the bundle with the given digest. It does **not** prove that whoever shows
//! it controls `pk`, and it is a bearer disclosure: once seen, the opening can
//! be copied into a receipt with any context. The `context` field labels what
//! a receipt was issued for; it is not replay protection. Both gaps need a
//! zero-knowledge receipt (planned v1, using Ragu).
//!
//! Revealing the opening does not let anyone link the recipient's spends: the
//! sender already knows `(pk, v, ψ, rcm)`, and every nullifier also needs `nk`,
//! which a receipt never contains (the Tachyon book's "Note Privacy (OOB)"
//! argument).
//!
//! The verifier is responsible for one check this crate can't make: that the
//! bundle it passes in really is in a final block at the receipt's height.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::collections::BTreeSet;
use std::fmt;

use zakura_udon::field::Field as _;
use zcash_tachyon::{
    Bundle, Note, Tachygram, keys::PaymentKey, note::CommitmentTrapdoor, nullifier, pasta::Fp,
    stamp::StampState, value,
};

/// Magic bytes at the start of an encoded receipt.
pub const MAGIC: [u8; 4] = *b"TRCP";

/// The receipt format version this crate reads and writes.
pub const VERSION: u8 = 0;

/// Longest allowed `context`, in bytes.
pub const MAX_CONTEXT_LEN: usize = 255;

/// Encoded length of a receipt with an empty context.
pub const FIXED_LEN: usize = 4 + 1 + 1 + 4 + 32 + 32 + 32 + 8 + 32 + 32 + 1;

/// The network a receipt refers to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    /// Zcash mainnet.
    Mainnet,
    /// Zcash testnet.
    Testnet,
    /// A local regtest or devnet.
    Regtest,
}

impl Network {
    fn to_byte(self) -> u8 {
        match self {
            Network::Mainnet => 0,
            Network::Testnet => 1,
            Network::Regtest => 2,
        }
    }

    fn from_byte(b: u8) -> Result<Self, Error> {
        match b {
            0 => Ok(Network::Mainnet),
            1 => Ok(Network::Testnet),
            2 => Ok(Network::Regtest),
            other => Err(Error::UnknownNetwork(other)),
        }
    }
}

/// Which field of an opening failed to decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    /// The payment key `pk`.
    Pk,
    /// The nullifier trapdoor `ψ`.
    Psi,
    /// The commitment trapdoor `rcm`.
    Rcm,
    /// The claimed note commitment `cm`.
    Cm,
}

/// Why a receipt failed to decode or verify.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The bytes don't start with [`MAGIC`].
    BadMagic,
    /// The version byte isn't one this crate understands.
    UnsupportedVersion(u8),
    /// The network byte isn't 0, 1 or 2.
    UnknownNetwork(u8),
    /// The input ended early.
    Truncated,
    /// Bytes were left over after the receipt.
    TrailingBytes,
    /// A 32-byte field isn't a canonical Pallas base field element.
    NonCanonical(Field),
    /// `rcm` is zero, which `zcash_tachyon` refuses to commit with.
    ZeroRcm,
    /// The value is above `MAX_MONEY`.
    ValueOutOfRange,
    /// The context is longer than [`MAX_CONTEXT_LEN`].
    ContextTooLong,
    /// Recomputing `cm` from the opening gave a different commitment.
    CommitmentMismatch,
    /// The receipt names a different bundle from the one supplied.
    WrongBundle,
    /// The commitment isn't among the bundle's tachygrams.
    NotInBundle,
    /// The receipt is for a different network.
    WrongNetwork,
    /// The receipt's context isn't the one the verifier expected.
    WrongContext,
    /// The note pays a different payment key from the one expected.
    WrongRecipient,
    /// Batch only: no bundle was supplied for this receipt's digest.
    UnknownBundle,
    /// Batch only: two receipts disclose the same note commitment.
    DuplicateCommitment,
    /// Batch only: the total overflowed.
    TotalOverflow,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Error::BadMagic => "not a Tachyon receipt (bad magic)".to_owned(),
            Error::UnsupportedVersion(v) => format!("unsupported receipt version {v}"),
            Error::UnknownNetwork(b) => format!("unknown network byte {b}"),
            Error::Truncated => "receipt is truncated".to_owned(),
            Error::TrailingBytes => "bytes left over after the receipt".to_owned(),
            Error::NonCanonical(field) => format!("{field:?} is not a canonical field element"),
            Error::ZeroRcm => "rcm is zero".to_owned(),
            Error::ValueOutOfRange => "value is above MAX_MONEY".to_owned(),
            Error::ContextTooLong => "context is longer than 255 bytes".to_owned(),
            Error::CommitmentMismatch => "the opening does not commit to cm".to_owned(),
            Error::WrongBundle => "receipt names a different bundle".to_owned(),
            Error::NotInBundle => "cm is not among the bundle's tachygrams".to_owned(),
            Error::WrongNetwork => "receipt is for another network".to_owned(),
            Error::WrongContext => "receipt context does not match".to_owned(),
            Error::WrongRecipient => "note pays a different payment key".to_owned(),
            Error::UnknownBundle => "no bundle supplied for this receipt".to_owned(),
            Error::DuplicateCommitment => "two receipts disclose the same note".to_owned(),
            Error::TotalOverflow => "batch total overflowed".to_owned(),
        };
        f.write_str(&msg)
    }
}

impl std::error::Error for Error {}

fn fp_bytes(fp: Fp) -> [u8; 32] {
    fp.to_bytes()
}

fn decode_fp(bytes: [u8; 32], field: Field) -> Result<Fp, Error> {
    Fp::from_bytes(bytes).ok_or(Error::NonCanonical(field))
}

/// A note opening: everything needed to recompute its commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Opening {
    /// The recipient's payment key `pk`, as a field element encoding.
    pub pk: [u8; 32],
    /// The note value in zatoshis.
    pub value: u64,
    /// The nullifier trapdoor `ψ`.
    pub psi: [u8; 32],
    /// The commitment trapdoor `rcm`.
    pub rcm: [u8; 32],
}

impl Opening {
    /// Take the opening of a note.
    #[must_use]
    pub fn from_note(note: &Note) -> Self {
        Opening {
            pk: fp_bytes(Fp::from(note.pk)),
            value: u64::from(note.value),
            psi: fp_bytes(Fp::from(note.psi)),
            rcm: fp_bytes(Fp::from(note.rcm)),
        }
    }

    /// Rebuild the note, checking every field.
    ///
    /// # Errors
    ///
    /// Returns an error if a field isn't canonical, `rcm` is zero, or the
    /// value is out of range.
    pub fn to_note(&self) -> Result<Note, Error> {
        let pk = PaymentKey::from(decode_fp(self.pk, Field::Pk)?);
        let psi = nullifier::Trapdoor::from(decode_fp(self.psi, Field::Psi)?);
        if self.rcm == [0u8; 32] {
            return Err(Error::ZeroRcm);
        }
        let rcm = CommitmentTrapdoor::from(decode_fp(self.rcm, Field::Rcm)?);
        let value = value::Positive::try_from(self.value).map_err(|_| Error::ValueOutOfRange)?;
        Ok(Note {
            pk,
            value,
            psi,
            rcm,
        })
    }

    /// Recompute the note commitment `cm` with `zcash_tachyon`.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Opening::to_note`].
    pub fn commitment(&self) -> Result<[u8; 32], Error> {
        let note = self.to_note()?;
        let tachygram = Tachygram::from(note.commitment());
        Ok(fp_bytes(Fp::from(tachygram)))
    }
}

/// A payment receipt, version 0.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    /// The network the payment was made on.
    pub network: Network,
    /// The height of the block holding the bundle. The verifier checks this
    /// against its own view of the chain.
    pub height: u32,
    /// The bundle's effecting-data digest (`Bundle::commitment`), which enters
    /// the transaction id.
    pub bundle_digest: [u8; 32],
    /// The note commitment `cm`, as published among the bundle's tachygrams.
    pub cm: [u8; 32],
    /// The note opening.
    pub opening: Opening,
    /// A label for what the receipt was issued for. Not replay protection.
    pub context: Vec<u8>,
}

impl Receipt {
    /// Make a receipt for a note created in the given bundle.
    ///
    /// # Errors
    ///
    /// Returns an error if the context is longer than [`MAX_CONTEXT_LEN`] or
    /// the note's commitment can't be recomputed.
    pub fn new(
        note: &Note,
        network: Network,
        height: u32,
        bundle_digest: [u8; 32],
        context: &[u8],
    ) -> Result<Self, Error> {
        if context.len() > MAX_CONTEXT_LEN {
            return Err(Error::ContextTooLong);
        }
        let opening = Opening::from_note(note);
        let cm = opening.commitment()?;
        Ok(Receipt {
            network,
            height,
            bundle_digest,
            cm,
            opening,
            context: context.to_vec(),
        })
    }

    /// Encode as bytes: magic, version, network, height (u32 LE), bundle
    /// digest, `cm`, `pk`, value (u64 LE), `ψ`, `rcm`, context length (u8),
    /// context.
    ///
    /// # Panics
    ///
    /// Panics if `context` is longer than [`MAX_CONTEXT_LEN`], which
    /// [`Receipt::new`] and [`Receipt::from_bytes`] never produce.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let context_len = u8::try_from(self.context.len()).expect("context is at most 255 bytes");
        let mut out = Vec::with_capacity(FIXED_LEN + self.context.len());
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.push(self.network.to_byte());
        out.extend_from_slice(&self.height.to_le_bytes());
        out.extend_from_slice(&self.bundle_digest);
        out.extend_from_slice(&self.cm);
        out.extend_from_slice(&self.opening.pk);
        out.extend_from_slice(&self.opening.value.to_le_bytes());
        out.extend_from_slice(&self.opening.psi);
        out.extend_from_slice(&self.opening.rcm);
        out.push(context_len);
        out.extend_from_slice(&self.context);
        out
    }

    /// Decode from bytes. This checks the format and that every field element
    /// is canonical, but doesn't verify anything against a bundle.
    ///
    /// # Errors
    ///
    /// Returns an error for any malformed input.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader { bytes, pos: 0 };
        if r.take::<4>()? != MAGIC {
            return Err(Error::BadMagic);
        }
        let version = r.take::<1>()?[0];
        if version != VERSION {
            return Err(Error::UnsupportedVersion(version));
        }
        let network = Network::from_byte(r.take::<1>()?[0])?;
        let height = u32::from_le_bytes(r.take::<4>()?);
        let bundle_digest = r.take::<32>()?;
        let cm = r.take::<32>()?;
        decode_fp(cm, Field::Cm)?;
        let pk = r.take::<32>()?;
        let value = u64::from_le_bytes(r.take::<8>()?);
        let psi = r.take::<32>()?;
        let rcm = r.take::<32>()?;
        let opening = Opening {
            pk,
            value,
            psi,
            rcm,
        };
        opening.to_note()?;
        let context_len = usize::from(r.take::<1>()?[0]);
        let context = r.take_slice(context_len)?.to_vec();
        if r.pos != bytes.len() {
            return Err(Error::TrailingBytes);
        }
        Ok(Receipt {
            network,
            height,
            bundle_digest,
            cm,
            opening,
            context,
        })
    }

    /// Encode as lowercase hex.
    #[must_use]
    pub fn to_hex(&self) -> String {
        to_hex(&self.to_bytes())
    }

    /// Decode from hex.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] for malformed hex, or any
    /// [`Receipt::from_bytes`] error.
    pub fn from_hex(s: &str) -> Result<Self, Error> {
        Self::from_bytes(&from_hex(s.trim()).ok_or(Error::Truncated)?)
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn take_slice(&mut self, n: usize) -> Result<&[u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::Truncated)?;
        let slice = self.bytes.get(self.pos..end).ok_or(Error::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let slice = self.take_slice(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(slice);
        Ok(out)
    }
}

/// The parts of a bundle a receipt is checked against: its digest and every
/// tachygram its actions publish.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleView {
    /// `Bundle::commitment()`, the bundle's effecting-data digest.
    pub digest: [u8; 32],
    /// Every tachygram the bundle's actions publish (each action's pair).
    pub tachygrams: BTreeSet<[u8; 32]>,
}

impl BundleView {
    /// Read the digest and action tachygrams from a Tachyon bundle in any
    /// stamp state.
    #[must_use]
    pub fn from_bundle<S: StampState + ?Sized>(bundle: &Bundle<S>) -> Self {
        let pairs = bundle.action_auth.iter().map(|(_sig, pair)| *pair);
        Self::new(bundle.commitment(), pairs)
    }

    /// Build a view from a digest and the action tachygram pairs.
    pub fn new(digest: [u8; 32], pairs: impl IntoIterator<Item = (Tachygram, Tachygram)>) -> Self {
        let mut tachygrams = BTreeSet::new();
        for (a, b) in pairs {
            tachygrams.insert(fp_bytes(Fp::from(a)));
            tachygrams.insert(fp_bytes(Fp::from(b)));
        }
        BundleView { digest, tachygrams }
    }
}

/// What the verifier expects a receipt to say.
#[derive(Clone, Copy, Debug)]
pub struct Expect<'a> {
    /// The network the verifier is checking against.
    pub network: Network,
    /// If set, the exact context the receipt must carry.
    pub context: Option<&'a [u8]>,
    /// If set, the payment key the note must pay (for example an escrow).
    pub recipient: Option<[u8; 32]>,
}

impl<'a> Expect<'a> {
    /// Expect only the network.
    #[must_use]
    pub fn network(network: Network) -> Self {
        Expect {
            network,
            context: None,
            recipient: None,
        }
    }

    /// Also require this context.
    #[must_use]
    pub fn with_context(self, context: &'a [u8]) -> Self {
        Expect {
            context: Some(context),
            ..self
        }
    }

    /// Also require the note to pay this payment key.
    #[must_use]
    pub fn with_recipient(self, pk: [u8; 32]) -> Self {
        Expect {
            recipient: Some(pk),
            ..self
        }
    }
}

/// What a verified receipt establishes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verified {
    /// The note commitment.
    pub cm: [u8; 32],
    /// The payment key the note pays.
    pub pk: [u8; 32],
    /// The note value in zatoshis.
    pub value: u64,
    /// The block height the receipt claims, for the caller to check.
    pub height: u32,
}

/// Verify one receipt against a bundle.
///
/// Checks, in order: the network, the context and recipient if the verifier
/// set them, that the opening commits to `cm`, that the receipt names this
/// bundle, and that `cm` is among the bundle's tachygrams.
///
/// # Errors
///
/// Returns the first check that fails.
pub fn verify(
    receipt: &Receipt,
    bundle: &BundleView,
    expect: &Expect<'_>,
) -> Result<Verified, Error> {
    if receipt.network != expect.network {
        return Err(Error::WrongNetwork);
    }
    if let Some(context) = expect.context
        && receipt.context != context
    {
        return Err(Error::WrongContext);
    }
    if let Some(pk) = expect.recipient
        && receipt.opening.pk != pk
    {
        return Err(Error::WrongRecipient);
    }
    if receipt.opening.commitment()? != receipt.cm {
        return Err(Error::CommitmentMismatch);
    }
    if receipt.bundle_digest != bundle.digest {
        return Err(Error::WrongBundle);
    }
    if !bundle.tachygrams.contains(&receipt.cm) {
        return Err(Error::NotInBundle);
    }
    Ok(Verified {
        cm: receipt.cm,
        pk: receipt.opening.pk,
        value: receipt.opening.value,
        height: receipt.height,
    })
}

/// The result of verifying a batch of receipts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatchTotal {
    /// How many receipts verified.
    pub count: usize,
    /// Their total value in zatoshis.
    pub total: u64,
}

/// A batch failure, with the index of the receipt that failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchError {
    /// Index into the receipts slice.
    pub index: usize,
    /// Why it failed.
    pub error: Error,
}

impl fmt::Display for BatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "receipt {}: {}", self.index, self.error)
    }
}

impl std::error::Error for BatchError {}

/// Verify a batch of receipts and total them, as a public recount does.
///
/// `bundle_for` returns the bundle a receipt names, by digest. Every receipt
/// must verify, and no note may be disclosed twice.
///
/// # Errors
///
/// Returns the first receipt that fails, with its index.
pub fn verify_batch<'b>(
    receipts: &[Receipt],
    bundle_for: impl Fn(&[u8; 32]) -> Option<&'b BundleView>,
    expect: &Expect<'_>,
) -> Result<BatchTotal, BatchError> {
    let mut seen = BTreeSet::new();
    let mut total: u64 = 0;
    for (index, receipt) in receipts.iter().enumerate() {
        let fail = |error| BatchError { index, error };
        let bundle = bundle_for(&receipt.bundle_digest).ok_or(fail(Error::UnknownBundle))?;
        let verified = verify(receipt, bundle, expect).map_err(fail)?;
        if !seen.insert(verified.cm) {
            return Err(fail(Error::DuplicateCommitment));
        }
        total = total
            .checked_add(verified.value)
            .ok_or(fail(Error::TotalOverflow))?;
    }
    Ok(BatchTotal {
        count: receipts.len(),
        total,
    })
}

/// Lowercase hex encoding.
#[must_use]
pub fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from(DIGITS[usize::from(b >> 4)]));
        s.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    s
}

/// Hex decoding. Returns `None` for odd length or a non-hex digit.
#[must_use]
pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    s.as_bytes()
        .chunks(2)
        .map(|pair| {
            let hi = char::from(pair[0]).to_digit(16)?;
            let lo = char::from(pair[1]).to_digit(16)?;
            u8::try_from(hi * 16 + lo).ok()
        })
        .collect()
}
