//! Payment receipts for the Tachyon shielded pool. See SPEC.md.
//!
//! v0 receipts are bearer disclosures: they don't prove control of `pk`, and
//! the caller must check the bundle is in a final block.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fmt;

use zakura_udon::field::Field as _;
use zcash_tachyon::{
    Bundle, Note, Tachygram, keys::PaymentKey, note::CommitmentTrapdoor, nullifier, pasta::Fp,
    stamp::StampState, value,
};

pub const MAGIC: [u8; 4] = *b"TRCP";
pub const VERSION: u8 = 0;
pub const MAX_CONTEXT_LEN: usize = 255;
pub const FIXED_LEN: usize = 4 + 1 + 1 + 4 + 32 + 32 + 32 + 8 + 32 + 32 + 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    Pk,
    Psi,
    Rcm,
    Cm,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    BadMagic,
    UnsupportedVersion(u8),
    UnknownNetwork(u8),
    Truncated,
    TrailingBytes,
    NonCanonical(Field),
    ZeroRcm,
    ValueOutOfRange,
    ContextTooLong,
    CommitmentMismatch,
    WrongBundle,
    NotInBundle,
    WrongNetwork,
    WrongContext,
    WrongRecipient,
    UnknownBundle,
    DuplicateCommitment,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Opening {
    pub pk: [u8; 32],
    pub value: u64,
    pub psi: [u8; 32],
    pub rcm: [u8; 32],
}

impl Opening {
    #[must_use]
    pub fn from_note(note: &Note) -> Self {
        Opening {
            pk: fp_bytes(Fp::from(note.pk)),
            value: u64::from(note.value),
            psi: fp_bytes(Fp::from(note.psi)),
            rcm: fp_bytes(Fp::from(note.rcm)),
        }
    }

    pub fn to_note(&self) -> Result<Note, Error> {
        let pk = PaymentKey::from(decode_fp(self.pk, Field::Pk)?);
        let psi = nullifier::Trapdoor::from(decode_fp(self.psi, Field::Psi)?);
        // Note::commitment panics on a zero rcm.
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

    pub fn commitment(&self) -> Result<[u8; 32], Error> {
        let note = self.to_note()?;
        let tachygram = Tachygram::from(note.commitment());
        Ok(fp_bytes(Fp::from(tachygram)))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub network: Network,
    pub height: u32,
    /// `Bundle::commitment()`.
    pub bundle_digest: [u8; 32],
    pub cm: [u8; 32],
    pub opening: Opening,
    /// A label, not replay protection.
    pub context: Vec<u8>,
}

impl Receipt {
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

    /// Checks the format only, not the bundle.
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

    #[must_use]
    pub fn to_hex(&self) -> String {
        to_hex(&self.to_bytes())
    }

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleView {
    pub digest: [u8; 32],
    pub tachygrams: BTreeSet<[u8; 32]>,
}

impl BundleView {
    #[must_use]
    pub fn from_bundle<S: StampState + ?Sized>(bundle: &Bundle<S>) -> Self {
        let pairs = bundle.action_auth.iter().map(|(_sig, pair)| *pair);
        Self::new(bundle.commitment(), pairs)
    }

    pub fn new(digest: [u8; 32], pairs: impl IntoIterator<Item = (Tachygram, Tachygram)>) -> Self {
        let mut tachygrams = BTreeSet::new();
        for (a, b) in pairs {
            tachygrams.insert(fp_bytes(Fp::from(a)));
            tachygrams.insert(fp_bytes(Fp::from(b)));
        }
        BundleView { digest, tachygrams }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Expect<'a> {
    pub network: Network,
    pub context: Option<&'a [u8]>,
    pub recipient: Option<[u8; 32]>,
}

impl<'a> Expect<'a> {
    #[must_use]
    pub fn network(network: Network) -> Self {
        Expect {
            network,
            context: None,
            recipient: None,
        }
    }

    #[must_use]
    pub fn with_context(self, context: &'a [u8]) -> Self {
        Expect {
            context: Some(context),
            ..self
        }
    }

    #[must_use]
    pub fn with_recipient(self, pk: [u8; 32]) -> Self {
        Expect {
            recipient: Some(pk),
            ..self
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verified {
    pub cm: [u8; 32],
    pub pk: [u8; 32],
    pub value: u64,
    pub height: u32,
}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatchTotal {
    pub count: usize,
    pub total: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchError {
    pub index: usize,
    pub error: Error,
}

impl fmt::Display for BatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "receipt {}: {}", self.index, self.error)
    }
}

impl std::error::Error for BatchError {}

/// Verifies every receipt, rejects a note disclosed twice, and sums the values.
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
