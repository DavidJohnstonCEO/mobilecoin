// Copyright (c) 2018-2020 MobileCoin Inc.

//! Abstract traits used by Structs which implement key management

pub use digest::Digest;
pub use ed25519::signature::{DigestSigner, DigestVerifier, Signature, Signer, Verifier};

// Macros with names that overlap a module name...
use alloc::vec;

use alloc::{string::String, vec::Vec};
use core::{convert::TryFrom, fmt::Debug, hash::Hash};
use digest::generic_array::{typenum::Unsigned, ArrayLength};
use digestible::Digestible;
use failure::Fail;
use mc_util_from_random::FromRandom;
use mcserial::LengthMismatch32;
use rand_core::{CryptoRng, RngCore};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// A collection of common errors for use by implementers
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Fail, Ord, PartialEq, PartialOrd, Serialize)]
pub enum KeyError {
    #[fail(
        display = "The length of the given data does not match the algorithm's expected length, provided {}, required {}",
        _0, _1
    )]
    LengthMismatch(usize, usize),
    #[fail(display = "The specified algorithm does not match what was expected")]
    AlgorithmMismatch,
    #[fail(display = "The provided public key is invalid")]
    InvalidPublicKey,
    #[fail(display = "The provided private key is invalid")]
    InvalidPrivateKey,
    #[fail(display = "The signature was not able to be validated")]
    SignatureMismatch,
    #[fail(display = "There was an opaque error returned by another crate or library")]
    InternalError,
}

impl From<LengthMismatch32> for KeyError {
    fn from(src: LengthMismatch32) -> Self {
        KeyError::LengthMismatch(src.0, 32)
    }
}

/// A trait for an object which is representable as canonical bytes.
///
/// This must be general enough to support both X25519Public and RistrettoPublic,
/// an X25519 object already implements AsRef<[u8]>, but RistrettoPublic cannot,
/// it must be compressed before you can get a reference to bytes.
///
/// This trait attempts to bridge this gap, using a zero-cost abstraction.
/// An object like X25519 can have GetBytes::Result = &[u8],
/// and this object already implements AsRef<[u8]>, which can be inlined to a no-op.
/// An object like Ristretto can have GetBytes::Result = [u8; 32] or similar.
pub trait GetBytes {
    type Output: AsRef<[u8]>;

    fn get_bytes(&self) -> Self::Output;
}

/// A trait indicating that a key can be read/written as ASN.1 using the
/// Distinguished Encoding Rules (DER).
pub trait DistinguishedEncoding: Sized {
    /// Retrieve the size of the key, in bytes.
    fn der_size() -> usize;

    /// Create a new object from the given DER-encoded SubjectPublicKeyInfo.
    fn try_from_der(src: &[u8]) -> Result<Self, KeyError>;

    /// Create the standardized DER-encoded representation of this object.
    fn to_der(&self) -> Vec<u8>;
}

/// A trait indicating that a string fingerprint can be generated for an
/// object.
pub trait Fingerprintable {
    fn fingerprint<D: digest::Digest>(&self) -> Result<String, KeyError>;
}

/// Blanket implementation of fingerprinting for any public key which also
/// implements the DistinguishedEncoding trait.
impl<T: PublicKey + DistinguishedEncoding> Fingerprintable for T {
    fn fingerprint<D: digest::Digest>(&self) -> Result<String, KeyError> {
        // Get the hash of the DER bytes
        let hash = D::digest(&self.to_der());
        // Get the hex string of the hash as bytes
        let mut hash_strbuf: Vec<u8> = vec![0u8; D::output_size() * 2];
        let hash_len = hash_strbuf.len();
        let hash_len = {
            let hash_slice = binascii::bin2hex(&hash, &mut hash_strbuf)
                .map_err(|_e| KeyError::LengthMismatch(hash_len, D::output_size() * 2))?;
            hash_slice.len()
        };
        hash_strbuf.truncate(hash_len);

        // Add byte separators (i.e. make it "50:55:55:55..."
        let mut retval = String::with_capacity(D::output_size() * 3 + 1);
        retval.push_str(
            core::str::from_utf8(&hash_strbuf[..2]).map_err(|_e| KeyError::InvalidPublicKey)?,
        );
        for ch in hash_strbuf[2..].chunks(2) {
            retval.push(':');
            retval.push_str(core::str::from_utf8(ch).map_err(|_e| KeyError::InvalidPublicKey)?);
        }

        Ok(retval)
    }
}

/// A trait which all public key structures should implement.
pub trait PublicKey:
    Clone
    + Debug
    + DeserializeOwned
    + Digestible
    + Eq
    + Hash
    + Into<Vec<u8>>
    + PartialEq
    + PartialOrd
    + Ord
    + Serialize
    + Sized
    + for<'bytes> TryFrom<&'bytes [u8], Error = KeyError>
{
    /// A typenum representing the fixed-length of a canonical representation
    /// of the public key.
    type Size: ArrayLength<u8> + Unsigned;
    /// Retrieve the size of this public key's raw bytes.
    fn size() -> usize {
        Self::Size::USIZE
    }
}

/// A trait for all public key types to implement.
pub trait PrivateKey: Debug + Sized + FromRandom {
    type Public: PublicKey + for<'privkey> From<&'privkey Self>;
}

/// A dependency trait for shared secret implementations
///
/// Objects which implement this can be read as bytes, but not copied or serialized.
pub trait KexSecret: AsRef<[u8]> + Debug + Sized {
    /// A lower bound on the number of bytes of entropy in the KexSecret,
    /// when key exchange has been performed correctly.
    ///
    /// This is typically the number of bytes in the representation of a curve point
    /// minus one -- it cannot have full entropy because it satisfies the curve equation.
    ///
    /// If e.g. a KDF is applied and this is used to drive an AEAD, then the key size
    /// of the AEAD should be less than this bound, or it is likely an
    /// unsound configuration -- the AEAD is not getting as much entropy as it needs.
    type EntropyLowerBound: Unsigned;
    fn entropy_lower_bound() -> usize {
        Self::EntropyLowerBound::USIZE
    }
}

/// A marker trait for public keys to be used in key exchange
pub trait KexPublic: PublicKey
where
    for<'privkey> Self: From<&'privkey <Self as KexPublic>::KexEphemeralPrivate>,
{
    type KexEphemeralPrivate: KexEphemeralPrivate + PrivateKey<Public = Self>;

    /// Create a new single-use shared secret for the destination.
    ///
    /// The public key and derived secret will be returned on success.
    fn new_secret(
        &self,
        csprng: &mut (impl RngCore + CryptoRng),
    ) -> (Self, <Self::KexEphemeralPrivate as KexPrivate>::Secret) {
        let our_privkey = <Self::KexEphemeralPrivate as FromRandom>::from_random(csprng);
        let our_pubkey: Self = (&our_privkey).into();
        let shared_secret = our_privkey.key_exchange(&self);
        (our_pubkey, shared_secret)
    }
}

/// A trait which private key types used in key exchange should implement
pub trait KexPrivate: PrivateKey
where
    for<'privkey> <Self as PrivateKey>::Public: From<&'privkey Self>,
{
    type Secret: KexSecret;
}

/// A trait which private keys used in a single key exchange should implement.
///
/// Note that ephemeral key-exchange pairs are dropped after the key exchange
/// is performed.
pub trait KexEphemeralPrivate: KexPrivate
where
    for<'privkey> <Self as PrivateKey>::Public: From<&'privkey Self>,
{
    /// Perform a key exchange to get a shared secret, consuming self
    fn key_exchange(
        self,
        their_public: &<Self as PrivateKey>::Public,
    ) -> <Self as KexPrivate>::Secret;
}

/// A trait which private keys used in multiple key exchanges should implement.
///
/// These types of key-exchange pairs can be saved and restored, and will
/// persist after a key-exchange has been performed.
pub trait KexReusablePrivate:
    Clone
    + DeserializeOwned
    + KexPrivate
    + Into<Vec<u8>>
    + Serialize
    + for<'bytes> TryFrom<&'bytes [u8]>
where
    for<'privkey> <Self as PrivateKey>::Public: From<&'privkey Self>,
{
    /// Perform a key exchange to get a shared secret, without consuming
    /// self
    fn key_exchange(
        &self,
        their_public: &<Self as PrivateKey>::Public,
    ) -> <Self as KexPrivate>::Secret;
}

/// A trait describing a diffie-helman key exchange system.
///
/// This should be implemented by a zero-width type, and used to select all
/// the various types associated with a given algorithm.
pub trait Kex {
    type Public: KexPublic<KexEphemeralPrivate = Self::EphemeralPrivate>
        + for<'reusable> From<&'reusable Self::Private>
        + GetBytes;
    type Private: KexReusablePrivate
        + PrivateKey<Public = Self::Public>
        + KexPrivate<Secret = Self::Secret>;
    type EphemeralPrivate: KexEphemeralPrivate
        + PrivateKey<Public = Self::Public>
        + KexPrivate<Secret = Self::Secret>;
    type Secret: KexSecret;
}
