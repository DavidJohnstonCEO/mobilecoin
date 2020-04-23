use crate::traits::{CryptoBox, Error};

use aead::{
    generic_array::{
        sequence::Concat,
        typenum::{IsLessOrEqual, Sum, Unsigned, B1},
        ArrayLength, GenericArray,
    },
    Aead, Error as AeadError, NewAead,
};
use core::{convert::TryFrom, marker::PhantomData, ops::Add};
use digest::{BlockInput, Digest, FixedOutput, Input, Reset};
use hkdf::Hkdf;
use keys::{GetBytes, Kex, KexSecret, PublicKey};
use rand_core::{CryptoRng, RngCore};

/// Represents an implementation of Ristretto-Box using Hkdf<Blake2b> and Aes128Gcm
///
/// This structure contains the actual cryptographic primitive details, and
/// specifies part of the wire format of the "footer" where the ephemeral
/// public key comes first, and the mac comes second.
///
/// Note: If when instantiating this, the IsLessOrEqual bounds fail,
/// it may indicate that your Kex algorithm does not supply enough entropy to properly
/// drive the Aead algorithm that you have chosen, and so the combination would be insecure.
pub struct HkdfBox<KexAlgo, DigestAlgo, AeadAlgo>
where
    KexAlgo: Kex,
    for<'privkey> <KexAlgo as Kex>::Public: From<&'privkey <KexAlgo as Kex>::EphemeralPrivate>,
    DigestAlgo: Digest + Input + FixedOutput + Default + Clone + BlockInput + Reset,
    AeadAlgo: Aead + NewAead,
    AeadAlgo::NonceSize:
        IsLessOrEqual<<KexAlgo::Secret as KexSecret>::EntropyLowerBound, Output = B1>,
    AeadAlgo::KeySize:
        IsLessOrEqual<<KexAlgo::Secret as KexSecret>::EntropyLowerBound, Output = B1>,
    <<KexAlgo as Kex>::Public as PublicKey>::Size: Add<<AeadAlgo as aead::Aead>::TagSize>,
    Sum<<KexAlgo::Public as PublicKey>::Size, AeadAlgo::TagSize>: ArrayLength<u8>,
{
    _kex: PhantomData<fn() -> KexAlgo>,
    _digest: PhantomData<fn() -> DigestAlgo>,
    _aead: PhantomData<fn() -> AeadAlgo>,
}

impl<KexAlgo, DigestAlgo, AeadAlgo> CryptoBox<KexAlgo> for HkdfBox<KexAlgo, DigestAlgo, AeadAlgo>
where
    KexAlgo: Kex,
    for<'privkey> <KexAlgo as Kex>::Public: From<&'privkey <KexAlgo as Kex>::EphemeralPrivate>,
    DigestAlgo: Digest + Input + FixedOutput + Default + Clone + BlockInput + Reset,
    AeadAlgo: Aead + NewAead,
    AeadAlgo::NonceSize:
        IsLessOrEqual<<KexAlgo::Secret as KexSecret>::EntropyLowerBound, Output = B1>,
    AeadAlgo::KeySize:
        IsLessOrEqual<<KexAlgo::Secret as KexSecret>::EntropyLowerBound, Output = B1>,
    <<KexAlgo as Kex>::Public as PublicKey>::Size: Add<<AeadAlgo as aead::Aead>::TagSize>,
    Sum<<KexAlgo::Public as PublicKey>::Size, AeadAlgo::TagSize>: ArrayLength<u8>,
{
    type FooterSize = Sum<<KexAlgo::Public as PublicKey>::Size, AeadAlgo::TagSize>;

    fn encrypt_in_place_detached<T: RngCore + CryptoRng>(
        &self,
        rng: &mut T,
        key: &KexAlgo::Public,
        buffer: &mut [u8],
    ) -> Result<GenericArray<u8, Self::FooterSize>, AeadError> {
        // ECDH
        use keys::KexPublic;
        let (our_public, shared_secret) = key.new_secret(rng);

        let curve_point_bytes =
            GenericArray::<u8, <KexAlgo::Public as PublicKey>::Size>::clone_from_slice(
                our_public.get_bytes().as_ref(),
            );

        // KDF
        let (aes_key, aes_nonce) = Self::kdf_step(&shared_secret);

        // AES
        let aead = AeadAlgo::new(aes_key);
        let mac = aead.encrypt_in_place_detached(&aes_nonce, &[], buffer)?;

        // Tag is curve_point_bytes || aes_mac_bytes
        Ok(curve_point_bytes.concat(mac))
    }

    fn decrypt_in_place_detached(
        &self,
        key: &KexAlgo::Private,
        tag: &GenericArray<u8, Self::FooterSize>,
        buffer: &mut [u8],
    ) -> Result<(), Error> {
        // ECDH
        use keys::KexReusablePrivate;
        let public_key =
            KexAlgo::Public::try_from(&tag[..<KexAlgo::Public as PublicKey>::Size::USIZE])
                .map_err(Error::Key)?;
        let shared_secret = key.key_exchange(&public_key);

        // KDF
        let (aes_key, aes_nonce) = Self::kdf_step(&shared_secret);

        // AES
        let mac_ref = <&GenericArray<u8, AeadAlgo::TagSize>>::from(
            &tag[<KexAlgo::Public as PublicKey>::Size::USIZE..],
        );
        let aead = AeadAlgo::new(aes_key);
        aead.decrypt_in_place_detached(&aes_nonce, &[], buffer, mac_ref)
            .map_err(|_| Error::MacFailed)?;

        Ok(())
    }
}

impl<KexAlgo, DigestAlgo, AeadAlgo> HkdfBox<KexAlgo, DigestAlgo, AeadAlgo>
where
    KexAlgo: Kex,
    for<'privkey> <KexAlgo as Kex>::Public: From<&'privkey <KexAlgo as Kex>::EphemeralPrivate>,
    DigestAlgo: Digest + Input + FixedOutput + Default + Clone + BlockInput + Reset,
    AeadAlgo: Aead + NewAead,
    AeadAlgo::NonceSize:
        IsLessOrEqual<<KexAlgo::Secret as KexSecret>::EntropyLowerBound, Output = B1>,
    AeadAlgo::KeySize:
        IsLessOrEqual<<KexAlgo::Secret as KexSecret>::EntropyLowerBound, Output = B1>,
    <<KexAlgo as Kex>::Public as PublicKey>::Size: Add<<AeadAlgo as aead::Aead>::TagSize>,
    Sum<<KexAlgo::Public as PublicKey>::Size, AeadAlgo::TagSize>: ArrayLength<u8>,
{
    /// KDF part, factored out to avoid duplication
    /// This part must produce the key and IV/nonce for aes-gcm
    /// Blake2b produces 64 bytes of private key material which is more than we need,
    /// so we don't do the HKDF-EXPAND step.
    fn kdf_step(
        dh_secret: &KexAlgo::Secret,
    ) -> (
        GenericArray<u8, AeadAlgo::KeySize>,
        GenericArray<u8, AeadAlgo::NonceSize>,
    ) {
        let kdf = Hkdf::<DigestAlgo>::new(Some(b"dei-salty-box"), dh_secret.as_ref());
        let mut key: GenericArray<u8, AeadAlgo::KeySize> = Default::default();
        let mut nonce: GenericArray<u8, AeadAlgo::NonceSize> = Default::default();
        kdf.expand(b"aead-key", key.as_mut_slice())
            .expect("Aead::KeySize is too large compared to Digest output size");
        kdf.expand(b"aead-nonce", nonce.as_mut_slice())
            .expect("Aead::NonceSize is too large compared to Digest output size");
        (key, nonce)
    }
}

impl<KexAlgo, DigestAlgo, AeadAlgo> Default for HkdfBox<KexAlgo, DigestAlgo, AeadAlgo>
where
    KexAlgo: Kex,
    for<'privkey> <KexAlgo as Kex>::Public: From<&'privkey <KexAlgo as Kex>::EphemeralPrivate>,
    DigestAlgo: Digest + Input + FixedOutput + Default + Clone + BlockInput + Reset,
    AeadAlgo: Aead + NewAead,
    AeadAlgo::NonceSize:
        IsLessOrEqual<<KexAlgo::Secret as KexSecret>::EntropyLowerBound, Output = B1>,
    AeadAlgo::KeySize:
        IsLessOrEqual<<KexAlgo::Secret as KexSecret>::EntropyLowerBound, Output = B1>,
    <<KexAlgo as Kex>::Public as PublicKey>::Size: Add<<AeadAlgo as aead::Aead>::TagSize>,
    Sum<<KexAlgo::Public as PublicKey>::Size, AeadAlgo::TagSize>: ArrayLength<u8>,
{
    fn default() -> Self {
        Self {
            _kex: Default::default(),
            _digest: Default::default(),
            _aead: Default::default(),
        }
    }
}
