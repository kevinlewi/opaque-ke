// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Key Exchange group implementation for Ed25519

use core::iter;

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::traits::IsIdentity;
use curve25519_dalek::{EdwardsPoint, Scalar};
use digest::Digest;
pub use ed25519_dalek;
use ed25519_dalek::hazmat::ExpandedSecretKey;
use ed25519_dalek::{SecretKey, Sha512};
use hybrid_array::Array;
use hybrid_array::typenum::{U32, U64};
use rand::CryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::Group;
use crate::ciphersuite::CipherSuite;
use crate::errors::{InternalError, ProtocolError};
use crate::key_exchange::sigma_i::hash_eddsa::implementation::HashEddsaImpl;
use crate::key_exchange::sigma_i::pure_eddsa::implementation::PureEddsaImpl;
pub use crate::key_exchange::sigma_i::shared::PreHash;
use crate::key_exchange::sigma_i::{CachedMessage, Message, MessageBuilder};
use crate::serialization::{SliceExt, UpdateExt};

/// Implementation for Ed25519.
pub struct Ed25519;

impl Group for Ed25519 {
    type Pk = VerifyingKey;
    type PkLen = U32;
    type Sk = SigningKey;
    type SkLen = U32;

    fn serialize_pk(pk: &Self::Pk) -> Array<u8, Self::PkLen> {
        pk.compressed.0.into()
    }

    fn deserialize_take_pk(bytes: &mut &[u8]) -> Result<Self::Pk, ProtocolError> {
        let bytes = bytes.take_array::<U32>("public key")?;

        VerifyingKey::from_bytes(bytes.into())
    }

    fn random_sk<R: CryptoRng>(rng: &mut R) -> Self::Sk {
        let mut sk = <[u8; 32]>::default();
        rng.fill_bytes(&mut sk);

        SigningKey::from_bytes(sk)
    }

    fn derive_scalar(seed: Array<u8, Self::SkLen>) -> Result<Self::Sk, InternalError> {
        Ok(SigningKey::from_bytes(seed.into()))
    }

    fn public_key(sk: &Self::Sk) -> Self::Pk {
        sk.verifying_key
    }

    fn serialize_sk(sk: &Self::Sk) -> Array<u8, Self::SkLen> {
        sk.sk.into()
    }

    fn deserialize_take_sk(bytes: &mut &[u8]) -> Result<Self::Sk, ProtocolError> {
        Ok(SigningKey::from_bytes(
            bytes.take_array::<U32>("secret key")?.into(),
        ))
    }
}

impl PureEddsaImpl for Ed25519 {
    type Signature = Signature;
    type SignatureLen = U64;

    fn sign<CS: CipherSuite, KE: Group>(
        sk: &Self::Sk,
        message: &Message<CS, KE>,
    ) -> (Self::Signature, CachedMessage<CS, KE>) {
        (sign(sk, false, message.sign_message()), message.to_cached())
    }

    /// Validates that the signature was created by signing the given message
    /// with the corresponding private key.
    fn verify<CS: CipherSuite, KE: Group>(
        pk: &Self::Pk,
        message_builder: MessageBuilder<'_, CS>,
        state: CachedMessage<CS, KE>,
        signature: &Self::Signature,
    ) -> Result<(), ProtocolError> {
        verify(
            pk,
            false,
            message_builder.build::<KE>(state).verify_message(),
            signature,
        )
    }

    fn deserialize_take_signature(bytes: &mut &[u8]) -> Result<Self::Signature, ProtocolError> {
        Signature::deserialize_take(bytes)
    }

    fn serialize_signature(signature: &Self::Signature) -> Array<u8, Self::SignatureLen> {
        signature.serialize()
    }
}

impl HashEddsaImpl for Ed25519 {
    type Signature = Signature;
    type SignatureLen = U64;
    type VerifyState<CS: CipherSuite, KE: Group> = PreHash<Sha512>;

    fn sign<CS: CipherSuite, KE: Group>(
        sk: &Self::Sk,
        message: &Message<CS, KE>,
    ) -> (Self::Signature, Self::VerifyState<CS, KE>) {
        let hash = message.hash::<Sha512>();

        (
            sign(sk, true, iter::once(hash.sign.finalize().as_slice())),
            PreHash(hash.verify.finalize()),
        )
    }

    /// Validates that the signature was created by signing the given message
    /// with the corresponding private key.
    fn verify<CS: CipherSuite, KE: Group>(
        pk: &Self::Pk,
        state: Self::VerifyState<CS, KE>,
        signature: &Self::Signature,
    ) -> Result<(), ProtocolError> {
        verify(pk, true, iter::once(state.0.as_slice()), signature)
    }

    fn deserialize_take_signature(bytes: &mut &[u8]) -> Result<Self::Signature, ProtocolError> {
        Signature::deserialize_take(bytes)
    }

    fn serialize_signature(signature: &Self::Signature) -> Array<u8, Self::SignatureLen> {
        signature.serialize()
    }
}

// This contains a manual implementation of EdDSA because `ed25519-dalek`
// doesn't support message streaming. See
// TODO: remove after https://github.com/dalek-cryptography/curve25519-dalek/pull/556.
fn sign<'a>(
    sk: &SigningKey,
    pre_hash: bool,
    message: impl Clone + Iterator<Item = &'a [u8]>,
) -> Signature {
    let mut h = Sha512::new();

    if pre_hash {
        h.update(b"SigEd25519 no Ed25519 collisions");
        h.update([1]); // Ed25519ph
        h.update([0]);
    }

    h.update(sk.hash_prefix);
    h.update_iter(message.clone());

    let r = Scalar::from_hash(h);
    #[allow(non_snake_case)]
    let R = EdwardsPoint::mul_base(&r).compress();

    h = Sha512::new();

    if pre_hash {
        h.update(b"SigEd25519 no Ed25519 collisions");
        h.update([1]); // Ed25519ph
        h.update([0]);
    }

    h.update(R.as_bytes());
    h.update(sk.verifying_key.compressed.0);
    h.update_iter(message);

    let k = Scalar::from_hash(h);
    let s: Scalar = (k * sk.scalar) + r;

    Signature { R, s }
}

fn verify<'a>(
    pk: &VerifyingKey,
    pre_hash: bool,
    message: impl Iterator<Item = &'a [u8]>,
    signature: &Signature,
) -> Result<(), ProtocolError> {
    let mut h = Sha512::new();

    if pre_hash {
        h.update(b"SigEd25519 no Ed25519 collisions");
        h.update([1]); // Ed25519ph
        h.update([0]);
    }

    h.update(signature.R.as_bytes());
    h.update(pk.compressed.as_bytes());
    h.update_iter(message);
    let k = Scalar::from_hash(h);

    #[allow(non_snake_case)]
    let minus_A: EdwardsPoint = -pk.point;
    #[allow(non_snake_case)]
    let expected_R =
        EdwardsPoint::vartime_double_scalar_mul_basepoint(&k, &(minus_A), &signature.s).compress();

    if expected_R == signature.R {
        Ok(())
    } else {
        Err(ProtocolError::InvalidLoginError)
    }
}

/// Ed25519 verifying key.
// `ed25519_dalek::VerifyingKey` doesn't implement `Zeroize`.
// TODO: remove after https://github.com/dalek-cryptography/curve25519-dalek/pull/747.
// Required for manual implementation of EdDSA.
// TODO: remove after https://github.com/dalek-cryptography/curve25519-dalek/pull/556.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Zeroize)]
pub struct VerifyingKey {
    point: EdwardsPoint,
    compressed: CompressedEdwardsY,
}

impl VerifyingKey {
    fn from_bytes(bytes: [u8; 32]) -> Result<Self, ProtocolError> {
        let compressed = CompressedEdwardsY(bytes);

        if let Some(point) = compressed.decompress().filter(|point| !point.is_identity()) {
            Ok(Self { point, compressed })
        } else {
            Err(ProtocolError::SerializationError)
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for VerifyingKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use core::fmt::{self, Formatter};

        use serde::de::{Deserialize, Deserializer, Error, SeqAccess, Visitor};

        struct VerifyingKeyVisitor;

        impl<'de> Visitor<'de> for VerifyingKeyVisitor {
            type Value = VerifyingKey;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                Formatter::write_str(formatter, "tuple struct VerifyingKey")
            }

            fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                let compressed = CompressedEdwardsY::deserialize(deserializer)?;
                VerifyingKey::from_bytes(compressed.0).map_err(Error::custom)
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let compressed: CompressedEdwardsY = seq.next_element()?.ok_or_else(|| {
                    Error::invalid_length(0, &"tuple struct VerifyingKey with 1 element")
                })?;
                VerifyingKey::from_bytes(compressed.0).map_err(Error::custom)
            }
        }

        deserializer.deserialize_newtype_struct("VerifyingKey", VerifyingKeyVisitor)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for VerifyingKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_newtype_struct("VerifyingKey", &self.compressed)
    }
}

/// Ed25519 signing key.
// We store the `ExpandedSecret` in memory to avoid computing it on demand and then discarding it
// again.
#[derive(Clone, Debug, Eq, PartialEq, ZeroizeOnDrop)]
pub struct SigningKey {
    // `ed25519_dalek::SigningKey` doesn't implement `Zeroize`. See
    // https://github.com/dalek-cryptography/curve25519-dalek/pull/747
    // Required for manual implementation of EdDSA.
    // TODO: remove after https://github.com/dalek-cryptography/curve25519-dalek/pull/556.
    sk: SecretKey,
    verifying_key: VerifyingKey,
    // `ed25519_dalek::ExpandedSecret` doesn't implement traits we need. See
    // TODO: remove after https://github.com/dalek-cryptography/curve25519-dalek/pull/748 and
    // https://github.com/dalek-cryptography/curve25519-dalek/pull/747.
    scalar: Scalar,
    hash_prefix: [u8; 32],
}

impl SigningKey {
    fn from_bytes(sk: [u8; 32]) -> Self {
        let ExpandedSecretKey {
            scalar,
            hash_prefix,
        } = ExpandedSecretKey::from(&sk);
        let point = EdwardsPoint::mul_base(&scalar);
        let verifying_key = VerifyingKey {
            point,
            compressed: point.compress(),
        };

        SigningKey {
            sk,
            verifying_key,
            scalar,
            hash_prefix,
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for SigningKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use core::fmt::{self, Formatter};

        use serde::de::{Deserialize, Deserializer, Error, SeqAccess, Visitor};
        use zeroize::Zeroizing;

        struct SigningKeyVisitor;

        impl<'de> Visitor<'de> for SigningKeyVisitor {
            type Value = SigningKey;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                Formatter::write_str(formatter, "tuple struct SigningKey")
            }

            // The serialized form is the raw 32-byte seed (see `Serialize`
            // below), which is generally not a canonical scalar, so it must not
            // be parsed as a `Scalar`.
            fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                let sk = Zeroizing::<SecretKey>::deserialize(deserializer)?;
                Ok(SigningKey::from_bytes(*sk))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let sk: Zeroizing<SecretKey> = seq.next_element()?.ok_or_else(|| {
                    Error::invalid_length(0, &"tuple struct SigningKey with 1 element")
                })?;
                Ok(SigningKey::from_bytes(*sk))
            }
        }

        deserializer.deserialize_newtype_struct("SigningKey", SigningKeyVisitor)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for SigningKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_newtype_struct("SigningKey", &self.sk)
    }
}

/// Ed25519 Signature.
// `ed25519_dalek::Signature` doesn't implement validation with Serde de/serialization.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(non_snake_case)]
pub struct Signature {
    R: CompressedEdwardsY,
    s: Scalar,
}

impl Signature {
    /// Expects the `R` and `s` components of a Ed25519 signature with no added
    /// framing.
    pub fn from_slice(mut bytes: &[u8]) -> Result<Self, ProtocolError> {
        Self::deserialize_take(&mut bytes)
    }

    fn deserialize_take(bytes: &mut &[u8]) -> Result<Self, ProtocolError> {
        #[allow(non_snake_case)]
        let R = CompressedEdwardsY(bytes.take_array::<U32>("signature R")?.into());

        let s = Scalar::from_canonical_bytes(bytes.take_array::<U32>("signature s")?.into())
            .into_option()
            .ok_or(ProtocolError::SerializationError)?;

        Ok(Self { R, s })
    }

    fn serialize(&self) -> Array<u8, U64> {
        Array::<u8, U32>::from(self.R.0).concat(Array::<u8, U32>::from(self.s.to_bytes()))
    }
}

impl Zeroize for Signature {
    fn zeroize(&mut self) {
        self.R.0 = [0; 32];
        self.s = Scalar::default();
    }
}

#[cfg(test)]
mod test {
    use std::iter;

    use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
    use rand::Rng;

    use super::*;

    #[test]
    fn pure_eddsa() {
        let mut message = [0; 1024];
        rand::rng().fill_bytes(&mut message);

        let mut sk = SecretKey::default();
        rand::rng().fill_bytes(&mut sk);
        let signing_key = SigningKey::from_bytes(&sk);

        let signature = signing_key.sign(&message);

        let custom_sk = Ed25519::deserialize_take_sk(&mut sk.as_slice()).unwrap();
        let custom_signature = sign(&custom_sk, false, iter::once(message.as_slice()));

        assert_eq!(
            signature.to_bytes(),
            custom_signature.serialize().as_slice()
        );

        let verifying_key = VerifyingKey::from(&signing_key);
        verifying_key.verify(&message, &signature).unwrap();

        let custom_pk = Ed25519::public_key(&custom_sk);
        verify(
            &custom_pk,
            false,
            iter::once(message.as_slice()),
            &custom_signature,
        )
        .unwrap();
    }

    #[test]
    fn hash_eddsa() {
        let mut message = [0; 1024];
        rand::rng().fill_bytes(&mut message);
        let message = Sha512::new_with_prefix(message);
        let pre_hash = message.clone().finalize();

        let mut sk = SecretKey::default();
        rand::rng().fill_bytes(&mut sk);
        let signing_key = SigningKey::from_bytes(&sk);

        let signature = signing_key.sign_prehashed(message.clone(), None).unwrap();

        let custom_sk = Ed25519::deserialize_take_sk(&mut sk.as_slice()).unwrap();
        let custom_signature = sign(&custom_sk, true, iter::once(pre_hash.as_slice()));

        assert_eq!(
            signature.to_bytes(),
            custom_signature.serialize().as_slice()
        );

        let verifying_key = VerifyingKey::from(&signing_key);
        verifying_key
            .verify_prehashed(message, None, &signature)
            .unwrap();

        let custom_pk = Ed25519::public_key(&custom_sk);
        verify(
            &custom_pk,
            true,
            iter::once(pre_hash.as_slice()),
            &custom_signature,
        )
        .unwrap();
    }

    /// Serde must round-trip any signing key, not just those whose seed
    /// happens to be a canonical scalar.
    #[cfg(feature = "serde")]
    #[test]
    fn signing_key_serde_roundtrip() {
        for _ in 0..64 {
            let mut sk = SecretKey::default();
            rand::rng().fill_bytes(&mut sk);
            let signing_key = super::SigningKey::from_bytes(sk);

            let json = serde_json::to_string(&signing_key).unwrap();
            let from_json: super::SigningKey = serde_json::from_str(&json).unwrap();
            assert_eq!(signing_key, from_json);

            let bytes = bincode::serialize(&signing_key).unwrap();
            let from_bincode: super::SigningKey = bincode::deserialize(&bytes).unwrap();
            assert_eq!(signing_key, from_bincode);

            // The encoding is the raw 32-byte seed, so it stays compatible
            // with data serialized by previous versions.
            assert_eq!(bytes, sk);
        }
    }
}
