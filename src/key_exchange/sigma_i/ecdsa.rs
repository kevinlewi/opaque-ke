// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! ECDSA implementation for [`elliptic_curve`] [`Group`] implementations to
//! support [`SigmaI`](crate::SigmaI).

use core::marker::PhantomData;

use derive_where::derive_where;
use digest::block_api::BlockSizeUser;
use digest::{Digest, FixedOutputReset};
use ecdsa::{EcdsaCurve, SignatureSize, hazmat};
use elliptic_curve::{CurveArithmetic, Field, FieldBytes, FieldBytesSize, Scalar, SecretKey};
use hybrid_array::{Array, ArraySize};
use rand::CryptoRng;
use zeroize::Zeroize;

use super::{Message, MessageBuilder, SignatureProtocol};
use crate::ciphersuite::CipherSuite;
use crate::errors::ProtocolError;
use crate::key_exchange::group::Group;
use crate::key_exchange::group::elliptic_curve::NonIdentity;
pub use crate::key_exchange::sigma_i::shared::PreHash;
use crate::serialization::SliceExt;

/// ECDSA for [`SigmaI`](crate::SigmaI).
///
/// The ["verification state"](Self::VerifyState) is the pre-hash for the
/// message to be verified.
pub struct Ecdsa<G, H>(PhantomData<(G, H)>);

impl<G, H> SignatureProtocol for Ecdsa<G, H>
where
    G: CurveArithmetic + Group<Sk = SecretKey<G>, Pk = NonIdentity<G>> + EcdsaCurve,
    SignatureSize<G>: ArraySize + generic_array::ArrayLength,
    H: Clone + Default + Digest + BlockSizeUser + FixedOutputReset<OutputSize = FieldBytesSize<G>>,
{
    type Group = G;
    type Signature = Signature<G>;
    type SignatureLen = SignatureSize<G>;
    type VerifyState<CS: CipherSuite, KE: Group> = PreHash<H>;

    // The nonce `k` is generated (RFC 6979 with added randomness) with the same
    // hash as the message.
    fn sign<'a, R: CryptoRng, CS: CipherSuite, KE: Group>(
        sk: &<Self::Group as Group>::Sk,
        rng: &mut R,
        message: &Message<CS, KE>,
    ) -> (Self::Signature, Self::VerifyState<CS, KE>) {
        let hash = message.hash::<H>();

        (
            Signature(sign::<_, G, H>(sk, rng, &hash.sign.finalize_fixed())),
            PreHash(hash.verify.finalize_fixed()),
        )
    }

    fn verify<CS: CipherSuite, KE: Group>(
        pk: &<Self::Group as Group>::Pk,
        _: MessageBuilder<'_, CS>,
        state: Self::VerifyState<CS, KE>,
        signature: &Self::Signature,
    ) -> Result<(), ProtocolError> {
        verify(pk, &state.0, &signature.0)
    }

    fn serialize_signature(signature: &Self::Signature) -> Array<u8, Self::SignatureLen> {
        signature.0.to_bytes()
    }

    fn deserialize_take_signature(bytes: &mut &[u8]) -> Result<Self::Signature, ProtocolError> {
        ecdsa::Signature::from_bytes(&bytes.take_array("signature")?)
            .map(Signature)
            .map_err(|_| ProtocolError::SerializationError)
    }
}

fn sign<R, C, H>(sk: &SecretKey<C>, rng: &mut R, pre_hash: &[u8]) -> ecdsa::Signature<C>
where
    R: CryptoRng,
    C: CurveArithmetic + EcdsaCurve,
    SignatureSize<C>: ArraySize,
    H: Digest + BlockSizeUser + FixedOutputReset<OutputSize = FieldBytesSize<C>>,
{
    let mut ad = FieldBytes::<C>::default();
    rng.fill_bytes(&mut ad);

    let (signature, _) =
        hazmat::sign_prehashed_rfc6979::<C, H>(&sk.to_nonzero_scalar(), pre_hash, &ad);
    signature
}

fn verify<C>(
    pk: &NonIdentity<C>,
    pre_hash: &[u8],
    signature: &ecdsa::Signature<C>,
) -> Result<(), ProtocolError>
where
    C: CurveArithmetic + EcdsaCurve,
    SignatureSize<C>: ArraySize,
{
    hazmat::verify_prehashed(&pk.0.to_point(), pre_hash, signature)
        .map_err(|_| ProtocolError::InvalidLoginError)
}

/// Wrapper around [`ecdsa::Signature`] to implement [`Zeroize`].
// TODO: remove after https://github.com/RustCrypto/signatures/pull/948.
#[derive_where(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(bound = "", transparent)
)]
pub struct Signature<G: CurveArithmetic + EcdsaCurve>(pub ecdsa::Signature<G>)
where
    SignatureSize<G>: ArraySize;

impl<G: CurveArithmetic + EcdsaCurve> Zeroize for Signature<G>
where
    SignatureSize<G>: ArraySize + generic_array::ArrayLength,
{
    fn zeroize(&mut self) {
        self.0 = ecdsa::Signature::from_scalars(
            Into::<FieldBytes<G>>::into(Scalar::<G>::ONE),
            Into::<FieldBytes<G>>::into(Scalar::<G>::ONE),
        )
        .expect("failed to create `Signature` with non-zero `Scalar`s");
    }
}

#[test]
fn ecdsa() {
    use std::vec;

    use digest::Digest;
    use p256::ecdsa::signature::{DigestVerifier, RandomizedDigestSigner};
    use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
    use p256::{NistP256, PublicKey};
    use rand::Rng;
    use sha2::Sha256;

    use crate::key_exchange::group::Group;
    use crate::tests::mock_rng::CycleRng;

    let mut rng = CycleRng::new(vec![1; 32]);
    let mut system_rng = rand::rng();

    let mut message = [0; 1024];
    system_rng.fill_bytes(&mut message);

    let sk = NistP256::random_sk(&mut system_rng);
    let signing_key = SigningKey::from(sk.clone());

    let signature: Signature = signing_key.sign_digest_with_rng(&mut rng, |digest: &mut Sha256| {
        Digest::update(digest, message)
    });
    let custom_signature = sign::<_, _, Sha256>(&sk, &mut rng, &Sha256::digest(message));

    assert_eq!(signature, custom_signature);

    let pk = NistP256::public_key(&sk);
    let verifying_key = VerifyingKey::from(PublicKey::from(pk.0));

    verifying_key
        .verify_digest(
            |digest: &mut Sha256| {
                Digest::update(digest, message);
                Ok(())
            },
            &signature,
        )
        .unwrap();
    verify(&pk, &Sha256::digest(message), &custom_signature).unwrap();
}
