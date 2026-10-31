// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Implementation for EC curves via [`elliptic_curve`] traits.

use core::fmt::{self, Debug, Formatter};

use derive_where::derive_where;
use elliptic_curve::group::{Group as _, GroupEncoding};
use elliptic_curve::sec1::{ModulusSize, ToSec1Point};
use elliptic_curve::{
    CurveArithmetic, FieldBytesSize, Generate, NonZeroScalar, ProjectivePoint, Scalar, SecretKey,
    point,
};
use generic_array::ArrayLength;
use hybrid_array::Array;
use rand::CryptoRng;
use voprf::Mode;

use super::{Group, STR_OPAQUE_DERIVE_AUTH_KEY_PAIR};
use crate::errors::{InternalError, ProtocolError};
use crate::key_exchange::shared::DiffieHellman;
use crate::serialization::SliceExt;

impl<G> Group for G
where
    Self: CurveArithmetic + voprf::CipherSuite<Group = Self> + voprf::Group<Scalar = Scalar<Self>>,
    FieldBytesSize<Self>: ModulusSize + ArrayLength,
    <FieldBytesSize<Self> as ModulusSize>::CompressedPointSize: ArrayLength,
    ProjectivePoint<Self>: GroupEncoding<Repr = Array<u8, <FieldBytesSize<Self> as ModulusSize>::CompressedPointSize>>
        + ToSec1Point<Self>,
{
    // We don't use `elliptic_curve::PublicKey` because it stores its internals
    // in a format ideal for serialization and not computation. This is
    // inconsistent with our other implementations.
    type Pk = NonIdentity<Self>;

    type PkLen = <FieldBytesSize<Self> as ModulusSize>::CompressedPointSize;

    type Sk = SecretKey<Self>;

    type SkLen = FieldBytesSize<Self>;

    fn serialize_pk(pk: &Self::Pk) -> Array<u8, Self::PkLen> {
        Array::try_from(pk.0.to_point().to_sec1_point(true).as_bytes())
            .expect("a compressed SEC1 point has the compressed point size")
    }

    fn deserialize_take_pk(bytes: &mut &[u8]) -> Result<Self::Pk, ProtocolError> {
        point::NonIdentity::<ProjectivePoint<Self>>::from_bytes(&bytes.take_array("public key")?)
            .into_option()
            .map(NonIdentity)
            .ok_or(ProtocolError::SerializationError)
    }

    fn random_sk<R: CryptoRng>(rng: &mut R) -> Self::Sk {
        SecretKey::<Self>::generate_from_rng(rng)
    }

    fn derive_scalar(seed: Array<u8, Self::SkLen>) -> Result<Self::Sk, InternalError> {
        voprf::derive_key::<Self>(&seed, &STR_OPAQUE_DERIVE_AUTH_KEY_PAIR, Mode::Oprf)
            .map(|scalar| {
                NonZeroScalar::new(scalar).expect("`derive_key()` returned a zero scalar")
            })
            .map(SecretKey::from)
            .map_err(InternalError::from)
    }

    fn public_key(sk: &Self::Sk) -> Self::Pk {
        // Non-panicking version in https://github.com/RustCrypto/traits/pull/1833.
        NonIdentity(
            point::NonIdentity::new(ProjectivePoint::<Self>::mul_by_generator(
                &*sk.to_nonzero_scalar(),
            ))
            .expect("multiplying with a non-zero scalar can never yield the identity element"),
        )
    }

    fn serialize_sk(sk: &Self::Sk) -> Array<u8, Self::SkLen> {
        sk.to_bytes()
    }

    fn deserialize_take_sk(bytes: &mut &[u8]) -> Result<Self::Sk, ProtocolError> {
        SecretKey::<Self>::from_bytes(&bytes.take_array("secret key")?)
            .map_err(|_| ProtocolError::SerializationError)
    }
}

impl<G> DiffieHellman<G> for SecretKey<G>
where
    G: CurveArithmetic + voprf::CipherSuite<Group = G> + voprf::Group<Scalar = Scalar<G>>,
    FieldBytesSize<G>: ModulusSize + ArrayLength,
    <FieldBytesSize<G> as ModulusSize>::CompressedPointSize: ArrayLength,
    ProjectivePoint<G>: GroupEncoding<Repr = Array<u8, <FieldBytesSize<G> as ModulusSize>::CompressedPointSize>>
        + ToSec1Point<G>,
{
    fn diffie_hellman(
        &self,
        pk: &NonIdentity<G>,
    ) -> Array<u8, <FieldBytesSize<G> as ModulusSize>::CompressedPointSize> {
        Array::try_from(
            (pk.0.to_point() * *self.to_nonzero_scalar())
                .to_sec1_point(true)
                .as_bytes(),
        )
        .expect("a compressed SEC1 point has the compressed point size")
    }
}

/// Wrapper around [`NonIdentity`](point::NonIdentity) to [`Eq`].
// TODO: remove after https://github.com/RustCrypto/traits/pull/1834.
#[derive_where(Clone, Copy)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(
        bound(
            deserialize = "point::NonIdentity<ProjectivePoint<G>>: serde::Deserialize<'de>",
            serialize = "point::NonIdentity<ProjectivePoint<G>>: serde::Serialize"
        ),
        transparent
    )
)]
pub struct NonIdentity<G: CurveArithmetic>(pub point::NonIdentity<ProjectivePoint<G>>);

impl<G: CurveArithmetic> Debug for NonIdentity<G> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("NonIdentity")
            .field(&self.0.to_point())
            .finish()
    }
}

impl<G: CurveArithmetic> PartialEq for NonIdentity<G> {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_point().eq(&other.0.to_point())
    }
}

impl<G: CurveArithmetic> Eq for NonIdentity<G> {}
