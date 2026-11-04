// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Defines the [`CipherSuite`] trait to specify the underlying primitives for
//! OPAQUE

use core::ops::Add;

use generic_array::ArrayLength;
use generic_array::typenum::Sum;

use crate::envelope::NonceLen;
use crate::hash::{Hash, OutputSize};
use crate::key_exchange::KeyExchange;
use crate::key_exchange::group::Group;
use crate::ksf::Ksf;
use crate::opaque::MaskedResponseLen;

/// Configures the underlying primitives used in OPAQUE
/// * `OprfCs`: A VOPRF ciphersuite, see [`voprf::CipherSuite`].
/// * `KeGroup`: A `Group` used for the `KeyExchange`.
/// * `KeyExchange`: The key exchange protocol to use in the login step
/// * `Hash`: The main hashing function to use
/// * `Ksf`: A key stretching function, typically used for password hashing
pub trait CipherSuite
where
    OprfHash<Self>: Hash,
    // Envelope: Nonce + Hash
    // MaskedResponse: (Nonce + Hash) + KePk
    OutputSize<OprfHash<Self>>: Add<NonceLen>,
    Sum<OutputSize<OprfHash<Self>>, NonceLen>: ArrayLength + Add<<KeGroup<Self> as Group>::PkLen>,
    MaskedResponseLen<Self>: ArrayLength,
{
    /// A VOPRF ciphersuite, see [`voprf::CipherSuite`].
    ///
    /// The [`ArrayLength`] bounds hold for every [`voprf::Group`] and let
    /// opaque-ke store VOPRF elements and scalars in its serialized types.
    type OprfCs: voprf::CipherSuite<Group: voprf::Group<ElemLen: ArrayLength, ScalarLen: ArrayLength>>;
    /// A key exchange protocol
    type KeyExchange: KeyExchange;
    /// A key stretching function, typically used for password hashing
    type Ksf: Ksf;
}

pub(crate) type OprfGroup<CS: CipherSuite> = <CS::OprfCs as voprf::CipherSuite>::Group;
pub(crate) type OprfHash<CS: CipherSuite> = <CS::OprfCs as voprf::CipherSuite>::Hash;
pub(crate) type KeGroup<CS: CipherSuite> = <CS::KeyExchange as KeyExchange>::Group;
pub(crate) type KeHash<CS: CipherSuite> = <CS::KeyExchange as KeyExchange>::Hash;
