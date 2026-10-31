// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! A convenience trait for digest bounds used throughout the library

use digest::block_api::EagerHash;
use digest::{FixedOutputReset, OutputSizeUser};
use generic_array::ArrayLength;

pub(crate) type OutputSize<H> = <H as OutputSizeUser>::OutputSize;

/// A hash usable for HKDF and HMAC: an eager block hash (which also bounds
/// its block size below 256 bytes) with a resettable fixed output, whose
/// block-level core produces the same output size as the hash itself.
pub trait Hash:
    EagerHash<Core: OutputSizeUser<OutputSize = OutputSize<Self>>>
    + OutputSizeUser<OutputSize: ArrayLength>
    + Default
    + FixedOutputReset
{
}

impl<T> Hash for T where
    T: EagerHash<Core: OutputSizeUser<OutputSize = OutputSize<T>>>
        + OutputSizeUser<OutputSize: ArrayLength>
        + Default
        + FixedOutputReset
{
}
