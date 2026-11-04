// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

use core::ops::Add;

use digest::Update;
use generic_array::typenum::{Sum, Unsigned};
use generic_array::{ArrayLength, GenericArray};
use hybrid_array::{Array, ArraySize};

use crate::errors::ProtocolError;

/// Conversion of RustCrypto-native byte strings, e.g. [`digest::Output`] or
/// [`Group`](crate::key_exchange::group::Group) encodings, into
/// [`GenericArray`]s for opaque-ke's compound serialization types.
///
/// Messages whose lengths are sums of primitive lengths are [`GenericArray`]s,
/// because such sums can fall outside the sizes `hybrid_array` implements. The
/// conversion is provided by generic-array's `hybrid-array-0_4` feature: it
/// converts by value, without heap allocation or element-wise cloning, and the
/// lengths are checked at compile time. Parts are then joined with
/// [`Concat`](generic_array::sequence::Concat).
///
/// For values holding secrets, use [`ByteArray::concat_ref()`] instead, which
/// does not create intermediate copies.
pub(crate) trait HybridArrayExt {
    type Len: ArrayLength;

    /// Converts `self` into a [`GenericArray`] by value.
    fn into_generic_array(self) -> GenericArray<u8, Self::Len>;

    /// Returns a [`GenericArray`] copy of `self`.
    fn to_generic_array(&self) -> GenericArray<u8, Self::Len>;
}

impl<L: ArraySize + ArrayLength> HybridArrayExt for Array<u8, L> {
    type Len = L;

    fn into_generic_array(self) -> GenericArray<u8, L> {
        GenericArray::from(self)
    }

    fn to_generic_array(&self) -> GenericArray<u8, L> {
        GenericArray::from(self.clone())
    }
}

/// A fixed-size byte string, either a [`hybrid_array::Array`] or a
/// [`GenericArray`], whose length is known at compile time.
pub(crate) trait ByteArray {
    type Len: ArrayLength;

    fn as_bytes(&self) -> &[u8];

    /// Concatenates `self` and `other` into a new [`GenericArray`], copying
    /// directly from both references. Unlike converting and then using
    /// [`Concat`](generic_array::sequence::Concat), this creates no temporary
    /// copies of the inputs, so it is used for values holding secrets. The
    /// output length is checked at compile time.
    fn concat_ref<O: ByteArray>(&self, other: &O) -> GenericArray<u8, Sum<Self::Len, O::Len>>
    where
        Self::Len: Add<O::Len>,
        Sum<Self::Len, O::Len>: ArrayLength,
    {
        let mut output = GenericArray::<u8, Sum<Self::Len, O::Len>>::default();
        let (front, back) = output.split_at_mut(Self::Len::USIZE);
        front.copy_from_slice(self.as_bytes());
        back.copy_from_slice(other.as_bytes());
        output
    }
}

impl<L: ArraySize + ArrayLength> ByteArray for Array<u8, L> {
    type Len = L;

    fn as_bytes(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<L: ArrayLength> ByteArray for GenericArray<u8, L> {
    type Len = L;

    fn as_bytes(&self) -> &[u8] {
        self.as_slice()
    }
}

// Corresponds to the I2OSP() function from RFC8017
pub(crate) fn i2osp<L: ArraySize>(input: usize) -> Result<Array<u8, L>, ProtocolError> {
    const SIZEOF_USIZE: usize = core::mem::size_of::<usize>();

    // Make sure input fits in output.
    if (SIZEOF_USIZE as u32 - input.leading_zeros() / 8) > L::U32 {
        return Err(ProtocolError::SerializationError);
    }

    let mut output = Array::default();
    output[L::USIZE.saturating_sub(SIZEOF_USIZE)..]
        .copy_from_slice(&input.to_be_bytes()[SIZEOF_USIZE.saturating_sub(L::USIZE)..]);
    Ok(output)
}

// Corresponds to the OS2IP() function from RFC8017
#[cfg(test)]
pub(crate) fn os2ip(input: &[u8]) -> Result<usize, ProtocolError> {
    if input.len() > core::mem::size_of::<usize>() {
        return Err(ProtocolError::SerializationError);
    }

    let mut output_array = [0u8; core::mem::size_of::<usize>()];
    output_array[core::mem::size_of::<usize>() - input.len()..].copy_from_slice(input);
    Ok(usize::from_be_bytes(output_array))
}

pub(crate) trait GenericArrayExt<O: ArrayLength> {
    type Output: ArrayLength;

    /// This allows us to concat two [`GenericArray`]s but with `where` bounds
    /// `Other + Self`. Because sometimes `Self + Other` doesn't imply the
    /// bounds and we have to add them to every call.
    fn concat_ext(&self, rest: &GenericArray<u8, O>) -> GenericArray<u8, Self::Output>;
}

impl<L: ArrayLength, O: ArrayLength> GenericArrayExt<O> for GenericArray<u8, L>
where
    O: Add<L>,
    Sum<O, L>: ArrayLength,
{
    type Output = Sum<O, L>;

    fn concat_ext(&self, other: &GenericArray<u8, O>) -> GenericArray<u8, Self::Output> {
        let mut output = GenericArray::<u8, Self::Output>::default();
        output[..L::USIZE].copy_from_slice(self);
        output[L::USIZE..].copy_from_slice(other);

        output
    }
}

pub(crate) trait UpdateExt {
    fn update_iter<'a>(&mut self, iter: impl Iterator<Item = &'a [u8]>);

    fn chain_iter<'a>(self, iter: impl Iterator<Item = &'a [u8]>) -> Self;
}

impl<T: Update> UpdateExt for T {
    fn update_iter<'a>(&mut self, iter: impl Iterator<Item = &'a [u8]>) {
        for bytes in iter {
            self.update(bytes);
        }
    }

    fn chain_iter<'a>(self, iter: impl Iterator<Item = &'a [u8]>) -> Self {
        let mut self_ = self;

        for bytes in iter {
            self_ = self_.chain(bytes);
        }

        self_
    }
}

pub(crate) trait SliceExt {
    fn take_array<L: ArraySize>(
        self: &mut &Self,
        name: &'static str,
    ) -> Result<Array<u8, L>, ProtocolError>;
}

impl SliceExt for [u8] {
    fn take_array<L: ArraySize>(
        self: &mut &Self,
        name: &'static str,
    ) -> Result<Array<u8, L>, ProtocolError> {
        if L::USIZE > self.len() {
            return Err(ProtocolError::SizeError {
                name,
                len: L::USIZE,
                actual_len: self.len(),
            });
        }

        let (front, back) = self.split_at(L::USIZE);
        *self = back;
        Ok(Array::try_from(front).expect("`front` has exactly `L` bytes"))
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod unit_tests {
    use generic_array::typenum::{U1, U2};

    use super::*;

    // Test the error condition for I2OSP
    #[test]
    fn test_i2osp_err_check() {
        assert!(i2osp::<U1>(0).is_ok());

        assert!(i2osp::<U1>(255).is_ok());
        assert!(i2osp::<U1>(256).is_err());
        assert!(i2osp::<U1>(257).is_err());

        assert!(i2osp::<U2>(256 * 256 - 1).is_ok());
        assert!(i2osp::<U2>(256 * 256).is_err());
        assert!(i2osp::<U2>(256 * 256 + 1).is_err());
    }
}
