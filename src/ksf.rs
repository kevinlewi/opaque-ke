// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! Trait specifying a key stretching function

use hybrid_array::{Array, ArraySize};

use crate::errors::InternalError;

/// Used for the key stretching function in OPAQUE
pub trait Ksf: Default {
    /// Computes the key stretching function
    fn hash<L: ArraySize>(&self, input: Array<u8, L>) -> Result<Array<u8, L>, InternalError>;
}

/// A no-op hash which simply returns its input
#[derive(Default)]
pub struct Identity;

impl Ksf for Identity {
    fn hash<L: ArraySize>(&self, input: Array<u8, L>) -> Result<Array<u8, L>, InternalError> {
        Ok(input)
    }
}

#[cfg(feature = "argon2")]
impl Ksf for argon2::Argon2<'_> {
    fn hash<L: ArraySize>(&self, input: Array<u8, L>) -> Result<Array<u8, L>, InternalError> {
        let mut output = Array::default();
        self.hash_password_into(&input, &[0; argon2::RECOMMENDED_SALT_LEN], &mut output)
            .map_err(|_| InternalError::KsfError)?;
        Ok(output)
    }
}

#[cfg(all(test, feature = "argon2"))]
mod tests {
    use super::*;

    /// Preserve the default KSF outputs generated with argon2 0.5.3, including
    /// the zero salt used by OPAQUE, for 32-byte and 64-byte OPRF outputs.
    #[test]
    fn argon2_matches_0_5_3_output() {
        let ksf = argon2::Argon2::default();
        let output = ksf
            .hash(hybrid_array::ArrayN::<u8, 32>::from([42; 32]))
            .unwrap();
        assert_eq!(
            hex::encode(output),
            "49fafd0e4b83b923dc3580a20f29306e64fd9c7657cef11aebb86ae5def41bda"
        );

        let output = ksf
            .hash(hybrid_array::ArrayN::<u8, 64>::from([42; 64]))
            .unwrap();
        assert_eq!(
            hex::encode(output),
            concat!(
                "a61f5b25dc3c30a79d8f103626c35a32819096161113853a713686f171424a49",
                "a5fd861798db2b6ba9b96fb559dfcd42d0927d9ec2874b202fbd08c35ba41024"
            )
        );
    }
}
