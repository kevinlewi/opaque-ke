# Changelog

## Unreleased
* Fixed serde deserialization of Ed25519 `SigningKey` (used by the SIGMA-I
  EdDSA ciphersuites, e.g. in a serialized `ServerSetup`): the stored 32-byte
  seed was parsed as a canonical scalar, so deserialization failed for most
  keys. Affects all releases since 4.0.0. The serialized format is unchanged
* Migrated to the RustCrypto 0.14 / `hybrid-array` ecosystem, removing the
  `crypto-bigint` 0.5 dependency affected by
  [RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387.html)
  (thanks to [nbari](https://github.com/nbari) for #428 and #427; resolves #426,
  supersedes #424):
  * digest 0.10 -> 0.11, hkdf/hmac 0.12 -> 0.13, elliptic-curve 0.13 -> 0.14.3,
    curve25519-dalek 4 -> 5, ed25519-dalek 2 -> 3, ecdsa 0.16 -> 0.17,
    rand 0.8 -> 0.10, voprf 0.5 -> 0.6.0-pre.2, generic-array 0.14 -> 1, and
    the new hybrid-array 0.4 dependency
  * argon2 0.5 -> 0.6, preserving the existing KSF parameters and output bytes
  * The direct rfc6979 dependency was removed; ECDSA signing now uses
    `ecdsa::hazmat::sign_prehashed_rfc6979()`
  * Parts of this migration were adapted from the `sid-opaque-ke` crate of the
    [structured-id/sid](https://github.com/structured-id/sid) project
* Increased MSRV to 1.88
* **Breaking: primitive buffers are now `hybrid_array::Array`** (re-exported as
  `pub use hybrid_array;`): hash outputs (`digest::Output`, e.g. session keys,
  export keys and OPRF seeds), `Group` public and secret key encodings,
  signatures, ML-KEM keys and ciphertexts, `PrivateKeySerialization` and
  `OprfSeedSerialization` outputs and `Ksf::hash()` inputs and outputs. Their
  length types (e.g. `Group::PkLen`, `PrivateKeySerialization::Len`) are bound
  by both `hybrid_array::ArraySize` and `generic_array::ArrayLength`
* **Breaking: serialized messages (`serialize()` outputs and `*Len` aliases)
  remain `generic_array::GenericArray`, now from generic-array 1.x**, to support
  compound lengths. Length bounds are now `generic_array::ArrayLength` instead of
  `ArrayLength<u8>`, and `pub use generic_array;` now re-exports generic-array 1.x
* **Breaking: RNG bounds are now `rand::CryptoRng` from rand 0.10** (rand_core
  0.10) instead of `RngCore + CryptoRng` from rand 0.8. `rand::rngs::SysRng` is
  fallible and can be used via `rand::rand_core::UnwrapErr(SysRng)`
* **Breaking: the `Hash` trait bounds were simplified** to build on
  `digest::block_api::EagerHash`; the repeated `ProxyHash`, `IsLess<U256>` and
  `NonZero` bounds are gone and `ProxyHash` was removed
* **Breaking: the getrandom wasm backend is no longer enabled by opaque-ke.**
  The `std` feature now only enables `rand/std`. Web (`wasm32-unknown-unknown`)
  users who rely on system randomness must enable getrandom's `wasm_js` feature
  themselves
* **Breaking: elliptic curve ciphersuites need p256/p384/p521 0.14 with the
  `oprf` feature** (previously the `voprf` and `hash2curve` features of 0.13)
* **Breaking: `sigma_i::ecdsa::Signature<G>` now requires `G: EcdsaCurve`**,
  following ecdsa 0.17
* ECDSA signatures may differ from the previous implementation for the same
  RNG output in negligible-probability cases: rfc6979 0.6 reduces the message
  hash modulo the curve order, and rejected `k` values now continue the
  HMAC-DRBG instead of drawing new randomness
* Randomly generated values (e.g. blinds and secret keys) can differ from
  previous versions for the same RNG output, because voprf 0.6 and
  elliptic-curve 0.14 consume RNG bytes differently. Protocol encodings,
  registration records and ML-KEM expanded-key client states keep their
  existing byte formats
* Upgraded the HSM test dependency to cryptoki 0.12.1 to address
  RUSTSEC-2026-0286

## 4.1.0-pre.2 (March 26, 2026)
* Upgraded ml-kem from 0.2 to 0.3.0-rc.0
* Increased MSRV to 1.87

## 4.1.0-pre.1 (November 17, 2025)
* Added ml-kem re-export behind the kem feature

## 4.1.0-pre.0 (November 11, 2025)
* Fixed dependency exporting for the rand crate
* Added TripleDhKem key exchange protocol

## 4.0.1 (October 30, 2025)
* Fixing docs building issue

## 4.0.0 (October 23, 2025)
* Increased MSRV to 1.83
* Synced implementation with RFC 9807 (no core protocol changes)
* Added a SIGMA-I key exchange implementation
* Removed KeGroup type from the Ciphersuite trait (now part of KeyExchange type)
  * **Breaking: existing Ciphersuite trait definitions need to be updated**
* Ensured that dummy record is always created to avoid timing attack issues
* Modified the dummy registration file to only contain the public key
  instead of the keypair
  * **Breaking: existing `ServerSetup`s need to be updated**
    ```rust
    // Given `old` is a `ServerSetup` from `opaque-ke` v3.
    let old_serialized = old.serialize();

    type OldSeedLen = <<<OldCipherSuite as opaque_ke_3::CipherSuite>::OprfCs as voprf::CipherSuite>::Hash as OutputSizeUser>::OutputSize;
    type OldSkLen = <<OldCipherSuite as opaque_ke_3::CipherSuite>::KeGroup as opaque_ke_3::key_exchange::group::KeGroup>::SkLen;

    let (old_serialied_rest, old_fake_keypair_serialized): (
        GenericArray<u8, Sum<OldSeedLen, OldSkLen>>,
        _,
    ) = old_serialized.split();

    let old_fake_keypair =
        KeyPair::<<OldCipherSuite as opaque_ke_3::CipherSuite>::KeGroup>::from_private_key_slice(
            &old_fake_keypair_serialized,
        )
        .unwrap();
    let old_fake_pk_serialized = old_fake_keypair.public().serialize();

    let new_serialized = old_serialied_rest.concat(old_fake_pk_serialized);
    // Given `NewCipherSuite` is a `CipherSuite` implementation equivalent to `OldCipherSuite`.
    ServerSetup::<NewCipherSuite>::deserialize(&new_serialized).unwrap()
    ```
* Added remote OPRF seed support
* Replace remote private key trait with a state machine, facilitating async support.
* Serde de/serialization formats have been simplified
  * **Breaking: existing `ServerRegistration`s may need to be updated**
    ```rust
    // Given `old` is a `ServerRegistration` from `opaque-ke` v3.
    let old_serialized = old.serialize();
    // Given `NewCipherSuite` is a `CipherSuite` implementation equivalent to the old cipher suite.
    ServerRegistration::<NewCipherSuite>::deserialize(&old_serialized).unwrap()
    ```


## 3.0.0 (October 10, 2024)
* Synced implementation with draft-irtf-cfrg-opaque-16
  * **Breaking: protocol context string changed from `RFCXXXX` to `OPAQUEv1-`**
* Dropped unmaintained json crate in favor of serde_json
* Updated dependencies
* Increased MSRV to 1.74
* Adjusted curve25519 support logic
* Adjusted key generation logic to be in line with commit 727b9ac of
  https://github.com/cfrg/draft-irtf-cfrg-opaque
* Updated VOPRF to draft 19
  * **Breaking: backwards-incompatible changes introduced in OPRF protocol**
* Added P384 testing support
* Renaming of X25519 to Curve25519

## 2.0.0 (September 21, 2022)
* Synced implementation with draft-irtf-cfrg-opaque-10
* Changed argon2 salt length to recommended value (16 bytes)
* Fixed issue from 2.0.0-pre.2 not pinning voprf dependency correctly
* Split out VOPRF implementation into its own crate
* Added support for running the API without performing
  allocations
* Revamped the way the Group trait was used, so as to be more
  easily extendable to other groups
* Added support for p256 as the group and x25519 as the key exchange group
* Added common traits for each public-facing struct, including serde support

## 1.2.0 (October 7, 2021)

* Added explicit support for the thumbv6m-none-eabi target (no-std)

## 1.1.0 (August 18, 2021)

* Updated dependencies and bumped MSRV to 1.51
* Added no_std support

## 1.0.0 (July 19, 2021)

* Branched from v0.5.0
* Various security improvements: non-zero scalars, zeroizing on drop,
  constant-time operations, reflected value check, and adding an
  i2osp error condition

## 0.6.0 (June 30, 2021)

* Synced implementation with draft-irtf-cfrg-opaque-05, which changes
  the envelope structure and introduces a ServerSetup object to be
  maintained by the server
* Various security improvements: non-zero scalars, zeroizing on drop,
  constant-time operations
* Adding serde support behind a feature
* Supporting common traits (eb59676)
* Swapping out scrypt for argon2 (535b9b8) for the slow-hash feature
* Adding support for common traits on public structs
* Updated dependencies

## 0.5.1 (July 16, 2021)

* Various security improvements: non-zero scalars, zeroizing on drop,
  constant-time operations, reflected value check, and adding an
  i2osp error condition

## 0.5.0 (March 1, 2021)

* Removed dependency on generic-bytes-derive package

## 0.4.0 (February 26, 2021)

* Adherence to protocol format described in
  https://tools.ietf.org/html/draft-irtf-cfrg-opaque-03
* Renamed to_bytes() and try_from() to serialize() and deserialize() for
  top-level structs
* Conformed all message type parameters to be parameterized in the
  Ciphersuite object

## 0.3.1 (February 11, 2021)

* Re-exporting the rand library (and including it as a dependency instead of
  just rand_core)
* Exposing a convenience function for converting from byte array to Key type

## 0.3.0 (February 8, 2021)

* General API and documentation improvements, including the support of custom
  identifiers, optional result parameters, and the use of the export key
* Compliance with RFC 8017 on data serialization functions (I2OSP / OS2IP)
* Adherence to protocol format described in
  https://tools.ietf.org/html/draft-irtf-cfrg-opaque-02
* Added parameters for key exchange additional data
* Added simple_login and digital_locker examples

## 0.2.1 (October 22, 2020)

* Changed visibility of hash module to be public

## 0.2.0 (September 3, 2020)

* Added CipherSuite API for specifying underlying primitives
* Added support for specifying a slow password hashing function
* Collapsed SignalKeyPair to X25519KeyPair
* Updated the envelope implementation to match the suggested XOR-based
  construction in https://tools.ietf.org/html/draft-krawczyk-cfrg-opaque-06
* Included randomized tests for testing try_from crashes
* Implemented Elligator2 map instead of try-and-increment for hash-to-curve
* Added extensibility for supporting different key exchange protocols
* Added benchmarks for the OPRF & switchable dalek backend depending on platform

## 0.1.0 (June 5, 2020)

* Initial release
