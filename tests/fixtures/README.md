These fixtures contain public, deterministic test material generated with the
unmodified published releases. They allow compatibility testing without pulling
older crypto dependencies back into the test graph.

`opaque-ke-3.0.0.json` uses NIST P-256 for both OPRF and TripleDH, the identity
KSF, and one ChaCha20 RNG seeded with `[42; 32]`. Setup and registration run in
that order, using the password and client identifier in `tests/migration.rs`.

`opaque-ke-4.0.1.json` uses Ristretto255, TripleDH/SHA-512 and Argon2 0.5.3 with
default parameters. Separate ChaCha20 RNGs use seeds `[42; 32]` for setup,
`[43; 32]` for registration, `[44; 32]` for client login and `[45; 32]` for server
login. The password and identifiers are in `tests/compatibility.rs`. Both
generators use `rand_chacha` 0.3 and `rand_core` 0.6.
