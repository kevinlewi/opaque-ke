// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

#![cfg(all(feature = "argon2", feature = "ristretto255"))]

use opaque_ke::errors::ProtocolError;
use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, CredentialFinalization,
    CredentialRequest, Identifiers, ServerLogin, ServerLoginParameters, ServerRegistration,
    ServerSetup, TripleDh,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

struct Suite;

impl CipherSuite for Suite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = argon2::Argon2<'static>;
}

struct Fixture {
    setup: String,
    record: String,
    credential_request: String,
    credential_response: String,
    client_login: String,
    server_login: String,
    finalization: String,
    session_key: String,
}

/// Contains only public test material generated with opaque-ke 4.0.1.
fn fixture() -> Fixture {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/opaque-ke-4.0.1.json")).unwrap();
    let field = |name: &str| fixture[name].as_str().unwrap().to_owned();
    Fixture {
        setup: field("setup"),
        record: field("record"),
        credential_request: field("credential_request"),
        credential_response: field("credential_response"),
        client_login: field("client_login"),
        server_login: field("server_login"),
        finalization: field("finalization"),
        session_key: field("session_key"),
    }
}

fn identifiers() -> Identifiers<'static> {
    Identifiers {
        client: Some(b"compatibility@example.com"),
        server: Some(b"api.permesi.dev"),
    }
}

#[test]
fn setup_seed_derivation_matches_4_0_1() {
    let mut rng = ChaCha20Rng::from_seed([42; 32]);
    let setup = ServerSetup::<Suite>::new(&mut rng);
    assert_eq!(hex::encode(setup.serialize()), fixture().setup);
}

/// Old registration and pending states must interoperate with the upgraded
/// client/server.
#[test]
fn login_accepts_4_0_1_records_and_transcripts() {
    let fixture = fixture();
    let setup = ServerSetup::<Suite>::deserialize(&hex::decode(&fixture.setup).unwrap()).unwrap();
    let record =
        ServerRegistration::<Suite>::deserialize(&hex::decode(&fixture.record).unwrap()).unwrap();
    assert_eq!(hex::encode(record.serialize()), fixture.record);
    let request =
        CredentialRequest::deserialize(&hex::decode(&fixture.credential_request).unwrap()).unwrap();
    let mut server_rng = ChaCha20Rng::from_seed([45; 32]);
    let server = ServerLogin::start(
        &mut server_rng,
        &setup,
        Some(record),
        request,
        b"compatibility@example.com",
        ServerLoginParameters {
            context: None,
            identifiers: identifiers(),
        },
    )
    .unwrap();
    assert_eq!(
        hex::encode(server.message.serialize()),
        fixture.credential_response
    );
    assert_eq!(hex::encode(server.state.serialize()), fixture.server_login);

    let legacy_client =
        ClientLogin::<Suite>::deserialize(&hex::decode(&fixture.client_login).unwrap()).unwrap();
    let ksf = argon2::Argon2::default();
    let mut client_rng = ChaCha20Rng::from_seed([44; 32]);
    let client = legacy_client
        .finish(
            &mut client_rng,
            b"public compatibility fixture password",
            server.message,
            ClientLoginFinishParameters::new(None, identifiers(), Some(&ksf)),
        )
        .unwrap();
    assert_eq!(
        hex::encode(client.message.serialize()),
        fixture.finalization
    );

    let legacy_server =
        ServerLogin::<Suite>::deserialize(&hex::decode(&fixture.server_login).unwrap()).unwrap();
    let legacy_server = legacy_server
        .finish(client.message, ServerLoginParameters::default())
        .unwrap();
    let server = server
        .state
        .finish(
            CredentialFinalization::deserialize(&hex::decode(&fixture.finalization).unwrap())
                .unwrap(),
            ServerLoginParameters::default(),
        )
        .unwrap();
    assert_eq!(hex::encode(client.session_key), fixture.session_key);
    assert_eq!(hex::encode(server.session_key), fixture.session_key);
    assert_eq!(hex::encode(legacy_server.session_key), fixture.session_key);
}

#[test]
fn login_rejects_modified_4_0_1_proof() {
    let fixture = fixture();
    let server =
        ServerLogin::<Suite>::deserialize(&hex::decode(&fixture.server_login).unwrap()).unwrap();
    let mut proof = hex::decode(&fixture.finalization).unwrap();
    proof[0] ^= 1;
    let result = server.finish(
        CredentialFinalization::deserialize(&proof).unwrap(),
        ServerLoginParameters::default(),
    );
    assert!(matches!(result, Err(ProtocolError::InvalidLoginError)));
}
