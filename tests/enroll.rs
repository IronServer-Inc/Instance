//! Phase 9 enroll tests (implementation.md § Phase 9). Synthetic Apple JWT + StoreKit chain;
//! see tests/common/mod.rs.

mod common;

use axum::http::StatusCode;
use common::*;
use iron_instance::state::{MemberStore, DEVICE_CAP};

const SUB: &str = "apple-sub-000111";
const ORIG_TX: &str = "2000000055500001";

#[tokio::test]
async fn valid_jwt_jws_manifest_issues_bearer() {
    let chain = make_chain();
    let orch = orch_signing_key();
    let pk = client_pk(1);
    let manifest = manifest(&[(pk, member_hash(SUB, ORIG_TX))]);
    let app = app(anchors(chain.root_sha256, *orch.verifying_key()), manifest, MemberStore::default());

    let jwt = make_apple_jwt(SUB);
    let jws = make_storekit_jws(&chain, ORIG_TX, &app_account_token(SUB));
    let (status, body) = call(app, enroll_request(&jwt, &jws, Some(pk))).await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(body["session_token"].as_str().unwrap().len() >= 40);
}

#[tokio::test]
async fn wrong_jwt_signature_is_401() {
    let chain = make_chain();
    let orch = orch_signing_key();
    let pk = client_pk(1);
    let manifest = manifest(&[(pk, member_hash(SUB, ORIG_TX))]);
    let app = app(anchors(chain.root_sha256, *orch.verifying_key()), manifest, MemberStore::default());

    let jwt = corrupt_jwt(&make_apple_jwt(SUB));
    let jws = make_storekit_jws(&chain, ORIG_TX, &app_account_token(SUB));
    let (status, _) = call(app, enroll_request(&jwt, &jws, Some(pk))).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn appaccounttoken_mismatch_is_403() {
    let chain = make_chain();
    let orch = orch_signing_key();
    let pk = client_pk(1);
    let manifest = manifest(&[(pk, member_hash(SUB, ORIG_TX))]);
    let app = app(anchors(chain.root_sha256, *orch.verifying_key()), manifest, MemberStore::default());

    let jwt = make_apple_jwt(SUB);
    // appAccountToken derived from a different sub -> mismatch against jwt.sub.
    let jws = make_storekit_jws(&chain, ORIG_TX, &app_account_token("someone-else"));
    let (status, _) = call(app, enroll_request(&jwt, &jws, Some(pk))).await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn manifest_miss_is_403() {
    let chain = make_chain();
    let orch = orch_signing_key();
    // Manifest holds a different device's pubkey; this client is not a member.
    let manifest = manifest(&[(client_pk(9), member_hash(SUB, ORIG_TX))]);
    let app = app(anchors(chain.root_sha256, *orch.verifying_key()), manifest, MemberStore::default());

    let jwt = make_apple_jwt(SUB);
    let jws = make_storekit_jws(&chain, ORIG_TX, &app_account_token(SUB));
    let (status, _) = call(app, enroll_request(&jwt, &jws, Some(client_pk(1)))).await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

// A user's devices share one keypair, so repeat enrolls arrive on the *same* pubkey and each is
// a real device asking for its own bearer. This replaces a test that drove four distinct pubkeys
// at one member_hash and expected a 429: that shape is unreachable, because freeze_manifest emits
// exactly one pubkey per user, so a second pubkey is a second identity and never shares a hash.
#[tokio::test]
async fn each_device_on_one_identity_gets_its_own_bearer() {
    let chain = make_chain();
    let orch = orch_signing_key();
    let pk = client_pk(1);
    let manifest = manifest(&[(pk, member_hash(SUB, ORIG_TX))]);
    let members = MemberStore::default();
    let app = app(
        anchors(chain.root_sha256, *orch.verifying_key()),
        manifest,
        members.clone(),
    );

    let jwt = make_apple_jwt(SUB);
    let jws = make_storekit_jws(&chain, ORIG_TX, &app_account_token(SUB));

    let mut tokens = Vec::new();
    for _ in 0..2 {
        let (status, body) = call(app.clone(), enroll_request(&jwt, &jws, Some(pk))).await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        tokens.push(body["session_token"].as_str().unwrap().to_string());
    }

    assert_ne!(tokens[0], tokens[1], "each enroll mints a distinct bearer");
    // The regression this guards: the first device must still be able to chat.
    assert!(members.contains_token(&tokens[0]), "first device was logged out");
    assert!(members.contains_token(&tokens[1]));
}

#[tokio::test]
async fn bearers_past_the_cap_evict_the_oldest_and_still_admit() {
    let chain = make_chain();
    let orch = orch_signing_key();
    let pk = client_pk(1);
    let manifest = manifest(&[(pk, member_hash(SUB, ORIG_TX))]);
    let members = MemberStore::default();
    let app = app(
        anchors(chain.root_sha256, *orch.verifying_key()),
        manifest,
        members.clone(),
    );

    let jwt = make_apple_jwt(SUB);
    let jws = make_storekit_jws(&chain, ORIG_TX, &app_account_token(SUB));

    let mut tokens = Vec::new();
    for _ in 0..(DEVICE_CAP + 1) {
        let (status, body) = call(app.clone(), enroll_request(&jwt, &jws, Some(pk))).await;
        assert_eq!(status, StatusCode::OK, "enroll must never be refused: body: {body}");
        tokens.push(body["session_token"].as_str().unwrap().to_string());
    }

    assert_eq!(members.session_count(&pk), DEVICE_CAP);
    assert!(!members.contains_token(&tokens[0]), "oldest bearer must be evicted");
    assert!(members.contains_token(tokens.last().unwrap()));
}

// Finding 4.1: the x5c walk must enforce X.509 path constraints, not just link signatures. A
// chain whose "intermediate" is signed correctly but is CA:FALSE (an end-entity presented as an
// issuer) must be rejected. Without the basicConstraints check this returns 200.
#[tokio::test]
async fn non_ca_intermediate_is_rejected() {
    let chain = make_chain_non_ca_intermediate();
    let orch = orch_signing_key();
    let pk = client_pk(1);
    let manifest = manifest(&[(pk, member_hash(SUB, ORIG_TX))]);
    let app = app(anchors(chain.root_sha256, *orch.verifying_key()), manifest, MemberStore::default());

    let jwt = make_apple_jwt(SUB);
    let jws = make_storekit_jws(&chain, ORIG_TX, &app_account_token(SUB));
    let (status, _) = call(app, enroll_request(&jwt, &jws, Some(pk))).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "a CA:FALSE intermediate must not be accepted as an issuer");
}

// Finding 4.1: every cert must be inside its validity window. An intermediate whose notAfter is in
// the past must be rejected even though its signature still verifies.
#[tokio::test]
async fn expired_intermediate_is_rejected() {
    let chain = make_chain_expired_intermediate();
    let orch = orch_signing_key();
    let pk = client_pk(1);
    let manifest = manifest(&[(pk, member_hash(SUB, ORIG_TX))]);
    let app = app(anchors(chain.root_sha256, *orch.verifying_key()), manifest, MemberStore::default());

    let jwt = make_apple_jwt(SUB);
    let jws = make_storekit_jws(&chain, ORIG_TX, &app_account_token(SUB));
    let (status, _) = call(app, enroll_request(&jwt, &jws, Some(pk))).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "an expired intermediate must not be accepted");
}
