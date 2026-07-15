//! Phase 9 enroll tests (implementation.md § Phase 9). Synthetic Apple JWT + StoreKit chain;
//! see tests/common/mod.rs.

mod common;

use axum::http::StatusCode;
use common::*;
use iron_instance::state::MemberStore;

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

#[tokio::test]
async fn fourth_device_for_same_transaction_is_429() {
    let chain = make_chain();
    let orch = orch_signing_key();
    let mh = member_hash(SUB, ORIG_TX);
    let pks = [client_pk(1), client_pk(2), client_pk(3), client_pk(4)];
    let manifest = manifest(&pks.iter().map(|p| (*p, mh)).collect::<Vec<_>>());
    let app = app(anchors(chain.root_sha256, *orch.verifying_key()), manifest, MemberStore::default());

    let jwt = make_apple_jwt(SUB);
    let jws = make_storekit_jws(&chain, ORIG_TX, &app_account_token(SUB));

    // Same originalTransactionId, four distinct devices: 3 admitted, 4th over the cap.
    for pk in &pks[..3] {
        let (status, _) = call(app.clone(), enroll_request(&jwt, &jws, Some(*pk))).await;
        assert_eq!(status, StatusCode::OK);
    }
    let (status, _) = call(app.clone(), enroll_request(&jwt, &jws, Some(pks[3]))).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}
