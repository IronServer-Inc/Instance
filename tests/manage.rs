//! Phase 9 manage tests (implementation.md § Phase 9).

mod common;

use axum::http::StatusCode;
use common::*;
use iron_instance::state::{MemberEntry, MemberStore};

fn seed_member(members: &MemberStore, token: &str, member_hash: [u8; 32]) {
    members.insert(MemberEntry {
        client_pubkey: client_pk(1),
        member_hash,
        session_token: token.to_string(),
        original_tx_id: "tx-manage".to_string(),
    });
}

#[tokio::test]
async fn properly_signed_revoke_removes_member_and_bearer() {
    let orch = orch_signing_key();
    let members = MemberStore::default();
    let mh = [0x11u8; 32];
    let token = "bearer-to-be-revoked";
    seed_member(&members, token, mh);
    assert!(members.contains_token(token));

    let app = app(anchors([0u8; 32], *orch.verifying_key()), manifest(&[]), members.clone());
    let (payload, sig) = make_manage_revoke(&orch, &hex(&mh), "nonce-1");
    let (status, body) = call(app, manage_request(&payload, &sig)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["revoked"], true);
    assert!(!members.contains_token(token), "bearer must be invalidated");
}

#[tokio::test]
async fn bad_signature_is_401() {
    let orch = orch_signing_key();
    let members = MemberStore::default();
    seed_member(&members, "bearer-x", [0x22u8; 32]);

    let app = app(anchors([0u8; 32], *orch.verifying_key()), manifest(&[]), members.clone());
    // Sign with a different key than the one pinned in anchors.
    let attacker = iron_instance_test_wrong_key();
    let (payload, sig) = make_manage_revoke(&attacker, &hex(&[0x22u8; 32]), "nonce-9");
    let (status, _) = call(app, manage_request(&payload, &sig)).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(members.contains_token("bearer-x"), "member must survive a bad-signature manage");
}

#[tokio::test]
async fn replayed_nonce_is_409() {
    let orch = orch_signing_key();
    let members = MemberStore::default();
    seed_member(&members, "bearer-y", [0x33u8; 32]);

    let app = app(anchors([0u8; 32], *orch.verifying_key()), manifest(&[]), members.clone());
    let (payload, sig) = make_manage_revoke(&orch, &hex(&[0x33u8; 32]), "nonce-replay");

    let (first, _) = call(app.clone(), manage_request(&payload, &sig)).await;
    assert_eq!(first, StatusCode::OK);

    let (second, _) = call(app.clone(), manage_request(&payload, &sig)).await;
    assert_eq!(second, StatusCode::CONFLICT);
}

// A P-256 key distinct from the pinned Orchestrator key.
fn iron_instance_test_wrong_key() -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap()
}
