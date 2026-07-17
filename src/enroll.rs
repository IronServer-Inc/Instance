//! POST /enroll  { apple_identity_jwt, storekit_jws } -> { session_token }
//!
//! Mirrors architecture.md § First Instance Connection:
//!   - Apple identity JWT (RS256) vs the pinned JWKS (apple_jwks.rs).
//!   - StoreKit JWS (ES256) with its x5c chain walked to a pinned Apple Root CA - G3, then the
//!     JWS verified with the leaf key (mirrors Orchestrator/_shared/{x509_chain,storekit_verify}.ts).
//!   - appAccountToken == uuidV5(namespace, sub).
//!   - manifest membership: { client_pubkey (from the mTLS session), sha256(sub||origTxId) }.
//!   - originalTransactionId dedup, cap DEVICE_CAP.
//!
//! Every credential failure collapses to 401; policy failures (appAccountToken / manifest) to
//! 403; the device cap to 429 -- matching implementation.md § Phase 9.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

use crate::apple_jwks::verify_apple_jwt;
use crate::state::{AppState, ClientPubkey, MemberEntry};
use crate::{b64url_nopad, hex_encode, random_32, uuid_eq, uuid_v5};

// SHA-256(DER) of Apple Root CA - G3. Mirrored from
// Orchestrator/_shared/x509_chain.ts (fetched + verified out-of-band there 2026-05-11).
pub const APPLE_ROOT_CA_G3_SHA256: [u8; 32] = [
    0x63, 0x34, 0x3a, 0xbf, 0xb8, 0x9a, 0x6a, 0x03, 0xeb, 0xb5, 0x7e, 0x9b, 0x3f, 0x5f, 0xa7, 0xbe, 0x7c, 0x4f,
    0x5c, 0x75, 0x6f, 0x30, 0x17, 0xb3, 0xa8, 0xc4, 0x88, 0xc3, 0x65, 0x3e, 0x91, 0x79,
];

#[derive(Deserialize)]
pub struct EnrollRequest {
    apple_identity_jwt: String,
    storekit_jws: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoreKitPayload {
    pub bundle_id: String,
    pub original_transaction_id: String,
    pub transaction_id: String,
    pub product_id: String,
    #[serde(default)]
    pub app_account_token: Option<String>,
}

fn err(code: StatusCode, msg: &str) -> Response {
    (code, Json(json!({ "error": msg }))).into_response()
}

pub async fn handler(
    State(state): State<AppState>,
    client: Option<Extension<ClientPubkey>>,
    Json(req): Json<EnrollRequest>,
) -> Response {
    // client_pubkey comes from the mTLS session (request extension). No cert -> no membership.
    let Some(Extension(ClientPubkey(client_pubkey))) = client else {
        return err(StatusCode::FORBIDDEN, "no client certificate");
    };

    let a = &state.anchors;

    let Ok(claims) = verify_apple_jwt(&req.apple_identity_jwt, &a.apple_jwt_keys, &a.apple_issuer, &a.apple_audience)
    else {
        return err(StatusCode::UNAUTHORIZED, "apple jwt invalid");
    };

    let Ok(tx) = verify_storekit_jws(&req.storekit_jws, &a.storekit_root_sha256, &a.storekit_bundle_id) else {
        return err(StatusCode::UNAUTHORIZED, "storekit jws invalid");
    };

    // appAccountToken must be the UUIDv5 derivation of the authenticated sub.
    let expected = uuid_v5(&a.appaccount_namespace, claims.sub.as_bytes());
    match tx.app_account_token.as_deref() {
        Some(got) if uuid_eq(&expected, got) => {}
        _ => return err(StatusCode::FORBIDDEN, "appAccountToken mismatch"),
    }

    // member_hash = sha256(sub || originalTransactionId); sub is discarded after this.
    let mut hasher = Sha256::new();
    hasher.update(claims.sub.as_bytes());
    hasher.update(tx.original_transaction_id.as_bytes());
    let member_hash: [u8; 32] = hasher.finalize().into();

    let pk_hex = hex_encode(&client_pubkey);
    let mh_hex = hex_encode(&member_hash);
    let in_manifest = state
        .manifest
        .members
        .iter()
        .any(|m| m.pubkey.eq_ignore_ascii_case(&pk_hex) && m.hash.eq_ignore_ascii_case(&mh_hex));
    if !in_manifest {
        return err(StatusCode::FORBIDDEN, "not in cohort manifest");
    }

    let session_token = b64url_nopad(&random_32());
    let entry = MemberEntry {
        client_pubkey,
        member_hash,
        session_token: session_token.clone(),
        original_tx_id: tx.original_transaction_id.clone(),
    };
    if !state.members.insert(entry) {
        return err(StatusCode::TOO_MANY_REQUESTS, "device cap reached");
    }

    Json(json!({ "session_token": session_token })).into_response()
}

/// Verify a StoreKit / App Store Server JWS: ES256, x5c chain (2..=5) pinned to `root_sha256`,
/// each link's signature checked, then the JWS verified with the leaf key. Returns the decoded
/// payload after asserting bundleId + required id fields. Any failure -> `Err(())`.
fn verify_storekit_jws(jws: &str, root_sha256: &[u8; 32], expected_bundle_id: &str) -> Result<StoreKitPayload, ()> {
    use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};

    let header = decode_header(jws).map_err(|_| ())?;
    if header.alg != Algorithm::ES256 {
        return Err(());
    }
    let x5c = header.x5c.ok_or(())?;
    if x5c.len() < 2 || x5c.len() > 5 {
        return Err(());
    }
    let ders: Vec<Vec<u8>> = x5c.iter().map(|s| crate::b64_decode_any(s).ok_or(())).collect::<Result<_, _>>()?;

    // Pin the root first -- cheapest check, fail fast before any signature work.
    if Sha256::digest(ders.last().unwrap()).as_slice() != root_sha256 {
        return Err(());
    }

    let parsed: Vec<X509Certificate> =
        ders.iter().map(|d| X509Certificate::from_der(d).map(|(_, c)| c).map_err(|_| ())).collect::<Result<_, _>>()?;

    // Verify cert[i] is signed by cert[i+1] (x509-parser auto-detects P-256/P-384/RSA).
    for i in 0..parsed.len() - 1 {
        parsed[i].verify_signature(Some(parsed[i + 1].public_key())).map_err(|_| ())?;
    }

    // from_ec_der wants the raw SEC1 point (0x04 || X || Y), not the SPKI wrapper.
    let leaf_key = DecodingKey::from_ec_der(&parsed[0].public_key().subject_public_key.data);
    let mut validation = Validation::new(Algorithm::ES256);
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    validation.validate_aud = false;
    let payload = decode::<StoreKitPayload>(jws, &leaf_key, &validation).map_err(|_| ())?.claims;

    if payload.bundle_id != expected_bundle_id
        || payload.original_transaction_id.is_empty()
        || payload.transaction_id.is_empty()
        || payload.product_id.is_empty()
    {
        return Err(());
    }
    Ok(payload)
}
