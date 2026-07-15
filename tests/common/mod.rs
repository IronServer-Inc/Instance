//! Shared test harness for the Phase 9 suite. Everything here is synthetic and generated at
//! test time (same approach as the Phase 7 attestation tests): a throwaway RSA key + JWKS for
//! the Apple JWT, an rcgen-built P-256 cert chain for the StoreKit x5c, and a fixed-scalar
//! P-256 key for the Orchestrator. No real Apple/Orchestrator secret is involved.
//!
//! Cross-checks by construction: appAccountToken is computed with the independent `uuid` crate
//! (vs the crate's own hand-rolled uuid_v5) and x5c is encoded with the `base64` crate (vs the
//! crate's own b64_decode_any) -- if either hand-rolled helper drifted, enroll would reject
//! these fixtures and the tests would fail.

#![allow(dead_code)] // helpers are shared across three test binaries; not all used in each

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use base64::Engine;
use http_body_util::BodyExt;
use iron_instance::apple_jwks::{APPLE_AUDIENCE, APPLE_ISSUER};
use iron_instance::build_router;
use iron_instance::manifest::{Manifest, ManifestMember};
use iron_instance::state::{Anchors, AppState, BootContext, ClientPubkey, MemberStore, Pubkey};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{SigningKey, VerifyingKey};
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, PKCS_ECDSA_P256_SHA256};
use serde_json::json;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

pub const APPACCOUNT_NAMESPACE_STR: &str = "dafb6e23-9c4d-5d27-aa05-3f6c2e9e7b14";
pub const APPACCOUNT_NAMESPACE: [u8; 16] =
    [0xda, 0xfb, 0x6e, 0x23, 0x9c, 0x4d, 0x5d, 0x27, 0xaa, 0x05, 0x3f, 0x6c, 0x2e, 0x9e, 0x7b, 0x14];
pub const SLOT_PRODUCT_ID: &str = "com.rayeeev.IronServer.slot.v1";

pub const RSA_TEST_KID: &str = "test-apple-kid";
pub const RSA_TEST_N: &str = "sE8GPh_A8QJqUscf48hv_VTIPYu8e9LvydeZUhyGAotjRN-iWSmxvqvvQDAmFtYYxlvTJ1iAy1tmY6QU-E5V2WGpiTjLPNpO6HQIqSaCB1v8pvtm6t2jf0cwNSZfN3HePiPDTGQDbiHtdSRzE-sI1DCh0ItJwuf2MTN2bnaqRJOYiJ24jzo1sur6Qrw1yGvS3KGNS1GcBChVgsCTNHC2R3BmLzJAmIfEFBQeNZLUU-4wzT-XiLCVxNFjYMIB1YWA6KLvHulbFVdZm1dYApqSp4eoCTndD5O5hLMQcmF8jgQD0SyL3eBHiOZBEmP5tKH_SaTKGo3rv5uN0UVypJoDxw";

// Throwaway RSA test signing key (matches RSA_TEST_N). Generated once with openssl for the
// Apple-JWT test path; never a production secret.
pub const RSA_TEST_PK8_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCwTwY+H8DxAmpS
xx/jyG/9VMg9i7x70u/J15lSHIYCi2NE36JZKbG+q+9AMCYW1hjGW9MnWIDLW2Zj
pBT4TlXZYamJOMs82k7odAipJoIHW/ym+2bq3aN/RzA1Jl83cd4+I8NMZANuIe11
JHMT6wjUMKHQi0nC5/YxM3ZudqpEk5iInbiPOjWy6vpCvDXIa9LcoY1LUZwEKFWC
wJM0cLZHcGYvMkCYh8QUFB41ktRT7jDNP5eIsJXE0WNgwgHVhYDoou8e6VsVV1mb
V1gCmpKnh6gJOd0Pk7mEsxByYXyOBAPRLIvd4EeI5kESY/m0of9JpMoajeu/m43R
RXKkmgPHAgMBAAECggEAKxtPK+5IlsSf6VhNODygAQDzKnUZYu76eM+xaW2W6FVb
MpI5F/LFRhi0mO2MyoWTLiByWordhpr0yETsaZ+BhvJFaMsNifXYWCZSncTQAuuf
NNZ/3cnN+UcXBs+4dQ5up6PH0swbOJir/bmpN0P+dx7i2WHM6Y4cWAA8oxp5W+WP
Rjm5UicDZa+2HXiI+3+Aw3+lT8xJUIi29wczqpQ+kgX1wluyzLeMXbwRzjM6wUWd
p1p6SAet7zKLhLjaZ22UdmjLaRJOUhdUnyGnU870Qpfeke3v2zTNR+7ExPls1Y2h
2fCUSN1t/6LA/GbBs9YsyCKTjthVtvJQem91XghUEQKBgQD3v/ST4raCpg08Dk0i
BD09wUJYmyLm4RcgELS1qO5nyq5qzhnnD0tFLgjc78QZocyciLyJdIFOajA9GHt2
MybHcEsFZUGii2v7wMie/kNKqKfew2h+om3qPDX1Dbcsrh4BvFsKFmGWhB+nB8g6
+gutnHUOBdAHmlir53MYwRtpFwKBgQC2LgozMMdiGhnbnV2JJTlCMlj8aWmu4pHJ
tjtFzac98Hms9hvi0uP7/5NTk9YcdMqUhAhUP2beoTrpiQfPwv6ONK/JbDzGkVqj
yJyI++7LKYV+Aq8ww1zPIrgpOZr8T0eHyayCe67Mi5DWt8Qj2dC2HbQW1kRppBcs
ACRUcuOI0QKBgDiRh9LMjUe/in4P9eSyexlCq1d39Lwq4RDdP6XK8MSaLsEMVjW/
9DvTiwqHZItFumZzgjkQdQXmkSUiFe6jN1OKfFa7DAWFOB6/og9LlynQ4KOoko93
nwlAvkE55H07NHbI/zCKc7XebSvCRyHQPiJh+wg8o4dY4q49prYcQZn5AoGAepBw
5k2r5jE/MkQl2I3FfuaWfYKBylm90WIbcHPST1aI1bdhvXE6VqB0QqdURiLA47gM
Tnm1QJRiKRm6uqkqTwvdM/rwzHqf606dGX+9AMu3drZhnMHin6xxD7MktRi1PAKP
X93MFOrUj9BkUeZJhyxmq3KN5jCyMjUKPBJrR/ECgYBFWbcjtsVhII8lzVOCVtL0
t/HVzjDuYYD29AGc6twNTbcAmWA0TNGirXNoNLB8+qACN1Ej4oQAUTYuPrm3pTn4
Cjy8RtDSk+43d3g50Dic3E56MOpfBSSVGfJp0FnWqzpmKZmjW3LRXFS9Qztzb6T7
zRa2rhLQvDNhNogBKA6Hfg==
-----END PRIVATE KEY-----
";

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn client_pk(seed: u8) -> Pubkey {
    let mut p = [seed; 65];
    p[0] = 0x04;
    p
}

pub fn member_hash(sub: &str, orig_tx: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(sub.as_bytes());
    h.update(orig_tx.as_bytes());
    h.finalize().into()
}

pub fn apple_jwt_keys() -> HashMap<String, DecodingKey> {
    let mut m = HashMap::new();
    m.insert(RSA_TEST_KID.to_string(), DecodingKey::from_rsa_components(RSA_TEST_N, "AQAB").unwrap());
    m
}

#[derive(serde::Serialize)]
struct AppleClaims {
    iss: String,
    aud: String,
    sub: String,
    exp: u64,
    iat: u64,
}

/// A valid Apple identity JWT for `sub`, signed by the throwaway RSA key.
pub fn make_apple_jwt(sub: &str) -> String {
    let now = now_secs();
    let claims = AppleClaims { iss: APPLE_ISSUER.into(), aud: APPLE_AUDIENCE.into(), sub: sub.into(), exp: now + 3600, iat: now };
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(RSA_TEST_KID.into());
    let key = EncodingKey::from_rsa_pem(RSA_TEST_PK8_PEM.as_bytes()).unwrap();
    jsonwebtoken::encode(&header, &claims, &key).unwrap()
}

/// A valid JWT with its signature corrupted (last char flipped) -> must fail verification.
pub fn corrupt_jwt(jwt: &str) -> String {
    let mut s = jwt.to_string();
    let last = s.pop().unwrap();
    s.push(if last == 'A' { 'B' } else { 'A' });
    s
}

/// appAccountToken == UUIDv5(namespace, sub), computed with the independent `uuid` crate.
pub fn app_account_token(sub: &str) -> String {
    let ns = uuid::Uuid::parse_str(APPACCOUNT_NAMESPACE_STR).unwrap();
    uuid::Uuid::new_v5(&ns, sub.as_bytes()).to_string()
}

pub struct Chain {
    pub root_sha256: [u8; 32],
    pub x5c: Vec<String>, // [leaf, intermediate, root] as standard base64 DER
    pub leaf_key_pem: String,
}

/// Synthetic StoreKit chain: root (P-256 CA) -> intermediate (P-256 CA) -> leaf. The leaf key
/// signs the JWS; the root's SHA-256 becomes the pinned anchor.
pub fn make_chain() -> Chain {
    let b64 = base64::engine::general_purpose::STANDARD;

    let root_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut root_params = CertificateParams::new(vec!["Synthetic Apple Root".to_string()]).unwrap();
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let root_der = root_params.self_signed(&root_key).unwrap().der().to_vec();
    let root_issuer = Issuer::new(root_params, root_key);

    let int_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut int_params = CertificateParams::new(vec!["Synthetic Apple WWDR".to_string()]).unwrap();
    int_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let int_der = int_params.signed_by(&int_key, &root_issuer).unwrap().der().to_vec();
    let int_issuer = Issuer::new(int_params, int_key);

    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let leaf_params = CertificateParams::new(vec!["Synthetic Apple Leaf".to_string()]).unwrap();
    let leaf_der = leaf_params.signed_by(&leaf_key, &int_issuer).unwrap().der().to_vec();

    Chain {
        root_sha256: Sha256::digest(&root_der).into(),
        x5c: vec![b64.encode(&leaf_der), b64.encode(&int_der), b64.encode(&root_der)],
        leaf_key_pem: leaf_key.serialize_pem(),
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SkPayload {
    bundle_id: String,
    original_transaction_id: String,
    transaction_id: String,
    product_id: String,
    app_account_token: String,
}

/// A StoreKit JWS signed by `chain`'s leaf, carrying the x5c chain and the given fields.
pub fn make_storekit_jws(chain: &Chain, orig_tx: &str, app_account_token: &str) -> String {
    let payload = SkPayload {
        bundle_id: APPLE_AUDIENCE.into(),
        original_transaction_id: orig_tx.into(),
        transaction_id: format!("txn-{orig_tx}"),
        product_id: SLOT_PRODUCT_ID.into(),
        app_account_token: app_account_token.into(),
    };
    let mut header = Header::new(Algorithm::ES256);
    header.x5c = Some(chain.x5c.clone());
    let key = EncodingKey::from_ec_pem(chain.leaf_key_pem.as_bytes()).unwrap();
    jsonwebtoken::encode(&header, &payload, &key).unwrap()
}

/// Fixed-scalar Orchestrator management key (deterministic; no RNG needed in tests).
pub fn orch_signing_key() -> SigningKey {
    SigningKey::from_slice(&[7u8; 32]).unwrap()
}

/// A signed /manage revoke envelope: (payload_b64url, signature_b64url).
pub fn make_manage_revoke(signing: &SigningKey, member_hash_hex: &str, nonce: &str) -> (String, String) {
    let action = json!({ "action": "revoke", "member_hash": member_hash_hex, "nonce": nonce }).to_string();
    let sig: p256::ecdsa::Signature = signing.sign(action.as_bytes());
    let b64u = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    (b64u.encode(action.as_bytes()), b64u.encode(sig.to_bytes()))
}

/// Anchors wired for tests: real Apple issuer/aud/namespace, but the synthetic StoreKit root
/// hash and Orchestrator pubkey from the given fixtures.
pub fn anchors(storekit_root_sha256: [u8; 32], orch_pub: VerifyingKey) -> Anchors {
    Anchors {
        apple_jwt_keys: apple_jwt_keys(),
        apple_issuer: APPLE_ISSUER.into(),
        apple_audience: APPLE_AUDIENCE.into(),
        storekit_bundle_id: APPLE_AUDIENCE.into(),
        storekit_root_sha256,
        appaccount_namespace: APPACCOUNT_NAMESPACE,
        orch_manage_pubkey: orch_pub,
    }
}

pub fn manifest(entries: &[(Pubkey, [u8; 32])]) -> Manifest {
    Manifest {
        cohort_id: "c-test".into(),
        members: entries.iter().map(|(pk, h)| ManifestMember { pubkey: hex(pk), hash: hex(h) }).collect(),
    }
}

pub fn app(anchors: Anchors, manifest: Manifest, members: MemberStore) -> Router {
    let state = AppState {
        boot: Arc::new(BootContext { spki_sha256: [0u8; 32] }),
        members,
        manifest: Arc::new(manifest),
        anchors: Arc::new(anchors),
    };
    build_router(state)
}

pub fn enroll_request(jwt: &str, jws: &str, client_pubkey: Option<Pubkey>) -> Request<Body> {
    let body = json!({ "apple_identity_jwt": jwt, "storekit_jws": jws }).to_string();
    let mut builder = Request::builder().method("POST").uri("/enroll").header("content-type", "application/json");
    if let Some(pk) = client_pubkey {
        builder = builder.extension(ClientPubkey(pk));
    }
    builder.body(Body::from(body)).unwrap()
}

pub fn manage_request(payload_b64: &str, sig_b64: &str) -> Request<Body> {
    let body = json!({ "payload": payload_b64, "signature": sig_b64 }).to_string();
    Request::builder()
        .method("POST")
        .uri("/manage")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap()
}

/// Drive one request through the router (no TLS) and return (status, JSON body).
pub async fn call(app: Router, req: Request<Body>) -> (StatusCode, serde_json::Value) {
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, value)
}
