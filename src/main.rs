//! Instance bootstrap: generate the boot TLS keypair, self-sign a leaf wrapping its SPKI,
//! bring up the four endpoints on :443 over mutually-authenticated TLS 1.3. Client certs are
//! mandatory and gated on cohort-manifest membership (see mtls.rs).

use std::net::SocketAddr;
use std::sync::Arc;

use p256::ecdsa::VerifyingKey;
use rcgen::{CertificateParams, KeyPair, PublicKeyData, PKCS_ECDSA_P256_SHA256};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};

use iron_instance::apple_jwks::{load_apple_jwt_keys, APPLE_AUDIENCE, APPLE_ISSUER, SIGN_IN_WITH_APPLE_JWKS};
use iron_instance::build_router;
use iron_instance::enroll::APPLE_ROOT_CA_G3_SHA256;
use iron_instance::manifest::Manifest;
use iron_instance::mtls::{server_config, MtlsAcceptor};
use iron_instance::state::{Anchors, AppState, BootContext, MemberStore};

// UUIDv5 namespace for appAccountToken <-> sub. Mirrors iOS Constants.Identity and
// Orchestrator/_shared/uuid_v5.ts (dafb6e23-9c4d-5d27-aa05-3f6c2e9e7b14).
const APPACCOUNT_NAMESPACE: [u8; 16] =
    [0xda, 0xfb, 0x6e, 0x23, 0x9c, 0x4d, 0x5d, 0x27, 0xaa, 0x05, 0x3f, 0x6c, 0x2e, 0x9e, 0x7b, 0x14];

// Pinned Orchestrator management pubkey (raw 65-byte X9.63 P-256). Public by design: it is
// measured and published, and the private half lives only in Supabase secrets. The test build
// pins this same production key deliberately -- rotating it changes the measurement.
const ORCH_MANAGE_PUBKEY_SEC1: &[u8] = include_bytes!("../pinned/orchestrator_manage_pubkey.sec1");

#[tokio::main]
async fn main() {
    // Boot TLS keypair, generated in process memory (production: sealed VM memory). P-256 /
    // ecdsa-with-SHA256 so the iOS client can present a matching SecIdentity, and so both peers
    // share one curve family.
    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("boot keygen");
    let spki_der = key_pair.subject_public_key_info();
    let spki_sha256: [u8; 32] = Sha256::digest(&spki_der[..]).into();

    let params = CertificateParams::new(vec!["ironserver-instance".to_string()]).expect("cert params");
    let cert = params.self_signed(&key_pair).expect("self-sign leaf");
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    // Cohort manifest. The production image's iron-manifest unit resolves the launch
    // parameter (manifest_url + manifest_sha256), hash-verifies the bytes, and installs them
    // at IRON_MANIFEST_PATH before this service starts; dev points IRON_MANIFEST_PATH at a
    // local file. Unset -> empty manifest -> no client can complete the handshake (closed).
    let manifest = Arc::new(match std::env::var("IRON_MANIFEST_PATH").ok() {
        Some(path) => Manifest::from_bytes(&std::fs::read(&path).expect("manifest file")).expect("manifest parse"),
        None => Manifest::default(),
    });

    let anchors = Anchors {
        apple_jwt_keys: load_apple_jwt_keys(SIGN_IN_WITH_APPLE_JWKS),
        apple_issuer: APPLE_ISSUER.to_string(),
        apple_audience: APPLE_AUDIENCE.to_string(),
        storekit_bundle_id: APPLE_AUDIENCE.to_string(),
        storekit_root_sha256: APPLE_ROOT_CA_G3_SHA256,
        appaccount_namespace: APPACCOUNT_NAMESPACE,
        orch_manage_pubkey: VerifyingKey::from_sec1_bytes(ORCH_MANAGE_PUBKEY_SEC1).expect("pinned Orchestrator pubkey"),
    };

    let tls = server_config(manifest.clone(), cert_der, key_der).expect("tls config");

    let state = AppState {
        boot: Arc::new(BootContext { spki_sha256 }),
        members: MemberStore::default(),
        manifest,
        anchors: Arc::new(anchors),
    };
    let app = build_router(state);

    // Default :443. On macOS 443 is privileged, so dev runs unprivileged with IRON_INSTANCE_PORT.
    // Not a production door: the image never sets it, nothing can set env vars (no admin plane), and
    // the firewall admits only 443. Same goes for IRON_VLLM_URL / IRON_GPU_REPORT_CMD -- the image's
    // own systemd wiring, not attacker-reachable input.
    let port: u16 = std::env::var("IRON_INSTANCE_PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(443);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    // The SPKI hash is public (the client pins it; it is bound into attestation report_data).
    // No secret is printed here.
    println!("iron-instance: boot TLS SPKI SHA-256 = {}", to_hex(&spki_sha256));
    println!("iron-instance: listening on https://{addr} (mTLS: client cert required, manifest-gated)");

    axum_server::bind(addr)
        .acceptor(MtlsAcceptor::new(tls))
        .serve(app.into_make_service())
        .await
        .expect("serve");
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
