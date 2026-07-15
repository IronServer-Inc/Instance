//! End-to-end mTLS tests: a real TLS 1.3 client against the real server stack (rustls +
//! MtlsAcceptor + the router). These are the only tests that exercise the peer-cert capture
//! path, so they speak raw HTTP/1.1 over the TLS stream rather than mocking anything.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;

use common::*;
use iron_instance::build_router;
use iron_instance::manifest::Manifest;
use iron_instance::mtls::{client_point_from_cert, server_config, MtlsAcceptor};
use iron_instance::state::{AppState, BootContext, MemberStore, Pubkey};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// The instance leaf is self-signed; the real client pins it by SPKI hash via attestation
/// (Phase 7/8), which is out of scope here. For these tests any server cert is fine.
#[derive(Debug)]
struct AnyServerCert(Arc<CryptoProvider>);

impl ServerCertVerifier for AnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

type Identity = (CertificateDer<'static>, PrivateKeyDer<'static>);

/// A fresh self-signed P-256 client identity, plus its X9.63 public point.
fn client_identity() -> (Identity, Pubkey) {
    let kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let params = CertificateParams::new(vec!["IronServer Client".to_string()]).unwrap();
    let der = params.self_signed(&kp).unwrap().der().to_vec();
    let point = client_point_from_cert(&der).unwrap();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(kp.serialize_der()));
    ((CertificateDer::from(der), key), point)
}

fn client_config(identity: Option<Identity>) -> ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyServerCert(provider)));
    match identity {
        Some((cert, key)) => builder.with_client_auth_cert(vec![cert], key).unwrap(),
        None => builder.with_no_client_auth(),
    }
}

/// Boot the real server stack on an ephemeral port with the given cohort manifest.
async fn start_server(manifest: Manifest) -> SocketAddr {
    let kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let params = CertificateParams::new(vec!["ironserver-instance".to_string()]).unwrap();
    let cert_der = CertificateDer::from(params.self_signed(&kp).unwrap().der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(kp.serialize_der()));

    let manifest = Arc::new(manifest);
    let tls = server_config(manifest.clone(), cert_der, key_der).unwrap();

    let state = AppState {
        boot: Arc::new(BootContext { spki_sha256: [0u8; 32] }),
        members: MemberStore::default(),
        manifest,
        anchors: Arc::new(anchors([0u8; 32], *orch_signing_key().verifying_key())),
    };
    let app = build_router(state);

    // Bind first so the port is live before serve() spins up -- no sleep/race.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap(); // tokio refuses to register a blocking fd
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum_server::from_tcp(listener)
            .unwrap()
            .acceptor(MtlsAcceptor::new(tls))
            .serve(app.into_make_service())
            .await
            .unwrap();
    });
    addr
}

/// Speak raw HTTP/1.1 over the TLS stream. Errors surface here when the server rejects the
/// client cert (TLS 1.3 sends that alert after the client's handshake optimistically completes).
async fn https_post(addr: SocketAddr, config: ClientConfig, path: &str, body: &str) -> std::io::Result<String> {
    let connector = TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect(addr).await?;
    let mut tls = connector.connect(ServerName::try_from("localhost").unwrap(), tcp).await?;
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    tls.write_all(req.as_bytes()).await?;
    let mut buf = Vec::new();
    tls.read_to_end(&mut buf).await?;
    Ok(String::from_utf8_lossy(&buf).to_string())
}

#[tokio::test]
async fn manifest_member_handshakes_and_client_pubkey_reaches_handler() {
    let ((cert, key), point) = client_identity();
    let addr = start_server(manifest(&[(point, [0u8; 32])])).await;

    // Junk credentials on purpose: we only care *which* rejection we get. 401 "apple jwt
    // invalid" means enroll got past the client-cert check -- i.e. the ClientPubkey extension
    // was populated from the TLS peer cert. A 403 "no client certificate" would mean capture
    // silently failed.
    let body = r#"{"apple_identity_jwt":"junk","storekit_jws":"junk"}"#;
    let resp = https_post(addr, client_config(Some((cert, key))), "/enroll", body).await.unwrap();

    assert!(resp.contains("401"), "expected 401, got: {resp}");
    assert!(resp.contains("apple jwt invalid"), "client pubkey did not reach the handler: {resp}");
    assert!(!resp.contains("no client certificate"));
}

#[tokio::test]
async fn client_not_in_manifest_is_dropped_at_handshake() {
    let ((cert, key), _point) = client_identity();
    // Manifest holds a different device's point.
    let (_, other) = client_identity();
    let addr = start_server(manifest(&[(other, [0u8; 32])])).await;

    let body = r#"{"apple_identity_jwt":"junk","storekit_jws":"junk"}"#;
    let result = https_post(addr, client_config(Some((cert, key))), "/enroll", body).await;

    match result {
        Err(_) => {}
        Ok(resp) => assert!(!resp.contains("HTTP/1.1"), "non-member must not get an HTTP response: {resp}"),
    }
}

#[tokio::test]
async fn client_without_certificate_is_rejected() {
    let (_, point) = client_identity();
    let addr = start_server(manifest(&[(point, [0u8; 32])])).await;

    let body = r#"{"apple_identity_jwt":"junk","storekit_jws":"junk"}"#;
    let result = https_post(addr, client_config(None), "/enroll", body).await;

    match result {
        Err(_) => {}
        Ok(resp) => assert!(!resp.contains("HTTP/1.1"), "certless client must not get an HTTP response: {resp}"),
    }
}
