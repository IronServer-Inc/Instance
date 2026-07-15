//! mTLS: client-cert capture + cohort-manifest enforcement at the handshake.
//!
//! Both peers present a self-signed X.509 envelope carrying a P-256 SPKI. The X.509 wrapper is
//! a wire-format concession to Apple's TLS stack (architecture.md § First Instance Connection)
//! -- there is no CA and chain validation is meaningless here. Trust comes from two places:
//!
//!   1. The handshake's CertificateVerify proves the client holds the private key for the point
//!      in its leaf (rustls checks this for us via `verify_tls13_signature`).
//!   2. That point must appear in the cohort manifest, or we drop the connection.
//!
//! After the handshake the client's 65-byte X9.63 point is injected into every request on that
//! connection as a `ClientPubkey` extension, which is what /enroll binds the manifest entry to.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::http::Request;
use axum_server::accept::Accept;
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error as TlsError, ServerConfig, SignatureScheme};
use tokio::io::{AsyncRead, AsyncWrite};
use tower::Service;
use x509_parser::prelude::*;

use crate::manifest::Manifest;
use crate::state::{ClientPubkey, Pubkey};

/// Pull the uncompressed X9.63 P-256 point (0x04 || X || Y) out of a leaf certificate's SPKI.
/// Anything that is not exactly a 65-byte uncompressed point is rejected.
pub fn client_point_from_cert(der: &[u8]) -> Option<Pubkey> {
    let (_, cert) = X509Certificate::from_der(der).ok()?;
    let point = &cert.public_key().subject_public_key.data;
    if point.len() != 65 || point[0] != 0x04 {
        return None;
    }
    let mut out = [0u8; 65];
    out.copy_from_slice(point);
    Some(out)
}

/// Accepts any well-formed P-256 client leaf whose public point is in the cohort manifest.
#[derive(Debug)]
pub struct ManifestClientVerifier {
    manifest: Arc<Manifest>,
    provider: Arc<CryptoProvider>,
}

impl ManifestClientVerifier {
    pub fn new(manifest: Arc<Manifest>, provider: Arc<CryptoProvider>) -> Self {
        Self { manifest, provider }
    }
}

impl ClientCertVerifier for ManifestClientVerifier {
    // No CAs: we never ask the client to pick a cert by issuer.
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        let point = client_point_from_cert(end_entity)
            .ok_or_else(|| TlsError::General("client leaf is not a P-256 X9.63 key".into()))?;
        if !self.manifest.contains_pubkey(&point) {
            return Err(TlsError::General("client pubkey not in cohort manifest".into()));
        }
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// TLS 1.3 server config: our boot leaf, mandatory client auth, manifest-gated.
pub fn server_config(
    manifest: Arc<Manifest>,
    cert_der: CertificateDer<'static>,
    key_der: PrivateKeyDer<'static>,
) -> Result<ServerConfig, TlsError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(ManifestClientVerifier::new(manifest, provider.clone()));
    ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![cert_der], key_der)
}

/// Wraps axum-server's rustls acceptor: after the handshake, read the peer's leaf and attach its
/// public point to every request on that connection.
#[derive(Clone)]
pub struct MtlsAcceptor {
    inner: RustlsAcceptor,
}

impl MtlsAcceptor {
    pub fn new(config: ServerConfig) -> Self {
        Self { inner: RustlsAcceptor::new(RustlsConfig::from_config(Arc::new(config))) }
    }
}

impl<I, S> Accept<I, S> for MtlsAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = <RustlsAcceptor as Accept<I, S>>::Stream;
    type Service = AddClientPubkey<S>;
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let inner = self.inner.clone();
        Box::pin(async move {
            let (tls, service) = inner.accept(stream, service).await?;
            // Client auth is mandatory and the verifier already vetted this cert, so a peer cert
            // is present here; treat its absence as "no pubkey" and let the handlers 403.
            let pubkey = tls
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|chain| chain.first())
                .and_then(|leaf| client_point_from_cert(leaf));
            Ok((tls, AddClientPubkey { inner: service, pubkey }))
        })
    }
}

#[derive(Clone)]
pub struct AddClientPubkey<S> {
    inner: S,
    pubkey: Option<Pubkey>,
}

impl<S, B> Service<Request<B>> for AddClientPubkey<S>
where
    S: Service<Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        if let Some(pk) = self.pubkey {
            req.extensions_mut().insert(ClientPubkey(pk));
        }
        self.inner.call(req)
    }
}
