//! GET /attestation?nonce=<64 hex chars>
//!
//! Real hardware attestation. Emits the version-2 envelope the iOS AttestationVerifier parses:
//! { version, cpu_vendor, cpu_report, cpu_chain, gpu_reports[], gpu_chains[][] }, reports
//! base64, chains leaf-first base64-DER.
//!
//! ## The two bindings
//!
//! **CPU (Intel TDX).** REPORTDATA is 64 bytes and entirely caller-supplied, so it carries the
//! binding directly: `report_data = nonce(32) || SHA-256(boot TLS SPKI)(32)`. Fetched through
//! the kernel's configfs-tsm ABI (Linux 6.7+, CONFIG_TSM_REPORTS): write the 64 bytes to
//! `inblob`, read the quote from `outblob`. No vendor SDK, no ioctl. One TEE, N GPUs inside it.
//!
//! **GPU (NVIDIA CC).** The only caller-controlled input is the 32-byte SPDM nonce. OpaqueData
//! is driver/firmware metadata emitted by the GPU -- the guest cannot set it (see
//! https://arxiv.org/html/2507.02770v1). The SPKI is therefore bound *through the nonce*, and
//! because the shipping model is served tensor-parallel across every GPU on the board (each
//! holding a shard of the KV cache -- the user's plaintext), we attest ALL of them, one report
//! per GPU, each bound to its own index:
//!
//! ```text
//! gpu_nonce_i = SHA-256( nonce || SHA-256(SPKI) || u8(i) )
//! ```
//!
//! The index domain-separates the slots so a report cannot be lifted from one into another.
//! What it does NOT prove is that N *distinct* GPUs answered (one CC-mode GPU can sign N
//! challenges); the client enforces that from the N reports' device certs, and re-checks CC
//! mode from each signed report. This service's job is only to assemble a faithful envelope and
//! to fail closed (via the helper below) if any GPU cannot produce a CC-mode report.

use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::state::AppState;
use crate::{b64_decode_any, hex_decode, hex_encode};

/// configfs-tsm report interface (Linux >= 6.7, CONFIG_TSM_REPORTS).
const TSM_REPORT_ROOT: &str = "/sys/kernel/config/tsm/report";

/// Wrapper shipped in the image that calls NVIDIA's attestation tooling. Given one derived
/// nonce per GPU (via repeated `--nonce-hex`, in index order), it attests every GPU on the
/// board and prints `{"gpus":[{"report":"<base64>","cert_chain":["<base64-DER>",...]}, ...]}`
/// in that same order, refusing (nonzero exit) if the GPU count disagrees or any GPU is not in
/// Confidential Computing mode. Isolating the vendor SDK behind one contract keeps the service
/// free of Python and confines the vendor-specific part to a single file (nix/gpu-report.py).
/// MUST be validated on real hardware (T2).
const GPU_REPORT_CMD: &str = "/run/current-system/sw/bin/iron-gpu-report";

/// GPUs on the HGX B200 board, all serving one tensor-parallel model. The client pins the same
/// number (`Constants.Attestation.expectedGPUCount`); a mismatch fails attestation there. The
/// helper independently refuses if the hardware does not present exactly this many.
const EXPECTED_GPU_COUNT: usize = 8;

#[derive(Deserialize)]
pub struct AttestationQuery {
    nonce: Option<String>,
}

pub async fn handler(State(state): State<AppState>, Query(q): Query<AttestationQuery>) -> Response {
    let Some(nonce_hex) = q.nonce else {
        return err(StatusCode::BAD_REQUEST, "missing nonce");
    };
    let nonce = match hex_decode(&nonce_hex) {
        Some(b) if b.len() == 32 => b,
        _ => return err(StatusCode::BAD_REQUEST, "nonce must be 32 bytes hex"),
    };
    let spki = state.boot.spki_sha256;

    // CPU: the full 64-byte REPORTDATA is ours.
    let mut report_data = [0u8; 64];
    report_data[..32].copy_from_slice(&nonce);
    report_data[32..].copy_from_slice(&spki);

    // GPU: only 32 bytes of nonce are ours, so fold the SPKI into it -- one per GPU index.
    let gpu_nonces: Vec<[u8; 32]> = (0..EXPECTED_GPU_COUNT)
        .map(|i| derive_gpu_nonce(&nonce, &spki, i as u8))
        .collect();

    // Attestation is blocking I/O (sysfs + a subprocess); keep it off the async reactor.
    let joined = tokio::task::spawn_blocking(move || {
        let quote = tdx_quote(&report_data)?;
        let cpu_chain = pck_chain_from_quote(&quote);
        let gpus = gpu_reports_all(&gpu_nonces)?;
        Ok::<_, io::Error>((quote, cpu_chain, gpus))
    })
    .await;

    let (quote, cpu_chain, gpus) = match joined {
        Ok(Ok(v)) => v,
        // Never surface the raw error: it can carry host paths. Fail closed.
        Ok(Err(_)) | Err(_) => return err(StatusCode::SERVICE_UNAVAILABLE, "attestation unavailable"),
    };

    let gpu_reports: Vec<String> = gpus.iter().map(|(r, _)| b64_encode(r)).collect();
    let gpu_chains: Vec<Vec<String>> = gpus
        .iter()
        .map(|(_, chain)| chain.iter().map(|d| b64_encode(d)).collect())
        .collect();

    Json(json!({
        "version": 2,
        "cpu_vendor": "intel_tdx",
        "cpu_report": b64_encode(&quote),
        "cpu_chain": cpu_chain.iter().map(|d| b64_encode(d)).collect::<Vec<_>>(),
        "gpu_reports": gpu_reports,
        "gpu_chains": gpu_chains,
    }))
    .into_response()
}

fn err(code: StatusCode, msg: &str) -> Response {
    (code, Json(json!({ "error": msg }))).into_response()
}

/// Fetch a TDX quote binding `report_data`, via configfs-tsm.
///
/// Each request gets its own report entry: configfs entries are stateful (inblob -> outblob),
/// so sharing one across concurrent requests would race and cross-bind reports.
fn tdx_quote(report_data: &[u8; 64]) -> io::Result<Vec<u8>> {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = PathBuf::from(TSM_REPORT_ROOT)
        .join(format!("iron-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed)));

    fs::create_dir(&dir)?;
    let result = (|| {
        fs::write(dir.join("inblob"), report_data)?;
        let quote = fs::read(dir.join("outblob"))?;
        if quote.is_empty() {
            return Err(io::Error::other("empty TDX quote"));
        }
        Ok(quote)
    })();
    // configfs entries persist until removed; always clean up, even on error.
    let _ = fs::remove_dir(&dir);
    result
}

/// Extract the PCK certificate chain the quote carries in its `cert_data` (type 5), leaf-first.
///
/// That field is a PEM bundle, so we lift the PEM blocks out rather than re-deriving Intel's
/// quote layout here -- the client re-parses the quote itself and walks this chain to the
/// pinned Intel SGX Root CA.
fn pck_chain_from_quote(quote: &[u8]) -> Vec<Vec<u8>> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";

    let text = String::from_utf8_lossy(quote);
    let mut out = Vec::new();
    let mut rest = text.as_ref();
    while let Some(start) = rest.find(BEGIN) {
        let after = &rest[start + BEGIN.len()..];
        let Some(end) = after.find(END) else { break };
        if let Some(der) = b64_decode_any(&after[..end]) {
            if !der.is_empty() {
                out.push(der);
            }
        }
        rest = &after[end + END.len()..];
    }
    out
}

/// Ask NVIDIA's tooling to attest every GPU, one per derived nonce (index order), returning
/// each report plus its device cert chain. The helper fails closed if the board does not
/// present exactly `nonces.len()` GPUs or if any is not in Confidential Computing mode; we
/// surface that as a plain error so the handler returns 503.
fn gpu_reports_all(nonces: &[[u8; 32]]) -> io::Result<Vec<(Vec<u8>, Vec<Vec<u8>>)>> {
    let cmd = std::env::var("IRON_GPU_REPORT_CMD").unwrap_or_else(|_| GPU_REPORT_CMD.to_string());
    let mut command = Command::new(cmd);
    for nonce in nonces {
        command.arg("--nonce-hex").arg(hex_encode(nonce));
    }
    let out = command.output()?;
    if !out.status.success() {
        return Err(io::Error::other("gpu attestation helper failed"));
    }

    #[derive(Deserialize)]
    struct Gpu {
        report: String,
        cert_chain: Vec<String>,
    }
    #[derive(Deserialize)]
    struct Helper {
        gpus: Vec<Gpu>,
    }
    let parsed: Helper = serde_json::from_slice(&out.stdout).map_err(io::Error::other)?;

    // The helper is inside the measured image, but the client still re-verifies the count from
    // the envelope; assembling the wrong number here would just fail there. Check anyway so a
    // helper bug fails closed at the source rather than shipping a short envelope.
    if parsed.gpus.len() != nonces.len() {
        return Err(io::Error::other("gpu attestation helper returned wrong report count"));
    }

    parsed
        .gpus
        .iter()
        .map(|g| {
            let report = b64_decode_any(&g.report).ok_or_else(|| io::Error::other("gpu report not base64"))?;
            let chain = g
                .cert_chain
                .iter()
                .map(|c| b64_decode_any(c).ok_or_else(|| io::Error::other("gpu cert not base64")))
                .collect::<Result<Vec<_>, _>>()?;
            if report.is_empty() || chain.is_empty() {
                return Err(io::Error::other("empty gpu attestation"));
            }
            Ok((report, chain))
        })
        .collect()
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding -- what Swift's `Data(base64Encoded:)` accepts.
fn b64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        out.push(B64[(n >> 18 & 63) as usize] as char);
        out.push(B64[(n >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 { B64[(n >> 6 & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64[(n & 63) as usize] as char } else { '=' });
    }
    out
}

/// The nonce we hand GPU `index`: `SHA-256(client_nonce || SHA-256(SPKI) || u8(index))`.
///
/// The trailing index byte domain-separates the per-GPU challenges so a genuine report cannot
/// be replayed from one slot into another. The client derives the identical value; the golden
/// vector below is asserted on both sides.
fn derive_gpu_nonce(nonce: &[u8], spki_sha256: &[u8; 32], index: u8) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(nonce);
    h.update(spki_sha256);
    h.update([index]);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CROSS-LANGUAGE CONTRACT. These exact vectors are also asserted by the iOS suite
    /// (`AttestationVerifierTests.gpuNonceDerivationMatchesInstance`, same nonce/SPKI fixtures).
    /// If the two derivations ever drift, real attestation fails closed and silently -- the same
    /// trap the Orchestrator's UUIDv5 comment warns about. Change one side, change both.
    #[test]
    fn gpu_nonce_derivation_matches_ios_verifier() {
        let nonce: Vec<u8> = (0u8..32).collect();
        let spki: Vec<u8> = (0..91u8).map(|i| i ^ 0xA5).collect();
        let spki_sha256: [u8; 32] = Sha256::digest(&spki).into();

        assert_eq!(hex_encode(&spki_sha256), "f9939b4ac1207a11d218b07c9ade879cc82f76585f33be18df2a3c0f0f4dd29f");
        assert_eq!(
            hex_encode(&derive_gpu_nonce(&nonce, &spki_sha256, 0)),
            "b31ac3402d6284dc6b63bc797d28a9b4107c05730cffd35f4234723ad50a539e"
        );
        assert_eq!(
            hex_encode(&derive_gpu_nonce(&nonce, &spki_sha256, 1)),
            "73325886c24473cee3e0929d85dd8fa696e49f964e87ae3bed7aa018251b5c06"
        );
        assert_eq!(
            hex_encode(&derive_gpu_nonce(&nonce, &spki_sha256, 7)),
            "0bf29014c0f9e6d29edb224b8ae32b85d88e87ac4bd60c19dfffc02d37b78b5f"
        );
    }

    #[test]
    fn b64_encode_matches_rfc4648_vectors() {
        assert_eq!(b64_encode(b""), "");
        assert_eq!(b64_encode(b"f"), "Zg==");
        assert_eq!(b64_encode(b"fo"), "Zm8=");
        assert_eq!(b64_encode(b"foo"), "Zm9v");
        assert_eq!(b64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(b64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(b64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn pck_chain_lifts_pem_blocks_leaf_first() {
        // Two 1-byte "certs" (0x41, 0x42) wrapped as PEM inside a quote-shaped blob.
        let quote = b"\x00\x01binary-prefix-----BEGIN CERTIFICATE-----\nQQ==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nQg==\n-----END CERTIFICATE-----\n";
        let chain = pck_chain_from_quote(quote);
        assert_eq!(chain, vec![vec![0x41], vec![0x42]]);
    }

    #[test]
    fn pck_chain_of_a_quote_without_pem_is_empty() {
        assert!(pck_chain_from_quote(&[0u8; 128]).is_empty());
    }
}
