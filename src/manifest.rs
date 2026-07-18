//! Hashed member manifest handed to the VM as a launch parameter. The pointer (`manifest_url` +
//! `manifest_sha256`) is resolved by the image's iron-manifest unit, which fetches and
//! hash-verifies the bytes before this service starts and installs them at IRON_MANIFEST_PATH;
//! this module parses them and answers membership queries. Binding the manifest hash into
//! attestation (so the provider provably cannot swap manifests) is not yet exercised on hardware.

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct ManifestMember {
    // Wire contract, pinned against ironserver.freeze_manifest() in the Orchestrator:
    // pubkey = hex of the 65-byte X9.63 P-256 point, hash = hex of
    // sha256(sub || originalTransactionId); both compared case-insensitively.
    pub pubkey: String,
    pub hash: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Manifest {
    #[serde(default)]
    pub cohort_id: String,
    #[serde(default)]
    pub members: Vec<ManifestMember>,
}

impl Manifest {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    /// Is this client public point a cohort member? Checked at the mTLS handshake (the
    /// connection is dropped otherwise) and again, paired with the member_hash, at enroll.
    pub fn contains_pubkey(&self, point: &[u8; 65]) -> bool {
        let hex = crate::hex_encode(point);
        self.members.iter().any(|m| m.pubkey.eq_ignore_ascii_case(&hex))
    }
}
