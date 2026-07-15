//! RAM-only state + injectable trust anchors. Nothing here is persisted; a reboot wipes it,
//! which is what forces the full attestation + enroll flow on reconnect (architecture.md
//! § Reconnection).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use jsonwebtoken::DecodingKey;
use p256::ecdsa::VerifyingKey;

use crate::manifest::Manifest;

pub type Pubkey = [u8; 65]; // X9.63 uncompressed P-256: 0x04 || X || Y
pub type MemberHash = [u8; 32]; // sha256(sub || originalTransactionId)

pub const DEVICE_CAP: u32 = 3;

/// The client's mTLS public point, pulled from the TLS session's leaf cert. Threaded to the
/// handlers as a request extension; production sets it from the peer cert (the mTLS-capture
/// increment), tests set it directly.
#[derive(Clone, Copy)]
pub struct ClientPubkey(pub Pubkey);

#[derive(Clone)]
pub struct MemberEntry {
    pub client_pubkey: Pubkey,
    pub member_hash: MemberHash,
    pub session_token: String,
    pub original_tx_id: String,
}

#[derive(Default)]
struct Inner {
    by_pubkey: HashMap<Pubkey, MemberEntry>,
    by_token: HashMap<String, Pubkey>,
    consumed: HashMap<String, u32>, // original_tx_id -> device_count
    seen_nonces: HashSet<String>,   // /manage replay guard
}

/// `allowlist: client_pubkey -> { member_hash, session_token, ... }` plus a bearer index for
/// O(1) chat auth, the `consumed` dedup counter, and the /manage nonce set. Cloneable handle.
#[derive(Clone, Default)]
pub struct MemberStore {
    inner: Arc<RwLock<Inner>>,
}

impl MemberStore {
    pub fn device_count(&self, tx_id: &str) -> u32 {
        *self.inner.read().unwrap().consumed.get(tx_id).unwrap_or(&0)
    }

    /// Insert (or refresh) an allowlist entry. A first-time client_pubkey bumps the
    /// per-transaction device counter and is rejected (false -> 429) once original_tx_id is at
    /// DEVICE_CAP; re-enrolling an existing device just rotates its bearer without counting.
    pub fn insert(&self, entry: MemberEntry) -> bool {
        let mut g = self.inner.write().unwrap();
        match g.by_pubkey.get(&entry.client_pubkey) {
            None => {
                if *g.consumed.get(&entry.original_tx_id).unwrap_or(&0) >= DEVICE_CAP {
                    return false;
                }
                *g.consumed.entry(entry.original_tx_id.clone()).or_insert(0) += 1;
            }
            Some(old) => {
                let old_token = old.session_token.clone();
                g.by_token.remove(&old_token);
            }
        }
        g.by_token.insert(entry.session_token.clone(), entry.client_pubkey);
        let pk = entry.client_pubkey;
        g.by_pubkey.insert(pk, entry);
        true
    }

    pub fn get_by_token(&self, token: &str) -> Option<MemberEntry> {
        let g = self.inner.read().unwrap();
        let pk = g.by_token.get(token)?;
        g.by_pubkey.get(pk).cloned()
    }

    pub fn contains_token(&self, token: &str) -> bool {
        self.inner.read().unwrap().by_token.contains_key(token)
    }

    /// Remove the member whose member_hash matches; drops their bearer. Used by /manage revoke.
    pub fn revoke_by_member_hash(&self, hash: &MemberHash) -> bool {
        let mut g = self.inner.write().unwrap();
        let pk = g.by_pubkey.iter().find(|(_, e)| &e.member_hash == hash).map(|(pk, _)| *pk);
        match pk {
            Some(pk) => {
                if let Some(e) = g.by_pubkey.remove(&pk) {
                    g.by_token.remove(&e.session_token);
                }
                true
            }
            None => false,
        }
    }

    /// Record a /manage nonce. Returns false if it was already seen (replay -> 409).
    pub fn note_nonce(&self, nonce: &str) -> bool {
        self.inner.write().unwrap().seen_nonces.insert(nonce.to_string())
    }
}

pub struct BootContext {
    /// SHA-256 of the boot TLS leaf's SubjectPublicKeyInfo DER. Goes into attestation
    /// report_data[32..64] and is what the client pins in the mTLS SPKI check (Phase 8).
    pub spki_sha256: [u8; 32],
}

/// Pinned trust anchors, injected so the step-2 tests can supply synthetic material while
/// production (main.rs) wires the real pinned values (include_bytes! JWKS + pubkey, in-repo
/// Apple Root CA - G3 hash). DevInstance and Instance share this code; only the pinned data
/// files differ (option B).
pub struct Anchors {
    pub apple_jwt_keys: HashMap<String, DecodingKey>, // kid -> Apple Sign-In RSA key
    pub apple_issuer: String,
    pub apple_audience: String,
    pub storekit_bundle_id: String,
    pub storekit_root_sha256: [u8; 32], // Apple Root CA - G3 (prod) / synthetic root (test)
    pub appaccount_namespace: [u8; 16], // UUIDv5 namespace for appAccountToken <-> sub
    pub orch_manage_pubkey: VerifyingKey,
}

#[derive(Clone)]
pub struct AppState {
    pub boot: Arc<BootContext>,
    pub members: MemberStore,
    pub manifest: Arc<Manifest>,
    pub anchors: Arc<Anchors>,
}
