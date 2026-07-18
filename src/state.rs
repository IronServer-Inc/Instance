//! RAM-only state + injectable trust anchors. Nothing here is persisted; a reboot wipes it,
//! which is what forces the full attestation + enroll flow on reconnect (architecture.md
//! § Reconnection).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Instant;

use jsonwebtoken::DecodingKey;
use p256::ecdsa::VerifyingKey;

use crate::manifest::Manifest;

pub type Pubkey = [u8; 65]; // X9.63 uncompressed P-256: 0x04 || X || Y
pub type MemberHash = [u8; 32]; // sha256(sub || originalTransactionId)

pub const DEVICE_CAP: u32 = 3;

// Per-pubkey token bucket for /attestation. It runs before enroll so it cannot be bearer-gated, but
// mTLS already proved cohort membership (mtls.rs injects the pubkey), so it is capped per member:
// each call mints a TDX quote and attests 8 GPUs, and one member must not be able to spam it and
// starve the other 399. Keyed by pubkey, so the map is bounded by the cohort.
pub const ATTEST_BURST: f64 = 5.0;
pub const ATTEST_REFILL_PER_SEC: f64 = 0.1; // sustained 1 per 10s after the burst

/// The client's mTLS public point, pulled from the TLS session's leaf cert. Threaded to the
/// handlers as a request extension; the server sets it from the peer cert (see mtls.rs),
/// integration tests set it directly.
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
    consumed: HashMap<String, u32>,             // original_tx_id -> device_count
    seen_nonces: HashSet<String>,               // /manage replay guard
    attest_buckets: HashMap<Pubkey, (f64, Instant)>, // /attestation token bucket: (tokens, last refill)
}

/// `allowlist: client_pubkey -> { member_hash, session_token, ... }` plus a bearer index for
/// O(1) chat auth, the `consumed` dedup counter, and the /manage nonce set. Cloneable handle.
#[derive(Clone, Default)]
pub struct MemberStore {
    inner: Arc<RwLock<Inner>>,
}

impl MemberStore {
    // Recover the guard from a poisoned lock instead of propagating. Nothing here panics under the
    // lock, so the data is consistent -- but if it ever did, .unwrap() would turn that one panic into
    // a lock that panics every later request: a whole-box kill switch. This removes that.
    fn read_guard(&self) -> RwLockReadGuard<'_, Inner> {
        self.inner.read().unwrap_or_else(|e| e.into_inner())
    }
    fn write_guard(&self) -> RwLockWriteGuard<'_, Inner> {
        self.inner.write().unwrap_or_else(|e| e.into_inner())
    }

    pub fn device_count(&self, tx_id: &str) -> u32 {
        *self.read_guard().consumed.get(tx_id).unwrap_or(&0)
    }

    /// Take a token from this pubkey's /attestation bucket. False -> over the limit (429). See the
    /// ATTEST_* constants for the reasoning; keyed by the mTLS client pubkey mtls.rs injected.
    pub fn allow_attestation(&self, pubkey: &Pubkey) -> bool {
        let now = Instant::now();
        let mut g = self.write_guard();
        let bucket = g.attest_buckets.entry(*pubkey).or_insert((ATTEST_BURST, now));
        bucket.0 = (bucket.0 + now.duration_since(bucket.1).as_secs_f64() * ATTEST_REFILL_PER_SEC).min(ATTEST_BURST);
        bucket.1 = now;
        if bucket.0 >= 1.0 {
            bucket.0 -= 1.0;
            true
        } else {
            false
        }
    }

    /// Insert (or refresh) an allowlist entry. A first-time client_pubkey bumps the
    /// per-transaction device counter and is rejected (false -> 429) once original_tx_id is at
    /// DEVICE_CAP; re-enrolling an existing device just rotates its bearer without counting.
    pub fn insert(&self, entry: MemberEntry) -> bool {
        let mut g = self.write_guard();
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

    // Bearer lookup is a HashMap probe, not a constant-time compare. That is fine here: the token
    // is 256 bits of CSPRNG output, so lookup timing leaks bucket structure, never enough of the
    // secret to guess it. (Same for the manifest hex compares in enroll.rs, which are over public
    // pubkeys, not secrets.)
    pub fn get_by_token(&self, token: &str) -> Option<MemberEntry> {
        let g = self.read_guard();
        let pk = g.by_token.get(token)?;
        g.by_pubkey.get(pk).cloned()
    }

    pub fn contains_token(&self, token: &str) -> bool {
        self.read_guard().by_token.contains_key(token)
    }

    /// Remove the member whose member_hash matches; drops their bearer. Used by /manage revoke.
    pub fn revoke_by_member_hash(&self, hash: &MemberHash) -> bool {
        let mut g = self.write_guard();
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
        self.write_guard().seen_nonces.insert(nonce.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(seed: u8) -> Pubkey {
        let mut p = [seed; 65];
        p[0] = 0x04;
        p
    }

    #[test]
    fn attestation_bucket_caps_the_burst_per_pubkey() {
        let store = MemberStore::default();
        let a = pk(1);
        // The burst is spent by back-to-back calls (refill over microseconds is negligible)...
        for _ in 0..(ATTEST_BURST as usize) {
            assert!(store.allow_attestation(&a));
        }
        // ...and the next one is refused: without the limiter every call would pass.
        assert!(!store.allow_attestation(&a));

        // A different member has an independent bucket.
        let b = pk(2);
        assert!(store.allow_attestation(&b));
    }
}

pub struct BootContext {
    /// SHA-256 of the boot TLS leaf's SubjectPublicKeyInfo DER. Goes into attestation
    /// report_data[32..64] and is what the client pins in the mTLS SPKI check.
    pub spki_sha256: [u8; 32],
}

/// Pinned trust anchors, injected so the integration tests can supply synthetic material while
/// production (main.rs) wires the real pinned values (include_bytes! JWKS + pubkey, in-repo
/// Apple Root CA - G3 hash). The production and test builds share this code; only the pinned
/// data files differ.
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
