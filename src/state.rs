//! RAM-only state + injectable trust anchors. Nothing here is persisted; a reboot wipes it,
//! which is what forces the full attestation + enroll flow on reconnect (architecture.md
//! § Reconnection).

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Instant;

use jsonwebtoken::DecodingKey;
use p256::ecdsa::VerifyingKey;

use crate::manifest::Manifest;

pub type Pubkey = [u8; 65]; // X9.63 uncompressed P-256: 0x04 || X || Y
pub type MemberHash = [u8; 32]; // sha256(sub || originalTransactionId)

/// Concurrent bearers one client_pubkey may hold.
///
/// The pubkey is a **user** identity, not a device one: a user's devices share one P-256
/// keypair (architecture.md § Multiple devices), so "which device" is invisible here and
/// each enroll simply mints another live bearer for the same identity. The cap is what
/// keeps that from being unbounded.
pub const DEVICE_CAP: usize = 3;

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

/// One enroll's worth of membership: the identity that enrolled, plus the bearer being minted
/// for it right now. What the store keeps is a `Member`, which accumulates these bearers.
#[derive(Clone)]
pub struct MemberEntry {
    pub client_pubkey: Pubkey,
    pub member_hash: MemberHash,
    pub session_token: String,
    pub original_tx_id: String,
}

/// The stored form: one per client_pubkey, holding every bearer currently live for it.
#[derive(Clone)]
struct Member {
    member_hash: MemberHash,
    original_tx_id: String,
    /// Live bearers, oldest first. Bounded by `DEVICE_CAP`.
    sessions: VecDeque<String>,
}

#[derive(Default)]
struct Inner {
    by_pubkey: HashMap<Pubkey, Member>,
    by_token: HashMap<String, Pubkey>,
    seen_nonces: HashSet<String>,               // /manage replay guard
    attest_buckets: HashMap<Pubkey, (f64, Instant)>, // /attestation token bucket: (tokens, last refill)
}

/// `allowlist: client_pubkey -> { member_hash, [session_token; <=DEVICE_CAP] }` plus a bearer
/// index for O(1) chat auth, and the /manage nonce set. Cloneable handle.
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

    /// How many bearers this pubkey currently holds. Test/observability seam.
    pub fn session_count(&self, pubkey: &Pubkey) -> usize {
        self.read_guard().by_pubkey.get(pubkey).map_or(0, |m| m.sessions.len())
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

    /// Mint a bearer for this identity, keeping the ones it already holds.
    ///
    /// **This used to revoke on re-enroll, and that was wrong once devices began sharing a
    /// keypair.** The old branch treated a known pubkey as "the same device reconnecting" and
    /// dropped its previous bearer — so a user's second device, presenting the same synced key,
    /// silently logged the first one out, and the two would ping-pong. A pubkey is a user, not a
    /// device; a user legitimately holds several live bearers at once.
    ///
    /// At the cap the **oldest bearer is evicted, not the newest refused.** Refusing would strand
    /// the user: nothing tells the Instance a device was wiped or the app deleted, so a stale
    /// bearer occupies its slot until reboot, and a user who reinstalls `DEVICE_CAP` times could
    /// not enroll at all. Eviction makes the cap behave like device slots — the newcomer displaces
    /// the least-recently-enrolled, which then re-enrolls if it is still around.
    ///
    /// Always succeeds; the return value is retained so callers keep a place to handle a future
    /// refusal, and because `/enroll`'s 429 branch is cheaper to keep than to re-derive.
    pub fn insert(&self, entry: MemberEntry) -> bool {
        let mut g = self.write_guard();
        let pk = entry.client_pubkey;

        // Scoped so the &mut borrow of by_pubkey ends before by_token is touched.
        let evicted: Vec<String> = {
            let member = g.by_pubkey.entry(pk).or_insert_with(|| Member {
                member_hash: entry.member_hash,
                original_tx_id: entry.original_tx_id.clone(),
                sessions: VecDeque::new(),
            });
            // A re-enroll re-asserts the identity: enroll.rs just matched this exact
            // (pubkey, member_hash) pair against the manifest, so the fresh value wins.
            member.member_hash = entry.member_hash;
            member.original_tx_id = entry.original_tx_id.clone();
            member.sessions.push_back(entry.session_token.clone());

            let mut out = Vec::new();
            while member.sessions.len() > DEVICE_CAP {
                if let Some(old) = member.sessions.pop_front() {
                    out.push(old);
                }
            }
            out
        };

        for token in evicted {
            g.by_token.remove(&token);
        }
        g.by_token.insert(entry.session_token, pk);
        true
    }

    // Bearer lookup is a HashMap probe, not a constant-time compare. That is fine here: the token
    // is 256 bits of CSPRNG output, so lookup timing leaks bucket structure, never enough of the
    // secret to guess it. (Same for the manifest hex compares in enroll.rs, which are over public
    // pubkeys, not secrets.)
    pub fn get_by_token(&self, token: &str) -> Option<MemberEntry> {
        let g = self.read_guard();
        let pk = g.by_token.get(token)?;
        let member = g.by_pubkey.get(pk)?;
        Some(MemberEntry {
            client_pubkey: *pk,
            member_hash: member.member_hash,
            session_token: token.to_string(),
            original_tx_id: member.original_tx_id.clone(),
        })
    }

    pub fn contains_token(&self, token: &str) -> bool {
        self.read_guard().by_token.contains_key(token)
    }

    /// Remove the member whose member_hash matches; drops **every** bearer it holds. Used by
    /// /manage revoke.
    ///
    /// Dropping all of them is the point: one identity now spans several devices, and a revoke
    /// that cleared only one bearer would leave the user's other devices chatting on a slot the
    /// operator just revoked.
    pub fn revoke_by_member_hash(&self, hash: &MemberHash) -> bool {
        let mut g = self.write_guard();
        let pk = g.by_pubkey.iter().find(|(_, m)| &m.member_hash == hash).map(|(pk, _)| *pk);
        match pk {
            Some(pk) => {
                if let Some(m) = g.by_pubkey.remove(&pk) {
                    for token in m.sessions {
                        g.by_token.remove(&token);
                    }
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

    fn entry(pubkey: Pubkey, token: &str) -> MemberEntry {
        MemberEntry {
            client_pubkey: pubkey,
            member_hash: [7u8; 32],
            session_token: token.to_string(),
            original_tx_id: "tx-1".to_string(),
        }
    }

    /// The regression that motivated the rework: a second device presenting the *same* synced
    /// keypair must not log the first one out.
    #[test]
    fn a_second_enroll_on_one_pubkey_keeps_the_first_bearer() {
        let store = MemberStore::default();
        let a = pk(1);

        assert!(store.insert(entry(a, "bearer-first")));
        assert!(store.insert(entry(a, "bearer-second")));

        assert!(store.contains_token("bearer-first"), "first device must stay enrolled");
        assert!(store.contains_token("bearer-second"));
        assert_eq!(store.session_count(&a), 2);
    }

    #[test]
    fn bearers_are_capped_by_evicting_the_oldest() {
        let store = MemberStore::default();
        let a = pk(1);

        for i in 0..DEVICE_CAP {
            assert!(store.insert(entry(a, &format!("bearer-{i}"))));
        }
        assert_eq!(store.session_count(&a), DEVICE_CAP);

        // One past the cap: the newcomer is admitted and the oldest goes, rather than the
        // newcomer being refused and the user stranded behind stale bearers.
        assert!(store.insert(entry(a, "bearer-newest")));
        assert_eq!(store.session_count(&a), DEVICE_CAP);
        assert!(!store.contains_token("bearer-0"), "oldest bearer must be evicted");
        assert!(store.contains_token("bearer-newest"));
        assert!(store.contains_token(&format!("bearer-{}", DEVICE_CAP - 1)));
    }

    #[test]
    fn one_pubkeys_cap_does_not_touch_another() {
        let store = MemberStore::default();
        let a = pk(1);
        let b = pk(2);

        for i in 0..(DEVICE_CAP + 2) {
            store.insert(entry(a, &format!("a-{i}")));
        }
        store.insert(entry(b, "b-only"));

        assert_eq!(store.session_count(&a), DEVICE_CAP);
        assert!(store.contains_token("b-only"));
    }

    #[test]
    fn revoke_drops_every_bearer_the_identity_holds() {
        let store = MemberStore::default();
        let a = pk(1);

        store.insert(entry(a, "device-1"));
        store.insert(entry(a, "device-2"));

        assert!(store.revoke_by_member_hash(&[7u8; 32]));

        // A revoke that cleared only one would leave the user's other devices chatting.
        assert!(!store.contains_token("device-1"));
        assert!(!store.contains_token("device-2"));
        assert_eq!(store.session_count(&a), 0);
    }

    #[test]
    fn lookup_by_token_reports_the_identity_behind_that_bearer() {
        let store = MemberStore::default();
        let a = pk(1);
        store.insert(entry(a, "device-1"));
        store.insert(entry(a, "device-2"));

        let found = store.get_by_token("device-2").expect("bearer must resolve");
        assert_eq!(found.client_pubkey, a);
        assert_eq!(found.session_token, "device-2");
        assert_eq!(found.member_hash, [7u8; 32]);
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
