//! Pinned Apple Sign-In JWKS + RS256 identity-JWT verification. Mirrors the Orchestrator's
//! contract (Orchestrator/_shared/apple_jwks.ts): RS256 only; iss/aud/exp/iat/sub required;
//! 60s leeway; sub 1..=255 bytes; belt-and-suspenders iss/aud recheck; unknown kid -> reject.
//! The Instance makes zero outbound calls, so the JWKS is the pinned snapshot, never fetched.

use std::collections::HashMap;

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;

/// "Sign in with Apple" JWKS snapshot. Source: https://appleid.apple.com/auth/keys
/// (fetched 2026-07-10). Apple rotates these keys, so a rotation means re-pinning this
/// snapshot and rebuilding the image (new measurement -> app update).
pub const SIGN_IN_WITH_APPLE_JWKS: &[u8] = include_bytes!("../pinned/apple_sign_in_jwks.json");

pub const APPLE_ISSUER: &str = "https://appleid.apple.com";
// Apple identity-token audience == the app Bundle ID (root CLAUDE.md pinned facts).
pub const APPLE_AUDIENCE: &str = "com.rayeeev.IronServer";

// App Store Server (StoreKit) verification uses the x5c chain to Apple Root CA - G3, not a
// JWKS endpoint. That verification lives in enroll.rs; the pinned root hash is there too.

#[derive(Deserialize)]
struct Jwk {
    kid: String,
    n: String,
    e: String,
    #[serde(default)]
    kty: Option<String>,
    #[serde(rename = "use", default)]
    use_field: Option<String>,
}

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

/// Parse a pinned JWKS into per-kid RS256 decoding keys. Panics if the pinned snapshot is
/// unparseable -- that is a build-time error, not a request-time one.
pub fn load_apple_jwt_keys(jwks_json: &[u8]) -> HashMap<String, DecodingKey> {
    let doc: Jwks = serde_json::from_slice(jwks_json).expect("pinned Apple JWKS must parse");
    let mut out = HashMap::new();
    for k in doc.keys {
        if k.kty.as_deref() != Some("RSA") {
            continue;
        }
        if matches!(k.use_field.as_deref(), Some(u) if u != "sig") {
            continue;
        }
        if let Ok(dk) = DecodingKey::from_rsa_components(&k.n, &k.e) {
            out.insert(k.kid, dk);
        }
    }
    out
}

#[derive(Debug, Deserialize)]
pub struct AppleClaims {
    pub iss: String,
    pub sub: String,
    pub aud: serde_json::Value, // string or array of strings
    pub exp: u64,
    pub iat: u64,
}

/// Verify an Apple identity JWT against the pinned keys. Any failure returns `Err(())` (the
/// caller maps every enroll credential failure to 401) -- we never distinguish reasons to a
/// caller who could probe them.
pub fn verify_apple_jwt(
    token: &str,
    keys: &HashMap<String, DecodingKey>,
    issuer: &str,
    audience: &str,
) -> Result<AppleClaims, ()> {
    let header = decode_header(token).map_err(|_| ())?;
    if header.alg != Algorithm::RS256 {
        return Err(());
    }
    let kid = header.kid.ok_or(())?;
    let key = keys.get(&kid).ok_or(())?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[audience]);
    validation.set_required_spec_claims(&["iss", "aud", "exp", "iat", "sub"]);
    validation.leeway = 60;

    let claims = decode::<AppleClaims>(token, key, &validation).map_err(|_| ())?.claims;

    if claims.iss != issuer {
        return Err(());
    }
    if !aud_contains(&claims.aud, audience) {
        return Err(());
    }
    if claims.sub.is_empty() || claims.sub.len() > 255 {
        return Err(());
    }
    Ok(claims)
}

fn aud_contains(aud: &serde_json::Value, needle: &str) -> bool {
    match aud {
        serde_json::Value::String(s) => s == needle,
        serde_json::Value::Array(items) => items.iter().any(|v| v.as_str() == Some(needle)),
        _ => false,
    }
}
