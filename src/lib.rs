//! IronServer vLLM Instance.
//!
//! Four endpoints (`/attestation`, `/enroll`, `/v1/chat/completions`, `/manage`). Nothing here
//! is stubbed: the production build (`Instance/`) performs real Intel TDX + NVIDIA CC
//! attestation and proxies a real vLLM. The sibling test build (`Instance-test/`) is this same
//! code with exactly one file changed -- `attestation.rs`, whose GPU half software-signs
//! synthetic reports because a non-CC GPU cannot emit a real one; its CPU half is the real TDX
//! quote. Every other module is byte-identical between the two and must stay that way.
//! See ../architecture.md § vLLM Instance.

pub mod apple_jwks;
pub mod attestation;
pub mod chat;
pub mod enroll;
pub mod manage;
pub mod manifest;
pub mod mtls;
pub mod state;

use axum::routing::{get, post};
use axum::Router;
use state::AppState;

/// Wire the four endpoints. TLS and boot key generation live in `main.rs`; this stays
/// transport-agnostic so the step-2 integration tests can drive it without a TLS listener.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/attestation", get(attestation::handler))
        .route("/enroll", post(enroll::handler))
        .route("/v1/chat/completions", post(chat::handler))
        .route("/manage", post(manage::handler))
        .with_state(state)
}

pub(crate) fn random_32() -> [u8; 32] {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).expect("system CSPRNG unavailable");
    buf
}

const HEX: &[u8; 16] = b"0123456789abcdef";

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

pub(crate) fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let val = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i < b.len() {
        out.push((val(b[i])? << 4) | val(b[i + 1])?);
        i += 2;
    }
    Some(out)
}

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// base64url, no padding -- matches the Orchestrator's session-token encoding.
pub(crate) fn b64url_nopad(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut chunks = bytes.chunks_exact(3);
    for c in &mut chunks {
        let n = (c[0] as u32) << 16 | (c[1] as u32) << 8 | c[2] as u32;
        out.push(B64URL[(n >> 18 & 63) as usize] as char);
        out.push(B64URL[(n >> 12 & 63) as usize] as char);
        out.push(B64URL[(n >> 6 & 63) as usize] as char);
        out.push(B64URL[(n & 63) as usize] as char);
    }
    let rem = chunks.remainder();
    match rem.len() {
        1 => {
            let n = (rem[0] as u32) << 16;
            out.push(B64URL[(n >> 18 & 63) as usize] as char);
            out.push(B64URL[(n >> 12 & 63) as usize] as char);
        }
        2 => {
            let n = (rem[0] as u32) << 16 | (rem[1] as u32) << 8;
            out.push(B64URL[(n >> 18 & 63) as usize] as char);
            out.push(B64URL[(n >> 12 & 63) as usize] as char);
            out.push(B64URL[(n >> 6 & 63) as usize] as char);
        }
        _ => {}
    }
    out
}

/// Decode base64 in either alphabet (standard `+/` or url `-_`), padding optional; whitespace
/// ignored. Covers both the StoreKit `x5c` DERs (standard, padded) and the /manage envelope
/// (url, no pad). Kept off the dependency surface, like the Orchestrator's WebCrypto choice.
pub(crate) fn b64_decode_any(s: &str) -> Option<Vec<u8>> {
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a' + 26) as u32,
            b'0'..=b'9' => (c - b'0' + 52) as u32,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        })
    };
    let (mut acc, mut nbits) = (0u32, 0u32);
    let mut out = Vec::with_capacity(s.len() * 3 / 4 + 3);
    for &c in s.as_bytes() {
        if c == b'=' || c == b'\n' || c == b'\r' {
            continue;
        }
        acc = (acc << 6) | val(c)?;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    Some(out)
}

/// SHA-1 (FIPS 180-4). Used only as the deterministic mixing function for UUIDv5 over
/// already-trusted inputs (public namespace + Apple `sub`) -- not as a security primitive.
/// Mirrors the reasoning in Orchestrator/_shared/uuid_v5.ts.
pub(crate) fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0];
    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for block in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            *word = u32::from_be_bytes([block[i * 4], block[i * 4 + 1], block[i * 4 + 2], block[i * 4 + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let tmp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// RFC 4122 v5 UUID string (lowercase, hyphenated). Byte-for-byte match required with
/// Orchestrator/_shared/uuid_v5.ts + iOS Constants.Identity.appAccountTokenNamespace.
pub(crate) fn uuid_v5(namespace: &[u8; 16], name: &[u8]) -> String {
    let mut input = Vec::with_capacity(16 + name.len());
    input.extend_from_slice(namespace);
    input.extend_from_slice(name);
    let d = sha1(&input);
    let mut b = [0u8; 16];
    b.copy_from_slice(&d[..16]);
    b[6] = (b[6] & 0x0f) | 0x50; // version 5
    b[8] = (b[8] & 0x3f) | 0x80; // RFC-4122 variant
    let h = hex_encode(&b);
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

/// True iff two UUID strings are equal ignoring case and hyphens (Apple echoes appAccountToken
/// in mixed case). Mirrors uuidEqual() in the Orchestrator.
pub(crate) fn uuid_eq(a: &str, b: &str) -> bool {
    let norm = |s: &str| s.chars().filter(|c| *c != '-').flat_map(|c| c.to_lowercase()).collect::<String>();
    norm(a) == norm(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_fips_vectors() {
        assert_eq!(hex_encode(&sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(hex_encode(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    #[test]
    fn uuid_v5_matches_orchestrator_golden() {
        // Golden value computed by Python hashlib against the pinned namespace (see the
        // fixture-generation step); proves parity with uuid_v5.ts / iOS.
        let ns: [u8; 16] = [
            0xda, 0xfb, 0x6e, 0x23, 0x9c, 0x4d, 0x5d, 0x27, 0xaa, 0x05, 0x3f, 0x6c, 0x2e, 0x9e, 0x7b, 0x14,
        ];
        assert_eq!(uuid_v5(&ns, b"test-sub-000"), "0dd14662-856c-5f35-9ae5-34cea39f5d13");
    }

    #[test]
    fn b64_decode_both_alphabets() {
        assert_eq!(b64_decode_any("SGVsbG8=").unwrap(), b"Hello");
        assert_eq!(b64_decode_any("SGVsbG8").unwrap(), b"Hello"); // no pad
        // url alphabet: 0xff,0xef,0xbf encodes to "/++/" (std) == "_--_" (url)
        assert_eq!(b64_decode_any("_--_").unwrap(), b64_decode_any("/++/").unwrap());
    }

    #[test]
    fn uuid_eq_ignores_case_and_hyphens() {
        assert!(uuid_eq("0DD14662-856C-5F35-9AE5-34CEA39F5D13", "0dd14662856c5f359ae534cea39f5d13"));
    }
}
