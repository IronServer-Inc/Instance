//! POST /manage  { payload, signature }
//!
//! `payload` is base64url(JSON action bytes); `signature` is base64url(raw r||s, 64 B) of a
//! P-256 ECDSA (SHA-256) signature over those exact payload bytes by the pinned Orchestrator
//! management key. Verify -> replay-guard on the payload nonce -> apply the typed action.
//!
//! Worst case if the Orchestrator is compromised: it can revoke legitimate users (DoS). It
//! cannot read messages or impersonate anyone (architecture.md § vLLM Instance).

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::Signature;
use serde::Deserialize;
use serde_json::json;

use crate::state::AppState;
use crate::{b64_decode_any, hex_decode};

#[derive(Deserialize)]
pub struct ManageEnvelope {
    payload: String,
    signature: String,
}

#[derive(Deserialize)]
struct ManageAction {
    action: String,
    nonce: String,
    #[serde(default)]
    member_hash: Option<String>, // hex(32B) for "revoke"
}

fn err(code: StatusCode, msg: &str) -> Response {
    (code, Json(json!({ "error": msg }))).into_response()
}

pub async fn handler(State(state): State<AppState>, Json(env): Json<ManageEnvelope>) -> Response {
    let (Some(payload_bytes), Some(sig_bytes)) = (b64_decode_any(&env.payload), b64_decode_any(&env.signature)) else {
        return err(StatusCode::UNAUTHORIZED, "malformed envelope");
    };
    let Ok(signature) = Signature::from_slice(&sig_bytes) else {
        return err(StatusCode::UNAUTHORIZED, "malformed signature");
    };
    if state.anchors.orch_manage_pubkey.verify(&payload_bytes, &signature).is_err() {
        return err(StatusCode::UNAUTHORIZED, "signature invalid");
    }

    let Ok(action) = serde_json::from_slice::<ManageAction>(&payload_bytes) else {
        return err(StatusCode::BAD_REQUEST, "malformed action");
    };

    // Replay guard AFTER signature verification, so unsigned traffic can't burn nonces.
    if !state.members.note_nonce(&action.nonce) {
        return err(StatusCode::CONFLICT, "nonce replay");
    }

    match action.action.as_str() {
        "revoke" => {
            let Some(mh) = action.member_hash.as_deref().and_then(hex_decode).filter(|b| b.len() == 32) else {
                return err(StatusCode::BAD_REQUEST, "revoke requires 32-byte hex member_hash");
            };
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&mh);
            let revoked = state.members.revoke_by_member_hash(&hash);
            Json(json!({ "revoked": revoked })).into_response()
        }
        _ => err(StatusCode::BAD_REQUEST, "unknown action"),
    }
}
