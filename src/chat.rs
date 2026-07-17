//! POST /v1/chat/completions -- OpenAI-compatible, bearer-authenticated SSE streaming.
//!
//! Proxies to vLLM on loopback. The request body is forwarded verbatim and vLLM's SSE frames are
//! relayed byte-for-byte, so the wire shape is exactly the OpenAI one the client already speaks.
//!
//! The allowlist is re-checked between frames, so a /manage revoke lands mid-generation: the
//! stream is cut and an error frame is emitted.
//!
//! This is the only place the Instance talks to anything, and it is loopback only. Nothing here
//! is logged: the body is the user's plaintext prompt.

use std::convert::Infallible;
use std::sync::OnceLock;

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde_json::json;
use tokio_stream::wrappers::ReceiverStream;

use crate::state::AppState;

/// vLLM's OpenAI-compatible server, bound to loopback inside the CVM.
const DEFAULT_UPSTREAM: &str = "http://127.0.0.1:8000/v1/chat/completions";

/// The frame the client parses to distinguish revocation from a dropped stream. Byte-identical
/// across the production and test builds, so the client handles revocation the same against either.
const REVOKED_FRAME: &str = "data: {\"error\":{\"message\":\"session revoked\",\"type\":\"revoked\"}}\n\n";

fn upstream() -> String {
    std::env::var("IRON_VLLM_URL").unwrap_or_else(|_| DEFAULT_UPSTREAM.to_string())
}

/// One pooled client for the process. It cannot live in AppState: state.rs is kept
/// byte-identical across the production and test builds.
fn client() -> &'static Client<HttpConnector, Full<Bytes>> {
    static CLIENT: OnceLock<Client<HttpConnector, Full<Bytes>>> = OnceLock::new();
    CLIENT.get_or_init(|| Client::builder(TokioExecutor::new()).build_http())
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    raw.strip_prefix("Bearer ").map(str::to_string)
}

pub async fn handler(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let token = match bearer(&headers) {
        Some(t) if state.members.contains_token(&t) => t,
        _ => return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "invalid bearer" }))).into_response(),
    };

    let request = match hyper::Request::builder()
        .method("POST")
        .uri(upstream())
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "text/event-stream")
        .body(Full::new(body))
    {
        Ok(r) => r,
        Err(_) => return (StatusCode::BAD_GATEWAY, Json(json!({ "error": "bad upstream request" }))).into_response(),
    };

    let upstream = match client().request(request).await {
        Ok(r) => r,
        Err(_) => return (StatusCode::BAD_GATEWAY, Json(json!({ "error": "model backend unavailable" }))).into_response(),
    };

    if !upstream.status().is_success() {
        // Pass the status through but not the body: it can echo the prompt back.
        let code = StatusCode::from_u16(upstream.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
        return (code, Json(json!({ "error": "model backend rejected the request" }))).into_response();
    }

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, Infallible>>(16);
    let members = state.members.clone();

    tokio::spawn(async move {
        let mut body = upstream.into_body();
        while let Some(frame) = body.frame().await {
            let Ok(frame) = frame else { return };
            let Ok(data) = frame.into_data() else { continue };

            // A /manage revoke between frames cuts the stream mid-generation.
            if !members.contains_token(&token) {
                let _ = tx.send(Ok(Bytes::from_static(REVOKED_FRAME.as_bytes()))).await;
                return;
            }
            if tx.send(Ok(data)).await.is_err() {
                return; // client hung up
            }
        }
    });

    Response::builder()
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .body(Body::from_stream(ReceiverStream::new(rx)))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}
