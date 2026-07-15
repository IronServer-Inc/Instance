//! Phase 9 chat tests for the production build: the vLLM *proxy* (DevInstance tests the echo
//! model instead). A fake vLLM upstream stands in for the real one; everything else -- bearer
//! auth, SSE relay, mid-stream revocation -- is the shipping code path.

mod common;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::http::{Request, StatusCode};
use axum::response::Response;
use axum::routing::post;
use axum::Router;
use common::*;
use http_body_util::BodyExt;
use iron_instance::state::{MemberEntry, MemberStore};
use tokio_stream::wrappers::ReceiverStream;
use tower::ServiceExt;

const TOKEN: &str = "chat-bearer-abc123";

/// IRON_VLLM_URL is process-global, so chat tests must not run concurrently.
fn serial() -> MutexGuard<'static, ()> {
    static M: OnceLock<Mutex<()>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner())
}

fn seed(members: &MemberStore, token: &str, member_hash: [u8; 32]) {
    members.insert(MemberEntry {
        client_pubkey: client_pk(1),
        member_hash,
        session_token: token.to_string(),
        original_tx_id: "tx-chat".to_string(),
    });
}

/// A stand-in vLLM: streams `chunks` OpenAI-shaped SSE frames, `delay_ms` apart, then [DONE].
async fn start_fake_vllm(chunks: usize, delay_ms: u64) -> SocketAddr {
    let app = Router::new().route(
        "/v1/chat/completions",
        post(move |_body: Bytes| async move {
            let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, Infallible>>(8);
            tokio::spawn(async move {
                for i in 0..chunks {
                    let frame = format!("data: {{\"choices\":[{{\"delta\":{{\"content\":\"tok{i} \"}}}}]}}\n\n");
                    if tx.send(Ok(Bytes::from(frame))).await.is_err() {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                }
                let _ = tx.send(Ok(Bytes::from_static(b"data: [DONE]\n\n"))).await;
            });
            Response::builder()
                .header("content-type", "text/event-stream")
                .body(Body::from_stream(ReceiverStream::new(rx)))
                .unwrap()
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

fn point_at(addr: SocketAddr) {
    std::env::set_var("IRON_VLLM_URL", format!("http://{addr}/v1/chat/completions"));
}

fn chat_request(token: Option<&str>) -> Request<Body> {
    let body = serde_json::json!({
        "model": "ironserver",
        "messages": [{ "role": "user", "content": "hello" }],
        "stream": true
    })
    .to_string();
    let mut b = Request::builder().method("POST").uri("/v1/chat/completions").header("content-type", "application/json");
    if let Some(t) = token {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    b.body(Body::from(body)).unwrap()
}

#[tokio::test]
async fn bearer_in_allowlist_relays_vllm_stream() {
    let _g = serial();
    point_at(start_fake_vllm(3, 5).await);

    let members = MemberStore::default();
    seed(&members, TOKEN, [0x44u8; 32]);
    let app = app(anchors([0u8; 32], *orch_signing_key().verifying_key()), manifest(&[]), members);

    let resp = app.oneshot(chat_request(Some(TOKEN))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let sse = String::from_utf8_lossy(&resp.into_body().collect().await.unwrap().to_bytes()).to_string();

    // vLLM's frames are relayed byte-for-byte.
    assert!(sse.contains("tok0 ") && sse.contains("tok1 ") && sse.contains("tok2 "), "got: {sse}");
    assert!(sse.contains("[DONE]"), "got: {sse}");
}

#[tokio::test]
async fn absent_bearer_is_401_and_never_reaches_vllm() {
    let _g = serial();
    // Deliberately point at a dead port: a 401 must be decided before any upstream call.
    std::env::set_var("IRON_VLLM_URL", "http://127.0.0.1:1/v1/chat/completions");

    let members = MemberStore::default();
    seed(&members, TOKEN, [0x44u8; 32]);
    let app = app(anchors([0u8; 32], *orch_signing_key().verifying_key()), manifest(&[]), members);

    let resp = app.oneshot(chat_request(None)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn revoked_mid_stream_terminates_with_error_chunk() {
    let _g = serial();
    // Long, slow stream so the revoke lands while vLLM is still generating.
    point_at(start_fake_vllm(40, 25).await);

    let members = MemberStore::default();
    let mh = [0x55u8; 32];
    seed(&members, TOKEN, mh);
    let app = app(anchors([0u8; 32], *orch_signing_key().verifying_key()), manifest(&[]), members.clone());

    let resp = app.oneshot(chat_request(Some(TOKEN))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let mut body = resp.into_body();
    let _first = body.frame().await; // first relayed token
    assert!(members.revoke_by_member_hash(&mh));

    let mut rest = String::new();
    while let Some(Ok(frame)) = body.frame().await {
        if let Ok(data) = frame.into_data() {
            rest.push_str(&String::from_utf8_lossy(&data));
        }
    }

    assert!(rest.contains("revoked"), "revocation must cut the stream: {rest}");
    assert!(!rest.contains("[DONE]"), "a revoked stream must not complete normally");
}
