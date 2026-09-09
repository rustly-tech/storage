//! HTTP boundary for verified source uploads and trusted artifact reads.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::routing::{get, put};
use axum::{Json, Router};
use rustly_cas::{Cid, Provenance};
use rustly_store::ObjectStore;
use rustly_upload_protocol::{UploadReceipt, UploadTokens};
use serde::Serialize;
use subtle::ConstantTimeEq;
use tower_http::cors::{Any, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

/// Maximum source file accepted by the public upload route.
pub const MAX_SOURCE_BYTES: usize = 256 * 1024;

/// Gateway dependencies.
#[derive(Clone)]
pub struct GatewayState {
    /// Content-addressed storage backend.
    pub store: Arc<dyn ObjectStore>,
    /// Upload grant and receipt signer.
    pub upload_tokens: UploadTokens,
    /// Separate credential for trusted judge reads.
    pub read_secret: Vec<u8>,
}

/// Successful source upload.
#[derive(Debug, Clone, Serialize)]
pub struct UploadResponse {
    /// Verified content identifier.
    pub cid: String,
    /// Verified byte count.
    pub size: u64,
    /// Signed proof consumable by the metadata API.
    pub receipt: String,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    code: &'static str,
    message: String,
}

type HttpError = (StatusCode, Json<ErrorBody>);

fn error(status: StatusCode, code: &'static str, message: impl Into<String>) -> HttpError {
    (
        status,
        Json(ErrorBody {
            code,
            message: message.into(),
        }),
    )
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Build the gateway router.
pub fn router(state: GatewayState) -> Router {
    Router::new()
        .route("/health", get(|| async { StatusCode::NO_CONTENT }))
        .route("/api/v1/uploads/{cid}", put(upload))
        .route(
            "/api/v1/artifacts/{cid}",
            get(read_artifact).put(write_trusted_artifact),
        )
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::PUT])
                .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]),
        )
        .layer(RequestBodyLimitLayer::new(MAX_SOURCE_BYTES))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn write_trusted_artifact(
    State(state): State<GatewayState>,
    Path(cid_text): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, HttpError> {
    require_trusted(&state, &headers)?;
    let expected: Cid = cid_text.parse().map_err(|_| {
        error(
            StatusCode::BAD_REQUEST,
            "invalid_cid",
            "CID is not canonical BLAKE3",
        )
    })?;
    if !expected.verifies(&body) {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "integrity_failure",
            "artifact bytes do not match the requested CID",
        ));
    }
    let stored = state
        .store
        .put(&body, Provenance::trusted_only())
        .await
        .map_err(|error_value| {
            tracing::error!(%error_value, "trusted artifact write failed");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "storage_unavailable",
                "artifact storage is unavailable",
            )
        })?;
    if stored != expected {
        return Err(error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "stored artifact identifier mismatch",
        ));
    }
    Ok(StatusCode::NO_CONTENT)
}

fn require_trusted(state: &GatewayState, headers: &HeaderMap) -> Result<(), HttpError> {
    let provided = bearer(headers).unwrap_or_default().as_bytes();
    if provided.ct_eq(&state.read_secret).unwrap_u8() != 1 {
        return Err(error(
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "trusted artifact credential required",
        ));
    }
    Ok(())
}

async fn upload(
    State(state): State<GatewayState>,
    Path(cid_text): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<UploadResponse>), HttpError> {
    let token = bearer(&headers).ok_or_else(|| {
        error(
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "upload grant required",
        )
    })?;
    let grant = state
        .upload_tokens
        .verify_grant(token, unix_now())
        .map_err(|_| {
            error(
                StatusCode::UNAUTHORIZED,
                "unauthenticated",
                "invalid or expired upload grant",
            )
        })?;
    if grant.cid != cid_text || grant.size != body.len() as u64 {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "invalid_upload",
            "upload does not match its grant",
        ));
    }
    let expected: Cid = cid_text.parse().map_err(|_| {
        error(
            StatusCode::BAD_REQUEST,
            "invalid_upload",
            "CID is not canonical BLAKE3",
        )
    })?;
    if !expected.verifies(&body) {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "integrity_failure",
            "source bytes do not match the requested CID",
        ));
    }
    let stored = state
        .store
        .put(&body, Provenance::trusted_only())
        .await
        .map_err(|error_value| {
            tracing::error!(%error_value, "source upload failed");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "storage_unavailable",
                "artifact storage is unavailable",
            )
        })?;
    if stored != expected {
        return Err(error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "stored artifact identifier mismatch",
        ));
    }

    let receipt = UploadReceipt {
        user_id: grant.user_id,
        cid: stored.to_string(),
        size: body.len() as u64,
        // Keep the receipt valid long enough for a browser to retry submission
        // creation after an interrupted request without uploading again.
        expires_at: unix_now() + 24 * 60 * 60,
        nonce: grant.nonce,
    };
    Ok((
        StatusCode::CREATED,
        Json(UploadResponse {
            cid: receipt.cid.clone(),
            size: receipt.size,
            receipt: state.upload_tokens.sign_receipt(&receipt),
        }),
    ))
}

async fn read_artifact(
    State(state): State<GatewayState>,
    Path(cid_text): Path<String>,
    headers: HeaderMap,
) -> Result<Bytes, HttpError> {
    require_trusted(&state, &headers)?;
    let cid: Cid = cid_text.parse().map_err(|_| {
        error(
            StatusCode::BAD_REQUEST,
            "invalid_cid",
            "CID is not canonical BLAKE3",
        )
    })?;
    let bytes = state
        .store
        .get_for_judging(&cid)
        .await
        .map_err(|error_value| {
            tracing::error!(%error_value, "artifact read failed");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "storage_unavailable",
                "artifact storage is unavailable",
            )
        })?
        .ok_or_else(|| error(StatusCode::NOT_FOUND, "not_found", "artifact not found"))?;
    Ok(Bytes::from(bytes))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::Request;
    use rustly_store::MemoryStore;
    use rustly_upload_protocol::UploadGrant;
    use tower::ServiceExt as _;

    use super::*;

    fn fixture() -> (Router, UploadTokens, Vec<u8>) {
        let tokens = UploadTokens::new(vec![0x51; 32]).unwrap();
        let read_secret = vec![0x52; 32];
        let state = GatewayState {
            store: Arc::new(MemoryStore::new()),
            upload_tokens: tokens.clone(),
            read_secret: read_secret.clone(),
        };
        (router(state), tokens, read_secret)
    }

    #[tokio::test]
    async fn upload_hashes_stores_receipts_and_allows_only_trusted_reads() {
        let (app, tokens, read_secret) = fixture();
        let source = b"fn main() {}";
        let cid = Cid::of(source).to_string();
        let grant = tokens.sign_grant(&UploadGrant {
            user_id: "user-1".into(),
            cid: cid.clone(),
            size: source.len() as u64,
            expires_at: unix_now() + 60,
            nonce: "nonce".into(),
        });
        let upload = Request::builder()
            .method("PUT")
            .uri(format!("/api/v1/uploads/{cid}"))
            .header("authorization", format!("Bearer {grant}"))
            .body(Body::from(source.as_slice()))
            .unwrap();
        let response = app.clone().oneshot(upload).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        let denied = Request::builder()
            .uri(format!("/api/v1/artifacts/{cid}"))
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(denied).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );

        let read = Request::builder()
            .uri(format!("/api/v1/artifacts/{cid}"))
            .header(
                "authorization",
                format!("Bearer {}", String::from_utf8(read_secret).unwrap()),
            )
            .body(Body::empty())
            .unwrap();
        assert_eq!(app.oneshot(read).await.unwrap().status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn a_valid_grant_cannot_store_different_bytes() {
        let (app, tokens, _) = fixture();
        let cid = Cid::of(b"expected").to_string();
        let grant = tokens.sign_grant(&UploadGrant {
            user_id: "user-1".into(),
            cid: cid.clone(),
            size: 8,
            expires_at: unix_now() + 60,
            nonce: "nonce".into(),
        });
        let request = Request::builder()
            .method("PUT")
            .uri(format!("/api/v1/uploads/{cid}"))
            .header("authorization", format!("Bearer {grant}"))
            .body(Body::from("tampered"))
            .unwrap();
        assert_eq!(
            app.oneshot(request).await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn trusted_writes_are_authenticated_and_content_verified() {
        let (app, _, read_secret) = fixture();
        let bytes = b"trusted evaluation package";
        let cid = Cid::of(bytes).to_string();
        let denied = Request::builder()
            .method("PUT")
            .uri(format!("/api/v1/artifacts/{cid}"))
            .body(Body::from(bytes.as_slice()))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(denied).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );

        let write = Request::builder()
            .method("PUT")
            .uri(format!("/api/v1/artifacts/{cid}"))
            .header(
                "authorization",
                format!("Bearer {}", String::from_utf8(read_secret.clone()).unwrap()),
            )
            .body(Body::from(bytes.as_slice()))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(write).await.unwrap().status(),
            StatusCode::NO_CONTENT
        );

        let read = Request::builder()
            .uri(format!("/api/v1/artifacts/{cid}"))
            .header(
                "authorization",
                format!("Bearer {}", String::from_utf8(read_secret).unwrap()),
            )
            .body(Body::empty())
            .unwrap();
        assert_eq!(app.oneshot(read).await.unwrap().status(), StatusCode::OK);
    }
}
