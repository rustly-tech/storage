use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result};
use rustly_artifact_gateway::{router, GatewayState};
use rustly_store::{FilesystemStore, ObjectStore, S3Config, S3Store};
use rustly_upload_protocol::UploadTokens;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "rustly_artifact_gateway=info".into()),
        )
        .json()
        .init();

    let token_secret = required_secret("RUSTLY_ARTIFACT_TOKEN_SECRET")?;
    let read_secret = required_secret("RUSTLY_ARTIFACT_READ_SECRET")?;
    let store: Arc<dyn ObjectStore> = match std::env::var("RUSTLY_S3_ENDPOINT") {
        Ok(endpoint) => Arc::new(S3Store::new(S3Config {
            endpoint,
            region: required("RUSTLY_S3_REGION")?,
            bucket: required("RUSTLY_S3_BUCKET")?,
            access_key_id: required("RUSTLY_S3_ACCESS_KEY_ID")?,
            secret_access_key: required("RUSTLY_S3_SECRET_ACCESS_KEY")?,
            prefix: std::env::var("RUSTLY_S3_PREFIX").unwrap_or_else(|_| "rustly".into()),
            max_object_bytes: rustly_artifact_gateway::MAX_SOURCE_BYTES,
            request_timeout: Duration::from_secs(15),
            max_attempts: 3,
        })?),
        Err(_) => Arc::new(
            FilesystemStore::open(
                std::env::var("RUSTLY_ARTIFACT_DIR").unwrap_or_else(|_| ".rustly-artifacts".into()),
            )
            .await?,
        ),
    };
    let state = GatewayState {
        store,
        upload_tokens: UploadTokens::new(token_secret)?,
        read_secret,
    };
    let bind = std::env::var("RUSTLY_ARTIFACT_BIND").unwrap_or_else(|_| "0.0.0.0:8081".into());
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .with_context(|| format!("binding {bind}"))?;
    tracing::info!(%bind, "artifact gateway listening");
    axum::serve(listener, router(state)).await?;
    Ok(())
}

fn required(name: &'static str) -> Result<String> {
    std::env::var(name).with_context(|| format!("{name} is required"))
}

fn required_secret(name: &'static str) -> Result<Vec<u8>> {
    let secret = required(name)?;
    anyhow::ensure!(secret.len() >= 32, "{name} must be at least 32 bytes");
    Ok(secret.into_bytes())
}
