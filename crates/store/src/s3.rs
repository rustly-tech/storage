//! S3-compatible remote [`ObjectStore`] adapter.
//!
//! The provider client is confined to this module. Callers depend on
//! [`ObjectStore`], and Backblaze B2, MinIO, AWS S3, or another compatible
//! service is selected entirely through configuration.

use std::time::Duration;

use async_trait::async_trait;
use object_store::aws::{AmazonS3, AmazonS3Builder};
use object_store::path::Path;
use object_store::{ObjectStoreExt, RetryConfig};
use rustly_cas::{Cid, Manifest, Provenance};

use crate::store::{Entry, ObjectStore, StoreError, StoreResult};

/// Configuration for an S3-compatible store.
#[derive(Clone)]
pub struct S3Config {
    /// HTTPS endpoint, without the bucket name.
    pub endpoint: String,
    /// Signing region used by the compatible service.
    pub region: String,
    /// Private bucket name.
    pub bucket: String,
    /// Application/access key identifier.
    pub access_key_id: String,
    /// Application/secret key.
    pub secret_access_key: String,
    /// Prefix reserved for this deployment.
    pub prefix: String,
    /// Maximum object accepted by this adapter.
    pub max_object_bytes: usize,
    /// Timeout applied independently to every provider call.
    pub request_timeout: Duration,
    /// Total attempts for transient provider or transport failures.
    pub max_attempts: usize,
}

impl S3Config {
    fn validate(&self) -> StoreResult<()> {
        if !self.endpoint.starts_with("https://") && !self.endpoint.starts_with("http://127.0.0.1")
        {
            return Err(StoreError::Unavailable(
                "S3 endpoint must use HTTPS (HTTP is accepted only for loopback tests)".into(),
            ));
        }
        if self.region.is_empty()
            || self.bucket.is_empty()
            || self.access_key_id.is_empty()
            || self.secret_access_key.is_empty()
            || self.max_object_bytes == 0
            || self.request_timeout.is_zero()
            || self.max_attempts == 0
        {
            return Err(StoreError::Unavailable(
                "S3 region, bucket, credentials, size limit, and timeout are required".into(),
            ));
        }
        Ok(())
    }
}

/// An object store backed by any S3-compatible private bucket.
#[derive(Clone)]
pub struct S3Store {
    store: AmazonS3,
    prefix: String,
    max_object_bytes: usize,
    request_timeout: Duration,
}

impl S3Store {
    /// Construct an adapter from explicit configuration.
    pub fn new(config: S3Config) -> StoreResult<Self> {
        config.validate()?;
        let allow_http = config.endpoint.starts_with("http://127.0.0.1");
        let retry = RetryConfig {
            max_retries: config.max_attempts.saturating_sub(1),
            retry_timeout: config.request_timeout,
            ..RetryConfig::default()
        };
        let store = AmazonS3Builder::new()
            .with_bucket_name(config.bucket)
            .with_region(config.region)
            .with_endpoint(config.endpoint)
            .with_access_key_id(config.access_key_id)
            .with_secret_access_key(config.secret_access_key)
            .with_virtual_hosted_style_request(false)
            .with_allow_http(allow_http)
            .with_retry(retry)
            .build()
            .map_err(|error| StoreError::Unavailable(format!("S3 client: {error}")))?;
        Ok(Self {
            store,
            prefix: config.prefix.trim_matches('/').to_owned(),
            max_object_bytes: config.max_object_bytes,
            request_timeout: config.request_timeout,
        })
    }

    fn key(&self, kind: &str, cid: &Cid, suffix: &str) -> String {
        let digest = cid.digest();
        let path = format!(
            "{kind}/{}/{}/{}{}",
            &digest[..2],
            &digest[2..4],
            digest,
            suffix
        );
        if self.prefix.is_empty() {
            path
        } else {
            format!("{}/{path}", self.prefix)
        }
    }

    fn object_key(&self, cid: &Cid) -> String {
        self.key("objects", cid, "")
    }

    fn entry_key(&self, cid: &Cid) -> String {
        self.key("entries", cid, ".json")
    }

    async fn request<T, F, Fut>(&self, operation: &'static str, send: F) -> StoreResult<T>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = object_store::Result<T>>,
    {
        match tokio::time::timeout(self.request_timeout, send()).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(error)) => Err(StoreError::Unavailable(format!("{operation}: {error}"))),
            Err(_) => Err(StoreError::Unavailable(format!("{operation} timed out"))),
        }
    }

    fn path(&self, key: String) -> Path {
        Path::from(key)
    }

    async fn put_bytes(&self, key: String, bytes: &[u8]) -> StoreResult<()> {
        let path = self.path(key);
        self.request("put object", || {
            self.store.put(&path, bytes.to_vec().into())
        })
        .await?;
        Ok(())
    }

    async fn delete_key(&self, key: String) -> StoreResult<()> {
        let path = self.path(key);
        match tokio::time::timeout(self.request_timeout, self.store.delete(&path)).await {
            Ok(Ok(())) | Ok(Err(object_store::Error::NotFound { .. })) => Ok(()),
            Ok(Err(error)) => Err(StoreError::Unavailable(format!("delete object: {error}"))),
            Err(_) => Err(StoreError::Unavailable("delete object timed out".into())),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct EntryRemote {
    manifest: Manifest,
    provenance: Provenance,
}

#[async_trait]
impl ObjectStore for S3Store {
    fn id(&self) -> &'static str {
        "s3"
    }

    async fn put(&self, content: &[u8], provenance: Provenance) -> StoreResult<Cid> {
        if content.len() > self.max_object_bytes {
            return Err(StoreError::Unavailable(format!(
                "object is {} bytes; limit is {} bytes",
                content.len(),
                self.max_object_bytes
            )));
        }
        let manifest = Manifest::build(content, None);
        let cid = manifest.cid.clone();
        self.put_bytes(self.object_key(&cid), content).await?;
        let metadata = serde_json::to_vec(&EntryRemote {
            manifest,
            provenance,
        })
        .map_err(|error| StoreError::Unavailable(format!("encode entry: {error}")))?;
        if let Err(error) = self.put_bytes(self.entry_key(&cid), &metadata).await {
            let _ = self.delete_key(self.object_key(&cid)).await;
            return Err(error);
        }
        Ok(cid)
    }

    async fn get(&self, cid: &Cid) -> StoreResult<Option<Vec<u8>>> {
        let path = self.path(self.object_key(cid));
        let response = match tokio::time::timeout(self.request_timeout, self.store.get(&path)).await
        {
            Ok(Ok(response)) => response,
            Ok(Err(object_store::Error::NotFound { .. })) => return Ok(None),
            Ok(Err(error)) => return Err(StoreError::Unavailable(format!("get object: {error}"))),
            Err(_) => return Err(StoreError::Unavailable("get object timed out".into())),
        };
        let bytes = tokio::time::timeout(self.request_timeout, response.bytes())
            .await
            .map_err(|_| StoreError::Unavailable("read object body timed out".into()))?
            .map_err(|error| StoreError::Unavailable(format!("read object body: {error}")))?
            .to_vec();
        if bytes.len() > self.max_object_bytes || !cid.verifies(&bytes) {
            let actual = Cid::of(&bytes);
            let _ = self.remove(cid).await;
            return Err(StoreError::Integrity {
                cid: cid.to_string(),
                detail: format!("content is {} bytes and hashes to {actual}", bytes.len()),
            });
        }
        Ok(Some(bytes))
    }

    async fn head(&self, cid: &Cid) -> StoreResult<Option<Entry>> {
        let path = self.path(self.entry_key(cid));
        let response = match tokio::time::timeout(self.request_timeout, self.store.get(&path)).await
        {
            Ok(Ok(response)) => response,
            Ok(Err(object_store::Error::NotFound { .. })) => return Ok(None),
            Ok(Err(error)) => return Err(StoreError::Unavailable(format!("get entry: {error}"))),
            Err(_) => return Err(StoreError::Unavailable("get entry timed out".into())),
        };
        let bytes = tokio::time::timeout(self.request_timeout, response.bytes())
            .await
            .map_err(|_| StoreError::Unavailable("read entry body timed out".into()))?
            .map_err(|error| StoreError::Unavailable(format!("read entry body: {error}")))?;
        let remote: EntryRemote =
            serde_json::from_slice(&bytes).map_err(|error| StoreError::Integrity {
                cid: cid.to_string(),
                detail: format!("entry metadata is corrupt: {error}"),
            })?;
        if remote.manifest.cid != *cid || remote.manifest.validate().is_err() {
            let _ = self.remove(cid).await;
            return Err(StoreError::Integrity {
                cid: cid.to_string(),
                detail: "entry metadata does not describe the requested CID".into(),
            });
        }
        Ok(Some(Entry {
            manifest: remote.manifest,
            provenance: remote.provenance,
        }))
    }

    async fn contains(&self, cid: &Cid) -> StoreResult<bool> {
        let path = self.path(self.object_key(cid));
        match tokio::time::timeout(self.request_timeout, self.store.head(&path)).await {
            Ok(Ok(_)) => Ok(true),
            Ok(Err(object_store::Error::NotFound { .. })) => Ok(false),
            Ok(Err(error)) => Err(StoreError::Unavailable(format!("head object: {error}"))),
            Err(_) => Err(StoreError::Unavailable("head object timed out".into())),
        }
    }

    async fn remove(&self, cid: &Cid) -> StoreResult<()> {
        let object = self.delete_key(self.object_key(cid));
        let entry = self.delete_key(self.entry_key(cid));
        let (object, entry) = tokio::join!(object, entry);
        object.and(entry)
    }

    async fn promote(&self, cid: &Cid, reproduced: &[u8]) -> StoreResult<()> {
        if !cid.verifies(reproduced) {
            self.remove(cid).await?;
            return Err(StoreError::Integrity {
                cid: cid.to_string(),
                detail: format!("trusted rebuild hashes to {}", Cid::of(reproduced)),
            });
        }
        let Some(mut entry) = self.head(cid).await? else {
            return Err(StoreError::Unavailable(format!("{cid} is not held here")));
        };
        entry.provenance.trust = entry.provenance.trust.promote_after_reproduction();
        let metadata = serde_json::to_vec(&EntryRemote {
            manifest: entry.manifest,
            provenance: entry.provenance,
        })
        .map_err(|error| StoreError::Unavailable(format!("encode entry: {error}")))?;
        self.put_bytes(self.entry_key(cid), &metadata).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(endpoint: &str) -> S3Config {
        S3Config {
            endpoint: endpoint.into(),
            region: "us-east-1".into(),
            bucket: "rustly".into(),
            access_key_id: "access".into(),
            secret_access_key: "secret".into(),
            prefix: "test".into(),
            max_object_bytes: 1024,
            request_timeout: Duration::from_secs(1),
            max_attempts: 3,
        }
    }

    #[test]
    fn remote_endpoints_are_encrypted_except_for_loopback_tests() {
        assert!(S3Store::new(config("https://s3.example.test")).is_ok());
        assert!(S3Store::new(config("http://127.0.0.1:9000")).is_ok());
        assert!(S3Store::new(config("http://object-store.example.test")).is_err());
    }
}
