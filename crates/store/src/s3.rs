//! S3-compatible remote [`ObjectStore`] adapter.
//!
//! The provider client is confined to this module. Callers depend on
//! [`ObjectStore`], and Backblaze B2, MinIO, AWS S3, or another compatible
//! service is selected entirely through configuration.

use std::time::Duration;

use async_trait::async_trait;
use rustly_cas::{Cid, Manifest, Provenance};
use s3::bucket::Bucket;
use s3::creds::Credentials;
use s3::region::Region;

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
    bucket: Bucket,
    prefix: String,
    max_object_bytes: usize,
    request_timeout: Duration,
    max_attempts: usize,
}

impl S3Store {
    /// Construct an adapter from explicit configuration.
    pub fn new(config: S3Config) -> StoreResult<Self> {
        config.validate()?;
        let credentials = Credentials::new(
            Some(&config.access_key_id),
            Some(&config.secret_access_key),
            None,
            None,
            None,
        )
        .map_err(|error| StoreError::Unavailable(format!("S3 credentials: {error}")))?;
        let region = Region::Custom {
            region: config.region,
            endpoint: config.endpoint,
        };
        let bucket = Bucket::new(&config.bucket, region, credentials)
            .map_err(|error| StoreError::Unavailable(format!("S3 client: {error}")))?
            .with_path_style()
            .with_request_timeout(config.request_timeout)
            .map_err(|error| StoreError::Unavailable(format!("S3 timeout: {error}")))?;
        Ok(Self {
            bucket: *bucket,
            prefix: config.prefix.trim_matches('/').to_owned(),
            max_object_bytes: config.max_object_bytes,
            request_timeout: config.request_timeout,
            max_attempts: config.max_attempts,
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

    async fn request<T, E, F, Fut, P>(
        &self,
        operation: &'static str,
        mut send: F,
        retryable_response: P,
    ) -> StoreResult<T>
    where
        E: std::fmt::Display,
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T, E>>,
        P: Fn(&T) -> bool,
    {
        let mut last = String::new();
        for attempt in 1..=self.max_attempts {
            match tokio::time::timeout(self.request_timeout, send()).await {
                Ok(Ok(response)) if !retryable_response(&response) => return Ok(response),
                Ok(Ok(_)) => last = format!("{operation} returned a retryable response"),
                Ok(Err(error)) => last = format!("{operation}: {error}"),
                Err(_) => last = format!("{operation} timed out"),
            }
            if attempt < self.max_attempts {
                tokio::time::sleep(Duration::from_millis(50 * attempt as u64)).await;
            }
        }
        Err(StoreError::Unavailable(format!(
            "{last} after {} attempt(s)",
            self.max_attempts
        )))
    }

    fn ensure_status(operation: &str, status: u16) -> StoreResult<()> {
        if (200..300).contains(&status) {
            Ok(())
        } else {
            Err(StoreError::Unavailable(format!(
                "{operation} returned HTTP {status}"
            )))
        }
    }

    async fn put_bytes(&self, key: String, bytes: &[u8]) -> StoreResult<()> {
        let response = self
            .request(
                "put object",
                || self.bucket.put_object(&key, bytes),
                |response| response.status_code() == 429 || response.status_code() >= 500,
            )
            .await?;
        Self::ensure_status("put object", response.status_code())
    }

    async fn delete_key(&self, key: String) -> StoreResult<()> {
        let response = self
            .request(
                "delete object",
                || self.bucket.delete_object(&key),
                |response| response.status_code() == 429 || response.status_code() >= 500,
            )
            .await?;
        if response.status_code() == 404 {
            return Ok(());
        }
        Self::ensure_status("delete object", response.status_code())
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
        let key = self.object_key(cid);
        let response = self
            .request(
                "get object",
                || self.bucket.get_object(&key),
                |response| response.status_code() == 429 || response.status_code() >= 500,
            )
            .await?;
        if response.status_code() == 404 {
            return Ok(None);
        }
        Self::ensure_status("get object", response.status_code())?;
        let bytes = response.to_vec();
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
        let key = self.entry_key(cid);
        let response = self
            .request(
                "get entry",
                || self.bucket.get_object(&key),
                |response| response.status_code() == 429 || response.status_code() >= 500,
            )
            .await?;
        if response.status_code() == 404 {
            return Ok(None);
        }
        Self::ensure_status("get entry", response.status_code())?;
        let remote: EntryRemote =
            serde_json::from_slice(response.as_slice()).map_err(|error| StoreError::Integrity {
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
        let key = self.object_key(cid);
        let (_, status) = self
            .request(
                "head object",
                || self.bucket.head_object(&key),
                |(_, status)| *status == 429 || *status >= 500,
            )
            .await?;
        match status {
            200..=299 => Ok(true),
            404 => Ok(false),
            status => Err(StoreError::Unavailable(format!(
                "head object returned HTTP {status}"
            ))),
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
