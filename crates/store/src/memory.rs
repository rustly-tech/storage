//! An in-memory [`ObjectStore`].
//!
//! Used by tests and by `dev` runs with no disk. It passes the same conformance
//! suite as the filesystem backend, which is what makes it legitimate for
//! everything above this layer to be tested against it.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use rustly_cas::{Cid, Manifest, Provenance};
use tokio::sync::RwLock;

use crate::store::{Entry, ObjectStore, StoreError, StoreResult};

#[derive(Debug, Default)]
struct Inner {
    content: HashMap<Cid, Vec<u8>>,
    entries: HashMap<Cid, Entry>,
}

/// An in-memory object store.
#[derive(Debug, Clone, Default)]
pub struct MemoryStore {
    inner: Arc<RwLock<Inner>>,
}

impl MemoryStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of objects held.
    pub async fn len(&self) -> usize {
        self.inner.read().await.content.len()
    }

    /// Whether the store is empty.
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    /// Corrupt an entry in place. Test helper: there is no other way to
    /// exercise the verify-on-read path, and that path is the point of the
    /// whole design.
    pub async fn corrupt_for_test(&self, cid: &Cid, replacement: Vec<u8>) {
        self.inner
            .write()
            .await
            .content
            .insert(cid.clone(), replacement);
    }
}

#[async_trait]
impl ObjectStore for MemoryStore {
    fn id(&self) -> &'static str {
        "memory"
    }

    async fn put(&self, content: &[u8], provenance: Provenance) -> StoreResult<Cid> {
        let manifest = Manifest::build(content, None);
        let cid = manifest.cid.clone();
        let mut inner = self.inner.write().await;
        inner.content.insert(cid.clone(), content.to_vec());
        inner.entries.insert(
            cid.clone(),
            Entry {
                manifest,
                provenance,
            },
        );
        Ok(cid)
    }

    async fn get(&self, cid: &Cid) -> StoreResult<Option<Vec<u8>>> {
        let content = { self.inner.read().await.content.get(cid).cloned() };
        let Some(content) = content else {
            return Ok(None);
        };

        // Verified on every read. In memory this can only fail if something
        // wrote through `corrupt_for_test`, but the code path must be identical
        // to the filesystem backend or the conformance suite proves nothing.
        if !cid.verifies(&content) {
            let mut inner = self.inner.write().await;
            inner.content.remove(cid);
            inner.entries.remove(cid);
            return Err(StoreError::Integrity {
                cid: cid.to_string(),
                detail: format!("content hashes to {}", Cid::of(&content)),
            });
        }
        Ok(Some(content))
    }

    async fn head(&self, cid: &Cid) -> StoreResult<Option<Entry>> {
        Ok(self.inner.read().await.entries.get(cid).cloned())
    }

    async fn contains(&self, cid: &Cid) -> StoreResult<bool> {
        Ok(self.inner.read().await.content.contains_key(cid))
    }

    async fn remove(&self, cid: &Cid) -> StoreResult<()> {
        let mut inner = self.inner.write().await;
        inner.content.remove(cid);
        inner.entries.remove(cid);
        Ok(())
    }

    async fn promote(&self, cid: &Cid, reproduced: &[u8]) -> StoreResult<()> {
        if !cid.verifies(reproduced) {
            self.remove(cid).await?;
            return Err(StoreError::Integrity {
                cid: cid.to_string(),
                detail: format!(
                    "a trusted rebuild produced {}; the quarantined copy was destroyed",
                    Cid::of(reproduced)
                ),
            });
        }
        let mut inner = self.inner.write().await;
        if let Some(entry) = inner.entries.get_mut(cid) {
            entry.provenance.trust = entry.provenance.trust.promote_after_reproduction();
        }
        Ok(())
    }
}
