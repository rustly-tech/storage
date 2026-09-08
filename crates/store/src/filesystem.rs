//! A filesystem [`ObjectStore`].
//!
//! The store a worker or a seed actually runs. Objects are sharded two levels
//! deep by digest, so no directory ever holds millions of entries, and content
//! is written to a temporary file and renamed, so a crash mid-write cannot leave
//! a truncated object under a valid-looking name.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use rustly_cas::{Cid, Manifest, Provenance};

use crate::store::{Entry, ObjectStore, StoreError, StoreResult};

fn unavailable(context: &str, error: impl std::fmt::Display) -> StoreError {
    StoreError::Unavailable(format!("{context}: {error}"))
}

/// A filesystem-backed object store.
#[derive(Debug, Clone)]
pub struct FilesystemStore {
    root: PathBuf,
}

impl FilesystemStore {
    /// Open, creating the root if needed.
    pub async fn open(root: impl Into<PathBuf>) -> StoreResult<Self> {
        let root = root.into();
        tokio::fs::create_dir_all(&root)
            .await
            .map_err(|e| unavailable("creating the store root", e))?;
        Ok(Self { root })
    }

    /// The store root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn object_path(&self, cid: &Cid) -> PathBuf {
        let (a, b, name) = cid.shard_path();
        self.root.join("objects").join(a).join(b).join(name)
    }

    fn entry_path(&self, cid: &Cid) -> PathBuf {
        let (a, b, name) = cid.shard_path();
        self.root
            .join("entries")
            .join(a)
            .join(b)
            .join(format!("{name}.json"))
    }

    async fn write_atomically(&self, path: &Path, bytes: &[u8]) -> StoreResult<()> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| unavailable("creating a shard directory", e))?;
        }
        // Write then rename. A crash between the two leaves a `.partial` file
        // that no reader looks for, rather than a truncated object under a name
        // that promises different content.
        let temporary = path.with_extension("partial");
        tokio::fs::write(&temporary, bytes)
            .await
            .map_err(|e| unavailable("writing an object", e))?;
        tokio::fs::rename(&temporary, path)
            .await
            .map_err(|e| unavailable("renaming an object into place", e))?;
        Ok(())
    }
}

#[async_trait]
impl ObjectStore for FilesystemStore {
    fn id(&self) -> &'static str {
        "filesystem"
    }

    async fn put(&self, content: &[u8], provenance: Provenance) -> StoreResult<Cid> {
        let manifest = Manifest::build(content, None);
        let cid = manifest.cid.clone();

        self.write_atomically(&self.object_path(&cid), content)
            .await?;
        let entry = Entry {
            manifest,
            provenance,
        };
        let encoded = serde_json::to_vec_pretty(&EntryOnDisk::from(&entry))
            .map_err(|e| unavailable("encoding an entry", e))?;
        self.write_atomically(&self.entry_path(&cid), &encoded)
            .await?;
        Ok(cid)
    }

    async fn get(&self, cid: &Cid) -> StoreResult<Option<Vec<u8>>> {
        let path = self.object_path(cid);
        let content = match tokio::fs::read(&path).await {
            Ok(content) => content,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(unavailable("reading an object", e)),
        };

        // Verified on every read, not only on write. Verifying on write alone
        // would mean trusting the disk and every process that can reach it.
        if !cid.verifies(&content) {
            let actual = Cid::of(&content);
            // Evict before returning, so the next read is a clean miss rather
            // than a repeat of the same failure.
            let _ = tokio::fs::remove_file(&path).await;
            let _ = tokio::fs::remove_file(self.entry_path(cid)).await;
            tracing::warn!(cid = %cid, %actual, "evicted an object that failed verification");
            return Err(StoreError::Integrity {
                cid: cid.to_string(),
                detail: format!("content hashes to {actual}"),
            });
        }
        Ok(Some(content))
    }

    async fn head(&self, cid: &Cid) -> StoreResult<Option<Entry>> {
        match tokio::fs::read(self.entry_path(cid)).await {
            Ok(bytes) => {
                let on_disk: EntryOnDisk =
                    serde_json::from_slice(&bytes).map_err(|e| StoreError::Integrity {
                        cid: cid.to_string(),
                        detail: format!("entry metadata is corrupt: {e}"),
                    })?;
                Ok(Some(on_disk.into()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(unavailable("reading entry metadata", e)),
        }
    }

    async fn contains(&self, cid: &Cid) -> StoreResult<bool> {
        Ok(tokio::fs::try_exists(self.object_path(cid))
            .await
            .map_err(|e| unavailable("checking for an object", e))?)
    }

    async fn remove(&self, cid: &Cid) -> StoreResult<()> {
        let _ = tokio::fs::remove_file(self.object_path(cid)).await;
        let _ = tokio::fs::remove_file(self.entry_path(cid)).await;
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
        let Some(mut entry) = self.head(cid).await? else {
            return Err(StoreError::Unavailable(format!("{cid} is not held here")));
        };
        entry.provenance.trust = entry.provenance.trust.promote_after_reproduction();
        let encoded = serde_json::to_vec_pretty(&EntryOnDisk::from(&entry))
            .map_err(|e| unavailable("encoding an entry", e))?;
        self.write_atomically(&self.entry_path(cid), &encoded).await
    }
}

/// The on-disk shape of an entry.
///
/// A named type rather than serialising `Entry` directly, so the storage format
/// can change without dragging the in-memory type along, and so the manifest
/// version is visible in every file on disk.
#[derive(serde::Serialize, serde::Deserialize)]
struct EntryOnDisk {
    manifest: Manifest,
    provenance: Provenance,
}

impl From<&Entry> for EntryOnDisk {
    fn from(entry: &Entry) -> Self {
        Self {
            manifest: entry.manifest.clone(),
            provenance: entry.provenance.clone(),
        }
    }
}

impl From<EntryOnDisk> for Entry {
    fn from(on_disk: EntryOnDisk) -> Self {
        Self {
            manifest: on_disk.manifest,
            provenance: on_disk.provenance,
        }
    }
}
