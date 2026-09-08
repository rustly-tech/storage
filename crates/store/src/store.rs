//! The [`ObjectStore`] trait.

use async_trait::async_trait;
use rustly_cas::{Cid, Distribution, Manifest, Provenance, TrustState};

/// Something went wrong reaching or reading the store.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The store could not be reached or read.
    #[error("store unavailable: {0}")]
    Unavailable(String),

    /// Content did not hash to the CID it was stored under.
    ///
    /// The store evicts the entry before returning this, so the next read is a
    /// clean miss rather than a repeat failure. Callers must treat it as
    /// "rebuild or re-fetch", never as a statement about the caller's input.
    #[error("integrity failure for {cid}: {detail}")]
    Integrity {
        /// The CID that was requested.
        cid: String,
        /// What was wrong.
        detail: String,
    },

    /// The caller asked to distribute something that must not be distributed.
    #[error("refusing to serve {cid}: it is marked {distribution:?}")]
    DistributionRefused {
        /// The CID.
        cid: String,
        /// Its distribution class.
        distribution: Distribution,
    },
}

/// Convenience alias.
pub type StoreResult<T> = Result<T, StoreError>;

/// An entry as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The manifest describing the object.
    pub manifest: Manifest,
    /// Where it came from and how far it may travel.
    pub provenance: Provenance,
}

/// A store of immutable, content-addressed objects.
#[async_trait]
pub trait ObjectStore: Send + Sync {
    /// Stable identifier, for diagnostics and metrics.
    fn id(&self) -> &'static str;

    /// Store `content`, returning its CID.
    ///
    /// The caller does not choose the key: it is the hash of the content, so a
    /// mislabelled entry cannot exist.
    async fn put(&self, content: &[u8], provenance: Provenance) -> StoreResult<Cid>;

    /// Read an object, verifying it against its CID.
    ///
    /// `Ok(None)` is a miss. `Err(Integrity)` means the entry was corrupt and
    /// has been evicted.
    async fn get(&self, cid: &Cid) -> StoreResult<Option<Vec<u8>>>;

    /// Read an object's metadata without reading its content.
    async fn head(&self, cid: &Cid) -> StoreResult<Option<Entry>>;

    /// Whether an object is present. Does not read content, so it is not an
    /// integrity check.
    async fn contains(&self, cid: &Cid) -> StoreResult<bool>;

    /// Remove an object. Used to evict corruption and to reclaim space.
    async fn remove(&self, cid: &Cid) -> StoreResult<()>;

    /// Promote a quarantined object after trusted capacity reproduced it.
    ///
    /// `reproduced` must be the bytes trusted capacity produced. If they do not
    /// hash to `cid`, the quarantined copy is destroyed and the mismatch is
    /// reported: two builds of the same inputs disagreeing is a serious signal.
    async fn promote(&self, cid: &Cid, reproduced: &[u8]) -> StoreResult<()>;

    /// Read an object that is safe to serve to an arbitrary peer.
    ///
    /// Refuses anything marked [`Distribution::TrustedOnly`]. Provided as a
    /// separate method so a caller serving peers cannot reach for `get` by
    /// habit and hand out hidden tests.
    async fn get_for_peer(&self, cid: &Cid) -> StoreResult<Option<Vec<u8>>> {
        let Some(entry) = self.head(cid).await? else {
            return Ok(None);
        };
        if !entry.provenance.may_share_with_peer() {
            return Err(StoreError::DistributionRefused {
                cid: cid.to_string(),
                distribution: entry.provenance.distribution,
            });
        }
        self.get(cid).await
    }

    /// Read an object that may be used to decide a verdict.
    ///
    /// A quarantined object reads as **absent**, so a caller that forgets to
    /// check trust gets a miss and rebuilds rather than an unverified artifact.
    async fn get_for_judging(&self, cid: &Cid) -> StoreResult<Option<Vec<u8>>> {
        let Some(entry) = self.head(cid).await? else {
            return Ok(None);
        };
        if !entry.provenance.may_decide_a_verdict() {
            tracing::debug!(
                cid = %cid,
                trust = ?entry.provenance.trust,
                "treating a quarantined object as absent"
            );
            return Ok(None);
        }
        self.get(cid).await
    }
}

/// The trust state an object should be stored with, given who produced it.
pub fn trust_for_producer(operator_controlled: bool) -> TrustState {
    if operator_controlled {
        TrustState::Verified
    } else {
        TrustState::Quarantined
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_operator_controlled_producers_skip_quarantine() {
        assert_eq!(trust_for_producer(true), TrustState::Verified);
        assert_eq!(trust_for_producer(false), TrustState::Quarantined);
    }
}
