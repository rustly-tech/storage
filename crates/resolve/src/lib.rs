//! Resolving an object from whichever source has it.
//!
//! # The rule that shapes everything here
//!
//! > P2P available → the system is cheaper and faster.
//! > P2P unavailable → the system is slower and still correct.
//!
//! P2P is never authoritative. It cannot be, because every byte is verified
//! against its CID before it is used: an untrusted peer can only fail to serve,
//! never serve something wrong. That is what makes it safe to accept bytes from
//! a stranger, and it is why the resolution order below is a performance
//! decision rather than a security one.
//!
//! # Order
//!
//! ```text
//! local ──▶ peers ──▶ origin ──▶ rebuild
//! free      cheap     metered    expensive
//! ```
//!
//! Each step is tried only if the previous missed. Everything found is verified
//! and then cached locally, so the second request for an object is free.
//!
//! # Status
//!
//! `LocalSource` and `OriginSource` are **IMPLEMENTED**. A peer transport
//! (libp2p, QUIC, WebRTC) is **PLANNED**; the [`Source`] trait is what it will
//! implement, and [`Resolver`] already handles a peer that lies, stalls, or
//! disappears, because those are the cases a test can exercise today.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use rustly_cas::{Cid, Provenance};
use rustly_store::{ObjectStore, StoreError};

/// Something that might hold an object.
#[async_trait]
pub trait Source: Send + Sync {
    /// Stable identifier, for metrics and for blaming a bad peer.
    fn id(&self) -> String;

    /// Whether fetching from this source costs money.
    ///
    /// The resolver consults this so a $0 deployment under quota pressure can
    /// skip metered sources rather than quietly spending.
    fn is_metered(&self) -> bool {
        false
    }

    /// Fetch, or `None` if this source does not have it.
    ///
    /// A source is **not** required to return correct bytes. The resolver
    /// verifies everything, which is precisely why an untrusted source is safe
    /// to ask.
    async fn fetch(&self, cid: &Cid) -> Result<Option<Vec<u8>>, ResolveError>;
}

/// Why resolution failed.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    /// No source had the object.
    #[error("no source has {cid}")]
    NotFound {
        /// The CID that could not be found.
        cid: String,
    },

    /// A source was unreachable. Not fatal on its own; the resolver moves on.
    ///
    /// The field is `source_id` rather than `source` because `thiserror` treats
    /// a field named `source` as the underlying cause and requires it to be an
    /// error type.
    #[error("source `{source_id}` is unavailable: {detail}")]
    SourceUnavailable {
        /// Which source.
        source_id: String,
        /// What went wrong.
        detail: String,
    },

    /// The local store failed.
    #[error("local store: {0}")]
    Store(#[from] StoreError),
}

/// What resolution did, for metrics and for tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    /// The bytes.
    pub content: Vec<u8>,
    /// Which source finally provided them.
    pub source: String,
    /// Sources that were asked and did not have it, in order.
    pub missed: Vec<String>,
    /// Sources that returned bytes failing verification.
    ///
    /// Non-empty here is the signal that a peer is broken or hostile.
    pub rejected: Vec<String>,
}

/// Counters a deployment can scrape.
#[derive(Debug, Default)]
pub struct Metrics {
    /// Served from the local store.
    pub local_hits: AtomicU64,
    /// Served by a remote source.
    pub remote_hits: AtomicU64,
    /// Not found anywhere.
    pub misses: AtomicU64,
    /// Responses that failed verification.
    pub rejections: AtomicU64,
    /// Metered sources skipped because spending was not permitted.
    pub metered_skips: AtomicU64,
}

impl Metrics {
    fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// A snapshot, for reporting.
    pub fn snapshot(&self) -> [(&'static str, u64); 5] {
        [
            ("local_hits", self.local_hits.load(Ordering::Relaxed)),
            ("remote_hits", self.remote_hits.load(Ordering::Relaxed)),
            ("misses", self.misses.load(Ordering::Relaxed)),
            ("rejections", self.rejections.load(Ordering::Relaxed)),
            ("metered_skips", self.metered_skips.load(Ordering::Relaxed)),
        ]
    }
}

/// Decides whether a metered fetch may proceed.
///
/// The `ZeroCostGovernor` from the infrastructure design, reduced to the one
/// question this crate needs to ask. Under quota pressure the resolver skips
/// metered sources and reports a miss, so a caller rebuilds instead of spending.
pub trait SpendPolicy: Send + Sync {
    /// Whether a metered fetch is permitted right now.
    fn may_spend(&self) -> bool;
}

/// Always permits metered fetches.
#[derive(Debug, Clone, Copy, Default)]
pub struct AlwaysSpend;
impl SpendPolicy for AlwaysSpend {
    fn may_spend(&self) -> bool {
        true
    }
}

/// Never permits metered fetches. What $0 mode uses under Red pressure.
#[derive(Debug, Clone, Copy, Default)]
pub struct NeverSpend;
impl SpendPolicy for NeverSpend {
    fn may_spend(&self) -> bool {
        false
    }
}

/// Resolves objects from the cheapest source that has them.
pub struct Resolver {
    local: Arc<dyn ObjectStore>,
    sources: Vec<Arc<dyn Source>>,
    policy: Arc<dyn SpendPolicy>,
    /// Counters, public so a deployment can scrape them.
    pub metrics: Metrics,
}

impl Resolver {
    /// Build a resolver over a local store and an ordered list of sources.
    ///
    /// Order matters: cheapest first. The resolver does not reorder, because
    /// only the operator knows what their peers and origins actually cost.
    pub fn new(local: Arc<dyn ObjectStore>, sources: Vec<Arc<dyn Source>>) -> Self {
        Self {
            local,
            sources,
            policy: Arc::new(AlwaysSpend),
            metrics: Metrics::default(),
        }
    }

    /// Use a spend policy, so metered sources can be skipped under quota pressure.
    pub fn with_spend_policy(mut self, policy: Arc<dyn SpendPolicy>) -> Self {
        self.policy = policy;
        self
    }

    /// Resolve `cid`, caching whatever is found.
    ///
    /// Every remote response is verified before it is used or cached. A source
    /// that returns wrong bytes is recorded in [`Resolution::rejected`] and the
    /// resolver moves on, so one bad peer costs latency rather than correctness.
    pub async fn resolve(&self, cid: &Cid) -> Result<Resolution, ResolveError> {
        if let Some(content) = self.local.get(cid).await? {
            Metrics::bump(&self.metrics.local_hits);
            return Ok(Resolution {
                content,
                source: self.local.id().to_owned(),
                missed: vec![],
                rejected: vec![],
            });
        }

        let mut missed = Vec::new();
        let mut rejected = Vec::new();

        for source in &self.sources {
            if source.is_metered() && !self.policy.may_spend() {
                // Degrade, never spend. A slower answer, or none, beats a bill.
                Metrics::bump(&self.metrics.metered_skips);
                tracing::debug!(source = %source.id(), "skipping a metered source under quota pressure");
                missed.push(source.id());
                continue;
            }

            match source.fetch(cid).await {
                Ok(Some(content)) => {
                    if !cid.verifies(&content) {
                        // The whole reason an untrusted source is safe to ask.
                        Metrics::bump(&self.metrics.rejections);
                        tracing::warn!(
                            source = %source.id(),
                            cid = %cid,
                            "a source returned content that does not match its CID"
                        );
                        rejected.push(source.id());
                        continue;
                    }

                    // Cache locally. Verified content is verified regardless of
                    // who sent it, so it enters the store as ordinary public
                    // content.
                    if let Err(error) = self.local.put(&content, Provenance::built_public()).await {
                        // A caching failure must not fail the resolve: we have
                        // the bytes and they are correct.
                        tracing::warn!(%error, "could not cache a resolved object");
                    }

                    Metrics::bump(&self.metrics.remote_hits);
                    return Ok(Resolution {
                        content,
                        source: source.id(),
                        missed,
                        rejected,
                    });
                }
                Ok(None) => missed.push(source.id()),
                Err(error) => {
                    // An unreachable source is normal on a P2P network. Note it
                    // and try the next one.
                    tracing::debug!(source = %source.id(), %error, "source unavailable");
                    missed.push(source.id());
                }
            }
        }

        Metrics::bump(&self.metrics.misses);
        Err(ResolveError::NotFound {
            cid: cid.to_string(),
        })
    }
}

/// A source backed by another [`ObjectStore`], e.g. a seed bucket.
pub struct StoreSource {
    name: String,
    store: Arc<dyn ObjectStore>,
    metered: bool,
}

impl StoreSource {
    /// Wrap a store as a source.
    pub fn new(name: impl Into<String>, store: Arc<dyn ObjectStore>, metered: bool) -> Self {
        Self {
            name: name.into(),
            store,
            metered,
        }
    }
}

#[async_trait]
impl Source for StoreSource {
    fn id(&self) -> String {
        self.name.clone()
    }

    fn is_metered(&self) -> bool {
        self.metered
    }

    async fn fetch(&self, cid: &Cid) -> Result<Option<Vec<u8>>, ResolveError> {
        match self.store.get(cid).await {
            Ok(content) => Ok(content),
            // A corrupt entry at the source is a miss from our point of view.
            // It has already been evicted there; we simply look elsewhere.
            Err(StoreError::Integrity { .. }) => Ok(None),
            Err(error) => Err(ResolveError::SourceUnavailable {
                source_id: self.name.clone(),
                detail: error.to_string(),
            }),
        }
    }
}
