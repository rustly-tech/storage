//! Resolution behaviour, including the cases a real P2P network will produce:
//! a peer that lies, a peer that stalls, a peer that vanishes.
//!
//! These are testable today because the resolver treats every source as
//! untrusted. The transport is not built yet; the failure handling is.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use rustly_cas::{Cid, Provenance};
use rustly_resolve::{AlwaysSpend, NeverSpend, ResolveError, Resolver, Source, StoreSource};
use rustly_store::{MemoryStore, ObjectStore};

/// A source that behaves however a test needs it to.
struct ScriptedSource {
    name: String,
    behaviour: Behaviour,
    metered: bool,
    calls: AtomicUsize,
}

enum Behaviour {
    /// Returns exactly these bytes for any request.
    Serves(Vec<u8>),
    /// Never has anything.
    Empty,
    /// Always fails to respond.
    Unreachable,
}

impl ScriptedSource {
    fn new(name: &str, behaviour: Behaviour) -> Arc<Self> {
        Arc::new(Self {
            name: name.into(),
            behaviour,
            metered: false,
            calls: AtomicUsize::new(0),
        })
    }

    fn metered(name: &str, behaviour: Behaviour) -> Arc<Self> {
        Arc::new(Self {
            name: name.into(),
            behaviour,
            metered: true,
            calls: AtomicUsize::new(0),
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl Source for ScriptedSource {
    fn id(&self) -> String {
        self.name.clone()
    }

    fn is_metered(&self) -> bool {
        self.metered
    }

    async fn fetch(&self, _cid: &Cid) -> Result<Option<Vec<u8>>, ResolveError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        match &self.behaviour {
            Behaviour::Serves(bytes) => Ok(Some(bytes.clone())),
            Behaviour::Empty => Ok(None),
            Behaviour::Unreachable => Err(ResolveError::SourceUnavailable {
                source_id: self.name.clone(),
                detail: "connection refused".into(),
            }),
        }
    }
}

fn local() -> Arc<dyn ObjectStore> {
    Arc::new(MemoryStore::new())
}

#[tokio::test]
async fn a_local_hit_asks_no_source_at_all() {
    let store = local();
    let cid = store
        .put(b"already here", Provenance::built_public())
        .await
        .unwrap();

    let peer = ScriptedSource::new("peer-1", Behaviour::Serves(b"already here".to_vec()));
    let resolver = Resolver::new(Arc::clone(&store), vec![peer.clone()]);

    let resolution = resolver.resolve(&cid).await.unwrap();
    assert_eq!(resolution.content, b"already here");
    assert_eq!(resolution.source, "memory");
    assert_eq!(peer.calls(), 0, "a local hit must not touch the network");
}

#[tokio::test]
async fn sources_are_tried_in_order_and_the_first_hit_wins() {
    let content = b"the object".to_vec();
    let cid = Cid::of(&content);

    let first = ScriptedSource::new("peer-1", Behaviour::Empty);
    let second = ScriptedSource::new("peer-2", Behaviour::Serves(content.clone()));
    let third = ScriptedSource::new("origin", Behaviour::Serves(content.clone()));

    let resolver = Resolver::new(local(), vec![first.clone(), second.clone(), third.clone()]);
    let resolution = resolver.resolve(&cid).await.unwrap();

    assert_eq!(resolution.source, "peer-2");
    assert_eq!(resolution.missed, vec!["peer-1"]);
    assert_eq!(
        third.calls(),
        0,
        "a later source must not be asked after a hit"
    );
}

#[tokio::test]
async fn a_lying_peer_is_rejected_and_the_next_source_answers() {
    let content = b"the honest object".to_vec();
    let cid = Cid::of(&content);

    let liar = ScriptedSource::new(
        "hostile-peer",
        Behaviour::Serves(b"malicious bytes".to_vec()),
    );
    let honest = ScriptedSource::new("origin", Behaviour::Serves(content.clone()));

    let resolver = Resolver::new(local(), vec![liar.clone(), honest.clone()]);
    let resolution = resolver.resolve(&cid).await.unwrap();

    assert_eq!(
        resolution.content, content,
        "the caller receives the correct bytes"
    );
    assert_eq!(resolution.source, "origin");
    assert_eq!(
        resolution.rejected,
        vec!["hostile-peer"],
        "a lying peer must be recorded, so a bad peer can be identified"
    );
}

#[tokio::test]
async fn a_lying_peer_never_poisons_the_local_cache() {
    let content = b"the honest object".to_vec();
    let cid = Cid::of(&content);
    let store = local();

    let liar = ScriptedSource::new("hostile", Behaviour::Serves(b"malicious".to_vec()));
    let resolver = Resolver::new(Arc::clone(&store), vec![liar]);

    // Nobody honest has it, so resolution fails.
    assert!(matches!(
        resolver.resolve(&cid).await,
        Err(ResolveError::NotFound { .. })
    ));
    assert_eq!(
        store.get(&cid).await.unwrap(),
        None,
        "unverified bytes must never reach the cache"
    );
}

#[tokio::test]
async fn an_unreachable_source_is_skipped_rather_than_fatal() {
    let content = b"still available".to_vec();
    let cid = Cid::of(&content);

    let down = ScriptedSource::new("peer-down", Behaviour::Unreachable);
    let up = ScriptedSource::new("peer-up", Behaviour::Serves(content.clone()));

    let resolver = Resolver::new(local(), vec![down, up]);
    let resolution = resolver.resolve(&cid).await.unwrap();
    assert_eq!(resolution.source, "peer-up");
    assert!(resolution.missed.contains(&"peer-down".to_string()));
}

#[tokio::test]
async fn a_resolved_object_is_cached_so_the_second_request_is_free() {
    let content = b"worth caching".to_vec();
    let cid = Cid::of(&content);

    let origin = ScriptedSource::new("origin", Behaviour::Serves(content.clone()));
    let resolver = Resolver::new(local(), vec![origin.clone()]);

    assert_eq!(resolver.resolve(&cid).await.unwrap().source, "origin");
    assert_eq!(resolver.resolve(&cid).await.unwrap().source, "memory");
    assert_eq!(
        origin.calls(),
        1,
        "the second request must not leave the machine"
    );
}

#[tokio::test]
async fn with_no_sources_at_all_the_system_is_slower_but_still_correct() {
    // The stated rule: P2P unavailable means slower, never wrong.
    let content = b"only local".to_vec();
    let store = local();
    let cid = store
        .put(&content, Provenance::built_public())
        .await
        .unwrap();

    let resolver = Resolver::new(Arc::clone(&store), vec![]);
    assert_eq!(resolver.resolve(&cid).await.unwrap().content, content);

    let absent = Cid::of(b"nowhere at all");
    assert!(matches!(
        resolver.resolve(&absent).await,
        Err(ResolveError::NotFound { .. })
    ));
}

#[tokio::test]
async fn a_metered_source_is_skipped_when_spending_is_not_permitted() {
    let content = b"costs money to fetch".to_vec();
    let cid = Cid::of(&content);

    let paid = ScriptedSource::metered("b2-origin", Behaviour::Serves(content.clone()));
    let resolver =
        Resolver::new(local(), vec![paid.clone()]).with_spend_policy(Arc::new(NeverSpend));

    // Degrade, never spend: a miss is the correct outcome, and the caller
    // rebuilds rather than being billed.
    assert!(matches!(
        resolver.resolve(&cid).await,
        Err(ResolveError::NotFound { .. })
    ));
    assert_eq!(
        paid.calls(),
        0,
        "a metered source must not be contacted under Red pressure"
    );
    assert_eq!(resolver.metrics.snapshot()[4], ("metered_skips", 1));
}

#[tokio::test]
async fn a_free_source_is_still_used_under_quota_pressure() {
    let content = b"free to fetch".to_vec();
    let cid = Cid::of(&content);

    let free = ScriptedSource::new("peer", Behaviour::Serves(content.clone()));
    let paid = ScriptedSource::metered("b2-origin", Behaviour::Serves(content.clone()));

    let resolver = Resolver::new(local(), vec![free.clone(), paid.clone()])
        .with_spend_policy(Arc::new(NeverSpend));

    assert_eq!(resolver.resolve(&cid).await.unwrap().source, "peer");
    assert_eq!(paid.calls(), 0);
}

#[tokio::test]
async fn a_metered_source_is_used_when_spending_is_permitted() {
    let content = b"worth paying for".to_vec();
    let cid = Cid::of(&content);

    let paid = ScriptedSource::metered("b2-origin", Behaviour::Serves(content.clone()));
    let resolver =
        Resolver::new(local(), vec![paid.clone()]).with_spend_policy(Arc::new(AlwaysSpend));

    assert_eq!(resolver.resolve(&cid).await.unwrap().source, "b2-origin");
    assert_eq!(paid.calls(), 1);
}

#[tokio::test]
async fn another_store_can_act_as_a_source() {
    let content = b"held by a seed".to_vec();
    let seed = Arc::new(MemoryStore::new());
    let cid = seed
        .put(&content, Provenance::built_public())
        .await
        .unwrap();

    let resolver = Resolver::new(
        local(),
        vec![Arc::new(StoreSource::new("seed", seed, false))],
    );
    assert_eq!(resolver.resolve(&cid).await.unwrap().source, "seed");
}

#[tokio::test]
async fn a_corrupt_entry_at_a_source_reads_as_a_miss_not_a_failure() {
    let content = b"corrupt at the seed".to_vec();
    let seed = Arc::new(MemoryStore::new());
    let cid = seed
        .put(&content, Provenance::built_public())
        .await
        .unwrap();
    seed.corrupt_for_test(&cid, b"tampered".to_vec()).await;

    let resolver = Resolver::new(
        local(),
        vec![Arc::new(StoreSource::new(
            "seed",
            Arc::clone(&seed) as Arc<dyn ObjectStore>,
            false,
        ))],
    );

    // The seed evicts its own corrupt entry; we simply look elsewhere.
    assert!(matches!(
        resolver.resolve(&cid).await,
        Err(ResolveError::NotFound { .. })
    ));
}

#[tokio::test]
async fn metrics_count_what_a_deployment_needs_to_see() {
    let content = b"metrics".to_vec();
    let cid = Cid::of(&content);

    // The scripted sources answer every request with the same bytes, so the
    // miss case is measured with its own resolver rather than reusing these.
    let liar = ScriptedSource::new("liar", Behaviour::Serves(b"wrong".to_vec()));
    let good = ScriptedSource::new("good", Behaviour::Serves(content.clone()));
    let resolver = Resolver::new(local(), vec![liar, good]);

    resolver.resolve(&cid).await.unwrap(); // remote hit, one rejection
    resolver.resolve(&cid).await.unwrap(); // local hit; no source is asked

    let snapshot = resolver.metrics.snapshot();
    assert_eq!(snapshot[0], ("local_hits", 1));
    assert_eq!(snapshot[1], ("remote_hits", 1));
    assert_eq!(snapshot[2], ("misses", 0));
    assert_eq!(snapshot[3], ("rejections", 1));

    let empty = Resolver::new(local(), vec![]);
    let _ = empty.resolve(&Cid::of(b"absent")).await;
    assert_eq!(empty.metrics.snapshot()[2], ("misses", 1));
}

#[tokio::test]
async fn every_response_is_verified_against_the_requested_cid_not_just_any_cid() {
    // A source that serves *some* valid object is not serving *this* one. The
    // resolver must reject a well-formed answer to a different question.
    let wanted = Cid::of(b"the object I asked for");
    let confused = ScriptedSource::new(
        "confused",
        Behaviour::Serves(b"a different object".to_vec()),
    );

    let resolver = Resolver::new(local(), vec![confused]);
    assert!(matches!(
        resolver.resolve(&wanted).await,
        Err(ResolveError::NotFound { .. })
    ));
    assert_eq!(resolver.metrics.snapshot()[3], ("rejections", 1));
}
