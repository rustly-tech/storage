//! One conformance suite, run against every backend.
//!
//! Both backends must behave identically, and CI runs this against both. That
//! equivalence is what makes it legitimate to test everything above this layer
//! against the in-memory store: the fast, hermetic path is proven to be the same
//! path.

use rustly_cas::{Cid, Distribution, Provenance, TrustState};

use crate::store::{ObjectStore, StoreError};

/// Run the full suite.
///
/// # Panics
///
/// Panics on the first behavioural difference from the specification, naming the
/// rule that was violated.
pub async fn run_suite<S: ObjectStore + ?Sized>(store: &S) {
    round_trip(store).await;
    misses_are_misses(store).await;
    put_is_idempotent(store).await;
    metadata_is_recorded(store).await;
    quarantined_objects_are_invisible_to_judging(store).await;
    trusted_only_objects_are_never_served_to_peers(store).await;
    promotion_requires_a_matching_rebuild(store).await;
    removal_works(store).await;
    large_objects_round_trip(store).await;
}

async fn round_trip<S: ObjectStore + ?Sized>(store: &S) {
    let cid = store
        .put(b"round trip", Provenance::built_public())
        .await
        .expect("put");
    assert_eq!(
        cid,
        Cid::of(b"round trip"),
        "the key must be the hash of the content"
    );
    assert_eq!(
        store.get(&cid).await.expect("get").as_deref(),
        Some(&b"round trip"[..])
    );
    assert!(store.contains(&cid).await.expect("contains"));
}

async fn misses_are_misses<S: ObjectStore + ?Sized>(store: &S) {
    let absent = Cid::of(b"never stored anywhere at all");
    assert_eq!(
        store.get(&absent).await.expect("a miss is not an error"),
        None
    );
    assert_eq!(store.head(&absent).await.expect("head"), None);
    assert!(!store.contains(&absent).await.expect("contains"));
}

async fn put_is_idempotent<S: ObjectStore + ?Sized>(store: &S) {
    let first = store
        .put(b"same bytes", Provenance::built_public())
        .await
        .unwrap();
    let second = store
        .put(b"same bytes", Provenance::built_public())
        .await
        .unwrap();
    assert_eq!(first, second, "identical content must have one name");
    assert_eq!(
        store.get(&first).await.unwrap().as_deref(),
        Some(&b"same bytes"[..])
    );
}

async fn metadata_is_recorded<S: ObjectStore + ?Sized>(store: &S) {
    let cid = store
        .put(b"with metadata", Provenance::built_public())
        .await
        .unwrap();
    let entry = store
        .head(&cid)
        .await
        .unwrap()
        .expect("an entry must exist");

    assert_eq!(entry.manifest.cid, cid);
    assert_eq!(entry.manifest.size, b"with metadata".len() as u64);
    assert!(entry.manifest.validate().is_ok());
    assert_eq!(entry.provenance.trust, TrustState::Verified);
    assert_eq!(entry.provenance.distribution, Distribution::Public);
}

async fn quarantined_objects_are_invisible_to_judging<S: ObjectStore + ?Sized>(store: &S) {
    let content = b"a volunteer build";
    let cid = store
        .put(content, Provenance::from_volunteer("peer-9"))
        .await
        .unwrap();

    assert_eq!(
        store.get_for_judging(&cid).await.unwrap(),
        None,
        "a quarantined object must read as absent, so a forgetful caller rebuilds"
    );
    // It is still held, for diagnostics and for later reproduction.
    assert_eq!(
        store.get(&cid).await.unwrap().as_deref(),
        Some(&content[..])
    );
    assert!(store.contains(&cid).await.unwrap());
}

async fn trusted_only_objects_are_never_served_to_peers<S: ObjectStore + ?Sized>(store: &S) {
    let cid = store
        .put(b"a hidden test case", Provenance::trusted_only())
        .await
        .unwrap();

    match store.get_for_peer(&cid).await {
        Err(StoreError::DistributionRefused { distribution, .. }) => {
            assert_eq!(distribution, Distribution::TrustedOnly);
        }
        other => panic!("trusted-only material must never be served to a peer, got {other:?}"),
    }
    // A public object, by contrast, is servable.
    let public = store
        .put(b"a public content pack", Provenance::built_public())
        .await
        .unwrap();
    assert!(store.get_for_peer(&public).await.unwrap().is_some());
}

async fn promotion_requires_a_matching_rebuild<S: ObjectStore + ?Sized>(store: &S) {
    let content = b"an artifact from a volunteer";
    let cid = store
        .put(content, Provenance::from_volunteer("peer-3"))
        .await
        .unwrap();
    assert!(store.get_for_judging(&cid).await.unwrap().is_none());

    store
        .promote(&cid, content)
        .await
        .expect("a matching rebuild promotes");
    assert!(
        store.get_for_judging(&cid).await.unwrap().is_some(),
        "after reproduction the artifact may decide a verdict"
    );

    // A rebuild that disagrees destroys the quarantined copy. Two builds of the
    // same inputs producing different bytes is a serious signal, not a retry.
    let other = store
        .put(
            b"another volunteer artifact",
            Provenance::from_volunteer("p"),
        )
        .await
        .unwrap();
    let error = store
        .promote(&other, b"completely different bytes")
        .await
        .expect_err("a mismatched rebuild must fail");
    assert!(matches!(error, StoreError::Integrity { .. }));
    assert!(
        !store.contains(&other).await.unwrap(),
        "the quarantined copy must be destroyed"
    );
}

async fn removal_works<S: ObjectStore + ?Sized>(store: &S) {
    let cid = store
        .put(b"temporary", Provenance::built_public())
        .await
        .unwrap();
    store.remove(&cid).await.unwrap();
    assert!(!store.contains(&cid).await.unwrap());
    assert_eq!(store.get(&cid).await.unwrap(), None);
    assert_eq!(store.head(&cid).await.unwrap(), None);
    // Removing something absent is not an error.
    store.remove(&cid).await.unwrap();
}

async fn large_objects_round_trip<S: ObjectStore + ?Sized>(store: &S) {
    // Larger than one chunk, so the manifest has several and the whole-object
    // and per-chunk verification paths both run.
    let content: Vec<u8> = (0..rustly_cas::CHUNK_BYTES * 2 + 1234)
        .map(|i| (i % 253) as u8)
        .collect();
    let cid = store
        .put(&content, Provenance::built_public())
        .await
        .unwrap();

    let read = store
        .get(&cid)
        .await
        .unwrap()
        .expect("a large object round-trips");
    assert_eq!(read.len(), content.len());
    assert_eq!(read, content);

    let entry = store.head(&cid).await.unwrap().unwrap();
    assert!(
        entry.manifest.chunks.len() >= 3,
        "a large object should be chunked"
    );
    assert!(entry.manifest.verify(&content).is_ok());
}
