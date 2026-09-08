//! Both backends must satisfy the same suite, identically.

use rustly_cas::{Cid, Provenance};
use rustly_store::{conformance, FilesystemStore, MemoryStore, ObjectStore, StoreError};

#[tokio::test]
async fn the_memory_store_satisfies_the_conformance_suite() {
    conformance::run_suite(&MemoryStore::new()).await;
}

#[tokio::test]
async fn the_filesystem_store_satisfies_the_conformance_suite() {
    let dir = tempfile::tempdir().unwrap();
    let store = FilesystemStore::open(dir.path()).await.unwrap();
    conformance::run_suite(&store).await;
}

#[tokio::test]
async fn the_filesystem_store_detects_corruption_on_read_and_evicts_it() {
    let dir = tempfile::tempdir().unwrap();
    let store = FilesystemStore::open(dir.path()).await.unwrap();
    let cid = store
        .put(b"honest bytes", Provenance::built_public())
        .await
        .unwrap();

    // Corrupt the file exactly as a bad disk or a hostile process would.
    let (a, b, name) = cid.shard_path();
    let path = dir.path().join("objects").join(a).join(b).join(name);
    tokio::fs::write(&path, b"tampered bytes").await.unwrap();

    let error = store
        .get(&cid)
        .await
        .expect_err("corruption must be detected on read");
    assert!(matches!(error, StoreError::Integrity { .. }));
    assert!(
        !store.contains(&cid).await.unwrap(),
        "a known-bad entry must be evicted, so the next read is a clean miss"
    );
    assert_eq!(store.get(&cid).await.unwrap(), None);
}

#[tokio::test]
async fn the_memory_store_detects_corruption_on_read_too() {
    let store = MemoryStore::new();
    let cid = store
        .put(b"honest bytes", Provenance::built_public())
        .await
        .unwrap();
    store.corrupt_for_test(&cid, b"tampered".to_vec()).await;

    assert!(matches!(
        store.get(&cid).await,
        Err(StoreError::Integrity { .. })
    ));
    assert_eq!(
        store.get(&cid).await.unwrap(),
        None,
        "the corrupt entry was evicted"
    );
}

#[tokio::test]
async fn a_truncated_object_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let store = FilesystemStore::open(dir.path()).await.unwrap();
    let content = vec![42u8; 10_000];
    let cid = store
        .put(&content, Provenance::built_public())
        .await
        .unwrap();

    let (a, b, name) = cid.shard_path();
    let path = dir.path().join("objects").join(a).join(b).join(name);
    tokio::fs::write(&path, &content[..9_999]).await.unwrap();

    assert!(matches!(
        store.get(&cid).await,
        Err(StoreError::Integrity { .. })
    ));
}

#[tokio::test]
async fn a_partial_write_never_becomes_a_readable_object() {
    let dir = tempfile::tempdir().unwrap();
    let store = FilesystemStore::open(dir.path()).await.unwrap();
    let cid = store
        .put(b"complete", Provenance::built_public())
        .await
        .unwrap();

    let (a, b, name) = cid.shard_path();
    let partial = dir
        .path()
        .join("objects")
        .join(a)
        .join(b)
        .join(format!("{name}.partial"));
    assert!(
        !partial.exists(),
        "no .partial file survives a successful put"
    );
}

#[tokio::test]
async fn objects_are_sharded_so_no_directory_grows_without_limit() {
    let dir = tempfile::tempdir().unwrap();
    let store = FilesystemStore::open(dir.path()).await.unwrap();
    for i in 0..64u32 {
        store
            .put(&i.to_le_bytes(), Provenance::built_public())
            .await
            .unwrap();
    }

    let mut top = tokio::fs::read_dir(dir.path().join("objects"))
        .await
        .unwrap();
    let mut shards = 0;
    while top.next_entry().await.unwrap().is_some() {
        shards += 1;
    }
    assert!(
        shards > 1,
        "64 objects should land in more than one shard, got {shards}"
    );
}

#[tokio::test]
async fn a_store_reopened_from_disk_still_reads_its_objects() {
    let dir = tempfile::tempdir().unwrap();
    let cid = {
        let store = FilesystemStore::open(dir.path()).await.unwrap();
        store
            .put(b"durable", Provenance::built_public())
            .await
            .unwrap()
    };

    let reopened = FilesystemStore::open(dir.path()).await.unwrap();
    assert_eq!(
        reopened.get(&cid).await.unwrap().as_deref(),
        Some(&b"durable"[..])
    );
    assert!(reopened.head(&cid).await.unwrap().is_some());
}

#[tokio::test]
async fn a_backend_cannot_be_asked_for_a_cid_it_did_not_produce() {
    let store = MemoryStore::new();
    let unrelated = Cid::of(b"this was never stored");
    assert_eq!(store.get(&unrelated).await.unwrap(), None);
    assert_eq!(store.get_for_judging(&unrelated).await.unwrap(), None);
    assert_eq!(store.get_for_peer(&unrelated).await.unwrap(), None);
}
