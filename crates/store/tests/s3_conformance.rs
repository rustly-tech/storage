#![cfg(feature = "s3")]

use std::time::{Duration, Instant};

use rustly_cas::{Cid, Provenance};
use rustly_store::conformance;
use rustly_store::{ObjectStore, S3Config, S3Store, StoreError};
use s3::bucket::Bucket;
use s3::creds::Credentials;
use s3::region::Region;

fn setting(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.into())
}

fn configuration(max_object_bytes: usize) -> S3Config {
    S3Config {
        endpoint: setting("RUSTLY_TEST_S3_ENDPOINT", "http://127.0.0.1:9000"),
        region: setting("RUSTLY_TEST_S3_REGION", "us-east-1"),
        bucket: setting("RUSTLY_TEST_S3_BUCKET", "rustly-test"),
        access_key_id: setting("RUSTLY_TEST_S3_ACCESS_KEY", "rustly-test"),
        secret_access_key: setting("RUSTLY_TEST_S3_SECRET_KEY", "rustly-test-secret-change-me"),
        prefix: format!("conformance-{}", std::process::id()),
        max_object_bytes,
        request_timeout: Duration::from_secs(30),
        max_attempts: 3,
    }
}

fn raw_bucket(config: &S3Config) -> Bucket {
    let credentials = Credentials::new(
        Some(&config.access_key_id),
        Some(&config.secret_access_key),
        None,
        None,
        None,
    )
    .unwrap();
    *Bucket::new(
        &config.bucket,
        Region::Custom {
            region: config.region.clone(),
            endpoint: config.endpoint.clone(),
        },
        credentials,
    )
    .unwrap()
    .with_path_style()
}

fn object_key(config: &S3Config, cid: &Cid) -> String {
    let digest = cid.digest();
    format!(
        "{}/objects/{}/{}/{}",
        config.prefix,
        &digest[..2],
        &digest[2..4],
        digest
    )
}

#[tokio::test]
#[ignore = "requires an S3-compatible test service"]
async fn s3_backend_satisfies_the_store_contract_and_detects_remote_corruption() {
    let config = configuration(3 * rustly_cas::CHUNK_BYTES);
    let store = S3Store::new(config.clone()).unwrap();
    conformance::run_suite(&store).await;

    let cid = store
        .put(b"uncorrupted", Provenance::built_public())
        .await
        .unwrap();
    let response = raw_bucket(&config)
        .put_object(object_key(&config, &cid), b"tampered")
        .await
        .unwrap();
    assert!(response.status_code() < 300);
    assert!(matches!(
        store.get(&cid).await,
        Err(StoreError::Integrity { .. })
    ));
    assert!(!store.contains(&cid).await.unwrap());
}

#[tokio::test]
#[ignore = "requires an S3-compatible test service"]
async fn s3_backend_enforces_size_and_bounded_failure_time() {
    let store = S3Store::new(configuration(4)).unwrap();
    assert!(store
        .put(b"five!", Provenance::built_public())
        .await
        .is_err());

    let mut unreachable = configuration(1024);
    unreachable.endpoint = "http://127.0.0.1:1".into();
    unreachable.request_timeout = Duration::from_millis(100);
    unreachable.max_attempts = 2;
    let unreachable = S3Store::new(unreachable).unwrap();
    let started = Instant::now();
    assert!(unreachable
        .put(b"bounded", Provenance::built_public())
        .await
        .is_err());
    assert!(started.elapsed() < Duration::from_secs(2));
}
