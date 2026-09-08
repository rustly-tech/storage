# Rustly storage

Content-addressed storage for Rustly.

This repository contains the libraries that name objects by their BLAKE3 hash,
verify them when read, store them in memory or on disk, and find them across
multiple sources.

## Packages

- `rustly-cas` defines content IDs, chunked manifests, and provenance.
- `rustly-store` provides in-memory, filesystem, and optional S3-compatible
  object stores.
- `rustly-resolve` retrieves and verifies objects from available sources.

The [design notes](docs/DESIGN.md) explain verification and distribution
classes. [S3 setup and qualification](docs/S3.md) covers remote storage.

## Verify

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

## License

MIT or Apache-2.0, at your option.
