# Rustly storage

Content-addressed storage for Rustly.

This repository contains the libraries that name objects by their BLAKE3 hash,
verify them when read, store them in memory or on disk, and find them across
multiple sources.

## Packages

- `rustly-cas` defines content IDs, chunked manifests, and provenance.
- `rustly-store` provides in-memory and filesystem object stores.
- `rustly-resolve` retrieves and verifies objects from available sources.

The [design notes](docs/DESIGN.md) explain verification, distribution classes,
and current implementation status.

## Verify

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

## License

MIT or Apache-2.0, at your option.
