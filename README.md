# rustly-tech/fabric

The content-addressed data plane for [Rustly](https://rustly.tech). Immutable
objects, BLAKE3 names, verified on every read.

## The one idea

**An object's name is the hash of its content.** That single decision removes
most of a distributed system's hard problems:

- No cache invalidation. An object never changes; a "new version" is a different
  object with a different name.
- No trust decision about a source. Bytes from a volunteer peer, a CDN, or local
  disk are checked identically, so *where they came from* stops being a security
  question.
- No coordination for deduplication. Identical content has an identical name,
  everywhere, forever.

## Why this makes P2P safe to add later

> P2P available → the system is cheaper and faster.
> P2P unavailable → the system is slower and still correct.

Because every read is verified, an untrusted peer cannot serve *wrong* bytes — it
can only fail to serve, which costs latency rather than correctness. P2P is
therefore a pure accelerator, and the resolution order is a performance decision
rather than a security one.

The transport is not built. The failure handling is, and it is tested: a peer
that lies is rejected and recorded, a peer that stalls is skipped, and a lying
peer's bytes never reach the local cache.

## Verification is not optional

Every backend verifies content against its CID **on read**, not only on write. A
store that verifies on write is trusting the filesystem, the disk, and every
process that can reach the directory.

A corrupt entry is **evicted before the error is returned**, so the next read is
a clean miss rather than a repeat failure, and the caller rebuilds instead of
proceeding with plausible wrong bytes.

## Two things provenance is for, and one it is not

It is **not** a content-integrity control — verification already covers that.
It is for:

- **Diagnostics.** When a peer serves corrupt bytes repeatedly, we want to know
  which peer.
- **Confidentiality.** Verification says nothing about who is *allowed* to hold
  an object. Hidden tests and unencrypted private source must not be distributed
  broadly regardless of how well they hash.

| Distribution | May reach a peer or CDN |
| --- | --- |
| `Public` | Yes |
| `EncryptedAtRest` | Yes |
| `TrustedOnly` | **Never** — hidden tests live here |

| Trust state | May decide a verdict |
| --- | --- |
| `Quarantined` | No — reads as **absent** to judging, so a forgetful caller rebuilds |
| `Verified` | Yes |
| `Hot` | Yes — a cache hint, never a trust upgrade |

Quarantine lifts only through `promote_after_reproduction`, and the name says
what the caller must have done. A mismatched rebuild destroys the quarantined
copy: two builds of the same inputs disagreeing is a serious signal, not a retry.

## Layout

```
crates/
  cas/       CIDs, chunked manifests, provenance
  store/     the ObjectStore trait, memory and filesystem backends, conformance
  resolve/   multi-source resolution: local → peers → origin
```

## Chunking

Fixed 1 MiB chunks. A whole-object CID is enough to *verify* an object but not
to fetch one usefully; chunking buys partial verification (a bad peer wastes one
chunk, not a whole download), parallel multi-source fetch, and deduplication.

Fixed-size rather than content-defined, deliberately: these objects — compiled
artifacts, content packs, toolchain bundles — are replaced wholesale rather than
edited, so the extra complexity would buy very little.

## Erasure coding

Not implemented. Base correctness first.

The manifest carries an explicit `Redundancy` field, and a manifest declaring a
scheme this build does not implement is **refused rather than guessed** —
reconstructing under a scheme we do not implement would produce plausible wrong
bytes, which is the worst possible failure for a store whose entire premise is
that bytes are trustworthy.

## Degrade, never spend

`Resolver` consults a `SpendPolicy` before contacting a metered source. Under
quota pressure a metered source is skipped and the resolve reports a miss, so the
caller rebuilds rather than incurring cost. This is the `ZeroCostGovernor` from
[the infrastructure design](https://github.com/rustly-tech/infra/blob/main/docs/ZERO_COST.md),
reduced to the one question this crate needs to ask.

## Status

| Piece | Status |
| --- | --- |
| CIDs, verification, sharding | **IMPLEMENTED** |
| Chunked manifests, whole-object and per-chunk verification | **IMPLEMENTED** |
| Provenance: origin, trust state, distribution class | **IMPLEMENTED** |
| `ObjectStore` with memory and filesystem backends | **IMPLEMENTED**, one conformance suite for both |
| Multi-source resolution with spend policy | **IMPLEMENTED** |
| S3-compatible backend | **PLANNED** |
| Peer transport (libp2p, QUIC, WebRTC bridge) | **PLANNED** — the `Source` trait is what it will implement |
| Encrypted erasure coding | **PLANNED** — the format reserves the field and refuses to guess |

53 tests. `cargo test` needs no network, no disk beyond a temporary directory,
and no accounts.

## Development

```sh
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all --check
```

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
