# Content-addressed storage design

Objects are named by a BLAKE3 hash of their bytes. Every backend verifies bytes
against that content ID on read. A corrupt local entry is evicted before the
error is returned so a later read can fetch or rebuild it cleanly.

## Distribution and trust

Provenance helps diagnose bad sources and restrict where sensitive objects may
be stored. It is separate from content verification.

| Distribution | May reach a peer or CDN |
| --- | --- |
| `Public` | Yes |
| `EncryptedAtRest` | Yes |
| `TrustedOnly` | No |

| Trust state | May decide a verdict |
| --- | --- |
| `Quarantined` | No |
| `Verified` | Yes |
| `Hot` | Yes; this is only a cache hint |

Quarantined artifacts are promoted only after a reproducible rebuild. A rebuild
that produces different bytes removes the quarantined copy.

## Chunking and resolution

Large objects use fixed 1 MiB chunks. Chunk IDs allow partial verification,
parallel retrieval, and deduplication. The resolver tries sources in order and
checks every result before returning it.

Peer transport, erasure coding, and an S3-compatible store are planned. The
current implementation includes content IDs, manifests, provenance, in-memory
and filesystem stores, and multi-source resolution. Unsupported redundancy
schemes are rejected rather than inferred.

The store treats compiled artifacts, content packs, source archives, and
toolchain bundles uniformly. Hidden tests use the `TrustedOnly` distribution
class and must not be sent to untrusted sources.
