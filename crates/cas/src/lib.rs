//! Content addressing.
//!
//! # The one idea
//!
//! An object's name **is** the hash of its content. That single decision
//! removes most of a distributed system's hard problems:
//!
//! * There is no cache invalidation, because an object never changes. A "new
//!   version" is a different object with a different name.
//! * There is no trust decision about a source. Bytes from a volunteer peer, a
//!   CDN, or local disk are checked the same way, so where they came from stops
//!   being a security question.
//! * There is no coordination cost for deduplication. Identical content has an
//!   identical name, everywhere, forever.
//!
//! # Why this makes P2P safe to add later
//!
//! Because every read is verified, an untrusted peer cannot serve wrong bytes -
//! it can only fail to serve, which costs latency rather than correctness. That
//! is what lets P2P be a pure accelerator: available, the system is cheaper and
//! faster; unavailable, it is slower and still right.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod cid;
pub mod manifest;
pub mod provenance;

pub use cid::{Cid, CidError};
pub use manifest::{Chunk, Manifest, ManifestError, CHUNK_BYTES, MANIFEST_VERSION};
pub use provenance::{Distribution, Origin, Provenance, TrustState};
