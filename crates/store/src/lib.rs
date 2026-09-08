//! Object storage.
//!
//! One trait, [`ObjectStore`], and two backends. The trait exists because
//! invariant J says no provider may become logically irreplaceable: application
//! code names `ObjectStore`, never a vendor, and `cargo-deny` fails the build if
//! a cloud SDK enters the dependency graph.
//!
//! # Verification is not optional
//!
//! Every implementation must verify content against its CID **on read**, not
//! only on write. A store that verifies on write is trusting the filesystem, the
//! disk, and every process that can reach the directory. A corrupt entry is
//! evicted and reported, so the caller rebuilds rather than proceeding with
//! plausible wrong bytes.
//!
//! [`conformance`] is a single suite both backends must pass identically, which
//! is what makes it legitimate to test everything above this layer in memory.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod conformance;
pub mod filesystem;
pub mod memory;
#[cfg(feature = "s3")]
pub mod s3;
mod store;

pub use filesystem::FilesystemStore;
pub use memory::MemoryStore;
#[cfg(feature = "s3")]
pub use s3::{S3Config, S3Store};
pub use store::{trust_for_producer, Entry, ObjectStore, StoreError, StoreResult};
