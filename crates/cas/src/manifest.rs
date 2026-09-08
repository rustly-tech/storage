//! Chunked object manifests.
//!
//! # Why chunk at all
//!
//! A whole-object CID is enough to verify an object, but not enough to fetch one
//! *usefully*. Chunking buys three things that matter for a system meant to run
//! on free tiers:
//!
//! * **Partial verification.** A peer's chunk is checked on arrival, so a bad
//!   peer wastes one chunk of bandwidth rather than a whole download.
//! * **Parallel and multi-source fetch.** Different chunks can come from
//!   different places at once, which is what makes P2P worth having.
//! * **Deduplication.** Two toolchain bundles that differ in one file share
//!   every other chunk, and we store the difference rather than both.
//!
//! Fixed-size chunking, deliberately. Content-defined chunking deduplicates
//! better across edits, and the objects here - compiled artifacts, content
//! packs, toolchain bundles - are replaced wholesale rather than edited. The
//! extra complexity would buy very little.
//!
//! # Erasure coding
//!
//! Not implemented, and deliberately so: base correctness first. The manifest
//! carries an explicit [`Redundancy`] field so adding an encrypted erasure layer
//! later is a new variant rather than a format break.

use serde::{Deserialize, Serialize};

use crate::cid::Cid;

/// Manifest format version. Independent of this crate's version.
pub const MANIFEST_VERSION: u32 = 1;

/// Chunk size. 1 MiB: large enough that per-chunk overhead is noise, small
/// enough that a failed chunk is a cheap retry on a slow connection.
pub const CHUNK_BYTES: usize = 1024 * 1024;

/// How an object is protected against loss.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "scheme")]
pub enum Redundancy {
    /// Chunks are stored as-is. Availability comes from replication.
    #[default]
    None,
    /// Reed-Solomon style erasure coding.
    ///
    /// Status: **PLANNED**. Reserved so adding it is a new variant rather than a
    /// format break. Readers must reject a manifest that declares it, instead of
    /// guessing.
    Erasure {
        /// Data shards.
        data: u8,
        /// Parity shards.
        parity: u8,
    },
}

/// One chunk of an object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Chunk {
    /// Content identifier of this chunk's bytes.
    pub cid: Cid,
    /// Byte offset of this chunk within the object.
    pub offset: u64,
    /// Length in bytes.
    pub length: u32,
}

/// A description of an immutable object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Format version.
    pub manifest_version: u32,
    /// Content identifier of the whole object.
    pub cid: Cid,
    /// Total size in bytes.
    pub size: u64,
    /// Media type, advisory only. Never used to decide whether to trust content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    /// Chunks, in order.
    pub chunks: Vec<Chunk>,
    /// Redundancy scheme.
    #[serde(default)]
    pub redundancy: Redundancy,
}

/// A manifest that does not describe a coherent object.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ManifestError {
    /// Unsupported format version.
    #[error("manifest version {0} is not supported (expected {MANIFEST_VERSION})")]
    UnsupportedVersion(u32),
    /// Chunks do not tile the object exactly.
    #[error("chunks do not tile the object: {0}")]
    NotContiguous(String),
    /// Declared size disagrees with the chunks.
    #[error("declared size {declared} but chunks cover {covered}")]
    SizeMismatch {
        /// Size the manifest claims.
        declared: u64,
        /// Size the chunks actually cover.
        covered: u64,
    },
    /// Content does not hash to the declared CID.
    #[error("content hashes to {actual}, not {declared}")]
    CidMismatch {
        /// CID the manifest claims.
        declared: String,
        /// CID the content actually has.
        actual: String,
    },
    /// A redundancy scheme this build cannot honour.
    #[error("redundancy scheme is not implemented; refusing to guess")]
    UnsupportedRedundancy,
    /// An object with no chunks.
    #[error("a manifest must describe at least one chunk")]
    Empty,
}

impl Manifest {
    /// Build a manifest by chunking `content`.
    pub fn build(content: &[u8], media_type: Option<String>) -> Self {
        let chunks: Vec<Chunk> = content
            .chunks(CHUNK_BYTES)
            .enumerate()
            .map(|(index, chunk)| Chunk {
                cid: Cid::of(chunk),
                offset: (index * CHUNK_BYTES) as u64,
                length: chunk.len() as u32,
            })
            .collect();

        // An empty object is still an object, and it still needs a chunk, so
        // that "no chunks" can mean "malformed" without ambiguity.
        let chunks = if chunks.is_empty() {
            vec![Chunk {
                cid: Cid::of(b""),
                offset: 0,
                length: 0,
            }]
        } else {
            chunks
        };

        Self {
            manifest_version: MANIFEST_VERSION,
            cid: Cid::of(content),
            size: content.len() as u64,
            media_type,
            chunks,
            redundancy: Redundancy::None,
        }
    }

    /// Check internal consistency, without seeing the content.
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.manifest_version != MANIFEST_VERSION {
            return Err(ManifestError::UnsupportedVersion(self.manifest_version));
        }
        if self.chunks.is_empty() {
            return Err(ManifestError::Empty);
        }
        if self.redundancy != Redundancy::None {
            // Refuse rather than guess. Reconstructing an object under a scheme
            // we do not implement would produce plausible wrong bytes.
            return Err(ManifestError::UnsupportedRedundancy);
        }

        let mut expected_offset = 0_u64;
        for (index, chunk) in self.chunks.iter().enumerate() {
            if chunk.offset != expected_offset {
                return Err(ManifestError::NotContiguous(format!(
                    "chunk {index} starts at {} but the previous chunk ends at {expected_offset}",
                    chunk.offset
                )));
            }
            if chunk.length as usize > CHUNK_BYTES {
                return Err(ManifestError::NotContiguous(format!(
                    "chunk {index} is {} bytes, over the {CHUNK_BYTES} limit",
                    chunk.length
                )));
            }
            expected_offset += u64::from(chunk.length);
        }

        if expected_offset != self.size {
            return Err(ManifestError::SizeMismatch {
                declared: self.size,
                covered: expected_offset,
            });
        }
        Ok(())
    }

    /// Verify assembled content against this manifest.
    ///
    /// Checks every chunk as well as the whole. Checking only the whole would
    /// leave a manifest that lies about its chunks undetected until a peer
    /// served one of those chunks and it did not match anything.
    pub fn verify(&self, content: &[u8]) -> Result<(), ManifestError> {
        self.validate()?;

        if content.len() as u64 != self.size {
            return Err(ManifestError::SizeMismatch {
                declared: self.size,
                covered: content.len() as u64,
            });
        }
        for (index, chunk) in self.chunks.iter().enumerate() {
            let start = chunk.offset as usize;
            let end = start + chunk.length as usize;
            let slice = content.get(start..end).ok_or_else(|| {
                ManifestError::NotContiguous(format!("chunk {index} runs past the content"))
            })?;
            if !chunk.cid.verifies(slice) {
                return Err(ManifestError::CidMismatch {
                    declared: chunk.cid.to_string(),
                    actual: Cid::of(slice).to_string(),
                });
            }
        }
        if !self.cid.verifies(content) {
            return Err(ManifestError::CidMismatch {
                declared: self.cid.to_string(),
                actual: Cid::of(content).to_string(),
            });
        }
        Ok(())
    }

    /// Chunk CIDs that are not yet held locally, in fetch order.
    pub fn missing<'a>(&'a self, held: &dyn Fn(&Cid) -> bool) -> Vec<&'a Chunk> {
        self.chunks
            .iter()
            .filter(|chunk| !held(&chunk.cid))
            .collect()
    }

    /// Number of distinct chunks. Repeated content is stored once.
    pub fn distinct_chunks(&self) -> usize {
        let mut cids: Vec<&Cid> = self.chunks.iter().map(|c| &c.cid).collect();
        cids.sort();
        cids.dedup();
        cids.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_built_manifest_verifies_its_own_content() {
        for size in [
            0,
            1,
            100,
            CHUNK_BYTES - 1,
            CHUNK_BYTES,
            CHUNK_BYTES + 1,
            CHUNK_BYTES * 3 + 7,
        ] {
            let content: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let manifest = Manifest::build(&content, None);
            assert!(manifest.validate().is_ok(), "size {size}");
            assert!(manifest.verify(&content).is_ok(), "size {size}");
            assert_eq!(manifest.size, size as u64);
        }
    }

    #[test]
    fn chunk_count_follows_the_chunk_size() {
        assert_eq!(
            Manifest::build(&[], None).chunks.len(),
            1,
            "an empty object still has a chunk"
        );
        assert_eq!(Manifest::build(&[0u8; 10], None).chunks.len(), 1);
        assert_eq!(
            Manifest::build(&vec![0u8; CHUNK_BYTES], None).chunks.len(),
            1
        );
        assert_eq!(
            Manifest::build(&vec![0u8; CHUNK_BYTES + 1], None)
                .chunks
                .len(),
            2
        );
        assert_eq!(
            Manifest::build(&vec![0u8; CHUNK_BYTES * 3], None)
                .chunks
                .len(),
            3
        );
    }

    #[test]
    fn corrupting_one_chunk_is_detected_even_though_the_object_is_large() {
        let mut content = vec![7u8; CHUNK_BYTES * 3];
        let manifest = Manifest::build(&content, None);

        // Flip a bit in the middle chunk.
        content[CHUNK_BYTES + 500] ^= 0xFF;
        let error = manifest.verify(&content).unwrap_err();
        assert!(matches!(error, ManifestError::CidMismatch { .. }));
    }

    #[test]
    fn truncated_content_is_detected() {
        let content = vec![3u8; 5000];
        let manifest = Manifest::build(&content, None);
        let error = manifest.verify(&content[..4999]).unwrap_err();
        assert!(matches!(error, ManifestError::SizeMismatch { .. }));
    }

    #[test]
    fn a_manifest_with_a_gap_is_rejected() {
        let content = vec![1u8; CHUNK_BYTES * 2];
        let mut manifest = Manifest::build(&content, None);
        manifest.chunks[1].offset += 10;

        assert!(matches!(
            manifest.validate(),
            Err(ManifestError::NotContiguous(_))
        ));
    }

    #[test]
    fn a_manifest_that_lies_about_its_size_is_rejected() {
        let mut manifest = Manifest::build(b"hello", None);
        manifest.size = 999;
        assert!(matches!(
            manifest.validate(),
            Err(ManifestError::SizeMismatch { .. })
        ));
    }

    #[test]
    fn a_manifest_that_lies_about_a_chunk_is_caught_even_if_the_whole_matches() {
        let content = vec![9u8; 100];
        let mut manifest = Manifest::build(&content, None);
        // The object CID stays correct; only the chunk CID is wrong.
        manifest.chunks[0].cid = Cid::of(b"something else entirely");

        let error = manifest.verify(&content).unwrap_err();
        assert!(
            matches!(error, ManifestError::CidMismatch { .. }),
            "verifying only the whole object would miss this, and a peer serving \
             that chunk would then fail against nothing"
        );
    }

    #[test]
    fn an_unsupported_version_is_refused_rather_than_interpreted() {
        let mut manifest = Manifest::build(b"x", None);
        manifest.manifest_version = 99;
        assert_eq!(
            manifest.validate(),
            Err(ManifestError::UnsupportedVersion(99))
        );
    }

    #[test]
    fn an_unimplemented_redundancy_scheme_is_refused_rather_than_guessed() {
        let mut manifest = Manifest::build(b"x", None);
        manifest.redundancy = Redundancy::Erasure { data: 4, parity: 2 };
        assert_eq!(
            manifest.validate(),
            Err(ManifestError::UnsupportedRedundancy)
        );
    }

    #[test]
    fn repeated_content_deduplicates_across_chunks() {
        let content = vec![0u8; CHUNK_BYTES * 4];
        let manifest = Manifest::build(&content, None);
        assert_eq!(manifest.chunks.len(), 4);
        assert_eq!(
            manifest.distinct_chunks(),
            1,
            "four identical chunks are stored once"
        );
    }

    #[test]
    fn missing_reports_only_what_is_not_held() {
        let content = vec![5u8; CHUNK_BYTES * 2 + 10];
        let manifest = Manifest::build(&content, None);
        let first = manifest.chunks[0].cid.clone();

        let missing = manifest.missing(&|cid| *cid == first);
        assert!(missing.iter().all(|chunk| chunk.cid != first));
        assert!(missing.len() < manifest.chunks.len());
        assert!(manifest.missing(&|_| true).is_empty());
        assert_eq!(manifest.missing(&|_| false).len(), manifest.chunks.len());
    }

    #[test]
    fn a_manifest_round_trips_through_json() {
        let manifest = Manifest::build(b"round trip", Some("application/wasm".into()));
        let json = serde_json::to_string(&manifest).unwrap();
        assert_eq!(serde_json::from_str::<Manifest>(&json).unwrap(), manifest);
        assert!(json.contains("\"manifest_version\":1"));
    }
}
