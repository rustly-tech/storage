//! Content identifiers.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Prefix identifying the hash function.
///
/// Present so that changing hash function is a visible, parseable migration
/// rather than a silent reinterpretation of every existing name.
pub const CID_PREFIX: &str = "b3:";

/// Length of the hex-encoded digest.
pub const CID_HEX_LEN: usize = 64;

/// A content identifier: `b3:` followed by a lowercase BLAKE3 digest.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Cid(String);

/// A string that is not a valid CID.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CidError {
    /// The `b3:` prefix is missing.
    #[error("missing the `{CID_PREFIX}` prefix: {0:?}")]
    MissingPrefix(String),
    /// The digest is not 64 hex characters.
    #[error("digest must be {CID_HEX_LEN} hex characters, got {0}")]
    BadLength(usize),
    /// The digest contains a character that is not lowercase hex.
    #[error("digest must be lowercase hex")]
    NotLowercaseHex,
}

impl Cid {
    /// The CID of some bytes.
    pub fn of(bytes: &[u8]) -> Self {
        Self(format!("{CID_PREFIX}{}", blake3::hash(bytes).to_hex()))
    }

    /// Parse and validate.
    pub fn parse(value: &str) -> Result<Self, CidError> {
        let Some(hex) = value.strip_prefix(CID_PREFIX) else {
            return Err(CidError::MissingPrefix(value.to_owned()));
        };
        if hex.len() != CID_HEX_LEN {
            return Err(CidError::BadLength(hex.len()));
        }
        // Lowercase only, so one piece of content has exactly one name. Accepting
        // both cases would silently create two names for the same bytes and
        // defeat deduplication.
        if !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(CidError::NotLowercaseHex);
        }
        Ok(Self(value.to_owned()))
    }

    /// Whether `bytes` really are the content this CID names.
    pub fn verifies(&self, bytes: &[u8]) -> bool {
        Self::of(bytes) == *self
    }

    /// The full identifier, including the prefix.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The hex digest, without the prefix.
    pub fn digest(&self) -> &str {
        &self.0[CID_PREFIX.len()..]
    }

    /// A short prefix, for logs. Never use this to identify an object.
    pub fn short(&self) -> &str {
        &self.digest()[..8]
    }

    /// A two-level fan-out path, so a directory never holds millions of entries.
    pub fn shard_path(&self) -> (String, String, String) {
        let digest = self.digest();
        (
            digest[..2].to_owned(),
            digest[2..4].to_owned(),
            digest.to_owned(),
        )
    }
}

impl fmt::Display for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Cid {
    type Err = CidError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for Cid {
    fn serialize<S: Serializer>(&self, serialiser: S) -> Result<S::Ok, S::Error> {
        serialiser.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Cid {
    fn deserialize<D: Deserializer<'de>>(deserialiser: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserialiser)?;
        Cid::parse(&raw).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_content_has_an_identical_name_everywhere() {
        assert_eq!(Cid::of(b"hello"), Cid::of(b"hello"));
        assert_ne!(Cid::of(b"hello"), Cid::of(b"hell0"));
        assert_ne!(Cid::of(b""), Cid::of(b"\0"));
    }

    #[test]
    fn a_cid_verifies_only_its_own_content() {
        let cid = Cid::of(b"the real bytes");
        assert!(cid.verifies(b"the real bytes"));
        assert!(!cid.verifies(b"the real byte"));
        assert!(!cid.verifies(b"the real bytes "));
        assert!(!cid.verifies(b""));
    }

    #[test]
    fn a_single_flipped_bit_is_detected() {
        let original = vec![0xAAu8; 4096];
        let cid = Cid::of(&original);
        let mut tampered = original.clone();
        tampered[2048] ^= 0x01;
        assert!(!cid.verifies(&tampered));
    }

    #[test]
    fn parsing_accepts_only_the_canonical_form() {
        let cid = Cid::of(b"x");
        assert_eq!(Cid::parse(cid.as_str()).unwrap(), cid);

        assert_eq!(
            Cid::parse("deadbeef").unwrap_err(),
            CidError::MissingPrefix("deadbeef".into())
        );
        assert!(matches!(Cid::parse("b3:abc"), Err(CidError::BadLength(3))));
        // Uppercase is rejected: one piece of content must have exactly one name,
        // or deduplication silently stops working.
        assert_eq!(
            Cid::parse(&format!("b3:{}", "A".repeat(64))).unwrap_err(),
            CidError::NotLowercaseHex
        );
        assert_eq!(
            Cid::parse(&format!("b3:{}", "g".repeat(64))).unwrap_err(),
            CidError::NotLowercaseHex
        );
    }

    #[test]
    fn a_path_traversal_attempt_is_not_a_cid() {
        for hostile in ["b3:../../etc/passwd", "../secret", "b3:/etc/passwd"] {
            assert!(Cid::parse(hostile).is_err(), "should reject {hostile:?}");
        }
    }

    #[test]
    fn sharding_fans_out_and_never_escapes_its_root() {
        let cid = Cid::of(b"content");
        let (a, b, name) = cid.shard_path();
        assert_eq!(a.len(), 2);
        assert_eq!(b.len(), 2);
        assert_eq!(name, cid.digest());
        for part in [&a, &b, &name] {
            assert!(!part.contains('/') && !part.contains('.'));
        }
    }

    #[test]
    fn the_prefix_makes_a_future_hash_change_visible() {
        assert!(Cid::of(b"x").as_str().starts_with("b3:"));
        // A digest with a different prefix must not silently parse as BLAKE3.
        assert!(Cid::parse(&format!("sha256:{}", "a".repeat(64))).is_err());
    }

    #[test]
    fn round_trips_through_json_and_string() {
        let cid = Cid::of(b"round trip");
        assert_eq!(cid.as_str().parse::<Cid>().unwrap(), cid);
        let json = serde_json::to_string(&cid).unwrap();
        assert_eq!(serde_json::from_str::<Cid>(&json).unwrap(), cid);
        assert!(serde_json::from_str::<Cid>("\"not-a-cid\"").is_err());
    }

    #[test]
    fn short_form_is_for_logs_only() {
        assert_eq!(Cid::of(b"x").short().len(), 8);
    }
}
