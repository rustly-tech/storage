//! Signed capabilities for browser-to-storage uploads.
//!
//! The metadata API issues a short-lived grant. The storage gateway verifies
//! that grant, hashes and stores the bytes, then returns a receipt signed in a
//! separate context. A submission carries the receipt, so the API can verify
//! storage accepted the exact CID without proxying source bytes.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Wire-format version.
pub const VERSION: &str = "v1";

/// A source-upload capability issued by the metadata API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadGrant {
    /// Stable user identifier allowed to upload.
    pub user_id: String,
    /// Expected BLAKE3 CID.
    pub cid: String,
    /// Exact number of bytes expected.
    pub size: u64,
    /// Expiry as Unix seconds.
    pub expires_at: i64,
    /// Unique value preventing two grants from having identical tokens.
    pub nonce: String,
}

/// Proof that trusted storage accepted and verified an upload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadReceipt {
    /// Stable user identifier that owned the grant.
    pub user_id: String,
    /// Verified BLAKE3 CID.
    pub cid: String,
    /// Verified byte count.
    pub size: u64,
    /// Receipt expiry as Unix seconds.
    pub expires_at: i64,
    /// Nonce copied from the grant.
    pub nonce: String,
}

/// A signing or validation failure.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TokenError {
    /// Secret is too short for production use.
    #[error("token secret must be at least 32 bytes")]
    WeakSecret,
    /// Token is malformed, tampered with, or of the wrong kind.
    #[error("invalid upload token")]
    Invalid,
    /// Token is past its expiry.
    #[error("upload token expired")]
    Expired,
}

/// Issues and verifies upload capabilities.
#[derive(Clone)]
pub struct UploadTokens {
    secret: Vec<u8>,
}

impl std::fmt::Debug for UploadTokens {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UploadTokens")
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl UploadTokens {
    /// Construct from a secret of at least 32 bytes.
    pub fn new(secret: impl Into<Vec<u8>>) -> Result<Self, TokenError> {
        let secret = secret.into();
        if secret.len() < 32 {
            return Err(TokenError::WeakSecret);
        }
        Ok(Self { secret })
    }

    /// Sign a source-upload grant.
    pub fn sign_grant(&self, grant: &UploadGrant) -> String {
        self.sign("grant", grant)
    }

    /// Verify a source-upload grant.
    pub fn verify_grant(&self, token: &str, now: i64) -> Result<UploadGrant, TokenError> {
        let grant: UploadGrant = self.verify("grant", token)?;
        if grant.expires_at < now {
            return Err(TokenError::Expired);
        }
        Ok(grant)
    }

    /// Sign a verified upload receipt.
    pub fn sign_receipt(&self, receipt: &UploadReceipt) -> String {
        self.sign("receipt", receipt)
    }

    /// Verify a storage receipt.
    pub fn verify_receipt(&self, token: &str, now: i64) -> Result<UploadReceipt, TokenError> {
        let receipt: UploadReceipt = self.verify("receipt", token)?;
        if receipt.expires_at < now {
            return Err(TokenError::Expired);
        }
        Ok(receipt)
    }

    fn sign<T: Serialize>(&self, kind: &str, value: &T) -> String {
        let payload = serde_json::to_vec(value).expect("upload claims are serializable");
        let encoded = URL_SAFE_NO_PAD.encode(payload);
        let input = format!("{VERSION}.{kind}.{encoded}");
        let signature = self.mac(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
    }

    fn verify<T: DeserializeOwned>(&self, kind: &str, token: &str) -> Result<T, TokenError> {
        let mut parts = token.split('.');
        let version = parts.next().ok_or(TokenError::Invalid)?;
        let actual_kind = parts.next().ok_or(TokenError::Invalid)?;
        let payload = parts.next().ok_or(TokenError::Invalid)?;
        let signature = parts.next().ok_or(TokenError::Invalid)?;
        if parts.next().is_some() || version != VERSION || actual_kind != kind {
            return Err(TokenError::Invalid);
        }
        let input = format!("{version}.{actual_kind}.{payload}");
        let expected = self.mac(input.as_bytes());
        let actual = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| TokenError::Invalid)?;
        if expected.ct_eq(&actual).unwrap_u8() != 1 {
            return Err(TokenError::Invalid);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| TokenError::Invalid)?;
        serde_json::from_slice(&bytes).map_err(|_| TokenError::Invalid)
    }

    fn mac(&self, bytes: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(&self.secret).expect("HMAC accepts every key");
        mac.update(bytes);
        mac.finalize().into_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens() -> UploadTokens {
        UploadTokens::new(vec![0x42; 32]).unwrap()
    }

    fn grant() -> UploadGrant {
        UploadGrant {
            user_id: "018f-user".into(),
            cid: "b3:abcd".into(),
            size: 123,
            expires_at: 2_000,
            nonce: "nonce-1".into(),
        }
    }

    #[test]
    fn grants_round_trip_and_expire() {
        let token = tokens().sign_grant(&grant());
        assert_eq!(tokens().verify_grant(&token, 1_999).unwrap(), grant());
        assert_eq!(
            tokens().verify_grant(&token, 2_001),
            Err(TokenError::Expired)
        );
    }

    #[test]
    fn tampering_and_token_kind_confusion_fail() {
        let token = tokens().sign_grant(&grant());
        let mut tampered = token.into_bytes();
        let last = tampered.len() - 1;
        tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(tampered).unwrap();
        assert_eq!(
            tokens().verify_grant(&tampered, 1_000),
            Err(TokenError::Invalid)
        );

        let receipt = UploadReceipt {
            user_id: "018f-user".into(),
            cid: "b3:abcd".into(),
            size: 123,
            expires_at: 2_000,
            nonce: "nonce-1".into(),
        };
        let receipt_token = tokens().sign_receipt(&receipt);
        assert_eq!(
            tokens().verify_grant(&receipt_token, 1_000),
            Err(TokenError::Invalid)
        );
    }

    #[test]
    fn debug_never_exposes_the_secret() {
        let debug = format!("{:?}", tokens());
        assert!(debug.contains("redacted"));
        assert!(!debug.contains("BBBB"));
    }
}
