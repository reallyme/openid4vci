// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Signed Credential Issuer Metadata provider boundary.

use openid4vci_types::IssuerMetadata;
use reallyme_codec::base64url::base64url_to_bytes;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::error::{IssuerError, IssuerResult, IssuerStatus};

/// Maximum compact signed-metadata size accepted from a signing provider.
pub const MAX_SIGNED_ISSUER_METADATA_JWT_BYTES: usize = 512 * 1024;

/// Bounded compact JWS containing Credential Issuer Metadata.
#[derive(ZeroizeOnDrop)]
pub struct SignedIssuerMetadataJwt {
    compact: String,
}

impl SignedIssuerMetadataJwt {
    /// Creates a syntactically valid, bounded compact JWS value.
    pub fn new(compact: String) -> IssuerResult<Self> {
        if compact.is_empty()
            || compact.len() > MAX_SIGNED_ISSUER_METADATA_JWT_BYTES
            || compact.trim() != compact
        {
            return Err(IssuerError::new(IssuerStatus::EncodingFailed));
        }
        let segments = compact.split('.').collect::<Vec<_>>();
        if segments.len() != 3 || segments.iter().any(|segment| segment.is_empty()) {
            return Err(IssuerError::new(IssuerStatus::EncodingFailed));
        }
        for segment in segments {
            let _decoded = Zeroizing::new(
                base64url_to_bytes(segment)
                    .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?,
            );
        }
        Ok(Self { compact })
    }

    /// Exposes the compact JWS to the HTTP response adapter.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.compact
    }
}

/// Signs the canonical typed metadata supplied by the issuer engine.
pub trait IssuerMetadataSigner: Send + Sync {
    /// Produces signed metadata anchored to the supplied current Unix time.
    fn sign_metadata(
        &self,
        metadata: &IssuerMetadata,
        issued_at_unix: i64,
    ) -> IssuerResult<SignedIssuerMetadataJwt>;
}
