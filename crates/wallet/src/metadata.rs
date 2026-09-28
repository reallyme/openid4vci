// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wallet verification boundary for signed Credential Issuer Metadata.

use serde_json::Value;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use openid4vci_types::IssuerMetadata;

use crate::error::{WalletError, WalletResult, WalletStatus};

mod verify;

pub use verify::verify_signed_issuer_metadata;

const MAX_SIGNED_METADATA_JWT_BYTES: usize = 384 * 1024;
const MAX_TRUST_EVIDENCE_IDENTIFIER_BYTES: usize = 512;

/// JOSE algorithms accepted by the wallet's signed-metadata profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignedMetadataAlgorithm {
    /// ECDSA using P-256 and SHA-256.
    Es256,
    /// ECDSA using secp256k1 and SHA-256.
    Es256K,
    /// Edwards-curve signatures using Ed25519.
    EdDsa,
}

impl SignedMetadataAlgorithm {
    fn from_jose_name(value: &str) -> WalletResult<Self> {
        match value {
            "ES256" => Ok(Self::Es256),
            "ES256K" => Ok(Self::Es256K),
            "EdDSA" => Ok(Self::EdDsa),
            _ => Err(WalletError::new(
                WalletStatus::SignedMetadataUnsupportedAlgorithm,
            )),
        }
    }
}

/// Trust purpose applied to signed Credential Issuer Metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignedMetadataTrustPurpose {
    /// Authenticate metadata used to configure credential issuance.
    CredentialIssuerMetadata,
}

/// Trust purpose used to authenticate the signed-metadata signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignedMetadataSignerTrustPurpose {
    /// Generic trust policy for a Credential Issuer Metadata signer.
    CredentialIssuerMetadataSigner,
    /// EUDI Wallet Relying Party Access Certificate policy.
    WalletRelyingPartyAccessCertificate,
}

/// Bounded provenance for an accepted signed-metadata signer.
#[derive(ZeroizeOnDrop)]
pub struct SignedMetadataTrustEvidenceInput {
    /// Exact compact-JWS signing input authenticated by the verifier.
    pub verified_signing_input: String,
    /// Authenticated metadata signer identity.
    pub signer_identity: String,
    /// Optional `iss` identity bound to the signer by trust policy.
    pub asserted_issuer: Option<String>,
    /// Applied trust-policy revision.
    pub policy_version: String,
    /// Immutable trust-source snapshot identifier.
    pub source_snapshot: String,
    /// Selected trust-anchor evidence identifier.
    pub anchor: String,
    /// Unix time at which signer trust was evaluated.
    pub evaluated_at: i64,
    /// Last Unix time at which this trust decision may be consumed.
    pub valid_until: i64,
    /// Protocol operation authorized by the receipt.
    #[zeroize(skip)]
    pub purpose: SignedMetadataTrustPurpose,
    /// Trust profile used to authenticate the signer.
    #[zeroize(skip)]
    pub signer_trust_purpose: SignedMetadataSignerTrustPurpose,
}

/// Validated provenance for an accepted signed-metadata signer.
#[derive(ZeroizeOnDrop)]
pub struct SignedMetadataTrustEvidence {
    input: SignedMetadataTrustEvidenceInput,
}

impl SignedMetadataTrustEvidence {
    /// Creates a complete signer-trust receipt. The opaque snapshot and anchor
    /// fields allow WRPAC-backed adapters to retain their exact decision input.
    pub(crate) fn new(input: SignedMetadataTrustEvidenceInput) -> WalletResult<Self> {
        if input.verified_signing_input.is_empty() {
            return Err(WalletError::new(
                WalletStatus::InvalidSignedMetadataTrustEvidence,
            ));
        }
        for identifier in [
            &input.signer_identity,
            &input.policy_version,
            &input.source_snapshot,
            &input.anchor,
        ] {
            if identifier.is_empty()
                || identifier.len() > MAX_TRUST_EVIDENCE_IDENTIFIER_BYTES
                || identifier.contains('\r')
                || identifier.contains('\n')
            {
                return Err(WalletError::new(
                    WalletStatus::InvalidSignedMetadataTrustEvidence,
                ));
            }
        }
        if input.asserted_issuer.as_ref().is_some_and(|identifier| {
            identifier.is_empty()
                || identifier.len() > MAX_TRUST_EVIDENCE_IDENTIFIER_BYTES
                || identifier.contains('\r')
                || identifier.contains('\n')
        }) {
            return Err(WalletError::new(
                WalletStatus::InvalidSignedMetadataTrustEvidence,
            ));
        }
        if input.evaluated_at <= 0 || input.valid_until < input.evaluated_at {
            return Err(WalletError::new(
                WalletStatus::InvalidSignedMetadataTrustEvidence,
            ));
        }
        Ok(Self { input })
    }

    /// Returns the authenticated signer identity.
    #[must_use]
    pub fn signer_identity(&self) -> &str {
        &self.input.signer_identity
    }

    /// Returns the exact JWS signing input covered by this trust decision.
    #[must_use]
    pub fn verified_signing_input(&self) -> &str {
        &self.input.verified_signing_input
    }

    /// Returns the optional `iss` identity that trust policy bound to the signer.
    #[must_use]
    pub fn asserted_issuer(&self) -> Option<&str> {
        self.input.asserted_issuer.as_deref()
    }

    /// Returns the trust-policy revision.
    #[must_use]
    pub fn policy_version(&self) -> &str {
        &self.input.policy_version
    }

    /// Returns the immutable trust-source snapshot identifier.
    #[must_use]
    pub fn source_snapshot(&self) -> &str {
        &self.input.source_snapshot
    }

    /// Returns the selected trust-anchor identifier.
    #[must_use]
    pub fn anchor(&self) -> &str {
        &self.input.anchor
    }

    /// Returns the Unix time at which signer trust was evaluated.
    #[must_use]
    pub const fn evaluated_at(&self) -> i64 {
        self.input.evaluated_at
    }

    /// Returns the last Unix time at which this decision may be consumed.
    #[must_use]
    pub const fn valid_until(&self) -> i64 {
        self.input.valid_until
    }

    /// Returns the purpose of the trust decision.
    #[must_use]
    pub const fn purpose(&self) -> SignedMetadataTrustPurpose {
        self.input.purpose
    }

    /// Returns the signer-authentication purpose applied by trust policy.
    #[must_use]
    pub const fn signer_trust_purpose(&self) -> SignedMetadataSignerTrustPurpose {
        self.input.signer_trust_purpose
    }
}

/// Owned compact JWS containing Credential Issuer Metadata.
#[derive(ZeroizeOnDrop)]
pub struct SignedIssuerMetadataJwt {
    compact: String,
}

impl SignedIssuerMetadataJwt {
    /// Creates a bounded compact signed-metadata value.
    pub fn new(compact: String) -> WalletResult<Self> {
        if compact.is_empty()
            || compact.len() > MAX_SIGNED_METADATA_JWT_BYTES
            || compact.trim() != compact
        {
            return Err(WalletError::new(WalletStatus::InvalidSignedMetadata));
        }
        Ok(Self { compact })
    }

    /// Exposes the compact JWS only to the signature/trust verifier boundary.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.compact
    }
}

/// Wallet-controlled validation inputs for signed issuer metadata.
#[derive(ZeroizeOnDrop)]
pub struct SignedIssuerMetadataValidationContext {
    /// Credential Issuer Identifier from which metadata was retrieved.
    pub expected_credential_issuer: String,
    /// Current Unix time used to enforce the optional `exp` claim.
    pub current_time: i64,
    /// Maximum accepted age of the mandatory `iat` claim.
    pub max_age_seconds: u64,
    /// Permitted clock skew at `iat` and `exp` boundaries.
    pub allowed_clock_skew_seconds: u64,
    /// Algorithms accepted by wallet policy for this metadata source.
    #[zeroize(skip)]
    pub accepted_algorithms: Vec<SignedMetadataAlgorithm>,
    /// Signer trust purpose required by the active wallet profile.
    #[zeroize(skip)]
    pub required_signer_trust_purpose: SignedMetadataSignerTrustPurpose,
}

/// Strictly parsed signed metadata supplied to a trust verifier.
///
/// The metadata payload is intentionally not exposed as [`IssuerMetadata`]
/// until the injected verifier has authenticated both signer and signature.
pub struct ParsedSignedIssuerMetadata {
    protected_header: Value,
    signing_input: String,
    signature: Vec<u8>,
    payload: Zeroizing<String>,
    issuer: Option<String>,
    subject: String,
    issued_at: i64,
    expires_at: Option<i64>,
    algorithm: SignedMetadataAlgorithm,
}

impl ParsedSignedIssuerMetadata {
    /// Returns the complete protected JOSE header used for trust resolution.
    #[must_use]
    pub const fn protected_header(&self) -> &Value {
        &self.protected_header
    }

    /// Returns the exact encoded header and payload covered by the signature.
    #[must_use]
    pub fn signing_input(&self) -> &str {
        &self.signing_input
    }

    /// Returns the decoded JWS signature.
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Returns the optional signer identifier asserted in the payload.
    #[must_use]
    pub fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    /// Returns the Credential Issuer Identifier asserted by `sub`.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Returns the signed metadata issuance time.
    #[must_use]
    pub const fn issued_at(&self) -> i64 {
        self.issued_at
    }

    /// Returns the optional signed metadata expiration time.
    #[must_use]
    pub const fn expires_at(&self) -> Option<i64> {
        self.expires_at
    }

    /// Returns the allow-listed protected-header algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> SignedMetadataAlgorithm {
        self.algorithm
    }
}

impl Drop for ParsedSignedIssuerMetadata {
    fn drop(&mut self) {
        verify::zeroize_json_strings(&mut self.protected_header);
        self.signing_input.zeroize();
        self.signature.zeroize();
        self.issuer.zeroize();
        self.subject.zeroize();
    }
}

/// Establishes signer trust and verifies the JWS signature.
///
/// Implementations resolve a trusted verification key from protected header
/// mechanisms such as `kid`, `x5c`, or `trust_chain`. When `iss` is present,
/// they also establish that the authenticated signer is authorized to attest
/// for that identity and repeat it in the returned evidence. Returning success
/// without those checks violates this contract.
pub trait SignedIssuerMetadataTrustVerifier: Send + Sync {
    /// Authenticates the signer and verifies the compact JWS signature.
    fn verify_signed_issuer_metadata(
        &self,
        jwt: &SignedIssuerMetadataJwt,
        parsed: &ParsedSignedIssuerMetadata,
    ) -> WalletResult<SignedMetadataTrustEvidenceInput>;
}

/// Credential Issuer Metadata plus the exact evidence used to trust it.
pub struct VerifiedSignedIssuerMetadata {
    metadata: IssuerMetadata,
    algorithm: SignedMetadataAlgorithm,
    issued_at: i64,
    expires_at: Option<i64>,
    trust_evidence: SignedMetadataTrustEvidence,
}

impl VerifiedSignedIssuerMetadata {
    /// Returns the authenticated metadata.
    #[must_use]
    pub const fn metadata(&self) -> &IssuerMetadata {
        &self.metadata
    }

    /// Consumes the receipt and returns authenticated metadata.
    #[must_use]
    pub fn into_metadata(self) -> IssuerMetadata {
        self.metadata
    }

    /// Returns the accepted signature algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> SignedMetadataAlgorithm {
        self.algorithm
    }

    /// Returns the accepted `iat` value.
    #[must_use]
    pub const fn issued_at(&self) -> i64 {
        self.issued_at
    }

    /// Returns the accepted optional `exp` value.
    #[must_use]
    pub const fn expires_at(&self) -> Option<i64> {
        self.expires_at
    }

    /// Returns signer and WRPAC-compatible trust provenance.
    #[must_use]
    pub const fn trust_evidence(&self) -> &SignedMetadataTrustEvidence {
        &self.trust_evidence
    }
}
