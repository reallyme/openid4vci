// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Credential Endpoint request types from OpenID4VCI 1.0 final.

use core::fmt::{Debug, Formatter};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroize;

use crate::error::{OpenId4VciError, OpenId4VciResult, Reason};
use crate::jwk::PublicJwk;
use crate::validation::{
    is_optional_non_empty, parse_json, to_json, validate_non_empty_asciiish, zeroize_json_strings,
    EXTENSIBLE_DOCUMENT_JSON,
};

/// Maximum compact base64url length accepted for a ZK issuance intent.
pub const MAX_REALLYME_ZK_V1_ISSUANCE_REQUEST_BYTES: usize = 2048;

/// Credential selection in a Credential Request.
#[derive(Clone, PartialEq, Eq)]
pub enum CredentialSelector {
    /// The request names a credential configuration from issuer metadata.
    ConfigurationId(String),
    /// The request names a credential identifier returned by the token response.
    CredentialIdentifier(String),
}

impl Debug for CredentialSelector {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ConfigurationId(_) => formatter.write_str("ConfigurationId(<redacted>)"),
            Self::CredentialIdentifier(_) => {
                formatter.write_str("CredentialIdentifier(<redacted>)")
            }
        }
    }
}

impl Drop for CredentialSelector {
    fn drop(&mut self) {
        match self {
            Self::ConfigurationId(value) | Self::CredentialIdentifier(value) => value.zeroize(),
        }
    }
}

/// Credential Response encryption parameters requested by the Wallet.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialResponseEncryption {
    /// Public JWK used by the issuer to encrypt the response.
    pub jwk: PublicJwk,
    /// JWE content encryption algorithm.
    pub enc: String,
    /// Optional JWE compression algorithm.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zip: Option<String>,
}

impl Debug for CredentialResponseEncryption {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CredentialResponseEncryption")
            .field("jwk", &"<redacted>")
            .field("enc", &self.enc)
            .field("zip", &self.zip)
            .finish()
    }
}

impl Drop for CredentialResponseEncryption {
    fn drop(&mut self) {
        self.enc.zeroize();
        self.zip.zeroize();
    }
}

impl CredentialResponseEncryption {
    /// Validates that required encryption parameters are present.
    pub fn validate(&self) -> OpenId4VciResult<()> {
        validate_non_empty_asciiish(&self.enc)?;
        is_optional_non_empty(&self.zip)
    }
}

/// OpenID4VCI `proofs` object.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proofs {
    /// JWT proof-of-possession values.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub jwt: Vec<String>,
    /// Data Integrity Verifiable Presentation proofs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub di_vp: Vec<Value>,
    /// Key attestation proof. OpenID4VCI final requires exactly one JWT if present.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attestation: Vec<String>,
}

impl Debug for Proofs {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Proofs")
            .field("jwt_count", &self.jwt.len())
            .field("di_vp_count", &self.di_vp.len())
            .field("attestation_count", &self.attestation.len())
            .finish()
    }
}

impl Drop for Proofs {
    fn drop(&mut self) {
        self.zeroize_sensitive();
    }
}

impl Proofs {
    fn zeroize_sensitive(&mut self) {
        self.jwt.zeroize();
        for presentation in &mut self.di_vp {
            zeroize_json_strings(presentation);
        }
        self.attestation.zeroize();
    }

    /// Returns true when no proof type is populated.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.jwt.is_empty() && self.di_vp.is_empty() && self.attestation.is_empty()
    }

    /// Returns the number of populated proof-type members.
    #[must_use]
    pub fn populated_type_count(&self) -> usize {
        let jwt = usize::from(!self.jwt.is_empty());
        let di_vp = usize::from(!self.di_vp.is_empty());
        let attestation = usize::from(!self.attestation.is_empty());
        jwt.saturating_add(di_vp).saturating_add(attestation)
    }

    /// Validates final-spec proof shape rules.
    pub fn validate(&self) -> OpenId4VciResult<()> {
        if self.is_empty() {
            return Err(OpenId4VciError::new(Reason::InvalidProofs));
        }
        if self.populated_type_count() != 1 {
            return Err(OpenId4VciError::new(Reason::InvalidProofs));
        }
        for jwt in &self.jwt {
            validate_non_empty_asciiish(jwt)?;
        }
        for vp in &self.di_vp {
            if vp.is_null() {
                return Err(OpenId4VciError::new(Reason::InvalidProofs));
            }
        }
        match self.attestation.as_slice() {
            [] => Ok(()),
            [jwt] => validate_non_empty_asciiish(jwt),
            _ => Err(OpenId4VciError::new(Reason::InvalidProofs)),
        }
    }
}

/// Compact Buffa `ReallyMeZkV1IssuanceRequest` carried in a Credential Request.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ReallyMeZkV1IssuanceRequest {
    compact: String,
}

impl Debug for ReallyMeZkV1IssuanceRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ReallyMeZkV1IssuanceRequest")
            .field("compact", &"<redacted>")
            .finish()
    }
}

impl Drop for ReallyMeZkV1IssuanceRequest {
    fn drop(&mut self) {
        self.compact.zeroize();
    }
}

impl ReallyMeZkV1IssuanceRequest {
    /// Creates a bounded compact Buffa ZK issuance request.
    pub fn new(compact: String) -> OpenId4VciResult<Self> {
        let request = Self { compact };
        request.validate()?;
        Ok(request)
    }

    /// Returns the compact base64url Buffa request value.
    #[must_use]
    pub fn compact(&self) -> &str {
        &self.compact
    }

    /// Validates the transport wrapper before generated-message decoding.
    pub fn validate(&self) -> OpenId4VciResult<()> {
        validate_non_empty_asciiish(&self.compact)?;
        if self.compact.len() > MAX_REALLYME_ZK_V1_ISSUANCE_REQUEST_BYTES {
            return Err(OpenId4VciError::new(Reason::PayloadTooLarge));
        }
        Ok(())
    }
}

/// OpenID4VCI Credential Request.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialRequest {
    /// Credential configuration identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_configuration_id: Option<String>,
    /// Credential identifier returned by authorization details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_identifier: Option<String>,
    /// Proofs for the key material to which credentials are bound.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proofs: Option<Proofs>,
    /// Wallet-provided response encryption parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_response_encryption: Option<CredentialResponseEncryption>,
    /// Wallet-prepared ZK private-claim issuance intent.
    #[serde(
        rename = "reallyme_zk_v1_issuance",
        skip_serializing_if = "Option::is_none"
    )]
    pub reallyme_zk_v1_issuance: Option<ReallyMeZkV1IssuanceRequest>,
}

impl Debug for CredentialRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CredentialRequest")
            .field(
                "credential_configuration_id",
                &self
                    .credential_configuration_id
                    .as_ref()
                    .map(|_| "<redacted>"),
            )
            .field(
                "credential_identifier",
                &self.credential_identifier.as_ref().map(|_| "<redacted>"),
            )
            .field("proofs", &self.proofs)
            .field(
                "credential_response_encryption",
                &self.credential_response_encryption,
            )
            .field("reallyme_zk_v1_issuance", &self.reallyme_zk_v1_issuance)
            .finish()
    }
}

impl Drop for CredentialRequest {
    fn drop(&mut self) {
        self.credential_configuration_id.zeroize();
        self.credential_identifier.zeroize();
    }
}

impl CredentialRequest {
    /// Parses and validates a JSON Credential Request.
    pub fn parse_json(body: &str) -> OpenId4VciResult<Self> {
        // OpenID4VCI 1.0 §8.2 requires Credential Issuers to ignore
        // unrecognized request parameters. Nested proof and encryption objects
        // remain closed because their own types deny unknown members.
        let request: Self = parse_json(body, EXTENSIBLE_DOCUMENT_JSON)?;
        request.validate()?;
        Ok(request)
    }

    /// Serializes a validated Credential Request.
    pub fn to_json(&self) -> OpenId4VciResult<String> {
        self.validate()?;
        to_json(self)
    }

    /// Returns the request's exactly-one credential selector.
    pub fn selector(&self) -> OpenId4VciResult<CredentialSelector> {
        match (
            self.credential_configuration_id.as_ref(),
            self.credential_identifier.as_ref(),
        ) {
            (Some(configuration_id), None) => {
                validate_non_empty_asciiish(configuration_id)?;
                Ok(CredentialSelector::ConfigurationId(
                    configuration_id.clone(),
                ))
            }
            (None, Some(identifier)) => {
                validate_non_empty_asciiish(identifier)?;
                Ok(CredentialSelector::CredentialIdentifier(identifier.clone()))
            }
            _ => Err(OpenId4VciError::new(Reason::InvalidCredentialSelector)),
        }
    }

    /// Validates final-spec Credential Request shape.
    pub fn validate(&self) -> OpenId4VciResult<()> {
        self.selector()?;
        if let Some(proofs) = &self.proofs {
            proofs.validate()?;
        }
        if let Some(encryption) = &self.credential_response_encryption {
            encryption.validate()?;
        }
        if let Some(issuance) = &self.reallyme_zk_v1_issuance {
            issuance.validate()?;
        }
        Ok(())
    }
}

#[path = "tests/request_security_tests.rs"]
#[cfg(test)]
mod request_security_tests;
