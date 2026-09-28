// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Credential Issuer Metadata types.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::encryption::{
    CredentialRequestEncryptionMetadata, CredentialResponseEncryptionMetadata,
};
use super::validate::{
    validate_optional_signing_algs, validate_optional_strings, validate_optional_url,
    validate_optional_urls, FORBIDDEN_METADATA_MEMBERS,
};
use crate::error::{OpenId4VciError, OpenId4VciResult, Reason};
use crate::validation::{
    is_optional_non_empty, parse_json_rejecting_top_level_members, to_json, validate_https_url,
    validate_issuer_identifier, validate_non_empty_asciiish, validate_vec_non_empty,
    EXTENSIBLE_DOCUMENT_JSON,
};
use crate::CredentialFormat;

/// Credential Issuer Metadata from OpenID4VCI 1.0 final.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IssuerMetadata {
    /// Credential Issuer Identifier.
    pub credential_issuer: String,
    /// OAuth Authorization Server identifiers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_servers: Option<Vec<String>>,
    /// Credential Endpoint URL.
    pub credential_endpoint: String,
    /// Dedicated Nonce Endpoint URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce_endpoint: Option<String>,
    /// Deferred Credential Endpoint URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deferred_credential_endpoint: Option<String>,
    /// Notification Endpoint URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification_endpoint: Option<String>,
    /// EUDI WUA preference for Wallet Instance Attestation status maintenance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_client_status_period: Option<u64>,
    /// Credential Request encryption support.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_request_encryption: Option<CredentialRequestEncryptionMetadata>,
    /// Credential Response encryption support.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_response_encryption: Option<CredentialResponseEncryptionMetadata>,
    /// Support for issuing multiple credentials in one request (`proofs` array).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_credential_issuance: Option<BatchCredentialIssuance>,
    /// Supported credential configurations.
    pub credential_configurations_supported: BTreeMap<String, CredentialConfiguration>,
}

impl IssuerMetadata {
    /// Starts a final-spec metadata builder.
    #[must_use]
    pub fn builder(
        credential_issuer: String,
        credential_endpoint: String,
    ) -> IssuerMetadataBuilder {
        IssuerMetadataBuilder::new(credential_issuer, credential_endpoint)
    }

    /// Parses and validates issuer metadata JSON.
    pub fn parse_json(body: &str) -> OpenId4VciResult<Self> {
        let metadata: Self = parse_json_rejecting_top_level_members(
            body,
            EXTENSIBLE_DOCUMENT_JSON,
            &FORBIDDEN_METADATA_MEMBERS,
        )?;
        metadata.validate()?;
        Ok(metadata)
    }

    /// Serializes validated issuer metadata.
    pub fn to_json(&self) -> OpenId4VciResult<String> {
        self.validate()?;
        to_json(self)
    }

    /// Validates final-spec issuer metadata.
    pub fn validate(&self) -> OpenId4VciResult<()> {
        validate_issuer_identifier(&self.credential_issuer)?;
        validate_https_url(&self.credential_endpoint, false)?;
        validate_optional_urls(&self.authorization_servers)?;
        validate_optional_url(&self.nonce_endpoint)?;
        validate_optional_url(&self.deferred_credential_endpoint)?;
        validate_optional_url(&self.notification_endpoint)?;
        if matches!(self.preferred_client_status_period, Some(0)) {
            return Err(OpenId4VciError::new(Reason::InvalidString));
        }
        if self.credential_configurations_supported.is_empty() {
            return Err(OpenId4VciError::new(Reason::MissingRequiredField));
        }
        for key in self.credential_configurations_supported.keys() {
            validate_non_empty_asciiish(key)?;
        }
        for value in self.credential_configurations_supported.values() {
            value.validate()?;
        }
        if let Some(encryption) = &self.credential_request_encryption {
            encryption.validate()?;
        }
        if let Some(encryption) = &self.credential_response_encryption {
            encryption.validate()?;
        }
        if let Some(batch) = &self.batch_credential_issuance {
            batch.validate()?;
        }
        Ok(())
    }
}

/// Builder for final-spec Credential Issuer Metadata.
///
/// SDK and HTTP adapters use this helper to derive repeated credential
/// configuration boilerplate in one place.
#[derive(Debug, Clone, PartialEq)]
pub struct IssuerMetadataBuilder {
    metadata: IssuerMetadata,
    proof_required: bool,
    jwt_proof_signing_alg_values_supported: Option<Vec<String>>,
}

impl IssuerMetadataBuilder {
    /// Creates a builder with required issuer and credential endpoint values.
    #[must_use]
    pub fn new(credential_issuer: String, credential_endpoint: String) -> Self {
        Self {
            metadata: IssuerMetadata {
                credential_issuer,
                authorization_servers: None,
                credential_endpoint,
                nonce_endpoint: None,
                deferred_credential_endpoint: None,
                notification_endpoint: None,
                preferred_client_status_period: None,
                credential_request_encryption: None,
                credential_response_encryption: None,
                batch_credential_issuance: None,
                credential_configurations_supported: BTreeMap::new(),
            },
            proof_required: false,
            jwt_proof_signing_alg_values_supported: None,
        }
    }

    /// Sets OAuth Authorization Server issuer identifiers.
    #[must_use]
    pub fn authorization_servers(mut self, values: Vec<String>) -> Self {
        self.metadata.authorization_servers = Some(values);
        self
    }

    /// Sets the dedicated Nonce Endpoint URL.
    #[must_use]
    pub fn nonce_endpoint(mut self, value: String) -> Self {
        self.metadata.nonce_endpoint = Some(value);
        self
    }

    /// Sets the Deferred Credential Endpoint URL.
    #[must_use]
    pub fn deferred_credential_endpoint(mut self, value: String) -> Self {
        self.metadata.deferred_credential_endpoint = Some(value);
        self
    }

    /// Sets the Notification Endpoint URL.
    #[must_use]
    pub fn notification_endpoint(mut self, value: String) -> Self {
        self.metadata.notification_endpoint = Some(value);
        self
    }

    /// Sets the EUDI WUA Wallet Instance Attestation status-period preference.
    #[must_use]
    pub const fn preferred_client_status_period(mut self, value: u64) -> Self {
        self.metadata.preferred_client_status_period = Some(value);
        self
    }

    /// Sets Credential Request encryption metadata.
    #[must_use]
    pub fn credential_request_encryption(
        mut self,
        value: CredentialRequestEncryptionMetadata,
    ) -> Self {
        self.metadata.credential_request_encryption = Some(value);
        self
    }

    /// Sets Credential Response encryption metadata.
    #[must_use]
    pub fn credential_response_encryption(
        mut self,
        value: CredentialResponseEncryptionMetadata,
    ) -> Self {
        self.metadata.credential_response_encryption = Some(value);
        self
    }

    /// Advertises support for batch issuance with a maximum `proofs` array size.
    #[must_use]
    pub const fn batch_credential_issuance(mut self, batch_size: u64) -> Self {
        self.metadata.batch_credential_issuance = Some(BatchCredentialIssuance { batch_size });
        self
    }

    /// Marks the issuer policy as requiring key proofs.
    #[must_use]
    pub const fn proof_required(mut self, value: bool) -> Self {
        self.proof_required = value;
        self
    }

    /// Sets JWT proof signing algorithms advertised on configurations that do
    /// not already carry explicit proof metadata.
    #[must_use]
    pub fn jwt_proof_signing_alg_values_supported(mut self, values: Vec<String>) -> Self {
        self.jwt_proof_signing_alg_values_supported = Some(values);
        self
    }

    /// Adds one supported credential configuration.
    #[must_use]
    pub fn credential_configuration(
        mut self,
        id: String,
        configuration: CredentialConfiguration,
    ) -> Self {
        self.metadata
            .credential_configurations_supported
            .insert(id, configuration);
        self
    }

    /// Builds validated issuer metadata.
    pub fn build(mut self) -> OpenId4VciResult<IssuerMetadata> {
        if let Some(proof_algs) = &self.jwt_proof_signing_alg_values_supported {
            validate_vec_non_empty(proof_algs)?;
            let mut proof_types = BTreeMap::new();
            proof_types.insert(
                "jwt".to_owned(),
                ProofTypeMetadata {
                    proof_signing_alg_values_supported: proof_algs.clone(),
                    key_attestations_required: None,
                },
            );
            for configuration in self
                .metadata
                .credential_configurations_supported
                .values_mut()
            {
                if configuration.proof_types_supported.is_none() {
                    configuration.proof_types_supported = Some(proof_types.clone());
                }
            }
        }
        self.metadata.validate()?;
        Ok(self.metadata)
    }
}

/// One credential configuration advertised by the issuer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialConfiguration {
    /// Credential format profile identifier.
    pub format: CredentialFormat,
    /// Optional OAuth scope that authorizes this credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Supported cryptographic binding methods.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_binding_methods_supported: Option<Vec<String>>,
    /// Supported credential signing algorithms.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_signing_alg_values_supported: Option<Vec<CredentialSigningAlg>>,
    /// Supported proof types.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_types_supported: Option<BTreeMap<String, ProofTypeMetadata>>,
    /// SD-JWT VC type identifier (`vct`), REQUIRED for the `dc+sd-jwt` format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vct: Option<String>,
    /// mdoc document type (`doctype`), REQUIRED for the `mso_mdoc` format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doctype: Option<String>,
    /// Usage and display metadata for issued credentials (claims descriptions,
    /// display objects). OpenID4VCI 1.0 §12.2.4 `credential_metadata`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_metadata: Option<serde_json::Value>,
}

/// Credential signing algorithm identifier advertised in issuer metadata.
///
/// JOSE-based formats use case-sensitive algorithm names, while the mdoc
/// profile allows numeric COSE algorithm identifiers. Keeping both variants
/// typed avoids lossy stringification at the JSON boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CredentialSigningAlg {
    /// JOSE or fully specified string algorithm identifier.
    Named(String),
    /// COSE numeric algorithm identifier used by mdoc metadata.
    Cose(i64),
}

impl CredentialSigningAlg {
    /// Validates the algorithm identifier.
    pub fn validate(&self) -> OpenId4VciResult<()> {
        match self {
            Self::Named(value) => validate_non_empty_asciiish(value),
            Self::Cose(_) => Ok(()),
        }
    }
}

impl CredentialConfiguration {
    /// Creates a minimal credential configuration for a format.
    #[must_use]
    pub const fn new(format: CredentialFormat) -> Self {
        Self {
            format,
            scope: None,
            cryptographic_binding_methods_supported: None,
            credential_signing_alg_values_supported: None,
            proof_types_supported: None,
            vct: None,
            doctype: None,
            credential_metadata: None,
        }
    }

    /// Returns whether this configuration advertises holder proof support.
    #[must_use]
    pub fn supports_proofs(&self) -> bool {
        self.proof_types_supported
            .as_ref()
            .is_some_and(|proof_types| !proof_types.is_empty())
    }

    /// Validates credential configuration metadata.
    pub fn validate(&self) -> OpenId4VciResult<()> {
        is_optional_non_empty(&self.scope)?;
        validate_optional_strings(&self.cryptographic_binding_methods_supported)?;
        validate_optional_signing_algs(&self.credential_signing_alg_values_supported)?;
        is_optional_non_empty(&self.vct)?;
        is_optional_non_empty(&self.doctype)?;
        if let Some(proof_types) = &self.proof_types_supported {
            if proof_types.is_empty() {
                return Err(OpenId4VciError::new(Reason::MissingRequiredField));
            }
            for key in proof_types.keys() {
                validate_non_empty_asciiish(key)?;
            }
            for value in proof_types.values() {
                value.validate()?;
            }
        }
        Ok(())
    }
}

/// Proof-type metadata object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofTypeMetadata {
    /// Supported proof-signing algorithms.
    pub proof_signing_alg_values_supported: Vec<String>,
    /// Whether this proof type requires a key attestation, and any constraints
    /// on it (OpenID4VCI 1.0 §12.2.4 `key_attestations_required`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_attestations_required: Option<KeyAttestationsRequired>,
}

impl ProofTypeMetadata {
    /// Validates proof-type metadata.
    pub fn validate(&self) -> OpenId4VciResult<()> {
        validate_vec_non_empty(&self.proof_signing_alg_values_supported)?;
        if let Some(key_attestations) = &self.key_attestations_required {
            key_attestations.validate()?;
        }
        Ok(())
    }
}

/// Key-attestation requirement metadata for a proof type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyAttestationsRequired {
    /// Accepted key-storage attack-potential-resistance levels.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_storage: Option<Vec<String>>,
    /// Accepted user-authentication attack-potential-resistance levels.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_authentication: Option<Vec<String>>,
    /// EUDI WUA preference for Key Attestation status maintenance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_key_storage_status_period: Option<u64>,
}

impl KeyAttestationsRequired {
    /// Validates optional constraint lists.
    pub fn validate(&self) -> OpenId4VciResult<()> {
        validate_optional_strings(&self.key_storage)?;
        validate_optional_strings(&self.user_authentication)
    }
}

/// Batch issuance support metadata (OpenID4VCI 1.0 §12.2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchCredentialIssuance {
    /// Maximum number of entries in the request `proofs` array. MUST be >= 2.
    pub batch_size: u64,
}

/// Minimum meaningful batch size (OpenID4VCI 1.0 §12.2.4: MUST be 2 or greater).
pub const MIN_BATCH_SIZE: u64 = 2;

impl BatchCredentialIssuance {
    /// Validates the batch size lower bound.
    pub fn validate(&self) -> OpenId4VciResult<()> {
        if self.batch_size < MIN_BATCH_SIZE {
            return Err(OpenId4VciError::new(Reason::InvalidString));
        }
        Ok(())
    }
}
