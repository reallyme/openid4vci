// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Credential request and response encryption metadata.

use serde::{Deserialize, Serialize};

use super::validate::{validate_optional_strings, validate_response_encryption_algorithms};
use crate::error::{OpenId4VciError, OpenId4VciResult, Reason};
use crate::jwk::PublicJwkSet;
use crate::validation::validate_vec_non_empty;

/// Credential Request encryption support metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRequestEncryptionMetadata {
    /// Supported JWE key management algorithms.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg_values_supported: Option<Vec<String>>,
    /// Supported JWE content encryption algorithms.
    pub enc_values_supported: Vec<String>,
    /// Supported JWE compression algorithms.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zip_values_supported: Option<Vec<String>>,
    /// Public JWK Set the Wallet encrypts requests to.
    pub jwks: PublicJwkSet,
    /// Whether request encryption is mandatory.
    pub encryption_required: bool,
}

impl CredentialRequestEncryptionMetadata {
    /// Validates algorithms and every public encryption key.
    pub fn validate(&self) -> OpenId4VciResult<()> {
        validate_optional_strings(&self.alg_values_supported)?;
        validate_vec_non_empty(&self.enc_values_supported)?;
        validate_optional_strings(&self.zip_values_supported)?;
        for key in self.jwks.keys() {
            let algorithm = key
                .algorithm()
                .ok_or(OpenId4VciError::new(Reason::InvalidJwkSet))?;
            if self
                .alg_values_supported
                .as_ref()
                .is_some_and(|algorithms| !algorithms.iter().any(|value| value == algorithm))
                || !jwk_algorithm_matches_key_type(algorithm, key.key_type())
            {
                return Err(OpenId4VciError::new(Reason::InvalidJwkSet));
            }
        }
        Ok(())
    }
}

fn jwk_algorithm_matches_key_type(algorithm: &str, key_type: &str) -> bool {
    match algorithm {
        "ECDH-ES" | "ECDH-ES+A128KW" | "ECDH-ES+A192KW" | "ECDH-ES+A256KW" => {
            matches!(key_type, "EC" | "OKP")
        }
        "RSA-OAEP" | "RSA-OAEP-256" | "RSA-OAEP-384" | "RSA-OAEP-512" => key_type == "RSA",
        _ => false,
    }
}

/// Credential Response encryption support metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialResponseEncryptionMetadata {
    /// Supported JWE key management algorithms.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg_values_supported: Option<Vec<String>>,
    /// Supported JWE content encryption algorithms.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enc_values_supported: Option<Vec<String>>,
    /// Supported JWE compression algorithms.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zip_values_supported: Option<Vec<String>>,
    /// Whether response encryption is mandatory.
    pub encryption_required: bool,
}

impl CredentialResponseEncryptionMetadata {
    /// Validates encryption metadata.
    pub fn validate(&self) -> OpenId4VciResult<()> {
        validate_optional_strings(&self.alg_values_supported)?;
        validate_optional_strings(&self.enc_values_supported)?;
        validate_optional_strings(&self.zip_values_supported)?;
        validate_response_encryption_algorithms(&self.alg_values_supported)?;
        // OpenID4VCI 1.0 Final section 12.2.4 makes both arrays required
        // whenever the response-encryption metadata object is published. The
        // `encryption_required` flag controls use by a Wallet, not whether the
        // issuer may omit its advertised algorithms.
        if self.alg_values_supported.is_none() || self.enc_values_supported.is_none() {
            return Err(OpenId4VciError::new(Reason::MissingRequiredField));
        }
        Ok(())
    }
}
