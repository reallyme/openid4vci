// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wallet-side request builders.

use core::fmt::{Debug, Formatter};

#[cfg(feature = "identity-jose")]
use openid4vci_types::CredentialResponse;
use openid4vci_types::{
    CredentialRequest, CredentialRequestEncryptionMetadata, CredentialResponseEncryption,
    CredentialResponseEncryptionMetadata, IssuerMetadata, Proofs,
};
use reallyme_openid_oauth::{AttestationClientAuthentication, GrantType, PkceVerifier};
use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{WalletError, WalletResult, WalletStatus};
use crate::resolve::{CredentialOfferGrantType, ValidatedIssuance};
use crate::secret::{AuthorizationCode, TransactionCode};
use crate::validate::validate_public_string;
#[cfg(feature = "identity-jose")]
use crate::{
    EncryptedCredentialRequest, JoseJweCredentialRequestEncryptor,
    JoseJweCredentialResponseDecryptor,
};

/// Token request for the OAuth Authorization Code grant.
///
/// The authorization code and PKCE verifier are bearer credentials. The type
/// keeps both in zeroizing buffers and exposes them only through the token
/// endpoint serialization boundary.
pub struct AuthorizationCodeTokenRequest {
    grant_type: GrantType,
    code: Zeroizing<String>,
    redirect_uri: String,
    code_verifier: Zeroizing<String>,
    client_id: Option<String>,
    attestation_client_authentication: Option<AttestationClientAuthentication>,
}

impl AuthorizationCodeTokenRequest {
    /// Builds an authorization-code token request from secret-bearing wrappers.
    pub fn new(
        issuance: &ValidatedIssuance,
        code: &AuthorizationCode,
        redirect_uri: String,
        pkce_verifier: &PkceVerifier,
        client_id: Option<String>,
        attestation_client_authentication: Option<AttestationClientAuthentication>,
    ) -> WalletResult<Self> {
        issuance.require_grant(CredentialOfferGrantType::AuthorizationCode)?;
        validate_public_string(&redirect_uri)?;
        if let Some(value) = &client_id {
            validate_public_string(value)?;
        }
        if let Some(attestation) = &attestation_client_authentication {
            attestation
                .validate()
                .map_err(|_| WalletError::new(WalletStatus::InvalidRequest))?;
        }
        Ok(Self {
            grant_type: GrantType::AuthorizationCode,
            code: Zeroizing::new(code.expose_secret().to_owned()),
            redirect_uri,
            code_verifier: Zeroizing::new(pkce_verifier.expose_secret().to_owned()),
            client_id,
            attestation_client_authentication,
        })
    }
}

/// Redacts bearer material so accidental `{:?}` logging cannot leak secrets.
impl Debug for AuthorizationCodeTokenRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuthorizationCodeTokenRequest")
            .field("grant_type", &self.grant_type)
            .field("code", &"<redacted>")
            .field("redirect_uri", &self.redirect_uri)
            .field("code_verifier", &"<redacted>")
            .field("client_id", &self.client_id)
            .field(
                "attestation_client_authentication",
                &self.attestation_client_authentication.is_some(),
            )
            .finish()
    }
}

impl Serialize for AuthorizationCodeTokenRequest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // The token endpoint requires the raw grant parameters on the wire; this
        // is the single, intentional exposure point for the bearer secrets.
        let mut len = 4;
        len += usize::from(self.client_id.is_some());
        len += 2 * usize::from(self.attestation_client_authentication.is_some());
        let mut map = serializer.serialize_map(Some(len))?;
        map.serialize_entry("grant_type", &self.grant_type)?;
        map.serialize_entry("code", self.code.as_str())?;
        map.serialize_entry("redirect_uri", &self.redirect_uri)?;
        map.serialize_entry("code_verifier", self.code_verifier.as_str())?;
        if let Some(client_id) = &self.client_id {
            map.serialize_entry("client_id", client_id)?;
        }
        if let Some(attestation) = &self.attestation_client_authentication {
            map.serialize_entry("client_attestation", &attestation.client_attestation)?;
            map.serialize_entry(
                "client_attestation_pop",
                &attestation.client_attestation_pop,
            )?;
        }
        map.end()
    }
}

/// Token request for the OpenID4VCI Pre-Authorized Code grant.
///
/// The pre-authorized code and transaction code are bearer credentials, so this
/// type keeps them in zeroizing buffers, refuses to derive `Debug`/`Clone`/
/// `Deserialize`, and exposes the plaintext only through the deliberate wire
/// `Serialize` boundary that transmits the request to the token endpoint.
pub struct PreAuthorizedTokenRequest {
    grant_type: GrantType,
    pre_authorized_code: Zeroizing<String>,
    tx_code: Option<Zeroizing<String>>,
    client_id: Option<String>,
    attestation_client_authentication: Option<AttestationClientAuthentication>,
}

impl PreAuthorizedTokenRequest {
    /// Builds a pre-authorized token request from secret-bearing wrappers.
    pub fn new(
        issuance: &ValidatedIssuance,
        tx_code: Option<&TransactionCode>,
        client_id: Option<String>,
        attestation_client_authentication: Option<AttestationClientAuthentication>,
    ) -> WalletResult<Self> {
        let pre_authorized_code = issuance.pre_authorized_code()?;
        if let Some(value) = &client_id {
            validate_public_string(value)?;
        }
        if let Some(attestation) = &attestation_client_authentication {
            attestation
                .validate()
                .map_err(|_| WalletError::new(WalletStatus::InvalidRequest))?;
        }
        Ok(Self {
            grant_type: GrantType::PreAuthorizedCode,
            pre_authorized_code: Zeroizing::new(pre_authorized_code.to_owned()),
            tx_code: tx_code.map(|code| Zeroizing::new(code.expose_secret().to_owned())),
            client_id,
            attestation_client_authentication,
        })
    }
}

/// Redacts the bearer secrets so accidental `{:?}` logging cannot leak them.
impl Debug for PreAuthorizedTokenRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PreAuthorizedTokenRequest")
            .field("grant_type", &self.grant_type)
            .field("pre_authorized_code", &"<redacted>")
            .field("tx_code", &self.tx_code.as_ref().map(|_| "<redacted>"))
            .field("client_id", &self.client_id)
            .field(
                "attestation_client_authentication",
                &self.attestation_client_authentication.is_some(),
            )
            .finish()
    }
}

impl Serialize for PreAuthorizedTokenRequest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // The token endpoint requires the raw grant parameters on the wire; this
        // is the single, intentional exposure point for the bearer secrets.
        let mut len = 2;
        len += usize::from(self.tx_code.is_some());
        len += usize::from(self.client_id.is_some());
        len += 2 * usize::from(self.attestation_client_authentication.is_some());
        let mut map = serializer.serialize_map(Some(len))?;
        map.serialize_entry("grant_type", &self.grant_type)?;
        map.serialize_entry("pre-authorized_code", self.pre_authorized_code.as_str())?;
        if let Some(tx_code) = &self.tx_code {
            map.serialize_entry("tx_code", tx_code.as_str())?;
        }
        if let Some(client_id) = &self.client_id {
            map.serialize_entry("client_id", client_id)?;
        }
        if let Some(attestation) = &self.attestation_client_authentication {
            map.serialize_entry("client_attestation", &attestation.client_attestation)?;
            map.serialize_entry(
                "client_attestation_pop",
                &attestation.client_attestation_pop,
            )?;
        }
        map.end()
    }
}

/// Wallet-built Credential Request bundle with optional DPoP proof.
#[derive(PartialEq)]
pub struct WalletCredentialRequest {
    credential_request: CredentialRequest,
    dpop_proof_jwt: Option<String>,
    request_encryption_required: bool,
    request_encryption_metadata: Option<CredentialRequestEncryptionMetadata>,
}

impl Debug for WalletCredentialRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("WalletCredentialRequest")
            .field("credential_request", &self.credential_request)
            .field(
                "dpop_proof_jwt",
                &self.dpop_proof_jwt.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "request_encryption_required",
                &self.request_encryption_required,
            )
            .finish()
    }
}

impl Drop for WalletCredentialRequest {
    fn drop(&mut self) {
        self.dpop_proof_jwt.zeroize();
    }
}

impl WalletCredentialRequest {
    /// Creates a credential request for a credential configuration identifier.
    pub fn for_configuration_id(
        issuance: &ValidatedIssuance,
        credential_configuration_id: String,
        proofs: Option<Proofs>,
        credential_response_encryption: Option<CredentialResponseEncryption>,
        dpop_proof_jwt: Option<String>,
    ) -> WalletResult<Self> {
        validate_public_string(&credential_configuration_id)?;
        if !issuance.allows_configuration(&credential_configuration_id) {
            return Err(WalletError::new(WalletStatus::InvalidRequest));
        }
        Self::new(
            issuance,
            CredentialRequest {
                credential_configuration_id: Some(credential_configuration_id),
                credential_identifier: None,
                proofs,
                credential_response_encryption,
            },
            dpop_proof_jwt,
        )
    }

    /// Creates a credential request for a credential identifier from token response authorization details.
    pub fn for_credential_identifier(
        issuance: &ValidatedIssuance,
        credential_identifier: String,
        proofs: Option<Proofs>,
        credential_response_encryption: Option<CredentialResponseEncryption>,
        dpop_proof_jwt: Option<String>,
    ) -> WalletResult<Self> {
        validate_public_string(&credential_identifier)?;
        Self::new(
            issuance,
            CredentialRequest {
                credential_configuration_id: None,
                credential_identifier: Some(credential_identifier),
                proofs,
                credential_response_encryption,
            },
            dpop_proof_jwt,
        )
    }

    /// Creates a validated wallet credential request.
    pub fn new(
        issuance: &ValidatedIssuance,
        credential_request: CredentialRequest,
        dpop_proof_jwt: Option<String>,
    ) -> WalletResult<Self> {
        credential_request
            .validate()
            .map_err(|_| WalletError::new(WalletStatus::InvalidRequest))?;
        if let Some(jwt) = &dpop_proof_jwt {
            validate_public_string(jwt)?;
        }
        if let Some(configuration_id) = &credential_request.credential_configuration_id {
            if !issuance.allows_configuration(configuration_id) {
                return Err(WalletError::new(WalletStatus::InvalidRequest));
            }
        }
        if let Some(encryption) = &credential_request.credential_response_encryption {
            validate_response_encryption_selection(
                encryption,
                issuance.response_encryption_metadata(),
            )?;
        }
        if issuance
            .response_encryption_metadata()
            .is_some_and(|metadata| metadata.encryption_required)
            && credential_request.credential_response_encryption.is_none()
        {
            return Err(WalletError::new(WalletStatus::ResponseEncryptionRequired));
        }
        let request_encryption_metadata = issuance.request_encryption_metadata().cloned();
        Ok(Self {
            request_encryption_required: credential_request
                .credential_response_encryption
                .is_some()
                || request_encryption_metadata
                    .as_ref()
                    .is_some_and(|metadata| metadata.encryption_required),
            credential_request,
            dpop_proof_jwt,
            request_encryption_metadata,
        })
    }

    /// Creates a request while enforcing the issuer's response-encryption policy.
    ///
    /// Callers that obtained issuer metadata must use this boundary instead of
    /// constructing a request in isolation; it prevents a required encrypted
    /// response from being silently downgraded to plaintext.
    pub fn new_with_issuer_metadata(
        issuance: &ValidatedIssuance,
        credential_request: CredentialRequest,
        dpop_proof_jwt: Option<String>,
        issuer_metadata: &IssuerMetadata,
    ) -> WalletResult<Self> {
        issuer_metadata
            .validate()
            .map_err(|_| WalletError::new(WalletStatus::InvalidIssuerMetadata))?;
        if !issuance.is_bound_to_metadata(issuer_metadata) {
            return Err(WalletError::new(WalletStatus::IssuerMetadataIssuerMismatch));
        }
        Self::new(issuance, credential_request, dpop_proof_jwt)
    }

    /// Returns the selected credential configuration identifier, if present.
    #[must_use]
    pub fn credential_configuration_id(&self) -> Option<&str> {
        self.credential_request
            .credential_configuration_id
            .as_deref()
    }

    /// Returns the token-authorized credential identifier, if present.
    #[must_use]
    pub fn credential_identifier(&self) -> Option<&str> {
        self.credential_request.credential_identifier.as_deref()
    }

    /// Returns the optional DPoP proof for the HTTP header boundary.
    #[must_use]
    pub fn dpop_proof_jwt(&self) -> Option<&str> {
        self.dpop_proof_jwt.as_deref()
    }

    /// Reports whether the request body must be transported as compact JWE.
    ///
    /// Encryption is mandatory when issuer metadata requires encrypted
    /// Credential Requests or when the Wallet requests an encrypted response.
    #[must_use]
    pub const fn requires_request_encryption(&self) -> bool {
        self.request_encryption_required
    }

    /// Serializes a request only when plaintext transport is permitted.
    ///
    /// This is the supported plaintext wire boundary. The inner request is not
    /// exposed so callers cannot accidentally serialize it after the Wallet or
    /// issuer committed to request encryption.
    pub fn plaintext_json(&self) -> WalletResult<Zeroizing<String>> {
        if self.request_encryption_required {
            return Err(WalletError::new(WalletStatus::RequestEncryptionRequired));
        }
        self.credential_request
            .to_json()
            .map(Zeroizing::new)
            .map_err(|_| WalletError::new(WalletStatus::InvalidRequest))
    }

    /// Encrypts the request using the issuer-advertised request-encryption key.
    #[cfg(feature = "identity-jose")]
    pub fn encrypt_request(
        &self,
        encryptor: &JoseJweCredentialRequestEncryptor,
    ) -> WalletResult<EncryptedCredentialRequest> {
        let metadata = self
            .request_encryption_metadata
            .as_ref()
            .ok_or_else(|| WalletError::new(WalletStatus::InvalidEncryptionParameters))?;
        encryptor.encrypt_request(&self.credential_request, metadata)
    }

    /// Returns response-encryption parameters requested by the Wallet.
    #[must_use]
    pub fn response_encryption(&self) -> Option<&CredentialResponseEncryption> {
        self.credential_request
            .credential_response_encryption
            .as_ref()
    }

    /// Parses a Credential Response while enforcing the request's encryption
    /// commitment. Supplying JSON after response encryption was requested is a
    /// downgrade and is rejected before parsing.
    #[cfg(feature = "identity-jose")]
    pub fn parse_response(
        &self,
        body: &str,
        decryptor: Option<&JoseJweCredentialResponseDecryptor>,
    ) -> WalletResult<CredentialResponse> {
        match (
            &self.credential_request.credential_response_encryption,
            decryptor,
        ) {
            (Some(_), Some(decryptor)) => decryptor.decrypt_response(body),
            (Some(_), None) => Err(WalletError::new(WalletStatus::ResponseEncryptionRequired)),
            (None, None) => CredentialResponse::parse_json(body)
                .map_err(|_| WalletError::new(WalletStatus::InvalidRequest)),
            (None, Some(_)) => Err(WalletError::new(WalletStatus::InvalidEncryptionParameters)),
        }
    }
}

fn validate_response_encryption_selection(
    encryption: &CredentialResponseEncryption,
    metadata: Option<&CredentialResponseEncryptionMetadata>,
) -> WalletResult<()> {
    let metadata =
        metadata.ok_or_else(|| WalletError::new(WalletStatus::InvalidEncryptionParameters))?;
    metadata
        .validate()
        .map_err(|_| WalletError::new(WalletStatus::InvalidIssuerMetadata))?;
    let algorithm = encryption
        .jwk
        .algorithm()
        .ok_or_else(|| WalletError::new(WalletStatus::InvalidEncryptionParameters))?;

    // Parameters in `credential_response_encryption` are a selection from the
    // issuer's advertised capabilities. Rejecting locally avoids a downgrade
    // or a request that the issuer can only reject after network transport.
    if !metadata
        .alg_values_supported
        .as_ref()
        .is_some_and(|values| values.iter().any(|value| value == algorithm))
        || !metadata
            .enc_values_supported
            .as_ref()
            .is_some_and(|values| values.iter().any(|value| value == &encryption.enc))
        || encryption.zip.as_ref().is_some_and(|zip| {
            !metadata
                .zip_values_supported
                .as_ref()
                .is_some_and(|values| values.iter().any(|value| value == zip))
        })
    {
        return Err(WalletError::new(WalletStatus::InvalidEncryptionParameters));
    }
    Ok(())
}
