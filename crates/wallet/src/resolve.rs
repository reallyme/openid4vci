// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Credential Offer resolution.

use openid4vci_types::{
    parse_credential_offer_uri, CredentialOffer, CredentialRequestEncryptionMetadata,
    CredentialResponseEncryptionMetadata, IssuerMetadata, ParsedCredentialOffer,
};

use crate::error::{WalletError, WalletResult, WalletStatus};

/// Grant selected for one validated issuance interaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialOfferGrantType {
    /// OAuth Authorization Code grant.
    AuthorizationCode,
    /// OpenID4VCI Pre-Authorized Code grant.
    PreAuthorizedCode,
}

/// Issuance interaction bound to trusted issuer metadata and one authorization server.
///
/// Offer-initiated interactions additionally retain the validated offer. A
/// wallet-initiated authorization-code interaction has no offer, but still
/// carries the same issuer, authorization-server, and configuration binding.
pub struct ValidatedIssuance {
    offer: Option<CredentialOffer>,
    grant_type: CredentialOfferGrantType,
    credential_issuer: String,
    authorization_server: String,
    credential_configuration_ids: Vec<String>,
    request_encryption: Option<CredentialRequestEncryptionMetadata>,
    response_encryption: Option<CredentialResponseEncryptionMetadata>,
}

impl core::fmt::Debug for ValidatedIssuance {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ValidatedIssuance")
            .field("credential_issuer", &self.credential_issuer)
            .field("grant_type", &self.grant_type)
            .field("authorization_server", &self.authorization_server)
            .field(
                "credential_configuration_count",
                &self.credential_configuration_ids.len(),
            )
            .finish()
    }
}

impl ValidatedIssuance {
    /// Validates an offer and binds it to one grant and authorization server.
    pub fn new(
        offer: CredentialOffer,
        metadata: &IssuerMetadata,
        grant_type: CredentialOfferGrantType,
        authorization_server: String,
    ) -> WalletResult<Self> {
        validate_offer_authorization_servers(&offer, metadata)?;
        let allowed = metadata.authorization_servers.as_ref().map_or_else(
            || authorization_server == metadata.credential_issuer,
            |servers| servers.iter().any(|server| server == &authorization_server),
        );
        if !allowed {
            return Err(WalletError::new(WalletStatus::InvalidAuthorizationServer));
        }
        let grants = offer
            .grants
            .as_ref()
            .ok_or_else(|| WalletError::new(WalletStatus::MissingRequiredValue))?;
        let hint = match grant_type {
            CredentialOfferGrantType::AuthorizationCode => grants
                .authorization_code
                .as_ref()
                .ok_or_else(|| WalletError::new(WalletStatus::MissingRequiredValue))?
                .authorization_server
                .as_deref(),
            CredentialOfferGrantType::PreAuthorizedCode => grants
                .pre_authorized_code
                .as_ref()
                .ok_or_else(|| WalletError::new(WalletStatus::MissingRequiredValue))?
                .authorization_server
                .as_deref(),
        };
        if hint.is_some_and(|hint| hint != authorization_server) {
            return Err(WalletError::new(WalletStatus::InvalidAuthorizationServer));
        }
        Ok(Self {
            credential_issuer: offer.credential_issuer.clone(),
            credential_configuration_ids: offer.credential_configuration_ids.clone(),
            offer: Some(offer),
            grant_type,
            authorization_server,
            request_encryption: metadata.credential_request_encryption.clone(),
            response_encryption: metadata.credential_response_encryption.clone(),
        })
    }

    /// Binds a wallet-initiated authorization-code flow to validated metadata.
    ///
    /// This constructor deliberately has no Credential Offer input. Supported
    /// configuration identifiers come from the metadata that established the
    /// issuer boundary for the interaction.
    pub fn wallet_initiated(
        metadata: &IssuerMetadata,
        authorization_server: String,
    ) -> WalletResult<Self> {
        metadata
            .validate()
            .map_err(|_| WalletError::new(WalletStatus::InvalidIssuerMetadata))?;
        let allowed = metadata.authorization_servers.as_ref().map_or_else(
            || authorization_server == metadata.credential_issuer,
            |servers| servers.iter().any(|server| server == &authorization_server),
        );
        if !allowed {
            return Err(WalletError::new(WalletStatus::InvalidAuthorizationServer));
        }
        Ok(Self {
            offer: None,
            grant_type: CredentialOfferGrantType::AuthorizationCode,
            credential_issuer: metadata.credential_issuer.clone(),
            authorization_server,
            credential_configuration_ids: metadata
                .credential_configurations_supported
                .keys()
                .cloned()
                .collect(),
            request_encryption: metadata.credential_request_encryption.clone(),
            response_encryption: metadata.credential_response_encryption.clone(),
        })
    }

    /// Returns the authorization server to which this interaction is bound.
    #[must_use]
    pub fn authorization_server(&self) -> &str {
        &self.authorization_server
    }

    pub(crate) fn require_grant(&self, expected: CredentialOfferGrantType) -> WalletResult<()> {
        if self.grant_type != expected {
            return Err(WalletError::new(WalletStatus::InvalidRequest));
        }
        Ok(())
    }

    pub(crate) fn pre_authorized_code(&self) -> WalletResult<&str> {
        self.require_grant(CredentialOfferGrantType::PreAuthorizedCode)?;
        self.offer
            .as_ref()
            .ok_or_else(|| WalletError::new(WalletStatus::MissingRequiredValue))?
            .grants
            .as_ref()
            .and_then(|grants| grants.pre_authorized_code.as_ref())
            .map(|grant| grant.pre_authorized_code.as_str())
            .ok_or_else(|| WalletError::new(WalletStatus::MissingRequiredValue))
    }

    pub(crate) fn allows_configuration(&self, configuration_id: &str) -> bool {
        self.credential_configuration_ids
            .iter()
            .any(|offered| offered == configuration_id)
    }

    pub(crate) const fn request_encryption_metadata(
        &self,
    ) -> Option<&CredentialRequestEncryptionMetadata> {
        self.request_encryption.as_ref()
    }

    pub(crate) const fn response_encryption_metadata(
        &self,
    ) -> Option<&CredentialResponseEncryptionMetadata> {
        self.response_encryption.as_ref()
    }

    pub(crate) fn is_bound_to_metadata(&self, metadata: &IssuerMetadata) -> bool {
        self.credential_issuer == metadata.credential_issuer
            && self.request_encryption == metadata.credential_request_encryption
            && self.response_encryption == metadata.credential_response_encryption
    }
}

/// Backwards-compatible name for offer-bound issuance interactions.
///
/// New wallet-initiated code should name [`ValidatedIssuance`] directly.
pub type ValidatedCredentialOffer = ValidatedIssuance;

/// Fetches a referenced Credential Offer.
pub trait CredentialOfferFetcher {
    /// Resolves the HTTPS `credential_offer_uri` value into a validated offer.
    ///
    /// Implementations are a security boundary: they must disable redirects,
    /// resolve every DNS answer before connecting, reject loopback, private,
    /// link-local, multicast, and otherwise non-public addresses, pin the
    /// selected address for the connection to prevent DNS rebinding, enforce a
    /// bounded response body, and send no ambient credentials.
    fn fetch_offer(&self, credential_offer_uri: &str) -> WalletResult<CredentialOffer>;
}

/// Binds every authorization-server hint in an offer to issuer metadata.
///
/// When metadata omits `authorization_servers`, OpenID4VCI defines the
/// Credential Issuer itself as the authorization server. A hint outside that
/// exact allowlist is rejected before any authorization code or transaction
/// code can be sent to it.
pub fn validate_offer_authorization_servers(
    offer: &CredentialOffer,
    metadata: &IssuerMetadata,
) -> WalletResult<()> {
    offer
        .validate()
        .map_err(|_| WalletError::new(WalletStatus::InvalidRequest))?;
    metadata
        .validate()
        .map_err(|_| WalletError::new(WalletStatus::InvalidIssuerMetadata))?;
    if offer.credential_issuer != metadata.credential_issuer {
        return Err(WalletError::new(WalletStatus::IssuerMetadataIssuerMismatch));
    }
    let is_allowed = |candidate: &str| {
        metadata.authorization_servers.as_ref().map_or_else(
            || candidate == metadata.credential_issuer,
            |servers| servers.iter().any(|server| server == candidate),
        )
    };
    if let Some(grants) = &offer.grants {
        let authorization_code_hint = grants
            .authorization_code
            .as_ref()
            .and_then(|grant| grant.authorization_server.as_deref());
        let pre_authorized_hint = grants
            .pre_authorized_code
            .as_ref()
            .and_then(|grant| grant.authorization_server.as_deref());
        for hint in [authorization_code_hint, pre_authorized_hint]
            .into_iter()
            .flatten()
        {
            if !is_allowed(hint) {
                return Err(WalletError::new(WalletStatus::InvalidAuthorizationServer));
            }
        }
    }
    Ok(())
}

/// Resolves an inline or referenced Credential Offer URI.
pub fn resolve_credential_offer_uri(
    uri: &str,
    fetcher: Option<&dyn CredentialOfferFetcher>,
) -> WalletResult<CredentialOffer> {
    match parse_credential_offer_uri(uri)
        .map_err(|_| WalletError::new(WalletStatus::InvalidRequest))?
    {
        ParsedCredentialOffer::Inline(offer) => Ok(offer),
        ParsedCredentialOffer::Reference(reference) => {
            let Some(fetcher) = fetcher else {
                return Err(WalletError::new(WalletStatus::OfferResolutionRequired));
            };
            let offer = fetcher.fetch_offer(&reference)?;
            offer
                .validate()
                .map_err(|_| WalletError::new(WalletStatus::InvalidRequest))?;
            Ok(offer)
        }
    }
}
