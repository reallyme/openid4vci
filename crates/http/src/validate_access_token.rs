// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Required access-token validation boundary for issuer resource routes.

use openid4vci_issuer::IssuanceAuthorization;
use openid4vci_types::CredentialSelector;
use reallyme_openid_oauth::validation::validate_token;
use zeroize::Zeroizing;

use crate::serve_oauth::{OAuthHttpError, OAuthHttpErrorReason, OAuthHttpResult};

/// Security context established while validating an access token.
///
/// The authenticated client identifier is retained separately from the token
/// because wallet-attestation validation must bind both authentication events
/// to the same OAuth client. Both values are zeroized when this context drops.
pub struct ValidatedAccessToken {
    client_id: Zeroizing<String>,
    confirmed_jkt: Option<Zeroizing<String>>,
}

impl ValidatedAccessToken {
    /// Creates a validated access-token security context.
    pub fn new(client_id: String, confirmed_jkt: Option<String>) -> OAuthHttpResult<Self> {
        let client_id = Zeroizing::new(client_id);
        validate_token(client_id.as_str())
            .map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidClient))?;

        let confirmed_jkt = confirmed_jkt.map(Zeroizing::new);
        if let Some(thumbprint) = confirmed_jkt.as_deref() {
            validate_token(thumbprint)
                .map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidDpopProof))?;
        }

        Ok(Self {
            client_id,
            confirmed_jkt,
        })
    }

    /// OAuth client identifier authenticated by the access token.
    #[must_use]
    pub fn client_id(&self) -> &str {
        self.client_id.as_str()
    }

    /// RFC 9449 confirmation thumbprint for a sender-constrained token.
    #[must_use]
    pub fn confirmed_jkt(&self) -> Option<&str> {
        self.confirmed_jkt.as_deref().map(String::as_str)
    }
}

/// Result of binding a Credential Request selector to an access token.
pub enum CredentialAuthorizationDecision {
    /// The selector exists and the access token authorizes it.
    Authorized(IssuanceAuthorization),
    /// The credential configuration is not supported by this deployment.
    UnknownCredentialConfiguration,
    /// The credential identifier was not issued by this deployment.
    UnknownCredentialIdentifier,
    /// The selector exists but is outside the access token's grant.
    InsufficientAuthorization,
}

/// Validates access tokens presented to protected issuer resources.
///
/// Keeping this boundary separate from the co-located authorization-server
/// adapter permits external AS deployments without default-open resources.
pub trait AccessTokenValidator: Send + Sync {
    /// Validates token integrity, expiry, revocation, audience, and issuer and
    /// returns the authenticated client and RFC 9449 confirmation binding.
    fn validate_access_token(&self, access_token: &str) -> OAuthHttpResult<ValidatedAccessToken>;

    /// Authorizes a credential selector against an already validated token.
    fn authorize_credential_request(
        &self,
        access_token: &str,
        selector: &CredentialSelector,
    ) -> OAuthHttpResult<CredentialAuthorizationDecision>;

    /// Authorizes retrieval of one deferred transaction. The default fails closed.
    fn authorize_deferred_credential_request(
        &self,
        access_token: &str,
        transaction_id: &str,
    ) -> OAuthHttpResult<IssuanceAuthorization> {
        let _ = (access_token, transaction_id);
        Err(OAuthHttpError::new(
            OAuthHttpErrorReason::InsufficientAuthorization,
        ))
    }

    /// Authorizes one notification identifier. The default fails closed.
    fn authorize_notification_request(
        &self,
        access_token: &str,
        notification_id: &str,
    ) -> OAuthHttpResult<()> {
        let _ = (access_token, notification_id);
        Err(OAuthHttpError::new(
            OAuthHttpErrorReason::InsufficientAuthorization,
        ))
    }
}
