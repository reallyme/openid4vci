// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Exchanges authorization codes and refresh tokens for DPoP-bound access tokens.
//!
//! The FAPI 2.0 final profile prohibits routine refresh-token rotation for
//! confidential, sender-constrained clients. Refresh exchanges therefore keep
//! the original opaque token valid until its bounded expiry while issuing a
//! fresh DPoP-bound access token.

use openid4vci_http::{
    CredentialAuthorizationDecision, OAuthHttpError, OAuthHttpErrorReason, OAuthHttpResult,
    OAuthParameters, OAuthRequestHeaders, TokenResponse, ValidatedAccessToken,
};
use openid4vci_types::CredentialSelector;

use super::credential_authorization::{CredentialAuthorization, CredentialSelectorResolutionError};
use super::run::{ACCESS_TOKEN_EXPIRES_IN_SECONDS, REFRESH_TOKEN_EXPIRES_IN_SECONDS};
use super::store_authorization_state::{
    opaque_token_digest, AccessTokenRecord, AuthenticatedClient, CodeRecord,
    ExampleOAuthAuthorizationServer, RefreshTokenRecord,
};

const AUTHORIZATION_CODE_GRANT: &str = "authorization_code";
const REFRESH_TOKEN_GRANT: &str = "refresh_token";

impl ExampleOAuthAuthorizationServer {
    pub(super) fn exchange_token(
        &self,
        headers: &OAuthRequestHeaders,
        parameters: &OAuthParameters,
    ) -> OAuthHttpResult<TokenResponse> {
        let client = self.validate_client_attestation(headers)?;
        match Self::required(parameters, "grant_type")? {
            AUTHORIZATION_CODE_GRANT => {
                self.exchange_authorization_code(headers, parameters, &client)
            }
            REFRESH_TOKEN_GRANT => self.exchange_refresh_token(headers, parameters, &client),
            _ => Err(OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequest)),
        }
    }

    pub(super) fn lookup_access_token_security_context(
        &self,
        access_token: &str,
    ) -> OAuthHttpResult<ValidatedAccessToken> {
        let records = self
            .access_tokens
            .lock()
            .map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequest))?;
        let record = records
            .get(&opaque_token_digest(access_token))
            .ok_or(OAuthHttpError::new(OAuthHttpErrorReason::InvalidDpopProof))?;
        if Self::now_unix_seconds()? >= record.expires_at {
            return Err(OAuthHttpError::new(OAuthHttpErrorReason::InvalidDpopProof));
        }
        ValidatedAccessToken::new(record.client_subject.clone(), Some(record.dpop_jkt.clone()))
    }

    fn exchange_authorization_code(
        &self,
        headers: &OAuthRequestHeaders,
        parameters: &OAuthParameters,
        client: &AuthenticatedClient,
    ) -> OAuthHttpResult<TokenResponse> {
        let code = Self::required(parameters, "code")?;
        let verifier = parameters
            .get("code_verifier")
            .map(String::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or(OAuthHttpError::new(OAuthHttpErrorReason::InvalidGrant))?;
        let record = self.consume_authorization_code(code)?;
        if Self::now_unix_seconds()? >= record.expires_at {
            return Err(OAuthHttpError::new(OAuthHttpErrorReason::InvalidGrant));
        }
        validate_client_binding(parameters, client, &record)?;
        Self::verify_pkce_s256(verifier, &record.code_challenge)?;
        let proof_jkt = self.validate_dpop(headers, self.endpoint("/token"), None, None)?;
        if record
            .dpop_jkt
            .as_deref()
            .is_some_and(|expected| expected != proof_jkt)
        {
            return Err(OAuthHttpError::new(OAuthHttpErrorReason::InvalidDpopProof));
        }
        let access_token = self.issue_access_token(
            proof_jkt,
            record.client_subject.clone(),
            record.credential_authorizations.clone(),
        )?;
        let refresh_token = self.issue_refresh_token(RefreshTokenRecord {
            client_id: record.client_id.clone(),
            client_subject: record.client_subject.clone(),
            client_instance_key_thumbprint: record.client_instance_key_thumbprint.clone(),
            credential_authorizations: record.credential_authorizations.clone(),
            expires_at: refresh_token_expiry()?,
        })?;
        self.used_code_access_tokens
            .lock()
            .map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequest))?
            .insert(
                opaque_token_digest(code),
                opaque_token_digest(&access_token),
            );
        Ok(self.token_response(
            access_token,
            refresh_token,
            &record.credential_authorizations,
        ))
    }

    fn exchange_refresh_token(
        &self,
        headers: &OAuthRequestHeaders,
        parameters: &OAuthParameters,
        client: &AuthenticatedClient,
    ) -> OAuthHttpResult<TokenResponse> {
        let presented = Self::required(parameters, "refresh_token")?;
        let presented_digest = token_digest(presented);
        let record = self
            .refresh_tokens
            .lock()
            .map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequest))?
            .get(&presented_digest)
            .cloned()
            .ok_or(OAuthHttpError::new(OAuthHttpErrorReason::InvalidGrant))?;
        if Self::now_unix_seconds()? >= record.expires_at {
            self.refresh_tokens
                .lock()
                .map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequest))?
                .remove(&presented_digest);
            return Err(OAuthHttpError::new(OAuthHttpErrorReason::InvalidGrant));
        }
        validate_refresh_client_binding(parameters, client, &record)?;
        let proof_jkt = self.validate_dpop(headers, self.endpoint("/token"), None, None)?;
        let access_token = self.issue_access_token(
            proof_jkt,
            record.client_subject.clone(),
            record.credential_authorizations.clone(),
        )?;
        Ok(self.token_response(
            access_token,
            presented.to_owned(),
            &record.credential_authorizations,
        ))
    }

    fn consume_authorization_code(&self, code: &str) -> OAuthHttpResult<CodeRecord> {
        let record = self
            .code_records
            .lock()
            .map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequest))?
            .remove(&opaque_token_digest(code));
        let Some(record) = record else {
            if let Some(access_token) = self
                .used_code_access_tokens
                .lock()
                .map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequest))?
                .remove(&opaque_token_digest(code))
            {
                self.access_tokens
                    .lock()
                    .map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequest))?
                    .remove(&access_token);
            }
            return Err(OAuthHttpError::new(OAuthHttpErrorReason::InvalidGrant));
        };
        Ok(record)
    }

    pub(super) fn issue_access_token(
        &self,
        proof_jkt: String,
        client_subject: String,
        credential_authorizations: Vec<CredentialAuthorization>,
    ) -> OAuthHttpResult<String> {
        let access_token = Self::random_token("openid4vci-access-token-")?;
        self.store_access_token(
            access_token.clone(),
            proof_jkt,
            client_subject,
            credential_authorizations,
        )?;
        Ok(access_token)
    }

    fn store_access_token(
        &self,
        access_token: String,
        proof_jkt: String,
        client_subject: String,
        credential_authorizations: Vec<CredentialAuthorization>,
    ) -> OAuthHttpResult<()> {
        let expires_at = Self::now_unix_seconds()?
            .checked_add(ACCESS_TOKEN_EXPIRES_IN_SECONDS)
            .ok_or(OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequest))?;
        self.access_tokens
            .lock()
            .map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequest))?
            .insert(
                opaque_token_digest(&access_token),
                AccessTokenRecord {
                    dpop_jkt: proof_jkt,
                    client_subject,
                    credential_authorizations,
                    expires_at,
                },
            );
        Ok(())
    }

    pub(super) fn authorize_access_token_credential(
        &self,
        access_token: &str,
        selector: &CredentialSelector,
    ) -> OAuthHttpResult<CredentialAuthorizationDecision> {
        let records = self
            .access_tokens
            .lock()
            .map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequest))?;
        let record = records
            .get(&opaque_token_digest(access_token))
            .ok_or(OAuthHttpError::new(OAuthHttpErrorReason::InvalidDpopProof))?;
        if Self::now_unix_seconds()? >= record.expires_at {
            return Err(OAuthHttpError::new(OAuthHttpErrorReason::InvalidDpopProof));
        }
        let requested_authorization = match CredentialAuthorization::from_selector(selector) {
            Ok(value) => value,
            Err(CredentialSelectorResolutionError::UnknownConfiguration) => {
                return Ok(CredentialAuthorizationDecision::UnknownCredentialConfiguration);
            }
            Err(CredentialSelectorResolutionError::UnknownIdentifier) => {
                return Ok(CredentialAuthorizationDecision::UnknownCredentialIdentifier);
            }
        };
        if record
            .credential_authorizations
            .iter()
            .any(|authorization| authorization == &requested_authorization)
        {
            let context = openid4vci_issuer::IssuanceAuthorization::new(
                requested_authorization.configuration_id().to_owned(),
                record.client_subject.clone(),
                opaque_token_digest(&record.client_subject),
            )
            .and_then(|authorization| authorization.with_client_id(record.client_subject.clone()))
            .map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequest))?;
            Ok(CredentialAuthorizationDecision::Authorized(context))
        } else {
            Ok(CredentialAuthorizationDecision::InsufficientAuthorization)
        }
    }

    fn issue_refresh_token(&self, record: RefreshTokenRecord) -> OAuthHttpResult<String> {
        let refresh_token = Self::random_token("openid4vci-refresh-token-")?;
        self.refresh_tokens
            .lock()
            .map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequest))?
            .insert(token_digest(&refresh_token), record);
        Ok(refresh_token)
    }

    fn token_response(
        &self,
        access_token: String,
        refresh_token: String,
        credential_authorizations: &[CredentialAuthorization],
    ) -> TokenResponse {
        TokenResponse::new(
            access_token,
            "DPoP".to_owned(),
            ACCESS_TOKEN_EXPIRES_IN_SECONDS,
            credential_authorizations
                .iter()
                .map(|authorization| authorization.response_detail(&self.credential_issuer))
                .collect(),
        )
        .with_refresh_token(refresh_token)
    }
}

pub(super) fn validate_client_binding(
    parameters: &OAuthParameters,
    client: &AuthenticatedClient,
    record: &CodeRecord,
) -> OAuthHttpResult<()> {
    if client.subject != record.client_subject
        || client.instance_key_thumbprint != record.client_instance_key_thumbprint
        || parameters
            .get("client_id")
            .is_some_and(|client_id| client_id != &record.client_id)
    {
        return Err(OAuthHttpError::new(OAuthHttpErrorReason::InvalidGrant));
    }
    Ok(())
}

pub(super) fn validate_refresh_client_binding(
    parameters: &OAuthParameters,
    client: &AuthenticatedClient,
    record: &RefreshTokenRecord,
) -> OAuthHttpResult<()> {
    if client.subject != record.client_subject
        || client.instance_key_thumbprint != record.client_instance_key_thumbprint
        || parameters
            .get("client_id")
            .is_some_and(|client_id| client_id != &record.client_id)
    {
        return Err(OAuthHttpError::new(OAuthHttpErrorReason::InvalidGrant));
    }
    Ok(())
}

fn refresh_token_expiry() -> OAuthHttpResult<u64> {
    ExampleOAuthAuthorizationServer::now_unix_seconds()?
        .checked_add(REFRESH_TOKEN_EXPIRES_IN_SECONDS)
        .ok_or(OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequest))
}

fn token_digest(token: &str) -> [u8; 32] {
    opaque_token_digest(token)
}
