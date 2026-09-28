// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Authorizes conformance clients and issues sender-constrained tokens.

use std::time::{SystemTime, UNIX_EPOCH};

use super::build_authorization_redirect::{
    redirect_to_authorization_completion, redirect_with_code, redirect_with_error,
};
use super::configure::endpoint;
use super::credential_authorization::CredentialAuthorization;
use super::run::{
    AUTHORIZATION_CODE_EXPIRES_IN_SECONDS, AUTHORIZATION_COMPLETE_QUERY,
    CLIENT_ATTESTATION_POP_TYP, CLIENT_ATTESTATION_TYP, OIDF_USER_REJECT_QUERY, OPAQUE_TOKEN_BYTES,
    PAR_EXPIRES_IN_SECONDS,
};
use super::store_authorization_state::{
    opaque_token_digest, AuthenticatedClient, CodeRecord, ExampleOAuthAuthorizationServer,
    ParRecord,
};
use super::verify::{
    conformance_attester_jwk, require_string_claim, validate_temporal_claims,
    verify_compact_es256_jwt,
};
use openid4vci_http::{
    AccessTokenValidator, AuthorizationResponse, CredentialAuthorizationDecision,
    OAuthAuthorizationServer, OAuthHttpError, OAuthHttpErrorReason, OAuthHttpResult,
    OAuthParameters, OAuthRequestHeaders, PushedAuthorizationResponse, TokenResponse,
    ValidatedAccessToken,
};
use openid4vci_types::CredentialSelector;
use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_crypto::core::RngOutputKind;
use reallyme_crypto::csprng::{generate_bytes, OsSecureRandom};
use reallyme_crypto::jwk::Jwk;
use reallyme_openid_oauth::PkceVerifier;
use reallyme_openid_oauth::{
    jwk_thumbprint, AttestationClientAuthentication, DpopProof, DpopValidationContext,
};
use secrecy::SecretString;
use serde_json::Value;

impl ExampleOAuthAuthorizationServer {
    /// Registers the exact redirect URI for one conformance client.
    pub(super) fn register_redirect_uri(
        &mut self,
        client_id: String,
        redirect_uri: String,
    ) -> OAuthHttpResult<()> {
        if client_id.is_empty() || !client_id.is_ascii() {
            return Err(OAuthHttpError::new(OAuthHttpErrorReason::InvalidClient));
        }
        let parsed = url::Url::parse(&redirect_uri)
            .map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequest))?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.fragment().is_some()
        {
            return Err(OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequest));
        }
        self.registered_redirect_uris
            .entry(client_id)
            .or_default()
            .insert(redirect_uri);
        Ok(())
    }

    pub(super) fn validate_registered_client(
        &self,
        client_id: &str,
        redirect_uri: &str,
    ) -> OAuthHttpResult<()> {
        if self
            .registered_redirect_uris
            .get(client_id)
            .is_some_and(|registered| registered.contains(redirect_uri))
        {
            Ok(())
        } else {
            Err(OAuthHttpError::new(
                OAuthHttpErrorReason::InvalidPushedAuthorizationRequest,
            ))
        }
    }

    fn direct_authorization_error(
        &self,
        parameters: &OAuthParameters,
    ) -> OAuthHttpResult<AuthorizationResponse> {
        let client_id = Self::required(parameters, "client_id")?;
        let redirect_uri = Self::required(parameters, "redirect_uri")?;
        if !self
            .registered_redirect_uris
            .get(client_id)
            .is_some_and(|registered| registered.contains(redirect_uri))
        {
            return Err(OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequest));
        }
        Ok(AuthorizationResponse::redirect(redirect_with_error(
            redirect_uri,
            "invalid_request",
            parameters.get("state").map(String::as_str),
        )?))
    }

    fn invalid_request_uri_response(
        &self,
        record: &ParRecord,
    ) -> OAuthHttpResult<AuthorizationResponse> {
        // Only a callback authenticated when the PAR was accepted may receive
        // an authorization error. Rechecking registration here prevents a
        // future mutable-registration implementation from turning retained
        // PAR state into an open redirect.
        self.validate_registered_client(&record.client_id, &record.redirect_uri)
            .map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequestUri))?;
        Ok(AuthorizationResponse::redirect(redirect_with_error(
            &record.redirect_uri,
            "invalid_request_uri",
            record.state.as_deref(),
        )?))
    }

    pub(super) fn random_token(prefix: &'static str) -> OAuthHttpResult<String> {
        let mut rng = OsSecureRandom;
        let random = generate_bytes::<OPAQUE_TOKEN_BYTES>(&mut rng, RngOutputKind::Generic)
            .map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequest))?;
        let mut value = prefix.to_owned();
        value.push_str(&bytes_to_base64url(random.as_bytes()));
        Ok(value)
    }

    pub(super) fn required<'a>(
        parameters: &'a OAuthParameters,
        name: &'static str,
    ) -> OAuthHttpResult<&'a str> {
        parameters
            .get(name)
            .map(String::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequest))
    }

    pub(super) fn endpoint(&self, path: &'static str) -> String {
        endpoint(&self.authorization_server_issuer, path)
    }

    pub(super) fn validate_client_attestation(
        &self,
        headers: &OAuthRequestHeaders,
    ) -> OAuthHttpResult<AuthenticatedClient> {
        let client_attestation = headers
            .client_attestation()
            .map(str::to_owned)
            .ok_or(OAuthHttpError::new(OAuthHttpErrorReason::InvalidClient))?;
        let client_attestation_pop = headers
            .client_attestation_pop()
            .map(str::to_owned)
            .ok_or(OAuthHttpError::new(OAuthHttpErrorReason::InvalidClient))?;
        AttestationClientAuthentication::new(
            client_attestation.clone(),
            client_attestation_pop.clone(),
        )
        .map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidClient))?;
        let attester_jwk = conformance_attester_jwk()?;
        let (attestation_header, attestation_claims) =
            verify_compact_es256_jwt(&client_attestation, &attester_jwk)?;
        if attestation_header.get("typ").and_then(Value::as_str) != Some(CLIENT_ATTESTATION_TYP) {
            return Err(OAuthHttpError::new(OAuthHttpErrorReason::InvalidClient));
        }
        validate_temporal_claims(&attestation_claims)?;
        let subject = require_string_claim(&attestation_claims, "sub")?.to_owned();
        let proof_jwk_value = attestation_claims
            .get("cnf")
            .and_then(|cnf| cnf.get("jwk"))
            .cloned()
            .ok_or(OAuthHttpError::new(OAuthHttpErrorReason::InvalidClient))?;
        if proof_jwk_value.get("d").is_some() {
            return Err(OAuthHttpError::new(OAuthHttpErrorReason::InvalidClient));
        }
        let instance_key_thumbprint = jwk_thumbprint(&proof_jwk_value)
            .map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidClient))?;
        let proof_jwk = serde_json::from_value::<Jwk>(proof_jwk_value)
            .map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidClient))?;
        let (pop_header, pop_claims) =
            verify_compact_es256_jwt(&client_attestation_pop, &proof_jwk)?;
        if pop_header.get("typ").and_then(Value::as_str) != Some(CLIENT_ATTESTATION_POP_TYP) {
            return Err(OAuthHttpError::new(OAuthHttpErrorReason::InvalidClient));
        }
        validate_temporal_claims(&pop_claims)?;
        if pop_claims.get("aud").and_then(Value::as_str)
            != Some(self.authorization_server_issuer.as_str())
        {
            return Err(OAuthHttpError::new(OAuthHttpErrorReason::InvalidClient));
        }
        Ok(AuthenticatedClient {
            subject,
            instance_key_thumbprint,
        })
    }

    pub(super) fn validate_dpop(
        &self,
        headers: &OAuthRequestHeaders,
        target_uri: String,
        access_token: Option<&str>,
        confirmed_jkt: Option<&str>,
    ) -> OAuthHttpResult<String> {
        let proof_value = headers
            .dpop()
            .filter(|value| !value.trim().is_empty())
            .ok_or(OAuthHttpError::new(OAuthHttpErrorReason::InvalidDpopProof))?;
        let proof = DpopProof::new(proof_value.to_owned())
            .map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidDpopProof))?;
        let now = i64::try_from(Self::now_unix_seconds()?)
            .map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidDpopProof))?;
        proof
            .validate(
                &DpopValidationContext {
                    method: "POST".to_owned(),
                    target_uri,
                    access_token: access_token.map(str::to_owned),
                    nonce: None,
                    earliest_iat: now.saturating_sub(300),
                    latest_iat: now.saturating_add(60),
                    confirmed_jkt: confirmed_jkt.map(str::to_owned),
                },
                self.dpop_verifier.as_ref(),
            )
            .map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidDpopProof))?;
        proof
            .public_jwk_thumbprint()
            .map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidDpopProof))
    }

    pub(super) fn verify_pkce_s256(verifier: &str, challenge: &str) -> OAuthHttpResult<()> {
        let verifier = PkceVerifier::new(SecretString::new(verifier.to_owned().into_boxed_str()))
            .map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidGrant))?;
        let observed = verifier.challenge();
        if observed.code_challenge == challenge {
            Ok(())
        } else {
            Err(OAuthHttpError::new(OAuthHttpErrorReason::InvalidGrant))
        }
    }

    pub(super) fn now_unix_seconds() -> OAuthHttpResult<u64> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequest))
    }
}

impl OAuthAuthorizationServer for ExampleOAuthAuthorizationServer {
    fn security_capabilities(&self) -> openid4vci_http::OAuthAuthorizationServerCapabilities {
        openid4vci_http::OAuthAuthorizationServerCapabilities::high_assurance()
    }

    fn pushed_authorization_request(
        &self,
        headers: &OAuthRequestHeaders,
        parameters: &OAuthParameters,
    ) -> OAuthHttpResult<PushedAuthorizationResponse> {
        let client = self.validate_client_attestation(headers)?;
        if parameters.contains_key("request_uri") {
            return Err(OAuthHttpError::new(
                OAuthHttpErrorReason::InvalidPushedAuthorizationRequest,
            ));
        }
        if Self::required(parameters, "response_type")? != "code" {
            return Err(OAuthHttpError::new(
                OAuthHttpErrorReason::InvalidPushedAuthorizationRequest,
            ));
        }
        if Self::required(parameters, "code_challenge_method")? != "S256" {
            return Err(OAuthHttpError::new(
                OAuthHttpErrorReason::InvalidPushedAuthorizationRequest,
            ));
        }
        let client_id = Self::required(parameters, "client_id")?.to_owned();
        let redirect_uri = Self::required(parameters, "redirect_uri")?.to_owned();
        if client.subject != client_id {
            return Err(OAuthHttpError::new(OAuthHttpErrorReason::InvalidClient));
        }
        self.validate_registered_client(&client_id, &redirect_uri)?;
        let code_challenge = Self::required(parameters, "code_challenge")?.to_owned();
        let dpop_jkt = if headers.dpop().is_some() {
            let observed = self.validate_dpop(headers, self.endpoint("/par"), None, None)?;
            if let Some(requested_jkt) = parameters.get("dpop_jkt") {
                if requested_jkt != &observed {
                    return Err(OAuthHttpError::new(OAuthHttpErrorReason::InvalidDpopProof));
                }
            }
            Some(observed)
        } else {
            parameters
                .get("dpop_jkt")
                .map(|requested_jkt| requested_jkt.to_owned())
        };
        let now = Self::now_unix_seconds()?;
        let expires_at = now
            .checked_add(PAR_EXPIRES_IN_SECONDS)
            .ok_or(OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequest))?;
        let request_uri = Self::random_token("urn:ietf:params:oauth:request_uri:openid4vci:")?;
        let record = ParRecord {
            client_id,
            client_subject: client.subject.clone(),
            client_instance_key_thumbprint: client.instance_key_thumbprint.clone(),
            redirect_uri,
            state: parameters.get("state").cloned(),
            code_challenge,
            dpop_jkt,
            credential_authorizations: CredentialAuthorization::from_parameters(parameters)?,
            expires_at,
            used: false,
        };
        self.par_records
            .lock()
            .map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequest))?
            .insert(request_uri.clone(), record);
        Ok(PushedAuthorizationResponse::new(
            request_uri,
            PAR_EXPIRES_IN_SECONDS,
        ))
    }

    fn authorize(&self, parameters: &OAuthParameters) -> OAuthHttpResult<AuthorizationResponse> {
        let Some(request_uri) = parameters
            .get("request_uri")
            .map(String::as_str)
            .filter(|value| !value.trim().is_empty())
        else {
            // OAuth authorization errors may use a callback only after exact
            // client registration has been checked by this provider.
            return self.direct_authorization_error(parameters);
        };
        let now = Self::now_unix_seconds()?;
        let client_id = Self::required(parameters, "client_id")?;
        let mut records = self
            .par_records
            .lock()
            .map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequest))?;
        let record = records
            .get_mut(request_uri)
            .ok_or_else(|| OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequestUri))?;
        if client_id != record.client_id {
            let retained_record = record.clone();
            drop(records);
            if !self.registered_redirect_uris.contains_key(client_id) {
                return Err(OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequestUri));
            }
            // The original PAR callback was authenticated with client 1 and
            // is the only trustworthy destination associated with the invalid
            // request URI. The front-channel redirect_uri remains ignored.
            return self.invalid_request_uri_response(&retained_record);
        }
        if now >= record.expires_at || record.used {
            let retained_record = record.clone();
            drop(records);
            return self.invalid_request_uri_response(&retained_record);
        }
        if parameters
            .get(AUTHORIZATION_COMPLETE_QUERY)
            .map(String::as_str)
            != Some("1")
        {
            let completion = redirect_to_authorization_completion(
                &self.endpoint("/authorize"),
                client_id,
                request_uri,
                AUTHORIZATION_COMPLETE_QUERY,
                parameters.get(OIDF_USER_REJECT_QUERY).map(String::as_str) == Some("1"),
                OIDF_USER_REJECT_QUERY,
            )?;
            drop(records);
            return Ok(AuthorizationResponse::redirect(completion));
        }
        // RFC 9126 request URIs are single-use. Mark the record before doing
        // any fallible completion work so concurrent authenticated completion
        // requests cannot mint multiple authorization codes from one PAR. A
        // preliminary visit remains reusable until authentication completes,
        // as recommended by FAPI 2.0 Security Profile section 5.3.2.2.
        record.used = true;
        let record = record.clone();
        drop(records);
        if parameters.get(OIDF_USER_REJECT_QUERY).map(String::as_str) == Some("1") {
            return Ok(AuthorizationResponse::redirect(redirect_with_error(
                &record.redirect_uri,
                "access_denied",
                record.state.as_deref(),
            )?));
        }
        let code = Self::random_token("openid4vci-code-")?;
        let expires_at = now
            .checked_add(AUTHORIZATION_CODE_EXPIRES_IN_SECONDS)
            .ok_or(OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequest))?;
        self.code_records
            .lock()
            .map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequest))?
            .insert(
                opaque_token_digest(&code),
                CodeRecord {
                    client_id: record.client_id.clone(),
                    client_subject: record.client_subject.clone(),
                    client_instance_key_thumbprint: record.client_instance_key_thumbprint.clone(),
                    code_challenge: record.code_challenge.clone(),
                    dpop_jkt: record.dpop_jkt.clone(),
                    credential_authorizations: record.credential_authorizations.clone(),
                    expires_at,
                },
            );
        Ok(AuthorizationResponse::redirect(redirect_with_code(
            &record.redirect_uri,
            &code,
            record.state.as_deref(),
            &self.authorization_server_issuer,
        )?))
    }

    fn token(
        &self,
        headers: &OAuthRequestHeaders,
        parameters: &OAuthParameters,
    ) -> OAuthHttpResult<TokenResponse> {
        self.exchange_token(headers, parameters)
    }
}

impl AccessTokenValidator for ExampleOAuthAuthorizationServer {
    fn validate_access_token(&self, access_token: &str) -> OAuthHttpResult<ValidatedAccessToken> {
        self.lookup_access_token_security_context(access_token)
    }

    fn authorize_credential_request(
        &self,
        access_token: &str,
        selector: &CredentialSelector,
    ) -> OAuthHttpResult<CredentialAuthorizationDecision> {
        self.authorize_access_token_credential(access_token, selector)
    }

    fn authorize_deferred_credential_request(
        &self,
        access_token: &str,
        transaction_id: &str,
    ) -> OAuthHttpResult<openid4vci_issuer::IssuanceAuthorization> {
        self.validate_access_token(access_token)?;
        if transaction_id == "transaction-1" {
            let subject = self
                .access_tokens
                .lock()
                .map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequest))?
                .get(&super::store_authorization_state::opaque_token_digest(
                    access_token,
                ))
                .map(|record| record.client_subject.clone())
                .ok_or(OAuthHttpError::new(OAuthHttpErrorReason::InvalidDpopProof))?;
            openid4vci_issuer::IssuanceAuthorization::new(
                "pid".to_owned(),
                subject.clone(),
                super::store_authorization_state::opaque_token_digest(&subject),
            )
            .and_then(|authorization| authorization.with_client_id(subject))
            .map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequest))
        } else {
            Err(OAuthHttpError::new(
                OAuthHttpErrorReason::InsufficientAuthorization,
            ))
        }
    }

    fn authorize_notification_request(
        &self,
        access_token: &str,
        notification_id: &str,
    ) -> OAuthHttpResult<()> {
        self.validate_access_token(access_token)?;
        if notification_id == "notification-1" {
            Ok(())
        } else {
            Err(OAuthHttpError::new(
                OAuthHttpErrorReason::InsufficientAuthorization,
            ))
        }
    }
}
