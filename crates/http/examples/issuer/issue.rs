// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Issues conformance credentials and validates DPoP proofs.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::sync::Mutex;

use openid4vci_issuer::{
    CredentialIssuer, IssuanceOutcome, IssuerError, IssuerResult, IssuerStatus, VerifiedProofSet,
};
use openid4vci_types::{
    CredentialEnvelope, CredentialRequest, CredentialResponse, CredentialSelector,
};
use reallyme_crypto::core::Algorithm;
use reallyme_crypto::dispatch::verify;
use reallyme_crypto::jwk::Jwk;
use reallyme_crypto::p256::p256_ecdsa_jose_signature_to_der;
use reallyme_openid_oauth::{DpopVerifier, OauthError, Reason};
use serde_json::{json, Value};

use super::credential_authorization::{CredentialAuthorization, CredentialSelectorResolutionError};
use super::mdoc::issue_pid_mdoc;
use super::run::{
    current_unix_seconds_issuer, CONFORMANCE_ISSUER_X5C_LEAF, CREDENTIAL_TIME_ROUNDING_SECONDS,
    PID_VCT,
};
use super::sign::sign_es256_jws;

const MAX_DPOP_REPLAY_ENTRIES: usize = 65_536;
const DPOP_REPLAY_RETENTION_SECONDS: i64 = 600;

pub(super) struct ExampleDpopVerifier {
    replay: Mutex<DpopReplayState>,
}

#[derive(Default)]
struct DpopReplayState {
    seen_jti: HashMap<String, i64>,
    expirations: BinaryHeap<Reverse<(i64, String)>>,
}

impl ExampleDpopVerifier {
    pub(super) fn new() -> Self {
        Self {
            replay: Mutex::new(DpopReplayState::default()),
        }
    }
}

impl DpopVerifier for ExampleDpopVerifier {
    fn verify_signature(
        &self,
        protected_header: &Value,
        signing_input: &[u8],
        signature: &[u8],
    ) -> Result<(), OauthError> {
        if protected_header.get("alg").and_then(Value::as_str) != Some("ES256") {
            return Err(OauthError::new(Reason::InvalidDpopProof));
        }
        let jwk_value = protected_header
            .get("jwk")
            .cloned()
            .ok_or(OauthError::new(Reason::InvalidDpopProof))?;
        let jwk = serde_json::from_value::<Jwk>(jwk_value)
            .map_err(|_| OauthError::new(Reason::InvalidDpopProof))?;
        let public_key = jwk
            .public_key_bytes()
            .map_err(|_| OauthError::new(Reason::InvalidDpopProof))?;
        let der_signature = p256_ecdsa_jose_signature_to_der(signature)
            .map_err(|_| OauthError::new(Reason::InvalidDpopProof))?;
        verify(Algorithm::P256, &public_key, signing_input, &der_signature)
            .map_err(|_| OauthError::new(Reason::InvalidDpopProof))
    }

    fn check_replay(&self, jti: &str, iat: i64) -> Result<(), OauthError> {
        let mut replay = self
            .replay
            .lock()
            .map_err(|_| OauthError::new(Reason::InvalidDpopProof))?;
        let earliest_retained = iat.saturating_sub(DPOP_REPLAY_RETENTION_SECONDS);
        while let Some(Reverse((seen_iat, seen_jti))) = replay.expirations.peek() {
            if *seen_iat >= earliest_retained {
                break;
            }
            let seen_iat = *seen_iat;
            let seen_jti = seen_jti.clone();
            replay.expirations.pop();
            if replay.seen_jti.get(&seen_jti).copied() == Some(seen_iat) {
                replay.seen_jti.remove(&seen_jti);
            }
        }
        if replay.seen_jti.contains_key(jti) || replay.seen_jti.len() >= MAX_DPOP_REPLAY_ENTRIES {
            return Err(OauthError::new(Reason::InvalidDpopProof));
        }
        replay.seen_jti.insert(jti.to_owned(), iat);
        replay.expirations.push(Reverse((iat, jti.to_owned())));
        Ok(())
    }
}

pub(super) struct ExampleCredentialIssuer {
    credential_issuer: String,
}

impl ExampleCredentialIssuer {
    pub(super) fn new(credential_issuer: String) -> Self {
        Self { credential_issuer }
    }
}

impl CredentialIssuer for ExampleCredentialIssuer {
    fn issue(
        &self,
        authorization: &openid4vci_issuer::IssuanceAuthorization,
        _request: &CredentialRequest,
        selector: &CredentialSelector,
        verified_proofs: Option<&VerifiedProofSet>,
    ) -> IssuerResult<IssuanceOutcome> {
        let verified_proofs =
            verified_proofs.ok_or(IssuerError::new(IssuerStatus::InvalidProof))?;
        let selected_authorization =
            CredentialAuthorization::from_selector(selector).map_err(|error| {
                IssuerError::new(match error {
                    CredentialSelectorResolutionError::UnknownConfiguration => {
                        IssuerStatus::UnsupportedCredential
                    }
                    CredentialSelectorResolutionError::UnknownIdentifier => {
                        IssuerStatus::UnknownCredentialIdentifier
                    }
                })
            })?;
        if authorization.credential_configuration_id() != selected_authorization.configuration_id()
        {
            return Err(IssuerError::new(IssuerStatus::UnsupportedCredential));
        }
        let credentials = match selected_authorization {
            CredentialAuthorization::SdJwtPid => {
                let binding_keys = verified_proofs.ordered_public_jwks()?;
                let mut credentials = Vec::with_capacity(binding_keys.len());
                for proof_jwk in binding_keys {
                    let credential = build_sd_jwt_credential(&self.credential_issuer, proof_jwk)?;
                    credentials.push(CredentialEnvelope::compact(credential));
                }
                credentials
            }
            CredentialAuthorization::MdocPid => {
                let binding_keys = verified_proofs.ordered_confirmation_keys()?;
                let mut credentials = Vec::with_capacity(binding_keys.len());
                for binding_key in binding_keys {
                    credentials.push(issue_pid_mdoc(binding_key)?);
                }
                credentials
            }
        };
        Ok(IssuanceOutcome::Immediate(
            CredentialResponse::immediate(credentials, Some("notification-1".to_owned()))
                .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?,
        ))
    }
}

fn build_sd_jwt_credential(credential_issuer: &str, proof_jwk: &Value) -> IssuerResult<String> {
    let current_time = current_unix_seconds_issuer()?;
    let now = current_time
        .checked_sub(current_time % CREDENTIAL_TIME_ROUNDING_SECONDS)
        .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?;
    let expires_at = now
        .checked_add(86_400)
        .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?;
    let header = json!({
        "alg": "ES256",
        "typ": "dc+sd-jwt",
        "kid": "ct_client_attester_key",
        "x5c": [CONFORMANCE_ISSUER_X5C_LEAF]
    });
    let claims = json!({
        "iss": credential_issuer,
        "iat": now,
        "nbf": now,
        "exp": expires_at,
        "vct": PID_VCT,
        "cnf": { "jwk": proof_jwk },
        "given_name": "Erika",
        "family_name": "Mustermann",
        "birthdate": "1970-01-01"
    });
    let mut signed = sign_es256_jws(&header, &claims)?;
    signed.push('~');
    Ok(signed)
}
