// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! HTTP OAuth security validation for protected issuer routes.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, Uri};
use openid4vci_types::{ProblemDetails, ProblemType};
use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_crypto::operations::constant_time::equal as constant_time_equal;
use reallyme_openid_oauth::{
    jwk_thumbprint, jwt::decode_compact_jwt, validate_attestation_client_authentication,
    validation::normalize_uri_without_query_or_fragment, AttestationClientAuthentication,
    AttestationClientAuthenticationValidationContext, AttestationClientAuthenticationVerifier,
    CompactJwt, DpopClaims, DpopHeader, DpopProof, DpopValidationContext, DpopVerifier, OauthError,
    Reason, VerifiedAttestationClientAuthentication, OAUTH_CLIENT_ATTESTATION_HEADER,
    OAUTH_CLIENT_ATTESTATION_POP_HEADER,
};

use crate::validate_access_token::AccessTokenValidator;
use zeroize::Zeroizing;

const DPOP_HEADER: &str = "dpop";
const DPOP_AUTHORIZATION_SCHEME: &str = "DPoP";
const BEARER_AUTHORIZATION_SCHEME: &str = "Bearer";
const MAX_ACCESS_TOKEN_BYTES: usize = 8_192;

#[derive(Debug, thiserror::Error)]
pub(crate) enum HttpSecurityError {
    #[error("invalid_access_token")]
    InvalidAccessToken,
    #[error("http_security_policy_failed")]
    Policy(ProblemDetails),
}

impl From<ProblemDetails> for HttpSecurityError {
    fn from(problem: ProblemDetails) -> Self {
        Self::Policy(problem)
    }
}

/// Supplies the current Unix time used to anchor DPoP / attestation `iat`
/// acceptance windows to wall-clock time per request.
pub trait Clock: Send + Sync {
    /// Returns the current time as seconds since the Unix epoch.
    fn now_unix(&self) -> i64;
}

/// Default [`Clock`] backed by the system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> i64 {
        // Fails closed (returns 0, rejecting normally-dated proofs) if the system
        // clock is before the Unix epoch or beyond `i64` seconds.
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|elapsed| i64::try_from(elapsed.as_secs()).ok())
            .unwrap_or(0)
    }
}

/// Derives an `[earliest, latest]` `iat` acceptance window from the current time.
fn iat_window(
    now_unix: i64,
    max_age_seconds: i64,
    max_future_skew_seconds: i64,
) -> Result<(i64, i64), ProblemDetails> {
    if now_unix <= 0 || max_age_seconds < 0 || max_future_skew_seconds < 0 {
        return Err(ProblemDetails::new(ProblemType::ServerError, None));
    }
    let earliest = now_unix
        .checked_sub(max_age_seconds)
        .ok_or_else(|| ProblemDetails::new(ProblemType::ServerError, None))?;
    let latest = now_unix
        .checked_add(max_future_skew_seconds)
        .ok_or_else(|| ProblemDetails::new(ProblemType::ServerError, None))?;
    Ok((earliest, latest))
}

/// Fixed failure reasons for persisting an accepted wallet-attestation receipt.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum WalletAttestationEvidenceError {
    /// The configured evidence store could not retain the receipt.
    #[error("storage_unavailable")]
    StorageUnavailable,
}

/// Receives the exact client-authentication receipt after signature, binding,
/// temporal, challenge, and replay validation have all succeeded.
pub trait WalletAttestationEvidenceRecorder: Send + Sync {
    /// Persists or transactionally binds the receipt to the current request.
    fn record(
        &self,
        evidence: &VerifiedAttestationClientAuthentication,
    ) -> Result<(), WalletAttestationEvidenceError>;
}

/// HTTP-level issuer security policy for protected endpoints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerHttpSecurityConfig {
    /// DPoP proof policy for sender-constrained access tokens.
    pub dpop: Option<DpopHttpConfig>,
    /// Wallet attestation client-authentication policy.
    pub wallet_attestation: Option<WalletAttestationHttpConfig>,
}

impl IssuerHttpSecurityConfig {
    pub(crate) fn is_satisfied_by(
        &self,
        dpop_verifier: Option<&Arc<dyn DpopVerifier + Send + Sync>>,
        attestation_verifier: Option<
            &Arc<dyn AttestationClientAuthenticationVerifier + Send + Sync>,
        >,
        evidence_recorder: Option<&Arc<dyn WalletAttestationEvidenceRecorder>>,
    ) -> bool {
        (self.dpop.is_none() || dpop_verifier.is_some())
            && (self.wallet_attestation.is_none()
                || (attestation_verifier.is_some() && evidence_recorder.is_some()))
    }
}

/// DPoP validation policy for credential-bearing HTTP endpoints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DpopHttpConfig {
    /// Optional expected DPoP nonce supplied by the composing authorization
    /// server. Rotation and `DPoP-Nonce` challenge responses are AS concerns;
    /// this resource adapter always enforces the configured value and relies
    /// on the mandatory verifier replay hook when nonce use is disabled.
    pub nonce: Option<String>,
    /// Maximum accepted proof age in seconds (window lower bound below now).
    pub max_age_seconds: i64,
    /// Maximum accepted clock skew into the future in seconds.
    pub max_future_skew_seconds: i64,
}

/// Wallet attestation client authentication policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletAttestationHttpConfig {
    /// Expected Authorization Server issuer identifier used as PoP audience.
    pub expected_audience: String,
    /// Optional expected challenge in the PoP JWT.
    pub expected_challenge: Option<String>,
    /// Maximum accepted PoP age in seconds (window lower bound below now).
    pub max_age_seconds: i64,
    /// Maximum accepted clock skew into the future in seconds.
    pub max_future_skew_seconds: i64,
    /// Maximum age of the already-computed wallet-attestation trust decision.
    pub max_trust_evidence_age_seconds: i64,
}

pub(crate) struct HttpSecurityValidation<'a> {
    pub(crate) dpop_verifier: Option<&'a Arc<dyn DpopVerifier + Send + Sync>>,
    pub(crate) attestation_verifier:
        Option<&'a Arc<dyn AttestationClientAuthenticationVerifier + Send + Sync>>,
    pub(crate) attestation_evidence_recorder:
        Option<&'a Arc<dyn WalletAttestationEvidenceRecorder>>,
    pub(crate) access_token_validator: &'a Arc<dyn AccessTokenValidator>,
    pub(crate) issuer: &'a str,
    pub(crate) headers: &'a HeaderMap,
    pub(crate) uri: &'a Uri,
}

pub(crate) fn validate_http_security(
    config: &IssuerHttpSecurityConfig,
    validation: HttpSecurityValidation<'_>,
    now_unix: i64,
) -> Result<Zeroizing<String>, HttpSecurityError> {
    let access_token = authorization_token(validation.headers, config.dpop.is_some())?;
    let validated_access_token = validation
        .access_token_validator
        .validate_access_token(access_token.as_str())
        .map_err(|_| HttpSecurityError::InvalidAccessToken)?;
    if config.dpop.is_none() && validated_access_token.confirmed_jkt().is_some() {
        return Err(HttpSecurityError::InvalidAccessToken);
    }
    if let Some(dpop_config) = &config.dpop {
        let verifier = validation
            .dpop_verifier
            .ok_or_else(|| ProblemDetails::new(ProblemType::ServerError, None))?;
        let proof = dpop_proof_from_headers(validation.headers)?;
        let (earliest_iat, latest_iat) = iat_window(
            now_unix,
            dpop_config.max_age_seconds,
            dpop_config.max_future_skew_seconds,
        )?;
        let confirmed_jkt = validated_access_token
            .confirmed_jkt()
            .ok_or(HttpSecurityError::InvalidAccessToken)?;
        validate_dpop_proof(
            &proof,
            &DpopValidationContext {
                method: "POST".to_owned(),
                target_uri: absolute_target_uri(validation.issuer, validation.uri)?,
                access_token: Some(access_token.as_str().to_owned()),
                nonce: dpop_config.nonce.clone(),
                earliest_iat,
                latest_iat,
                confirmed_jkt: Some(confirmed_jkt.to_owned()),
            },
            verifier.as_ref(),
        )
        .map_err(oauth_problem)?;
    }
    if let Some(attestation_config) = &config.wallet_attestation {
        let verifier = validation
            .attestation_verifier
            .ok_or_else(|| ProblemDetails::new(ProblemType::ServerError, None))?;
        let authentication = attestation_client_authentication_from_headers(validation.headers)?;
        let recorder = validation
            .attestation_evidence_recorder
            .ok_or_else(|| ProblemDetails::new(ProblemType::ServerError, None))?;
        let (earliest_iat, latest_iat) = iat_window(
            now_unix,
            attestation_config.max_age_seconds,
            attestation_config.max_future_skew_seconds,
        )?;
        // The OAuth attestation verifier returns only after PoP verification
        // against the `cnf.jwk` extracted from that same attestation and after
        // replay consumption. Recording this exact value preserves the RFC
        // 7638 key thumbprint and validated PoP event without reconstructing it.
        let verified = validate_attestation_client_authentication(
            &authentication,
            &AttestationClientAuthenticationValidationContext {
                expected_client_id: validated_access_token.client_id().to_owned(),
                expected_audience: attestation_config.expected_audience.clone(),
                expected_challenge: attestation_config.expected_challenge.clone(),
                earliest_iat,
                latest_iat,
                current_time: now_unix,
                max_trust_evidence_age_seconds: attestation_config.max_trust_evidence_age_seconds,
            },
            verifier.as_ref(),
        )
        .map_err(oauth_problem)?;
        recorder
            .record(&verified)
            .map_err(|_| ProblemDetails::new(ProblemType::ServerError, None))?;
    }
    Ok(access_token)
}

fn dpop_proof_from_headers(headers: &HeaderMap) -> Result<DpopProof, ProblemDetails> {
    let value = header_value(headers, DPOP_HEADER)?;
    DpopProof::new(value.to_owned()).map_err(oauth_problem)
}

/// Validates a DPoP proof while applying RFC 9449 section 4.3(9) before URL
/// policy validation.
///
/// The OAuth substrate performs the same checks, but version 0.3.3 validates
/// fragments as prohibited URL input before removing them for `htu`
/// comparison. The RFC instead requires the receiver to ignore query and
/// fragment components for this comparison. Keeping the complete validation
/// here avoids weakening any signature, replay, token-hash, or key-binding
/// check while accepting every `htu` wire form permitted by the RFC.
fn validate_dpop_proof(
    proof: &DpopProof,
    context: &DpopValidationContext,
    verifier: &dyn DpopVerifier,
) -> Result<(), OauthError> {
    let jwt = CompactJwt::new(proof.as_str().to_owned())?;
    let (header, claims, signature): (DpopHeader, DpopClaims, Vec<u8>) = decode_compact_jwt(&jwt)?;
    header.validate()?;
    claims.validate()?;
    if !claims.htm.eq_ignore_ascii_case(&context.method) {
        return Err(OauthError::new(Reason::InvalidDpopProof));
    }
    let expected_htu = normalize_dpop_htu(&context.target_uri)?;
    let observed_htu = normalize_dpop_htu(&claims.htu)?;
    if observed_htu != expected_htu {
        return Err(OauthError::new(Reason::InvalidDpopProof));
    }
    if let Some(expected_nonce) = &context.nonce {
        if claims
            .nonce
            .as_ref()
            .is_none_or(|nonce| !constant_time_equal(nonce.as_bytes(), expected_nonce.as_bytes()))
        {
            return Err(OauthError::new(Reason::InvalidDpopProof));
        }
    }
    if let Some(access_token) = &context.access_token {
        let Some(confirmed_jkt) = &context.confirmed_jkt else {
            return Err(OauthError::new(Reason::InvalidDpopProof));
        };
        let expected_ath =
            bytes_to_base64url(reallyme_crypto::sha2::digest(access_token.as_bytes()).as_bytes());
        if claims
            .ath
            .as_deref()
            .is_none_or(|ath| !constant_time_equal(ath.as_bytes(), expected_ath.as_bytes()))
        {
            return Err(OauthError::new(Reason::InvalidDpopProof));
        }
        let proof_jkt = jwk_thumbprint(&header.jwk)?;
        if !constant_time_equal(proof_jkt.as_bytes(), confirmed_jkt.as_bytes()) {
            return Err(OauthError::new(Reason::InvalidDpopProof));
        }
    } else if let Some(confirmed_jkt) = &context.confirmed_jkt {
        let proof_jkt = jwk_thumbprint(&header.jwk)?;
        if !constant_time_equal(proof_jkt.as_bytes(), confirmed_jkt.as_bytes()) {
            return Err(OauthError::new(Reason::InvalidDpopProof));
        }
    }
    if claims.iat < context.earliest_iat || claims.iat > context.latest_iat {
        return Err(OauthError::new(Reason::InvalidDpopProof));
    }
    let header_value =
        serde_json::to_value(&header).map_err(|_| OauthError::new(Reason::InvalidJson))?;
    let (signing_input, _) = jwt.signing_parts()?;
    verifier.verify_signature(&header_value, signing_input.as_bytes(), &signature)?;
    verifier.check_replay(&claims.jti, claims.iat)
}

fn normalize_dpop_htu(value: &str) -> Result<String, OauthError> {
    let component_start = value
        .char_indices()
        .find_map(|(index, character)| matches!(character, '?' | '#').then_some(index))
        .unwrap_or(value.len());
    let without_query_or_fragment = value
        .get(..component_start)
        .ok_or(OauthError::new(Reason::InvalidDpopProof))?;
    normalize_uri_without_query_or_fragment(without_query_or_fragment)
        .map_err(|_| OauthError::new(Reason::InvalidDpopProof))
}

pub(crate) fn authorization_token(
    headers: &HeaderMap,
    dpop_required: bool,
) -> Result<Zeroizing<String>, HttpSecurityError> {
    let value = access_token_header_value(headers)?;
    let (scheme, token) = value
        .split_once(' ')
        .ok_or(HttpSecurityError::InvalidAccessToken)?;
    let expected_scheme = if dpop_required {
        DPOP_AUTHORIZATION_SCHEME
    } else {
        BEARER_AUTHORIZATION_SCHEME
    };
    if !scheme.eq_ignore_ascii_case(expected_scheme) {
        return Err(HttpSecurityError::InvalidAccessToken);
    }
    if token.is_empty() || token.len() > MAX_ACCESS_TOKEN_BYTES || !is_token68(token) {
        return Err(HttpSecurityError::InvalidAccessToken);
    }
    Ok(Zeroizing::new(token.to_owned()))
}

fn access_token_header_value(headers: &HeaderMap) -> Result<&str, HttpSecurityError> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let first = values.next().ok_or(HttpSecurityError::InvalidAccessToken)?;
    if values.next().is_some() {
        return Err(HttpSecurityError::InvalidAccessToken);
    }
    first
        .to_str()
        .map_err(|_| HttpSecurityError::InvalidAccessToken)
}

fn is_token68(token: &str) -> bool {
    let unpadded = token.trim_end_matches('=');
    !unpadded.is_empty()
        && unpadded.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
        })
        && token[unpadded.len()..].bytes().all(|byte| byte == b'=')
}

fn attestation_client_authentication_from_headers(
    headers: &HeaderMap,
) -> Result<AttestationClientAuthentication, ProblemDetails> {
    AttestationClientAuthentication::new(
        header_value(headers, OAUTH_CLIENT_ATTESTATION_HEADER)?.to_owned(),
        header_value(headers, OAUTH_CLIENT_ATTESTATION_POP_HEADER)?.to_owned(),
    )
    .map_err(oauth_problem)
}

fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, ProblemDetails> {
    // RFC 9449 §4.3(1) and the attestation-based client-auth draft require
    // exactly one of each security header; reject smuggled duplicates.
    let mut values = headers.get_all(name).iter();
    let first = values
        .next()
        .ok_or_else(|| ProblemDetails::new(ProblemType::InvalidProof, None))?;
    if values.next().is_some() {
        return Err(ProblemDetails::new(ProblemType::InvalidProof, None));
    }
    first
        .to_str()
        .map_err(|_| ProblemDetails::new(ProblemType::InvalidProof, None))
}

fn absolute_target_uri(issuer: &str, uri: &Uri) -> Result<String, HttpSecurityError> {
    // The DPoP `htu` binding target is always derived from the trusted issuer
    // origin and the request path. A client- or proxy-supplied scheme and
    // authority in absolute-form request lines is deliberately ignored so the
    // comparison target cannot be influenced by the caller (RFC 9449 §4.3).
    // RFC 9449 defines `htu` without query and fragment components. `uri` is
    // the Axum `OriginalUri`, so nested-router prefixes and percent-encoded
    // path octets are retained exactly as received by the application.
    let path = uri.path();
    let trusted_origin = issuer_origin(issuer).unwrap_or(issuer);
    let capacity = trusted_origin
        .len()
        .checked_add(path.len())
        .ok_or_else(|| ProblemDetails::new(ProblemType::ServerError, None))?;
    let mut target = String::with_capacity(capacity);
    match (trusted_origin.strip_suffix('/'), path.strip_prefix('/')) {
        (Some(base), Some(rest)) => {
            target.push_str(base);
            target.push('/');
            target.push_str(rest);
        }
        _ => {
            target.push_str(trusted_origin);
            target.push_str(path);
        }
    }
    Ok(target)
}

fn issuer_origin(issuer: &str) -> Option<&str> {
    let scheme_end = issuer.find("://")?;
    let authority_start = scheme_end.checked_add(3)?;
    let authority_len = match issuer[authority_start..].find('/') {
        Some(length) => length,
        None => issuer.len().checked_sub(authority_start)?,
    };
    let origin_end = authority_start.checked_add(authority_len)?;
    issuer.get(..origin_end)
}

fn oauth_problem(error: OauthError) -> ProblemDetails {
    match error.reason() {
        Reason::InvalidDpopProof
        | Reason::DpopReplay
        | Reason::InvalidClientAttestation
        | Reason::VerificationFailed => ProblemDetails::new(ProblemType::InvalidProof, None),
        _ => ProblemDetails::new(ProblemType::InvalidRequest, None),
    }
}

#[path = "tests/validate_http_security_tests.rs"]
#[cfg(test)]
mod validate_http_security_tests;
