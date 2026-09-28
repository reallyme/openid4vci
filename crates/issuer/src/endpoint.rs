// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pure endpoint functions for issuer flows.

use openid4vci_types::{
    CredentialRequest, CredentialResponse, CredentialSelector, DeferredCredentialRequest,
    NonceResponse, NotificationRequest,
};

use crate::authorization::IssuanceAuthorization;
use crate::credential_policy::CredentialEndpointConfig;
use crate::encode::validate_response_credential_count_with_verified_proofs;
use crate::encrypt::{
    select_response_encryption_parameters, CredentialRequestInput, CredentialResponseBody,
    CredentialResponseEncryptor, DeferredCredentialRequestInput,
};
use crate::error::{IssuerError, IssuerResult, IssuerStatus};
use crate::nonce::{NonceManager, MAX_NONCE_TTL_SECONDS};
use crate::proof::{ProofVerifier, VerifiedProof, VerifiedProofSet};
use crate::validate_credential_request::{
    specialize_unknown_credential, validate_and_verify_credential_request,
};

/// Side-effect-free credential request validation summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialRequestPreflight {
    /// Credential target selected by the request.
    pub selector: CredentialSelector,
    /// Number of credential-binding keys accepted by proof verification.
    pub binding_key_count: u32,
    /// Number of proof entries accepted by proof verification.
    pub verified_proof_count: u32,
    /// Whether the verified proof set includes a key attestation proof.
    pub includes_key_attestation: bool,
    /// Whether the wallet requested encrypted credential responses.
    pub response_encryption_requested: bool,
}

/// Issues credentials after request and proof validation.
pub trait CredentialIssuer {
    /// Issues or defers the requested credential.
    ///
    /// For multiple verified binding keys, the provider must issue one
    /// credential per key in [`VerifiedProofSet::ordered_public_jwks`] order.
    /// This is the same provider boundary used by composed product hosts; HTTP
    /// and conformance adapters must not reimplement credential issuance.
    fn issue(
        &self,
        authorization: &IssuanceAuthorization,
        request: &CredentialRequest,
        selector: &CredentialSelector,
        verified_proofs: Option<&VerifiedProofSet>,
    ) -> IssuerResult<IssuanceOutcome>;
}

/// Resolves a deferred credential transaction.
pub trait DeferredIssuer {
    /// Returns a final or still-deferred response for the transaction.
    /// Response encryption is deliberately selected from the current Deferred
    /// Credential Request, as required by OpenID4VCI 1.0 §9.1.
    fn resolve_deferred(
        &self,
        authorization: &IssuanceAuthorization,
        transaction_id: &str,
    ) -> IssuerResult<DeferredResolution>;
}

/// Result of resolving a deferred transaction.
#[derive(Debug, Clone, PartialEq)]
pub struct DeferredResolution {
    /// Final or still-pending issuance state.
    pub outcome: IssuanceOutcome,
}

impl DeferredResolution {
    /// Creates a resolution that preserves the original encryption commitment.
    #[must_use]
    pub const fn new(outcome: IssuanceOutcome) -> Self {
        Self { outcome }
    }
}

/// Handles idempotent notification events.
pub trait NotificationHandler {
    /// Records or ignores an idempotent wallet notification.
    fn handle_notification(&self, request: &NotificationRequest) -> IssuerResult<()>;
}

/// Output of issuer credential issuance logic.
#[derive(Debug, Clone, PartialEq)]
pub enum IssuanceOutcome {
    /// Credential issuance is complete.
    Immediate(CredentialResponse),
    /// Credential issuance is deferred or still pending.
    Deferred(CredentialResponse),
}

impl IssuanceOutcome {
    /// Returns the contained credential response.
    #[must_use]
    pub fn into_response(self) -> CredentialResponse {
        match self {
            Self::Immediate(response) | Self::Deferred(response) => response,
        }
    }
}

/// Implements the dedicated Nonce Endpoint.
///
/// The freshly generated `c_nonce` carries an authenticated expiry so the
/// Credential Endpoint can later confirm that this issuer created it and
/// consume it exactly once (OpenID4VCI 1.0 §7).
pub fn handle_nonce_request(
    nonce_manager: &dyn NonceManager,
    now_unix: u64,
    ttl_seconds: u64,
) -> IssuerResult<NonceResponse> {
    if ttl_seconds == 0 || ttl_seconds > MAX_NONCE_TTL_SECONDS {
        return Err(IssuerError::new(IssuerStatus::InvalidRequest));
    }
    let nonce = nonce_manager.issue(now_unix, ttl_seconds)?;
    NonceResponse::new(nonce).map_err(|_| IssuerError::new(IssuerStatus::InvalidRequest))
}

/// Requires every proof in a batch to carry the same `c_nonce`, then consumes
/// that nonce exactly once. Comparing the complete proof set before mutation
/// prevents a mixed-nonce request from burning several valid nonce records.
/// This is the server-managed nonce freshness mechanism required by
/// OpenID4VCI 1.0 Final Appendix F.4.
fn consume_verified_nonces(
    verified: &VerifiedProofSet,
    authorization: &IssuanceAuthorization,
    nonce_manager: &dyn NonceManager,
    now_unix: u64,
) -> IssuerResult<()> {
    let nonce = verified
        .proofs()
        .first()
        .and_then(VerifiedProof::nonce)
        .ok_or_else(|| IssuerError::new(IssuerStatus::InvalidNonce))?;
    if verified
        .proofs()
        .iter()
        .any(|proof| proof.nonce() != Some(nonce))
    {
        return Err(IssuerError::new(IssuerStatus::InvalidNonce));
    }
    nonce_manager.consume(nonce, authorization.rate_limit_partition(), now_unix)
}

/// Implements the Credential Endpoint as pure business logic.
///
/// Verified proof nonces are consumed single-use through `nonce_manager` before
/// issuance, so a captured Credential Request cannot be replayed.
pub fn handle_credential_request(
    authorization: &IssuanceAuthorization,
    request: &CredentialRequest,
    config: &CredentialEndpointConfig,
    proof_verifier: &dyn ProofVerifier,
    issuer: &dyn CredentialIssuer,
    nonce_manager: &dyn NonceManager,
    now_unix: u64,
) -> IssuerResult<CredentialResponse> {
    if config.request_encryption_required
        || config.response_encryption_required
        || request.credential_response_encryption.is_some()
    {
        return Err(IssuerError::new(IssuerStatus::EncryptionRequired));
    }
    issue_credential_request(
        authorization,
        request,
        config,
        proof_verifier,
        issuer,
        nonce_manager,
        now_unix,
    )
}

fn issue_credential_request(
    authorization: &IssuanceAuthorization,
    request: &CredentialRequest,
    config: &CredentialEndpointConfig,
    proof_verifier: &dyn ProofVerifier,
    issuer: &dyn CredentialIssuer,
    nonce_manager: &dyn NonceManager,
    now_unix: u64,
) -> IssuerResult<CredentialResponse> {
    let (selector, verified) = validate_and_verify_credential_request(
        authorization,
        request,
        config,
        proof_verifier,
        now_unix,
    )?;
    if matches!(
        &selector,
        CredentialSelector::ConfigurationId(configuration_id)
            if configuration_id != authorization.credential_configuration_id()
    ) {
        return Err(IssuerError::new(IssuerStatus::UnsupportedCredential));
    }
    if let Some(verified) = &verified {
        consume_verified_nonces(verified, authorization, nonce_manager, now_unix)?;
    }
    let outcome = issuer
        .issue(authorization, request, &selector, verified.as_ref())
        .map_err(|error| specialize_unknown_credential(error, &selector))?;
    let response = outcome.into_response();
    response
        .validate()
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    validate_response_credential_count_with_verified_proofs(request, verified.as_ref(), &response)?;
    Ok(response)
}

fn select_and_validate_encryption<'a>(
    request: &'a CredentialRequest,
    config: &CredentialEndpointConfig,
    encryptor: &dyn CredentialResponseEncryptor,
) -> IssuerResult<Option<std::borrow::Cow<'a, openid4vci_types::CredentialResponseEncryption>>> {
    let selected = request
        .credential_response_encryption
        .as_ref()
        .map(|encryption| {
            select_response_encryption_parameters(
                encryption,
                config.response_encryption_metadata.as_ref(),
            )
        })
        .transpose()?;
    if let Some(encryption) = selected.as_deref() {
        encryptor.validate_parameters(encryption)?;
    }
    Ok(selected)
}

/// Implements the Credential Endpoint and returns the transport response body.
// Keep security-sensitive collaborators explicit at this pure boundary. A
// generic service bag would make authorization, nonce consumption, and
// encryption-order review less transparent.
#[allow(clippy::too_many_arguments)]
pub fn handle_credential_request_body(
    authorization: &IssuanceAuthorization,
    input: &CredentialRequestInput,
    config: &CredentialEndpointConfig,
    proof_verifier: &dyn ProofVerifier,
    issuer: &dyn CredentialIssuer,
    encryptor: &dyn CredentialResponseEncryptor,
    nonce_manager: &dyn NonceManager,
    now_unix: u64,
) -> IssuerResult<CredentialResponseBody> {
    let request = input.request();
    enforce_request_transport(
        request.credential_response_encryption.is_some(),
        config.request_encryption_required,
        input.was_decrypted(),
    )?;
    let selected_encryption = select_and_validate_encryption(request, config, encryptor)?;
    let response = issue_credential_request(
        authorization,
        request,
        config,
        proof_verifier,
        issuer,
        nonce_manager,
        now_unix,
    )?;
    match selected_encryption {
        Some(encryption) => {
            let deferred = response.transaction_id.is_some();
            encryptor
                .encrypt_response(&response, encryption.as_ref())
                .map(|encrypted| CredentialResponseBody::Jwt {
                    encrypted,
                    deferred,
                })
        }
        None => Ok(CredentialResponseBody::Json(response)),
    }
}

/// Validates a Credential Request and verifies proofs without issuing.
pub fn preflight_credential_request(
    authorization: &IssuanceAuthorization,
    request: &CredentialRequest,
    config: &CredentialEndpointConfig,
    proof_verifier: &dyn ProofVerifier,
    now_unix: u64,
) -> IssuerResult<CredentialRequestPreflight> {
    if config.request_encryption_required || request.credential_response_encryption.is_some() {
        return Err(IssuerError::new(IssuerStatus::EncryptionRequired));
    }
    let (selector, verified) = validate_and_verify_credential_request(
        authorization,
        request,
        config,
        proof_verifier,
        now_unix,
    )?;
    let (binding_key_count, verified_proof_count, includes_key_attestation) = match verified {
        Some(proofs) => (
            proofs.binding_key_count(),
            u32::try_from(proofs.proofs().len())
                .map_err(|_| IssuerError::new(IssuerStatus::InvalidProof))?,
            proofs.includes_key_attestation(),
        ),
        None => (0, 0, false),
    };
    Ok(CredentialRequestPreflight {
        selector,
        binding_key_count,
        verified_proof_count,
        includes_key_attestation,
        response_encryption_requested: request.credential_response_encryption.is_some(),
    })
}

fn resolve_deferred_credential_request(
    authorization: &IssuanceAuthorization,
    request: &DeferredCredentialRequest,
    issuer: &dyn DeferredIssuer,
) -> IssuerResult<CredentialResponse> {
    request
        .validate()
        .map_err(|_| IssuerError::new(IssuerStatus::InvalidRequest))?;
    let resolution = issuer.resolve_deferred(authorization, &request.transaction_id)?;
    let response = resolution.outcome.into_response();
    response
        .validate()
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    Ok(response)
}

/// Implements the Deferred Credential Endpoint and returns the transport response body.
pub fn handle_deferred_credential_request_body(
    authorization: &IssuanceAuthorization,
    input: &DeferredCredentialRequestInput,
    config: &CredentialEndpointConfig,
    issuer: &dyn DeferredIssuer,
    encryptor: &dyn CredentialResponseEncryptor,
) -> IssuerResult<CredentialResponseBody> {
    let request = input.request();
    enforce_request_transport(
        request.credential_response_encryption.is_some(),
        config.request_encryption_required,
        input.was_decrypted(),
    )?;
    if config.response_encryption_required && request.credential_response_encryption.is_none() {
        return Err(IssuerError::new(IssuerStatus::EncryptionRequired));
    }
    let selected_encryption = request
        .credential_response_encryption
        .as_ref()
        .map(|encryption| {
            select_response_encryption_parameters(
                encryption,
                config.response_encryption_metadata.as_ref(),
            )
        })
        .transpose()?;
    if let Some(encryption) = selected_encryption.as_deref() {
        encryptor.validate_parameters(encryption)?;
    }
    let response = resolve_deferred_credential_request(authorization, request, issuer)?;
    match selected_encryption {
        Some(encryption) => {
            let deferred = response.transaction_id.is_some();
            encryptor
                .encrypt_response(&response, encryption.as_ref())
                .map(|encrypted| CredentialResponseBody::Jwt {
                    encrypted,
                    deferred,
                })
        }
        None => Ok(CredentialResponseBody::Json(response)),
    }
}

fn enforce_request_transport(
    response_encryption_requested: bool,
    request_encryption_required: bool,
    request_was_decrypted: bool,
) -> IssuerResult<()> {
    if (response_encryption_requested || request_encryption_required) && !request_was_decrypted {
        return Err(IssuerError::new(IssuerStatus::EncryptionRequired));
    }
    Ok(())
}

/// Implements the Notification Endpoint as pure business logic.
pub fn handle_notification_request(
    request: &NotificationRequest,
    handler: &dyn NotificationHandler,
) -> IssuerResult<()> {
    request
        .validate()
        .map_err(|_| IssuerError::new(IssuerStatus::InvalidRequest))?;
    handler.handle_notification(request)
}
