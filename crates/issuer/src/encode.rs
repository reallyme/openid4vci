// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Credential encoding boundaries for issuer engines.
//!
//! OpenID4VCI does not define how credentials are issued or signed. This module
//! keeps that work behind injected encoders so SD-JWT VC and mdoc implementations
//! can bind to `reallyme-identity` without leaking signing concerns into endpoint
//! validation.

use core::fmt::{Debug, Formatter};

use openid4vci_types::{
    CredentialEnvelope, CredentialFormat, CredentialRequest, CredentialResponse,
};
use serde_json::Value;
use zeroize::Zeroize;

use crate::error::{IssuerError, IssuerResult, IssuerStatus};
use crate::proof::VerifiedProofSet;

/// Issued credential payload supplied to an OpenID4VCI encoder.
#[derive(PartialEq)]
pub struct IssuedCredential {
    /// Credential format produced by the issuing stack.
    pub format: CredentialFormat,
    /// Final JSON credential value, usually a compact string or object.
    pub credential: Value,
}

impl Debug for IssuedCredential {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("IssuedCredential")
            .field("format", &self.format)
            .field("credential", &"<redacted>")
            .finish()
    }
}

impl Drop for IssuedCredential {
    fn drop(&mut self) {
        zeroize_json_strings(&mut self.credential);
    }
}

impl IssuedCredential {
    /// Creates an issued credential and validates that the payload is present.
    pub fn new(format: CredentialFormat, credential: Value) -> IssuerResult<Self> {
        if credential.is_null() {
            return Err(IssuerError::new(IssuerStatus::EncodingFailed));
        }
        Ok(Self { format, credential })
    }
}

fn zeroize_json_strings(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(values) => {
            for nested in values {
                zeroize_json_strings(nested);
            }
        }
        Value::Object(values) => {
            for nested in values.values_mut() {
                zeroize_json_strings(nested);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// Encoder abstraction for one credential format.
pub trait CredentialEncoder: Send + Sync {
    /// Returns the credential format emitted by this encoder.
    fn format(&self) -> CredentialFormat;

    /// Encodes one already-issued credential for a Credential Response.
    fn encode(
        &self,
        request: &CredentialRequest,
        issued: &IssuedCredential,
    ) -> IssuerResult<CredentialEnvelope>;
}

/// Pass-through encoder for credentials already prepared by `reallyme-identity`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassThroughCredentialEncoder {
    format: CredentialFormat,
}

impl PassThroughCredentialEncoder {
    /// Creates a pass-through encoder for a specific final-spec credential format.
    #[must_use]
    pub const fn new(format: CredentialFormat) -> Self {
        Self { format }
    }
}

impl CredentialEncoder for PassThroughCredentialEncoder {
    fn format(&self) -> CredentialFormat {
        self.format.clone()
    }

    fn encode(
        &self,
        _request: &CredentialRequest,
        issued: &IssuedCredential,
    ) -> IssuerResult<CredentialEnvelope> {
        if issued.format != self.format {
            return Err(IssuerError::new(IssuerStatus::UnsupportedCredential));
        }
        let envelope = match &issued.credential {
            Value::String(compact) => CredentialEnvelope::compact(compact.clone()),
            value => CredentialEnvelope::json(value.clone()),
        };
        envelope
            .validate()
            .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
        Ok(envelope)
    }
}

/// Encodes multiple issued credentials into an immediate Credential Response.
pub fn encode_immediate_response(
    request: &CredentialRequest,
    encoder: &dyn CredentialEncoder,
    issued: &[IssuedCredential],
    notification_id: Option<String>,
) -> IssuerResult<CredentialResponse> {
    if issued.is_empty() {
        return Err(IssuerError::new(IssuerStatus::EncodingFailed));
    }
    validate_issued_credential_count(request, issued.len())?;
    encode_immediate_response_with_expected_count(
        request,
        encoder,
        issued,
        notification_id,
        issued.len(),
    )
}

/// Encodes credentials using verified binding-key cardinality.
///
/// Direct `attestation` proofs carry exactly one JWT but can attest multiple
/// public keys. This variant permits one credential per trusted attested key,
/// as recommended by OpenID4VCI 1.0 Final Appendix F.3.
pub fn encode_immediate_response_with_verified_proofs(
    request: &CredentialRequest,
    verified_proofs: Option<&VerifiedProofSet>,
    encoder: &dyn CredentialEncoder,
    issued: &[IssuedCredential],
    notification_id: Option<String>,
) -> IssuerResult<CredentialResponse> {
    if issued.is_empty() {
        return Err(IssuerError::new(IssuerStatus::EncodingFailed));
    }
    validate_issued_credential_count_with_verified_proofs(request, verified_proofs, issued.len())?;
    encode_immediate_response_with_expected_count(
        request,
        encoder,
        issued,
        notification_id,
        issued.len(),
    )
}

pub(crate) fn encode_immediate_response_with_expected_count(
    request: &CredentialRequest,
    encoder: &dyn CredentialEncoder,
    issued: &[IssuedCredential],
    notification_id: Option<String>,
    expected_count: usize,
) -> IssuerResult<CredentialResponse> {
    if issued.is_empty() || issued.len() != expected_count {
        return Err(IssuerError::new(IssuerStatus::InvalidProof));
    }
    let mut credentials = Vec::with_capacity(expected_count);
    for credential in issued {
        credentials.push(encoder.encode(request, credential)?);
    }
    CredentialResponse::immediate(credentials, notification_id)
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))
}

/// Returns the number of credentials implied by proof-array cardinality before
/// proof verification.
///
/// Direct attestations always contain one JWT even when that JWT covers several
/// keys. Use the verified-proof variants below once attestation verification is
/// available.
#[must_use]
pub fn expected_credential_count(request: &CredentialRequest) -> usize {
    match request.proofs.as_ref() {
        Some(proofs) if !proofs.jwt.is_empty() => proofs.jwt.len(),
        Some(proofs) if !proofs.di_vp.is_empty() => proofs.di_vp.len(),
        Some(proofs) if !proofs.attestation.is_empty() => proofs.attestation.len(),
        _ => 1,
    }
}

/// Ensures already-issued credentials line up with request proof cardinality
/// before direct-attestation key cardinality is known.
pub fn validate_issued_credential_count(
    request: &CredentialRequest,
    issued_count: usize,
) -> IssuerResult<()> {
    if issued_count == expected_credential_count(request) {
        Ok(())
    } else {
        Err(IssuerError::new(IssuerStatus::InvalidProof))
    }
}

/// Ensures issued credentials line up with verified credential-binding keys.
pub fn validate_issued_credential_count_with_verified_proofs(
    request: &CredentialRequest,
    verified_proofs: Option<&VerifiedProofSet>,
    issued_count: usize,
) -> IssuerResult<()> {
    let expected = expected_bound_credential_count(request, verified_proofs)?;
    if issued_count == expected {
        Ok(())
    } else {
        Err(IssuerError::new(IssuerStatus::InvalidProof))
    }
}

/// Ensures an immediate response lines up with request proof cardinality.
pub fn validate_response_credential_count(
    request: &CredentialRequest,
    response: &CredentialResponse,
) -> IssuerResult<()> {
    match response.credentials.as_ref() {
        Some(credentials) => validate_issued_credential_count(request, credentials.len()),
        None => Ok(()),
    }
}

/// Ensures an immediate response lines up with verified binding-key cardinality.
pub fn validate_response_credential_count_with_verified_proofs(
    request: &CredentialRequest,
    verified_proofs: Option<&VerifiedProofSet>,
    response: &CredentialResponse,
) -> IssuerResult<()> {
    match response.credentials.as_ref() {
        Some(credentials) => validate_issued_credential_count_with_verified_proofs(
            request,
            verified_proofs,
            credentials.len(),
        ),
        None => Ok(()),
    }
}

fn expected_bound_credential_count(
    request: &CredentialRequest,
    verified_proofs: Option<&VerifiedProofSet>,
) -> IssuerResult<usize> {
    let uses_direct_attestation = request
        .proofs
        .as_ref()
        .is_some_and(|proofs| !proofs.attestation.is_empty());
    if !uses_direct_attestation {
        return Ok(expected_credential_count(request));
    }
    let verified = verified_proofs.ok_or(IssuerError::new(IssuerStatus::InvalidProof))?;
    if !verified.includes_key_attestation() || verified.binding_key_count() == 0 {
        return Err(IssuerError::new(IssuerStatus::InvalidProof));
    }
    usize::try_from(verified.binding_key_count())
        .map_err(|_| IssuerError::new(IssuerStatus::InvalidProof))
}
