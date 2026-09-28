// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Issuer-service test doubles shared by the Axum integration tests.

use openid4vci_http::{WalletAttestationEvidenceError, WalletAttestationEvidenceRecorder};
use openid4vci_issuer::{
    expected_credential_count, CredentialIssuer, CredentialRequestDecryptor,
    CredentialResponseEncryptor, DeferredIssuer, DeferredResolution, EncryptedCredentialResponse,
    IssuanceAuthorization, IssuanceOutcome, IssuerError, IssuerResult, IssuerStatus,
    VerifiedProofSet,
};
use openid4vci_types::{
    CredentialEnvelope, CredentialRequest, CredentialResponse, CredentialResponseEncryption,
    CredentialSelector,
};
use reallyme_crypto::sha2::digest as digest_sha2_256;
use reallyme_openid_oauth::VerifiedAttestationClientAuthentication;

pub(crate) struct TestCredentialIssuer;

impl CredentialIssuer for TestCredentialIssuer {
    fn issue(
        &self,
        authorization: &IssuanceAuthorization,
        request: &CredentialRequest,
        selector: &CredentialSelector,
        _verified_proofs: Option<&VerifiedProofSet>,
    ) -> IssuerResult<IssuanceOutcome> {
        if selector != &CredentialSelector::ConfigurationId("pid".to_owned())
            || authorization.credential_configuration_id() != "pid"
        {
            return Err(IssuerError::new(IssuerStatus::UnsupportedCredential));
        }
        let credentials = (0..expected_credential_count(request))
            .map(|_| CredentialEnvelope::compact("credential".to_owned()))
            .collect();
        Ok(IssuanceOutcome::Immediate(
            CredentialResponse::immediate(credentials, Some("notification-1".to_owned()))
                .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?,
        ))
    }
}

pub(crate) struct TestResponseEncryptor;

impl CredentialResponseEncryptor for TestResponseEncryptor {
    fn validate_parameters(&self, _encryption: &CredentialResponseEncryption) -> IssuerResult<()> {
        Ok(())
    }

    fn encrypt_response(
        &self,
        _response: &CredentialResponse,
        _encryption: &CredentialResponseEncryption,
    ) -> IssuerResult<EncryptedCredentialResponse> {
        EncryptedCredentialResponse::new("a.b.c.d.e".to_owned())
    }
}

/// Treats the opaque encrypted body as plaintext JSON so transport tests can
/// exercise the post-decryption path without coupling to a JOSE provider.
pub(crate) struct TestRequestDecryptor;

impl CredentialRequestDecryptor for TestRequestDecryptor {
    fn decrypt_request(
        &self,
        compact_jwe: &str,
    ) -> IssuerResult<openid4vci_issuer::DecryptedCredentialRequestJson> {
        openid4vci_issuer::DecryptedCredentialRequestJson::new(compact_jwe.to_owned())
    }
}

pub(crate) struct TestEvidenceRecorder;

impl WalletAttestationEvidenceRecorder for TestEvidenceRecorder {
    fn record(
        &self,
        evidence: &VerifiedAttestationClientAuthentication,
    ) -> Result<(), WalletAttestationEvidenceError> {
        let expected_pop_jti_sha256 = digest_sha2_256(b"attestation-pop-jti-1");
        if evidence.client_instance_key_thumbprint().is_empty()
            || evidence.pop_jti_sha256() != expected_pop_jti_sha256.as_bytes()
        {
            return Err(WalletAttestationEvidenceError::StorageUnavailable);
        }
        Ok(())
    }
}

pub(crate) struct TestDeferredIssuer;

impl DeferredIssuer for TestDeferredIssuer {
    fn resolve_deferred(
        &self,
        _authorization: &IssuanceAuthorization,
        transaction_id: &str,
    ) -> IssuerResult<DeferredResolution> {
        let outcome = CredentialResponse::immediate(
            vec![CredentialEnvelope::compact("deferred".to_owned())],
            None,
        )
        .map(IssuanceOutcome::Immediate)
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
        if !matches!(transaction_id, "transaction-1" | "encrypted-transaction-1") {
            return Err(IssuerError::new(IssuerStatus::InvalidTransaction));
        }
        Ok(DeferredResolution::new(outcome))
    }
}
