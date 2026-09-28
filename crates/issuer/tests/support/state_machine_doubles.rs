// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Stateful doubles shared by issuer state-machine integration tests.

use std::sync::atomic::{AtomicUsize, Ordering};

use openid4vci_issuer::{
    CredentialResponseEncryptor, DeferredIssuer, DeferredResolution, DeferredStore,
    EncryptedCredentialResponse, IssuanceAuthorization, IssuanceOutcome, IssuerError, IssuerResult,
    IssuerStatus, PassThroughCredentialEncoder,
};
use openid4vci_types::{
    CredentialEnvelope, CredentialFormat, CredentialResponse, CredentialResponseEncryption,
};

#[derive(Default)]
pub(crate) struct CountingDeferredIssuer {
    pub(crate) resolve_count: AtomicUsize,
}

impl DeferredIssuer for CountingDeferredIssuer {
    fn resolve_deferred(
        &self,
        _authorization: &IssuanceAuthorization,
        _transaction_id: &str,
    ) -> IssuerResult<DeferredResolution> {
        self.resolve_count.fetch_add(1, Ordering::SeqCst);
        CredentialResponse::immediate(
            vec![CredentialEnvelope::compact("credential".to_owned())],
            None,
        )
        .map(IssuanceOutcome::Immediate)
        .map(DeferredResolution::new)
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))
    }
}

pub(crate) struct StoreBackedDeferredIssuer<'a> {
    pub(crate) store: &'a dyn DeferredStore,
}

impl DeferredIssuer for StoreBackedDeferredIssuer<'_> {
    fn resolve_deferred(
        &self,
        _authorization: &IssuanceAuthorization,
        transaction_id: &str,
    ) -> IssuerResult<DeferredResolution> {
        let record = self.store.take(transaction_id, 1_000)?;
        let encoder = PassThroughCredentialEncoder::new(CredentialFormat::SdJwtVc);
        record
            .encode_response(&encoder, None)
            .map(IssuanceOutcome::Immediate)
            .map(DeferredResolution::new)
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

pub(crate) struct RejectingZipResponseEncryptor;

impl CredentialResponseEncryptor for RejectingZipResponseEncryptor {
    fn validate_parameters(&self, encryption: &CredentialResponseEncryption) -> IssuerResult<()> {
        if encryption.zip.is_some() {
            return Err(IssuerError::new(IssuerStatus::InvalidEncryptionParameters));
        }
        Ok(())
    }

    fn encrypt_response(
        &self,
        _response: &CredentialResponse,
        encryption: &CredentialResponseEncryption,
    ) -> IssuerResult<EncryptedCredentialResponse> {
        if encryption.zip.is_some() {
            return Err(IssuerError::new(IssuerStatus::InvalidEncryptionParameters));
        }
        EncryptedCredentialResponse::new("a.b.c.d.e".to_owned())
    }
}
