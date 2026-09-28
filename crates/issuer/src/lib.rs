// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Transport-agnostic OpenID4VCI issuer endpoint engine.
//!
//! The functions in this crate accept already-parsed wire objects and injected
//! traits for storage, proof verification, and credential issuance. HTTP
//! headers, bearer-token validation, request routing, and TLS live in adapters.

mod authorization;
mod credential_policy;
pub mod encode;
pub mod encrypt;
#[cfg(feature = "identity-jose")]
pub mod encrypt_jwe;
pub mod endpoint;
pub mod error;
mod generate_identifier;
#[cfg(feature = "identity-jose")]
pub mod jose;
pub mod metadata;
pub mod nonce;
pub mod proof;
pub mod store;
mod validate_credential_request;
pub mod verify_attestation;

pub use authorization::IssuanceAuthorization;
pub use credential_policy::{CredentialEndpointConfig, ProofTypeEndpointPolicy};
pub use encode::{
    encode_immediate_response, encode_immediate_response_with_verified_proofs,
    expected_credential_count, validate_issued_credential_count,
    validate_issued_credential_count_with_verified_proofs, validate_response_credential_count,
    validate_response_credential_count_with_verified_proofs, CredentialEncoder, IssuedCredential,
    PassThroughCredentialEncoder,
};
pub use encrypt::{
    decrypt_credential_request_json, require_encrypted_request_for_response_encryption,
    select_response_encryption_parameters, validate_response_encryption_parameters,
    CredentialRequestDecryptor, CredentialRequestInput, CredentialRequestJson,
    CredentialResponseBody, CredentialResponseEncryptor, DecryptedCredentialRequestJson,
    DeferredCredentialRequestInput, EncryptedCredentialResponse,
    DEFAULT_MAX_CREDENTIAL_REQUEST_JSON_BYTES, DEFAULT_MAX_ENCRYPTED_RESPONSE_BYTES,
};
#[cfg(feature = "identity-jose")]
pub use encrypt_jwe::{
    JoseJweCredentialRequestDecryptor, JoseJweCredentialResponseEncryptor, JoseJwePrivateKey,
};
pub use endpoint::{
    handle_credential_request, handle_credential_request_body,
    handle_deferred_credential_request_body, handle_nonce_request, handle_notification_request,
    preflight_credential_request, CredentialIssuer, CredentialRequestPreflight, DeferredIssuer,
    DeferredResolution, IssuanceOutcome, NotificationHandler,
};
pub use error::{IssuerError, IssuerResult, IssuerStatus};
pub use generate_identifier::{
    NotificationIdGenerator, OsNotificationIdGenerator, OsTransactionIdGenerator,
    TransactionIdGenerator,
};
#[cfg(feature = "identity-jose")]
pub use jose::{JoseJwtProofVerifier, ProofKeyBinding, ProofKeyResolver};
pub use metadata::{
    IssuerMetadataSigner, SignedIssuerMetadataJwt, MAX_SIGNED_ISSUER_METADATA_JWT_BYTES,
};
pub use nonce::{
    AuthenticatedNonceManager, NonceCapacitySnapshot, NonceManager, MAX_NONCE_TTL_SECONDS,
};
pub use proof::{
    validate_common_proof_claims, CompactProofJwtParser, ConfirmationJwk,
    KeyAttestationLocalPolicy, KeyAttestationPolicy, ProofAlgorithm, ProofKind,
    ProofVerificationContext, ProofVerifier, UnverifiedProofClaims, VerifiedProof,
    VerifiedProofSet, DEFAULT_MAX_PROOF_JWT_BYTES, PROOF_JWT_TYP,
};
pub use store::{
    DeferredIssuance, DeferredStore, InMemoryDeferredStore, InMemoryNotificationStore,
    NotificationRecord, NotificationStore,
};
pub use verify_attestation::KeyAttestationProofVerifier;
