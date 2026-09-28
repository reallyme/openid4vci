// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Configures example issuer metadata, encryption, and deferred services.

use std::collections::BTreeMap;

use openid4vci_issuer::{
    DeferredIssuer, DeferredResolution, IssuanceOutcome, IssuerError, IssuerResult, IssuerStatus,
    KeyAttestationLocalPolicy, NotificationHandler,
};
use openid4vci_types::{
    CredentialConfiguration, CredentialEnvelope, CredentialFormat,
    CredentialRequestEncryptionMetadata, CredentialResponse, CredentialResponseEncryptionMetadata,
    CredentialSigningAlg, IssuerMetadata, KeyAttestationsRequired, NotificationEvent,
    NotificationRequest, ProofTypeMetadata, PublicJwk, PublicJwkSet,
};
use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_openid_oauth::AuthorizationServerMetadata;
use serde_json::json;

use super::mdoc::{PID_MDOC_CONFIGURATION_ID, PID_MDOC_DOCTYPE};
use super::run::{
    ExampleIssuerError, EXAMPLE_MAX_BATCH_SIZE, KEY_ATTESTATION_ALLOWED_CLOCK_SKEW_SECONDS,
    KEY_ATTESTATION_MAX_AGE_SECONDS, P256_PRIVATE_SCALAR_BYTES, P256_UNCOMPRESSED_PUBLIC_KEY_BYTES,
    P256_X_COORDINATE_RANGE, P256_Y_COORDINATE_RANGE, PID_VCT, REQUEST_ENCRYPTION_KEY_KID,
    REQUEST_ENCRYPTION_PRIVATE_SCALAR_LAST_BYTE,
};

pub(super) const EXAMPLE_ISSUER_PATH: &str = "/openid4vci/example-issuer/";

pub(super) struct ExampleDeferredIssuer;

impl DeferredIssuer for ExampleDeferredIssuer {
    fn resolve_deferred(
        &self,
        _authorization: &openid4vci_issuer::IssuanceAuthorization,
        transaction_id: &str,
    ) -> IssuerResult<DeferredResolution> {
        if transaction_id != "transaction-1" {
            return Err(IssuerError::new(IssuerStatus::InvalidTransaction));
        }
        let outcome = IssuanceOutcome::Immediate(
            CredentialResponse::immediate(
                vec![CredentialEnvelope::compact(
                    "deferred-conformance-credential".to_owned(),
                )],
                None,
            )
            .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?,
        );
        Ok(DeferredResolution::new(outcome))
    }
}

pub(super) struct ExampleNotificationHandler;

impl NotificationHandler for ExampleNotificationHandler {
    fn handle_notification(&self, request: &NotificationRequest) -> IssuerResult<()> {
        if request.event == NotificationEvent::CredentialAccepted {
            Ok(())
        } else {
            Err(IssuerError::new(IssuerStatus::InvalidNotificationId))
        }
    }
}

pub(super) fn metadata(
    scoped_issuer_url: &str,
    authorization_server_url: &str,
    request_encryption_public_key: &[u8],
) -> Result<IssuerMetadata, ExampleIssuerError> {
    IssuerMetadata::builder(
        scoped_issuer_url.to_owned(),
        endpoint(scoped_issuer_url, "/credential"),
    )
    .authorization_servers(vec![authorization_server_url
        .trim_end_matches('/')
        .to_owned()])
    .nonce_endpoint(endpoint(scoped_issuer_url, "/nonce"))
    .deferred_credential_endpoint(endpoint(scoped_issuer_url, "/deferred_credential"))
    .notification_endpoint(endpoint(scoped_issuer_url, "/notification"))
    .batch_credential_issuance(EXAMPLE_MAX_BATCH_SIZE)
    .proof_required(true)
    .jwt_proof_signing_alg_values_supported(vec!["ES256".to_owned(), "EdDSA".to_owned()])
    .credential_request_encryption(request_encryption_metadata(request_encryption_public_key)?)
    .credential_response_encryption(response_encryption_metadata())
    .credential_configuration("pid".to_owned(), credential_configuration())
    .credential_configuration(
        PID_MDOC_CONFIGURATION_ID.to_owned(),
        mdoc_credential_configuration(),
    )
    .build()
    .map_err(|_| ExampleIssuerError::InvalidMetadata)
}

pub(super) fn example_request_encryption_keypair() -> Result<(Vec<u8>, Vec<u8>), ExampleIssuerError>
{
    let mut private_scalar = [0_u8; P256_PRIVATE_SCALAR_BYTES];
    private_scalar[P256_PRIVATE_SCALAR_BYTES - 1] = REQUEST_ENCRYPTION_PRIVATE_SCALAR_LAST_BYTE;
    let (public_key, private_key) =
        reallyme_crypto::p256::generate_p256_keypair_from_secret_key(&private_scalar)
            .map_err(|_| ExampleIssuerError::InvalidMetadata)?;
    Ok((public_key, private_key.to_vec()))
}

fn request_encryption_metadata(
    public_key: &[u8],
) -> Result<CredentialRequestEncryptionMetadata, ExampleIssuerError> {
    Ok(CredentialRequestEncryptionMetadata {
        alg_values_supported: None,
        enc_values_supported: supported_jwe_content_encryption_algorithms(),
        zip_values_supported: None,
        jwks: PublicJwkSet::new(vec![request_encryption_jwk(public_key)?])
            .map_err(|_| ExampleIssuerError::InvalidMetadata)?,
        encryption_required: false,
    })
}

pub(super) fn response_encryption_metadata() -> CredentialResponseEncryptionMetadata {
    CredentialResponseEncryptionMetadata {
        alg_values_supported: Some(vec!["ECDH-ES".to_owned()]),
        enc_values_supported: Some(supported_jwe_content_encryption_algorithms()),
        zip_values_supported: Some(vec!["DEF".to_owned()]),
        encryption_required: false,
    }
}

fn supported_jwe_content_encryption_algorithms() -> Vec<String> {
    vec![
        "A128GCM".to_owned(),
        "A192GCM".to_owned(),
        "A256GCM".to_owned(),
    ]
}

fn request_encryption_jwk(public_key: &[u8]) -> Result<PublicJwk, ExampleIssuerError> {
    let uncompressed = if public_key.len() == P256_UNCOMPRESSED_PUBLIC_KEY_BYTES
        && public_key.first() == Some(&0x04)
    {
        public_key.to_vec()
    } else {
        reallyme_crypto::p256::decompress_public_key(public_key)
            .map_err(|_| ExampleIssuerError::InvalidMetadata)?
    };
    let x = uncompressed
        .get(P256_X_COORDINATE_RANGE)
        .ok_or(ExampleIssuerError::InvalidMetadata)?;
    let y = uncompressed
        .get(P256_Y_COORDINATE_RANGE)
        .ok_or(ExampleIssuerError::InvalidMetadata)?;
    PublicJwk::new(json!({
        "kty": "EC",
        "crv": "P-256",
        "alg": "ECDH-ES",
        "use": "enc",
        "kid": REQUEST_ENCRYPTION_KEY_KID,
        "x": bytes_to_base64url(x),
        "y": bytes_to_base64url(y)
    }))
    .map_err(|_| ExampleIssuerError::InvalidMetadata)
}

pub(super) fn authorization_server_metadata(
    issuer_base_url: &str,
) -> Result<AuthorizationServerMetadata, ExampleIssuerError> {
    let issuer = issuer_base_url.trim_end_matches('/').to_owned();
    let body = json!({
        "issuer": issuer,
        "authorization_endpoint": endpoint(&issuer, "/authorize"),
        "token_endpoint": endpoint(&issuer, "/token"),
        "pushed_authorization_request_endpoint": endpoint(&issuer, "/par"),
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"],
        "dpop_signing_alg_values_supported": ["ES256", "EdDSA"],
        "require_pushed_authorization_requests": true,
        "token_endpoint_auth_methods_supported": ["attest_jwt_client_auth", "none"],
        "authorization_response_iss_parameter_supported": true,
        "client_attestation_signing_alg_values_supported": ["ES256"],
        "client_attestation_pop_signing_alg_values_supported": ["ES256"]
    });
    AuthorizationServerMetadata::parse_json(&body.to_string())
        .map_err(|_| ExampleIssuerError::InvalidMetadata)
}

pub(super) fn scoped_issuer_url(issuer_base_url: &str) -> String {
    let mut value = issuer_base_url.trim_end_matches('/').to_owned();
    value.push_str(EXAMPLE_ISSUER_PATH);
    value
}

fn credential_configuration() -> CredentialConfiguration {
    let mut configuration = CredentialConfiguration::new(CredentialFormat::SdJwtVc);
    configuration.scope = Some("pid".to_owned());
    configuration.cryptographic_binding_methods_supported =
        Some(vec!["jwk".to_owned(), "did:key".to_owned()]);
    configuration.credential_signing_alg_values_supported = Some(vec![
        CredentialSigningAlg::Named("ES256".to_owned()),
        CredentialSigningAlg::Named("EdDSA".to_owned()),
    ]);
    let mut proof_types = BTreeMap::new();
    proof_types.insert("jwt".to_owned(), key_attestation_proof_metadata());
    configuration.proof_types_supported = Some(proof_types);
    configuration.vct = Some(PID_VCT.to_owned());
    configuration.credential_metadata = Some(json!({
        "claims": [
            {"path": ["given_name"], "mandatory": false},
            {"path": ["family_name"], "mandatory": false},
            {"path": ["birthdate"], "mandatory": false}
        ]
    }));
    configuration
}

fn mdoc_credential_configuration() -> CredentialConfiguration {
    let mut configuration = CredentialConfiguration::new(CredentialFormat::MsoMdoc);
    configuration.scope = Some(PID_MDOC_CONFIGURATION_ID.to_owned());
    configuration.cryptographic_binding_methods_supported = Some(vec!["jwk".to_owned()]);
    configuration.credential_signing_alg_values_supported =
        Some(vec![CredentialSigningAlg::Cose(-7)]);
    let mut proof_types = BTreeMap::new();
    proof_types.insert("jwt".to_owned(), key_attestation_proof_metadata());
    configuration.proof_types_supported = Some(proof_types);
    configuration.doctype = Some(PID_MDOC_DOCTYPE.to_owned());
    configuration.credential_metadata = Some(json!({
        "claims": [
            {"path": [PID_MDOC_DOCTYPE, "given_name"], "mandatory": false},
            {"path": [PID_MDOC_DOCTYPE, "family_name"], "mandatory": false},
            {"path": [PID_MDOC_DOCTYPE, "birth_date"], "mandatory": false},
            {"path": [PID_MDOC_DOCTYPE, "issuing_country"], "mandatory": false}
        ]
    }));
    configuration
}

pub(super) fn key_attestation_policy() -> Result<KeyAttestationLocalPolicy, ExampleIssuerError> {
    KeyAttestationLocalPolicy::new(
        KEY_ATTESTATION_MAX_AGE_SECONDS,
        KEY_ATTESTATION_ALLOWED_CLOCK_SKEW_SECONDS,
    )
    .map_err(|_| ExampleIssuerError::InvalidMetadata)
}

fn key_attestation_proof_metadata() -> ProofTypeMetadata {
    ProofTypeMetadata {
        proof_signing_alg_values_supported: vec!["ES256".to_owned()],
        // An empty constraint object means that signer trust and key binding
        // are mandatory without inventing device-resistance claims that the
        // deployment's trust provider has not independently established.
        key_attestations_required: Some(KeyAttestationsRequired {
            key_storage: None,
            user_authentication: None,
            preferred_key_storage_status_period: None,
        }),
    }
}

pub(super) fn endpoint(issuer_base_url: &str, path: &'static str) -> String {
    let mut value = issuer_base_url.trim_end_matches('/').to_owned();
    value.push_str(path);
    value
}
