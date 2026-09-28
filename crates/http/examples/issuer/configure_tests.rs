// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Issuer metadata and endpoint-policy configuration assertions.

use super::configure::{authorization_server_metadata, metadata};
use super::mdoc::{PID_MDOC_CONFIGURATION_ID, PID_MDOC_DOCTYPE};
use super::run::{ExampleIssuerError, EXAMPLE_MAX_BATCH_SIZE};

#[test]
fn authorization_server_metadata_is_validated_before_serving() -> Result<(), ExampleIssuerError> {
    let metadata = authorization_server_metadata("https://issuer.example/")?;

    assert_eq!(metadata.issuer, "https://issuer.example");
    assert_eq!(
        metadata.pushed_authorization_request_endpoint.as_deref(),
        Some("https://issuer.example/par")
    );
    assert_eq!(
        metadata.code_challenge_methods_supported.as_deref(),
        Some(&["S256".to_owned()][..])
    );
    Ok(())
}

#[test]
fn metadata_advertises_the_shared_batch_limit() -> Result<(), ExampleIssuerError> {
    let mut request_encryption_public_key = [0_u8; 65];
    request_encryption_public_key[0] = 0x04;
    let metadata = metadata(
        "https://issuer.example/openid4vci/example-issuer/",
        "https://issuer.example/",
        &request_encryption_public_key,
    )?;

    assert_eq!(
        metadata
            .batch_credential_issuance
            .map(|batch| batch.batch_size),
        Some(EXAMPLE_MAX_BATCH_SIZE)
    );
    let mdoc = metadata
        .credential_configurations_supported
        .get(PID_MDOC_CONFIGURATION_ID)
        .ok_or(ExampleIssuerError::InvalidMetadata)?;
    assert_eq!(mdoc.doctype.as_deref(), Some(PID_MDOC_DOCTYPE));
    assert_eq!(mdoc.scope.as_deref(), Some(PID_MDOC_CONFIGURATION_ID));
    assert_eq!(
        mdoc.credential_signing_alg_values_supported.as_deref(),
        Some(&[openid4vci_types::CredentialSigningAlg::Cose(-7)][..])
    );
    Ok(())
}

#[test]
fn metadata_and_endpoint_policy_share_key_attestation_requirements(
) -> Result<(), ExampleIssuerError> {
    let mut request_encryption_public_key = [0_u8; 65];
    request_encryption_public_key[0] = 0x04;
    let metadata = metadata(
        "https://issuer.example/openid4vci/example-issuer/",
        "https://issuer.example/",
        &request_encryption_public_key,
    )?;
    let proof = metadata
        .credential_configurations_supported
        .get("pid")
        .and_then(|configuration| configuration.proof_types_supported.as_ref())
        .and_then(|proof_types| proof_types.get("jwt"))
        .ok_or(ExampleIssuerError::InvalidMetadata)?;

    assert!(proof.key_attestations_required.is_some());
    let policy = super::configure::key_attestation_policy()?;
    assert_eq!(policy.accepted_algorithms.len(), 1);
    Ok(())
}
