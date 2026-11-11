// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! ETSI TS 119 472-3 issuer-profile policy tests.

use std::collections::BTreeMap;

use openid4vci_issuer::{
    CredentialEndpointConfig, CredentialRequestProfile, IssuerError, IssuerResult, IssuerStatus,
    KeyAttestationLocalPolicy,
};
use openid4vci_types::{
    CredentialConfiguration, CredentialFormat, IssuerMetadata, KeyAttestationsRequired,
    ProofTypeMetadata,
};

#[test]
fn etsi_endpoint_profile_requires_nonce_and_wua_policy() -> IssuerResult<()> {
    let mut proof_types = BTreeMap::new();
    proof_types.insert(
        "jwt".to_owned(),
        ProofTypeMetadata {
            proof_signing_alg_values_supported: vec!["ES256".to_owned()],
            key_attestations_required: Some(KeyAttestationsRequired {
                key_storage: None,
                user_authentication: None,
                preferred_key_storage_status_period: None,
            }),
        },
    );
    let metadata = IssuerMetadata::builder(
        "https://issuer.example".to_owned(),
        "https://issuer.example/credential".to_owned(),
    )
    .nonce_endpoint("https://issuer.example/nonce".to_owned())
    .credential_configuration(
        "pid".to_owned(),
        CredentialConfiguration {
            cryptographic_binding_methods_supported: Some(vec!["jwk".to_owned()]),
            proof_types_supported: Some(proof_types),
            ..CredentialConfiguration::new(CredentialFormat::SdJwtVc)
        },
    )
    .build()
    .map_err(|_| IssuerError::new(IssuerStatus::InvalidProofPolicy))?;
    let local = KeyAttestationLocalPolicy::new(300, 5)?;
    let profiled = CredentialEndpointConfig::from_metadata(&metadata, "pid", Some(local))?
        .with_etsi_ts119472_part3_profile()?;
    assert_eq!(
        profiled.credential_request_profile,
        CredentialRequestProfile::EtsiTs119472Part3
    );

    let mut without_nonce = metadata;
    without_nonce.nonce_endpoint = None;
    let result = CredentialEndpointConfig::from_metadata(&without_nonce, "pid", Some(local))?
        .with_etsi_ts119472_part3_profile();
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidProofPolicy)
    );
    Ok(())
}
