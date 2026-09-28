// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Credential response-encryption policy selection tests.

use std::borrow::Cow;

use openid4vci_issuer::{select_response_encryption_parameters, IssuerResult};
use openid4vci_types::{
    CredentialResponseEncryption, CredentialResponseEncryptionMetadata, PublicJwk,
};
use serde_json::json;

#[test]
fn rejects_unadvertised_response_compression() -> IssuerResult<()> {
    let requested = response_encryption()?;
    let metadata = response_encryption_metadata(None);

    let result = select_response_encryption_parameters(&requested, Some(&metadata));

    assert_eq!(
        result.err().map(|error| error.status()),
        Some(openid4vci_issuer::IssuerStatus::InvalidEncryptionParameters)
    );
    assert_eq!(requested.zip.as_deref(), Some("DEF"));
    Ok(())
}

#[test]
fn rejects_response_compression_not_listed_by_issuer() -> IssuerResult<()> {
    let requested = response_encryption()?;
    let metadata = response_encryption_metadata(Some(vec!["GZIP".to_owned()]));

    let result = select_response_encryption_parameters(&requested, Some(&metadata));

    assert_eq!(
        result.err().map(|error| error.status()),
        Some(openid4vci_issuer::IssuerStatus::InvalidEncryptionParameters)
    );
    Ok(())
}

#[test]
fn preserves_advertised_response_compression_for_provider() -> IssuerResult<()> {
    let requested = response_encryption()?;
    let metadata = response_encryption_metadata(Some(vec!["DEF".to_owned()]));

    let selected = select_response_encryption_parameters(&requested, Some(&metadata))?;

    assert!(matches!(selected, Cow::Borrowed(_)));
    assert_eq!(selected.zip.as_deref(), Some("DEF"));
    Ok(())
}

fn response_encryption() -> IssuerResult<CredentialResponseEncryption> {
    Ok(CredentialResponseEncryption {
        jwk: PublicJwk::new(json!({"kty":"EC","alg":"ECDH-ES"})).map_err(|_| {
            openid4vci_issuer::IssuerError::new(
                openid4vci_issuer::IssuerStatus::InvalidEncryptionParameters,
            )
        })?,
        enc: "A256GCM".to_owned(),
        zip: Some("DEF".to_owned()),
    })
}

fn response_encryption_metadata(
    zip_values_supported: Option<Vec<String>>,
) -> CredentialResponseEncryptionMetadata {
    CredentialResponseEncryptionMetadata {
        alg_values_supported: Some(vec!["ECDH-ES".to_owned()]),
        enc_values_supported: Some(vec!["A256GCM".to_owned()]),
        zip_values_supported,
        encryption_required: false,
    }
}
