// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Focused validation helpers for Credential Issuer Metadata substructures.

use crate::error::{OpenId4VciError, OpenId4VciResult, Reason};
use crate::metadata::CredentialSigningAlg;
use crate::validation::{validate_https_url, validate_issuer_identifier, validate_vec_non_empty};

pub(crate) const FORBIDDEN_METADATA_MEMBERS: [&str; 1] = ["batch_credential_endpoint"];

pub(crate) fn validate_optional_url(value: &Option<String>) -> OpenId4VciResult<()> {
    if let Some(url) = value {
        validate_https_url(url, false)?;
    }
    Ok(())
}

pub(crate) fn validate_optional_urls(value: &Option<Vec<String>>) -> OpenId4VciResult<()> {
    if let Some(urls) = value {
        validate_vec_non_empty(urls)?;
        for url in urls {
            validate_issuer_identifier(url)?;
        }
    }
    Ok(())
}

pub(crate) fn validate_optional_strings(value: &Option<Vec<String>>) -> OpenId4VciResult<()> {
    if let Some(values) = value {
        validate_vec_non_empty(values)?;
    }
    Ok(())
}

pub(crate) fn validate_optional_signing_algs(
    value: &Option<Vec<CredentialSigningAlg>>,
) -> OpenId4VciResult<()> {
    if let Some(values) = value {
        if values.is_empty() {
            return Err(OpenId4VciError::new(Reason::MissingRequiredField));
        }
        for value in values {
            value.validate()?;
        }
    }
    Ok(())
}

pub(crate) fn validate_response_encryption_algorithms(
    value: &Option<Vec<String>>,
) -> OpenId4VciResult<()> {
    let Some(values) = value else {
        return Ok(());
    };
    if values.iter().all(|item| item.starts_with("PBES2-")) {
        return Err(OpenId4VciError::new(Reason::InvalidString));
    }
    Ok(())
}
