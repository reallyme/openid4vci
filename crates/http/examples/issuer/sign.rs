// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared ES256 signing provider for issuer credential and metadata outputs.

use openid4vci_issuer::{IssuerError, IssuerResult, IssuerStatus};
use reallyme_codec::base64url::{base64url_to_bytes, bytes_to_base64url};
use reallyme_crypto::core::Algorithm;
use reallyme_crypto::dispatch::sign;
use reallyme_crypto::p256::p256_ecdsa_der_to_jose_signature;
use serde_json::Value;
use zeroize::Zeroizing;

use super::run::CONFORMANCE_ISSUER_PRIVATE_KEY_D;

pub(super) fn sign_es256_jws(header: &Value, payload: &Value) -> IssuerResult<String> {
    let protected = bytes_to_base64url(
        &serde_json::to_vec(header).map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?,
    );
    let payload = bytes_to_base64url(
        &serde_json::to_vec(payload).map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?,
    );
    let mut signing_input = protected;
    signing_input.push('.');
    signing_input.push_str(&payload);
    let private_key = Zeroizing::new(
        base64url_to_bytes(CONFORMANCE_ISSUER_PRIVATE_KEY_D)
            .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?,
    );
    let der_signature = sign(Algorithm::P256, &private_key, signing_input.as_bytes())
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    let signature = p256_ecdsa_der_to_jose_signature(&der_signature)
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    signing_input.push('.');
    signing_input.push_str(&bytes_to_base64url(&signature));
    Ok(signing_input)
}
