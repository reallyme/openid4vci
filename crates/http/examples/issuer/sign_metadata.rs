// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Signed Credential Issuer Metadata provider for the deployable example.

use openid4vci_issuer::{
    IssuerError, IssuerMetadataSigner, IssuerResult, IssuerStatus, SignedIssuerMetadataJwt,
};
use openid4vci_types::IssuerMetadata;
use serde_json::{json, Value};

use super::run::CONFORMANCE_ISSUER_X5C_LEAF;
use super::sign::sign_es256_jws;

pub(super) struct ExampleIssuerMetadataSigner;

impl IssuerMetadataSigner for ExampleIssuerMetadataSigner {
    fn sign_metadata(
        &self,
        metadata: &IssuerMetadata,
        issued_at_unix: i64,
    ) -> IssuerResult<SignedIssuerMetadataJwt> {
        if issued_at_unix < 0 {
            return Err(IssuerError::new(IssuerStatus::EncodingFailed));
        }
        let encoded = metadata
            .to_json()
            .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
        let mut claims = serde_json::from_str::<Value>(&encoded)
            .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
        let object = claims
            .as_object_mut()
            .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?;
        if object.contains_key("sub") || object.contains_key("iat") {
            return Err(IssuerError::new(IssuerStatus::EncodingFailed));
        }
        object.insert(
            "sub".to_owned(),
            Value::String(metadata.credential_issuer.clone()),
        );
        object.insert("iat".to_owned(), Value::from(issued_at_unix));
        let header = json!({
            "alg": "ES256",
            "typ": "openidvci-issuer-metadata+jwt",
            "x5c": [CONFORMANCE_ISSUER_X5C_LEAF]
        });
        SignedIssuerMetadataJwt::new(sign_es256_jws(&header, &claims)?)
    }
}
