// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::cell::RefCell;

use super::{
    credential_issuer_metadata_url, resolve_credential_issuer_metadata,
    CredentialIssuerMetadataFetcher,
};
use crate::{WalletError, WalletResult, WalletStatus};

struct FixedFetcher {
    expected_url: &'static str,
    body: &'static str,
    observed_url: RefCell<Option<String>>,
}

impl CredentialIssuerMetadataFetcher for FixedFetcher {
    fn fetch_metadata_json(&self, metadata_url: &str) -> WalletResult<String> {
        self.observed_url.replace(Some(metadata_url.to_owned()));
        if metadata_url != self.expected_url {
            return Err(WalletError::new(
                WalletStatus::IssuerMetadataResolutionFailed,
            ));
        }
        Ok(self.body.to_owned())
    }
}

#[test]
fn derives_root_and_path_issuer_well_known_urls() -> WalletResult<()> {
    assert_eq!(
        credential_issuer_metadata_url("https://issuer.example")?,
        "https://issuer.example/.well-known/openid-credential-issuer"
    );
    assert_eq!(
        credential_issuer_metadata_url("https://issuer.example/")?,
        "https://issuer.example/.well-known/openid-credential-issuer/"
    );
    assert_eq!(
        credential_issuer_metadata_url("https://issuer.example/tenant/a")?,
        "https://issuer.example/.well-known/openid-credential-issuer/tenant/a"
    );
    assert_eq!(
        credential_issuer_metadata_url("https://issuer.example/tenant/a/")?,
        "https://issuer.example/.well-known/openid-credential-issuer/tenant/a/"
    );
    Ok(())
}

#[test]
fn rejects_ambient_authority_and_non_https_issuers() {
    for issuer in [
        "http://issuer.example",
        "https://user:password@issuer.example",
        "https://issuer.example?tenant=a",
        "https://issuer.example#fragment",
        "https://localhost",
        "https://localhost.",
        "https://issuer.localhost/tenant",
        "https://issuer.localhost./tenant",
        "https://127.0.0.1",
        "https://[::1]",
    ] {
        let result = credential_issuer_metadata_url(issuer);
        assert!(matches!(
            result,
            Err(error) if error.status() == WalletStatus::InvalidIssuerMetadata
        ));
    }
}

#[test]
fn resolves_and_binds_metadata_to_exact_issuer() -> WalletResult<()> {
    let fetcher = FixedFetcher {
        expected_url: "https://issuer.example/.well-known/openid-credential-issuer/tenant",
        body: r#"{
            "credential_issuer":"https://issuer.example/tenant",
            "credential_endpoint":"https://issuer.example/credential",
            "credential_configurations_supported":{
                "pid":{"format":"dc+sd-jwt","vct":"urn:example:pid"}
            }
        }"#,
        observed_url: RefCell::new(None),
    };

    let metadata = resolve_credential_issuer_metadata(&fetcher, "https://issuer.example/tenant")?;

    assert_eq!(metadata.credential_issuer, "https://issuer.example/tenant");
    assert_eq!(
        fetcher.observed_url.borrow().as_deref(),
        Some(fetcher.expected_url)
    );
    Ok(())
}

#[test]
fn rejects_metadata_for_a_different_issuer() {
    let fetcher = FixedFetcher {
        expected_url: "https://issuer.example/.well-known/openid-credential-issuer",
        body: r#"{
            "credential_issuer":"https://other.example",
            "credential_endpoint":"https://other.example/credential",
            "credential_configurations_supported":{
                "pid":{"format":"dc+sd-jwt","vct":"urn:example:pid"}
            }
        }"#,
        observed_url: RefCell::new(None),
    };

    let result = resolve_credential_issuer_metadata(&fetcher, "https://issuer.example");

    assert!(matches!(
        result,
        Err(error) if error.status() == WalletStatus::IssuerMetadataIssuerMismatch
    ));
}
