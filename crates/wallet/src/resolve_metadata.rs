// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Credential Issuer Metadata discovery and issuer binding.

use openid4vci_types::IssuerMetadata;
use url::{Host, Url};

use crate::{WalletError, WalletResult, WalletStatus};

const CREDENTIAL_ISSUER_WELL_KNOWN_PATH: &str = "/.well-known/openid-credential-issuer";
const MAX_ISSUER_IDENTIFIER_BYTES: usize = 8_192;

/// Fetches a Credential Issuer Metadata JSON document from an exact URL.
pub trait CredentialIssuerMetadataFetcher {
    /// Fetch a bounded document without redirects or ambient authentication.
    ///
    /// Implementations must resolve every DNS answer before connecting,
    /// reject loopback, private, link-local, multicast, and otherwise
    /// non-public addresses, and pin the selected address for the connection.
    /// This connect-time check is required to prevent DNS rebinding after the
    /// syntactic URL validation performed by this crate.
    fn fetch_metadata_json(&self, metadata_url: &str) -> WalletResult<String>;
}

/// Derive the OpenID4VCI well-known URL for a Credential Issuer Identifier.
pub fn credential_issuer_metadata_url(credential_issuer: &str) -> WalletResult<String> {
    if credential_issuer.is_empty() || credential_issuer.len() > MAX_ISSUER_IDENTIFIER_BYTES {
        return Err(invalid_metadata());
    }
    let mut url = Url::parse(credential_issuer).map_err(|_| invalid_metadata())?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.host(), Some(Host::Domain(host)) if !is_localhost_name(host))
    {
        return Err(invalid_metadata());
    }

    // `url::Url` normalizes an absent path to `/`. OID4VCI 1.0 preserves the
    // issuer path verbatim, including a terminating slash, so distinguish an
    // absent path from an explicitly supplied root path before rewriting it.
    let issuer_path = if url.path() == "/" && !credential_issuer.ends_with('/') {
        ""
    } else {
        url.path()
    };
    let mut metadata_path = CREDENTIAL_ISSUER_WELL_KNOWN_PATH.to_owned();
    if !issuer_path.is_empty() {
        metadata_path.push_str(issuer_path);
    }
    url.set_path(&metadata_path);
    Ok(url.into())
}

fn is_localhost_name(host: &str) -> bool {
    let normalized = host.trim_end_matches('.');
    normalized.eq_ignore_ascii_case("localhost")
        || normalized.to_ascii_lowercase().ends_with(".localhost")
}

/// Fetch, parse, and bind unsigned Credential Issuer Metadata to an exact issuer.
///
/// HAIP deployments that require signed metadata use the same URL derivation,
/// request `application/jwt`, and pass the returned compact JWT through
/// [`crate::verify_signed_issuer_metadata`]. This function is deliberately
/// limited to the JSON representation so an HTTP adapter cannot silently
/// downgrade a signed-metadata policy.
pub fn resolve_credential_issuer_metadata(
    fetcher: &dyn CredentialIssuerMetadataFetcher,
    credential_issuer: &str,
) -> WalletResult<IssuerMetadata> {
    let metadata_url = credential_issuer_metadata_url(credential_issuer)?;
    let body = fetcher
        .fetch_metadata_json(&metadata_url)
        .map_err(|_| resolution_error())?;
    let metadata = IssuerMetadata::parse_json(&body).map_err(|_| invalid_metadata())?;
    if metadata.credential_issuer != credential_issuer {
        return Err(issuer_mismatch());
    }
    Ok(metadata)
}

const fn invalid_metadata() -> WalletError {
    WalletError::new(WalletStatus::InvalidIssuerMetadata)
}

const fn resolution_error() -> WalletError {
    WalletError::new(WalletStatus::IssuerMetadataResolutionFailed)
}

const fn issuer_mismatch() -> WalletError {
    WalletError::new(WalletStatus::IssuerMetadataIssuerMismatch)
}

#[cfg(test)]
#[path = "resolve_metadata_tests.rs"]
mod tests;
