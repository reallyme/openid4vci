// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_codec::jcs::canonicalize_json_text;
use serde::de::DeserializeOwned;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{OpenId4VciError, OpenId4VciResult, Reason};

pub(crate) const MAX_JSON_BYTES: usize = 65_536;
pub(crate) const MAX_JSON_OUTPUT_BYTES: usize = 262_144;
/// Maximum array/object nesting accepted by the shared JCS text parser.
///
/// This value mirrors the `reallyme-codec-jcs` limit used by
/// `canonicalize_json_text`. Keeping the policy named here makes the domain
/// boundary auditable without making callers depend on a transitive crate.
pub(crate) const MAX_JSON_NESTING_DEPTH: usize = 128;

/// Duplicate member names are always rejected before typed deserialization.
pub(crate) const REJECT_DUPLICATE_JSON_MEMBERS: bool = true;

/// Unknown-member behavior selected by each domain JSON document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnknownFieldPolicy {
    /// Operation-bearing documents have a closed, fail-closed wire shape.
    Reject,
    /// Registry- and standards-extensible documents ignore extension members.
    AllowExtensions,
}

/// Complete policy for an inbound domain JSON document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct JsonBoundaryPolicy {
    pub(crate) max_input_bytes: usize,
    pub(crate) max_nesting_depth: usize,
    pub(crate) reject_duplicate_members: bool,
    pub(crate) unknown_fields: UnknownFieldPolicy,
    pub(crate) malformed_reason: Reason,
    pub(crate) oversized_reason: Reason,
}

/// Fail-closed policy used by credential operations and their responses.
pub(crate) const CLOSED_OPERATION_JSON: JsonBoundaryPolicy = JsonBoundaryPolicy {
    max_input_bytes: MAX_JSON_BYTES,
    max_nesting_depth: MAX_JSON_NESTING_DEPTH,
    reject_duplicate_members: REJECT_DUPLICATE_JSON_MEMBERS,
    unknown_fields: UnknownFieldPolicy::Reject,
    malformed_reason: Reason::InvalidJson,
    oversized_reason: Reason::PayloadTooLarge,
};

/// Policy used only for documents whose standards define extension members.
pub(crate) const EXTENSIBLE_DOCUMENT_JSON: JsonBoundaryPolicy = JsonBoundaryPolicy {
    unknown_fields: UnknownFieldPolicy::AllowExtensions,
    ..CLOSED_OPERATION_JSON
};

pub(crate) fn parse_json<T: DeserializeOwned>(
    body: &str,
    policy: JsonBoundaryPolicy,
) -> OpenId4VciResult<T> {
    if body.len() > policy.max_input_bytes {
        return Err(OpenId4VciError::new(policy.oversized_reason));
    }
    // Canonicalization is the shared strict JSON boundary. It preserves the
    // duplicate-member and depth checks that direct typed deserialization
    // cannot enforce after object members have already been collapsed.
    // This boundary currently delegates duplicate and nesting enforcement to
    // the shared JCS implementation. Refuse an internally inconsistent policy
    // rather than claiming that a weaker setting was applied.
    if policy.max_nesting_depth != MAX_JSON_NESTING_DEPTH || !policy.reject_duplicate_members {
        return Err(OpenId4VciError::new(policy.malformed_reason));
    }
    let canonical = Zeroizing::new(
        canonicalize_json_text(body).map_err(|_| OpenId4VciError::new(policy.malformed_reason))?,
    );
    // Closed-object enforcement is encoded on the target model with
    // `serde(deny_unknown_fields)`; extensible models deliberately omit it.
    // Matching here keeps the model/callsite contract explicit under review.
    match policy.unknown_fields {
        UnknownFieldPolicy::Reject | UnknownFieldPolicy::AllowExtensions => {
            serde_json::from_str(canonical.as_str())
                .map_err(|_| OpenId4VciError::new(policy.malformed_reason))
        }
    }
}

pub(crate) fn parse_json_rejecting_top_level_members<T: DeserializeOwned>(
    body: &str,
    policy: JsonBoundaryPolicy,
    forbidden_members: &[&str],
) -> OpenId4VciResult<T> {
    let mut value: serde_json::Value = parse_json(body, policy)?;
    let contains_forbidden_member = value.as_object().is_some_and(|object| {
        forbidden_members
            .iter()
            .any(|member| object.contains_key(*member))
    });
    zeroize_json_strings(&mut value);
    if contains_forbidden_member {
        return Err(OpenId4VciError::new(policy.malformed_reason));
    }

    // Parse the bounded source again rather than moving values out of the
    // inspection tree. This lets the tree be wiped before typed ownership is
    // constructed and keeps deserialization failures on the existing
    // zeroizing canonical-text path.
    parse_json(body, policy)
}

pub(crate) fn to_json<T: serde::Serialize>(value: &T) -> OpenId4VciResult<String> {
    let mut output = Zeroizing::new(
        serde_json::to_string(value).map_err(|_| OpenId4VciError::new(Reason::InvalidJson))?,
    );
    if output.len() > MAX_JSON_OUTPUT_BYTES {
        return Err(OpenId4VciError::new(Reason::PayloadTooLarge));
    }
    Ok(core::mem::take(&mut *output))
}

pub(crate) fn validate_non_empty_asciiish(value: &str) -> OpenId4VciResult<()> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(OpenId4VciError::new(Reason::InvalidString));
    }
    Ok(())
}

pub(crate) fn validate_https_url(value: &str, allow_loopback_http: bool) -> OpenId4VciResult<()> {
    validate_non_empty_asciiish(value)?;
    let url = Url::parse(value).map_err(|_| OpenId4VciError::new(Reason::InvalidUrl))?;
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(OpenId4VciError::new(Reason::InvalidUrl));
    }
    match url.scheme() {
        "https" if is_public_domain_host(&url) => Ok(()),
        "http" if allow_loopback_http && is_loopback_host(&url) => Ok(()),
        _ => Err(OpenId4VciError::new(Reason::InvalidUrl)),
    }
}

fn is_public_domain_host(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(host)) => {
            let normalized = host.trim_end_matches('.');
            !normalized.eq_ignore_ascii_case("localhost")
                && !normalized.to_ascii_lowercase().ends_with(".localhost")
        }
        Some(url::Host::Ipv4(_) | url::Host::Ipv6(_)) | None => false,
    }
}

pub(crate) fn validate_issuer_identifier(value: &str) -> OpenId4VciResult<()> {
    validate_https_url(value, false)?;
    let url = Url::parse(value).map_err(|_| OpenId4VciError::new(Reason::InvalidUrl))?;
    if url.query().is_some() || url.fragment().is_some() {
        return Err(OpenId4VciError::new(Reason::InvalidUrl));
    }
    Ok(())
}

pub(crate) fn is_optional_non_empty(value: &Option<String>) -> OpenId4VciResult<()> {
    if let Some(item) = value {
        validate_non_empty_asciiish(item)?;
    }
    Ok(())
}

pub(crate) fn is_loopback_host(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(host)) => {
            host.trim_end_matches('.').eq_ignore_ascii_case("localhost")
        }
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

pub(crate) fn validate_vec_non_empty(values: &[String]) -> OpenId4VciResult<()> {
    if values.is_empty() {
        return Err(OpenId4VciError::new(Reason::MissingRequiredField));
    }
    for value in values {
        validate_non_empty_asciiish(value)?;
    }
    Ok(())
}

/// Clears string leaves in an owned JSON tree before its allocations are released.
///
/// Object keys describe protocol shape and are intentionally retained; values
/// can contain credentials, presentations, identifiers, and other holder data.
pub(crate) fn zeroize_json_strings(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => text.zeroize(),
        serde_json::Value::Array(values) => {
            for nested in values {
                zeroize_json_strings(nested);
            }
        }
        serde_json::Value::Object(values) => {
            for nested in values.values_mut() {
                zeroize_json_strings(nested);
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}
