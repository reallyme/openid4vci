// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Credential Offer types and URI helpers.

use core::fmt::{Debug, Formatter};

use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, CONTROLS};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{OpenId4VciError, OpenId4VciResult, Reason};
use crate::validation::{
    parse_json, to_json, validate_https_url, validate_issuer_identifier,
    validate_non_empty_asciiish, validate_vec_non_empty, EXTENSIBLE_DOCUMENT_JSON,
};

/// Default custom URL scheme for inline or referenced Credential Offers.
pub const DEFAULT_CREDENTIAL_OFFER_SCHEME: &str = "openid-credential-offer://";

/// Maximum accepted Credential Offer URI size before percent-decoding.
pub const MAX_CREDENTIAL_OFFER_URI_BYTES: usize = 65_536;

/// Maximum length of a `tx_code` description (OpenID4VCI 1.0 §4.1.1).
const TX_CODE_DESCRIPTION_MAX_CHARS: usize = 300;

const QUERY_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'&')
    .add(b'+')
    .add(b',')
    .add(b'/')
    .add(b':')
    .add(b';')
    .add(b'<')
    .add(b'=')
    .add(b'>')
    .add(b'?')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

/// Credential Offer document.
#[derive(Serialize, Deserialize)]
pub struct CredentialOffer {
    /// Credential Issuer Identifier.
    pub credential_issuer: String,
    /// Credential configurations offered by this issuer interaction.
    pub credential_configuration_ids: Vec<String>,
    /// Optional grant configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grants: Option<CredentialOfferGrant>,
}

impl Debug for CredentialOffer {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CredentialOffer")
            .field("credential_issuer", &self.credential_issuer)
            .field(
                "credential_configuration_count",
                &self.credential_configuration_ids.len(),
            )
            .field("grants", &self.grants)
            .finish()
    }
}

impl Drop for CredentialOffer {
    fn drop(&mut self) {
        self.credential_issuer.zeroize();
        self.credential_configuration_ids.zeroize();
    }
}

impl CredentialOffer {
    /// Builds an authorization-code offer.
    pub fn authorization_code(
        credential_issuer: String,
        credential_configuration_ids: Vec<String>,
        issuer_state: Option<String>,
    ) -> OpenId4VciResult<Self> {
        let offer = Self {
            credential_issuer,
            credential_configuration_ids,
            grants: Some(CredentialOfferGrant {
                authorization_code: Some(AuthorizationCodeGrant {
                    issuer_state,
                    authorization_server: None,
                }),
                pre_authorized_code: None,
            }),
        };
        offer.validate()?;
        Ok(offer)
    }

    /// Builds a pre-authorized-code offer using the final `tx_code` object.
    pub fn pre_authorized_code(
        credential_issuer: String,
        credential_configuration_ids: Vec<String>,
        pre_authorized_code: String,
        tx_code: Option<TxCode>,
    ) -> OpenId4VciResult<Self> {
        let offer = Self {
            credential_issuer,
            credential_configuration_ids,
            grants: Some(CredentialOfferGrant {
                authorization_code: None,
                pre_authorized_code: Some(PreAuthorizedCodeGrant {
                    pre_authorized_code,
                    tx_code,
                    authorization_server: None,
                }),
            }),
        };
        offer.validate()?;
        Ok(offer)
    }

    /// Parses and validates a Credential Offer JSON document.
    pub fn parse_json(body: &str) -> OpenId4VciResult<Self> {
        let offer: Self = parse_json(body, EXTENSIBLE_DOCUMENT_JSON)?;
        offer.validate()?;
        Ok(offer)
    }

    /// Serializes a validated Credential Offer.
    pub fn to_json(&self) -> OpenId4VciResult<String> {
        self.validate()?;
        to_json(self)
    }

    /// Wraps the offer as an inline Credential Offer URI.
    pub fn to_uri(&self) -> OpenId4VciResult<String> {
        let json = Zeroizing::new(self.to_json()?);
        build_credential_offer_uri(DEFAULT_CREDENTIAL_OFFER_SCHEME, &json)
    }

    /// Validates final-spec Credential Offer shape.
    pub fn validate(&self) -> OpenId4VciResult<()> {
        // OpenID4VCI 1.0 §12.2.1: the Credential Issuer Identifier is an https
        // URL with no query or fragment components.
        validate_issuer_identifier(&self.credential_issuer)?;
        validate_vec_non_empty(&self.credential_configuration_ids)?;
        if let Some(grants) = &self.grants {
            grants.validate()?;
        }
        Ok(())
    }
}

/// Grant configuration object inside a Credential Offer.
#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialOfferGrant {
    /// Authorization Code grant parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_code: Option<AuthorizationCodeGrant>,
    /// Pre-Authorized Code grant parameters.
    #[serde(
        rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        skip_serializing_if = "Option::is_none"
    )]
    pub pre_authorized_code: Option<PreAuthorizedCodeGrant>,
}

impl CredentialOfferGrant {
    /// Validates grant shape.
    pub fn validate(&self) -> OpenId4VciResult<()> {
        if let Some(grant) = &self.authorization_code {
            grant.validate()?;
        }
        if let Some(grant) = &self.pre_authorized_code {
            grant.validate()?;
        }
        Ok(())
    }
}

/// Authorization Code grant parameters.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationCodeGrant {
    /// Opaque issuer state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_state: Option<String>,
    /// Optional authorization server hint for multi-AS issuers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_server: Option<String>,
}

impl Debug for AuthorizationCodeGrant {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AuthorizationCodeGrant")
            .field(
                "issuer_state",
                &self.issuer_state.as_ref().map(|_| "<redacted>"),
            )
            .field("authorization_server", &self.authorization_server)
            .finish()
    }
}

impl Drop for AuthorizationCodeGrant {
    fn drop(&mut self) {
        self.issuer_state.zeroize();
        self.authorization_server.zeroize();
    }
}

impl AuthorizationCodeGrant {
    /// Validates the grant parameters.
    pub fn validate(&self) -> OpenId4VciResult<()> {
        if let Some(issuer_state) = &self.issuer_state {
            validate_non_empty_asciiish(issuer_state)?;
        }
        if let Some(authorization_server) = &self.authorization_server {
            validate_issuer_identifier(authorization_server)?;
        }
        Ok(())
    }
}

/// Pre-Authorized Code grant parameters.
///
/// Serialization and deserialization are intentional protocol boundaries:
/// the bearer code must be received in and emitted as a Credential Offer. The
/// type deliberately does not implement `Clone`, `Copy`, or equality, and its
/// custom `Debug` plus `Drop` implementations prevent incidental disclosure
/// and zeroize the owned wire value.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreAuthorizedCodeGrant {
    /// Opaque code issued before the OAuth token exchange.
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,
    /// Optional final-spec transaction-code description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_code: Option<TxCode>,
    /// Optional authorization server hint for multi-AS issuers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_server: Option<String>,
}

impl Debug for PreAuthorizedCodeGrant {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PreAuthorizedCodeGrant")
            .field("pre_authorized_code", &"<redacted>")
            .field("tx_code", &self.tx_code)
            .field("authorization_server", &self.authorization_server)
            .finish()
    }
}

impl Drop for PreAuthorizedCodeGrant {
    fn drop(&mut self) {
        self.pre_authorized_code.zeroize();
        self.authorization_server.zeroize();
    }
}

impl PreAuthorizedCodeGrant {
    /// Validates the grant parameters.
    pub fn validate(&self) -> OpenId4VciResult<()> {
        validate_non_empty_asciiish(&self.pre_authorized_code)?;
        if let Some(tx_code) = &self.tx_code {
            tx_code.validate()?;
        }
        if let Some(authorization_server) = &self.authorization_server {
            validate_issuer_identifier(authorization_server)?;
        }
        Ok(())
    }
}

/// Transaction-code input mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TxCodeInputMode {
    /// Numeric transaction code.
    Numeric,
    /// Text transaction code.
    Text,
}

/// Transaction-code metadata replacing draft `user_pin`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TxCode {
    /// Optional user input mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_mode: Option<TxCodeInputMode>,
    /// Optional expected code length.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<u64>,
    /// Optional ASCII description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl Debug for TxCode {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("TxCode")
            .field("input_mode", &self.input_mode)
            .field("length", &self.length)
            .field(
                "description",
                &self.description.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl Drop for TxCode {
    fn drop(&mut self) {
        self.description.zeroize();
    }
}

impl TxCode {
    /// Validates transaction-code metadata.
    pub fn validate(&self) -> OpenId4VciResult<()> {
        if matches!(self.length, Some(0)) {
            return Err(OpenId4VciError::new(Reason::InvalidString));
        }
        if let Some(description) = &self.description {
            validate_non_empty_asciiish(description)?;
            // OpenID4VCI 1.0 §4.1.1: the tx_code description MUST NOT exceed 300 characters.
            if description.chars().count() > TX_CODE_DESCRIPTION_MAX_CHARS {
                return Err(OpenId4VciError::new(Reason::InvalidString));
            }
        }
        Ok(())
    }
}

/// Parsed Credential Offer URI payload.
pub enum ParsedCredentialOffer {
    /// Inline `credential_offer` JSON value.
    Inline(CredentialOffer),
    /// Referenced `credential_offer_uri`.
    Reference(String),
}

impl Debug for ParsedCredentialOffer {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Inline(_) => formatter.write_str("Inline(<redacted>)"),
            Self::Reference(_) => formatter.write_str("Reference(<redacted>)"),
        }
    }
}

/// Builds an inline Credential Offer URI.
pub fn build_credential_offer_uri(base: &str, offer_json: &str) -> OpenId4VciResult<String> {
    validate_non_empty_asciiish(base)?;
    validate_non_empty_asciiish(offer_json)?;
    let separator = if base.contains('?') { "&" } else { "?" };
    let encoded = Zeroizing::new(utf8_percent_encode(offer_json, QUERY_ENCODE_SET).to_string());
    let uri = [base, separator, "credential_offer=", encoded.as_str()].concat();
    if uri.len() > MAX_CREDENTIAL_OFFER_URI_BYTES {
        return Err(OpenId4VciError::new(Reason::InvalidUrl));
    }
    Ok(uri)
}

/// Builds a referenced Credential Offer URI without reinterpreting separators
/// or fragments contained in the referenced HTTPS URL.
pub fn build_credential_offer_reference_uri(
    base: &str,
    referenced_offer_uri: &str,
) -> OpenId4VciResult<String> {
    validate_non_empty_asciiish(base)?;
    validate_https_url(referenced_offer_uri, false)?;
    let separator = if base.contains('?') { "&" } else { "?" };
    let encoded =
        Zeroizing::new(utf8_percent_encode(referenced_offer_uri, QUERY_ENCODE_SET).to_string());
    let uri = [base, separator, "credential_offer_uri=", encoded.as_str()].concat();
    if uri.len() > MAX_CREDENTIAL_OFFER_URI_BYTES {
        return Err(OpenId4VciError::new(Reason::InvalidUrl));
    }
    Ok(uri)
}

/// Parses an OpenID4VCI Credential Offer URI.
pub fn parse_credential_offer_uri(uri: &str) -> OpenId4VciResult<ParsedCredentialOffer> {
    if uri.len() > MAX_CREDENTIAL_OFFER_URI_BYTES {
        return Err(OpenId4VciError::new(Reason::InvalidUrl));
    }
    validate_non_empty_asciiish(uri)?;
    let inline_count = query_param_count(uri, "credential_offer");
    let reference_count = query_param_count(uri, "credential_offer_uri");
    match (inline_count, reference_count) {
        (1, 0) => {
            if let Some(value) = query_param(uri, "credential_offer") {
                let value = Zeroizing::new(value);
                let offer = CredentialOffer::parse_json(&value)?;
                return Ok(ParsedCredentialOffer::Inline(offer));
            }
        }
        (0, 1) => {
            if let Some(value) = query_param(uri, "credential_offer_uri") {
                validate_https_url(&value, false)?;
                return Ok(ParsedCredentialOffer::Reference(value));
            }
        }
        (0, 0) => return Err(OpenId4VciError::new(Reason::MissingRequiredField)),
        _ => return Err(OpenId4VciError::new(Reason::InvalidUrl)),
    }
    Err(OpenId4VciError::new(Reason::InvalidUrl))
}

fn query_param_count(uri: &str, key: &str) -> usize {
    let Some((_, query)) = uri.split_once('?') else {
        return 0;
    };
    let mut count = 0_usize;
    for part in query.split('&') {
        let (candidate_key, _) = match part.split_once('=') {
            Some(pair) => pair,
            None => (part, ""),
        };
        if candidate_key == key {
            if let Some(next) = count.checked_add(1) {
                count = next;
            }
        }
    }
    count
}

fn query_param(uri: &str, key: &str) -> Option<String> {
    let (_, query) = uri.split_once('?')?;
    for part in query.split('&') {
        let (candidate_key, raw_value) = match part.split_once('=') {
            Some(pair) => pair,
            None => (part, ""),
        };
        if candidate_key != key {
            continue;
        }
        let form_compatible = Zeroizing::new(raw_value.replace('+', " "));
        let decoded = percent_decode_str(&form_compatible).decode_utf8().ok()?;
        return Some(decoded.into_owned());
    }
    None
}
