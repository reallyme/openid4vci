// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Parse holder launches into bounded, privacy-safe status snapshots.

use core::fmt;

use openid4vci_types::{
    build_credential_offer_uri, parse_credential_offer_uri, CredentialOffer, ParsedCredentialOffer,
};
use reallyme_codec::jcs::canonicalize_trusted_json_value;
use reallyme_openid4vci_wallet::{resolve_credential_offer_uri, WalletStatus};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::form_urlencoded;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    holder_harness_flow_summary::HolderHarnessFlowSummary, respond_holder_harness::Problem,
    HolderHarnessFlowOutcome,
};

const OFFER_URI_BASE: &str = "openid-credential-offer://";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OfferLaunchBody {
    credential_offer_launch_uri: Option<String>,
    credential_offer_uri: Option<String>,
    credential_offer: Option<Value>,
}

impl fmt::Debug for OfferLaunchBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OfferLaunchBody")
            .field(
                "has_credential_offer_launch_uri",
                &self.credential_offer_launch_uri.is_some(),
            )
            .field(
                "has_credential_offer_uri",
                &self.credential_offer_uri.is_some(),
            )
            .field(
                "has_inline_credential_offer",
                &self.credential_offer.is_some(),
            )
            .finish()
    }
}

impl Drop for OfferLaunchBody {
    fn drop(&mut self) {
        self.credential_offer_launch_uri.zeroize();
        self.credential_offer_uri.zeroize();
        if let Some(value) = &mut self.credential_offer {
            zeroize_json_value(value);
        }
    }
}

impl OfferLaunchBody {
    pub(super) fn into_offer_uri(mut self) -> Result<String, Problem> {
        match (
            self.credential_offer_launch_uri.is_some(),
            self.credential_offer_uri.is_some(),
            self.credential_offer.is_some(),
        ) {
            (true, false, false) => self
                .credential_offer_launch_uri
                .take()
                .ok_or(Problem::InvalidRequest),
            (false, true, false) => self
                .credential_offer_uri
                .as_deref()
                .map(reference_offer_uri)
                .ok_or(Problem::InvalidRequest),
            (false, false, true) => {
                let offer = self
                    .credential_offer
                    .as_ref()
                    .ok_or(Problem::InvalidRequest)?;
                let json = Zeroizing::new(
                    canonicalize_trusted_json_value(offer).map_err(|_| Problem::InvalidRequest)?,
                );
                let offer = CredentialOffer::parse_json(json.as_str())
                    .map_err(|_| Problem::InvalidRequest)?;
                let validated_json =
                    Zeroizing::new(offer.to_json().map_err(|_| Problem::InvalidRequest)?);
                build_credential_offer_uri(OFFER_URI_BASE, validated_json.as_str())
                    .map_err(|_| Problem::InvalidRequest)
            }
            _ => Err(Problem::InvalidRequest),
        }
    }
}

fn reference_offer_uri(reference: &str) -> String {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("credential_offer_uri", reference);
    [OFFER_URI_BASE, "?", serializer.finish().as_str()].concat()
}

pub(super) fn parse_offer_launch(launch_uri: &str) -> Result<ParsedHarnessOffer, Problem> {
    match resolve_credential_offer_uri(launch_uri, None) {
        Ok(offer) => Ok(ParsedHarnessOffer::Inline(offer)),
        Err(error) if error.status() == WalletStatus::OfferResolutionRequired => {
            match parse_credential_offer_uri(launch_uri).map_err(|_| Problem::InvalidRequest)? {
                ParsedCredentialOffer::Reference(uri) => Ok(ParsedHarnessOffer::Reference(uri)),
                ParsedCredentialOffer::Inline(offer) => Ok(ParsedHarnessOffer::Inline(offer)),
            }
        }
        Err(_) => Err(Problem::InvalidRequest),
    }
}

pub(super) enum ParsedHarnessOffer {
    Inline(CredentialOffer),
    Reference(String),
}

// `Clone` is limited to the bounded, redacted status snapshot copied out of the
// mutex. The snapshot intentionally retains no grant code or credential value.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub(super) struct OfferRecord {
    session_id: u64,
    status: OfferStatus,
    offer: OfferSummary,
    #[serde(skip_serializing_if = "Option::is_none")]
    flow: Option<HolderHarnessFlowSummary>,
}

impl fmt::Debug for OfferRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OfferRecord")
            .field("session_id", &self.session_id)
            .field("status", &self.status)
            .field("offer", &self.offer)
            .field("has_flow", &self.flow.is_some())
            .finish()
    }
}

impl Zeroize for OfferRecord {
    fn zeroize(&mut self) {
        self.offer.zeroize();
    }
}

impl Drop for OfferRecord {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for OfferRecord {}

impl OfferRecord {
    pub(super) fn from_offer(
        session_id: u64,
        offer: ParsedHarnessOffer,
        flow: Option<HolderHarnessFlowOutcome>,
    ) -> Self {
        let flow = flow.map(HolderHarnessFlowSummary::from_outcome);
        match offer {
            ParsedHarnessOffer::Inline(mut offer) => {
                let credential_configuration_count = offer.credential_configuration_ids.len();
                let authorization_code_grant_present = offer
                    .grants
                    .as_ref()
                    .and_then(|grants| grants.authorization_code.as_ref())
                    .is_some();
                let pre_authorized_code_grant_present = offer
                    .grants
                    .as_ref()
                    .and_then(|grants| grants.pre_authorized_code.as_ref())
                    .is_some();
                Self {
                    session_id,
                    status: OfferStatus::Accepted,
                    offer: OfferSummary::Inline {
                        credential_issuer: core::mem::take(&mut offer.credential_issuer),
                        credential_configuration_count,
                        authorization_code_grant_present,
                        pre_authorized_code_grant_present,
                    },
                    flow,
                }
            }
            ParsedHarnessOffer::Reference(mut reference) => {
                reference.zeroize();
                Self {
                    session_id,
                    status: OfferStatus::ReferenceReceived,
                    offer: OfferSummary::Reference,
                    flow,
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum OfferStatus {
    Accepted,
    ReferenceReceived,
}

// Cloning follows OfferRecord's bounded snapshot semantics and only duplicates
// the validated issuer/reference identifier needed by the control-plane API.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum OfferSummary {
    Inline {
        credential_issuer: String,
        credential_configuration_count: usize,
        authorization_code_grant_present: bool,
        pre_authorized_code_grant_present: bool,
    },
    Reference,
}

impl fmt::Debug for OfferSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inline {
                credential_configuration_count,
                authorization_code_grant_present,
                pre_authorized_code_grant_present,
                ..
            } => formatter
                .debug_struct("InlineOfferSummary")
                .field("credential_issuer", &"<redacted>")
                .field(
                    "credential_configuration_count",
                    credential_configuration_count,
                )
                .field(
                    "authorization_code_grant_present",
                    authorization_code_grant_present,
                )
                .field(
                    "pre_authorized_code_grant_present",
                    pre_authorized_code_grant_present,
                )
                .finish(),
            Self::Reference => formatter.debug_struct("ReferenceOfferSummary").finish(),
        }
    }
}

impl Zeroize for OfferSummary {
    fn zeroize(&mut self) {
        match self {
            Self::Inline {
                credential_issuer, ..
            } => credential_issuer.zeroize(),
            Self::Reference => {}
        }
    }
}

impl Drop for OfferSummary {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for OfferSummary {}

fn zeroize_json_value(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(items) => {
            for item in items {
                zeroize_json_value(item);
            }
        }
        Value::Object(entries) => {
            let owned = core::mem::take(entries);
            for (mut key, mut item) in owned {
                key.zeroize();
                zeroize_json_value(&mut item);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

#[path = "tests/verify_holder_offer_redaction_tests.rs"]
#[cfg(test)]
mod verify_holder_offer_redaction_tests;
