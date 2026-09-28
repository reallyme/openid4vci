// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed credential authorization carried through the example OAuth flow.

use openid4vci_http::{OAuthHttpError, OAuthHttpErrorReason, OAuthHttpResult, OAuthParameters};
use openid4vci_types::CredentialSelector;
use serde_json::{json, Value};

use super::mdoc::{PID_MDOC_CONFIGURATION_ID, PID_MDOC_CREDENTIAL_IDENTIFIER};

const PID_SD_JWT_CONFIGURATION_ID: &str = "pid";
const PID_SD_JWT_CREDENTIAL_IDENTIFIER: &str = "pid-credential-1";
const OPENID_SCOPE: &str = "openid";
const OPENID_CREDENTIAL_AUTHORIZATION_TYPE: &str = "openid_credential";
const MAX_AUTHORIZATION_DETAILS: usize = 8;

/// Credential configurations authorized by this composed issuer deployment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CredentialAuthorization {
    SdJwtPid,
    MdocPid,
}

/// Stable selector-resolution outcomes shared by issuance and authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CredentialSelectorResolutionError {
    UnknownConfiguration,
    UnknownIdentifier,
}

impl CredentialAuthorization {
    pub(super) fn from_parameters(parameters: &OAuthParameters) -> OAuthHttpResult<Vec<Self>> {
        if let Some(details) = parameters.get("authorization_details") {
            return parse_authorization_details(details);
        }
        parse_scope(
            parameters
                .get("scope")
                .map(String::as_str)
                .ok_or_else(invalid_request)?,
        )
    }

    pub(super) const fn configuration_id(self) -> &'static str {
        match self {
            Self::SdJwtPid => PID_SD_JWT_CONFIGURATION_ID,
            Self::MdocPid => PID_MDOC_CONFIGURATION_ID,
        }
    }

    pub(super) fn from_selector(
        selector: &CredentialSelector,
    ) -> Result<Self, CredentialSelectorResolutionError> {
        match selector {
            CredentialSelector::ConfigurationId(value) => match value.as_str() {
                PID_SD_JWT_CONFIGURATION_ID => Ok(Self::SdJwtPid),
                PID_MDOC_CONFIGURATION_ID => Ok(Self::MdocPid),
                _ => Err(CredentialSelectorResolutionError::UnknownConfiguration),
            },
            CredentialSelector::CredentialIdentifier(value) => match value.as_str() {
                PID_SD_JWT_CREDENTIAL_IDENTIFIER => Ok(Self::SdJwtPid),
                PID_MDOC_CREDENTIAL_IDENTIFIER => Ok(Self::MdocPid),
                _ => Err(CredentialSelectorResolutionError::UnknownIdentifier),
            },
        }
    }

    const fn credential_identifier(self) -> &'static str {
        match self {
            Self::SdJwtPid => PID_SD_JWT_CREDENTIAL_IDENTIFIER,
            Self::MdocPid => PID_MDOC_CREDENTIAL_IDENTIFIER,
        }
    }

    pub(super) fn response_detail(self, credential_issuer: &str) -> Value {
        json!({
            "type": OPENID_CREDENTIAL_AUTHORIZATION_TYPE,
            "credential_configuration_id": self.configuration_id(),
            "credential_identifiers": [self.credential_identifier()],
            "locations": [credential_issuer]
        })
    }
}

fn parse_scope(scope: &str) -> OAuthHttpResult<Vec<CredentialAuthorization>> {
    let mut authorizations = Vec::new();
    for value in scope.split_ascii_whitespace() {
        let authorization = match value {
            PID_SD_JWT_CONFIGURATION_ID => Some(CredentialAuthorization::SdJwtPid),
            PID_MDOC_CONFIGURATION_ID => Some(CredentialAuthorization::MdocPid),
            OPENID_SCOPE => None,
            _ => return Err(invalid_request()),
        };
        if let Some(authorization) = authorization {
            push_distinct(&mut authorizations, authorization)?;
        }
    }
    require_authorization(authorizations)
}

fn parse_authorization_details(raw: &str) -> OAuthHttpResult<Vec<CredentialAuthorization>> {
    let details = serde_json::from_str::<Value>(raw).map_err(|_| invalid_request())?;
    let entries = details.as_array().ok_or_else(invalid_request)?;
    if entries.is_empty() || entries.len() > MAX_AUTHORIZATION_DETAILS {
        return Err(invalid_request());
    }

    let mut authorizations = Vec::new();
    for entry in entries {
        let object = entry.as_object().ok_or_else(invalid_request)?;
        if object.get("type").and_then(Value::as_str) != Some(OPENID_CREDENTIAL_AUTHORIZATION_TYPE)
        {
            return Err(invalid_request());
        }
        let configuration_id = object
            .get("credential_configuration_id")
            .and_then(Value::as_str)
            .ok_or_else(invalid_request)?;
        let authorization = match configuration_id {
            PID_SD_JWT_CONFIGURATION_ID => CredentialAuthorization::SdJwtPid,
            PID_MDOC_CONFIGURATION_ID => CredentialAuthorization::MdocPid,
            _ => return Err(invalid_request()),
        };
        push_distinct(&mut authorizations, authorization)?;
    }
    require_authorization(authorizations)
}

fn push_distinct(
    authorizations: &mut Vec<CredentialAuthorization>,
    authorization: CredentialAuthorization,
) -> OAuthHttpResult<()> {
    if authorizations.contains(&authorization) {
        return Err(invalid_request());
    }
    authorizations.push(authorization);
    Ok(())
}

fn require_authorization(
    authorizations: Vec<CredentialAuthorization>,
) -> OAuthHttpResult<Vec<CredentialAuthorization>> {
    if authorizations.is_empty() {
        Err(invalid_request())
    } else {
        Ok(authorizations)
    }
}

fn invalid_request() -> OAuthHttpError {
    OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequest)
}
