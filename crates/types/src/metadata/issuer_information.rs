// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Credential Issuer display and profile-defined information metadata.

use core::fmt;
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use url::Url;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{OpenId4VciError, OpenId4VciResult, Reason};
use crate::validation::{is_optional_non_empty, validate_non_empty_asciiish, zeroize_json_strings};

/// Localized display properties for a Credential Issuer.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuerDisplay {
    /// Human-readable issuer name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// BCP 47 language tag for this display entry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    /// Issuer logo metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo: Option<IssuerLogo>,
}

/// Credential Issuer logo metadata.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuerLogo {
    /// URI from which the Wallet can obtain the logo.
    pub uri: String,
    /// Accessible alternative text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alt_text: Option<String>,
}

/// Extensible issuer-information entry used by ETSI issuance profiles.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct IssuerInformation {
    /// Profile-defined information format identifier.
    pub format: String,
    /// Profile-defined information value retained without reinterpretation.
    pub data: serde_json::Value,
}

// These wire models deliberately support cloning and serialization for protocol
// transport. Each clone owns its allocations and clears sensitive values on drop;
// debug output never exposes profile-defined registrar or display data.
impl fmt::Debug for IssuerDisplay {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IssuerDisplay([REDACTED])")
    }
}

impl fmt::Debug for IssuerLogo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IssuerLogo([REDACTED])")
    }
}

impl fmt::Debug for IssuerInformation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IssuerInformation([REDACTED])")
    }
}

impl Zeroize for IssuerDisplay {
    fn zeroize(&mut self) {
        self.name.zeroize();
        self.locale.zeroize();
        self.logo.zeroize();
    }
}

impl Zeroize for IssuerLogo {
    fn zeroize(&mut self) {
        self.uri.zeroize();
        self.alt_text.zeroize();
    }
}

impl Zeroize for IssuerInformation {
    fn zeroize(&mut self) {
        self.format.zeroize();
        zeroize_json_strings(&mut self.data);
        self.data = serde_json::Value::Null;
    }
}

impl Drop for IssuerDisplay {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Drop for IssuerLogo {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Drop for IssuerInformation {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for IssuerDisplay {}
impl ZeroizeOnDrop for IssuerLogo {}
impl ZeroizeOnDrop for IssuerInformation {}

pub(super) fn validate_issuer_display(
    display: &Option<Vec<IssuerDisplay>>,
) -> OpenId4VciResult<()> {
    let Some(display) = display else {
        return Ok(());
    };
    if display.is_empty() {
        return Err(OpenId4VciError::new(Reason::MissingRequiredField));
    }
    let mut locales = BTreeSet::new();
    for entry in display {
        is_optional_non_empty(&entry.name)?;
        is_optional_non_empty(&entry.locale)?;
        if let Some(locale) = &entry.locale {
            if !locales.insert(locale.to_ascii_lowercase()) {
                return Err(OpenId4VciError::new(Reason::InvalidString));
            }
        }
        if let Some(logo) = &entry.logo {
            validate_non_empty_asciiish(&logo.uri)?;
            let parsed =
                Url::parse(&logo.uri).map_err(|_| OpenId4VciError::new(Reason::InvalidUrl))?;
            if !parsed.username().is_empty() || parsed.password().is_some() {
                return Err(OpenId4VciError::new(Reason::InvalidUrl));
            }
            is_optional_non_empty(&logo.alt_text)?;
        }
    }
    Ok(())
}

pub(super) fn validate_issuer_information(
    issuer_information: &Option<Vec<IssuerInformation>>,
) -> OpenId4VciResult<()> {
    let Some(issuer_information) = issuer_information else {
        return Ok(());
    };
    if issuer_information.is_empty() {
        return Err(OpenId4VciError::new(Reason::MissingRequiredField));
    }
    for entry in issuer_information {
        validate_non_empty_asciiish(&entry.format)?;
        if entry.data.is_null() {
            return Err(OpenId4VciError::new(Reason::MissingRequiredField));
        }
    }
    Ok(())
}
