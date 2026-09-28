// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Dedicated Nonce Endpoint types from OpenID4VCI 1.0 final.

use core::fmt::{Debug, Formatter};

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::error::OpenId4VciResult;
use crate::validation::{parse_json, to_json, validate_non_empty_asciiish, CLOSED_OPERATION_JSON};

/// Empty Nonce Endpoint request marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NonceRequest {}

/// Nonce Endpoint response.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NonceResponse {
    /// Challenge to be incorporated into credential key proofs.
    pub c_nonce: String,
}

impl Debug for NonceResponse {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("NonceResponse")
            .field("c_nonce", &"<redacted>")
            .finish()
    }
}

impl Drop for NonceResponse {
    fn drop(&mut self) {
        self.c_nonce.zeroize();
    }
}

impl NonceResponse {
    /// Creates a validated nonce response.
    pub fn new(c_nonce: String) -> OpenId4VciResult<Self> {
        let response = Self { c_nonce };
        response.validate()?;
        Ok(response)
    }

    /// Parses and validates a nonce response JSON body.
    pub fn parse_json(body: &str) -> OpenId4VciResult<Self> {
        let response: Self = parse_json(body, CLOSED_OPERATION_JSON)?;
        response.validate()?;
        Ok(response)
    }

    /// Serializes a validated nonce response.
    pub fn to_json(&self) -> OpenId4VciResult<String> {
        self.validate()?;
        to_json(self)
    }

    /// Validates the nonce value.
    pub fn validate(&self) -> OpenId4VciResult<()> {
        validate_non_empty_asciiish(&self.c_nonce)
    }
}
