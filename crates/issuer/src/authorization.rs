// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Validated access-token authorization passed into issuance providers.

use zeroize::Zeroizing;

use crate::error::{IssuerError, IssuerResult, IssuerStatus};

const MAX_AUTHORIZATION_SUBJECT_HANDLE_BYTES: usize = 4_096;

/// Validated authorization material that binds issuance to the approved
/// subject/grant without exposing the bearer access token to an issuer.
pub struct IssuanceAuthorization {
    credential_configuration_id: String,
    subject_handle: Zeroizing<String>,
    client_id: Option<Zeroizing<String>>,
    rate_limit_partition: [u8; 32],
}

impl IssuanceAuthorization {
    /// Constructs an authorization context after token/grant validation.
    pub fn new(
        credential_configuration_id: String,
        subject_handle: String,
        rate_limit_partition: [u8; 32],
    ) -> IssuerResult<Self> {
        if credential_configuration_id.is_empty()
            || subject_handle.is_empty()
            || subject_handle.len() > MAX_AUTHORIZATION_SUBJECT_HANDLE_BYTES
            || subject_handle.chars().any(char::is_control)
        {
            return Err(IssuerError::new(IssuerStatus::InvalidRequest));
        }
        Ok(Self {
            credential_configuration_id,
            subject_handle: Zeroizing::new(subject_handle),
            client_id: None,
            rate_limit_partition,
        })
    }

    /// Binds a non-anonymous grant to its OAuth client identifier.
    ///
    /// Proof JWT `iss` remains optional, but when a wallet supplies it the
    /// final specification requires it to equal this identifier. Anonymous
    /// pre-authorized grants intentionally leave this field unset.
    pub fn with_client_id(mut self, client_id: String) -> IssuerResult<Self> {
        if client_id.is_empty()
            || client_id.len() > MAX_AUTHORIZATION_SUBJECT_HANDLE_BYTES
            || client_id.chars().any(char::is_control)
        {
            return Err(IssuerError::new(IssuerStatus::InvalidRequest));
        }
        self.client_id = Some(Zeroizing::new(client_id));
        Ok(self)
    }

    /// Returns the configuration approved by the access-token grant.
    #[must_use]
    pub fn credential_configuration_id(&self) -> &str {
        &self.credential_configuration_id
    }

    /// Returns the host-defined opaque subject/grant handle.
    #[must_use]
    pub fn subject_handle(&self) -> &str {
        self.subject_handle.as_str()
    }

    /// Returns the authenticated OAuth client identifier, when the grant is
    /// not an anonymous pre-authorized flow.
    #[must_use]
    pub fn client_id(&self) -> Option<&str> {
        self.client_id.as_deref().map(String::as_str)
    }

    pub(crate) const fn rate_limit_partition(&self) -> &[u8; 32] {
        &self.rate_limit_partition
    }
}
