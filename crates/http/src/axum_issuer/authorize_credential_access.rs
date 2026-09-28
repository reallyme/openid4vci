// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Binds protected Credential Requests to access-token authorization.

use openid4vci_types::CredentialSelector;

use crate::serve_oauth::{OAuthHttpError, OAuthHttpErrorReason, OAuthHttpResult};
use crate::validate_access_token::CredentialAuthorizationDecision;

use super::configure::AxumIssuerState;

/// Enforces the required resource-server authorization boundary.
///
/// The validator is mandatory whether the Authorization Server is co-located
/// or external, so no router configuration can silently skip selector checks.
pub(crate) fn authorize_credential_access(
    state: &AxumIssuerState,
    access_token: Option<&str>,
    selector: &CredentialSelector,
) -> OAuthHttpResult<CredentialAuthorizationDecision> {
    let token =
        access_token.ok_or_else(|| OAuthHttpError::new(OAuthHttpErrorReason::InvalidDpopProof))?;
    state
        .access_token_validator
        .authorize_credential_request(token, selector)
}
