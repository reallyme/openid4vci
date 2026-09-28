// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Security capabilities declared by an OAuth Authorization Server provider.

/// Service boundary capabilities checked when composing high-assurance routes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OAuthAuthorizationServerCapabilities {
    dpop_sender_constraint: bool,
    client_authentication: bool,
    pushed_authorization_requests: bool,
    authorization_code_grant: bool,
    pkce_s256: bool,
    authorization_response_issuer: bool,
}

impl OAuthAuthorizationServerCapabilities {
    /// Declares an OAuth service without high-assurance guarantees.
    #[must_use]
    pub const fn interoperability() -> Self {
        Self {
            dpop_sender_constraint: false,
            client_authentication: false,
            pushed_authorization_requests: false,
            authorization_code_grant: false,
            pkce_s256: false,
            authorization_response_issuer: false,
        }
    }

    /// Declares that the provider enforces the HAIP-relevant OAuth controls.
    #[must_use]
    pub const fn high_assurance() -> Self {
        Self {
            dpop_sender_constraint: true,
            client_authentication: true,
            pushed_authorization_requests: true,
            authorization_code_grant: true,
            pkce_s256: true,
            authorization_response_issuer: true,
        }
    }

    pub(crate) const fn satisfies(
        self,
        require_dpop: bool,
        require_client_authentication: bool,
        require_par: bool,
        require_authorization_code_grant: bool,
        require_pkce_s256: bool,
        require_authorization_response_issuer: bool,
    ) -> bool {
        (!require_dpop || self.dpop_sender_constraint)
            && (!require_client_authentication || self.client_authentication)
            && (!require_par || self.pushed_authorization_requests)
            && (!require_authorization_code_grant || self.authorization_code_grant)
            && (!require_pkce_s256 || self.pkce_s256)
            && (!require_authorization_response_issuer || self.authorization_response_issuer)
    }
}
