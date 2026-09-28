// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! HAIP authorization-server composition policy tests.

#![cfg(feature = "axum")]

use openid4vci_http::{AxumIssuerError, AxumIssuerState};

#[path = "support/exercise_axum_issuer.rs"]
mod exercise_axum_issuer;

use exercise_axum_issuer::{haip_baseline_parts, RouteTestError};

#[test]
fn router_accepts_complete_haip_authorization_server_contract() -> Result<(), RouteTestError> {
    assert!(AxumIssuerState::new(haip_baseline_parts()?).is_ok());
    Ok(())
}

#[test]
fn router_rejects_haip_metadata_without_each_mandatory_oauth_control() -> Result<(), RouteTestError>
{
    let mut missing_code_grant = haip_baseline_parts()?;
    if let Some(metadata) = &mut missing_code_grant.authorization_server_metadata {
        metadata.grant_types_supported = None;
    }
    assert_eq!(
        AxumIssuerState::new(missing_code_grant).err(),
        Some(AxumIssuerError::UnsatisfiedSecurityPolicy)
    );

    let mut missing_pkce = haip_baseline_parts()?;
    if let Some(metadata) = &mut missing_pkce.authorization_server_metadata {
        metadata.code_challenge_methods_supported = None;
    }
    assert_eq!(
        AxumIssuerState::new(missing_pkce).err(),
        Some(AxumIssuerError::UnsatisfiedSecurityPolicy)
    );

    let mut missing_issuer = haip_baseline_parts()?;
    if let Some(metadata) = &mut missing_issuer.authorization_server_metadata {
        metadata.authorization_response_iss_parameter_supported = None;
    }
    assert_eq!(
        AxumIssuerState::new(missing_issuer).err(),
        Some(AxumIssuerError::UnsatisfiedSecurityPolicy)
    );

    let mut missing_client_authentication = haip_baseline_parts()?;
    if let Some(metadata) = &mut missing_client_authentication.authorization_server_metadata {
        metadata.token_endpoint_auth_methods_supported = Some(vec!["none".to_owned()]);
    }
    assert_eq!(
        AxumIssuerState::new(missing_client_authentication).err(),
        Some(AxumIssuerError::UnsatisfiedSecurityPolicy)
    );
    Ok(())
}
