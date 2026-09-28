// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Maps OpenID4VCI HTTP boundary errors to local protobuf reason codes.
//!
//! The HTTP crate is an adapter boundary, so it is the right place to translate
//! transport and conformance-harness failures into the repo-local OpenID4VCI
//! reason enum. Core protocol crates remain independent of generated protobuf.

use openid4vci_proto::generated::proto::reallyme::openid4vci::v1 as pb;
use openid4vci_proto_codec::convert::ProtoError;
use openid4vci_proto_codec::map_error_reason::{
    error_reason_from_identity_stack_error, identity_stack_error_from_reason,
};
use reallyme_ssi_proto::generated::proto::reallyme::identity::common::v1::IdentityStackError;

#[cfg(feature = "axum-holder-harness")]
use crate::HolderHarnessError;
#[cfg(feature = "holder-harness")]
use crate::HolderHarnessFlowErrorReason;
#[cfg(feature = "axum")]
use crate::{AxumIssuerError, OAuthHttpErrorReason};

/// Convert axum issuer construction failures into the local OpenID4VCI reason enum.
#[cfg(feature = "axum")]
#[must_use]
pub fn axum_issuer_error_to_proto(value: AxumIssuerError) -> pb::OpenId4VciErrorReason {
    match value {
        AxumIssuerError::InvalidMetadata
        | AxumIssuerError::InvalidCredentialPolicy
        | AxumIssuerError::InvalidMountPath => pb::OpenId4VciErrorReason::HttpInvalidMetadata,
        AxumIssuerError::InvalidBodyLimit => pb::OpenId4VciErrorReason::HttpInvalidBodyLimit,
        AxumIssuerError::MissingSecurityVerifier | AxumIssuerError::UnsatisfiedSecurityPolicy => {
            pb::OpenId4VciErrorReason::HttpMissingSecurityVerifier
        }
    }
}

/// Convert OAuth authorization-server adapter failures into the local OpenID4VCI reason enum.
#[cfg(feature = "axum")]
#[must_use]
pub fn oauth_http_error_reason_to_proto(value: OAuthHttpErrorReason) -> pb::OpenId4VciErrorReason {
    match value {
        OAuthHttpErrorReason::AuthorizationServerUnavailable => {
            pb::OpenId4VciErrorReason::OauthAuthorizationServerUnavailable
        }
        OAuthHttpErrorReason::InvalidRequest => pb::OpenId4VciErrorReason::OauthInvalidRequest,
        OAuthHttpErrorReason::InvalidGrant => pb::OpenId4VciErrorReason::OauthInvalidGrant,
        OAuthHttpErrorReason::InvalidClient => pb::OpenId4VciErrorReason::OauthInvalidClient,
        OAuthHttpErrorReason::InvalidPushedAuthorizationRequest => {
            pb::OpenId4VciErrorReason::OauthInvalidPushedAuthorizationRequest
        }
        OAuthHttpErrorReason::InvalidDpopProof => pb::OpenId4VciErrorReason::OauthInvalidDpopProof,
        OAuthHttpErrorReason::InvalidRequestUri => {
            pb::OpenId4VciErrorReason::OauthInvalidRequestUri
        }
        OAuthHttpErrorReason::InsufficientAuthorization => {
            pb::OpenId4VciErrorReason::OauthInsufficientAuthorization
        }
    }
}

/// Convert a local OpenID4VCI reason back to an OAuth authorization-server adapter reason.
#[cfg(feature = "axum")]
pub fn proto_to_oauth_http_error_reason(
    value: pb::OpenId4VciErrorReason,
) -> Result<OAuthHttpErrorReason, ProtoError> {
    match value {
        pb::OpenId4VciErrorReason::OauthAuthorizationServerUnavailable => {
            Ok(OAuthHttpErrorReason::AuthorizationServerUnavailable)
        }
        pb::OpenId4VciErrorReason::OauthInvalidRequest => Ok(OAuthHttpErrorReason::InvalidRequest),
        pb::OpenId4VciErrorReason::OauthInvalidGrant => Ok(OAuthHttpErrorReason::InvalidGrant),
        pb::OpenId4VciErrorReason::OauthInvalidClient => Ok(OAuthHttpErrorReason::InvalidClient),
        pb::OpenId4VciErrorReason::OauthInvalidPushedAuthorizationRequest => {
            Ok(OAuthHttpErrorReason::InvalidPushedAuthorizationRequest)
        }
        pb::OpenId4VciErrorReason::OauthInvalidDpopProof => {
            Ok(OAuthHttpErrorReason::InvalidDpopProof)
        }
        pb::OpenId4VciErrorReason::OauthInvalidRequestUri => {
            Ok(OAuthHttpErrorReason::InvalidRequestUri)
        }
        pb::OpenId4VciErrorReason::OauthInsufficientAuthorization => {
            Ok(OAuthHttpErrorReason::InsufficientAuthorization)
        }
        _ => Err(ProtoError::InvalidEnum),
    }
}

/// Convert holder harness construction errors into the local OpenID4VCI reason enum.
#[cfg(feature = "axum-holder-harness")]
#[must_use]
pub fn holder_harness_error_to_proto(value: HolderHarnessError) -> pb::OpenId4VciErrorReason {
    match value {
        HolderHarnessError::InvalidBodyLimit => pb::OpenId4VciErrorReason::HttpInvalidBodyLimit,
    }
}

/// Convert holder harness driver failures into the local OpenID4VCI reason enum.
#[cfg(feature = "holder-harness")]
#[must_use]
pub fn holder_harness_flow_error_reason_to_proto(
    value: HolderHarnessFlowErrorReason,
) -> pb::OpenId4VciErrorReason {
    match value {
        HolderHarnessFlowErrorReason::LaunchRejected => {
            pb::OpenId4VciErrorReason::HttpWalletFlowLaunchRejected
        }
        HolderHarnessFlowErrorReason::WalletAttestationUnavailable => {
            pb::OpenId4VciErrorReason::HttpWalletAttestationUnavailable
        }
        HolderHarnessFlowErrorReason::TokenExchangeFailed => {
            pb::OpenId4VciErrorReason::HttpTokenExchangeFailed
        }
        HolderHarnessFlowErrorReason::CredentialRequestFailed => {
            pb::OpenId4VciErrorReason::HttpCredentialRequestFailed
        }
        HolderHarnessFlowErrorReason::CredentialStorageFailed => {
            pb::OpenId4VciErrorReason::HttpCredentialStorageFailed
        }
    }
}

/// Convert a local OpenID4VCI reason back to a holder harness flow-driver reason.
#[cfg(feature = "holder-harness")]
pub fn proto_to_holder_harness_flow_error_reason(
    value: pb::OpenId4VciErrorReason,
) -> Result<HolderHarnessFlowErrorReason, ProtoError> {
    match value {
        pb::OpenId4VciErrorReason::HttpWalletFlowLaunchRejected => {
            Ok(HolderHarnessFlowErrorReason::LaunchRejected)
        }
        pb::OpenId4VciErrorReason::HttpWalletAttestationUnavailable => {
            Ok(HolderHarnessFlowErrorReason::WalletAttestationUnavailable)
        }
        pb::OpenId4VciErrorReason::HttpTokenExchangeFailed => {
            Ok(HolderHarnessFlowErrorReason::TokenExchangeFailed)
        }
        pb::OpenId4VciErrorReason::HttpCredentialRequestFailed => {
            Ok(HolderHarnessFlowErrorReason::CredentialRequestFailed)
        }
        pb::OpenId4VciErrorReason::HttpCredentialStorageFailed => {
            Ok(HolderHarnessFlowErrorReason::CredentialStorageFailed)
        }
        _ => Err(ProtoError::InvalidEnum),
    }
}

/// Wrap a local HTTP-boundary OpenID4VCI reason in the shared identity-stack envelope.
#[must_use]
pub fn http_identity_stack_error_from_reason(
    reason: pb::OpenId4VciErrorReason,
    correlation_id: Option<&str>,
) -> IdentityStackError {
    identity_stack_error_from_reason(reason, correlation_id)
}

/// Validate and extract an OpenID4VCI reason from a shared identity-stack envelope.
pub fn http_error_reason_from_identity_stack_error(
    error: &IdentityStackError,
) -> Result<pb::OpenId4VciErrorReason, ProtoError> {
    error_reason_from_identity_stack_error(error)
}
