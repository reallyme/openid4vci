// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Stack-error mapping tests for OpenID4VCI HTTP boundary adapters.

use buffa::{EnumValue, Enumeration};
use openid4vci_http::map_http_error_reason::{
    axum_issuer_error_to_proto, holder_harness_error_to_proto,
    holder_harness_flow_error_reason_to_proto, http_error_reason_from_identity_stack_error,
    http_identity_stack_error_from_reason, oauth_http_error_reason_to_proto,
    proto_to_holder_harness_flow_error_reason, proto_to_oauth_http_error_reason,
};
use openid4vci_http::{
    AxumIssuerError, HolderHarnessError, HolderHarnessFlowErrorReason, OAuthHttpErrorReason,
};
use openid4vci_proto::generated::proto::reallyme::openid4vci::v1 as pb;
use openid4vci_proto_codec::convert::ProtoError;
use openid4vci_proto_codec::map_error_reason::error_reason_code;
use reallyme_ssi_proto::generated::proto::reallyme::identity::common::v1::{
    IdentityStackError, IdentityStackErrorDomain,
};

#[test]
fn axum_issuer_errors_map_to_openid4vci_proto_reasons() {
    assert_eq!(
        axum_issuer_error_to_proto(AxumIssuerError::InvalidMetadata),
        pb::OpenId4VciErrorReason::HttpInvalidMetadata
    );
    assert_eq!(
        axum_issuer_error_to_proto(AxumIssuerError::InvalidBodyLimit),
        pb::OpenId4VciErrorReason::HttpInvalidBodyLimit
    );
    assert_eq!(
        axum_issuer_error_to_proto(AxumIssuerError::MissingSecurityVerifier),
        pb::OpenId4VciErrorReason::HttpMissingSecurityVerifier
    );
}

#[test]
fn oauth_errors_round_trip_through_openid4vci_proto_reasons() -> Result<(), ProtoError> {
    let cases = [
        (
            OAuthHttpErrorReason::AuthorizationServerUnavailable,
            pb::OpenId4VciErrorReason::OauthAuthorizationServerUnavailable,
        ),
        (
            OAuthHttpErrorReason::InvalidRequest,
            pb::OpenId4VciErrorReason::OauthInvalidRequest,
        ),
        (
            OAuthHttpErrorReason::InvalidGrant,
            pb::OpenId4VciErrorReason::OauthInvalidGrant,
        ),
        (
            OAuthHttpErrorReason::InvalidClient,
            pb::OpenId4VciErrorReason::OauthInvalidClient,
        ),
        (
            OAuthHttpErrorReason::InvalidPushedAuthorizationRequest,
            pb::OpenId4VciErrorReason::OauthInvalidPushedAuthorizationRequest,
        ),
        (
            OAuthHttpErrorReason::InvalidDpopProof,
            pb::OpenId4VciErrorReason::OauthInvalidDpopProof,
        ),
        (
            OAuthHttpErrorReason::InvalidRequestUri,
            pb::OpenId4VciErrorReason::OauthInvalidRequestUri,
        ),
        (
            OAuthHttpErrorReason::InsufficientAuthorization,
            pb::OpenId4VciErrorReason::OauthInsufficientAuthorization,
        ),
    ];

    for (reason, proto) in cases {
        assert_eq!(oauth_http_error_reason_to_proto(reason), proto);
        assert_eq!(proto_to_oauth_http_error_reason(proto)?, reason);
    }
    Ok(())
}

#[test]
fn holder_harness_errors_round_trip_through_openid4vci_proto_reasons() -> Result<(), ProtoError> {
    assert_eq!(
        holder_harness_error_to_proto(HolderHarnessError::InvalidBodyLimit),
        pb::OpenId4VciErrorReason::HttpInvalidBodyLimit
    );

    let cases = [
        (
            HolderHarnessFlowErrorReason::LaunchRejected,
            pb::OpenId4VciErrorReason::HttpWalletFlowLaunchRejected,
        ),
        (
            HolderHarnessFlowErrorReason::WalletAttestationUnavailable,
            pb::OpenId4VciErrorReason::HttpWalletAttestationUnavailable,
        ),
        (
            HolderHarnessFlowErrorReason::TokenExchangeFailed,
            pb::OpenId4VciErrorReason::HttpTokenExchangeFailed,
        ),
        (
            HolderHarnessFlowErrorReason::CredentialRequestFailed,
            pb::OpenId4VciErrorReason::HttpCredentialRequestFailed,
        ),
        (
            HolderHarnessFlowErrorReason::CredentialStorageFailed,
            pb::OpenId4VciErrorReason::HttpCredentialStorageFailed,
        ),
    ];

    for (reason, proto) in cases {
        assert_eq!(holder_harness_flow_error_reason_to_proto(reason), proto);
        assert_eq!(proto_to_holder_harness_flow_error_reason(proto)?, reason);
    }
    Ok(())
}

#[test]
fn cross_category_proto_reasons_fail_closed() {
    assert_eq!(
        proto_to_oauth_http_error_reason(pb::OpenId4VciErrorReason::InvalidRequest),
        Err(ProtoError::InvalidEnum)
    );
    assert_eq!(
        proto_to_holder_harness_flow_error_reason(pb::OpenId4VciErrorReason::InvalidRequest),
        Err(ProtoError::InvalidEnum)
    );
}

#[test]
fn http_stack_error_preserves_openid4vci_domain_and_reason_code() {
    let wrapped = http_identity_stack_error_from_reason(
        pb::OpenId4VciErrorReason::HttpWalletFlowLaunchRejected,
        Some("corr-http-01"),
    );

    assert_eq!(
        wrapped.domain.to_i32(),
        IdentityStackErrorDomain::IDENTITY_STACK_ERROR_DOMAIN_OPENID4VCI.to_i32()
    );
    assert_eq!(
        wrapped.reason_code,
        error_reason_code(pb::OpenId4VciErrorReason::HttpWalletFlowLaunchRejected)
    );
    assert_eq!(wrapped.correlation_id, "corr-http-01");
    assert_eq!(
        http_error_reason_from_identity_stack_error(&wrapped),
        Ok(pb::OpenId4VciErrorReason::HttpWalletFlowLaunchRejected)
    );

    let wrong_domain = IdentityStackError {
        domain: EnumValue::from(IdentityStackErrorDomain::IDENTITY_STACK_ERROR_DOMAIN_OPENID4VP),
        reason_code: error_reason_code(pb::OpenId4VciErrorReason::HttpWalletFlowLaunchRejected),
        ..IdentityStackError::default()
    };
    assert_eq!(
        http_error_reason_from_identity_stack_error(&wrong_domain),
        Err(ProtoError::InvalidEnum)
    );
}
