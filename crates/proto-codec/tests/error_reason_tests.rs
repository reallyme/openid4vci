// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests for proto-backed OpenID4VCI public error reason mappings.

use buffa::{EnumValue, Enumeration};
use openid4vci_attestation::AttestationStatus;
use openid4vci_issuer::IssuerStatus;
use openid4vci_profiles::ProfilePolicyStatus;
use openid4vci_proto::generated::proto::reallyme::openid4vci::v1 as pb;
use openid4vci_proto_codec::convert::ProtoError;
use openid4vci_proto_codec::map_error_reason::{
    attestation_status_from_proto, attestation_status_to_proto, credential_error_code_from_proto,
    credential_error_code_to_proto, deferred_credential_error_code_from_proto,
    deferred_credential_error_code_to_proto, error_reason_code, error_reason_from_enum_value,
    error_reason_from_i32, error_reason_from_identity_stack_error,
    identity_stack_error_from_reason, issuer_problem_status_from_proto,
    issuer_problem_status_to_proto, issuer_status_from_proto, issuer_status_to_proto,
    notification_error_code_from_proto, notification_error_code_to_proto,
    openid4vci_reason_from_proto, openid4vci_reason_to_proto, problem_type_from_proto,
    problem_type_to_proto, profile_policy_status_from_proto, profile_policy_status_to_proto,
    proto_codec_error_from_proto, proto_codec_error_to_proto, proto_error_to_proto,
    wallet_status_from_proto, wallet_status_to_proto,
};
use openid4vci_proto_codec::ProtoCodecError;
use openid4vci_types::{
    CredentialErrorCode, DeferredCredentialErrorCode, IssuerProblemStatus, NotificationErrorCode,
    ProblemType, Reason as OpenId4VciReason,
};
use reallyme_openid4vci_wallet::WalletStatus;
use reallyme_ssi_proto::generated::proto::reallyme::identity::common::v1::{
    IdentityStackError, IdentityStackErrorDomain,
};
use serde_json::json;

#[test]
fn openid4vci_validation_reasons_round_trip_through_proto() {
    let cases = [
        (
            OpenId4VciReason::MissingRequiredField,
            pb::OpenId4VciErrorReason::MissingRequiredField,
        ),
        (
            OpenId4VciReason::ForbiddenField,
            pb::OpenId4VciErrorReason::ForbiddenField,
        ),
        (
            OpenId4VciReason::InvalidString,
            pb::OpenId4VciErrorReason::InvalidString,
        ),
        (
            OpenId4VciReason::InvalidUrl,
            pb::OpenId4VciErrorReason::InvalidUrl,
        ),
        (
            OpenId4VciReason::InvalidJson,
            pb::OpenId4VciErrorReason::InvalidJson,
        ),
        (
            OpenId4VciReason::PayloadTooLarge,
            pb::OpenId4VciErrorReason::PayloadTooLarge,
        ),
        (
            OpenId4VciReason::InvalidCredentialSelector,
            pb::OpenId4VciErrorReason::InvalidCredentialSelector,
        ),
        (
            OpenId4VciReason::ProofRequired,
            pb::OpenId4VciErrorReason::ProofRequired,
        ),
        (
            OpenId4VciReason::InvalidProofs,
            pb::OpenId4VciErrorReason::InvalidProofs,
        ),
        (
            OpenId4VciReason::InvalidCredentialResponse,
            pb::OpenId4VciErrorReason::InvalidCredentialResponse,
        ),
        (
            OpenId4VciReason::InvalidNotification,
            pb::OpenId4VciErrorReason::InvalidNotification,
        ),
    ];

    for (domain, proto) in cases {
        assert_eq!(openid4vci_reason_to_proto(domain), proto);
        assert_eq!(openid4vci_reason_from_proto(proto), Ok(domain));
    }
}

#[test]
fn issuer_statuses_round_trip_through_proto() {
    let cases = [
        (
            IssuerStatus::InvalidRequest,
            pb::OpenId4VciErrorReason::InvalidRequest,
        ),
        (
            IssuerStatus::UnsupportedCredential,
            pb::OpenId4VciErrorReason::UnsupportedCredential,
        ),
        (
            IssuerStatus::UnknownCredentialIdentifier,
            pb::OpenId4VciErrorReason::UnknownCredentialIdentifier,
        ),
        (
            IssuerStatus::ProofRequired,
            pb::OpenId4VciErrorReason::ProofRequired,
        ),
        (
            IssuerStatus::InvalidProof,
            pb::OpenId4VciErrorReason::InvalidProof,
        ),
        (
            IssuerStatus::InvalidProofPolicy,
            pb::OpenId4VciErrorReason::InvalidProofPolicy,
        ),
        (
            IssuerStatus::AttestationSignatureRejected,
            pb::OpenId4VciErrorReason::AttestationSignatureRejected,
        ),
        (
            IssuerStatus::AttestationTrustRejected,
            pb::OpenId4VciErrorReason::AttestationTrustRejected,
        ),
        (
            IssuerStatus::AttestationTrustIndeterminate,
            pb::OpenId4VciErrorReason::AttestationTrustIndeterminate,
        ),
        (
            IssuerStatus::AttestationTrustEvidenceStale,
            pb::OpenId4VciErrorReason::AttestationTrustEvidenceStale,
        ),
        (
            IssuerStatus::AttestationTrustEvidenceFutureIssued,
            pb::OpenId4VciErrorReason::AttestationTrustEvidenceFutureIssued,
        ),
        (
            IssuerStatus::AttestationStatusRejected,
            pb::OpenId4VciErrorReason::AttestationStatusRejected,
        ),
        (
            IssuerStatus::AttestationStatusIndeterminate,
            pb::OpenId4VciErrorReason::AttestationStatusIndeterminate,
        ),
        (
            IssuerStatus::AttestationExpired,
            pb::OpenId4VciErrorReason::AttestationEvidenceExpired,
        ),
        (
            IssuerStatus::AttestationStale,
            pb::OpenId4VciErrorReason::AttestationEvidenceStale,
        ),
        (
            IssuerStatus::AttestationFutureIssued,
            pb::OpenId4VciErrorReason::AttestationEvidenceFutureIssued,
        ),
        (
            IssuerStatus::AttestationAlgorithmRejected,
            pb::OpenId4VciErrorReason::AttestationAlgorithmRejected,
        ),
        (
            IssuerStatus::AttestationSecurityPropertiesRejected,
            pb::OpenId4VciErrorReason::AttestationSecurityPropertiesRejected,
        ),
        (
            IssuerStatus::InvalidAttestationTrustEvidence,
            pb::OpenId4VciErrorReason::AttestationInvalidTrustEvidence,
        ),
        (
            IssuerStatus::InvalidAttestedKey,
            pb::OpenId4VciErrorReason::InvalidAttestedKey,
        ),
        (
            IssuerStatus::InvalidNonce,
            pb::OpenId4VciErrorReason::InvalidNonce,
        ),
        (
            IssuerStatus::EncryptionRequired,
            pb::OpenId4VciErrorReason::EncryptionRequired,
        ),
        (
            IssuerStatus::InvalidEncryptionParameters,
            pb::OpenId4VciErrorReason::InvalidEncryptionParameters,
        ),
        (
            IssuerStatus::InvalidTransaction,
            pb::OpenId4VciErrorReason::InvalidTransaction,
        ),
        (
            IssuerStatus::InvalidNotificationId,
            pb::OpenId4VciErrorReason::InvalidNotificationId,
        ),
        (
            IssuerStatus::StorageUnavailable,
            pb::OpenId4VciErrorReason::StorageUnavailable,
        ),
        (
            IssuerStatus::EncodingFailed,
            pb::OpenId4VciErrorReason::EncodingFailed,
        ),
    ];

    for (domain, proto) in cases {
        assert_eq!(issuer_status_to_proto(domain), proto);
        assert_eq!(issuer_status_from_proto(proto), Ok(domain));
    }
}

#[test]
fn public_wire_error_enums_round_trip_through_proto() {
    let credential = (
        CredentialErrorCode::CredentialRequestDenied,
        pb::OpenId4VciErrorReason::CredentialRequestDenied,
    );
    assert_eq!(credential_error_code_to_proto(credential.0), credential.1);
    assert_eq!(
        credential_error_code_from_proto(credential.1),
        Ok(credential.0)
    );

    let deferred = (
        DeferredCredentialErrorCode::InvalidTransactionId,
        pb::OpenId4VciErrorReason::InvalidTransaction,
    );
    assert_eq!(
        deferred_credential_error_code_to_proto(deferred.0),
        deferred.1
    );
    assert_eq!(
        deferred_credential_error_code_from_proto(deferred.1),
        Ok(deferred.0)
    );

    let notification = (
        NotificationErrorCode::InvalidNotificationRequest,
        pb::OpenId4VciErrorReason::InvalidNotification,
    );
    assert_eq!(
        notification_error_code_to_proto(notification.0),
        notification.1
    );
    assert_eq!(
        notification_error_code_from_proto(notification.1),
        Ok(notification.0)
    );

    let problem = (
        ProblemType::ServerError,
        pb::OpenId4VciErrorReason::ServerError,
    );
    assert_eq!(problem_type_to_proto(problem.0), problem.1);
    assert_eq!(problem_type_from_proto(problem.1), Ok(problem.0));

    let issuer_problem = (
        IssuerProblemStatus::InvalidNonce,
        pb::OpenId4VciErrorReason::InvalidNonce,
    );
    assert_eq!(
        issuer_problem_status_to_proto(issuer_problem.0),
        issuer_problem.1
    );
    assert_eq!(
        issuer_problem_status_from_proto(issuer_problem.1),
        Ok(issuer_problem.0)
    );
}

#[test]
fn attestation_wallet_profile_and_proto_errors_round_trip() {
    for (status, reason) in [
        (
            AttestationStatus::MissingJwt,
            pb::OpenId4VciErrorReason::AttestationMissingJwt,
        ),
        (
            AttestationStatus::InvalidJwt,
            pb::OpenId4VciErrorReason::AttestationInvalidJwt,
        ),
        (
            AttestationStatus::InvalidHeader,
            pb::OpenId4VciErrorReason::AttestationInvalidHeader,
        ),
        (
            AttestationStatus::InvalidClaims,
            pb::OpenId4VciErrorReason::AttestationInvalidClaims,
        ),
        (
            AttestationStatus::InvalidNonce,
            pb::OpenId4VciErrorReason::AttestationInvalidNonce,
        ),
        (
            AttestationStatus::UnsupportedAlgorithm,
            pb::OpenId4VciErrorReason::AttestationUnsupportedAlgorithm,
        ),
        (
            AttestationStatus::AlgorithmNotAllowed,
            pb::OpenId4VciErrorReason::AttestationAlgorithmNotAllowed,
        ),
        (
            AttestationStatus::Expired,
            pb::OpenId4VciErrorReason::AttestationExpired,
        ),
        (
            AttestationStatus::FutureIssued,
            pb::OpenId4VciErrorReason::AttestationFutureIssued,
        ),
        (
            AttestationStatus::Stale,
            pb::OpenId4VciErrorReason::AttestationStale,
        ),
        (
            AttestationStatus::UnsupportedAttestedKey,
            pb::OpenId4VciErrorReason::AttestationUnsupportedKey,
        ),
        (
            AttestationStatus::DuplicateAttestedKey,
            pb::OpenId4VciErrorReason::AttestationDuplicateKey,
        ),
        (
            AttestationStatus::SignatureRejected,
            pb::OpenId4VciErrorReason::AttestationSignatureInvalid,
        ),
        (
            AttestationStatus::TrustRejected,
            pb::OpenId4VciErrorReason::AttestationTrustInvalid,
        ),
        (
            AttestationStatus::TrustIndeterminate,
            pb::OpenId4VciErrorReason::AttestationTrustUndetermined,
        ),
        (
            AttestationStatus::TrustEvidenceStale,
            pb::OpenId4VciErrorReason::AttestationTrustEvidenceStale,
        ),
        (
            AttestationStatus::TrustEvidenceFutureIssued,
            pb::OpenId4VciErrorReason::AttestationTrustEvidenceFutureIssued,
        ),
        (
            AttestationStatus::StatusRejected,
            pb::OpenId4VciErrorReason::AttestationStatusInvalid,
        ),
        (
            AttestationStatus::StatusIndeterminate,
            pb::OpenId4VciErrorReason::AttestationStatusUndetermined,
        ),
        (
            AttestationStatus::InvalidTrustEvidence,
            pb::OpenId4VciErrorReason::AttestationInvalidTrustEvidence,
        ),
    ] {
        assert_eq!(attestation_status_to_proto(status), reason);
        assert_eq!(attestation_status_from_proto(reason), Ok(status));
    }

    let wallet = (
        WalletStatus::OfferResolutionRequired,
        pb::OpenId4VciErrorReason::HolderOfferResolutionRequired,
    );
    assert_eq!(wallet_status_to_proto(wallet.0), wallet.1);
    assert_eq!(wallet_status_from_proto(wallet.1), Ok(wallet.0));
    for (status, reason) in [
        (
            WalletStatus::InvalidEncryptionParameters,
            pb::OpenId4VciErrorReason::InvalidEncryptionParameters,
        ),
        (
            WalletStatus::EncryptionFailed,
            pb::OpenId4VciErrorReason::EncodingFailed,
        ),
        (
            WalletStatus::EncryptedResponseRejected,
            pb::OpenId4VciErrorReason::InvalidCredentialResponse,
        ),
        (
            WalletStatus::InvalidAuthorizationServer,
            pb::OpenId4VciErrorReason::HolderInvalidAuthorizationServer,
        ),
        (
            WalletStatus::ResponseEncryptionRequired,
            pb::OpenId4VciErrorReason::HolderResponseEncryptionRequired,
        ),
        (
            WalletStatus::RequestEncryptionRequired,
            pb::OpenId4VciErrorReason::HolderRequestEncryptionRequired,
        ),
        (
            WalletStatus::IssuerMetadataResolutionFailed,
            pb::OpenId4VciErrorReason::HolderIssuerMetadataResolutionFailed,
        ),
        (
            WalletStatus::InvalidIssuerMetadata,
            pb::OpenId4VciErrorReason::HolderInvalidIssuerMetadata,
        ),
        (
            WalletStatus::IssuerMetadataIssuerMismatch,
            pb::OpenId4VciErrorReason::HolderIssuerMetadataIssuerMismatch,
        ),
        (
            WalletStatus::InvalidSignedMetadata,
            pb::OpenId4VciErrorReason::HolderInvalidSignedMetadata,
        ),
        (
            WalletStatus::ExpiredSignedMetadata,
            pb::OpenId4VciErrorReason::HolderExpiredSignedMetadata,
        ),
        (
            WalletStatus::UntrustedSignedMetadata,
            pb::OpenId4VciErrorReason::HolderUntrustedSignedMetadata,
        ),
        (
            WalletStatus::FutureSignedMetadata,
            pb::OpenId4VciErrorReason::HolderFutureSignedMetadata,
        ),
        (
            WalletStatus::StaleSignedMetadata,
            pb::OpenId4VciErrorReason::HolderStaleSignedMetadata,
        ),
        (
            WalletStatus::SignedMetadataUnsupportedAlgorithm,
            pb::OpenId4VciErrorReason::HolderSignedMetadataUnsupportedAlgorithm,
        ),
        (
            WalletStatus::SignedMetadataAlgorithmNotAllowed,
            pb::OpenId4VciErrorReason::HolderSignedMetadataAlgorithmNotAllowed,
        ),
        (
            WalletStatus::SignedMetadataSignatureRejected,
            pb::OpenId4VciErrorReason::HolderSignedMetadataSignatureRejected,
        ),
        (
            WalletStatus::SignedMetadataTrustIndeterminate,
            pb::OpenId4VciErrorReason::HolderSignedMetadataTrustIndeterminate,
        ),
        (
            WalletStatus::SignedMetadataTrustEvidenceStale,
            pb::OpenId4VciErrorReason::HolderSignedMetadataTrustEvidenceStale,
        ),
        (
            WalletStatus::SignedMetadataTrustEvidenceFutureIssued,
            pb::OpenId4VciErrorReason::HolderSignedMetadataTrustEvidenceFutureIssued,
        ),
        (
            WalletStatus::InvalidSignedMetadataTrustEvidence,
            pb::OpenId4VciErrorReason::HolderInvalidSignedMetadataTrustEvidence,
        ),
    ] {
        assert_eq!(wallet_status_to_proto(status), reason);
        assert_eq!(wallet_status_from_proto(reason), Ok(status));
    }

    for (status, reason) in [
        (
            ProfilePolicyStatus::WalletAttestationRequired,
            pb::OpenId4VciErrorReason::ProfileWalletAttestationRequired,
        ),
        (
            ProfilePolicyStatus::AuthorizationCodeGrantRequired,
            pb::OpenId4VciErrorReason::ProfileAuthorizationCodeGrantRequired,
        ),
        (
            ProfilePolicyStatus::PkceS256Required,
            pb::OpenId4VciErrorReason::ProfilePkceS256Required,
        ),
        (
            ProfilePolicyStatus::AuthorizationResponseIssuerRequired,
            pb::OpenId4VciErrorReason::ProfileAuthorizationResponseIssuerRequired,
        ),
        (
            ProfilePolicyStatus::OauthClientAuthenticationRequired,
            pb::OpenId4VciErrorReason::ProfileOauthClientAuthenticationRequired,
        ),
    ] {
        assert_eq!(profile_policy_status_to_proto(status), reason);
        assert_eq!(profile_policy_status_from_proto(reason), Ok(status));
    }

    let codec = (
        ProtoCodecError::JsonDeserialize,
        pb::OpenId4VciErrorReason::ProtoJsonDeserialize,
    );
    assert_eq!(proto_codec_error_to_proto(codec.0), codec.1);
    assert_eq!(proto_codec_error_from_proto(codec.1), Ok(codec.0));

    let oversized = (
        ProtoCodecError::PayloadTooLarge,
        pb::OpenId4VciErrorReason::PayloadTooLarge,
    );
    assert_eq!(proto_codec_error_to_proto(oversized.0), oversized.1);
    assert_eq!(proto_codec_error_from_proto(oversized.1), Ok(oversized.0));

    assert_eq!(
        proto_error_to_proto(ProtoError::InvalidWireValue),
        pb::OpenId4VciErrorReason::ProtoInvalidWireValue
    );
    assert_eq!(
        proto_error_to_proto(ProtoError::PayloadTooLarge),
        pb::OpenId4VciErrorReason::PayloadTooLarge
    );
}

#[test]
fn unknown_or_cross_domain_reason_codes_fail_closed() {
    assert_eq!(error_reason_from_i32(999), Err(ProtoError::InvalidEnum));
    assert_eq!(
        error_reason_from_enum_value(EnumValue::from(999)),
        Err(ProtoError::InvalidEnum)
    );
    assert_eq!(
        openid4vci_reason_from_proto(pb::OpenId4VciErrorReason::InvalidProof),
        Err(ProtoError::InvalidEnum)
    );
}

#[test]
fn common_identity_stack_error_wraps_openid4vci_reason() {
    let wrapped =
        identity_stack_error_from_reason(pb::OpenId4VciErrorReason::InvalidProof, Some("corr-01"));

    assert_eq!(
        wrapped.domain.to_i32(),
        IdentityStackErrorDomain::IDENTITY_STACK_ERROR_DOMAIN_OPENID4VCI.to_i32()
    );
    assert_eq!(
        wrapped.reason_code,
        error_reason_code(pb::OpenId4VciErrorReason::InvalidProof)
    );
    assert_eq!(wrapped.correlation_id, "corr-01");
    assert_eq!(
        error_reason_from_identity_stack_error(&wrapped),
        Ok(pb::OpenId4VciErrorReason::InvalidProof)
    );

    let wrong_domain = IdentityStackError {
        domain: EnumValue::from(
            IdentityStackErrorDomain::IDENTITY_STACK_ERROR_DOMAIN_IDENTITY_CORE,
        ),
        reason_code: error_reason_code(pb::OpenId4VciErrorReason::InvalidProof),
        ..IdentityStackError::default()
    };
    assert_eq!(
        error_reason_from_identity_stack_error(&wrong_domain),
        Err(ProtoError::InvalidEnum)
    );
}

#[test]
fn generated_reason_json_uses_proto_enum_name() -> Result<(), serde_json::Error> {
    let serialized = serde_json::to_value(pb::OpenId4VciErrorReason::InvalidProof)?;
    assert_eq!(serialized, json!("OPEN_ID4_VCI_ERROR_REASON_INVALID_PROOF"));
    Ok(())
}
