// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Public conversions for stable OpenID4VCI protobuf error reasons.

use buffa::{EnumValue, Enumeration};
use openid4vci_attestation::AttestationStatus;
use openid4vci_issuer::IssuerStatus;
use openid4vci_profiles::ProfilePolicyStatus;
use openid4vci_proto::generated::proto::reallyme::openid4vci::v1 as pb;
use openid4vci_types::{
    CredentialErrorCode, DeferredCredentialErrorCode, IssuerProblemStatus, NotificationErrorCode,
    ProblemType, Reason as OpenId4VciReason,
};
use reallyme_openid4vci_wallet::WalletStatus;
use reallyme_ssi_proto::generated::proto::reallyme::identity::common::v1::IdentityStackError;

use crate::convert::{ProtoError, ProtoResult};
use crate::error::ProtoCodecError;
use crate::map_error_reason::{FromDomainReason, FromProtoReason, OPENID4VCI_DOMAIN};

/// Converts a wire-type validation reason to its stable protobuf reason.
#[must_use]
pub fn openid4vci_reason_to_proto(value: OpenId4VciReason) -> pb::OpenId4VciErrorReason {
    pb::OpenId4VciErrorReason::from_domain_reason(value)
}

/// Converts a protobuf reason to a wire-type validation reason.
pub fn openid4vci_reason_from_proto(
    value: pb::OpenId4VciErrorReason,
) -> ProtoResult<OpenId4VciReason> {
    OpenId4VciReason::from_proto_reason(value)
}

/// Converts an issuer status to its stable protobuf reason.
#[must_use]
pub fn issuer_status_to_proto(value: IssuerStatus) -> pb::OpenId4VciErrorReason {
    pb::OpenId4VciErrorReason::from_domain_reason(value)
}

/// Converts a protobuf reason to an issuer status.
pub fn issuer_status_from_proto(value: pb::OpenId4VciErrorReason) -> ProtoResult<IssuerStatus> {
    IssuerStatus::from_proto_reason(value)
}

/// Converts an issuer problem status to its stable protobuf reason.
#[must_use]
pub fn issuer_problem_status_to_proto(value: IssuerProblemStatus) -> pb::OpenId4VciErrorReason {
    pb::OpenId4VciErrorReason::from_domain_reason(value)
}

/// Converts a protobuf reason to an issuer problem status.
pub fn issuer_problem_status_from_proto(
    value: pb::OpenId4VciErrorReason,
) -> ProtoResult<IssuerProblemStatus> {
    IssuerProblemStatus::from_proto_reason(value)
}

/// Converts a credential error code to its stable protobuf reason.
#[must_use]
pub fn credential_error_code_to_proto(value: CredentialErrorCode) -> pb::OpenId4VciErrorReason {
    pb::OpenId4VciErrorReason::from_domain_reason(value)
}

/// Converts a protobuf reason to a credential error code.
pub fn credential_error_code_from_proto(
    value: pb::OpenId4VciErrorReason,
) -> ProtoResult<CredentialErrorCode> {
    CredentialErrorCode::from_proto_reason(value)
}

/// Converts a deferred-credential endpoint error code to its stable protobuf reason.
#[must_use]
pub fn deferred_credential_error_code_to_proto(
    value: DeferredCredentialErrorCode,
) -> pb::OpenId4VciErrorReason {
    pb::OpenId4VciErrorReason::from_domain_reason(value)
}

/// Converts a protobuf reason to a deferred-credential endpoint error code.
pub fn deferred_credential_error_code_from_proto(
    value: pb::OpenId4VciErrorReason,
) -> ProtoResult<DeferredCredentialErrorCode> {
    DeferredCredentialErrorCode::from_proto_reason(value)
}

/// Converts a notification endpoint error code to its stable protobuf reason.
#[must_use]
pub fn notification_error_code_to_proto(value: NotificationErrorCode) -> pb::OpenId4VciErrorReason {
    pb::OpenId4VciErrorReason::from_domain_reason(value)
}

/// Converts a protobuf reason to a notification endpoint error code.
pub fn notification_error_code_from_proto(
    value: pb::OpenId4VciErrorReason,
) -> ProtoResult<NotificationErrorCode> {
    NotificationErrorCode::from_proto_reason(value)
}

/// Converts a problem type to its stable protobuf reason.
#[must_use]
pub fn problem_type_to_proto(value: ProblemType) -> pb::OpenId4VciErrorReason {
    pb::OpenId4VciErrorReason::from_domain_reason(value)
}

/// Converts a protobuf reason to a problem type.
pub fn problem_type_from_proto(value: pb::OpenId4VciErrorReason) -> ProtoResult<ProblemType> {
    ProblemType::from_proto_reason(value)
}

/// Converts an attestation status to its stable protobuf reason.
#[must_use]
pub fn attestation_status_to_proto(value: AttestationStatus) -> pb::OpenId4VciErrorReason {
    pb::OpenId4VciErrorReason::from_domain_reason(value)
}

/// Converts a protobuf reason to an attestation status.
pub fn attestation_status_from_proto(
    value: pb::OpenId4VciErrorReason,
) -> ProtoResult<AttestationStatus> {
    AttestationStatus::from_proto_reason(value)
}

/// Converts a wallet status to its stable protobuf reason.
#[must_use]
pub fn wallet_status_to_proto(value: WalletStatus) -> pb::OpenId4VciErrorReason {
    pb::OpenId4VciErrorReason::from_domain_reason(value)
}

/// Converts a protobuf reason to a wallet status.
pub fn wallet_status_from_proto(value: pb::OpenId4VciErrorReason) -> ProtoResult<WalletStatus> {
    WalletStatus::from_proto_reason(value)
}

/// Converts a profile-policy status to its stable protobuf reason.
#[must_use]
pub fn profile_policy_status_to_proto(value: ProfilePolicyStatus) -> pb::OpenId4VciErrorReason {
    pb::OpenId4VciErrorReason::from_domain_reason(value)
}

/// Converts a protobuf reason to a profile-policy status.
pub fn profile_policy_status_from_proto(
    value: pb::OpenId4VciErrorReason,
) -> ProtoResult<ProfilePolicyStatus> {
    ProfilePolicyStatus::from_proto_reason(value)
}

/// Converts a codec error to its stable protobuf reason.
#[must_use]
pub fn proto_codec_error_to_proto(value: ProtoCodecError) -> pb::OpenId4VciErrorReason {
    pb::OpenId4VciErrorReason::from_domain_reason(value)
}

/// Converts a protobuf reason to a codec error.
pub fn proto_codec_error_from_proto(
    value: pb::OpenId4VciErrorReason,
) -> ProtoResult<ProtoCodecError> {
    ProtoCodecError::from_proto_reason(value)
}

/// Converts a domain conversion error to its stable protobuf reason.
#[must_use]
pub fn proto_error_to_proto(value: ProtoError) -> pb::OpenId4VciErrorReason {
    pb::OpenId4VciErrorReason::from_domain_reason(value)
}

/// Decodes a numeric protobuf reason with unknown-value rejection.
pub fn error_reason_from_i32(value: i32) -> ProtoResult<pb::OpenId4VciErrorReason> {
    pb::OpenId4VciErrorReason::from_i32(value).ok_or(ProtoError::InvalidEnum)
}

/// Decodes a Buffa enum value with unknown-value rejection.
pub fn error_reason_from_enum_value(
    value: EnumValue<pb::OpenId4VciErrorReason>,
) -> ProtoResult<pb::OpenId4VciErrorReason> {
    value.as_known().ok_or(ProtoError::InvalidEnum)
}

/// Builds a shared identity stack error from an OpenID4VCI reason.
#[must_use]
pub fn identity_stack_error_from_reason(
    reason: pb::OpenId4VciErrorReason,
    correlation_id: Option<&str>,
) -> IdentityStackError {
    IdentityStackError {
        domain: EnumValue::from(OPENID4VCI_DOMAIN),
        reason_code: error_reason_code(reason),
        correlation_id: correlation_id.unwrap_or_default().to_owned(),
        ..IdentityStackError::default()
    }
}

/// Recovers an OpenID4VCI reason from a shared identity stack error.
pub fn error_reason_from_identity_stack_error(
    error: &IdentityStackError,
) -> ProtoResult<pb::OpenId4VciErrorReason> {
    if error.domain.as_known() != Some(OPENID4VCI_DOMAIN) {
        return Err(ProtoError::InvalidEnum);
    }
    let value = i32::try_from(error.reason_code).map_err(|_| ProtoError::InvalidEnum)?;
    error_reason_from_i32(value)
}

/// Returns the stable unsigned numeric code for a protobuf reason.
#[must_use]
pub fn error_reason_code(reason: pb::OpenId4VciErrorReason) -> u32 {
    match u32::try_from(reason.to_i32()) {
        Ok(value) => value,
        Err(_) => pb::OpenId4VciErrorReason::Unspecified
            .to_i32()
            .unsigned_abs(),
    }
}
