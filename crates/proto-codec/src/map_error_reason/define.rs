// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Maps public OpenID4VCI errors to generated protobuf reason codes.
//!
//! Domain crates intentionally stay independent of generated code. Boundary
//! adapters use this module to normalize every public error into the
//! component-specific protobuf enum and, when needed, the shared ReallyMe
//! identity-stack error envelope.

use openid4vci_issuer::IssuerStatus;
use openid4vci_profiles::ProfilePolicyStatus;
use openid4vci_proto::generated::proto::reallyme::openid4vci::v1 as pb;
use openid4vci_types::{
    CredentialErrorCode, DeferredCredentialErrorCode, IssuerProblemStatus, NotificationErrorCode,
    ProblemType, Reason as OpenId4VciReason,
};
use reallyme_ssi_proto::generated::proto::reallyme::identity::common::v1::IdentityStackErrorDomain;

use crate::convert::{ProtoError, ProtoResult};
use crate::error::ProtoCodecError;

pub(crate) const OPENID4VCI_DOMAIN: IdentityStackErrorDomain =
    IdentityStackErrorDomain::IDENTITY_STACK_ERROR_DOMAIN_OPENID4VCI;

pub(crate) trait FromDomainReason<T> {
    fn from_domain_reason(value: T) -> Self;
}

pub(crate) trait FromProtoReason: Sized {
    fn from_proto_reason(value: pb::OpenId4VciErrorReason) -> ProtoResult<Self>;
}

impl FromDomainReason<OpenId4VciReason> for pb::OpenId4VciErrorReason {
    fn from_domain_reason(value: OpenId4VciReason) -> Self {
        match value {
            OpenId4VciReason::MissingRequiredField => Self::MissingRequiredField,
            OpenId4VciReason::ForbiddenField => Self::ForbiddenField,
            OpenId4VciReason::InvalidString => Self::InvalidString,
            OpenId4VciReason::InvalidUrl => Self::InvalidUrl,
            OpenId4VciReason::InvalidJson => Self::InvalidJson,
            OpenId4VciReason::PayloadTooLarge => Self::PayloadTooLarge,
            OpenId4VciReason::InvalidCredentialSelector => Self::InvalidCredentialSelector,
            OpenId4VciReason::ProofRequired => Self::ProofRequired,
            OpenId4VciReason::InvalidProofs => Self::InvalidProofs,
            OpenId4VciReason::InvalidCredentialResponse => Self::InvalidCredentialResponse,
            OpenId4VciReason::InvalidNotification => Self::InvalidNotification,
            _ => Self::InvalidRequest,
        }
    }
}

impl FromProtoReason for OpenId4VciReason {
    fn from_proto_reason(value: pb::OpenId4VciErrorReason) -> ProtoResult<Self> {
        match value {
            pb::OpenId4VciErrorReason::MissingRequiredField => Ok(Self::MissingRequiredField),
            pb::OpenId4VciErrorReason::ForbiddenField => Ok(Self::ForbiddenField),
            pb::OpenId4VciErrorReason::InvalidString => Ok(Self::InvalidString),
            pb::OpenId4VciErrorReason::InvalidUrl => Ok(Self::InvalidUrl),
            pb::OpenId4VciErrorReason::InvalidJson => Ok(Self::InvalidJson),
            pb::OpenId4VciErrorReason::PayloadTooLarge => Ok(Self::PayloadTooLarge),
            pb::OpenId4VciErrorReason::InvalidCredentialSelector => {
                Ok(Self::InvalidCredentialSelector)
            }
            pb::OpenId4VciErrorReason::ProofRequired => Ok(Self::ProofRequired),
            pb::OpenId4VciErrorReason::InvalidProofs => Ok(Self::InvalidProofs),
            pb::OpenId4VciErrorReason::InvalidCredentialResponse => {
                Ok(Self::InvalidCredentialResponse)
            }
            pb::OpenId4VciErrorReason::InvalidNotification => Ok(Self::InvalidNotification),
            _ => Err(ProtoError::InvalidEnum),
        }
    }
}

impl FromDomainReason<IssuerStatus> for pb::OpenId4VciErrorReason {
    fn from_domain_reason(value: IssuerStatus) -> Self {
        match value {
            IssuerStatus::InvalidRequest => Self::InvalidRequest,
            IssuerStatus::UnsupportedCredential => Self::UnsupportedCredential,
            IssuerStatus::UnknownCredentialIdentifier => Self::UnknownCredentialIdentifier,
            IssuerStatus::ProofRequired => Self::ProofRequired,
            IssuerStatus::InvalidProof => Self::InvalidProof,
            IssuerStatus::InvalidProofPolicy => Self::InvalidProofPolicy,
            IssuerStatus::AttestationSignatureRejected => Self::AttestationSignatureRejected,
            IssuerStatus::AttestationTrustRejected => Self::AttestationTrustRejected,
            IssuerStatus::AttestationTrustIndeterminate => Self::AttestationTrustIndeterminate,
            IssuerStatus::AttestationTrustEvidenceStale => Self::AttestationTrustEvidenceStale,
            IssuerStatus::AttestationTrustEvidenceFutureIssued => {
                Self::AttestationTrustEvidenceFutureIssued
            }
            IssuerStatus::AttestationStatusRejected => Self::AttestationStatusRejected,
            IssuerStatus::AttestationStatusIndeterminate => Self::AttestationStatusIndeterminate,
            IssuerStatus::AttestationExpired => Self::AttestationEvidenceExpired,
            IssuerStatus::AttestationStale => Self::AttestationEvidenceStale,
            IssuerStatus::AttestationFutureIssued => Self::AttestationEvidenceFutureIssued,
            IssuerStatus::AttestationAlgorithmRejected => Self::AttestationAlgorithmRejected,
            IssuerStatus::AttestationSecurityPropertiesRejected => {
                Self::AttestationSecurityPropertiesRejected
            }
            IssuerStatus::InvalidAttestationTrustEvidence => Self::AttestationInvalidTrustEvidence,
            IssuerStatus::InvalidAttestedKey => Self::InvalidAttestedKey,
            IssuerStatus::InvalidNonce => Self::InvalidNonce,
            IssuerStatus::EncryptionRequired => Self::EncryptionRequired,
            IssuerStatus::InvalidEncryptionParameters => Self::InvalidEncryptionParameters,
            IssuerStatus::InvalidTransaction => Self::InvalidTransaction,
            IssuerStatus::InvalidNotificationId => Self::InvalidNotificationId,
            IssuerStatus::StorageUnavailable => Self::StorageUnavailable,
            IssuerStatus::EncodingFailed => Self::EncodingFailed,
            // `IssuerStatus` is non-exhaustive across crate boundaries. Every
            // currently defined status is mapped above; future versions fail
            // closed as a server error until this contract is revised.
            _ => Self::ServerError,
        }
    }
}

impl FromProtoReason for IssuerStatus {
    fn from_proto_reason(value: pb::OpenId4VciErrorReason) -> ProtoResult<Self> {
        match value {
            pb::OpenId4VciErrorReason::InvalidRequest => Ok(Self::InvalidRequest),
            pb::OpenId4VciErrorReason::UnsupportedCredential => Ok(Self::UnsupportedCredential),
            pb::OpenId4VciErrorReason::UnknownCredentialIdentifier => {
                Ok(Self::UnknownCredentialIdentifier)
            }
            pb::OpenId4VciErrorReason::ProofRequired => Ok(Self::ProofRequired),
            pb::OpenId4VciErrorReason::InvalidProof => Ok(Self::InvalidProof),
            pb::OpenId4VciErrorReason::InvalidProofPolicy => Ok(Self::InvalidProofPolicy),
            pb::OpenId4VciErrorReason::AttestationSignatureRejected => {
                Ok(Self::AttestationSignatureRejected)
            }
            pb::OpenId4VciErrorReason::AttestationTrustRejected => {
                Ok(Self::AttestationTrustRejected)
            }
            pb::OpenId4VciErrorReason::AttestationTrustIndeterminate => {
                Ok(Self::AttestationTrustIndeterminate)
            }
            pb::OpenId4VciErrorReason::AttestationTrustEvidenceStale => {
                Ok(Self::AttestationTrustEvidenceStale)
            }
            pb::OpenId4VciErrorReason::AttestationTrustEvidenceFutureIssued => {
                Ok(Self::AttestationTrustEvidenceFutureIssued)
            }
            pb::OpenId4VciErrorReason::AttestationStatusRejected => {
                Ok(Self::AttestationStatusRejected)
            }
            pb::OpenId4VciErrorReason::AttestationStatusIndeterminate => {
                Ok(Self::AttestationStatusIndeterminate)
            }
            pb::OpenId4VciErrorReason::AttestationEvidenceExpired => Ok(Self::AttestationExpired),
            pb::OpenId4VciErrorReason::AttestationEvidenceStale => Ok(Self::AttestationStale),
            pb::OpenId4VciErrorReason::AttestationEvidenceFutureIssued => {
                Ok(Self::AttestationFutureIssued)
            }
            pb::OpenId4VciErrorReason::AttestationAlgorithmRejected => {
                Ok(Self::AttestationAlgorithmRejected)
            }
            pb::OpenId4VciErrorReason::AttestationSecurityPropertiesRejected => {
                Ok(Self::AttestationSecurityPropertiesRejected)
            }
            pb::OpenId4VciErrorReason::AttestationInvalidTrustEvidence => {
                Ok(Self::InvalidAttestationTrustEvidence)
            }
            pb::OpenId4VciErrorReason::InvalidAttestedKey => Ok(Self::InvalidAttestedKey),
            pb::OpenId4VciErrorReason::InvalidNonce => Ok(Self::InvalidNonce),
            pb::OpenId4VciErrorReason::EncryptionRequired => Ok(Self::EncryptionRequired),
            pb::OpenId4VciErrorReason::InvalidEncryptionParameters => {
                Ok(Self::InvalidEncryptionParameters)
            }
            pb::OpenId4VciErrorReason::InvalidTransaction => Ok(Self::InvalidTransaction),
            pb::OpenId4VciErrorReason::InvalidNotificationId => Ok(Self::InvalidNotificationId),
            pb::OpenId4VciErrorReason::StorageUnavailable => Ok(Self::StorageUnavailable),
            pb::OpenId4VciErrorReason::EncodingFailed => Ok(Self::EncodingFailed),
            _ => Err(ProtoError::InvalidEnum),
        }
    }
}

impl FromDomainReason<IssuerProblemStatus> for pb::OpenId4VciErrorReason {
    fn from_domain_reason(value: IssuerProblemStatus) -> Self {
        match value {
            IssuerProblemStatus::InvalidRequest => Self::InvalidRequest,
            IssuerProblemStatus::UnsupportedCredential => Self::UnsupportedCredential,
            IssuerProblemStatus::UnknownCredentialIdentifier => Self::UnknownCredentialIdentifier,
            IssuerProblemStatus::ProofRequired => Self::ProofRequired,
            IssuerProblemStatus::InvalidProof => Self::InvalidProof,
            IssuerProblemStatus::InvalidNonce => Self::InvalidNonce,
            IssuerProblemStatus::EncryptionRequired => Self::EncryptionRequired,
            IssuerProblemStatus::InvalidTransaction => Self::InvalidTransaction,
            IssuerProblemStatus::InvalidNotificationId => Self::InvalidNotificationId,
            IssuerProblemStatus::StorageUnavailable => Self::StorageUnavailable,
            IssuerProblemStatus::EncodingFailed => Self::EncodingFailed,
        }
    }
}

impl FromProtoReason for IssuerProblemStatus {
    fn from_proto_reason(value: pb::OpenId4VciErrorReason) -> ProtoResult<Self> {
        match value {
            pb::OpenId4VciErrorReason::InvalidRequest => Ok(Self::InvalidRequest),
            pb::OpenId4VciErrorReason::UnsupportedCredential => Ok(Self::UnsupportedCredential),
            pb::OpenId4VciErrorReason::UnknownCredentialIdentifier => {
                Ok(Self::UnknownCredentialIdentifier)
            }
            pb::OpenId4VciErrorReason::ProofRequired => Ok(Self::ProofRequired),
            pb::OpenId4VciErrorReason::InvalidProof => Ok(Self::InvalidProof),
            pb::OpenId4VciErrorReason::InvalidNonce => Ok(Self::InvalidNonce),
            pb::OpenId4VciErrorReason::EncryptionRequired => Ok(Self::EncryptionRequired),
            pb::OpenId4VciErrorReason::InvalidTransaction => Ok(Self::InvalidTransaction),
            pb::OpenId4VciErrorReason::InvalidNotificationId => Ok(Self::InvalidNotificationId),
            pb::OpenId4VciErrorReason::StorageUnavailable => Ok(Self::StorageUnavailable),
            pb::OpenId4VciErrorReason::EncodingFailed => Ok(Self::EncodingFailed),
            _ => Err(ProtoError::InvalidEnum),
        }
    }
}

impl FromDomainReason<CredentialErrorCode> for pb::OpenId4VciErrorReason {
    fn from_domain_reason(value: CredentialErrorCode) -> Self {
        match value {
            CredentialErrorCode::InvalidCredentialRequest => Self::InvalidRequest,
            CredentialErrorCode::InvalidProof => Self::InvalidProof,
            CredentialErrorCode::InvalidNonce => Self::InvalidNonce,
            CredentialErrorCode::UnknownCredentialConfiguration => Self::UnsupportedCredential,
            CredentialErrorCode::UnknownCredentialIdentifier => Self::UnknownCredentialIdentifier,
            CredentialErrorCode::InvalidEncryptionParameters => Self::InvalidEncryptionParameters,
            CredentialErrorCode::CredentialRequestDenied => Self::CredentialRequestDenied,
            _ => Self::InvalidRequest,
        }
    }
}

impl FromProtoReason for CredentialErrorCode {
    fn from_proto_reason(value: pb::OpenId4VciErrorReason) -> ProtoResult<Self> {
        match value {
            pb::OpenId4VciErrorReason::InvalidRequest => Ok(Self::InvalidCredentialRequest),
            pb::OpenId4VciErrorReason::InvalidProof => Ok(Self::InvalidProof),
            pb::OpenId4VciErrorReason::InvalidNonce => Ok(Self::InvalidNonce),
            pb::OpenId4VciErrorReason::UnsupportedCredential => {
                Ok(Self::UnknownCredentialConfiguration)
            }
            pb::OpenId4VciErrorReason::UnknownCredentialIdentifier => {
                Ok(Self::UnknownCredentialIdentifier)
            }
            pb::OpenId4VciErrorReason::InvalidEncryptionParameters => {
                Ok(Self::InvalidEncryptionParameters)
            }
            pb::OpenId4VciErrorReason::CredentialRequestDenied => Ok(Self::CredentialRequestDenied),
            _ => Err(ProtoError::InvalidEnum),
        }
    }
}

impl FromDomainReason<DeferredCredentialErrorCode> for pb::OpenId4VciErrorReason {
    fn from_domain_reason(value: DeferredCredentialErrorCode) -> Self {
        match value {
            DeferredCredentialErrorCode::InvalidCredentialRequest => Self::InvalidRequest,
            DeferredCredentialErrorCode::InvalidTransactionId => Self::InvalidTransaction,
            DeferredCredentialErrorCode::InvalidEncryptionParameters => {
                Self::InvalidEncryptionParameters
            }
            DeferredCredentialErrorCode::CredentialRequestDenied => Self::CredentialRequestDenied,
            _ => Self::InvalidRequest,
        }
    }
}

impl FromProtoReason for DeferredCredentialErrorCode {
    fn from_proto_reason(value: pb::OpenId4VciErrorReason) -> ProtoResult<Self> {
        match value {
            pb::OpenId4VciErrorReason::InvalidRequest => Ok(Self::InvalidCredentialRequest),
            pb::OpenId4VciErrorReason::InvalidTransaction => Ok(Self::InvalidTransactionId),
            pb::OpenId4VciErrorReason::InvalidEncryptionParameters => {
                Ok(Self::InvalidEncryptionParameters)
            }
            pb::OpenId4VciErrorReason::CredentialRequestDenied => Ok(Self::CredentialRequestDenied),
            _ => Err(ProtoError::InvalidEnum),
        }
    }
}

impl FromDomainReason<NotificationErrorCode> for pb::OpenId4VciErrorReason {
    fn from_domain_reason(value: NotificationErrorCode) -> Self {
        match value {
            NotificationErrorCode::InvalidNotificationRequest => Self::InvalidNotification,
            NotificationErrorCode::InvalidNotificationId => Self::InvalidNotificationId,
            _ => Self::InvalidNotification,
        }
    }
}

impl FromProtoReason for NotificationErrorCode {
    fn from_proto_reason(value: pb::OpenId4VciErrorReason) -> ProtoResult<Self> {
        match value {
            pb::OpenId4VciErrorReason::InvalidNotification => Ok(Self::InvalidNotificationRequest),
            pb::OpenId4VciErrorReason::InvalidNotificationId => Ok(Self::InvalidNotificationId),
            _ => Err(ProtoError::InvalidEnum),
        }
    }
}

impl FromDomainReason<ProblemType> for pb::OpenId4VciErrorReason {
    fn from_domain_reason(value: ProblemType) -> Self {
        match value {
            ProblemType::InvalidRequest => Self::InvalidRequest,
            ProblemType::InvalidProof => Self::InvalidProof,
            ProblemType::InvalidNonce => Self::InvalidNonce,
            ProblemType::InvalidNotificationId => Self::InvalidNotificationId,
            ProblemType::InvalidNotificationRequest => Self::InvalidNotification,
            ProblemType::UnsupportedCredential => Self::UnsupportedCredential,
            ProblemType::UnknownCredentialIdentifier => Self::UnknownCredentialIdentifier,
            ProblemType::EncryptionRequired => Self::EncryptionRequired,
            ProblemType::InvalidTransaction => Self::InvalidTransaction,
            ProblemType::PayloadTooLarge => Self::PayloadTooLarge,
            ProblemType::StorageUnavailable => Self::StorageUnavailable,
            ProblemType::ServerError => Self::ServerError,
        }
    }
}

impl FromProtoReason for ProblemType {
    fn from_proto_reason(value: pb::OpenId4VciErrorReason) -> ProtoResult<Self> {
        match value {
            pb::OpenId4VciErrorReason::InvalidRequest => Ok(Self::InvalidRequest),
            pb::OpenId4VciErrorReason::InvalidProof => Ok(Self::InvalidProof),
            pb::OpenId4VciErrorReason::InvalidNonce => Ok(Self::InvalidNonce),
            pb::OpenId4VciErrorReason::InvalidNotificationId => Ok(Self::InvalidNotificationId),
            pb::OpenId4VciErrorReason::InvalidNotification => Ok(Self::InvalidNotificationRequest),
            pb::OpenId4VciErrorReason::UnsupportedCredential => Ok(Self::UnsupportedCredential),
            pb::OpenId4VciErrorReason::UnknownCredentialIdentifier => {
                Ok(Self::UnknownCredentialIdentifier)
            }
            pb::OpenId4VciErrorReason::EncryptionRequired => Ok(Self::EncryptionRequired),
            pb::OpenId4VciErrorReason::InvalidTransaction => Ok(Self::InvalidTransaction),
            pb::OpenId4VciErrorReason::PayloadTooLarge => Ok(Self::PayloadTooLarge),
            pb::OpenId4VciErrorReason::StorageUnavailable => Ok(Self::StorageUnavailable),
            pb::OpenId4VciErrorReason::ServerError => Ok(Self::ServerError),
            _ => Err(ProtoError::InvalidEnum),
        }
    }
}

impl FromDomainReason<ProfilePolicyStatus> for pb::OpenId4VciErrorReason {
    fn from_domain_reason(value: ProfilePolicyStatus) -> Self {
        match value {
            ProfilePolicyStatus::CredentialConfigurationRequired => {
                Self::ProfileCredentialConfigurationRequired
            }
            ProfilePolicyStatus::UnsupportedCredentialFormat => {
                Self::ProfileUnsupportedCredentialFormat
            }
            ProfilePolicyStatus::CredentialConfigurationScopeRequired => {
                Self::ProfileCredentialConfigurationScopeRequired
            }
            ProfilePolicyStatus::ProofRequired => Self::ProfileProofRequired,
            ProfilePolicyStatus::NonceEndpointRequired => Self::ProfileNonceEndpointRequired,
            ProfilePolicyStatus::KeyAttestationRequired => Self::ProfileKeyAttestationRequired,
            ProfilePolicyStatus::WalletAttestationRequired => {
                Self::ProfileWalletAttestationRequired
            }
            ProfilePolicyStatus::DpopRequired => Self::ProfileDpopRequired,
            ProfilePolicyStatus::ParRequired => Self::ProfileParRequired,
            ProfilePolicyStatus::AuthorizationCodeGrantRequired => {
                Self::ProfileAuthorizationCodeGrantRequired
            }
            ProfilePolicyStatus::PkceS256Required => Self::ProfilePkceS256Required,
            ProfilePolicyStatus::AuthorizationResponseIssuerRequired => {
                Self::ProfileAuthorizationResponseIssuerRequired
            }
            ProfilePolicyStatus::OauthClientAuthenticationRequired => {
                Self::ProfileOauthClientAuthenticationRequired
            }
            ProfilePolicyStatus::RequestEncryptionSupportRequired => {
                Self::ProfileRequestEncryptionSupportRequired
            }
            ProfilePolicyStatus::RequestEncryptionRequired => {
                Self::ProfileRequestEncryptionRequired
            }
            ProfilePolicyStatus::ResponseEncryptionSupportRequired => {
                Self::ProfileResponseEncryptionSupportRequired
            }
            ProfilePolicyStatus::ResponseEncryptionRequired => {
                Self::ProfileResponseEncryptionRequired
            }
        }
    }
}

impl FromProtoReason for ProfilePolicyStatus {
    fn from_proto_reason(value: pb::OpenId4VciErrorReason) -> ProtoResult<Self> {
        match value {
            pb::OpenId4VciErrorReason::ProfileCredentialConfigurationRequired => {
                Ok(Self::CredentialConfigurationRequired)
            }
            pb::OpenId4VciErrorReason::ProfileUnsupportedCredentialFormat => {
                Ok(Self::UnsupportedCredentialFormat)
            }
            pb::OpenId4VciErrorReason::ProfileCredentialConfigurationScopeRequired => {
                Ok(Self::CredentialConfigurationScopeRequired)
            }
            pb::OpenId4VciErrorReason::ProfileProofRequired => Ok(Self::ProofRequired),
            pb::OpenId4VciErrorReason::ProfileNonceEndpointRequired => {
                Ok(Self::NonceEndpointRequired)
            }
            pb::OpenId4VciErrorReason::ProfileKeyAttestationRequired => {
                Ok(Self::KeyAttestationRequired)
            }
            pb::OpenId4VciErrorReason::ProfileWalletAttestationRequired => {
                Ok(Self::WalletAttestationRequired)
            }
            pb::OpenId4VciErrorReason::ProfileDpopRequired => Ok(Self::DpopRequired),
            pb::OpenId4VciErrorReason::ProfileParRequired => Ok(Self::ParRequired),
            pb::OpenId4VciErrorReason::ProfileAuthorizationCodeGrantRequired => {
                Ok(Self::AuthorizationCodeGrantRequired)
            }
            pb::OpenId4VciErrorReason::ProfilePkceS256Required => Ok(Self::PkceS256Required),
            pb::OpenId4VciErrorReason::ProfileAuthorizationResponseIssuerRequired => {
                Ok(Self::AuthorizationResponseIssuerRequired)
            }
            pb::OpenId4VciErrorReason::ProfileOauthClientAuthenticationRequired => {
                Ok(Self::OauthClientAuthenticationRequired)
            }
            pb::OpenId4VciErrorReason::ProfileRequestEncryptionSupportRequired => {
                Ok(Self::RequestEncryptionSupportRequired)
            }
            pb::OpenId4VciErrorReason::ProfileRequestEncryptionRequired => {
                Ok(Self::RequestEncryptionRequired)
            }
            pb::OpenId4VciErrorReason::ProfileResponseEncryptionSupportRequired => {
                Ok(Self::ResponseEncryptionSupportRequired)
            }
            pb::OpenId4VciErrorReason::ProfileResponseEncryptionRequired => {
                Ok(Self::ResponseEncryptionRequired)
            }
            _ => Err(ProtoError::InvalidEnum),
        }
    }
}

impl FromDomainReason<ProtoCodecError> for pb::OpenId4VciErrorReason {
    fn from_domain_reason(value: ProtoCodecError) -> Self {
        match value {
            ProtoCodecError::PayloadTooLarge => Self::PayloadTooLarge,
            ProtoCodecError::Decode => Self::ProtoDecode,
            ProtoCodecError::JsonSerialize => Self::ProtoJsonSerialize,
            ProtoCodecError::JsonDeserialize => Self::ProtoJsonDeserialize,
        }
    }
}

impl FromProtoReason for ProtoCodecError {
    fn from_proto_reason(value: pb::OpenId4VciErrorReason) -> ProtoResult<Self> {
        match value {
            pb::OpenId4VciErrorReason::PayloadTooLarge => Ok(Self::PayloadTooLarge),
            pb::OpenId4VciErrorReason::ProtoDecode => Ok(Self::Decode),
            pb::OpenId4VciErrorReason::ProtoJsonSerialize => Ok(Self::JsonSerialize),
            pb::OpenId4VciErrorReason::ProtoJsonDeserialize => Ok(Self::JsonDeserialize),
            _ => Err(ProtoError::InvalidEnum),
        }
    }
}

impl FromDomainReason<ProtoError> for pb::OpenId4VciErrorReason {
    fn from_domain_reason(value: ProtoError) -> Self {
        match value {
            ProtoError::MissingRequiredField => Self::ProtoMissingRequiredField,
            ProtoError::InvalidEnum => Self::ProtoInvalidEnum,
            ProtoError::InvalidJson => Self::ProtoInvalidJson,
            ProtoError::PayloadTooLarge => Self::PayloadTooLarge,
            ProtoError::InvalidWireValue => Self::ProtoInvalidWireValue,
        }
    }
}
