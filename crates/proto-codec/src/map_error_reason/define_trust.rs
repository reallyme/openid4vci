// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Trust-evidence error mappings for attestation and wallet boundaries.

use openid4vci_attestation::AttestationStatus;
use openid4vci_proto::generated::proto::reallyme::openid4vci::v1 as pb;
use reallyme_openid4vci_wallet::WalletStatus;

use super::define::{FromDomainReason, FromProtoReason};
use crate::convert::{ProtoError, ProtoResult};

impl FromDomainReason<AttestationStatus> for pb::OpenId4VciErrorReason {
    fn from_domain_reason(value: AttestationStatus) -> Self {
        match value {
            AttestationStatus::MissingJwt => Self::AttestationMissingJwt,
            AttestationStatus::InvalidJwt => Self::AttestationInvalidJwt,
            AttestationStatus::InvalidHeader => Self::AttestationInvalidHeader,
            AttestationStatus::InvalidClaims => Self::AttestationInvalidClaims,
            AttestationStatus::InvalidNonce => Self::AttestationInvalidNonce,
            AttestationStatus::UnsupportedAlgorithm => Self::AttestationUnsupportedAlgorithm,
            AttestationStatus::AlgorithmNotAllowed => Self::AttestationAlgorithmNotAllowed,
            AttestationStatus::Expired => Self::AttestationExpired,
            AttestationStatus::FutureIssued => Self::AttestationFutureIssued,
            AttestationStatus::Stale => Self::AttestationStale,
            AttestationStatus::UnsupportedAttestedKey => Self::AttestationUnsupportedKey,
            AttestationStatus::DuplicateAttestedKey => Self::AttestationDuplicateKey,
            AttestationStatus::SignatureRejected => Self::AttestationSignatureInvalid,
            AttestationStatus::TrustRejected => Self::AttestationTrustInvalid,
            AttestationStatus::TrustIndeterminate => Self::AttestationTrustUndetermined,
            AttestationStatus::TrustEvidenceStale => Self::AttestationTrustEvidenceStale,
            AttestationStatus::TrustEvidenceFutureIssued => {
                Self::AttestationTrustEvidenceFutureIssued
            }
            AttestationStatus::StatusRejected => Self::AttestationStatusInvalid,
            AttestationStatus::StatusIndeterminate => Self::AttestationStatusUndetermined,
            AttestationStatus::InvalidTrustEvidence => Self::AttestationInvalidTrustEvidence,
        }
    }
}

impl FromProtoReason for AttestationStatus {
    fn from_proto_reason(value: pb::OpenId4VciErrorReason) -> ProtoResult<Self> {
        match value {
            pb::OpenId4VciErrorReason::AttestationMissingJwt => Ok(Self::MissingJwt),
            pb::OpenId4VciErrorReason::AttestationInvalidJwt => Ok(Self::InvalidJwt),
            pb::OpenId4VciErrorReason::AttestationInvalidHeader => Ok(Self::InvalidHeader),
            pb::OpenId4VciErrorReason::AttestationInvalidClaims => Ok(Self::InvalidClaims),
            pb::OpenId4VciErrorReason::AttestationInvalidNonce => Ok(Self::InvalidNonce),
            pb::OpenId4VciErrorReason::AttestationUnsupportedAlgorithm => {
                Ok(Self::UnsupportedAlgorithm)
            }
            pb::OpenId4VciErrorReason::AttestationAlgorithmNotAllowed => {
                Ok(Self::AlgorithmNotAllowed)
            }
            pb::OpenId4VciErrorReason::AttestationExpired => Ok(Self::Expired),
            pb::OpenId4VciErrorReason::AttestationFutureIssued => Ok(Self::FutureIssued),
            pb::OpenId4VciErrorReason::AttestationStale => Ok(Self::Stale),
            pb::OpenId4VciErrorReason::AttestationUnsupportedKey => {
                Ok(Self::UnsupportedAttestedKey)
            }
            pb::OpenId4VciErrorReason::AttestationDuplicateKey => Ok(Self::DuplicateAttestedKey),
            pb::OpenId4VciErrorReason::AttestationSignatureInvalid => Ok(Self::SignatureRejected),
            pb::OpenId4VciErrorReason::AttestationTrustInvalid => Ok(Self::TrustRejected),
            pb::OpenId4VciErrorReason::AttestationTrustUndetermined => Ok(Self::TrustIndeterminate),
            pb::OpenId4VciErrorReason::AttestationTrustEvidenceStale => {
                Ok(Self::TrustEvidenceStale)
            }
            pb::OpenId4VciErrorReason::AttestationTrustEvidenceFutureIssued => {
                Ok(Self::TrustEvidenceFutureIssued)
            }
            pb::OpenId4VciErrorReason::AttestationStatusInvalid => Ok(Self::StatusRejected),
            pb::OpenId4VciErrorReason::AttestationStatusUndetermined => {
                Ok(Self::StatusIndeterminate)
            }
            pb::OpenId4VciErrorReason::AttestationInvalidTrustEvidence => {
                Ok(Self::InvalidTrustEvidence)
            }
            _ => Err(ProtoError::InvalidEnum),
        }
    }
}

impl FromDomainReason<WalletStatus> for pb::OpenId4VciErrorReason {
    fn from_domain_reason(value: WalletStatus) -> Self {
        match value {
            WalletStatus::MissingRequiredValue => Self::HolderMissingRequiredValue,
            WalletStatus::InvalidString => Self::HolderInvalidString,
            WalletStatus::InvalidRequest => Self::HolderInvalidRequest,
            WalletStatus::InvalidEncryptionParameters => Self::InvalidEncryptionParameters,
            WalletStatus::EncryptionFailed => Self::EncodingFailed,
            WalletStatus::EncryptedResponseRejected => Self::InvalidCredentialResponse,
            WalletStatus::OfferResolutionRequired => Self::HolderOfferResolutionRequired,
            WalletStatus::InvalidAuthorizationServer => Self::HolderInvalidAuthorizationServer,
            WalletStatus::ResponseEncryptionRequired => Self::HolderResponseEncryptionRequired,
            WalletStatus::RequestEncryptionRequired => Self::HolderRequestEncryptionRequired,
            WalletStatus::IssuerMetadataResolutionFailed => {
                Self::HolderIssuerMetadataResolutionFailed
            }
            WalletStatus::InvalidIssuerMetadata => Self::HolderInvalidIssuerMetadata,
            WalletStatus::IssuerMetadataIssuerMismatch => Self::HolderIssuerMetadataIssuerMismatch,
            WalletStatus::InvalidSignedMetadata => Self::HolderInvalidSignedMetadata,
            WalletStatus::ExpiredSignedMetadata => Self::HolderExpiredSignedMetadata,
            WalletStatus::FutureSignedMetadata => Self::HolderFutureSignedMetadata,
            WalletStatus::StaleSignedMetadata => Self::HolderStaleSignedMetadata,
            WalletStatus::SignedMetadataUnsupportedAlgorithm => {
                Self::HolderSignedMetadataUnsupportedAlgorithm
            }
            WalletStatus::SignedMetadataAlgorithmNotAllowed => {
                Self::HolderSignedMetadataAlgorithmNotAllowed
            }
            WalletStatus::SignedMetadataSignatureRejected => {
                Self::HolderSignedMetadataSignatureRejected
            }
            WalletStatus::UntrustedSignedMetadata => Self::HolderUntrustedSignedMetadata,
            WalletStatus::SignedMetadataTrustIndeterminate => {
                Self::HolderSignedMetadataTrustIndeterminate
            }
            WalletStatus::SignedMetadataTrustEvidenceStale => {
                Self::HolderSignedMetadataTrustEvidenceStale
            }
            WalletStatus::SignedMetadataTrustEvidenceFutureIssued => {
                Self::HolderSignedMetadataTrustEvidenceFutureIssued
            }
            WalletStatus::InvalidSignedMetadataTrustEvidence => {
                Self::HolderInvalidSignedMetadataTrustEvidence
            }
        }
    }
}

impl FromProtoReason for WalletStatus {
    fn from_proto_reason(value: pb::OpenId4VciErrorReason) -> ProtoResult<Self> {
        match value {
            pb::OpenId4VciErrorReason::HolderMissingRequiredValue => Ok(Self::MissingRequiredValue),
            pb::OpenId4VciErrorReason::HolderInvalidString => Ok(Self::InvalidString),
            pb::OpenId4VciErrorReason::HolderInvalidRequest => Ok(Self::InvalidRequest),
            pb::OpenId4VciErrorReason::InvalidEncryptionParameters => {
                Ok(Self::InvalidEncryptionParameters)
            }
            pb::OpenId4VciErrorReason::EncodingFailed => Ok(Self::EncryptionFailed),
            pb::OpenId4VciErrorReason::InvalidCredentialResponse => {
                Ok(Self::EncryptedResponseRejected)
            }
            pb::OpenId4VciErrorReason::HolderOfferResolutionRequired => {
                Ok(Self::OfferResolutionRequired)
            }
            pb::OpenId4VciErrorReason::HolderInvalidAuthorizationServer => {
                Ok(Self::InvalidAuthorizationServer)
            }
            pb::OpenId4VciErrorReason::HolderResponseEncryptionRequired => {
                Ok(Self::ResponseEncryptionRequired)
            }
            pb::OpenId4VciErrorReason::HolderRequestEncryptionRequired => {
                Ok(Self::RequestEncryptionRequired)
            }
            pb::OpenId4VciErrorReason::HolderIssuerMetadataResolutionFailed => {
                Ok(Self::IssuerMetadataResolutionFailed)
            }
            pb::OpenId4VciErrorReason::HolderInvalidIssuerMetadata => {
                Ok(Self::InvalidIssuerMetadata)
            }
            pb::OpenId4VciErrorReason::HolderIssuerMetadataIssuerMismatch => {
                Ok(Self::IssuerMetadataIssuerMismatch)
            }
            pb::OpenId4VciErrorReason::HolderInvalidSignedMetadata => {
                Ok(Self::InvalidSignedMetadata)
            }
            pb::OpenId4VciErrorReason::HolderExpiredSignedMetadata => {
                Ok(Self::ExpiredSignedMetadata)
            }
            pb::OpenId4VciErrorReason::HolderUntrustedSignedMetadata => {
                Ok(Self::UntrustedSignedMetadata)
            }
            pb::OpenId4VciErrorReason::HolderFutureSignedMetadata => Ok(Self::FutureSignedMetadata),
            pb::OpenId4VciErrorReason::HolderStaleSignedMetadata => Ok(Self::StaleSignedMetadata),
            pb::OpenId4VciErrorReason::HolderSignedMetadataUnsupportedAlgorithm => {
                Ok(Self::SignedMetadataUnsupportedAlgorithm)
            }
            pb::OpenId4VciErrorReason::HolderSignedMetadataAlgorithmNotAllowed => {
                Ok(Self::SignedMetadataAlgorithmNotAllowed)
            }
            pb::OpenId4VciErrorReason::HolderSignedMetadataSignatureRejected => {
                Ok(Self::SignedMetadataSignatureRejected)
            }
            pb::OpenId4VciErrorReason::HolderSignedMetadataTrustIndeterminate => {
                Ok(Self::SignedMetadataTrustIndeterminate)
            }
            pb::OpenId4VciErrorReason::HolderSignedMetadataTrustEvidenceStale => {
                Ok(Self::SignedMetadataTrustEvidenceStale)
            }
            pb::OpenId4VciErrorReason::HolderSignedMetadataTrustEvidenceFutureIssued => {
                Ok(Self::SignedMetadataTrustEvidenceFutureIssued)
            }
            pb::OpenId4VciErrorReason::HolderInvalidSignedMetadataTrustEvidence => {
                Ok(Self::InvalidSignedMetadataTrustEvidence)
            }
            _ => Err(ProtoError::InvalidEnum),
        }
    }
}
