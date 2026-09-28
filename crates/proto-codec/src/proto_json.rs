// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Closed public allowlist for generated OpenID4VCI ProtoJSON messages.

use buffa::Message;
use openid4vci_proto::generated::proto::reallyme::openid4vci::v1 as pb;
use serde::de::DeserializeOwned;

mod private {
    pub trait Sealed {}
}

/// Generated OpenID4VCI messages approved for the public ProtoJSON boundary.
///
/// This trait is sealed so unrelated Serde types cannot be routed through the
/// codec and accidentally presented as schema-owned OpenID4VCI DTOs.
pub trait OpenId4VciProtoJson:
    Message + serde::Serialize + DeserializeOwned + private::Sealed
{
}

macro_rules! impl_openid4vci_proto_json {
    ($($message:path),+ $(,)?) => {
        $(
            impl private::Sealed for $message {}
            impl OpenId4VciProtoJson for $message {}
        )+
    };
}

impl_openid4vci_proto_json!(
    pb::ProblemDetails,
    pb::TxCode,
    pb::AuthorizationCodeGrant,
    pb::PreAuthorizedCodeGrant,
    pb::CredentialOfferGrants,
    pb::CredentialOffer,
    pb::CredentialOfferUri,
    pb::CredentialSelector,
    pb::Proofs,
    pb::CredentialResponseEncryption,
    pb::CredentialRequest,
    pb::CredentialEnvelope,
    pb::ImmediateCredentialResponse,
    pb::DeferredCredentialResponse,
    pb::CredentialResponse,
    pb::DeferredCredentialRequest,
    pb::NonceRequest,
    pb::NonceResponse,
    pb::GetNonceRequest,
    pb::GetNonceResponse,
    pb::NotificationRequest,
    pb::NotifyRequest,
    pb::NotifyResponse,
    pb::IssueCredentialRequest,
    pb::IssueCredentialResponse,
    pb::CredentialRequestPreflight,
    pb::PreflightCredentialRequest,
    pb::PreflightCredentialResponse,
    pb::GetDeferredCredentialRequest,
    pb::GetDeferredCredentialResponse,
    pb::ProofTypeMetadata,
    pb::ProofTypeMetadataEntry,
    pb::KeyAttestationsRequired,
    pb::CredentialSigningAlg,
    pb::CredentialConfiguration,
    pb::CredentialRequestEncryptionMetadata,
    pb::CredentialResponseEncryptionMetadata,
    pb::BatchCredentialIssuance,
    pb::CredentialConfigurationEntry,
    pb::IssuerMetadata,
    pb::OpenId4VciOperationError,
    pb::OpenId4VciOperationRequest,
    pb::OpenId4VciOperationResult,
    pb::OpenId4VciOperationResponse,
);
