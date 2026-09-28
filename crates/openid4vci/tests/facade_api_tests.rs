// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Public facade API checks for SDK consumers.

use reallyme_openid4vci::{attestation, issuer, types, wallet};

#[test]
fn root_facade_exposes_core_sdk_modules() {
    let nonce = types::NonceResponse::new("nonce-1".to_owned());
    assert!(nonce.is_ok());
    let _wallet_status = wallet::WalletStatus::InvalidRequest;
    let _issuer_status = issuer::IssuerStatus::InvalidRequest;
    assert!(issuer::AuthenticatedNonceManager::with_generated_key().is_ok());
    let _attestation_status = attestation::AttestationStatus::InvalidJwt;
    let _attestation_evidence_input: Option<attestation::KeyAttestationTrustEvidenceInput> = None;
    let _signed_metadata_evidence_input: Option<wallet::SignedMetadataTrustEvidenceInput> = None;
    let _stale_attestation = issuer::IssuerStatus::AttestationTrustEvidenceStale;
    let _future_signed_metadata = wallet::WalletStatus::SignedMetadataTrustEvidenceFutureIssued;
}

#[test]
fn root_facade_exposes_sdk_policy() {
    let policy = reallyme_openid4vci::policy::OpenId4VciProtocolPolicy::production();

    assert!(policy.wallet_attestation_required);
    assert!(policy.key_attestation_required);
    assert!(policy.dpop_required);
    assert!(policy.par_required);
}

#[cfg(feature = "profiles")]
#[test]
fn root_facade_exposes_profile_policy() {
    let policy = reallyme_openid4vci::profiles::haip_policy();
    assert!(policy.is_eidas_relevant());
}

#[cfg(feature = "codec")]
#[test]
fn canonical_sdk_surface_uses_generated_messages_and_bounded_codecs() {
    assert_eq!(
        reallyme_openid4vci::sdk::protobuf::OPENID4VCI_PROTO_PACKAGE,
        "reallyme.openid4vci.v1"
    );
    let request =
        reallyme_openid4vci::sdk::protobuf::proto::reallyme::openid4vci::v1::GetNonceRequest {
            ..Default::default()
        };
    let encoded = reallyme_openid4vci::sdk::encode_proto(&request);
    assert!(encoded.is_ok());
    if let Ok(encoded) = encoded {
        let decoded = reallyme_openid4vci::sdk::decode_proto::<
            reallyme_openid4vci::sdk::protobuf::proto::reallyme::openid4vci::v1::GetNonceRequest,
        >(&encoded);
        assert!(decoded.is_ok());
    }
}

#[cfg(feature = "codec")]
#[test]
fn canonical_sdk_surface_exposes_typed_shared_error_envelopes() {
    let reason = reallyme_openid4vci::sdk::error::OpenId4VciErrorReason::InvalidRequest;
    let envelope = reallyme_openid4vci::sdk::error::identity_stack_error_from_reason(reason, None);
    let decoded =
        reallyme_openid4vci::sdk::error::error_reason_from_identity_stack_error(&envelope);

    assert_eq!(decoded.ok(), Some(reason));
    assert_eq!(
        envelope.reason_code,
        reallyme_openid4vci::sdk::error::error_reason_code(reason)
    );
    assert_eq!(
        reallyme_openid4vci::sdk::MAX_OPENID4VCI_PROTO_MESSAGE_BYTES,
        64 * 1024
    );
}

#[cfg(feature = "http")]
#[test]
fn root_facade_exposes_http_service_boundary() {
    let _headers = reallyme_openid4vci::http::NO_STORE_JSON_HEADERS;
}
