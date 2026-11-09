// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Common-root wire payload and request-binding tests.

use openid4vci_issuer::{
    encode_immediate_response, CommonRootCredentialEncoder, CommonRootIssuanceRequestBinding,
    CommonRootIssuedCredential, IssuanceStatusEvidence, IssuedCredential, IssuerResult,
    IssuerStatus, PassThroughCredentialEncoder,
};
use openid4vci_types::{CredentialFormat, CredentialPayload};
use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_credential_status::status_list_signing_payload;
use reallyme_crypto::{core::Algorithm as CryptoAlgorithm, dispatch::sign};
use reallyme_zk_api::ZkCommonCredentialRootClaim;
use serde_json::{json, Value};

use crate::support::{
    assert_rejects_tampered_request_field, assert_rejects_tampered_response_field,
    common_root_zk_material, decode_wire_payload, encoded_wire_bytes, encoding_error,
    first_compact_credential, issuer_status_verifier, p256_uncompressed, request,
    request_for_configuration, signed_active_status_list, tamper_request_root,
    tamper_request_with_duplicate_version, tamper_wire_payload, zk_issued_credential,
    zk_request_for_issued, AuthorizedClaimDecision, STATUS_TEST_FRESHNESS, STATUS_TEST_NOW,
};

#[test]
fn common_root_sha256_encoder_emits_canonical_reallyme_zk_payload() -> IssuerResult<()> {
    let encoder = CommonRootCredentialEncoder::new();
    let issued = zk_issued_credential()?;
    let request = zk_request_for_issued(&issued)?;
    let issued = [issued];

    let response = encode_immediate_response(&request, &encoder, &issued, None)?;
    let credential = response
        .credentials
        .as_ref()
        .and_then(|credentials| credentials.first())
        .ok_or(openid4vci_issuer::IssuerError::new(
            openid4vci_issuer::IssuerStatus::EncodingFailed,
        ))?;

    let CredentialPayload::Compact(value) = &credential.credential else {
        return Err(openid4vci_issuer::IssuerError::new(
            openid4vci_issuer::IssuerStatus::EncodingFailed,
        ));
    };
    let wire = decode_wire_payload(value)?;
    assert_eq!(wire.version, 1);
    assert!(!wire.credential_envelope_pb.is_empty());
    assert!(!wire.status_list_pb.is_empty());
    assert!(wire.proof_binding.is_set());
    assert_eq!(wire.verified_holder_public_key.len(), 65);
    assert_eq!(wire.lineage_tag_commitment.len(), 32);
    assert_eq!(wire.wallet_opening_commitment.len(), 32);
    assert_eq!(wire.opaque_lineage_leaf.len(), 32);
    Ok(())
}

#[test]
fn same_authorized_claim_decision_can_encode_sd_jwt_and_zk_configurations() -> IssuerResult<()> {
    let prepared = common_root_zk_material()?;
    let claim = AuthorizedClaimDecision {
        name: "age",
        value: b"42",
        salt: prepared.claim_salt,
    };

    let sd_jwt_request = request_for_configuration("pid-sd-jwt");
    let sd_jwt_issued = claim.sd_jwt_issued_credential()?;
    let sd_jwt_response = encode_immediate_response(
        &sd_jwt_request,
        &PassThroughCredentialEncoder::new(CredentialFormat::SdJwtVc),
        &[sd_jwt_issued],
        None,
    )?;
    let sd_jwt_receipt = first_compact_credential(&sd_jwt_response)?;
    assert_eq!(sd_jwt_receipt, claim.expected_sd_jwt_compact());

    let zk_issued = claim.zk_issued_credential(&prepared)?;
    let mut zk_request = zk_request_for_issued(&zk_issued)?;
    zk_request.credential_configuration_id = Some("pid-zk".to_owned());
    let zk_response = encode_immediate_response(
        &zk_request,
        &CommonRootCredentialEncoder::new(),
        &[zk_issued],
        None,
    )?;
    let zk_receipt = first_compact_credential(&zk_response)?;
    let zk_wire = decode_wire_payload(zk_receipt)?;
    let proof_binding = zk_wire.proof_binding.as_option().ok_or(encoding_error())?;

    assert_eq!(
        sd_jwt_request.credential_configuration_id.as_deref(),
        Some("pid-sd-jwt")
    );
    assert_eq!(
        zk_request.credential_configuration_id.as_deref(),
        Some("pid-zk")
    );
    assert_eq!(
        proof_binding.claims_root,
        prepared.material.proof_binding.claims_root
    );
    assert_eq!(
        zk_wire.verified_holder_public_key,
        p256_uncompressed(&prepared.material.holder_public_key)?
    );
    assert_eq!(zk_wire.lineage_tag_commitment, [0x44; 32]);
    assert_eq!(zk_wire.wallet_opening_commitment, [0x55; 32]);
    assert_eq!(zk_wire.opaque_lineage_leaf, prepared.opaque_lineage_leaf);
    Ok(())
}

#[test]
fn common_root_sha256_encoder_rejects_wrong_format() -> IssuerResult<()> {
    let encoder = CommonRootCredentialEncoder::new();
    let issued = [IssuedCredential::new(
        CredentialFormat::SdJwtVc,
        json!({"format": "reallyme_zk_v1"}),
    )?];

    let result = encode_immediate_response(&request(), &encoder, &issued, None);

    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::UnsupportedCredential)
    );
    Ok(())
}

#[test]
fn common_root_issuance_request_binding_rejects_zero_fields() {
    let valid_lineage = [0x44; 32];
    let valid_opening = [0x55; 32];
    let valid_leaf = [0x66; 32];

    assert_eq!(
        CommonRootIssuanceRequestBinding::new([0; 32], valid_opening, valid_leaf)
            .err()
            .map(|error| error.status()),
        Some(IssuerStatus::EncodingFailed)
    );
    assert_eq!(
        CommonRootIssuanceRequestBinding::new(valid_lineage, [0; 32], valid_leaf)
            .err()
            .map(|error| error.status()),
        Some(IssuerStatus::EncodingFailed)
    );
    assert_eq!(
        CommonRootIssuanceRequestBinding::new(valid_lineage, valid_opening, [0; 32])
            .err()
            .map(|error| error.status()),
        Some(IssuerStatus::EncodingFailed)
    );
}

#[test]
fn common_root_encoder_rejects_mutated_trusted_zk_payload() -> IssuerResult<()> {
    let encoder = CommonRootCredentialEncoder::new();
    let mut issued = zk_issued_credential()?;
    let replacement = zk_issued_credential()?;
    let request = zk_request_for_issued(&replacement)?;
    issued.credential = replacement.credential.clone();

    let result = encode_immediate_response(&request, &encoder, &[issued], None);

    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::EncodingFailed)
    );
    Ok(())
}

#[test]
fn common_root_sha256_encoder_rejects_malformed_binding() -> IssuerResult<()> {
    let encoder = CommonRootCredentialEncoder::new();
    let mut issued = zk_issued_credential()?;
    let request = zk_request_for_issued(&issued)?;
    tamper_wire_payload(&mut issued, |wire| {
        if let Some(binding) = wire.proof_binding.as_option_mut() {
            binding.envelope_hash[0] ^= 1;
        }
    })?;

    let result = encode_immediate_response(&request, &encoder, &[issued], None);

    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::EncodingFailed)
    );
    Ok(())
}

#[test]
fn common_root_sha256_encoder_rejects_changed_issuance_commitment() -> IssuerResult<()> {
    let encoder = CommonRootCredentialEncoder::new();
    let mut issued = zk_issued_credential()?;
    let request = zk_request_for_issued(&issued)?;
    tamper_wire_payload(&mut issued, |wire| {
        if let Some(binding) = wire.proof_binding.as_option_mut() {
            binding.issuance_binding[0] ^= 1;
        }
    })?;
    let result = encode_immediate_response(&request, &encoder, &[issued], None);
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::EncodingFailed)
    );
    Ok(())
}

#[test]
fn common_root_sha256_encoder_rejects_changed_validity_status_signature() -> IssuerResult<()> {
    let encoder = CommonRootCredentialEncoder::new();
    let mut issued = zk_issued_credential()?;
    let request = zk_request_for_issued(&issued)?;
    tamper_wire_payload(&mut issued, |wire| {
        if let Some(binding) = wire.proof_binding.as_option_mut() {
            binding.issuer_validity_status_signature[0] ^= 1;
        }
    })?;
    let result = encode_immediate_response(&request, &encoder, &[issued], None);
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::EncodingFailed)
    );
    Ok(())
}

#[test]
fn common_root_sha256_issued_payload_rejects_status_pointer_mismatch() -> IssuerResult<()> {
    let prepared = common_root_zk_material()?;
    let mut status = signed_active_status_list(&prepared.material.issuer_private_key)?;
    status.list_id = Some([9_u8; 32]);
    status.signature.sig_bytes = sign(
        CryptoAlgorithm::P256,
        &prepared.material.issuer_private_key,
        &status_list_signing_payload(&status).map_err(|_| encoding_error())?,
    )
    .map_err(|_| encoding_error())?;
    let claims = [ZkCommonCredentialRootClaim {
        name: "age",
        value: b"42",
        salt: &prepared.claim_salt,
    }];

    let result = CommonRootIssuedCredential::from_authorized_common_root_issuance(
        &prepared.material.envelope,
        &prepared.material.proof_binding,
        &prepared.material.issuer_public_key,
        &IssuanceStatusEvidence::new(
            &status,
            &issuer_status_verifier(&prepared.material),
            STATUS_TEST_NOW,
            STATUS_TEST_FRESHNESS,
        ),
        &prepared.material.holder_public_key,
        prepared.request_binding()?,
        &claims,
    );

    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::EncodingFailed)
    );
    Ok(())
}

#[test]
fn common_root_sha256_encoder_rejects_extension_fields() -> IssuerResult<()> {
    let encoder = CommonRootCredentialEncoder::new();
    let mut issued = zk_issued_credential()?;
    let request = zk_request_for_issued(&issued)?;
    let mut bytes = encoded_wire_bytes(&issued)?;
    bytes.extend_from_slice(&[0x98, 0x06, 0x01]);
    issued.credential = Value::String(bytes_to_base64url(&bytes));

    let result = encode_immediate_response(&request, &encoder, &[issued], None);

    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::EncodingFailed)
    );
    Ok(())
}

#[test]
fn common_root_sha256_encoder_rejects_duplicate_wire_version() -> IssuerResult<()> {
    let encoder = CommonRootCredentialEncoder::new();
    let mut issued = zk_issued_credential()?;
    let request = zk_request_for_issued(&issued)?;
    let mut bytes = encoded_wire_bytes(&issued)?;
    bytes.extend_from_slice(&[0x08, 0x01]);
    issued.credential = Value::String(bytes_to_base64url(&bytes));
    let result = encode_immediate_response(&request, &encoder, &[issued], None);
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::EncodingFailed)
    );
    Ok(())
}

#[test]
fn common_root_sha256_encoder_rejects_wrong_profile() -> IssuerResult<()> {
    let encoder = CommonRootCredentialEncoder::new();
    let mut issued = zk_issued_credential()?;
    let request = zk_request_for_issued(&issued)?;
    tamper_wire_payload(&mut issued, |wire| {
        wire.version = 2;
    })?;

    let result = encode_immediate_response(&request, &encoder, &[issued], None);

    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::EncodingFailed)
    );
    Ok(())
}

#[test]
fn common_root_sha256_rejects_malformed_manual_proto_payload() -> IssuerResult<()> {
    let encoder = CommonRootCredentialEncoder::new();
    let mut issued = zk_issued_credential()?;
    let request = zk_request_for_issued(&issued)?;
    issued.credential = Value::String("AQ".to_owned());

    let result = encode_immediate_response(&request, &encoder, &[issued], None);

    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::EncodingFailed)
    );
    Ok(())
}

#[test]
fn common_root_sha256_encoder_rejects_missing_issuance_request() -> IssuerResult<()> {
    let encoder = CommonRootCredentialEncoder::new();
    let issued = zk_issued_credential()?;

    let result = encode_immediate_response(&request(), &encoder, &[issued], None);

    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::EncodingFailed)
    );
    Ok(())
}

#[test]
fn common_root_sha256_encoder_rejects_mismatched_requested_root() -> IssuerResult<()> {
    let encoder = CommonRootCredentialEncoder::new();
    let issued = zk_issued_credential()?;
    let mut request = zk_request_for_issued(&issued)?;
    tamper_request_root(&mut request)?;

    let result = encode_immediate_response(&request, &encoder, &[issued], None);

    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::EncodingFailed)
    );
    Ok(())
}

#[test]
fn common_root_sha256_encoder_rejects_mismatched_request_commitments() -> IssuerResult<()> {
    assert_rejects_tampered_request_field(|wire| wire.lineage_tag_commitment[0] ^= 1)?;
    assert_rejects_tampered_request_field(|wire| wire.wallet_opening_commitment[0] ^= 1)?;
    assert_rejects_tampered_request_field(|wire| wire.opaque_lineage_leaf[0] ^= 1)?;
    Ok(())
}

#[test]
fn common_root_sha256_encoder_rejects_mismatched_response_commitments() -> IssuerResult<()> {
    assert_rejects_tampered_response_field(|wire| wire.lineage_tag_commitment[0] ^= 1)?;
    assert_rejects_tampered_response_field(|wire| wire.wallet_opening_commitment[0] ^= 1)?;
    assert_rejects_tampered_response_field(|wire| wire.opaque_lineage_leaf[0] ^= 1)?;
    Ok(())
}

#[test]
fn common_root_sha256_encoder_rejects_duplicate_request_version() -> IssuerResult<()> {
    let encoder = CommonRootCredentialEncoder::new();
    let issued = zk_issued_credential()?;
    let mut request = zk_request_for_issued(&issued)?;
    tamper_request_with_duplicate_version(&mut request)?;

    let result = encode_immediate_response(&request, &encoder, &[issued], None);

    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::EncodingFailed)
    );
    Ok(())
}
