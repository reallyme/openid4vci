// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::{Message, MessageField};
use openid4vci_proto::generated::proto::reallyme::openid4vci::v1 as pb;
use reallyme_codec::base64url::bytes_to_base64url;

use super::decode_reallyme_zk_v1_credential;
use crate::{ProtoCodecError, ProtoCodecResult};

fn fixture() -> pb::ReallyMeZkV1Credential {
    let mut binding = pb::ReallyMeZkV1ProofBinding::default();
    binding.version = 1;
    binding.envelope_hash = vec![1; 32];
    binding.claims_root = vec![2; 32];
    binding.issuer_public_key_x = vec![3; 32];
    binding.issuer_public_key_y = vec![4; 32];
    binding.subject_public_key_x = vec![5; 32];
    binding.subject_public_key_y = vec![6; 32];
    binding.issuer_envelope_signature = vec![7; 64];
    binding.issuer_root_binding_signature = vec![8; 64];
    binding.issuer_subject_binding_signature = vec![9; 64];
    binding.issuer_validity_status_signature = vec![14; 64];
    binding.issuance_binding = vec![10; 32];
    let mut wire = pb::ReallyMeZkV1Credential::default();
    wire.version = 1;
    wire.credential_envelope_pb = vec![11];
    wire.status_list_pb = vec![12];
    wire.proof_binding = MessageField::some(binding);
    wire.verified_holder_public_key = vec![13; 65];
    wire.lineage_tag_commitment = vec![14; 32];
    wire.wallet_opening_commitment = vec![15; 32];
    wire.opaque_lineage_leaf = vec![16; 32];
    wire
}

#[test]
fn accepts_canonical_container_without_claiming_issuer_trust() -> ProtoCodecResult<()> {
    let wire = fixture();
    let encoded = bytes_to_base64url(&wire.encode_to_vec());
    let decoded = decode_reallyme_zk_v1_credential(&encoded)?;
    assert_eq!(decoded.credential_envelope_pb(), &[11]);
    assert_eq!(decoded.status_list_pb(), &[12]);
    assert_eq!(decoded.verified_holder_public_key().len(), 65);
    assert_eq!(decoded.lineage_tag_commitment().len(), 32);
    assert_eq!(decoded.wallet_opening_commitment().len(), 32);
    assert_eq!(decoded.opaque_lineage_leaf().len(), 32);
    assert!(decoded.proof_binding().is_ok());
    Ok(())
}

#[test]
fn rejects_missing_binding_and_wrong_fixed_lengths() -> ProtoCodecResult<()> {
    let mut wire = fixture();
    wire.proof_binding = MessageField::none();
    assert!(decode_reallyme_zk_v1_credential(&bytes_to_base64url(&wire.encode_to_vec())).is_err());
    let mut wire = fixture();
    let mut binding = wire
        .proof_binding
        .as_option()
        .cloned()
        .ok_or(ProtoCodecError::Decode)?;
    binding.claims_root.pop();
    wire.proof_binding = MessageField::some(binding);
    assert!(decode_reallyme_zk_v1_credential(&bytes_to_base64url(&wire.encode_to_vec())).is_err());
    let mut wire = fixture();
    wire.wallet_opening_commitment.pop();
    assert!(decode_reallyme_zk_v1_credential(&bytes_to_base64url(&wire.encode_to_vec())).is_err());
    Ok(())
}

#[test]
fn rejects_duplicate_wire_field_and_noncanonical_base64() {
    let mut bytes = fixture().encode_to_vec();
    bytes.extend_from_slice(&[0x08, 0x01]);
    assert!(decode_reallyme_zk_v1_credential(&bytes_to_base64url(&bytes)).is_err());
    let canonical = bytes_to_base64url(&fixture().encode_to_vec());
    assert!(decode_reallyme_zk_v1_credential(&format!("{canonical}=")).is_err());
}
