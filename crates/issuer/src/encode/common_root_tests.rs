// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::Message;
use openid4vci_proto::generated::proto::reallyme::openid4vci::v1 as pb;
use reallyme_codec::base64url::bytes_to_base64url;
use serde_json::Value;

use super::{
    validate_common_root_payload, CommonRootProofBinding, COMMON_ROOT_PROFILE, DIGEST_BYTES,
    P256_COORDINATE_BYTES, P256_SIGNATURE_BYTES,
};
use crate::{IssuerResult, IssuerStatus};

#[test]
fn proof_binding_debug_redacts_material() {
    let binding = binding();

    let debug = format!("{binding:?}");

    assert!(debug.contains(COMMON_ROOT_PROFILE));
    assert!(!debug.contains("envelope_hash"));
}

#[test]
fn malformed_payload_rejects_unversioned_wire_value() -> IssuerResult<()> {
    let value = Value::String(bytes_to_base64url(
        &pb::ReallyMeZkV1Credential::default().encode_to_vec(),
    ));
    assert_eq!(
        validate_common_root_payload(&value)
            .err()
            .map(|error| error.status()),
        Some(IssuerStatus::EncodingFailed)
    );
    Ok(())
}

fn binding() -> CommonRootProofBinding {
    CommonRootProofBinding {
        envelope_hash: [0x10; DIGEST_BYTES],
        claims_root: [0x11; DIGEST_BYTES],
        issuer_public_key_x: [0x12; P256_COORDINATE_BYTES],
        issuer_public_key_y: [0x13; P256_COORDINATE_BYTES],
        subject_public_key_x: [0x14; P256_COORDINATE_BYTES],
        subject_public_key_y: [0x15; P256_COORDINATE_BYTES],
        issuer_envelope_signature: [0x16; P256_SIGNATURE_BYTES],
        issuer_root_binding_signature: [0x17; P256_SIGNATURE_BYTES],
        issuer_subject_binding_signature: [0x18; P256_SIGNATURE_BYTES],
        issuer_validity_status_signature: [0x1a; P256_SIGNATURE_BYTES],
        issuance_binding: [0x19; DIGEST_BYTES],
    }
}
