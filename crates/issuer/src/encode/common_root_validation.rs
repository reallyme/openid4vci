// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn common_root_payload(
    credential_pb: &[u8],
    status_list_pb: &[u8],
    verified_holder_public_key: &[u8; P256_SEC1_UNCOMPRESSED_BYTES],
    proof_binding: &CommonRootProofBinding,
    request_binding: &CommonRootIssuanceRequestBinding,
) -> IssuerResult<Value> {
    validate_proto_lengths(credential_pb, status_list_pb)?;
    let mut binding = pb::ReallyMeZkV1ProofBinding::default();
    binding.version = CREDENTIAL_PROOF_BINDING_VERSION;
    binding.envelope_hash = proof_binding.envelope_hash.to_vec();
    binding.claims_root = proof_binding.claims_root.to_vec();
    binding.issuer_public_key_x = proof_binding.issuer_public_key_x.to_vec();
    binding.issuer_public_key_y = proof_binding.issuer_public_key_y.to_vec();
    binding.subject_public_key_x = proof_binding.subject_public_key_x.to_vec();
    binding.subject_public_key_y = proof_binding.subject_public_key_y.to_vec();
    binding.issuer_envelope_signature = proof_binding.issuer_envelope_signature.to_vec();
    binding.issuer_root_binding_signature = proof_binding.issuer_root_binding_signature.to_vec();
    binding.issuer_subject_binding_signature =
        proof_binding.issuer_subject_binding_signature.to_vec();
    binding.issuer_validity_status_signature =
        proof_binding.issuer_validity_status_signature.to_vec();
    binding.issuance_binding = proof_binding.issuance_binding.to_vec();
    let mut wire = pb::ReallyMeZkV1Credential::default();
    wire.version = WIRE_VERSION;
    wire.credential_envelope_pb = credential_pb.to_vec();
    wire.status_list_pb = status_list_pb.to_vec();
    wire.proof_binding = MessageField::some(binding);
    wire.verified_holder_public_key = verified_holder_public_key.to_vec();
    wire.lineage_tag_commitment = request_binding.lineage_tag_commitment.to_vec();
    wire.wallet_opening_commitment = request_binding.wallet_opening_commitment.to_vec();
    wire.opaque_lineage_leaf = request_binding.opaque_lineage_leaf.to_vec();
    let encoded = Zeroizing::new(wire.encode_to_vec());
    if encoded.len() > MAX_WIRE_PROTO_BYTES {
        return Err(IssuerError::new(IssuerStatus::EncodingFailed));
    }
    Ok(Value::String(bytes_to_base64url(&encoded)))
}
struct ValidatedCommonRootPayload {
    claims_root: [u8; DIGEST_BYTES],
    verified_holder_public_key: [u8; P256_SEC1_UNCOMPRESSED_BYTES],
    lineage_tag_commitment: [u8; LINEAGE_TAG_COMMITMENT_BYTES],
    wallet_opening_commitment: [u8; WALLET_OPENING_COMMITMENT_BYTES],
    opaque_lineage_leaf: [u8; OPAQUE_LINEAGE_LEAF_BYTES],
}
fn validate_common_root_payload(value: &Value) -> IssuerResult<ValidatedCommonRootPayload> {
    let encoded = value
        .as_str()
        .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?;
    let maximum_encoded = MAX_WIRE_PROTO_BYTES
        .checked_add(2)
        .and_then(|length| length.checked_div(3))
        .and_then(|length| length.checked_mul(4))
        .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?;
    if encoded.is_empty() || encoded.len() > maximum_encoded {
        return Err(IssuerError::new(IssuerStatus::EncodingFailed));
    }
    let bytes = Zeroizing::new(
        base64url_to_bytes(encoded).map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?,
    );
    if bytes.len() > MAX_WIRE_PROTO_BYTES || bytes_to_base64url(&bytes) != encoded {
        return Err(IssuerError::new(IssuerStatus::EncodingFailed));
    }
    let wire = DecodeOptions::new()
        .with_recursion_limit(PROTO_RECURSION_LIMIT)
        .with_max_message_size(MAX_WIRE_PROTO_BYTES)
        .with_unknown_field_limit(PROTO_UNKNOWN_FIELD_LIMIT)
        .decode_from_slice::<pb::ReallyMeZkV1Credential>(&bytes)
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    if wire.encode_to_vec().as_slice() != bytes.as_slice() {
        return Err(IssuerError::new(IssuerStatus::EncodingFailed));
    }
    validate_wire_issuance_payload(&wire)
}
fn validate_matching_issuance_request(
    request: &CredentialRequest,
    payload: &ValidatedCommonRootPayload,
) -> IssuerResult<()> {
    let issuance = request
        .reallyme_zk_v1_issuance
        .as_ref()
        .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?;
    let bytes = Zeroizing::new(
        base64url_to_bytes(issuance.compact())
            .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?,
    );
    if bytes.is_empty()
        || bytes.len() > openid4vci_types::MAX_REALLYME_ZK_V1_ISSUANCE_REQUEST_BYTES
        || bytes_to_base64url(&bytes) != issuance.compact()
    {
        return Err(IssuerError::new(IssuerStatus::EncodingFailed));
    }
    let wire = DecodeOptions::new()
        .with_recursion_limit(PROTO_RECURSION_LIMIT)
        .with_max_message_size(openid4vci_types::MAX_REALLYME_ZK_V1_ISSUANCE_REQUEST_BYTES)
        .with_unknown_field_limit(PROTO_UNKNOWN_FIELD_LIMIT)
        .decode_from_slice::<pb::ReallyMeZkV1IssuanceRequest>(&bytes)
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    if wire.encode_to_vec().as_slice() != bytes.as_slice() {
        return Err(IssuerError::new(IssuerStatus::EncodingFailed));
    }
    if wire.version != WIRE_VERSION
        || wire.claims_root.len() != DIGEST_BYTES
        || wire.claims_root.iter().all(|byte| *byte == 0)
        || wire.verified_holder_public_key.len() != P256_SEC1_UNCOMPRESSED_BYTES
        || wire.lineage_tag_commitment.len() != LINEAGE_TAG_COMMITMENT_BYTES
        || wire.lineage_tag_commitment.iter().all(|byte| *byte == 0)
        || wire.wallet_opening_commitment.len() != WALLET_OPENING_COMMITMENT_BYTES
        || wire.wallet_opening_commitment.iter().all(|byte| *byte == 0)
        || wire.opaque_lineage_leaf.len() != OPAQUE_LINEAGE_LEAF_BYTES
        || wire.opaque_lineage_leaf.iter().all(|byte| *byte == 0)
    {
        return Err(IssuerError::new(IssuerStatus::EncodingFailed));
    }
    let requested_holder_public_key = normalize_p256_sec1(&wire.verified_holder_public_key)?;
    if fixed_hash(&wire.claims_root)? != payload.claims_root
        || requested_holder_public_key != payload.verified_holder_public_key
        || fixed_lineage_tag_commitment(&wire.lineage_tag_commitment)?
            != payload.lineage_tag_commitment
        || fixed_wallet_opening_commitment(&wire.wallet_opening_commitment)?
            != payload.wallet_opening_commitment
        || fixed_opaque_lineage_leaf(&wire.opaque_lineage_leaf)? != payload.opaque_lineage_leaf
    {
        return Err(IssuerError::new(IssuerStatus::EncodingFailed));
    }
    Ok(())
}
fn validate_wire_issuance_payload(
    wire: &pb::ReallyMeZkV1Credential,
) -> IssuerResult<ValidatedCommonRootPayload> {
    if wire.version != WIRE_VERSION
        || wire.verified_holder_public_key.len() != P256_SEC1_UNCOMPRESSED_BYTES
        || wire.lineage_tag_commitment.len() != LINEAGE_TAG_COMMITMENT_BYTES
        || wire.lineage_tag_commitment.iter().all(|byte| *byte == 0)
        || wire.wallet_opening_commitment.len() != WALLET_OPENING_COMMITMENT_BYTES
        || wire.wallet_opening_commitment.iter().all(|byte| *byte == 0)
        || wire.opaque_lineage_leaf.len() != OPAQUE_LINEAGE_LEAF_BYTES
        || wire.opaque_lineage_leaf.iter().all(|byte| *byte == 0)
    {
        return Err(IssuerError::new(IssuerStatus::EncodingFailed));
    }
    validate_proto_lengths(&wire.credential_envelope_pb, &wire.status_list_pb)?;
    let binding = wire
        .proof_binding
        .as_option()
        .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?;
    let proof_binding = proof_binding_from_proto(binding)?;
    let credential = DecodeOptions::new()
        .with_recursion_limit(PROTO_RECURSION_LIMIT)
        .with_max_message_size(MAX_CREDENTIAL_PROTO_BYTES)
        .with_unknown_field_limit(PROTO_UNKNOWN_FIELD_LIMIT)
        .decode_from_slice::<credential_pb::CredentialEnvelope>(&wire.credential_envelope_pb)
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    let envelope = credential_envelope_from_proto(&credential)
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    let status = DecodeOptions::new()
        .with_recursion_limit(PROTO_RECURSION_LIMIT)
        .with_max_message_size(MAX_STATUS_LIST_PROTO_BYTES)
        .with_unknown_field_limit(PROTO_UNKNOWN_FIELD_LIMIT)
        .decode_from_slice::<status_pb::StatusList>(&wire.status_list_pb)
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    let status = status_list_from_proto(&status)
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    validate_issuance_binding(
        &envelope,
        &proof_binding,
        &public_key_ref_to_p256_sec1(&envelope.issuer_signature.verification_key)?,
        &status,
        &wire.verified_holder_public_key,
    )?;
    Ok(ValidatedCommonRootPayload {
        claims_root: proof_binding.claims_root,
        verified_holder_public_key: normalize_p256_sec1(&wire.verified_holder_public_key)?,
        lineage_tag_commitment: fixed_lineage_tag_commitment(&wire.lineage_tag_commitment)?,
        wallet_opening_commitment: fixed_wallet_opening_commitment(
            &wire.wallet_opening_commitment,
        )?,
        opaque_lineage_leaf: fixed_opaque_lineage_leaf(&wire.opaque_lineage_leaf)?,
    })
}

fn validate_issuance_binding(
    envelope: &SsiCredentialEnvelope,
    proof_binding: &CredentialProofBinding,
    trusted_issuer_public_key_sec1: &[u8],
    verified_status_list: &StatusList,
    verified_holder_public_key_sec1: &[u8],
) -> IssuerResult<()> {
    if envelope.profile_id != SSI_COMMON_ROOT_PROFILE
        || envelope.claims_commitment.claimset_id != SSI_COMMON_ROOT_PROFILE
    {
        return Err(IssuerError::new(IssuerStatus::EncodingFailed));
    }
    common_root_hash_strategy(&envelope.claims_commitment)?;
    validate_credential_envelope(envelope)
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    validate_status_binding(&envelope.status, verified_status_list)?;
    let verified_holder_public_key = normalize_p256_sec1(verified_holder_public_key_sec1)?;
    let trusted_issuer_public_key = normalize_p256_sec1(trusted_issuer_public_key_sec1)?;
    let subject_public_key = match &envelope.subject.holder_binding {
        HolderBinding::CryptographicKey(key) => public_key_ref_to_p256_sec1(key)?,
        _ => {
            return Err(IssuerError::new(IssuerStatus::EncodingFailed));
        }
    };
    if verified_holder_public_key != subject_public_key {
        return Err(IssuerError::new(IssuerStatus::EncodingFailed));
    }

    validate_credential_proof_binding_public(envelope, proof_binding, &trusted_issuer_public_key)
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))
}

fn common_root_hash_strategy(commitment: &ClaimsCommitment) -> IssuerResult<ZkHashStrategy> {
    if commitment.value_encoding != COMMON_CREDENTIAL_ROOT_V1_CLAIM_ENCODING
        || commitment.domain_tags.clm != "CLM1"
        || commitment.domain_tags.leaf != "LEAF1"
        || commitment.domain_tags.node != "NODE1"
        || commitment.limits.max_value_len != SSI_MAX_CLAIM_VALUE_BYTES
        || commitment.limits.salt_len != SSI_CLAIM_SALT_BYTES
    {
        return Err(IssuerError::new(IssuerStatus::EncodingFailed));
    }
    match commitment.hash_alg.as_str() {
        SSI_SHA256_HASH_ALGORITHM => Ok(ZkHashStrategy::Sha256),
        SSI_POSEIDON2_HASH_ALGORITHM => Ok(ZkHashStrategy::Poseidon2),
        _ => Err(IssuerError::new(IssuerStatus::EncodingFailed)),
    }
}

fn verify_issuer_claims_root(
    hash_strategy: ZkHashStrategy,
    proposed_root: [u8; DIGEST_BYTES],
    opaque_lineage_leaf: [u8; DIGEST_BYTES],
    approved_claims: &[ZkCommonCredentialRootClaim<'_>],
) -> IssuerResult<ZkCommonCredentialRootApprovedIssuerRoot> {
    match hash_strategy {
        ZkHashStrategy::Sha256 => verify_common_credential_root_sha256_issuer_claims_root(
            proposed_root,
            opaque_lineage_leaf,
            approved_claims,
        ),
        ZkHashStrategy::Poseidon2 => verify_common_credential_root_poseidon2_issuer_claims_root(
            proposed_root,
            opaque_lineage_leaf,
            approved_claims,
        ),
        _ => return Err(IssuerError::new(IssuerStatus::EncodingFailed)),
    }
    .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))
}

fn validate_status_binding(
    status: &CredentialStatus,
    status_list: &StatusList,
) -> IssuerResult<()> {
    validate_status_list(status_list)
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    if status.purpose != status_list.purpose
        || Some(status.status_list_id) != status_list.list_id
        || status.status_list_index >= status_list.length
        || status_bit_is_set(status_list, status.status_list_index)?
    {
        return Err(IssuerError::new(IssuerStatus::EncodingFailed));
    }
    Ok(())
}

fn status_bit_is_set(status_list: &StatusList, index: u64) -> IssuerResult<bool> {
    let byte_index = usize::try_from(
        index
            .checked_div(8)
            .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?,
    )
    .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    let bit_index =
        u8::try_from(index % 8).map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    let byte = status_list
        .encoded_list
        .get(byte_index)
        .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?;
    Ok(((byte >> bit_index) & 1_u8) == 1_u8)
}

fn proof_binding_from_proto(
    binding: &pb::ReallyMeZkV1ProofBinding,
) -> IssuerResult<CredentialProofBinding> {
    Ok(CredentialProofBinding {
        version: binding.version,
        envelope_hash: fixed_hash(&binding.envelope_hash)?,
        claims_root: fixed_hash(&binding.claims_root)?,
        issuer_public_key_x: fixed_hash(&binding.issuer_public_key_x)?,
        issuer_public_key_y: fixed_hash(&binding.issuer_public_key_y)?,
        subject_public_key_x: fixed_hash(&binding.subject_public_key_x)?,
        subject_public_key_y: fixed_hash(&binding.subject_public_key_y)?,
        issuer_envelope_signature: fixed_signature(&binding.issuer_envelope_signature)?,
        issuer_root_binding_signature: fixed_signature(&binding.issuer_root_binding_signature)?,
        issuer_subject_binding_signature: fixed_signature(
            &binding.issuer_subject_binding_signature,
        )?,
        issuer_validity_status_signature: fixed_signature(
            &binding.issuer_validity_status_signature,
        )?,
        issuance_binding: fixed_hash(&binding.issuance_binding)?,
    })
}

fn validate_proto_lengths(credential_pb: &[u8], status_list_pb: &[u8]) -> IssuerResult<()> {
    if credential_pb.is_empty()
        || credential_pb.len() > MAX_CREDENTIAL_PROTO_BYTES
        || status_list_pb.is_empty()
        || status_list_pb.len() > MAX_STATUS_LIST_PROTO_BYTES
    {
        return Err(IssuerError::new(IssuerStatus::EncodingFailed));
    }
    Ok(())
}

fn fixed_hash(bytes: &[u8]) -> IssuerResult<[u8; DIGEST_BYTES]> {
    <[u8; DIGEST_BYTES]>::try_from(bytes)
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))
}

fn fixed_lineage_tag_commitment(bytes: &[u8]) -> IssuerResult<[u8; LINEAGE_TAG_COMMITMENT_BYTES]> {
    <[u8; LINEAGE_TAG_COMMITMENT_BYTES]>::try_from(bytes)
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))
}

fn fixed_wallet_opening_commitment(
    bytes: &[u8],
) -> IssuerResult<[u8; WALLET_OPENING_COMMITMENT_BYTES]> {
    <[u8; WALLET_OPENING_COMMITMENT_BYTES]>::try_from(bytes)
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))
}

fn fixed_opaque_lineage_leaf(bytes: &[u8]) -> IssuerResult<[u8; OPAQUE_LINEAGE_LEAF_BYTES]> {
    <[u8; OPAQUE_LINEAGE_LEAF_BYTES]>::try_from(bytes)
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))
}

fn fixed_signature(bytes: &[u8]) -> IssuerResult<[u8; P256_SIGNATURE_BYTES]> {
    <[u8; P256_SIGNATURE_BYTES]>::try_from(bytes)
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))
}

fn public_key_ref_to_p256_sec1(
    key: &PublicKeyRef,
) -> IssuerResult<[u8; P256_SEC1_UNCOMPRESSED_BYTES]> {
    if key.alg != CredentialAlgorithm::P256 {
        return Err(IssuerError::new(IssuerStatus::EncodingFailed));
    }
    match &key.public_key {
        PublicKeyRepresentation::Raw {
            serialization:
                RawPublicKeySerialization::Sec1Compressed | RawPublicKeySerialization::Sec1Uncompressed,
            bytes,
        } => normalize_p256_sec1(bytes),
        PublicKeyRepresentation::JwkJson(_)
        | PublicKeyRepresentation::CoseKey(_)
        | PublicKeyRepresentation::Multikey(_)
        | PublicKeyRepresentation::SubjectPublicKeyInfoDer(_)
        | PublicKeyRepresentation::Raw {
            serialization: RawPublicKeySerialization::FixedWidth,
            ..
        }
        | _ => Err(IssuerError::new(IssuerStatus::EncodingFailed)),
    }
}

fn normalize_p256_sec1(bytes: &[u8]) -> IssuerResult<[u8; P256_SEC1_UNCOMPRESSED_BYTES]> {
    let key = p256::PublicKey::from_sec1_bytes(bytes)
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    let encoded = key.to_sec1_point(false);
    let out = <[u8; P256_SEC1_UNCOMPRESSED_BYTES]>::try_from(encoded.as_bytes())
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    if out[0] == P256_SEC1_UNCOMPRESSED_PREFIX {
        Ok(out)
    } else {
        Err(IssuerError::new(IssuerStatus::EncodingFailed))
    }
}
