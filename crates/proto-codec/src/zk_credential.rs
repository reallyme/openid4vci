// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical Buffa boundary for the custom ZK credential string.
//!
//! This validates the OpenID4VCI container only. The caller must validate the
//! embedded SSI credential, status, issuer signatures, and holder binding.

use buffa::{DecodeOptions, Message};
use openid4vci_proto::generated::proto::reallyme::openid4vci::v1 as pb;
use reallyme_codec::base64url::{base64url_to_bytes, bytes_to_base64url};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{ProtoCodecError, ProtoCodecResult};

const WIRE_VERSION: u32 = 1;
const BINDING_VERSION: u32 = 1;
const HASH_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;
const P256_UNCOMPRESSED_BYTES: usize = 65;
const MAX_ENVELOPE_BYTES: usize = 1024 * 1024;
const MAX_STATUS_BYTES: usize = 128 * 1024;
const MAX_WIRE_BYTES: usize = MAX_ENVELOPE_BYTES + MAX_STATUS_BYTES + 1024;
const RECURSION_LIMIT: u32 = 32;

/// A structurally valid, canonical custom credential container.
///
/// The embedded issuer and status messages remain untrusted. This type does
/// not represent a verified credential receipt.
pub struct CanonicalReallyMeZkV1Credential {
    wire: pb::ReallyMeZkV1Credential,
}

impl Zeroize for CanonicalReallyMeZkV1Credential {
    fn zeroize(&mut self) {
        self.wire.credential_envelope_pb.zeroize();
        self.wire.status_list_pb.zeroize();
        self.wire.verified_holder_public_key.zeroize();
        self.wire.lineage_tag_commitment.zeroize();
        self.wire.wallet_opening_commitment.zeroize();
        self.wire.opaque_lineage_leaf.zeroize();
        if let Some(binding) = self.wire.proof_binding.as_option_mut() {
            binding.envelope_hash.zeroize();
            binding.claims_root.zeroize();
            binding.issuer_public_key_x.zeroize();
            binding.issuer_public_key_y.zeroize();
            binding.subject_public_key_x.zeroize();
            binding.subject_public_key_y.zeroize();
            binding.issuer_envelope_signature.zeroize();
            binding.issuer_root_binding_signature.zeroize();
            binding.issuer_subject_binding_signature.zeroize();
            binding.issuer_validity_status_signature.zeroize();
            binding.issuance_binding.zeroize();
        }
    }
}

impl Drop for CanonicalReallyMeZkV1Credential {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for CanonicalReallyMeZkV1Credential {}

impl CanonicalReallyMeZkV1Credential {
    /// Borrow the exact embedded SSI credential protobuf for receipt validation.
    #[must_use]
    pub fn credential_envelope_pb(&self) -> &[u8] {
        &self.wire.credential_envelope_pb
    }

    /// Borrow the exact embedded status-list protobuf for freshness checks.
    #[must_use]
    pub fn status_list_pb(&self) -> &[u8] {
        &self.wire.status_list_pb
    }

    /// Borrow the bounded proof binding without treating it as authenticated.
    pub fn proof_binding(&self) -> ProtoCodecResult<&pb::ReallyMeZkV1ProofBinding> {
        self.wire
            .proof_binding
            .as_option()
            .ok_or(ProtoCodecError::Decode)
    }

    /// Borrow the holder public key whose curve point must be checked by trust policy.
    #[must_use]
    pub fn verified_holder_public_key(&self) -> &[u8] {
        &self.wire.verified_holder_public_key
    }

    /// Borrow the lineage-tag commitment that must match the wallet request.
    #[must_use]
    pub fn lineage_tag_commitment(&self) -> &[u8] {
        &self.wire.lineage_tag_commitment
    }

    /// Borrow the wallet opening commitment that must match the wallet request.
    #[must_use]
    pub fn wallet_opening_commitment(&self) -> &[u8] {
        &self.wire.wallet_opening_commitment
    }

    /// Borrow the salted lineage claim digest that must match the approved request.
    #[must_use]
    pub fn opaque_lineage_claim_digest(&self) -> &[u8] {
        &self.wire.opaque_lineage_leaf
    }
}

/// Decode one unpadded base64url Buffa credential before SSI trust evaluation.
pub fn decode_reallyme_zk_v1_credential(
    encoded: &str,
) -> ProtoCodecResult<CanonicalReallyMeZkV1Credential> {
    let max_encoded = MAX_WIRE_BYTES
        .checked_add(2)
        .and_then(|value| value.checked_div(3))
        .and_then(|value| value.checked_mul(4))
        .ok_or(ProtoCodecError::PayloadTooLarge)?;
    if encoded.is_empty() || encoded.len() > max_encoded {
        return Err(ProtoCodecError::PayloadTooLarge);
    }
    let bytes = Zeroizing::new(base64url_to_bytes(encoded).map_err(|_| ProtoCodecError::Decode)?);
    if bytes.len() > MAX_WIRE_BYTES || bytes_to_base64url(&bytes) != encoded {
        return Err(ProtoCodecError::Decode);
    }
    let decoded_wire = DecodeOptions::new()
        .with_recursion_limit(RECURSION_LIMIT)
        .with_max_message_size(MAX_WIRE_BYTES)
        .with_unknown_field_limit(0)
        .decode_from_slice::<pb::ReallyMeZkV1Credential>(&bytes)
        .map_err(|_| ProtoCodecError::Decode)?;
    // Own Buffa's copied payload before validating fields so every rejection
    // after a successful decode follows the same zeroizing drop path.
    let credential = CanonicalReallyMeZkV1Credential { wire: decoded_wire };
    if Zeroizing::new(credential.wire.encode_to_vec()).as_slice() != bytes.as_slice()
        || credential.wire.version != WIRE_VERSION
        || credential.wire.credential_envelope_pb.is_empty()
        || credential.wire.credential_envelope_pb.len() > MAX_ENVELOPE_BYTES
        || credential.wire.status_list_pb.is_empty()
        || credential.wire.status_list_pb.len() > MAX_STATUS_BYTES
        || credential.wire.verified_holder_public_key.len() != P256_UNCOMPRESSED_BYTES
        || credential.wire.lineage_tag_commitment.len() != HASH_BYTES
        || credential
            .wire
            .lineage_tag_commitment
            .iter()
            .all(|byte| *byte == 0)
        || credential.wire.wallet_opening_commitment.len() != HASH_BYTES
        || credential
            .wire
            .wallet_opening_commitment
            .iter()
            .all(|byte| *byte == 0)
        || credential.wire.opaque_lineage_leaf.len() != HASH_BYTES
        || credential
            .wire
            .opaque_lineage_leaf
            .iter()
            .all(|byte| *byte == 0)
        || !credential
            .wire
            .proof_binding
            .as_option()
            .is_some_and(valid_binding_shape)
    {
        return Err(ProtoCodecError::Decode);
    }
    Ok(credential)
}

fn valid_binding_shape(binding: &pb::ReallyMeZkV1ProofBinding) -> bool {
    binding.version == BINDING_VERSION
        && binding.envelope_hash.len() == HASH_BYTES
        && binding.claims_root.len() == HASH_BYTES
        && binding.issuer_public_key_x.len() == HASH_BYTES
        && binding.issuer_public_key_y.len() == HASH_BYTES
        && binding.subject_public_key_x.len() == HASH_BYTES
        && binding.subject_public_key_y.len() == HASH_BYTES
        && binding.issuer_envelope_signature.len() == SIGNATURE_BYTES
        && binding.issuer_root_binding_signature.len() == SIGNATURE_BYTES
        && binding.issuer_subject_binding_signature.len() == SIGNATURE_BYTES
        && binding.issuer_validity_status_signature.len() == SIGNATURE_BYTES
        && binding.issuance_binding.len() == HASH_BYTES
}

#[cfg(test)]
#[path = "zk_credential_tests.rs"]
mod tests;
