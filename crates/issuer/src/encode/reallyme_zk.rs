// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `reallyme_zk_v1` credential response encoding.
//!
//! The issuer already owns SSI issuance and proof-binding validation. This
//! module keeps the OpenID4VCI transport payload deterministic so wallets and
//! foreign SDKs receive one stable public shape for either common-root hash
//! lane without learning issuer internals.

use core::fmt::{Debug, Formatter};

use buffa::{DecodeOptions, Message, MessageField};
use openid4vci_proto::generated::proto::reallyme::openid4vci::v1 as pb;
use openid4vci_types::{CredentialEnvelope, CredentialFormat, CredentialRequest};
use p256::elliptic_curve::sec1::ToSec1Point;
use reallyme_codec::base64url::{base64url_to_bytes, bytes_to_base64url};
use reallyme_credential::{
    committed::{
        issue::IssueInput,
        model::{
            ClaimsCommitment, CredentialAlgorithm, CredentialStatus, PublicKeyRef,
            PublicKeyRepresentation, RawPublicKeySerialization,
        },
        precomputed_commitment::issue_credential_with_precomputed_commitment,
        proof_binding::{
            validate_credential_proof_binding_public, CredentialProofBinding,
            CREDENTIAL_PROOF_BINDING_VERSION,
        },
    },
    credential_envelope_from_proto, credential_envelope_to_proto, validate_credential_envelope,
    CredentialEnvelope as SsiCredentialEnvelope, CredentialIssuerSigner, HolderBinding,
};
use reallyme_credential_status::{
    status_list_from_proto, status_list_to_proto, validate_status_list,
    verify_status_list_authenticity_with_policy, StatusList, StatusListFreshnessPolicy,
    StatusListVerifier,
};
use reallyme_ssi_proto::generated::proto::identity::{
    credential::v1 as credential_pb, status::v1 as status_pb,
};
use reallyme_zk_api::{
    circuits::ZkCredentialHashAlgorithm,
    common_root::{
        verify_common_credential_root_poseidon2_issuer_claims_root,
        verify_common_credential_root_sha256_issuer_claims_root,
        ZkCommonCredentialRootApprovedIssuerRoot, ZkCommonCredentialRootClaim,
        COMMON_CREDENTIAL_ROOT_V1_CLAIM_ENCODING,
    },
};
use serde_json::Value;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    encode::{CredentialEncoder, IssuedCredential},
    error::{IssuerError, IssuerResult, IssuerStatus},
};

/// OpenID4VCI format value for ReallyMe ZK common-root credentials.
pub const REALLYME_ZK_V1_FORMAT: &str = "reallyme_zk_v1";
/// Payload profile shared by both common-root hash lanes.
pub const COMMON_ROOT_PROFILE: &str = "common_root_v1";
/// SHA-256 hash suite value accepted by the mobile and Rust SDKs.
pub const COMMON_ROOT_SHA256_HASH_SUITE: &str = "sha256";
/// Poseidon2 hash suite value accepted by the mobile and Rust SDKs.
pub const COMMON_ROOT_POSEIDON2_HASH_SUITE: &str = "poseidon2";

const DIGEST_BYTES: usize = 32;
const P256_COORDINATE_BYTES: usize = 32;
const P256_SIGNATURE_BYTES: usize = 64;
const P256_SEC1_UNCOMPRESSED_BYTES: usize = 65;
const P256_SEC1_UNCOMPRESSED_PREFIX: u8 = 0x04;
const MAX_CREDENTIAL_PROTO_BYTES: usize = 1024 * 1024;
const MAX_STATUS_LIST_PROTO_BYTES: usize = 128 * 1024;
const MAX_WIRE_PROTO_BYTES: usize = MAX_CREDENTIAL_PROTO_BYTES + MAX_STATUS_LIST_PROTO_BYTES + 1024;
const WIRE_VERSION: u32 = 1;
const PROTO_RECURSION_LIMIT: u32 = 32;
const PROTO_UNKNOWN_FIELD_LIMIT: usize = 0;
const LINEAGE_TAG_COMMITMENT_BYTES: usize = 32;
const WALLET_OPENING_COMMITMENT_BYTES: usize = 32;
const LINEAGE_CLAIM_DIGEST_BYTES: usize = 32;
const SSI_COMMON_ROOT_PROFILE: &str = "reallyme.zk.common-root.v1";
const SSI_SHA256_HASH_ALGORITHM: &str = "sha-256";
const SSI_POSEIDON2_HASH_ALGORITHM: &str = "poseidon2-bn254";
const SSI_MAX_CLAIM_VALUE_BYTES: u32 = 64;
const SSI_CLAIM_SALT_BYTES: u32 = 16;

/// Public proof-binding material transported alongside one issued credential.
///
/// These bytes are public but correlatable. The type redacts debug output and
/// zeroizes on drop so temporary issuance records do not keep identifiers alive
/// longer than necessary.
#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct CommonRootProofBinding {
    /// SHA-256 of the canonical issuer signing payload.
    pub envelope_hash: [u8; DIGEST_BYTES],
    /// Common-root Merkle root in the hash lane named by the SSI envelope.
    pub claims_root: [u8; DIGEST_BYTES],
    /// P-256 issuer public-key x coordinate.
    pub issuer_public_key_x: [u8; P256_COORDINATE_BYTES],
    /// P-256 issuer public-key y coordinate.
    pub issuer_public_key_y: [u8; P256_COORDINATE_BYTES],
    /// P-256 subject public-key x coordinate.
    pub subject_public_key_x: [u8; P256_COORDINATE_BYTES],
    /// P-256 subject public-key y coordinate.
    pub subject_public_key_y: [u8; P256_COORDINATE_BYTES],
    /// Raw P-256 issuer signature over the credential envelope.
    pub issuer_envelope_signature: [u8; P256_SIGNATURE_BYTES],
    /// Raw P-256 issuer signature over `BINDMRK1`.
    pub issuer_root_binding_signature: [u8; P256_SIGNATURE_BYTES],
    /// Raw P-256 issuer signature over `BINDSUB1`.
    pub issuer_subject_binding_signature: [u8; P256_SIGNATURE_BYTES],
    /// Issuer signature over dates and hidden credential-status pointer.
    pub issuer_validity_status_signature: [u8; P256_SIGNATURE_BYTES],
    /// Stable issuance commitment for this envelope, root, issuer, and subject.
    pub issuance_binding: [u8; DIGEST_BYTES],
}

/// Wallet request commitments that the issuer binds into one response.
///
/// These values are public to the issuer but privacy-relevant across issuance
/// sessions. Keeping them in one typed value makes it hard for callers to bind
/// only the root and holder key while forgetting the wallet reconciliation
/// fields required by the ZK issuance protocol.
#[derive(Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct CommonRootIssuanceRequestBinding {
    /// Commitment to the holder's hidden lineage tag.
    lineage_tag_commitment: [u8; LINEAGE_TAG_COMMITMENT_BYTES],
    /// Wallet commitment to the first private opening used for reconciliation.
    wallet_opening_commitment: [u8; WALLET_OPENING_COMMITMENT_BYTES],
    /// Salted lineage claim digest carried by the `opaque_lineage_leaf` wire field.
    opaque_lineage_claim_digest: [u8; LINEAGE_CLAIM_DIGEST_BYTES],
}

impl CommonRootIssuanceRequestBinding {
    /// Builds the required request binding and rejects absent all-zero fields.
    ///
    /// The `opaque_lineage_claim_digest` argument carries the wallet's salted `CLM1`
    /// digest. The ZK verifier derives the reserved `LEAF1` leaf from it when
    /// recomputing the issuer-approved claims root.
    pub fn new(
        lineage_tag_commitment: [u8; LINEAGE_TAG_COMMITMENT_BYTES],
        wallet_opening_commitment: [u8; WALLET_OPENING_COMMITMENT_BYTES],
        opaque_lineage_claim_digest: [u8; LINEAGE_CLAIM_DIGEST_BYTES],
    ) -> IssuerResult<Self> {
        if lineage_tag_commitment.iter().all(|byte| *byte == 0)
            || wallet_opening_commitment.iter().all(|byte| *byte == 0)
            || opaque_lineage_claim_digest.iter().all(|byte| *byte == 0)
        {
            return Err(IssuerError::new(IssuerStatus::EncodingFailed));
        }
        Ok(Self {
            lineage_tag_commitment,
            wallet_opening_commitment,
            opaque_lineage_claim_digest,
        })
    }

    /// Returns the wallet's lineage-tag commitment.
    pub fn lineage_tag_commitment(&self) -> &[u8; LINEAGE_TAG_COMMITMENT_BYTES] {
        &self.lineage_tag_commitment
    }

    /// Returns the wallet-opening commitment used to reconcile the request.
    pub fn wallet_opening_commitment(&self) -> &[u8; WALLET_OPENING_COMMITMENT_BYTES] {
        &self.wallet_opening_commitment
    }

    /// Returns the salted lineage claim digest carried by the wire field.
    pub fn opaque_lineage_claim_digest(&self) -> &[u8; LINEAGE_CLAIM_DIGEST_BYTES] {
        &self.opaque_lineage_claim_digest
    }
}

impl Debug for CommonRootIssuanceRequestBinding {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CommonRootIssuanceRequestBinding")
            .field("profile", &COMMON_ROOT_PROFILE)
            .field("material", &"<redacted>")
            .finish()
    }
}

impl Debug for CommonRootProofBinding {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CommonRootProofBinding")
            .field("profile", &COMMON_ROOT_PROFILE)
            .field("material", &"<redacted>")
            .finish()
    }
}

impl From<&CredentialProofBinding> for CommonRootProofBinding {
    fn from(value: &CredentialProofBinding) -> Self {
        Self {
            envelope_hash: value.envelope_hash,
            claims_root: value.claims_root,
            issuer_public_key_x: value.issuer_public_key_x,
            issuer_public_key_y: value.issuer_public_key_y,
            subject_public_key_x: value.subject_public_key_x,
            subject_public_key_y: value.subject_public_key_y,
            issuer_envelope_signature: value.issuer_envelope_signature,
            issuer_root_binding_signature: value.issuer_root_binding_signature,
            issuer_subject_binding_signature: value.issuer_subject_binding_signature,
            issuer_validity_status_signature: value.issuer_validity_status_signature,
            issuance_binding: value.issuance_binding,
        }
    }
}

/// Issuer-prepared `reallyme_zk_v1` payload for OpenID4VCI responses.
#[derive(PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct CommonRootIssuedCredential {
    credential_pb: Zeroizing<Vec<u8>>,
    status_list_pb: Zeroizing<Vec<u8>>,
    verified_holder_public_key: [u8; P256_SEC1_UNCOMPRESSED_BYTES],
    proof_binding: CommonRootProofBinding,
    request_binding: CommonRootIssuanceRequestBinding,
    #[zeroize(skip)]
    hash_strategy: ZkCredentialHashAlgorithm,
}

/// Signed status material and the issuer's verification policy for one issuance.
///
/// Construction does not confer trust. Each issuance constructor authenticates
/// the list and checks its freshness before invoking the credential signer.
pub struct IssuanceStatusEvidence<'a> {
    list: &'a StatusList,
    verifier: &'a dyn StatusListVerifier,
    now_unix: u64,
    freshness: StatusListFreshnessPolicy,
}

impl<'a> IssuanceStatusEvidence<'a> {
    /// Captures the list and policy; authenticity is checked at issuance.
    pub fn new(
        list: &'a StatusList,
        verifier: &'a dyn StatusListVerifier,
        now_unix: u64,
        freshness: StatusListFreshnessPolicy,
    ) -> Self {
        Self {
            list,
            verifier,
            now_unix,
            freshness,
        }
    }

    fn verify(&self) -> IssuerResult<()> {
        verify_status_list_authenticity_with_policy(
            self.list,
            self.now_unix,
            self.freshness,
            self.verifier,
        )
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))
    }
}

impl Debug for CommonRootIssuedCredential {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CommonRootIssuedCredential")
            .field("format", &REALLYME_ZK_V1_FORMAT)
            .field("profile", &COMMON_ROOT_PROFILE)
            .field("hash_strategy", &self.hash_strategy)
            .field("credential", &"<redacted>")
            .field("proof_binding", &"<redacted>")
            .finish()
    }
}

impl CommonRootIssuedCredential {
    /// Approves authoritative claims, issues the SSI credential, and prepares
    /// its OpenID4VCI response without replacing any already signed field.
    ///
    /// The caller supplies claims from its issuance decision and the salted
    /// lineage claim digest from the holder. Neither the holder's claim values nor an
    /// unverified root can authorize the issuer signature. Status authenticity
    /// and freshness are checked before invoking the issuer signer.
    pub fn issue_from_authorized_claims(
        issue_input: IssueInput,
        commitment: ClaimsCommitment,
        signer: &dyn CredentialIssuerSigner,
        status: &IssuanceStatusEvidence<'_>,
        verified_holder_public_key_sec1: &[u8],
        request_binding: CommonRootIssuanceRequestBinding,
        approved_claims: &[ZkCommonCredentialRootClaim<'_>],
    ) -> IssuerResult<Self> {
        if issue_input.profile_id != SSI_COMMON_ROOT_PROFILE
            || commitment.claimset_id != SSI_COMMON_ROOT_PROFILE
        {
            return Err(IssuerError::new(IssuerStatus::EncodingFailed));
        }
        let hash_strategy = common_root_hash_strategy(&commitment)?;
        let root = fixed_hash(&commitment.merkle_root)?;
        let approved_root = verify_issuer_claims_root(
            hash_strategy,
            root,
            request_binding.opaque_lineage_claim_digest,
            approved_claims,
        )?;
        status.verify()?;
        // Reject stale status and mismatched holder proof before invoking the
        // issuer signer, whose action may be externally recorded by an HSM.
        validate_status_binding(&issue_input.status, status.list)?;
        let subject_key: &PublicKeyRef = match &issue_input.subject.holder_binding {
            HolderBinding::CryptographicKey(key) => key,
            _ => return Err(IssuerError::new(IssuerStatus::EncodingFailed)),
        };
        if normalize_p256_sec1(verified_holder_public_key_sec1)?
            != public_key_ref_to_p256_sec1(subject_key)?
        {
            return Err(IssuerError::new(IssuerStatus::EncodingFailed));
        }
        let issued = issue_credential_with_precomputed_commitment(issue_input, commitment, signer)
            .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
        let trusted_issuer_public_key = public_key_ref_to_p256_sec1(signer.verification_key())?;
        Self::from_verified_issuance(
            &issued.envelope,
            &issued.proof_binding,
            &trusted_issuer_public_key,
            status.list,
            verified_holder_public_key_sec1,
            approved_root,
            request_binding,
        )
    }

    /// Creates a payload only after checking issuer-approved ZK claim facts.
    ///
    /// `approved_claims` must come from the issuer's authoritative issuance
    /// decision after applying the credential profile's canonical byte
    /// conversion. It must not be copied from wallet-provided claim bytes. The
    /// wallet supplies the salted lineage claim digest. The verifier derives
    /// the reserved lineage leaf without learning the holder's private
    /// lineage value. The status verifier independently resolves the list
    /// signer and checks its freshness.
    pub fn from_authorized_common_root_issuance(
        envelope: &SsiCredentialEnvelope,
        proof_binding: &CredentialProofBinding,
        trusted_issuer_public_key_sec1: &[u8],
        status: &IssuanceStatusEvidence<'_>,
        verified_holder_public_key_sec1: &[u8],
        request_binding: CommonRootIssuanceRequestBinding,
        approved_claims: &[ZkCommonCredentialRootClaim<'_>],
    ) -> IssuerResult<Self> {
        let hash_strategy = common_root_hash_strategy(&envelope.claims_commitment)?;
        let approved_root = verify_issuer_claims_root(
            hash_strategy,
            proof_binding.claims_root,
            request_binding.opaque_lineage_claim_digest,
            approved_claims,
        )?;
        status.verify()?;
        Self::from_verified_issuance(
            envelope,
            proof_binding,
            trusted_issuer_public_key_sec1,
            status.list,
            verified_holder_public_key_sec1,
            approved_root,
            request_binding,
        )
    }

    /// Creates a payload from already-verified SSI issuance material.
    ///
    /// The issuer key, status list, and OpenID4VCI holder key must be verified by
    /// their protocol owners. This constructor binds them to the exact signed
    /// credential envelope and proof-binding material before producing the
    /// Buffa protobuf bytes carried by the OpenID4VCI response.
    fn from_verified_issuance(
        envelope: &SsiCredentialEnvelope,
        proof_binding: &CredentialProofBinding,
        trusted_issuer_public_key_sec1: &[u8],
        verified_status_list: &StatusList,
        verified_holder_public_key_sec1: &[u8],
        approved_root: ZkCommonCredentialRootApprovedIssuerRoot,
        request_binding: CommonRootIssuanceRequestBinding,
    ) -> IssuerResult<Self> {
        let hash_strategy = common_root_hash_strategy(&envelope.claims_commitment)?;
        if approved_root.credential_hash_algorithm() != hash_strategy
            || approved_root.root() != proof_binding.claims_root
        {
            return Err(IssuerError::new(IssuerStatus::EncodingFailed));
        }
        validate_issuance_binding(
            envelope,
            proof_binding,
            trusted_issuer_public_key_sec1,
            verified_status_list,
            verified_holder_public_key_sec1,
        )?;
        let credential_pb = Zeroizing::new(
            credential_envelope_to_proto(envelope)
                .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?
                .encode_to_vec(),
        );
        let status_list_pb = Zeroizing::new(
            status_list_to_proto(verified_status_list)
                .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?
                .encode_to_vec(),
        );
        validate_proto_lengths(&credential_pb, &status_list_pb)?;
        let verified_holder_public_key = normalize_p256_sec1(verified_holder_public_key_sec1)?;
        Ok(Self {
            credential_pb,
            status_list_pb,
            verified_holder_public_key,
            proof_binding: CommonRootProofBinding::from(proof_binding),
            request_binding,
            hash_strategy,
        })
    }

    /// Converts the typed payload into the generic issuer response pipeline.
    pub fn into_issued_credential(self) -> IssuerResult<IssuedCredential> {
        let value = common_root_payload(
            self.credential_pb.as_slice(),
            self.status_list_pb.as_slice(),
            &self.verified_holder_public_key,
            &self.proof_binding,
            &self.request_binding,
        )?;
        IssuedCredential::new_reallyme_zk_v1(value)
    }
}

/// Encoder for `reallyme_zk_v1` common-root credentials in both hash lanes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CommonRootCredentialEncoder;

impl CommonRootCredentialEncoder {
    /// Creates the stateless encoder.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl CredentialEncoder for CommonRootCredentialEncoder {
    fn format(&self) -> CredentialFormat {
        CredentialFormat::ReallyMeZkV1
    }

    fn encode(
        &self,
        request: &CredentialRequest,
        issued: &IssuedCredential,
    ) -> IssuerResult<CredentialEnvelope> {
        if issued.format != CredentialFormat::ReallyMeZkV1 {
            return Err(IssuerError::new(IssuerStatus::UnsupportedCredential));
        }
        if !issued.has_intact_reallyme_zk_v1_marker() {
            return Err(IssuerError::new(IssuerStatus::EncodingFailed));
        }
        let validated = validate_common_root_payload(&issued.credential)?;
        validate_matching_issuance_request(request, &validated)?;
        let encoded = issued
            .credential
            .as_str()
            .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?;
        let envelope = CredentialEnvelope::compact(encoded.to_owned());
        envelope
            .validate()
            .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
        Ok(envelope)
    }
}

include!("common_root_validation.rs");

#[cfg(test)]
#[path = "common_root_tests.rs"]
mod tests;
