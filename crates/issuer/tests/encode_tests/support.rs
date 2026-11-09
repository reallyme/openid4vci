// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared fixtures for issuer encoder integration tests.

use std::{cell::Cell, collections::BTreeMap};

use buffa::{DecodeOptions, Message};
use openid4vci_issuer::{
    encode_immediate_response, CommonRootCredentialEncoder, CommonRootIssuanceRequestBinding,
    CommonRootIssuedCredential, ConfirmationJwk, IssuanceStatusEvidence, IssuedCredential,
    IssuerError, IssuerResult, IssuerStatus, ProofAlgorithm, ProofKind, VerifiedProof,
};
use openid4vci_proto::generated::proto::reallyme::openid4vci::v1 as pb;
use openid4vci_types::{
    CredentialFormat, CredentialPayload, CredentialRequest, Proofs, ReallyMeZkV1IssuanceRequest,
};
use p256::elliptic_curve::sec1::ToSec1Point;
use reallyme_codec::base64url::{base64url_to_bytes, bytes_to_base64url};
use reallyme_credential::committed::{
    issue::{issue_credential, IssueInput, OsSaltRng},
    model::{
        AssuranceLevel, ClaimsCommitment, CommitmentLimits, CredentialAlgorithm, CredentialKind,
        CredentialStatus, CredentialSubject, DomainTags, HolderBinding, KeyAssurance, KeyReference,
        PartyReference, PublicKeyRef, PublicKeyRepresentation, RawPublicKeySerialization,
        StatusPurpose,
    },
    precomputed_commitment::issue_credential_with_precomputed_commitment,
};
use reallyme_credential::{
    CredentialError, CredentialIssuerSigner, DispatchCredentialIssuerSigner,
};
use reallyme_credential_status::{
    status_list_signing_payload, CredentialStatusError, StatusList, StatusListAlgorithm,
    StatusListFreshnessPolicy, StatusListSignature, StatusListVerifier,
};
use reallyme_crypto::{
    core::Algorithm as CryptoAlgorithm,
    dispatch::{generate_keypair, sign, verify},
};
use reallyme_zk_api::{
    build_common_credential_root_poseidon2_claims_commitment,
    build_common_credential_root_sha256_claims_commitment,
    derive_common_credential_root_v1_lineage, ZkCommonCredentialRootClaim,
    ZkCommonCredentialRootSubjectPublicKey, ZkHashStrategy, ZkIssuerPublicKey,
    COMMON_CREDENTIAL_ROOT_V1_CLAIM_ENCODING,
};
use serde_json::{json, Value};

pub(crate) fn request() -> CredentialRequest {
    CredentialRequest {
        credential_configuration_id: Some("pid".to_owned()),
        credential_identifier: None,
        proofs: None,
        credential_response_encryption: None,
        reallyme_zk_v1_issuance: None,
    }
}

pub(crate) fn request_with_jwt_proofs(count: usize) -> CredentialRequest {
    CredentialRequest {
        credential_configuration_id: Some("pid".to_owned()),
        credential_identifier: None,
        proofs: Some(Proofs {
            jwt: (0..count)
                .map(|index| ["proof-", &index.to_string()].concat())
                .collect(),
            di_vp: Vec::new(),
            attestation: Vec::new(),
        }),
        credential_response_encryption: None,
        reallyme_zk_v1_issuance: None,
    }
}

pub(crate) fn request_for_configuration(configuration_id: &str) -> CredentialRequest {
    let mut request = request();
    request.credential_configuration_id = Some(configuration_id.to_owned());
    request
}

pub(crate) fn first_compact_credential(
    response: &openid4vci_types::CredentialResponse,
) -> IssuerResult<&str> {
    let credential = response
        .credentials
        .as_ref()
        .and_then(|credentials| credentials.first())
        .ok_or(encoding_error())?;
    match &credential.credential {
        CredentialPayload::Compact(value) => Ok(value.as_str()),
        CredentialPayload::Json(_) | CredentialPayload::Binary(_) => Err(encoding_error()),
    }
}

pub(crate) fn binding_proof(public_jwk: Value) -> IssuerResult<VerifiedProof> {
    VerifiedProof::new(
        ProofKind::Jwt,
        None,
        None,
        None,
        None,
        Some(public_jwk),
        Some(ConfirmationJwk {
            algorithm: ProofAlgorithm::Es256,
            public_key: vec![0x04; 65],
            key_id: None,
        }),
    )
}

pub(crate) struct ZkIssuedMaterial {
    pub(crate) envelope: reallyme_credential::CredentialEnvelope,
    pub(crate) proof_binding: reallyme_credential::committed::proof_binding::CredentialProofBinding,
    pub(crate) holder_public_key: Vec<u8>,
    pub(crate) issuer_public_key: Vec<u8>,
    pub(crate) issuer_private_key: Vec<u8>,
}

pub(crate) struct CountingSigner<'a> {
    pub(crate) delegate: &'a dyn CredentialIssuerSigner,
    pub(crate) called: Cell<bool>,
}

impl CredentialIssuerSigner for CountingSigner<'_> {
    fn verification_key(&self) -> &PublicKeyRef {
        self.delegate.verification_key()
    }

    fn sign_credential_payload(&self, payload: &[u8]) -> Result<Vec<u8>, CredentialError> {
        self.called.set(true);
        self.delegate.sign_credential_payload(payload)
    }
}

pub(crate) struct PreparedCommonRootMaterial {
    pub(crate) material: ZkIssuedMaterial,
    pub(crate) opaque_lineage_leaf: [u8; 32],
    pub(crate) claim_salt: [u8; 16],
}

pub(crate) struct AuthorizedClaimDecision<'a> {
    pub(crate) name: &'a str,
    pub(crate) value: &'a [u8],
    pub(crate) salt: [u8; 16],
}

impl AuthorizedClaimDecision<'_> {
    // OpenID4VCI issuer encoding receives already-issued non-ZK credentials
    // from identity. This compact fixture proves configuration routing and
    // receipt separation only; SD-JWT signing is covered by the identity/SSI
    // issuer, not by this transport encoder.
    pub(crate) fn expected_sd_jwt_compact(&self) -> String {
        [
            "sd-jwt-vc.",
            self.name,
            ".",
            &bytes_to_base64url(self.value),
        ]
        .concat()
    }

    pub(crate) fn sd_jwt_issued_credential(&self) -> IssuerResult<IssuedCredential> {
        IssuedCredential::new(
            CredentialFormat::SdJwtVc,
            Value::String(self.expected_sd_jwt_compact()),
        )
    }

    pub(crate) fn zk_issued_credential(
        &self,
        prepared: &PreparedCommonRootMaterial,
    ) -> IssuerResult<IssuedCredential> {
        let claims = [ZkCommonCredentialRootClaim {
            name: self.name,
            value: self.value,
            salt: &self.salt,
        }];
        CommonRootIssuedCredential::from_authorized_common_root_issuance(
            &prepared.material.envelope,
            &prepared.material.proof_binding,
            &prepared.material.issuer_public_key,
            &IssuanceStatusEvidence::new(
                &signed_active_status_list(&prepared.material.issuer_private_key)?,
                &issuer_status_verifier(&prepared.material),
                STATUS_TEST_NOW,
                STATUS_TEST_FRESHNESS,
            ),
            &prepared.material.holder_public_key,
            prepared.request_binding()?,
            &claims,
        )?
        .into_issued_credential()
    }
}

impl PreparedCommonRootMaterial {
    pub(crate) fn request_binding(&self) -> IssuerResult<CommonRootIssuanceRequestBinding> {
        CommonRootIssuanceRequestBinding::new([0x44; 32], [0x55; 32], self.opaque_lineage_leaf)
    }
}

pub(crate) fn zk_issued_credential() -> IssuerResult<IssuedCredential> {
    let prepared = common_root_zk_material()?;
    let claims = [ZkCommonCredentialRootClaim {
        name: "age",
        value: b"42",
        salt: &prepared.claim_salt,
    }];
    CommonRootIssuedCredential::from_authorized_common_root_issuance(
        &prepared.material.envelope,
        &prepared.material.proof_binding,
        &prepared.material.issuer_public_key,
        &IssuanceStatusEvidence::new(
            &signed_active_status_list(&prepared.material.issuer_private_key)?,
            &issuer_status_verifier(&prepared.material),
            STATUS_TEST_NOW,
            STATUS_TEST_FRESHNESS,
        ),
        &prepared.material.holder_public_key,
        prepared.request_binding()?,
        &claims,
    )?
    .into_issued_credential()
}

pub(crate) fn decode_wire_payload(encoded: &str) -> IssuerResult<pb::ReallyMeZkV1Credential> {
    let bytes = base64url_to_bytes(encoded).map_err(|_| encoding_error())?;
    DecodeOptions::new()
        .with_recursion_limit(32)
        .with_unknown_field_limit(0)
        .decode_from_slice::<pb::ReallyMeZkV1Credential>(&bytes)
        .map_err(|_| encoding_error())
}

pub(crate) fn encoded_wire_bytes(issued: &IssuedCredential) -> IssuerResult<Vec<u8>> {
    let encoded = issued.credential.as_str().ok_or(encoding_error())?;
    base64url_to_bytes(encoded).map_err(|_| encoding_error())
}

pub(crate) fn tamper_wire_payload(
    issued: &mut IssuedCredential,
    tamper: impl FnOnce(&mut pb::ReallyMeZkV1Credential),
) -> IssuerResult<()> {
    let mut wire = decode_wire_payload(issued.credential.as_str().ok_or(encoding_error())?)?;
    tamper(&mut wire);
    issued.credential = Value::String(bytes_to_base64url(&wire.encode_to_vec()));
    Ok(())
}

pub(crate) fn zk_request_for_issued(issued: &IssuedCredential) -> IssuerResult<CredentialRequest> {
    let wire = decode_wire_payload(issued.credential.as_str().ok_or(encoding_error())?)?;
    let binding = wire.proof_binding.as_option().ok_or(encoding_error())?;
    let compact = compact_issuance_request(
        binding.claims_root.clone(),
        wire.verified_holder_public_key.clone(),
        wire.lineage_tag_commitment.clone(),
        wire.wallet_opening_commitment.clone(),
        wire.opaque_lineage_leaf.clone(),
    )?;
    let mut request = request();
    request.reallyme_zk_v1_issuance =
        Some(ReallyMeZkV1IssuanceRequest::new(compact).map_err(|_| encoding_error())?);
    Ok(request)
}

pub(crate) fn tamper_request_root(request: &mut CredentialRequest) -> IssuerResult<()> {
    tamper_request(request, |wire| wire.claims_root[0] ^= 1)
}

pub(crate) fn assert_rejects_tampered_request_field(
    tamper: impl FnOnce(&mut pb::ReallyMeZkV1IssuanceRequest),
) -> IssuerResult<()> {
    let encoder = CommonRootCredentialEncoder::new();
    let issued = zk_issued_credential()?;
    let mut request = zk_request_for_issued(&issued)?;
    tamper_request(&mut request, tamper)?;

    let result = encode_immediate_response(&request, &encoder, &[issued], None);

    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::EncodingFailed)
    );
    Ok(())
}

pub(crate) fn assert_rejects_tampered_response_field(
    tamper: impl FnOnce(&mut pb::ReallyMeZkV1Credential),
) -> IssuerResult<()> {
    let encoder = CommonRootCredentialEncoder::new();
    let mut issued = zk_issued_credential()?;
    let request = zk_request_for_issued(&issued)?;
    tamper_wire_payload(&mut issued, tamper)?;

    let result = encode_immediate_response(&request, &encoder, &[issued], None);

    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::EncodingFailed)
    );
    Ok(())
}

fn tamper_request(
    request: &mut CredentialRequest,
    tamper: impl FnOnce(&mut pb::ReallyMeZkV1IssuanceRequest),
) -> IssuerResult<()> {
    let issuance = request
        .reallyme_zk_v1_issuance
        .as_ref()
        .ok_or(encoding_error())?;
    let bytes = base64url_to_bytes(issuance.compact()).map_err(|_| encoding_error())?;
    let mut wire = DecodeOptions::new()
        .with_recursion_limit(32)
        .with_unknown_field_limit(0)
        .decode_from_slice::<pb::ReallyMeZkV1IssuanceRequest>(&bytes)
        .map_err(|_| encoding_error())?;
    tamper(&mut wire);
    request.reallyme_zk_v1_issuance = Some(
        ReallyMeZkV1IssuanceRequest::new(bytes_to_base64url(&wire.encode_to_vec()))
            .map_err(|_| encoding_error())?,
    );
    Ok(())
}

pub(crate) fn tamper_request_with_duplicate_version(
    request: &mut CredentialRequest,
) -> IssuerResult<()> {
    let issuance = request
        .reallyme_zk_v1_issuance
        .as_ref()
        .ok_or(encoding_error())?;
    let mut bytes = base64url_to_bytes(issuance.compact()).map_err(|_| encoding_error())?;
    bytes.extend_from_slice(&[0x08, 0x01]);
    request.reallyme_zk_v1_issuance = Some(
        ReallyMeZkV1IssuanceRequest::new(bytes_to_base64url(&bytes))
            .map_err(|_| encoding_error())?,
    );
    Ok(())
}

pub(crate) fn compact_issuance_request(
    claims_root: Vec<u8>,
    verified_holder_public_key: Vec<u8>,
    lineage_tag_commitment: Vec<u8>,
    wallet_opening_commitment: Vec<u8>,
    opaque_lineage_leaf: Vec<u8>,
) -> IssuerResult<String> {
    let mut request = pb::ReallyMeZkV1IssuanceRequest::default();
    request.version = 1;
    request.claims_root = claims_root;
    request.verified_holder_public_key = verified_holder_public_key;
    request.lineage_tag_commitment = lineage_tag_commitment;
    request.wallet_opening_commitment = wallet_opening_commitment;
    request.opaque_lineage_leaf = opaque_lineage_leaf;
    Ok(bytes_to_base64url(&request.encode_to_vec()))
}

pub(crate) fn common_root_zk_material() -> IssuerResult<PreparedCommonRootMaterial> {
    common_root_zk_material_for_lane(ZkHashStrategy::Sha256)
}

pub(crate) fn common_root_zk_material_for_lane(
    hash_strategy: ZkHashStrategy,
) -> IssuerResult<PreparedCommonRootMaterial> {
    let mut material = issue_zk_material()?;
    let issuer_key = p256_key_coordinates(&material.issuer_public_key)?;
    let subject_key = p256_key_coordinates(&material.holder_public_key)?;
    let lineage = derive_common_credential_root_v1_lineage(
        &[1_u8; 32],
        ZkIssuerPublicKey {
            x: issuer_key.0,
            y: issuer_key.1,
        },
        "did:me:issuer-relationship",
        ZkCommonCredentialRootSubjectPublicKey {
            x: subject_key.0,
            y: subject_key.1,
        },
        &[6_u8; 32],
    )
    .map_err(|_| encoding_error())?;
    let lineage_salt = [7_u8; 16];
    let claim_salt = [8_u8; 16];
    let claims = [ZkCommonCredentialRootClaim {
        name: "age",
        value: b"42",
        salt: &claim_salt,
    }];
    let commitment = match hash_strategy {
        ZkHashStrategy::Sha256 => {
            build_common_credential_root_sha256_claims_commitment(&lineage, &lineage_salt, &claims)
        }
        ZkHashStrategy::Poseidon2 => build_common_credential_root_poseidon2_claims_commitment(
            &lineage,
            &lineage_salt,
            &claims,
        ),
        _ => return Err(encoding_error()),
    }
    .map_err(|_| encoding_error())?;
    let opaque_lineage_leaf = commitment
        .opaque_lineage_leaf()
        .map_err(|_| encoding_error())?;
    let mut issue_input = p256_issue_input(
        material.issuer_public_key.clone(),
        material.holder_public_key.clone(),
    );
    issue_input.profile_id = "reallyme.zk.common-root.v1".to_owned();
    issue_input.claimset_id = "reallyme.zk.common-root.v1".to_owned();
    let issuer_verification_key = issue_input.issuer_verification_key.clone();
    let signer = DispatchCredentialIssuerSigner {
        private_key: &material.issuer_private_key,
        verification_key: &issuer_verification_key,
    };
    let issued = issue_credential_with_precomputed_commitment(
        issue_input,
        ClaimsCommitment {
            merkle_root: commitment.root().to_vec(),
            claimset_id: "reallyme.zk.common-root.v1".to_owned(),
            hash_alg: match hash_strategy {
                ZkHashStrategy::Sha256 => "sha-256",
                ZkHashStrategy::Poseidon2 => "poseidon2-bn254",
                _ => return Err(encoding_error()),
            }
            .to_owned(),
            value_encoding: COMMON_CREDENTIAL_ROOT_V1_CLAIM_ENCODING.to_owned(),
            domain_tags: DomainTags {
                clm: "CLM1".to_owned(),
                leaf: "LEAF1".to_owned(),
                node: "NODE1".to_owned(),
            },
            limits: CommitmentLimits {
                max_value_len: 64,
                salt_len: 16,
            },
        },
        &signer,
    )
    .map_err(|_| encoding_error())?;
    material.envelope = issued.envelope;
    material.proof_binding = issued.proof_binding;
    Ok(PreparedCommonRootMaterial {
        material,
        opaque_lineage_leaf,
        claim_salt,
    })
}

fn issue_zk_material() -> IssuerResult<ZkIssuedMaterial> {
    let (issuer_public_key, issuer_private_key) =
        generate_keypair(CryptoAlgorithm::P256).map_err(|_| encoding_error())?;
    let (holder_public_key, _holder_private_key) =
        generate_keypair(CryptoAlgorithm::P256).map_err(|_| encoding_error())?;
    let mut claims = BTreeMap::new();
    claims.insert("age".to_owned(), json!(42));
    let mut salt_rng = OsSaltRng;
    let issued = issue_credential(
        p256_issue_input(issuer_public_key.clone(), holder_public_key.clone()),
        &claims,
        CryptoAlgorithm::P256,
        &issuer_private_key,
        &mut salt_rng,
    )
    .map_err(|_| encoding_error())?;
    let proof_binding = issued.proof_binding.ok_or(encoding_error())?;
    Ok(ZkIssuedMaterial {
        envelope: issued.envelope,
        proof_binding,
        holder_public_key,
        issuer_public_key,
        issuer_private_key: issuer_private_key.to_vec(),
    })
}

fn p256_key_coordinates(public_key: &[u8]) -> IssuerResult<([u8; 32], [u8; 32])> {
    let key = p256::PublicKey::from_sec1_bytes(public_key).map_err(|_| encoding_error())?;
    let point = key.to_sec1_point(false);
    let bytes = point.as_bytes();
    let x = <[u8; 32]>::try_from(bytes.get(1..33).ok_or(encoding_error())?)
        .map_err(|_| encoding_error())?;
    let y = <[u8; 32]>::try_from(bytes.get(33..65).ok_or(encoding_error())?)
        .map_err(|_| encoding_error())?;
    Ok((x, y))
}

pub(crate) fn p256_uncompressed(public_key: &[u8]) -> IssuerResult<Vec<u8>> {
    let key = p256::PublicKey::from_sec1_bytes(public_key).map_err(|_| encoding_error())?;
    Ok(key.to_sec1_point(false).as_bytes().to_vec())
}

pub(crate) fn p256_issue_input(
    issuer_public_key: Vec<u8>,
    holder_public_key: Vec<u8>,
) -> IssueInput {
    IssueInput {
        kind: CredentialKind::Pid,
        profile_id: "claims-v1".to_owned(),
        assurance: AssuranceLevel::Substantial,
        issuer_reference: PartyReference::Did("did:test:issuer".to_owned()),
        issuer_verification_key: p256_key("did:test:issuer#key-1", issuer_public_key),
        issuer_country: "EU".to_owned(),
        valid_from: 1_700_000_000,
        valid_until: 1_800_000_000,
        status: CredentialStatus {
            status_list_url: "https://example.com/status".to_owned(),
            status_list_id: [0_u8; 32],
            status_list_index: 0,
            purpose: StatusPurpose::Revocation,
        },
        subject: CredentialSubject {
            subject_reference: PartyReference::Did("did:test:subject".to_owned()),
            holder_binding: HolderBinding::CryptographicKey(p256_key(
                "did:test:subject#key-1",
                holder_public_key,
            )),
        },
        claimset_id: "claims-v1".to_owned(),
        domain_tags: DomainTags {
            clm: "CLM1".to_owned(),
            leaf: "LEAF1".to_owned(),
            node: "NODE1".to_owned(),
        },
        limits: CommitmentLimits {
            max_value_len: 64,
            salt_len: 16,
        },
        qeaa_compliance: None,
    }
}

fn p256_key(did_url: &str, bytes: Vec<u8>) -> PublicKeyRef {
    PublicKeyRef {
        alg: CredentialAlgorithm::P256,
        reference: KeyReference::DidVerificationMethod(did_url.to_owned()),
        public_key: PublicKeyRepresentation::Raw {
            serialization: RawPublicKeySerialization::Sec1Compressed,
            bytes,
        },
        assurance: KeyAssurance::None,
    }
}

fn active_status_list() -> StatusList {
    StatusList {
        issuer: "did:test:issuer".to_owned(),
        purpose: reallyme_credential_status::StatusPurpose::Revocation,
        issued_at: 1_750_000_000,
        next_update: 1_800_000_000,
        encoded_list: vec![0],
        length: 8,
        list_id: Some([0_u8; 32]),
        signature: StatusListSignature {
            alg: StatusListAlgorithm::P256,
            sig_bytes: vec![1_u8; 64],
        },
    }
}

pub(crate) const STATUS_TEST_NOW: u64 = 1_750_000_001;
pub(crate) const STATUS_TEST_FRESHNESS: StatusListFreshnessPolicy = StatusListFreshnessPolicy {
    max_age_secs: 3_600,
};

pub(crate) struct IssuerStatusVerifier<'a> {
    public_key: &'a [u8],
}

impl StatusListVerifier for IssuerStatusVerifier<'_> {
    fn verify_status_list(
        &self,
        issuer: &str,
        alg: StatusListAlgorithm,
        payload: &[u8],
        signature: &[u8],
    ) -> Result<(), CredentialStatusError> {
        if issuer != "did:test:issuer" || alg != StatusListAlgorithm::P256 {
            return Err(CredentialStatusError::InvalidSignature);
        }
        verify(CryptoAlgorithm::P256, self.public_key, payload, signature)
            .map_err(|_| CredentialStatusError::InvalidSignature)
    }
}

pub(crate) fn signed_active_status_list(issuer_private_key: &[u8]) -> IssuerResult<StatusList> {
    let mut status = active_status_list();
    let payload = status_list_signing_payload(&status).map_err(|_| encoding_error())?;
    status.signature.sig_bytes =
        sign(CryptoAlgorithm::P256, issuer_private_key, &payload).map_err(|_| encoding_error())?;
    Ok(status)
}

pub(crate) fn issuer_status_verifier(material: &ZkIssuedMaterial) -> IssuerStatusVerifier<'_> {
    IssuerStatusVerifier {
        public_key: &material.issuer_public_key,
    }
}

pub(crate) const fn encoding_error() -> IssuerError {
    IssuerError::new(IssuerStatus::EncodingFailed)
}
