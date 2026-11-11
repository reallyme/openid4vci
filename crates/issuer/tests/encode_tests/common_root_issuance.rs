// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Authorized common-root issuance and pre-signing rejection tests.

use std::cell::Cell;

use openid4vci_issuer::{
    encode_immediate_response, CommonRootCredentialEncoder, CommonRootIssuanceRequestBinding,
    CommonRootIssuedCredential, IssuanceStatusEvidence, IssuerResult, IssuerStatus,
};
use reallyme_credential::DispatchCredentialIssuerSigner;
use reallyme_crypto::{core::Algorithm as CryptoAlgorithm, dispatch::generate_keypair};
use reallyme_zk_api::{
    circuits::ZkCredentialHashAlgorithm, common_root::ZkCommonCredentialRootClaim,
};

use crate::support::{
    common_root_zk_material, common_root_zk_material_for_lane, encoding_error,
    issuer_status_verifier, p256_issue_input, signed_active_status_list, zk_request_for_issued,
    CountingSigner, STATUS_TEST_FRESHNESS, STATUS_TEST_NOW,
};

#[test]
fn common_root_both_lanes_reject_finished_lineage_leaf_before_signing() -> IssuerResult<()> {
    for lane in [
        ZkCredentialHashAlgorithm::Sha256,
        ZkCredentialHashAlgorithm::Poseidon2,
    ] {
        let prepared = common_root_zk_material_for_lane(lane)?;
        assert_ne!(
            prepared.finished_lineage_leaf,
            prepared.opaque_lineage_claim_digest
        );
        let binding = prepared.request_binding()?;
        assert_eq!(
            binding.opaque_lineage_claim_digest(),
            &prepared.opaque_lineage_claim_digest
        );
        let legacy_binding = || {
            CommonRootIssuanceRequestBinding::new(
                *binding.lineage_tag_commitment(),
                *binding.wallet_opening_commitment(),
                prepared.finished_lineage_leaf,
            )
        };
        let claims = [ZkCommonCredentialRootClaim {
            name: "age",
            value: b"42",
            salt: &prepared.claim_salt,
        }];
        let mut input = p256_issue_input(
            prepared.material.issuer_public_key.clone(),
            prepared.material.holder_public_key.clone(),
        );
        input.profile_id = "reallyme.zk.common-root.v1".to_owned();
        input.claimset_id = "reallyme.zk.common-root.v1".to_owned();
        let key = input.issuer_verification_key.clone();
        let delegate = DispatchCredentialIssuerSigner {
            private_key: &prepared.material.issuer_private_key,
            verification_key: &key,
        };
        let signer = CountingSigner {
            delegate: &delegate,
            called: Cell::new(false),
        };
        let status = signed_active_status_list(&prepared.material.issuer_private_key)?;
        let verifier = issuer_status_verifier(&prepared.material);
        let evidence =
            IssuanceStatusEvidence::new(&status, &verifier, STATUS_TEST_NOW, STATUS_TEST_FRESHNESS);
        let result = CommonRootIssuedCredential::issue_from_authorized_claims(
            input,
            prepared.material.envelope.claims_commitment.clone(),
            &signer,
            &evidence,
            &prepared.material.holder_public_key,
            legacy_binding()?,
            &claims,
        );
        assert_eq!(
            result.err().map(|error| error.status()),
            Some(IssuerStatus::EncodingFailed)
        );
        assert!(!signer.called.get());

        let result = CommonRootIssuedCredential::from_authorized_common_root_issuance(
            &prepared.material.envelope,
            &prepared.material.proof_binding,
            &prepared.material.issuer_public_key,
            &evidence,
            &prepared.material.holder_public_key,
            legacy_binding()?,
            &claims,
        );
        assert_eq!(
            result.err().map(|error| error.status()),
            Some(IssuerStatus::EncodingFailed)
        );
    }
    Ok(())
}

#[test]
fn common_root_sha256_authorized_issuance_accepts_issuer_claim_root() -> IssuerResult<()> {
    let prepared = common_root_zk_material()?;
    let claims = [ZkCommonCredentialRootClaim {
        name: "age",
        value: b"42",
        salt: &prepared.claim_salt,
    }];
    let issued = CommonRootIssuedCredential::from_authorized_common_root_issuance(
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
    )?;
    let encoder = CommonRootCredentialEncoder::new();
    let issued = issued.into_issued_credential()?;
    let request = zk_request_for_issued(&issued)?;

    let response = encode_immediate_response(&request, &encoder, &[issued], None)?;

    assert_eq!(response.credentials.as_ref().map(Vec::len), Some(1));
    Ok(())
}

#[test]
fn common_root_sha256_authorized_issuance_rejects_forged_status_list() -> IssuerResult<()> {
    let prepared = common_root_zk_material()?;
    let mut status = signed_active_status_list(&prepared.material.issuer_private_key)?;
    status.signature.sig_bytes[0] ^= 1;
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
fn common_root_sha256_authorized_issuance_rejects_stale_status_list() -> IssuerResult<()> {
    let prepared = common_root_zk_material()?;
    let status = signed_active_status_list(&prepared.material.issuer_private_key)?;
    let claims = [ZkCommonCredentialRootClaim {
        name: "age",
        value: b"42",
        salt: &prepared.claim_salt,
    }];
    let stale_time = status
        .issued_at
        .checked_add(STATUS_TEST_FRESHNESS.max_age_secs)
        .ok_or_else(encoding_error)?;
    let result = CommonRootIssuedCredential::from_authorized_common_root_issuance(
        &prepared.material.envelope,
        &prepared.material.proof_binding,
        &prepared.material.issuer_public_key,
        &IssuanceStatusEvidence::new(
            &status,
            &issuer_status_verifier(&prepared.material),
            stale_time,
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
fn common_root_sha256_issues_and_transports_authorized_claims_without_resigning() -> IssuerResult<()>
{
    let prepared = common_root_zk_material()?;
    let claims = [ZkCommonCredentialRootClaim {
        name: "age",
        value: b"42",
        salt: &prepared.claim_salt,
    }];
    let mut issue_input = p256_issue_input(
        prepared.material.issuer_public_key.clone(),
        prepared.material.holder_public_key.clone(),
    );
    issue_input.profile_id = "reallyme.zk.common-root.v1".to_owned();
    issue_input.claimset_id = "reallyme.zk.common-root.v1".to_owned();
    let issuer_verification_key = issue_input.issuer_verification_key.clone();
    let signer = DispatchCredentialIssuerSigner {
        private_key: &prepared.material.issuer_private_key,
        verification_key: &issuer_verification_key,
    };
    let issued = CommonRootIssuedCredential::issue_from_authorized_claims(
        issue_input,
        prepared.material.envelope.claims_commitment.clone(),
        &signer,
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
    .into_issued_credential()?;
    let request = zk_request_for_issued(&issued)?;
    let response = encode_immediate_response(
        &request,
        &CommonRootCredentialEncoder::new(),
        &[issued],
        None,
    )?;
    assert_eq!(response.credentials.as_ref().map(Vec::len), Some(1));
    Ok(())
}

#[test]
fn common_root_poseidon2_issues_and_transports_authorized_claims() -> IssuerResult<()> {
    let prepared = common_root_zk_material_for_lane(ZkCredentialHashAlgorithm::Poseidon2)?;
    let claims = [ZkCommonCredentialRootClaim {
        name: "age",
        value: b"42",
        salt: &prepared.claim_salt,
    }];
    let mut issue_input = p256_issue_input(
        prepared.material.issuer_public_key.clone(),
        prepared.material.holder_public_key.clone(),
    );
    issue_input.profile_id = "reallyme.zk.common-root.v1".to_owned();
    issue_input.claimset_id = "reallyme.zk.common-root.v1".to_owned();
    let issuer_verification_key = issue_input.issuer_verification_key.clone();
    let signer = DispatchCredentialIssuerSigner {
        private_key: &prepared.material.issuer_private_key,
        verification_key: &issuer_verification_key,
    };
    let issued = CommonRootIssuedCredential::issue_from_authorized_claims(
        issue_input,
        prepared.material.envelope.claims_commitment.clone(),
        &signer,
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
    .into_issued_credential()?;
    let request = zk_request_for_issued(&issued)?;
    let response = encode_immediate_response(
        &request,
        &CommonRootCredentialEncoder::new(),
        &[issued],
        None,
    )?;
    assert_eq!(response.credentials.as_ref().map(Vec::len), Some(1));
    Ok(())
}

#[test]
fn common_root_poseidon2_rejects_sha256_metadata_before_signing() -> IssuerResult<()> {
    let prepared = common_root_zk_material_for_lane(ZkCredentialHashAlgorithm::Poseidon2)?;
    let mut issue_input = p256_issue_input(
        prepared.material.issuer_public_key.clone(),
        prepared.material.holder_public_key.clone(),
    );
    issue_input.profile_id = "reallyme.zk.common-root.v1".to_owned();
    issue_input.claimset_id = "reallyme.zk.common-root.v1".to_owned();
    let issuer_verification_key = issue_input.issuer_verification_key.clone();
    let dispatch_signer = DispatchCredentialIssuerSigner {
        private_key: &prepared.material.issuer_private_key,
        verification_key: &issuer_verification_key,
    };
    let signer = CountingSigner {
        delegate: &dispatch_signer,
        called: Cell::new(false),
    };
    let mut commitment = prepared.material.envelope.claims_commitment.clone();
    commitment.hash_alg = "sha-256".to_owned();
    let claims = [ZkCommonCredentialRootClaim {
        name: "age",
        value: b"42",
        salt: &prepared.claim_salt,
    }];
    let result = CommonRootIssuedCredential::issue_from_authorized_claims(
        issue_input,
        commitment,
        &signer,
        &IssuanceStatusEvidence::new(
            &signed_active_status_list(&prepared.material.issuer_private_key)?,
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
    assert!(!signer.called.get());
    Ok(())
}

#[test]
fn common_root_sha256_rejects_forged_status_before_signing() -> IssuerResult<()> {
    let prepared = common_root_zk_material()?;
    let mut issue_input = p256_issue_input(
        prepared.material.issuer_public_key.clone(),
        prepared.material.holder_public_key.clone(),
    );
    issue_input.profile_id = "reallyme.zk.common-root.v1".to_owned();
    issue_input.claimset_id = "reallyme.zk.common-root.v1".to_owned();
    let issuer_verification_key = issue_input.issuer_verification_key.clone();
    let dispatch_signer = DispatchCredentialIssuerSigner {
        private_key: &prepared.material.issuer_private_key,
        verification_key: &issuer_verification_key,
    };
    let signer = CountingSigner {
        delegate: &dispatch_signer,
        called: Cell::new(false),
    };
    let mut status = signed_active_status_list(&prepared.material.issuer_private_key)?;
    status.signature.sig_bytes[0] ^= 1;
    let claims = [ZkCommonCredentialRootClaim {
        name: "age",
        value: b"42",
        salt: &prepared.claim_salt,
    }];
    let result = CommonRootIssuedCredential::issue_from_authorized_claims(
        issue_input,
        prepared.material.envelope.claims_commitment.clone(),
        &signer,
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
    assert!(!signer.called.get());
    Ok(())
}

#[test]
fn common_root_sha256_issuer_rejects_wrong_claims_and_hash_lane() -> IssuerResult<()> {
    let prepared = common_root_zk_material()?;
    let mut issue_input = p256_issue_input(
        prepared.material.issuer_public_key.clone(),
        prepared.material.holder_public_key.clone(),
    );
    issue_input.profile_id = "reallyme.zk.common-root.v1".to_owned();
    issue_input.claimset_id = "reallyme.zk.common-root.v1".to_owned();
    let issuer_verification_key = issue_input.issuer_verification_key.clone();
    let signer = DispatchCredentialIssuerSigner {
        private_key: &prepared.material.issuer_private_key,
        verification_key: &issuer_verification_key,
    };
    let commitment = prepared.material.envelope.claims_commitment.clone();
    let wrong_claims = [ZkCommonCredentialRootClaim {
        name: "age",
        value: b"43",
        salt: &prepared.claim_salt,
    }];
    let result = CommonRootIssuedCredential::issue_from_authorized_claims(
        issue_input,
        commitment.clone(),
        &signer,
        &IssuanceStatusEvidence::new(
            &signed_active_status_list(&prepared.material.issuer_private_key)?,
            &issuer_status_verifier(&prepared.material),
            STATUS_TEST_NOW,
            STATUS_TEST_FRESHNESS,
        ),
        &prepared.material.holder_public_key,
        prepared.request_binding()?,
        &wrong_claims,
    );
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::EncodingFailed)
    );

    let mut wrong_lane = commitment;
    wrong_lane.hash_alg = "poseidon2-bn254".to_owned();
    let valid_claims = [ZkCommonCredentialRootClaim {
        name: "age",
        value: b"42",
        salt: &prepared.claim_salt,
    }];
    let mut issue_input = p256_issue_input(
        prepared.material.issuer_public_key.clone(),
        prepared.material.holder_public_key.clone(),
    );
    issue_input.profile_id = "reallyme.zk.common-root.v1".to_owned();
    issue_input.claimset_id = "reallyme.zk.common-root.v1".to_owned();
    let result = CommonRootIssuedCredential::issue_from_authorized_claims(
        issue_input,
        wrong_lane,
        &signer,
        &IssuanceStatusEvidence::new(
            &signed_active_status_list(&prepared.material.issuer_private_key)?,
            &issuer_status_verifier(&prepared.material),
            STATUS_TEST_NOW,
            STATUS_TEST_FRESHNESS,
        ),
        &prepared.material.holder_public_key,
        prepared.request_binding()?,
        &valid_claims,
    );
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::EncodingFailed)
    );
    Ok(())
}

#[test]
fn common_root_sha256_issuer_rejects_wrong_status_and_holder_before_issuance() -> IssuerResult<()> {
    let prepared = common_root_zk_material()?;
    let mut issue_input = p256_issue_input(
        prepared.material.issuer_public_key.clone(),
        prepared.material.holder_public_key.clone(),
    );
    issue_input.profile_id = "reallyme.zk.common-root.v1".to_owned();
    issue_input.claimset_id = "reallyme.zk.common-root.v1".to_owned();
    issue_input.status.status_list_id = [9_u8; 32];
    let issuer_verification_key = issue_input.issuer_verification_key.clone();
    let signer = DispatchCredentialIssuerSigner {
        private_key: &prepared.material.issuer_private_key,
        verification_key: &issuer_verification_key,
    };
    let claims = [ZkCommonCredentialRootClaim {
        name: "age",
        value: b"42",
        salt: &prepared.claim_salt,
    }];
    let result = CommonRootIssuedCredential::issue_from_authorized_claims(
        issue_input,
        prepared.material.envelope.claims_commitment.clone(),
        &signer,
        &IssuanceStatusEvidence::new(
            &signed_active_status_list(&prepared.material.issuer_private_key)?,
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

    let mut issue_input = p256_issue_input(
        prepared.material.issuer_public_key.clone(),
        prepared.material.holder_public_key.clone(),
    );
    issue_input.profile_id = "reallyme.zk.common-root.v1".to_owned();
    issue_input.claimset_id = "reallyme.zk.common-root.v1".to_owned();
    let result = CommonRootIssuedCredential::issue_from_authorized_claims(
        issue_input,
        prepared.material.envelope.claims_commitment.clone(),
        &signer,
        &IssuanceStatusEvidence::new(
            &signed_active_status_list(&prepared.material.issuer_private_key)?,
            &issuer_status_verifier(&prepared.material),
            STATUS_TEST_NOW,
            STATUS_TEST_FRESHNESS,
        ),
        &prepared.material.issuer_public_key,
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
fn common_root_sha256_authorized_issuance_rejects_unapproved_claim_bytes() -> IssuerResult<()> {
    let prepared = common_root_zk_material()?;
    let claims = [ZkCommonCredentialRootClaim {
        name: "age",
        value: b"43",
        salt: &prepared.claim_salt,
    }];
    let result = CommonRootIssuedCredential::from_authorized_common_root_issuance(
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
    );

    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::EncodingFailed)
    );
    Ok(())
}

#[test]
fn common_root_sha256_authorized_issuance_rejects_untrusted_issuer_key() -> IssuerResult<()> {
    let prepared = common_root_zk_material()?;
    let (other_issuer_public_key, _other_issuer_private_key) =
        generate_keypair(CryptoAlgorithm::P256).map_err(|_| encoding_error())?;
    let claims = [ZkCommonCredentialRootClaim {
        name: "age",
        value: b"42",
        salt: &prepared.claim_salt,
    }];
    let result = CommonRootIssuedCredential::from_authorized_common_root_issuance(
        &prepared.material.envelope,
        &prepared.material.proof_binding,
        &other_issuer_public_key,
        &IssuanceStatusEvidence::new(
            &signed_active_status_list(&prepared.material.issuer_private_key)?,
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
