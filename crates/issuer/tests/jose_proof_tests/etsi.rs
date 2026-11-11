// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! ETSI-specific JWT proof verification tests.

use std::sync::Arc;

use openid4vci_issuer::{
    CredentialRequestProfile, IssuerStatus, JoseJwtProofVerifier, ProofVerifier,
};
use openid4vci_types::Proofs;

use super::{
    context, key_attestation_jwt, proof_jwt_with_key_attestation, public_jwk_value,
    JoseProofTestError, TrustingKeyAttestationVerifier, NONCE, OTHER_SEED, SEED,
};

#[test]
fn etsi_profile_expands_the_first_key_proof_to_all_attested_keys() -> Result<(), JoseProofTestError>
{
    let first = public_jwk_value(&SEED)?;
    let second = public_jwk_value(&OTHER_SEED)?;
    let key_attestation =
        key_attestation_jwt(vec![first.clone(), second.clone()], Some(NONCE), true)?;
    let proofs = Proofs {
        jwt: vec![proof_jwt_with_key_attestation(NONCE, key_attestation)?],
        di_vp: Vec::new(),
        attestation: Vec::new(),
    };
    let mut verification_context = context(true);
    verification_context.credential_request_profile = CredentialRequestProfile::EtsiTs119472Part3;

    let verified = JoseJwtProofVerifier::new()
        .with_key_attestation_verifier(Arc::new(TrustingKeyAttestationVerifier))
        .verify(&proofs, &verification_context)
        .map_err(|_| JoseProofTestError::Verify)?;

    assert_eq!(verified.binding_key_count(), 2);
    assert!(verified.includes_key_attestation());
    let ordered = verified
        .ordered_public_jwks()
        .map_err(|_| JoseProofTestError::Verify)?;
    assert_eq!(ordered[0].get("x"), first.get("x"));
    assert_eq!(ordered[1].get("x"), second.get("x"));
    Ok(())
}

#[test]
fn etsi_profile_rejects_a_proof_not_signed_by_the_first_attested_key(
) -> Result<(), JoseProofTestError> {
    let key_attestation = key_attestation_jwt(
        vec![public_jwk_value(&OTHER_SEED)?, public_jwk_value(&SEED)?],
        Some(NONCE),
        true,
    )?;
    let proofs = Proofs {
        jwt: vec![proof_jwt_with_key_attestation(NONCE, key_attestation)?],
        di_vp: Vec::new(),
        attestation: Vec::new(),
    };
    let mut verification_context = context(true);
    verification_context.credential_request_profile = CredentialRequestProfile::EtsiTs119472Part3;

    let result = JoseJwtProofVerifier::new()
        .with_key_attestation_verifier(Arc::new(TrustingKeyAttestationVerifier))
        .verify(&proofs, &verification_context);

    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidProof)
    );
    Ok(())
}
