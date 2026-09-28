// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Credential proof parsing and verification.

mod attestation_policy;
mod process;
mod verify;

pub use attestation_policy::{KeyAttestationLocalPolicy, KeyAttestationPolicy};
#[cfg(feature = "identity-jose")]
pub(crate) use process::UnverifiedProofKeyBinding;
pub use process::{
    validate_common_proof_claims, CompactProofJwtParser, UnverifiedProofClaims,
    DEFAULT_MAX_PROOF_JWT_BYTES, PROOF_JWT_TYP,
};
pub use verify::{
    ConfirmationJwk, ProofAlgorithm, ProofKind, ProofVerificationContext, ProofVerifier,
    VerifiedProof, VerifiedProofSet,
};
