// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wallet and key attestation boundary types.
//!
//! Signature verification is deliberately injected by higher-level verifier
//! implementations so this crate can model attestation-based client
//! authentication without committing adapters to a specific trust registry.

pub mod error;
pub mod model;
pub mod verify_key_attestation;
pub mod wrap;

mod validate;
mod validate_key_attestation_claims;

pub use error::{AttestationError, AttestationResult, AttestationStatus};
pub use model::{
    AttackPotentialResistance, BindingKeyAlgorithm, CertificationReference,
    KeyAttestationAlgorithm, KeyAttestationStatusEvidence, KeyAttestationStatusReference,
    KeyAttestationTemporalPolicy, KeyAttestationTrustEvidence, KeyAttestationTrustEvidenceInput,
    KeyAttestationTrustPurpose, VerifiedBindingKey,
};
pub use verify_key_attestation::{
    parse_key_attestation, verify_key_attestation, KeyAttestationTrustVerifier,
    KeyAttestationValidationContext, ParsedKeyAttestation, VerifiedKeyAttestation,
};
pub use wrap::{ClientAttestationPopJwt, KeyAttestationJwt, WalletAttestationJwt};
