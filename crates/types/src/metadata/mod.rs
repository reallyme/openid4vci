// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Credential Issuer Metadata models and validation.

mod describe;
mod encryption;
mod validate;

pub use describe::{
    BatchCredentialIssuance, CredentialConfiguration, CredentialSigningAlg, IssuerMetadata,
    IssuerMetadataBuilder, KeyAttestationsRequired, ProofTypeMetadata, MIN_BATCH_SIZE,
};
pub use encryption::{CredentialRequestEncryptionMetadata, CredentialResponseEncryptionMetadata};
