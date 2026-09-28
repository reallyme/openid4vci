// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wallet-side builders for OpenID4VCI requests.

mod build_key_proof;
#[cfg(feature = "identity-jose")]
mod credential_jwe;
#[cfg(feature = "identity-jose")]
mod credential_jwe_key;
#[cfg(feature = "identity-jose")]
mod validate_credential_jwk_bounds;

pub mod error;
pub mod metadata;
pub mod request;
pub mod resolve;
mod resolve_metadata;
pub mod secret;

mod validate;

pub use build_key_proof::{KeyProofJwtRequest, KeyProofSigner};
#[cfg(feature = "identity-jose")]
pub use credential_jwe::{
    CredentialJweContentEncryptionAlgorithm, EncryptedCredentialRequest,
    JoseJweCredentialRequestEncryptor, JoseJweCredentialResponseDecryptor,
};
#[cfg(feature = "identity-jose")]
pub use credential_jwe_key::CredentialJwePrivateKey;
pub use error::{WalletError, WalletResult, WalletStatus};
pub use metadata::{
    verify_signed_issuer_metadata, ParsedSignedIssuerMetadata, SignedIssuerMetadataJwt,
    SignedIssuerMetadataTrustVerifier, SignedIssuerMetadataValidationContext,
    SignedMetadataAlgorithm, SignedMetadataSignerTrustPurpose, SignedMetadataTrustEvidence,
    SignedMetadataTrustEvidenceInput, SignedMetadataTrustPurpose, VerifiedSignedIssuerMetadata,
};
pub use request::{
    AuthorizationCodeTokenRequest, PreAuthorizedTokenRequest, WalletCredentialRequest,
};
pub use resolve::{
    resolve_credential_offer_uri, validate_offer_authorization_servers, CredentialOfferFetcher,
    CredentialOfferGrantType, ValidatedCredentialOffer, ValidatedIssuance,
};
pub use resolve_metadata::{
    credential_issuer_metadata_url, resolve_credential_issuer_metadata,
    CredentialIssuerMetadataFetcher,
};
pub use secret::{AuthorizationCode, PreAuthorizedCode, TransactionCode};
