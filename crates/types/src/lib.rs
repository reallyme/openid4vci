// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! OpenID4VCI 1.0 final wire types and validation helpers.
//!
//! This crate owns JSON-facing data structures only. Issuer storage, signing,
//! proof verification, wallet HTTP transport, and profile policy live in
//! sibling crates so the wire model remains stable and auditable.

pub mod credential_error;
pub mod error;
pub mod format;
pub mod jwk;
pub mod metadata;
pub mod nonce;
pub mod notification;
pub mod offer;
pub mod problem;
pub mod request;
pub mod response;

mod validation;

pub use credential_error::{
    CredentialErrorCode, CredentialErrorResponse, DeferredCredentialErrorCode,
    DeferredCredentialErrorResponse, NotificationErrorCode, NotificationErrorResponse,
};
pub use error::{OpenId4VciError, OpenId4VciResult, Reason};
pub use format::CredentialFormat;
pub use jwk::{PublicJwk, PublicJwkSet};
pub use metadata::{
    BatchCredentialIssuance, CredentialConfiguration, CredentialRequestEncryptionMetadata,
    CredentialResponseEncryptionMetadata, CredentialSigningAlg, IssuerMetadata,
    IssuerMetadataBuilder, KeyAttestationsRequired, ProofTypeMetadata, MIN_BATCH_SIZE,
};
pub use nonce::{NonceRequest, NonceResponse};
pub use notification::{NotificationEvent, NotificationRequest};
pub use offer::{
    build_credential_offer_reference_uri, build_credential_offer_uri, parse_credential_offer_uri,
    AuthorizationCodeGrant, CredentialOffer, CredentialOfferGrant, ParsedCredentialOffer,
    PreAuthorizedCodeGrant, TxCode, TxCodeInputMode, DEFAULT_CREDENTIAL_OFFER_SCHEME,
    MAX_CREDENTIAL_OFFER_URI_BYTES,
};
pub use problem::{IssuerProblemStatus, ProblemDetails, ProblemType};
pub use request::{CredentialRequest, CredentialResponseEncryption, CredentialSelector, Proofs};
pub use response::{
    CredentialEnvelope, CredentialPayload, CredentialResponse, DeferredCredentialRequest,
    MAX_CREDENTIAL_RESPONSE_JSON_BYTES,
};
