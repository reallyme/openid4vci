// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Profile policy surfaces for OpenID4VCI deployments.
//!
//! **HAIP** is the OpenID4VC High Assurance Interoperability Profile. It is
//! the eIDAS-relevant profile surface in this workspace. This crate owns
//! high-assurance issuer/wallet policy independently of HTTP framing and
//! credential-format encoding.

pub mod build;
pub mod define;
pub mod etsi_credential_request;
pub mod eudi_metadata;
pub mod validate;

pub use build::{eudi_pid_policy, haip_policy};
pub use define::{IssuanceProfile, ProfilePolicy, HAIP_PROFILE_NAME, HAIP_SHORT_NAME};
pub use etsi_credential_request::{
    validate_etsi_credential_request_proofs, EtsiCredentialProofError,
    EtsiCredentialProofErrorReason, EtsiCredentialProofMechanism,
};
pub use eudi_metadata::{
    parse_credential_reuse_policy, CredentialReusePolicy, ReuseMethod, ReuseMethodSet,
    ReusePolicyError, ReusePolicyErrorReason, ReusePolicyOption, SelectedCredentialReusePolicy,
};
pub use validate::{
    IssuerProfileRequirements, ProfilePolicyError, ProfilePolicyResult, ProfilePolicyStatus,
};
