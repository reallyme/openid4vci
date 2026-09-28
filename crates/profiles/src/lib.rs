// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Profile policy surfaces for OpenID4VCI deployments.
//!
//! **HAIP** is the OpenID4VC High Assurance Interoperability Profile. It is
//! the eIDAS-relevant profile surface in this workspace, and concrete
//! high-assurance issuer/wallet policy should be implemented here instead of
//! being scattered across HTTP adapters or credential-format encoders.

pub mod build;
pub mod define;
pub mod validate;

pub use build::{eudi_pid_policy, haip_policy};
pub use define::{IssuanceProfile, ProfilePolicy, HAIP_PROFILE_NAME, HAIP_SHORT_NAME};
pub use validate::{
    IssuerProfileRequirements, ProfilePolicyError, ProfilePolicyResult, ProfilePolicyStatus,
};
