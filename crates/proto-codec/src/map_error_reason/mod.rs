// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Stable OpenID4VCI error-reason mappings.

mod convert;
mod define;
mod define_trust;

pub use convert::{
    attestation_status_from_proto, attestation_status_to_proto, credential_error_code_from_proto,
    credential_error_code_to_proto, deferred_credential_error_code_from_proto,
    deferred_credential_error_code_to_proto, error_reason_code, error_reason_from_enum_value,
    error_reason_from_i32, error_reason_from_identity_stack_error,
    identity_stack_error_from_reason, issuer_problem_status_from_proto,
    issuer_problem_status_to_proto, issuer_status_from_proto, issuer_status_to_proto,
    notification_error_code_from_proto, notification_error_code_to_proto,
    openid4vci_reason_from_proto, openid4vci_reason_to_proto, problem_type_from_proto,
    problem_type_to_proto, profile_policy_status_from_proto, profile_policy_status_to_proto,
    proto_codec_error_from_proto, proto_codec_error_to_proto, proto_error_to_proto,
    wallet_status_from_proto, wallet_status_to_proto,
};
pub(crate) use define::{FromDomainReason, FromProtoReason, OPENID4VCI_DOMAIN};
