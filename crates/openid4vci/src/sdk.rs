// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical generated-message SDK surface.
//!
//! Cross-language packages bind this module's protobuf contract and bounded
//! wire operations. Hand-written Rust domain models remain available through
//! integration modules at the crate root, but they are not SDK DTOs.

/// Generated `reallyme.openid4vci.v1` protobuf bindings.
pub use openid4vci_proto::generated as protobuf;
pub use openid4vci_proto_codec::{
    decode_operation_response_v1, execute_operation_json_v1, execute_operation_request,
    execute_operation_v1, OpenId4VciOperationKind,
};
pub use openid4vci_proto_codec::{
    decode_proto, encode_proto, json_to_proto, proto_to_json, OpenId4VciProtoJson, ProtoCodecError,
};
pub use openid4vci_proto_codec::{
    MAX_OPENID4VCI_EMBEDDED_JSON_BYTES, MAX_OPENID4VCI_OPERATION_RESPONSE_BYTES,
    MAX_OPENID4VCI_OPERATION_RESPONSE_OVERHEAD_BYTES, MAX_OPENID4VCI_PROTO_JSON_BYTES,
    MAX_OPENID4VCI_PROTO_MESSAGE_BYTES, OPENID4VCI_EMBEDDED_JSON_RECURSION_LIMIT,
    OPENID4VCI_PROTO_JSON_RECURSION_LIMIT, OPENID4VCI_PROTO_RECURSION_LIMIT,
    OPENID4VCI_PROTO_UNKNOWN_FIELD_LIMIT,
};

/// Canonical typed error contracts shared by Rust and platform facades.
pub mod error {
    pub use openid4vci_proto::generated::proto::reallyme::openid4vci::v1::OpenId4VciErrorReason;
    pub use openid4vci_proto_codec::map_error_reason::{
        error_reason_code, error_reason_from_i32, error_reason_from_identity_stack_error,
        identity_stack_error_from_reason, proto_codec_error_to_proto,
    };
    pub use reallyme_ssi_proto::generated::proto::reallyme::identity::common::v1::{
        IdentityStackError, IdentityStackErrorDomain,
    };
}
