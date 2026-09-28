// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded OpenID4VCI protobuf codecs and typed domain conversions.
//!
//! Generated messages intentionally live in `openid4vci-proto`. This crate owns
//! every operation that interprets bytes, JSON, enum values, or message fields
//! as validated OpenID4VCI domain data.

/// Conversions between generated protobuf messages and OpenID4VCI wire types.
pub mod convert;

mod decode;
mod encode;
mod error;
mod json;
mod limits;
mod operation;
mod proto_json;

/// Public error/status to protobuf reason-code mappings.
pub mod map_error_reason;

pub use decode::{decode_proto, json_to_proto};
pub use encode::{encode_proto, proto_to_json};
pub use error::{ProtoCodecError, ProtoCodecResult};
pub use limits::{
    MAX_OPENID4VCI_EMBEDDED_JSON_BYTES, MAX_OPENID4VCI_PROTO_JSON_BYTES,
    MAX_OPENID4VCI_PROTO_MESSAGE_BYTES, OPENID4VCI_EMBEDDED_JSON_RECURSION_LIMIT,
    OPENID4VCI_PROTO_JSON_RECURSION_LIMIT, OPENID4VCI_PROTO_RECURSION_LIMIT,
    OPENID4VCI_PROTO_UNKNOWN_FIELD_LIMIT,
};
pub use operation::{
    decode_operation_response_v1, execute_operation_json_v1, execute_operation_request,
    execute_operation_v1, OpenId4VciOperationKind, MAX_OPENID4VCI_OPERATION_RESPONSE_BYTES,
    MAX_OPENID4VCI_OPERATION_RESPONSE_OVERHEAD_BYTES,
};
pub use proto_json::OpenId4VciProtoJson;
