// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Resource limits enforced by the generated protobuf boundary.

/// Maximum accepted or emitted binary protobuf message size.
pub const MAX_OPENID4VCI_PROTO_MESSAGE_BYTES: usize = 64 * 1_024;

/// Maximum accepted or emitted protobuf JSON document size.
///
/// The allowance accounts for base64 expansion when protobuf byte fields are
/// represented in JSON while retaining a finite boundary before allocation.
pub const MAX_OPENID4VCI_PROTO_JSON_BYTES: usize = 131_072;

/// Maximum accepted or emitted JSON document in one protobuf byte field.
pub const MAX_OPENID4VCI_EMBEDDED_JSON_BYTES: usize = 65_536;

/// Maximum nesting depth accepted in an embedded JSON byte field.
pub const OPENID4VCI_EMBEDDED_JSON_RECURSION_LIMIT: u32 = 64;

/// Maximum nesting depth accepted by the protobuf decoder.
pub const OPENID4VCI_PROTO_RECURSION_LIMIT: u32 = 64;

/// Maximum array/object nesting depth accepted by the ProtoJSON decoder.
pub const OPENID4VCI_PROTO_JSON_RECURSION_LIMIT: u32 = 64;

/// Number of unknown protobuf fields accepted at the public boundary.
///
/// OpenID4VCI operations fail closed on schema drift so callers cannot smuggle
/// unreviewed data through an older SDK or service implementation.
pub const OPENID4VCI_PROTO_UNKNOWN_FIELD_LIMIT: usize = 0;
