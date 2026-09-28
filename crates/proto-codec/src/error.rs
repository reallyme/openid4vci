// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Generated protobuf codec errors.

use thiserror::Error;

/// Result alias for generated protobuf codec helpers.
pub type ProtoCodecResult<T> = Result<T, ProtoCodecError>;

/// Fixed errors for generated protobuf byte and JSON helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ProtoCodecError {
    /// The binary protobuf message or protobuf JSON document exceeds its limit.
    #[error("openid4vci_protobuf_payload_too_large")]
    PayloadTooLarge,
    /// Protobuf bytes could not be decoded.
    #[error("invalid_openid4vci_protobuf")]
    Decode,
    /// Generated protobuf JSON serialization failed.
    #[error("invalid_openid4vci_protobuf_json_serialization")]
    JsonSerialize,
    /// Generated protobuf JSON deserialization failed.
    #[error("invalid_openid4vci_protobuf_json")]
    JsonDeserialize,
}
