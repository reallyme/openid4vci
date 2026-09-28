// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Generated protobuf encoding helpers.

use buffa::Message;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{ProtoCodecError, ProtoCodecResult};
use crate::limits::{MAX_OPENID4VCI_PROTO_JSON_BYTES, MAX_OPENID4VCI_PROTO_MESSAGE_BYTES};
use crate::OpenId4VciProtoJson;

/// Encodes a generated OpenID4VCI protobuf message into bytes.
pub fn encode_proto<M>(message: &M) -> ProtoCodecResult<Zeroizing<Vec<u8>>>
where
    M: OpenId4VciProtoJson,
{
    encode_proto_zeroizing_with_limit(message, MAX_OPENID4VCI_PROTO_MESSAGE_BYTES)
}

pub(crate) fn encode_proto_zeroizing_with_limit<M>(
    message: &M,
    maximum_bytes: usize,
) -> ProtoCodecResult<Zeroizing<Vec<u8>>>
where
    M: Message,
{
    let maximum = u32::try_from(maximum_bytes).map_err(|_| ProtoCodecError::PayloadTooLarge)?;
    let mut encoded = Zeroizing::new(Vec::new());
    message
        .try_encode_bounded(maximum, &mut *encoded)
        .map_err(|_| ProtoCodecError::PayloadTooLarge)?;
    Ok(encoded)
}

/// Serializes a generated OpenID4VCI protobuf message using Buffa protobuf JSON.
pub fn proto_to_json<M>(message: &M) -> ProtoCodecResult<Zeroizing<String>>
where
    M: OpenId4VciProtoJson,
{
    // Validate the generated message against the binary bound first. This also
    // keeps the validation allocation under a zeroizing owner.
    drop(encode_proto_zeroizing_with_limit(
        message,
        MAX_OPENID4VCI_PROTO_MESSAGE_BYTES,
    )?);

    // Allocate the serializer buffer under Zeroizing from the start so partial
    // serialization and oversize rejection wipe any emitted sensitive fields.
    let mut json_bytes = Zeroizing::new(Vec::new());
    serde_json::to_writer(&mut *json_bytes, message).map_err(|_| ProtoCodecError::JsonSerialize)?;
    if json_bytes.len() > MAX_OPENID4VCI_PROTO_JSON_BYTES {
        return Err(ProtoCodecError::PayloadTooLarge);
    }

    match String::from_utf8(core::mem::take(&mut *json_bytes)) {
        Ok(json) => Ok(Zeroizing::new(json)),
        Err(error) => {
            let mut invalid_bytes = error.into_bytes();
            invalid_bytes.zeroize();
            Err(ProtoCodecError::JsonSerialize)
        }
    }
}
