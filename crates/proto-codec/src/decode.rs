// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Generated protobuf decoding helpers.

use std::collections::BTreeSet;
use std::fmt::{Display, Formatter};

use buffa::{DecodeOptions, Message};
use serde::de::{DeserializeSeed, Error as DeError, MapAccess, SeqAccess, Visitor};

use crate::encode::encode_proto_zeroizing_with_limit;
use crate::error::{ProtoCodecError, ProtoCodecResult};
use crate::limits::{
    MAX_OPENID4VCI_PROTO_JSON_BYTES, MAX_OPENID4VCI_PROTO_MESSAGE_BYTES,
    OPENID4VCI_PROTO_JSON_RECURSION_LIMIT, OPENID4VCI_PROTO_RECURSION_LIMIT,
    OPENID4VCI_PROTO_UNKNOWN_FIELD_LIMIT,
};
use crate::OpenId4VciProtoJson;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProtoJsonStructureError {
    DuplicateMember,
    RecursionLimit,
}

impl Display for ProtoJsonStructureError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::DuplicateMember => "duplicate ProtoJSON member",
            Self::RecursionLimit => "ProtoJSON recursion limit exceeded",
        })
    }
}

#[derive(Clone, Copy)]
struct ProtoJsonStructureSeed {
    remaining_depth: u32,
}

impl ProtoJsonStructureSeed {
    fn child_depth<E: DeError>(self) -> Result<u32, E> {
        self.remaining_depth
            .checked_sub(1)
            .ok_or_else(|| E::custom(ProtoJsonStructureError::RecursionLimit))
    }
}

impl<'de> DeserializeSeed<'de> for ProtoJsonStructureSeed {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for ProtoJsonStructureSeed {
    type Value = ();

    fn expecting(&self, formatter: &mut Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("bounded ProtoJSON without duplicate members")
    }

    fn visit_bool<E: DeError>(self, _: bool) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E: DeError>(self, _: i64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E: DeError>(self, _: u64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E: DeError>(self, _: f64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_str<E: DeError>(self, _: &str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_borrowed_str<E: DeError>(self, _: &'de str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_string<E: DeError>(self, _: String) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_none<E: DeError>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_unit<E: DeError>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        ProtoJsonStructureSeed {
            remaining_depth: self.child_depth()?,
        }
        .deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let child_depth = self.child_depth()?;
        while sequence
            .next_element_seed(ProtoJsonStructureSeed {
                remaining_depth: child_depth,
            })?
            .is_some()
        {}
        Ok(())
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let child_depth = self.child_depth()?;
        let mut members = BTreeSet::new();
        while let Some(member) = object.next_key::<String>()? {
            if !members.insert(member) {
                return Err(A::Error::custom(ProtoJsonStructureError::DuplicateMember));
            }
            object.next_value_seed(ProtoJsonStructureSeed {
                remaining_depth: child_depth,
            })?;
        }
        Ok(())
    }
}

/// Decodes generated OpenID4VCI protobuf bytes into the requested message type.
pub fn decode_proto<M>(bytes: &[u8]) -> ProtoCodecResult<M>
where
    M: OpenId4VciProtoJson,
{
    decode_proto_with_limit(bytes, MAX_OPENID4VCI_PROTO_MESSAGE_BYTES)
}

pub(crate) fn decode_proto_with_limit<M>(bytes: &[u8], maximum_bytes: usize) -> ProtoCodecResult<M>
where
    M: Message,
{
    if bytes.len() > maximum_bytes {
        return Err(ProtoCodecError::PayloadTooLarge);
    }

    DecodeOptions::new()
        .with_recursion_limit(OPENID4VCI_PROTO_RECURSION_LIMIT)
        .with_unknown_field_limit(OPENID4VCI_PROTO_UNKNOWN_FIELD_LIMIT)
        .with_max_message_size(maximum_bytes)
        .decode_from_slice(bytes)
        .map_err(|_| ProtoCodecError::Decode)
}

/// Deserializes Buffa protobuf JSON into the requested generated message type.
pub fn json_to_proto<M>(json: &str) -> ProtoCodecResult<M>
where
    M: OpenId4VciProtoJson,
{
    if json.len() > MAX_OPENID4VCI_PROTO_JSON_BYTES {
        return Err(ProtoCodecError::PayloadTooLarge);
    }

    // Run a non-materializing structural pass before generated deserialization.
    // Generated Serde models reject unknown fields; this pass supplies the
    // duplicate-member and explicit recursion policies that derived models
    // cannot enforce after map members have been collapsed.
    let mut structure = serde_json::Deserializer::from_str(json);
    ProtoJsonStructureSeed {
        remaining_depth: OPENID4VCI_PROTO_JSON_RECURSION_LIMIT,
    }
    .deserialize(&mut structure)
    .map_err(|_| ProtoCodecError::JsonDeserialize)?;
    structure
        .end()
        .map_err(|_| ProtoCodecError::JsonDeserialize)?;

    let message: M = serde_json::from_str(json).map_err(|_| ProtoCodecError::JsonDeserialize)?;
    drop(encode_proto_zeroizing_with_limit(
        &message,
        MAX_OPENID4VCI_PROTO_MESSAGE_BYTES,
    )?);
    Ok(message)
}
