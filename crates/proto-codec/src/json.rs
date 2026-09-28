// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strict handling for JSON documents embedded in protobuf byte fields.

use serde::de::{DeserializeSeed, Error as DeError, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::Serialize;
use serde_json::{Map, Number, Value};
use std::fmt;
use zeroize::Zeroize;

use crate::convert::{ProtoError, ProtoResult};
use crate::limits::{MAX_OPENID4VCI_EMBEDDED_JSON_BYTES, OPENID4VCI_EMBEDDED_JSON_RECURSION_LIMIT};

const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;
const MIN_SAFE_JSON_INTEGER: i64 = -9_007_199_254_740_991;

#[derive(Clone, Copy)]
struct JsonValueSeed {
    remaining_depth: u32,
}

impl<'de> DeserializeSeed<'de> for JsonValueSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(JsonValueVisitor {
            remaining_depth: self.remaining_depth,
        })
    }
}

struct JsonValueVisitor {
    remaining_depth: u32,
}

impl JsonValueVisitor {
    fn child_depth<E: DeError>(&self) -> Result<u32, E> {
        self.remaining_depth
            .checked_sub(1)
            .ok_or_else(|| E::custom(JsonPolicyViolation::RecursionLimit))
    }
}

impl<'de> Visitor<'de> for JsonValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded JSON value without duplicate object keys")
    }

    fn visit_bool<E: DeError>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E: DeError>(self, value: i64) -> Result<Self::Value, E> {
        if !(MIN_SAFE_JSON_INTEGER
            ..=i64::try_from(MAX_SAFE_JSON_INTEGER)
                .map_err(|_| E::custom(JsonPolicyViolation::InvalidNumber))?)
            .contains(&value)
        {
            return Err(E::custom(JsonPolicyViolation::InvalidNumber));
        }
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_u64<E: DeError>(self, value: u64) -> Result<Self::Value, E> {
        if value > MAX_SAFE_JSON_INTEGER {
            return Err(E::custom(JsonPolicyViolation::InvalidNumber));
        }
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<E: DeError>(self, _: f64) -> Result<Self::Value, E> {
        // Match the outer ProtoJSON boundary: floating-point values are not a
        // stable, lossless representation for protocol JSON byte fields.
        Err(E::custom(JsonPolicyViolation::InvalidNumber))
    }

    fn visit_str<E: DeError>(self, value: &str) -> Result<Self::Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E: DeError>(self, value: String) -> Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E: DeError>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E: DeError>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        JsonValueSeed {
            remaining_depth: self.child_depth()?,
        }
        .deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let child_depth = self.child_depth()?;
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(JsonValueSeed {
            remaining_depth: child_depth,
        })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let child_depth = self.child_depth()?;
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                let _: IgnoredAny = object.next_value()?;
                return Err(A::Error::custom(JsonPolicyViolation::DuplicateKey));
            }
            let value = object.next_value_seed(JsonValueSeed {
                remaining_depth: child_depth,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

#[derive(Clone, Copy)]
enum JsonPolicyViolation {
    DuplicateKey,
    InvalidNumber,
    RecursionLimit,
}

impl fmt::Display for JsonPolicyViolation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DuplicateKey => "duplicate JSON object key",
            Self::InvalidNumber => "invalid JSON number",
            Self::RecursionLimit => "JSON recursion limit exceeded",
        })
    }
}

pub(crate) fn serialize_value<T: Serialize>(value: &T) -> ProtoResult<Vec<u8>> {
    let mut bytes = serde_json::to_vec(value).map_err(|_| ProtoError::InvalidJson)?;
    if bytes.len() > MAX_OPENID4VCI_EMBEDDED_JSON_BYTES {
        bytes.zeroize();
        return Err(ProtoError::PayloadTooLarge);
    }
    Ok(bytes)
}

pub(crate) fn deserialize_value(bytes: &[u8]) -> ProtoResult<Value> {
    if bytes.len() > MAX_OPENID4VCI_EMBEDDED_JSON_BYTES {
        return Err(ProtoError::PayloadTooLarge);
    }

    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = JsonValueSeed {
        remaining_depth: OPENID4VCI_EMBEDDED_JSON_RECURSION_LIMIT,
    }
    .deserialize(&mut deserializer)
    .map_err(|_| ProtoError::InvalidJson)?;
    deserializer.end().map_err(|_| ProtoError::InvalidJson)?;
    Ok(value)
}
