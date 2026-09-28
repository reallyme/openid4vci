// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Public-only JSON Web Key owners used at protocol serialization boundaries.

use core::fmt::{Debug, Formatter};

use serde::de::{Error as SerdeError, IgnoredAny, MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use zeroize::Zeroize;

use crate::error::{OpenId4VciError, OpenId4VciResult, Reason};
use crate::validation::{validate_non_empty_asciiish, zeroize_json_strings};

const PRIVATE_JWK_MEMBERS: &[&str] = &[
    "d",
    "p",
    "q",
    "dp",
    "dq",
    "qi",
    "oth",
    "k",
    "priv",
    "privateKey",
    "secretKey",
];
const MAX_JWK_MEMBERS: usize = 32;
const MAX_JWK_DEPTH: usize = 8;
const MAX_JWK_NODES: usize = 128;
const MAX_JWKS_KEYS: usize = 32;

/// A validated asymmetric public JWK.
///
/// The inner JSON value is private so secret-bearing or symmetric JWK shapes
/// cannot be created with a struct literal and accidentally serialized.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicJwk {
    value: Value,
}

impl PublicJwk {
    /// Validates and takes ownership of a public JWK value.
    pub fn new(mut value: Value) -> OpenId4VciResult<Self> {
        if validate_public_jwk_value(&value).is_err() {
            zeroize_json_strings(&mut value);
            return Err(OpenId4VciError::new(Reason::InvalidJwk));
        }
        Ok(Self { value })
    }

    /// Borrows the sanitized JSON representation for cryptographic providers.
    #[must_use]
    pub const fn as_value(&self) -> &Value {
        &self.value
    }

    /// Returns the JWK key identifier when present.
    #[must_use]
    pub fn key_id(&self) -> Option<&str> {
        self.string_member("kid")
    }

    /// Returns the JWK algorithm when present.
    #[must_use]
    pub fn algorithm(&self) -> Option<&str> {
        self.string_member("alg")
    }

    /// Returns the JWK key type.
    #[must_use]
    pub fn key_type(&self) -> &str {
        self.string_member("kty").unwrap_or_default()
    }

    fn string_member(&self, name: &str) -> Option<&str> {
        self.value.as_object()?.get(name)?.as_str()
    }
}

impl Debug for PublicJwk {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("PublicJwk(<redacted>)")
    }
}

impl Drop for PublicJwk {
    fn drop(&mut self) {
        zeroize_json_strings(&mut self.value);
    }
}

impl TryFrom<Value> for PublicJwk {
    type Error = OpenId4VciError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl Serialize for PublicJwk {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.value.serialize(serializer)
    }
}

struct PublicJwkVisitor;

impl<'de> Visitor<'de> for PublicJwkVisitor {
    type Value = PublicJwk;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("an asymmetric public JWK object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut members = serde_json::Map::new();
        let mut member_count = 0_usize;
        while let Some(name) = map.next_key::<String>()? {
            member_count = member_count
                .checked_add(1)
                .ok_or_else(|| A::Error::custom("invalid public JWK"))?;
            if member_count > MAX_JWK_MEMBERS
                || PRIVATE_JWK_MEMBERS.contains(&name.as_str())
                || members.contains_key(&name)
            {
                return Err(A::Error::custom("invalid public JWK"));
            }
            let mut value = map.next_value::<Value>()?;
            if contains_private_member(&value) {
                zeroize_json_strings(&mut value);
                return Err(A::Error::custom("invalid public JWK"));
            }
            members.insert(name, value);
        }
        PublicJwk::new(Value::Object(members)).map_err(|_| A::Error::custom("invalid public JWK"))
    }
}

impl<'de> Deserialize<'de> for PublicJwk {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(PublicJwkVisitor)
    }
}

/// A bounded non-empty JWK Set containing uniquely identified public keys.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicJwkSet {
    keys: Vec<PublicJwk>,
}

impl PublicJwkSet {
    /// Validates a JWK Set's key count and key identifiers.
    pub fn new(keys: Vec<PublicJwk>) -> OpenId4VciResult<Self> {
        if keys.is_empty() || keys.len() > MAX_JWKS_KEYS {
            return Err(OpenId4VciError::new(Reason::InvalidJwkSet));
        }
        for (index, key) in keys.iter().enumerate() {
            let key_id = key
                .key_id()
                .ok_or(OpenId4VciError::new(Reason::InvalidJwkSet))?;
            let algorithm = key
                .algorithm()
                .ok_or(OpenId4VciError::new(Reason::InvalidJwkSet))?;
            validate_non_empty_asciiish(key_id)?;
            validate_non_empty_asciiish(algorithm)?;
            if keys
                .iter()
                .take(index)
                .any(|candidate| candidate.key_id() == Some(key_id))
            {
                return Err(OpenId4VciError::new(Reason::InvalidJwkSet));
            }
        }
        Ok(Self { keys })
    }

    /// Validates and takes ownership of a JSON JWK Set representation.
    pub fn from_value(mut value: Value) -> OpenId4VciResult<Self> {
        let Some(object) = value.as_object_mut() else {
            zeroize_json_strings(&mut value);
            return Err(OpenId4VciError::new(Reason::InvalidJwkSet));
        };
        let Some(keys_value) = object.remove("keys") else {
            zeroize_json_strings(&mut value);
            return Err(OpenId4VciError::new(Reason::InvalidJwkSet));
        };
        let Value::Array(values) = keys_value else {
            zeroize_json_strings(&mut value);
            return Err(OpenId4VciError::new(Reason::InvalidJwkSet));
        };
        let mut keys = Vec::with_capacity(values.len());
        for value in values {
            keys.push(PublicJwk::new(value)?);
        }
        Self::new(keys)
    }

    /// Returns the public keys in metadata order.
    #[must_use]
    pub fn keys(&self) -> &[PublicJwk] {
        &self.keys
    }

    /// Converts the validated set to its JSON representation.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let keys = self.keys.iter().map(|key| key.as_value().clone()).collect();
        Value::Object(serde_json::Map::from_iter([(
            "keys".to_owned(),
            Value::Array(keys),
        )]))
    }
}

impl TryFrom<Value> for PublicJwkSet {
    type Error = OpenId4VciError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        Self::from_value(value)
    }
}

impl Debug for PublicJwkSet {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PublicJwkSet")
            .field("key_count", &self.keys.len())
            .finish()
    }
}

impl Serialize for PublicJwkSet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry("keys", &self.keys)?;
        map.end()
    }
}

struct PublicJwkSetVisitor;

impl<'de> Visitor<'de> for PublicJwkSetVisitor {
    type Value = PublicJwkSet;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("a public JWK Set object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys: Option<Vec<PublicJwk>> = None;
        while let Some(name) = map.next_key::<String>()? {
            if name == "keys" {
                if keys.is_some() {
                    return Err(A::Error::custom("invalid public JWK Set"));
                }
                keys = Some(map.next_value()?);
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        PublicJwkSet::new(keys.ok_or_else(|| A::Error::custom("invalid public JWK Set"))?)
            .map_err(|_| A::Error::custom("invalid public JWK Set"))
    }
}

impl<'de> Deserialize<'de> for PublicJwkSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(PublicJwkSetVisitor)
    }
}

fn validate_public_jwk_value(value: &Value) -> OpenId4VciResult<()> {
    let object = value
        .as_object()
        .ok_or(OpenId4VciError::new(Reason::InvalidJwk))?;
    if object.is_empty() || object.len() > MAX_JWK_MEMBERS || contains_private_member(value) {
        return Err(OpenId4VciError::new(Reason::InvalidJwk));
    }
    let key_type = object
        .get("kty")
        .and_then(Value::as_str)
        .ok_or(OpenId4VciError::new(Reason::InvalidJwk))?;
    validate_non_empty_asciiish(key_type)?;
    if key_type == "oct" {
        return Err(OpenId4VciError::new(Reason::InvalidJwk));
    }
    let mut nodes = 0_usize;
    validate_json_bounds(value, 0, &mut nodes)
}

fn contains_private_member(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(name, nested)| {
            PRIVATE_JWK_MEMBERS.contains(&name.as_str()) || contains_private_member(nested)
        }),
        Value::Array(values) => values.iter().any(contains_private_member),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => false,
    }
}

fn validate_json_bounds(value: &Value, depth: usize, nodes: &mut usize) -> OpenId4VciResult<()> {
    *nodes = nodes
        .checked_add(1)
        .ok_or(OpenId4VciError::new(Reason::InvalidJwk))?;
    if depth > MAX_JWK_DEPTH || *nodes > MAX_JWK_NODES {
        return Err(OpenId4VciError::new(Reason::InvalidJwk));
    }
    let next_depth = depth
        .checked_add(1)
        .ok_or(OpenId4VciError::new(Reason::InvalidJwk))?;
    match value {
        Value::Object(object) => {
            for nested in object.values() {
                validate_json_bounds(nested, next_depth, nodes)?;
            }
        }
        Value::Array(values) => {
            for nested in values {
                validate_json_bounds(nested, next_depth, nodes)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

impl Zeroize for PublicJwk {
    fn zeroize(&mut self) {
        zeroize_json_strings(&mut self.value);
    }
}
