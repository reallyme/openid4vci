// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Allocation-free structural limits applied before JWK canonicalization.

use serde_json::Value;
use thiserror::Error;

const MAX_PUBLIC_JWK_DEPTH: usize = 8;
const MAX_PUBLIC_JWK_NODES: usize = 128;
pub(crate) const MAX_PUBLIC_JWK_BYTES: usize = 16_384;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PublicJwkBoundsError {
    #[error("public JWK nesting exceeds the supported limit")]
    Depth,
    #[error("public JWK structure exceeds the supported limit")]
    Nodes,
    #[error("public JWK text exceeds the supported limit")]
    TextBytes,
    #[error("public JWK size arithmetic overflowed")]
    ArithmeticOverflow,
}

pub(crate) fn validate_public_jwk_shape(jwk: &Value) -> Result<(), PublicJwkBoundsError> {
    let mut budget = PublicJwkBudget::default();
    visit_value(jwk, 0, &mut budget)
}

#[derive(Default)]
struct PublicJwkBudget {
    nodes: usize,
    text_bytes: usize,
}

fn visit_value(
    value: &Value,
    depth: usize,
    budget: &mut PublicJwkBudget,
) -> Result<(), PublicJwkBoundsError> {
    if depth > MAX_PUBLIC_JWK_DEPTH {
        return Err(PublicJwkBoundsError::Depth);
    }
    budget.nodes = budget
        .nodes
        .checked_add(1)
        .ok_or(PublicJwkBoundsError::ArithmeticOverflow)?;
    if budget.nodes > MAX_PUBLIC_JWK_NODES {
        return Err(PublicJwkBoundsError::Nodes);
    }

    match value {
        Value::String(text) => add_text_bytes(text.len(), budget),
        Value::Array(values) => {
            for member in values {
                visit_value(member, next_depth(depth)?, budget)?;
            }
            Ok(())
        }
        Value::Object(object) => {
            for (name, member) in object {
                add_text_bytes(name.len(), budget)?;
                visit_value(member, next_depth(depth)?, budget)?;
            }
            Ok(())
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(()),
    }
}

fn add_text_bytes(
    additional: usize,
    budget: &mut PublicJwkBudget,
) -> Result<(), PublicJwkBoundsError> {
    budget.text_bytes = budget
        .text_bytes
        .checked_add(additional)
        .ok_or(PublicJwkBoundsError::ArithmeticOverflow)?;
    if budget.text_bytes > MAX_PUBLIC_JWK_BYTES {
        return Err(PublicJwkBoundsError::TextBytes);
    }
    Ok(())
}

fn next_depth(depth: usize) -> Result<usize, PublicJwkBoundsError> {
    depth
        .checked_add(1)
        .ok_or(PublicJwkBoundsError::ArithmeticOverflow)
}

#[cfg(test)]
#[path = "validate_credential_jwk_bounds_tests.rs"]
mod validate_credential_jwk_bounds_tests;
