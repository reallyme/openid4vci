// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde_json::{json, Value};

use super::{
    validate_public_jwk_shape, PublicJwkBoundsError, MAX_PUBLIC_JWK_BYTES, MAX_PUBLIC_JWK_NODES,
};

#[test]
fn rejects_excessive_text_before_canonicalization() {
    let jwk = json!({"extension": "a".repeat(MAX_PUBLIC_JWK_BYTES)});
    assert_eq!(
        validate_public_jwk_shape(&jwk),
        Err(PublicJwkBoundsError::TextBytes)
    );
}

#[test]
fn rejects_excessive_nesting_before_canonicalization() {
    let mut nested = json!(null);
    for _ in 0..10 {
        nested = json!({"child": nested});
    }
    assert_eq!(
        validate_public_jwk_shape(&nested),
        Err(PublicJwkBoundsError::Depth)
    );
}

#[test]
fn accepts_exact_text_and_node_boundaries() {
    let text = Value::String("a".repeat(MAX_PUBLIC_JWK_BYTES));
    assert_eq!(validate_public_jwk_shape(&text), Ok(()));

    let nodes = Value::Array(core::iter::repeat_n(Value::Null, MAX_PUBLIC_JWK_NODES - 1).collect());
    assert_eq!(validate_public_jwk_shape(&nodes), Ok(()));
}

#[test]
fn rejects_wide_structures_beyond_the_node_limit() {
    let nodes = Value::Array(core::iter::repeat_n(Value::Null, MAX_PUBLIC_JWK_NODES).collect());
    assert_eq!(
        validate_public_jwk_shape(&nodes),
        Err(PublicJwkBoundsError::Nodes)
    );
}
