// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Machine-readable conformance vector types.

use serde::{Deserialize, Serialize};

/// Expected result for a vector case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedResult {
    /// Vector must be accepted.
    Accept,
    /// Vector must be rejected.
    Reject,
}

/// One conformance vector case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceVector {
    /// Stable vector identifier.
    pub id: String,
    /// Spec section covered by the vector.
    pub spec_section: String,
    /// Target module or endpoint.
    pub target: String,
    /// Input payload. Most targets consume JSON; compact-JWT targets consume the
    /// encoded token directly for byte-exact parser coverage.
    pub input_json: String,
    /// Expected result.
    pub expected: ExpectedResult,
}
