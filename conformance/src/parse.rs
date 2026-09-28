// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Conformance vector parsing.

use crate::error::{ConformanceError, ConformanceResult};
use crate::vector::ConformanceVector;

/// Parses conformance vector JSON.
pub fn parse_vectors(json: &str) -> ConformanceResult<Vec<ConformanceVector>> {
    serde_json::from_str(json).map_err(|_| ConformanceError::InvalidJson)
}
