// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Conformance harness errors.

use thiserror::Error;

/// Result alias for conformance vector loading.
pub type ConformanceResult<T> = Result<T, ConformanceError>;

/// Conformance vector loading or execution error.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ConformanceError {
    /// The vector JSON was malformed.
    #[error("invalid_vector_json")]
    InvalidJson,
    /// A vector named a `target` the runner does not know how to dispatch.
    #[error("unknown_target")]
    UnknownTarget,
    /// A fixed conformance validation policy could not be constructed.
    #[error("invalid_harness_configuration")]
    InvalidHarnessConfiguration,
}
