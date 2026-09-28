// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Machine-readable conformance vector harness.

pub mod error;
pub mod parse;
pub mod run;
pub mod vector;

pub use error::{ConformanceError, ConformanceResult};
pub use parse::parse_vectors;
pub use run::{run_vector, run_vectors, VectorOutcome};
pub use vector::{ConformanceVector, ExpectedResult};
