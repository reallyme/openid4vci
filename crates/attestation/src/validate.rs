// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Attestation input validation helpers.

use crate::error::{AttestationError, AttestationResult, AttestationStatus};

/// Maximum accepted compact attestation JWT size. Bounds base64 decode and
/// serde work before a cryptographic verifier sees attacker-controlled input.
pub const MAX_ATTESTATION_JWT_BYTES: usize = 64 * 1024;

/// Validates compact-JWT segment shape before a cryptographic verifier sees it.
pub fn validate_compact_jwt(jwt: &str) -> AttestationResult<()> {
    if jwt.trim().is_empty() {
        return Err(AttestationError::new(AttestationStatus::MissingJwt));
    }
    if jwt.len() > MAX_ATTESTATION_JWT_BYTES {
        return Err(AttestationError::new(AttestationStatus::InvalidJwt));
    }
    let mut parts = jwt.split('.');
    let header = parts.next();
    let payload = parts.next();
    let signature = parts.next();
    let extra = parts.next();
    match (header, payload, signature, extra) {
        (Some(h), Some(p), Some(s), None) if !h.is_empty() && !p.is_empty() && !s.is_empty() => {
            Ok(())
        }
        _ => Err(AttestationError::new(AttestationStatus::InvalidJwt)),
    }
}
