// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Executes the machine-readable conformance vectors against the implementation.

use openid4vci_conformance::{
    parse_vectors, run_vector, ConformanceError, ConformanceResult, ConformanceVector,
    ExpectedResult, VectorOutcome,
};

const FINAL_NEGATIVE_VECTORS: &str = include_str!("../../vectors/openid4vci-final-negative.json");
const TRUST_EVIDENCE_VECTORS: &str = include_str!("../../vectors/openid4vci-trust-evidence.json");

#[test]
fn final_negative_vectors_match_implementation_behavior() -> ConformanceResult<()> {
    let vectors = parse_vectors(FINAL_NEGATIVE_VECTORS)?;
    assert!(
        !vectors.is_empty(),
        "expected at least one conformance vector"
    );

    for vector in &vectors {
        let outcome = run_vector(vector)?;
        assert_eq!(
            outcome,
            VectorOutcome::Passed,
            "vector {} ({}) did not behave as expected: {outcome:?}",
            vector.id,
            vector.spec_section
        );
    }
    Ok(())
}

#[test]
fn trust_evidence_vectors_match_implementation_behavior() -> ConformanceResult<()> {
    let vectors = parse_vectors(TRUST_EVIDENCE_VECTORS)?;
    assert!(!vectors.is_empty(), "expected trust-evidence vectors");

    for vector in &vectors {
        let outcome = run_vector(vector)?;
        assert_eq!(
            outcome,
            VectorOutcome::Passed,
            "vector {} ({}) did not behave as expected: {outcome:?}",
            vector.id,
            vector.spec_section
        );
    }
    Ok(())
}

#[test]
fn unknown_target_fails_loudly() {
    let vector = ConformanceVector {
        id: "unknown".to_owned(),
        spec_section: "n/a".to_owned(),
        target: "types::DoesNotExist".to_owned(),
        input_json: "{}".to_owned(),
        expected: ExpectedResult::Reject,
    };
    assert_eq!(run_vector(&vector), Err(ConformanceError::UnknownTarget));
}

#[test]
fn accept_expectation_is_enforced() -> ConformanceResult<()> {
    // A well-formed Credential Request is expected to be accepted; if the parser
    // rejected it, the runner would report `UnexpectedReject`.
    let vector = ConformanceVector {
        id: "accept-credential-request".to_owned(),
        spec_section: "OpenID4VCI 8.2".to_owned(),
        target: "types::CredentialRequest".to_owned(),
        input_json: r#"{"credential_configuration_id":"pid","proofs":{"jwt":["a.b.c"]}}"#
            .to_owned(),
        expected: ExpectedResult::Accept,
    };
    assert_eq!(run_vector(&vector)?, VectorOutcome::Passed);
    Ok(())
}
