// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Checks that conformance control-plane manifests remain machine-readable.

use openid4vci_types::{
    CredentialOffer, CredentialRequest, CredentialResponse, DeferredCredentialRequest,
    IssuerMetadata, NotificationRequest, ProblemDetails, Reason,
};
use serde_json::Value;

#[path = "support/inspect_manifest.rs"]
mod inspect_manifest;
#[path = "manifest_tests/oidf_certification.rs"]
mod oidf_certification;
#[path = "manifest_tests/oidf_runtime.rs"]
mod oidf_runtime;
#[path = "manifest_tests/requirements.rs"]
mod requirements;

use inspect_manifest::{
    find_item_by_id, has_documented_evidence_status, manifests, parse_json_or_null,
};

#[test]
fn conformance_manifests_are_valid_json() {
    for (name, body) in manifests() {
        let parsed = serde_json::from_str::<Value>(body);
        assert!(parsed.is_ok(), "manifest {name} must parse as JSON");
    }
}

#[test]
fn fuzz_smoke_runner_tracks_all_configured_targets() {
    let smoke_runner = include_str!("../../scripts/run-fuzz-smoke.sh");
    let fuzz_manifest = include_str!("../../fuzz/Cargo.toml");
    let targets = fuzz_manifest
        .split("[[bin]]")
        .skip(1)
        .filter_map(|section| {
            section.lines().find_map(|line| {
                line.strip_prefix("name = \"")
                    .and_then(|value| value.strip_suffix('"'))
            })
        })
        .collect::<Vec<_>>();
    assert!(!targets.is_empty(), "fuzz manifest must configure targets");
    assert_eq!(targets.len(), fuzz_manifest.matches("[[bin]]").count());
    assert!(smoke_runner.contains("OPENID4VCI_FUZZ_RUNS"));
    assert!(smoke_runner.contains("OPENID4VCI_FUZZ_MAX_LEN"));
    assert!(smoke_runner.contains("fuzz_args+=(\"$corpus_dir\")"));

    for target in targets {
        assert!(
            smoke_runner.contains(&format!("\"{target}\"")),
            "fuzz smoke runner must include target: {target}"
        );
        assert!(
            fuzz_manifest.contains(&format!("path = \"fuzz_targets/{target}.rs\"")),
            "fuzz Cargo manifest must point at target source: {target}"
        );
    }
}

#[test]
fn curated_fuzz_json_seeds_are_executable_contract_examples() {
    assert!(CredentialOffer::parse_json(include_str!(
        "../../fuzz/corpus/credential_offer_json/valid.json"
    ))
    .is_ok());
    assert!(CredentialRequest::parse_json(include_str!(
        "../../fuzz/corpus/credential_request_json/valid.json"
    ))
    .is_ok());
    assert!(CredentialResponse::parse_json(include_str!(
        "../../fuzz/corpus/credential_response_json/valid.json"
    ))
    .is_ok());
    assert!(DeferredCredentialRequest::parse_json(include_str!(
        "../../fuzz/corpus/deferred_credential_request_json/valid.json"
    ))
    .is_ok());
    assert!(IssuerMetadata::parse_json(include_str!(
        "../../fuzz/corpus/issuer_metadata_json/valid.json"
    ))
    .is_ok());
    assert!(NotificationRequest::parse_json(include_str!(
        "../../fuzz/corpus/notification_request_json/valid.json"
    ))
    .is_ok());
    assert!(serde_json::from_str::<ProblemDetails>(include_str!(
        "../../fuzz/corpus/problem_details_json/valid.json"
    ))
    .is_ok());

    let duplicate_result = IssuerMetadata::parse_json(include_str!(
        "../../fuzz/corpus/issuer_metadata_json/duplicate-configuration-entry.json"
    ));
    assert_eq!(
        duplicate_result.err().map(|error| error.reason()),
        Some(Reason::InvalidJson)
    );
}

#[test]
fn eudi_source_pins_are_resolved_and_scope_labeled() {
    let sources = parse_json_or_null(include_str!("../eudi/sources.lock"));
    let entries = sources
        .get("sources")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    assert!(!entries.is_empty());

    let unresolved = entries.iter().any(|item| {
        item.get("status").and_then(Value::as_str) == Some("pin-required")
            || item.get("pinned_commit").and_then(Value::as_str).is_none()
    });
    assert!(!unresolved);

    let has_released_arf = entries.iter().any(|item| {
        item.get("id").and_then(Value::as_str) == Some("eudi-arf")
            && item.get("pinned_release").and_then(Value::as_str) == Some("v2.9.0")
            && item.get("pinned_commit").and_then(Value::as_str)
                == Some("28644bfba9381fee5669f3eac90e96c5ef25f044")
    });
    assert!(has_released_arf);

    let has_untagged_wua = entries.iter().any(|item| {
        item.get("id").and_then(Value::as_str) == Some("eudi-wallet-unit-attestation")
            && item.get("status").and_then(Value::as_str)
                == Some("pinned-head-no-release-tag-observed")
    });
    assert!(has_untagged_wua);

    assert!(entries.iter().all(|item| {
        item.get("kind").and_then(Value::as_str)
            != Some("out_of_scope_presentation_tracking_source")
    }));
}

#[test]
fn specification_lock_has_no_unresolved_pins() {
    let specifications = parse_json_or_null(include_str!("../specifications.lock"));
    let entries = specifications
        .get("specifications")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    assert!(!entries.is_empty());

    let has_unresolved_pin = entries
        .iter()
        .any(|item| item.get("status").and_then(Value::as_str) == Some("pin-required"));
    assert!(!has_unresolved_pin);

    let eudi_is_pinned = entries.iter().any(|item| {
        item.get("id").and_then(Value::as_str) == Some("eudi-arf")
            && item.get("pinned_release").and_then(Value::as_str) == Some("v2.9.0")
            && item.get("source_lock").and_then(Value::as_str)
                == Some("conformance/eudi/sources.lock")
    });
    assert!(eudi_is_pinned);
}

#[test]
fn eudi_requirements_reference_pinned_sources() {
    let requirements = parse_json_or_null(include_str!("../eudi/requirements.json"));
    let entries = requirements
        .get("requirements")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    assert!(!entries.is_empty());

    let all_have_source_pins = entries.iter().all(|item| {
        item.get("source_id").and_then(Value::as_str).is_some()
            && item.get("source_path").and_then(Value::as_str).is_some()
            && item.get("source_commit").and_then(Value::as_str).is_some()
    });
    assert!(all_have_source_pins);

    let pid_policy_is_mapped = entries.iter().any(|item| {
        item.get("requirement_id").and_then(Value::as_str) == Some("EUDI-ISSUANCE-PID-001")
            && item.get("status").and_then(Value::as_str) == Some("implemented-baseline-policy")
            && item
                .get("tests")
                .and_then(Value::as_array)
                .is_some_and(|tests| {
                    tests.iter().any(|test| {
                        test.as_str()
                            == Some(
                                "eudi_pid_policy_is_eidas_relevant_high_assurance_issuance_profile",
                            )
                    })
                })
    });
    assert!(pid_policy_is_mapped);

    let wua_metadata_is_mapped = entries.iter().any(|item| {
        item.get("requirement_id").and_then(Value::as_str) == Some("EUDI-ISSUANCE-WUA-METADATA-001")
            && item.get("status").and_then(Value::as_str) == Some("implemented-at-wire-boundary")
            && item
                .get("tests")
                .and_then(Value::as_array)
                .is_some_and(|tests| {
                    tests.iter().any(|test| {
                        test.as_str() == Some("metadata_accepts_eudi_wua_status_period_preferences")
                    })
                })
    });
    assert!(wua_metadata_is_mapped);
}

#[test]
fn eudi_requirements_document_support_and_evidence_limits() {
    let manifest = parse_json_or_null(include_str!("../eudi/requirements.json"));
    let entries = manifest.get("requirements").and_then(Value::as_array);
    assert!(entries.is_some_and(|items| !items.is_empty()));
    if let Some(items) = entries {
        for item in items {
            assert!(has_documented_evidence_status(item));
        }
    }
}

#[test]
fn evidence_status_validation_requires_explicit_limitations() {
    for status in ["unsupported", "execution-unverified"] {
        assert!(has_documented_evidence_status(&serde_json::json!({
            "status": status,
            "limitation": "No retained execution evidence."
        })));
        for invalid in [
            Value::Null,
            serde_json::json!(""),
            serde_json::json!("  "),
            serde_json::json!(42),
        ] {
            assert!(!has_documented_evidence_status(&serde_json::json!({
                "status": status,
                "limitation": invalid
            })));
        }
        assert!(!has_documented_evidence_status(
            &serde_json::json!({"status": status})
        ));
    }
    assert!(has_documented_evidence_status(&serde_json::json!({
        "status": "implemented-at-profile-boundary"
    })));
    for invalid in [
        Value::Null,
        serde_json::json!({}),
        serde_json::json!({"status": 42}),
        serde_json::json!({"status": "implemented-imaginary"}),
    ] {
        assert!(!has_documented_evidence_status(&invalid));
    }
}

#[test]
fn eudi_issuer_registration_metadata_requirement_fails_closed() {
    let requirements = parse_json_or_null(include_str!("../eudi/requirements.json"));
    let sources = parse_json_or_null(include_str!("../eudi/sources.lock"));

    let requirement = find_item_by_id(
        &requirements,
        "requirements",
        "requirement_id",
        "EUDI-ISSUANCE-METADATA-001",
    );
    assert!(requirement.is_some());
    let requirement = requirement.unwrap_or(&Value::Null);
    assert_eq!(
        requirement.get("status").and_then(Value::as_str),
        Some("unsupported")
    );
    assert!(requirement
        .get("exclusion_reason")
        .and_then(Value::as_str)
        .is_some_and(|reason| reason.contains("registration compliance")));

    let arf_source = sources
        .get("sources")
        .and_then(Value::as_array)
        .and_then(|items| {
            items
                .iter()
                .find(|item| item.get("id").and_then(Value::as_str) == Some("eudi-arf"))
        })
        .unwrap_or(&Value::Null);
    assert_eq!(
        arf_source.get("pinned_release").and_then(Value::as_str),
        Some("v2.9.0")
    );
}

#[test]
fn eudi_interop_evidence_is_explicitly_unverified() {
    let requirements = parse_json_or_null(include_str!("../eudi/requirements.json"));
    let requirement = find_item_by_id(
        &requirements,
        "requirements",
        "requirement_id",
        "EUDI-ISSUANCE-INTEROP-001",
    )
    .unwrap_or(&Value::Null);
    assert_eq!(
        requirement.get("status").and_then(Value::as_str),
        Some("execution-unverified")
    );
    assert!(requirement
        .get("limitation")
        .and_then(Value::as_str)
        .is_some_and(|limitation| limitation.contains("no retained two-sided execution evidence")));
    assert!(requirement
        .get("implemented_in")
        .and_then(Value::as_array)
        .is_some_and(|paths| paths
            .iter()
            .all(|path| path.as_str().is_some_and(|path| !path.contains("reports")))));
}
