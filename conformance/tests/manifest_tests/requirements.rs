// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Requirement-to-implementation and test-evidence assertions.

use serde_json::Value;

use crate::inspect_manifest::{
    assert_implemented_requirements_are_mapped, assert_requirement_test_anchors_exist,
    has_non_empty_string_array, parse_json_or_null, RequirementManifest,
};

#[test]
fn requirements_manifest_tracks_concrete_jwe_adapters() {
    let requirements = parse_json_or_null(include_str!("../../requirements/openid4vci.json"));
    let tracks_adapters = requirements
        .get("requirements")
        .and_then(Value::as_array)
        .is_some_and(|items| {
            items.iter().any(|item| {
                item.get("id").and_then(Value::as_str) == Some("OID4VCI-JWE-001")
                    && item.get("status").and_then(Value::as_str) == Some("implemented")
                    && item
                        .get("tests")
                        .and_then(Value::as_array)
                        .is_some_and(|tests| {
                            tests.iter().any(|test| {
                                test.as_str()
                                    == Some("jose_jwe_response_encryptor_roundtrips_p256_ecdh_es")
                            }) && tests.iter().any(|test| {
                                test.as_str()
                                    == Some("jose_jwe_request_decryptor_roundtrips_p256_ecdh_es")
                            })
                        })
            })
        });
    assert!(tracks_adapters);
}

#[test]
fn implemented_requirements_are_mapped_to_tests() {
    assert_implemented_requirements_are_mapped(RequirementManifest {
        name: "requirements/openid4vci.json",
        body: parse_json_or_null(include_str!("../../requirements/openid4vci.json")),
        requirements_key: "requirements",
        id_key: "id",
        applicable_key: "applicable",
        implementation_key: "implementation",
        tests_key: "tests",
    });
    assert_implemented_requirements_are_mapped(RequirementManifest {
        name: "requirements/haip-issuance.json",
        body: parse_json_or_null(include_str!("../../requirements/haip-issuance.json")),
        requirements_key: "requirements",
        id_key: "id",
        applicable_key: "applicable",
        implementation_key: "implementation",
        tests_key: "tests",
    });
    assert_implemented_requirements_are_mapped(RequirementManifest {
        name: "eudi/requirements.json",
        body: parse_json_or_null(include_str!("../../eudi/requirements.json")),
        requirements_key: "requirements",
        id_key: "requirement_id",
        applicable_key: "applicable_to_openid4vci_repo",
        implementation_key: "implemented_in",
        tests_key: "tests",
    });
}

#[test]
fn openid4vci_requirements_map_conformance_evidence() {
    let requirements = parse_json_or_null(include_str!("../../requirements/openid4vci.json"));
    let entries = requirements
        .get("requirements")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    assert!(!entries.is_empty());

    for item in entries {
        let status = item.get("status").and_then(Value::as_str).unwrap_or("");
        let applicable = item
            .get("applicable")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !applicable || !status.starts_with("implemented") {
            continue;
        }

        let requirement_id = item
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("unknown-requirement");
        assert!(
            has_non_empty_string_array(&item, "conformance_evidence"),
            "implemented OpenID4VCI requirement must map conformance or vector evidence: {requirement_id}"
        );
    }
}

#[test]
fn requirement_test_anchors_exist_in_repo() {
    assert_requirement_test_anchors_exist(RequirementManifest {
        name: "requirements/openid4vci.json",
        body: parse_json_or_null(include_str!("../../requirements/openid4vci.json")),
        requirements_key: "requirements",
        id_key: "id",
        applicable_key: "applicable",
        implementation_key: "implementation",
        tests_key: "tests",
    });
    assert_requirement_test_anchors_exist(RequirementManifest {
        name: "requirements/haip-issuance.json",
        body: parse_json_or_null(include_str!("../../requirements/haip-issuance.json")),
        requirements_key: "requirements",
        id_key: "id",
        applicable_key: "applicable",
        implementation_key: "implementation",
        tests_key: "tests",
    });
    assert_requirement_test_anchors_exist(RequirementManifest {
        name: "eudi/requirements.json",
        body: parse_json_or_null(include_str!("../../eudi/requirements.json")),
        requirements_key: "requirements",
        id_key: "requirement_id",
        applicable_key: "applicable_to_openid4vci_repo",
        implementation_key: "implemented_in",
        tests_key: "tests",
    });
}
