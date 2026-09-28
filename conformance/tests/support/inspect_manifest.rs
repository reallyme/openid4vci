// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared assertions for conformance manifest integration tests.

use serde_json::Value;

pub(super) struct RequirementManifest {
    pub(super) name: &'static str,
    pub(super) body: Value,
    pub(super) requirements_key: &'static str,
    pub(super) id_key: &'static str,
    pub(super) applicable_key: &'static str,
    pub(super) implementation_key: &'static str,
    pub(super) tests_key: &'static str,
}

pub(super) fn parse_json_or_null(body: &str) -> Value {
    match serde_json::from_str(body) {
        Ok(value) => value,
        Err(_) => Value::Null,
    }
}

pub(super) fn find_item_by_id<'a>(
    body: &'a Value,
    collection_key: &str,
    id_key: &str,
    expected_id: &str,
) -> Option<&'a Value> {
    body.get(collection_key)
        .and_then(Value::as_array)?
        .iter()
        .find(|item| item.get(id_key).and_then(Value::as_str) == Some(expected_id))
}

pub(super) fn assert_implemented_requirements_are_mapped(manifest: RequirementManifest) {
    let entries = manifest
        .body
        .get(manifest.requirements_key)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    assert!(
        !entries.is_empty(),
        "requirement manifest must contain records: {}",
        manifest.name
    );

    for item in entries {
        let status = item.get("status").and_then(Value::as_str).unwrap_or("");
        let applicable = item
            .get(manifest.applicable_key)
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !applicable || !status.starts_with("implemented") {
            continue;
        }

        let requirement_id = item
            .get(manifest.id_key)
            .and_then(Value::as_str)
            .unwrap_or("unknown-requirement");
        assert!(
            has_non_empty_string_array(&item, manifest.implementation_key),
            "implemented requirement must map implementation anchors: {} {}",
            manifest.name,
            requirement_id
        );
        assert!(
            has_non_empty_string_array(&item, manifest.tests_key),
            "implemented requirement must map tests: {} {}",
            manifest.name,
            requirement_id
        );
    }
}

pub(super) fn assert_requirement_test_anchors_exist(manifest: RequirementManifest) {
    let entries = manifest
        .body
        .get(manifest.requirements_key)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    for item in entries {
        let applicable = item
            .get(manifest.applicable_key)
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !applicable {
            continue;
        }

        let requirement_id = item
            .get(manifest.id_key)
            .and_then(Value::as_str)
            .unwrap_or("unknown-requirement");
        for test_name in string_array_values(&item, manifest.tests_key) {
            assert!(
                test_anchor_exists(test_name),
                "requirement maps an unknown test anchor: {} {} {}",
                manifest.name,
                requirement_id,
                test_name
            );
        }
    }
}

pub(super) fn assert_open_items_have_next_actions(entries: Vec<Value>) {
    for item in entries {
        let status = item.get("status").and_then(Value::as_str).unwrap_or("");
        if status.starts_with("implemented")
            || status.starts_with("covered-locally")
            || status == "pinned-release"
        {
            continue;
        }
        assert!(
            item.get("next_action")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.trim().is_empty()),
            "open EUDI item must have next_action: {item:?}"
        );
    }
}

pub(super) fn has_non_empty_string_array(item: &Value, key: &str) -> bool {
    item.get(key)
        .and_then(Value::as_array)
        .is_some_and(|values| {
            !values.is_empty()
                && values
                    .iter()
                    .all(|value| value.as_str().is_some_and(|entry| !entry.trim().is_empty()))
        })
}

pub(super) fn string_array_values<'a>(item: &'a Value, key: &str) -> Vec<&'a str> {
    item.get(key)
        .and_then(Value::as_array)
        .map(|values| values.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

pub(super) fn test_anchor_exists(test_name: &str) -> bool {
    test_sources()
        .iter()
        .any(|source| source.contains(&["fn ", test_name].concat()))
}

pub(super) fn test_sources() -> [&'static str; 28] {
    [
        include_str!("../manifest_tests.rs"),
        include_str!("../vectors_tests.rs"),
        include_str!("../../../crates/attestation/tests/key_attestation_tests.rs"),
        include_str!("../../../crates/wallet/tests/offer_tests.rs"),
        include_str!("../../../crates/wallet/tests/state_machine_tests.rs"),
        include_str!("../../../crates/wallet/tests/signed_metadata_tests.rs"),
        include_str!("../../../crates/http/tests/axum_issuer_tests.rs"),
        include_str!("../../../crates/http/tests/axum_haip_policy_tests.rs"),
        include_str!("../../../crates/http/tests/axum_issuer_transport_tests.rs"),
        include_str!("../../../crates/http/src/tests/axum_holder_harness_tests.rs"),
        include_str!("../../../crates/http/examples/issuer/authorize_tests.rs"),
        include_str!("../../../crates/issuer/tests/attestation_proof_tests.rs"),
        include_str!("../../../crates/issuer/tests/endpoint_attestation_tests.rs"),
        include_str!("../../../crates/issuer/tests/encode_tests.rs"),
        include_str!("../../../crates/issuer/tests/endpoint_encryption_tests.rs"),
        include_str!("../../../crates/issuer/tests/endpoint_tests.rs"),
        include_str!("../../../crates/issuer/tests/jose_jwe_tests.rs"),
        include_str!("../../../crates/issuer/tests/jose_jwe_vector_tests.rs"),
        include_str!("../../../crates/issuer/tests/jose_proof_tests.rs"),
        include_str!("../../../crates/issuer/tests/notification_state_machine_tests.rs"),
        include_str!("../../../crates/issuer/tests/proof_tests.rs"),
        include_str!("../../../crates/issuer/tests/select_response_encryption_tests.rs"),
        include_str!("../../../crates/issuer/tests/state_machine_tests.rs"),
        include_str!("../../../crates/issuer/tests/store_tests.rs"),
        include_str!("../../../crates/profiles/tests/haip_tests.rs"),
        include_str!("../../../crates/proto-codec/tests/roundtrip_tests.rs"),
        include_str!("../../../crates/types/tests/final_spec_tests.rs"),
        include_str!("../../../crates/types/tests/problem_mapping_tests.rs"),
    ]
}

pub(super) fn manifests() -> [(&'static str, &'static str); 10] {
    [
        (
            "specifications.lock",
            include_str!("../../specifications.lock"),
        ),
        (
            "requirements/openid4vci.json",
            include_str!("../../requirements/openid4vci.json"),
        ),
        (
            "../crates/proto/tests/fixtures/protojson/manifest.json",
            include_str!("../../../crates/proto/tests/fixtures/protojson/manifest.json"),
        ),
        (
            "requirements/haip-issuance.json",
            include_str!("../../requirements/haip-issuance.json"),
        ),
        (
            "oidf/exclusions.json",
            include_str!("../../oidf/exclusions.json"),
        ),
        ("eudi/sources.lock", include_str!("../../eudi/sources.lock")),
        (
            "eudi/requirements.json",
            include_str!("../../eudi/requirements.json"),
        ),
        (
            "eudi/test-cases.json",
            include_str!("../../eudi/test-cases.json"),
        ),
        (
            "eudi/upstream-tests.json",
            include_str!("../../eudi/upstream-tests.json"),
        ),
        (
            "eudi/exclusions.json",
            include_str!("../../eudi/exclusions.json"),
        ),
    ]
}
