// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! OIDF certification contract and pre-submission gate assertions.

use serde_json::Value;

use crate::inspect_manifest::parse_json_or_null;

#[test]
fn suite_contract_pins_current_published_plan_inventory() {
    let contract = parse_json_or_null(include_str!("../../oidf/suite-contract.json"));
    let discovery = include_str!("../../../scripts/conformance/discover_oidf_openid4vci.py");
    let plans = contract
        .get("plans")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let plan_ids = plans
        .iter()
        .filter_map(|plan| plan.get("plan_id").and_then(Value::as_str))
        .collect::<Vec<_>>();

    assert_eq!(
        contract.get("commit").and_then(Value::as_str),
        Some("440eec8bac7b12b7389d7ca9cbc459b53507a443")
    );
    assert_eq!(plans.len(), 4);
    assert!(plan_ids.contains(&"oid4vci-1_0-issuer-haip-test-plan"));
    assert!(plan_ids.contains(&"oid4vci-1_0-issuer-test-plan"));
    assert!(plan_ids.contains(&"oid4vci-1_0-wallet-haip-test-plan"));
    assert!(plan_ids.contains(&"oid4vci-1_0-wallet-test-plan"));
    assert!(discovery.contains("PLAN_ANNOTATION_PATTERN"));
    assert!(discovery.contains("MODULE_ANNOTATION_PATTERN"));
    assert!(discovery.contains("validate_contract"));
}

#[test]
fn matrix_covers_all_haip_vci_profiles() {
    let matrix = parse_json_or_null(include_str!("../../oidf/profile-matrix.json"));
    let profiles = matrix
        .get("profiles")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let profile_ids = profiles
        .iter()
        .filter_map(|profile| profile.get("profile_id").and_then(Value::as_str))
        .collect::<Vec<_>>();

    let issuer_profiles = profiles
        .iter()
        .filter(|profile| {
            profile.get("entity_under_test").and_then(Value::as_str) == Some("credential_issuer")
        })
        .collect::<Vec<_>>();
    let wallet_profiles = profiles
        .iter()
        .filter(|profile| {
            profile.get("entity_under_test").and_then(Value::as_str) == Some("wallet")
        })
        .collect::<Vec<_>>();

    assert_eq!(profiles.len(), 10);
    assert!(profiles.iter().all(|profile| {
        profile
            .get("plan_expression")
            .and_then(Value::as_str)
            .is_some_and(|expression| expression.contains("haip-test-plan"))
            && profile
                .get("profile_name")
                .and_then(Value::as_str)
                .is_some_and(|name| name.starts_with("OID4VCI-1.0-FINAL+HAIP-1.0-FINAL"))
    }));
    assert!(profiles.iter().all(|profile| {
        profile.as_object().is_some_and(|fields| {
            fields.len() == 6
                && [
                    "profile_id",
                    "entity_under_test",
                    "plan_id",
                    "plan_expression",
                    "profile_name",
                    "expected_module_count",
                ]
                .iter()
                .all(|field| fields.contains_key(*field))
        })
    }));
    assert_eq!(issuer_profiles.len(), 4);
    assert!(issuer_profiles.iter().all(|profile| {
        profile.get("expected_module_count").and_then(Value::as_u64) == Some(63)
    }));
    assert!(profile_ids.contains(&"issuer-sd-jwt-vc-wallet-initiated"));
    assert!(profile_ids.contains(&"issuer-sd-jwt-vc-issuer-initiated"));
    assert!(profile_ids.contains(&"issuer-mdoc-wallet-initiated"));
    assert!(profile_ids.contains(&"issuer-mdoc-issuer-initiated"));

    assert_eq!(wallet_profiles.len(), 6);
    assert!(wallet_profiles.iter().all(|profile| {
        profile.get("expected_module_count").and_then(Value::as_u64) == Some(22)
    }));
    assert!(profile_ids.contains(&"wallet-sd-jwt-vc-wallet-initiated"));
    assert!(profile_ids.contains(&"wallet-sd-jwt-vc-issuer-initiated-by-value"));
    assert!(profile_ids.contains(&"wallet-sd-jwt-vc-issuer-initiated-by-reference"));
    assert!(profile_ids.contains(&"wallet-mdoc-wallet-initiated"));
    assert!(profile_ids.contains(&"wallet-mdoc-issuer-initiated-by-value"));
    assert!(profile_ids.contains(&"wallet-mdoc-issuer-initiated-by-reference"));
    assert!(matrix.get("product_name").is_none());
    assert!(matrix.get("product_version").is_none());
    assert!(matrix.get("certification_targets").is_none());
    assert!(matrix.get("delegated_certification_profiles").is_none());
    assert_eq!(
        matrix
            .get("credential_format_scope")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(2)
    );
}

#[test]
fn certification_inventory_pins_complete_module_variants() {
    let inventory = parse_json_or_null(include_str!(
        "../../oidf/certification-module-inventory.json"
    ));
    let plans = inventory
        .get("plans")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    assert_eq!(
        inventory.get("suite_commit").and_then(Value::as_str),
        Some("440eec8bac7b12b7389d7ca9cbc459b53507a443")
    );
    assert_eq!(
        inventory.get("suite_version").and_then(Value::as_str),
        Some("5.3.1")
    );
    assert_eq!(plans.len(), 2);

    let issuer = plans
        .iter()
        .find(|plan| {
            plan.get("plan_id").and_then(Value::as_str) == Some("oid4vci-1_0-issuer-haip-test-plan")
        })
        .cloned()
        .unwrap_or(Value::Null);
    let wallet = plans
        .iter()
        .find(|plan| {
            plan.get("plan_id").and_then(Value::as_str) == Some("oid4vci-1_0-wallet-haip-test-plan")
        })
        .cloned()
        .unwrap_or(Value::Null);

    assert_eq!(
        issuer
            .get("module_ids")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(61)
    );
    assert_eq!(
        wallet
            .get("module_ids")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(14)
    );
    assert_eq!(
        issuer.get("module_variant_sha256").and_then(Value::as_str),
        Some("7528eef2134b09ad067b6ab81bdee3e292f0c5b3641db7d0f70fa4a6bb1d1889")
    );
    assert_eq!(
        wallet.get("module_variant_sha256").and_then(Value::as_str),
        Some("4e5ccb4bb519a146c5cf2a041c6e39b93840e594594d1d3dbf0348851ce01977")
    );
    assert_eq!(
        issuer
            .get("default_plan_variant")
            .and_then(|variant| variant.get("grant_management"))
            .and_then(Value::as_str),
        Some("disabled")
    );
    assert_eq!(
        wallet
            .get("default_plan_variant")
            .and_then(|variant| variant.get("vci_credential_offer_variant"))
            .and_then(Value::as_str),
        Some("by_value")
    );
}

#[test]
fn certification_gate_forbids_expected_skips() {
    let runner = include_str!("../../../scripts/conformance/run_oidf_oid4vci_issuer.sh");
    let verifier = include_str!("../../../scripts/conformance/assert_oidf_results.py");
    assert!(!runner.contains("--expected-skips-file"));
    assert!(runner.contains("expected skips are forbidden"));
    assert!(verifier.contains("test_info.get(\"result\") != \"PASSED\""));
    assert!(verifier.contains("suite_module_count_mismatch"));
    assert!(verifier.contains("duplicate_suite_test_id"));
}
