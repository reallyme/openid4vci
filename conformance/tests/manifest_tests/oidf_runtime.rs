// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! OIDF runner, evidence, and local harness wiring assertions.

use serde_json::Value;

use crate::inspect_manifest::parse_json_or_null;

#[test]
fn oidf_exclusions_record_removed_batch_endpoint() {
    let exclusions = parse_json_or_null(include_str!("../../oidf/exclusions.json"));
    let contains_batch_exclusion = exclusions
        .get("exclusions")
        .and_then(Value::as_array)
        .is_some_and(|items| {
            items.iter().any(|item| {
                item.get("module_id").and_then(Value::as_str) == Some("batch_credential_endpoint")
                    && item
                        .get("exclusion_reason")
                        .and_then(Value::as_str)
                        .is_some_and(|reason| reason.contains("removed"))
            })
        });
    assert!(contains_batch_exclusion);
}

#[test]
fn oidf_preflight_is_wired_into_ci() {
    let workflow = include_str!("../../../.github/workflows/oidf-conformance.yml");
    let preflight = include_str!("../../../scripts/conformance/preflight_oidf_oid4vci_issuer.sh");
    let script = "scripts/conformance/preflight_oidf_oid4vci_issuer.sh";
    assert!(workflow.contains(script));
    assert!(preflight.contains("docker daemon is not reachable"));
    assert!(preflight.contains("missing required command"));
}

#[test]
fn oidf_runner_requires_exported_result_artifacts() {
    let workflow = include_str!("../../../.github/workflows/oidf-conformance.yml");
    let runner = include_str!("../../../scripts/conformance/run_oidf_oid4vci_issuer.sh");
    let browser_driver =
        include_str!("../../../scripts/conformance/drive_oidf_browser_redirects.py");
    let wallet_runner = include_str!("../../../scripts/conformance/run_oidf_oid4vci_wallet.sh");
    let wallet_driver = include_str!("../../../scripts/conformance/drive_oidf_wallet_modules.py");
    let wallet_control = include_str!("../../../scripts/conformance/oidf_wallet_control.py");
    let wallet_evidence_verifier =
        include_str!("../../../scripts/conformance/assert_oidf_wallet_implementation_evidence.py");
    let plan_executor = include_str!("../../../scripts/conformance/execute_oidf_test_plan.sh");
    let verifier = include_str!("../../../scripts/conformance/assert_oidf_results.py");
    let redactor = include_str!("../../../scripts/conformance/redact_oidf_config.sh");
    let issuer_provenance =
        include_str!("../../../scripts/conformance/assert_oidf_issuer_provenance.sh");
    let issuer_provenance_tests =
        include_str!("../../../scripts/conformance/test_assert_oidf_issuer_provenance.sh");
    assert!(runner.contains("scripts/conformance/assert_oidf_results.sh"));
    assert!(runner.contains("scripts/conformance/assert_oidf_issuer_provenance.sh"));
    // One executable check plus pre-run and post-run invocations.
    assert_eq!(runner.matches("\"$provenance_assertion\"").count(), 3);
    assert!(runner.contains("scripts/conformance/execute_oidf_test_plan.sh"));
    assert!(runner.contains("OIDF_ISSUER_PLAN_EXPRESSION"));
    assert!(runner.contains("--arg alias \"$oidf_alias\""));
    assert!(runner.contains(".alias = $alias"));
    assert!(runner.contains(".vci.credential_configuration_id = $credential_configuration_id"));
    assert!(runner.contains(".credential.trust_anchor_pem = $credential_trust_anchor"));
    assert!(runner.contains("OPENID4VCI_MDOC_IACA_FILE"));
    assert!(runner.contains("pid-mdoc"));
    assert!(runner.contains("profile-matrix.json"));
    assert!(runner.contains("issuer plan expression is not an allowlisted protocol profile"));
    assert!(runner.contains("schema_version: 3"));
    assert!(!runner.contains("product_name"));
    assert!(!runner.contains("product_version"));
    assert!(runner.contains("scripts/conformance/drive_oidf_browser_redirects.py"));
    assert!(runner.contains("OPENID4VCI_OIDF_BROWSER_DRIVER"));
    assert!(runner.contains("OPENID4VCI_OAUTH_PRIMARY_REDIRECT_URI"));
    assert!(runner.contains("OPENID4VCI_OAUTH_SECONDARY_REDIRECT_URI"));
    assert!(runner.contains("OPENID4VCI_OAUTH_SECONDARY_ALTERNATE_REDIRECT_URI"));
    assert!(browser_driver.contains("redirect_to"));
    assert!(browser_driver.contains("implicit_submit"));
    assert!(browser_driver.contains("credential_offer_endpoint"));
    assert!(browser_driver.contains("credential_offer_submission_url"));
    assert!(browser_driver.contains("fetch_newest_matching_plan"));
    assert!(browser_driver.contains("MAX_PLAN_PAGES"));
    assert!(browser_driver.contains("/api/plan?start={start}&length="));
    assert!(wallet_runner.contains("scripts/conformance/assert_oidf_results.sh"));
    assert!(wallet_runner.contains("scripts/conformance/execute_oidf_test_plan.sh"));
    assert!(wallet_runner.contains("OPENID4VCI_WALLET_HARNESS_ENDPOINT"));
    assert!(wallet_runner.contains("OPENID4VCI_WALLET_HARNESS_TOKEN"));
    assert!(wallet_runner.contains("OPENID4VCI_WALLET_HARNESS_HEALTH_ENDPOINT"));
    assert!(wallet_runner.contains("wallet_harness_missing_composed_flow_driver"));
    assert!(wallet_runner.contains("scripts/conformance/drive_oidf_wallet_modules.py"));
    assert!(
        wallet_runner.contains("scripts/conformance/assert_oidf_wallet_implementation_evidence.py")
    );
    assert!(wallet_runner.contains("OPENID4VCI_WALLET_IMPLEMENTATION_EVIDENCE_DIR"));
    assert!(wallet_runner.contains("oidf_wallet_implementation_evidence_failed"));
    assert!(wallet_driver.contains("/api/runner/"));
    assert!(wallet_driver.contains("/api/runner/browser/"));
    assert!(wallet_driver.contains("credential_configuration_id_hint"));
    assert!(wallet_driver.contains("open_authenticated_request"));
    assert!(wallet_control.contains("NoRedirectHandler"));
    assert!(wallet_control.contains("add_unredirected_header"));
    assert!(wallet_control.contains("wallet_harness_endpoint_mismatch"));
    assert!(wallet_evidence_verifier.contains("missing_implementation_evidence"));
    assert!(wallet_evidence_verifier.contains("passed_ids.issubset(evidence_ids)"));
    assert!(wallet_runner.contains("oid4vci-wallet-config.redacted.json"));
    assert!(wallet_runner.contains("oidf_wallet_suite_runner_completed"));
    assert!(wallet_runner.contains("wallet_plan_expression_not_allowlisted"));
    assert!(wallet_runner.contains("profile-matrix.json"));
    assert!(wallet_runner.contains(".profiles[]"));
    assert!(wallet_runner.contains("schema_version: 3"));
    assert!(!wallet_runner.contains("product_name"));
    assert!(!wallet_runner.contains("product_version"));
    assert!(wallet_runner.contains("wallet_source_repository_identity_missing"));
    assert!(wallet_runner.contains("wallet_source_changed_during_execution"));
    assert!(wallet_runner.contains("wallet_harness_binary_changed_during_execution"));
    assert!(wallet_runner.contains("wallet_runner_disabled"));
    assert!(!wallet_runner.contains("pending_runner"));
    assert!(workflow.contains("if-no-files-found: error"));
    assert!(workflow.contains("openid4vci/target/conformance-results"));
    assert!(workflow.contains("issuer_matrix: ${{ steps.profile_matrix.outputs.issuer }}"));
    assert!(workflow.contains("if (.target | length) == 4"));
    assert!(workflow
        .contains("matrix: ${{ fromJSON(needs.prepare-oidf-assets.outputs.issuer_matrix) }}"));
    assert!(!workflow.contains("inputs:\n      profile_id:"));
    assert!(!workflow.contains("schedule:"));
    assert!(!workflow.contains("oid4vci-wallet:"));
    assert!(!workflow.contains("run_oidf_oid4vci_wallet.sh"));
    assert!(runner.contains("oid4vci-issuer-config.redacted.json"));
    assert!(runner.contains("tls_cert=\"$runtime_dir/issuer-tls-cert.pem\""));
    assert!(runner.contains("tls_key=\"$runtime_dir/issuer-tls-key.pem\""));
    assert!(!runner.contains("tls_key=\"$results_dir/issuer-tls-key.pem\""));
    assert!(wallet_runner.contains("oid4vci-wallet-config.redacted.json"));
    assert!(redactor.contains("del(.d, .p, .q, .dp, .dq, .qi, .oth, .k)"));
    assert!(redactor.contains("sensitive_name"));
    assert!(verifier.contains("invalid_suite_export_count"));
    assert!(verifier.contains("suite_module_count_mismatch"));
    assert!(verifier.contains("result") && verifier.contains("PASSED"));
    assert!(verifier.contains("suite_module_variant_mismatch"));
    assert!(verifier.contains("mixed_suite_execution_plan_ids"));
    assert!(plan_executor.contains("OIDF_CONFORMANCE_MODE"));
    assert!(plan_executor.contains("hosted_mode_requires_conformance_token"));
    assert!(plan_executor.contains("hosted_mode_forbids_developer_mode"));
    assert!(issuer_provenance.contains("source commit changed during execution"));
    assert!(issuer_provenance.contains("issuer binary changed during execution"));
    assert!(issuer_provenance_tests.contains("dirty source worktree"));
    assert!(issuer_provenance_tests.contains("untracked source file"));
    assert!(issuer_provenance_tests.contains("source commit changed"));
    assert!(issuer_provenance_tests.contains("issuer binary changed"));
    assert!(issuer_provenance_tests.contains("malicious expected commit"));
    assert!(workflow.contains("scripts/conformance/test_assert_oidf_issuer_provenance.sh"));
    assert!(!workflow.contains("assert_oidf_pre_submission.sh"));
}

#[test]
fn oidf_wallet_harness_is_documented_and_scripted() {
    let readme = include_str!("../../README.md");
    let script = include_str!("../../../scripts/conformance/serve_oidf_oid4vci_wallet_harness.sh");
    let runner = include_str!("../../../scripts/conformance/run_oidf_oid4vci_wallet.sh");
    let plan = include_str!("../../oidf-wallet-plan.toml");
    let fixture = parse_json_or_null(include_str!(
        "../../fixtures/oidf/oid4vci-wallet-harness.json"
    ));
    assert!(readme.contains("serve_oidf_oid4vci_wallet_harness.sh"));
    assert!(script.contains("OPENID4VCI_WALLET_HARNESS_ENDPOINT"));
    assert!(script.contains("recorder-only"));
    assert!(runner.contains("OPENID4VCI_WALLET_HARNESS_ENDPOINT"));
    assert!(runner.contains("OPENID4VCI_WALLET_HARNESS_TOKEN"));
    assert!(runner.contains("composed_flow_driver_enabled == true"));
    assert!(runner.contains("wallet_runner_disabled"));
    assert!(!runner.contains("pending_runner"));
    assert!(plan.contains("host_endpoint_env = \"OPENID4VCI_WALLET_HARNESS_ENDPOINT\""));
    assert!(plan.contains("host_token_env = \"OPENID4VCI_WALLET_HARNESS_TOKEN\""));
    assert_eq!(
        fixture.get("target").and_then(Value::as_str),
        Some("crates/http/examples/holder_harness")
    );
    assert!(fixture
        .get("execute_mode_requirement")
        .and_then(Value::as_str)
        .is_some_and(|value| value.contains("composed_flow_driver_enabled=true")));
}
