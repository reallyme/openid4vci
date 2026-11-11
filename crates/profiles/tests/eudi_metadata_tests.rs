// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! ETSI Credential Issuer Metadata extension tests.

use openid4vci_profiles::{
    parse_credential_reuse_policy, CredentialReusePolicy, ReuseMethod, ReuseMethodSet,
    ReusePolicyError, ReusePolicyErrorReason, SelectedCredentialReusePolicy,
};
use serde_json::json;

fn all_methods() -> Result<ReuseMethodSet, ReusePolicyError> {
    ReuseMethodSet::new(
        ReuseMethodSet::ONCE_ONLY
            | ReuseMethodSet::LIMITED_TIME
            | ReuseMethodSet::ROTATING_BATCH
            | ReuseMethodSet::PER_RELYING_PARTY,
    )
}

#[test]
fn absent_policy_means_unrestricted_reuse() {
    assert_eq!(
        parse_credential_reuse_policy(None),
        Ok(CredentialReusePolicy::Unrestricted)
    );
    assert_eq!(
        parse_credential_reuse_policy(Some(&json!({ "display": [] }))),
        Ok(CredentialReusePolicy::Unrestricted)
    );
}

#[test]
fn unknown_policy_is_preserved_as_unsupported_and_overrides_batch_metadata() {
    let parsed = parse_credential_reuse_policy(Some(&json!({
        "credential_reuse_policy": { "id": "future_policy" }
    })));
    assert_eq!(parsed, Ok(CredentialReusePolicy::Unsupported));
    assert!(parsed.is_ok_and(|policy| policy.ignores_openid_batch_metadata()));
}

#[test]
fn parses_compact_policy_and_preserves_preference_order() -> Result<(), ReusePolicyError> {
    let policy = parse_credential_reuse_policy(Some(&json!({
        "credential_reuse_policy": {
            "id": "arf_annex_ii",
            "options": [{
                "details": ["limited_time", "rotating-batch", "per-relying-party"],
                "batch_size": 5,
                "reissue_trigger_lifetime_left": 65_543,
                "reissue_trigger_unused": 3
            }]
        }
    })))?;
    assert_eq!(
        policy.select_first_supported(all_methods()?),
        Some(ReuseMethod::LimitedTime)
    );
    assert_eq!(
        policy.select_first_supported(ReuseMethodSet::new(ReuseMethodSet::ROTATING_BATCH)?),
        Some(ReuseMethod::RotatingBatch)
    );
    assert!(policy.ignores_openid_batch_metadata());
    Ok(())
}

#[test]
fn parses_expanded_policy_in_document_order() -> Result<(), ReusePolicyError> {
    let policy = parse_credential_reuse_policy(Some(&json!({
        "credential_reuse_policy": {
            "id": "arf_annex_ii",
            "options": [
                {
                    "details": ["limited_time"],
                    "reissue_trigger_lifetime_left": 0
                },
                {
                    "details": ["rotating-batch"],
                    "batch_size": 4,
                    "reissue_trigger_lifetime_left": 10
                },
                {
                    "details": ["per-relying-party"],
                    "batch_size": 4,
                    "reissue_trigger_lifetime_left": 10
                }
            ]
        }
    })))?;
    assert_eq!(
        policy.select_first_supported(ReuseMethodSet::new(
            ReuseMethodSet::ROTATING_BATCH | ReuseMethodSet::PER_RELYING_PARTY,
        )?),
        Some(ReuseMethod::RotatingBatch)
    );
    Ok(())
}

#[test]
fn selection_retains_thresholds_from_the_selected_option() -> Result<(), ReusePolicyError> {
    let policy = parse_credential_reuse_policy(Some(&json!({
        "credential_reuse_policy": {
            "id": "arf_annex_ii",
            "options": [
                {
                    "details": ["per-relying-party"],
                    "batch_size": 5,
                    "reissue_trigger_lifetime_left": 120
                },
                {
                    "details": ["limited_time", "rotating-batch"],
                    "batch_size": 7,
                    "reissue_trigger_lifetime_left": 300
                }
            ]
        }
    })))?;
    let supported =
        ReuseMethodSet::new(ReuseMethodSet::LIMITED_TIME | ReuseMethodSet::ROTATING_BATCH)?;

    assert_eq!(
        policy.select_first_supported_policy(supported),
        Some(SelectedCredentialReusePolicy::ArfAnnexIi {
            method: ReuseMethod::LimitedTime,
            batch_size: Some(7),
            reissue_trigger_unused: None,
            reissue_trigger_lifetime_left_seconds: Some(300),
        })
    );
    Ok(())
}

#[test]
fn unrestricted_and_unsupported_policies_have_distinct_selection_results(
) -> Result<(), ReusePolicyError> {
    let supported = all_methods()?;
    assert_eq!(
        CredentialReusePolicy::Unrestricted.select_first_supported_policy(supported),
        Some(SelectedCredentialReusePolicy::Unrestricted)
    );
    assert_eq!(
        CredentialReusePolicy::Unsupported.select_first_supported_policy(supported),
        None
    );
    Ok(())
}

#[test]
fn per_relying_party_does_not_require_non_normative_unused_threshold() {
    let parsed = parse_credential_reuse_policy(Some(&json!({
        "credential_reuse_policy": {
            "id": "arf_annex_ii",
            "options": [{
                "details": ["limited_time", "per-relying-party"],
                "batch_size": 10,
                "reissue_trigger_lifetime_left": 86_400
            }]
        }
    })));
    assert!(parsed.is_ok());
}

#[test]
fn rejects_missing_or_conflicting_base_methods() {
    for details in [
        json!(["rotating-batch", "per-relying-party"]),
        json!(["once_only", "limited_time"]),
    ] {
        let parsed = parse_credential_reuse_policy(Some(&json!({
            "credential_reuse_policy": {
                "id": "arf_annex_ii",
                "options": [{
                    "details": details,
                    "batch_size": 4,
                    "reissue_trigger_unused": 1,
                    "reissue_trigger_lifetime_left": 10
                }]
            }
        })));
        assert_eq!(
            parsed.map_err(|error| error.reason()),
            Err(ReusePolicyErrorReason::InvalidBaseMethodCombination)
        );
    }
}

#[test]
fn rejects_invalid_method_specific_parameters() {
    let cases = [
        (
            json!({
                "details": ["once_only"],
                "batch_size": 1,
                "reissue_trigger_unused": 0
            }),
            ReusePolicyErrorReason::BatchSizeRequired,
        ),
        (
            json!({
                "details": ["once_only"],
                "batch_size": 2,
                "reissue_trigger_unused": 2
            }),
            ReusePolicyErrorReason::ReissueTriggerUnusedRequired,
        ),
        (
            json!({ "details": ["limited_time"] }),
            ReusePolicyErrorReason::ReissueTriggerLifetimeLeftRequired,
        ),
        (
            json!({
                "details": ["limited_time"],
                "reissue_trigger_lifetime_left": -1
            }),
            ReusePolicyErrorReason::InvalidNumericMember,
        ),
        (
            json!({
                "details": ["limited-time"],
                "reissue_trigger_lifetime_left": 1
            }),
            ReusePolicyErrorReason::UnsupportedMethod,
        ),
    ];

    for (option, expected) in cases {
        let parsed = parse_credential_reuse_policy(Some(&json!({
            "credential_reuse_policy": {
                "id": "arf_annex_ii",
                "options": [option]
            }
        })));
        assert_eq!(parsed.map_err(|error| error.reason()), Err(expected));
    }
}

#[test]
fn rejects_malformed_and_oversized_numeric_inputs() {
    let cases = [
        json!(null),
        json!([]),
        json!({ "id": "arf_annex_ii", "options": [] }),
        json!({
            "id": "arf_annex_ii",
            "options": [{
                "details": ["once_only"],
                "batch_size": 4_294_967_296_u64,
                "reissue_trigger_unused": 1
            }]
        }),
    ];
    for policy in cases {
        assert!(parse_credential_reuse_policy(Some(&json!({
            "credential_reuse_policy": policy
        })))
        .is_err());
    }
}

#[test]
fn rejects_unknown_capability_bits() {
    assert_eq!(
        ReuseMethodSet::new(1 << 7).map_err(|error| error.reason()),
        Err(ReusePolicyErrorReason::UnknownCapability)
    );
}
