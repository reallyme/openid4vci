// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{CredentialRequestJson, DEFAULT_MAX_CREDENTIAL_REQUEST_JSON_BYTES};
use crate::error::IssuerStatus;

#[test]
fn credential_request_json_borrows_valid_cleartext() {
    let owner = CredentialRequestJson::new("{\"credential_configuration_id\":\"pid\"}".to_owned());

    assert_eq!(
        owner.as_ref().ok().map(CredentialRequestJson::as_str),
        Some("{\"credential_configuration_id\":\"pid\"}")
    );
}

#[test]
fn credential_request_json_rejects_empty_cleartext() {
    assert_eq!(
        CredentialRequestJson::new(String::new())
            .err()
            .map(|error| error.status()),
        Some(IssuerStatus::InvalidRequest)
    );
}

#[test]
fn credential_request_json_rejects_oversized_cleartext() {
    let oversized_length = DEFAULT_MAX_CREDENTIAL_REQUEST_JSON_BYTES.checked_add(1);
    assert!(oversized_length.is_some());
    let Some(oversized_length) = oversized_length else {
        return;
    };
    assert_eq!(
        CredentialRequestJson::new("a".repeat(oversized_length))
            .err()
            .map(|error| error.status()),
        Some(IssuerStatus::InvalidRequest)
    );
}
