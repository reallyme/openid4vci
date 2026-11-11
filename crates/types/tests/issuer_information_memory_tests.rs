// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Memory ownership and redaction for sensitive issuer-information fields.

use reallyme_openid4vci_types::{IssuerDisplay, IssuerInformation, IssuerLogo};
use serde_json::{json, Value};
use zeroize::{Zeroize, ZeroizeOnDrop};

fn requires_zeroizing_owner<T: ZeroizeOnDrop>(_: &T) {}

#[test]
fn issuer_metadata_debug_redacts_sensitive_values() {
    let logo = IssuerLogo {
        uri: "https://issuer.example/private-logo".to_owned(),
        alt_text: Some("private-description".to_owned()),
    };
    let display = IssuerDisplay {
        name: Some("private-provider-name".to_owned()),
        locale: Some("en".to_owned()),
        logo: Some(logo.clone()),
    };
    let information = IssuerInformation {
        format: "registrar_dataset".to_owned(),
        data: json!({"identifier": "private-provider-identifier"}),
    };
    assert_eq!(format!("{logo:?}"), "IssuerLogo([REDACTED])");
    assert_eq!(format!("{display:?}"), "IssuerDisplay([REDACTED])");
    assert_eq!(format!("{information:?}"), "IssuerInformation([REDACTED])");
    requires_zeroizing_owner(&logo);
    requires_zeroizing_owner(&display);
    requires_zeroizing_owner(&information);
}

#[test]
fn cloned_information_has_an_independent_zeroizing_owner() {
    let mut information = IssuerInformation {
        format: "registrar_dataset".to_owned(),
        data: json!({"nested": [{"identifier": "private-provider-identifier"}]}),
    };
    let retained = information.clone();
    information.zeroize();
    assert!(information.format.is_empty());
    assert_eq!(information.data, Value::Null);
    assert_ne!(retained.data, Value::Null);
    requires_zeroizing_owner(&retained);
}
