// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{OfferRecord, OfferStatus, OfferSummary};

#[test]
fn status_debug_redacts_inline_and_reference_identifiers() {
    let inline = OfferRecord {
        session_id: 1,
        status: OfferStatus::Accepted,
        offer: OfferSummary::Inline {
            credential_issuer: "https://issuer.example/secret-tenant".to_owned(),
            credential_configuration_count: 1,
            authorization_code_grant_present: true,
            pre_authorized_code_grant_present: false,
        },
        flow: None,
    };
    let reference = OfferRecord {
        session_id: 2,
        status: OfferStatus::ReferenceReceived,
        offer: OfferSummary::Reference,
        flow: None,
    };

    let inline_debug = format!("{inline:?}");
    let reference_debug = format!("{reference:?}");
    assert!(!inline_debug.contains("secret-tenant"));
    assert!(!reference_debug.contains("secret-code"));
}
