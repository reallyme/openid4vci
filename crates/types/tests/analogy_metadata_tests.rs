// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Metadata extensibility at the boundary between discovery and capability selection.

use reallyme_openid4vci_types::{IssuerMetadata, OpenId4VciError, Reason};

const METADATA_WITH_FUTURE_BINDING: &str = r#"{
        "credential_issuer":"https://issuer.example",
        "credential_endpoint":"https://issuer.example/credential",
        "credential_configurations_supported":{
            "pid":{
                "format":"dc+sd-jwt",
                "vct":"https://credentials.example/pid",
                "cryptographic_binding_methods_supported":["jwk","urn:example:future-binding"],
                "proof_types_supported":{"jwt":{"proof_signing_alg_values_supported":["ES256"]}}
            }
        }
    }"#;

#[test]
fn unknown_binding_methods_survive_metadata_round_trip() -> Result<(), OpenId4VciError> {
    // Discovery describes the issuer's capabilities, including future methods.
    // Keeping an identifier does not authorize a Wallet to use that method.
    let metadata = IssuerMetadata::parse_json(METADATA_WITH_FUTURE_BINDING)?;
    let round_trip = IssuerMetadata::parse_json(&metadata.to_json()?)?;
    assert_eq!(metadata, round_trip);
    let configuration = round_trip.credential_configurations_supported.get("pid");
    assert_eq!(
        configuration.and_then(|value| value.cryptographic_binding_methods_supported.as_deref()),
        Some(["jwk".to_owned(), "urn:example:future-binding".to_owned()].as_slice())
    );
    Ok(())
}

#[test]
fn binding_method_extensibility_does_not_allow_empty_or_control_bearing_identifiers() {
    for invalid in [
        "",
        "   ",
        r"urn:example:\ninvalid",
        r"urn:example:\u0000invalid",
    ] {
        let body = METADATA_WITH_FUTURE_BINDING.replace("urn:example:future-binding", invalid);
        assert_eq!(
            IssuerMetadata::parse_json(&body)
                .err()
                .map(|error| error.reason()),
            Some(Reason::InvalidString)
        );
    }
}
