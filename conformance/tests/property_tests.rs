// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Property coverage for parser and generated-message boundaries.

#![cfg(not(target_arch = "wasm32"))]

use buffa::EnumValue;
use openid4vci_issuer::{CompactProofJwtParser, IssuerStatus};
use openid4vci_proto::generated::proto::reallyme::openid4vci::v1 as pb;
use openid4vci_proto_codec::convert::{issuer_metadata_from_proto, ProtoError};
use openid4vci_types::{parse_credential_offer_uri, CredentialRequest};
use proptest::collection::vec;
use proptest::prelude::any;
use proptest::sample::select;
use proptest::strategy::Strategy;
use proptest::test_runner::Config as ProptestConfig;
use serde_json::{json, Value};

const PROPERTY_CASES: u32 = 128;
const VALID_INLINE_OFFER: &str = concat!(
    "credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fissuer.example%22%2C",
    "%22credential_configuration_ids%22%3A%5B%22pid%22%5D%7D"
);
const VALID_REFERENCED_OFFER: &str =
    "credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffer%2F1";

proptest::proptest! {
    #![proptest_config(ProptestConfig::with_cases(PROPERTY_CASES))]

    #[test]
    fn credential_request_selector_and_proof_shape_are_total(
        selector_case in 0_u8..4,
        include_proofs in any::<bool>(),
        proof_count in 0_usize..4,
    ) {
        let mut body = serde_json::Map::new();
        if selector_case == 1 || selector_case == 3 {
            body.insert("credential_configuration_id".to_owned(), json!("pid"));
        }
        if selector_case == 2 || selector_case == 3 {
            body.insert("credential_identifier".to_owned(), json!("credential-id"));
        }
        if include_proofs {
            body.insert("proofs".to_owned(), json!({
                "jwt": vec!["proof.jwt"; proof_count],
            }));
        }

        let parsed = CredentialRequest::parse_json(&Value::Object(body).to_string());
        let valid_selector = selector_case == 1 || selector_case == 2;
        let valid_proofs = !include_proofs || proof_count > 0;
        proptest::prop_assert_eq!(parsed.is_ok(), valid_selector && valid_proofs);
    }

    #[test]
    fn offer_uri_accepts_exactly_one_offer_source(source_case in 0_u8..6) {
        let parameters = match source_case {
            0 => Vec::new(),
            1 => vec![VALID_INLINE_OFFER],
            2 => vec![VALID_REFERENCED_OFFER],
            3 => vec![VALID_INLINE_OFFER, VALID_REFERENCED_OFFER],
            4 => vec![VALID_INLINE_OFFER, VALID_INLINE_OFFER],
            _ => vec![VALID_REFERENCED_OFFER, VALID_REFERENCED_OFFER],
        };
        let uri = if parameters.is_empty() {
            "openid-credential-offer://".to_owned()
        } else {
            ["openid-credential-offer://?", parameters.join("&").as_str()].concat()
        };

        let parsed = parse_credential_offer_uri(&uri);
        proptest::prop_assert_eq!(parsed.is_ok(), source_case == 1 || source_case == 2);
    }

    #[test]
    fn malformed_compact_proof_jwt_shapes_fail_closed(
        parts in vec(compact_segment_strategy(), 0..6),
    ) {
        let jwt = parts.join(".");
        let malformed_shape = parts.len() != 3 || parts.iter().any(String::is_empty);
        if malformed_shape {
            let parsed = CompactProofJwtParser::default().parse_unverified(&jwt);
            proptest::prop_assert_eq!(
                parsed.err().map(|error| error.status()),
                Some(IssuerStatus::InvalidProof)
            );
        }
    }

    #[test]
    fn issuer_metadata_proto_json_byte_fields_are_checked(
        metadata_json in vec(any::<u8>(), 0..64),
    ) {
        let valid_json = metadata_json.is_empty()
            || serde_json::from_slice::<Value>(&metadata_json).is_ok();
        let parsed = issuer_metadata_from_proto(issuer_metadata_proto(metadata_json));

        if valid_json {
            proptest::prop_assert!(
                parsed.is_ok() || parsed == Err(ProtoError::InvalidWireValue)
            );
        } else {
            proptest::prop_assert_eq!(parsed, Err(ProtoError::InvalidJson));
        }
    }
}

fn compact_segment_strategy() -> impl Strategy<Value = String> {
    vec(select(compact_segment_chars()), 0..12).prop_map(|chars| chars.into_iter().collect())
}

fn compact_segment_chars() -> Vec<char> {
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        .chars()
        .collect()
}

fn issuer_metadata_proto(metadata_json: Vec<u8>) -> pb::IssuerMetadata {
    let mut proto = pb::IssuerMetadata::default();
    proto.credential_issuer = "https://issuer.example".to_owned();
    proto.credential_endpoint = "https://issuer.example/credential".to_owned();
    let mut configuration = pb::CredentialConfiguration::default();
    configuration.format = EnumValue::from(pb::CredentialFormat::DcSdJwt);
    configuration.credential_metadata_json = metadata_json;
    proto
        .credential_configurations_supported
        .push(pb::CredentialConfigurationEntry {
            credential_configuration_id: "pid".to_owned(),
            configuration: configuration.into(),
            __buffa_unknown_fields: Default::default(),
        });
    proto
}
