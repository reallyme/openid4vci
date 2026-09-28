// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use openid4vci_proto::generated::proto::reallyme::openid4vci::v1 as pb;
use openid4vci_proto_codec::{json_to_proto, proto_to_json};

macro_rules! assert_round_trip {
    ($message:ty, $json:expr) => {{
        let Ok(decoded) = json_to_proto::<$message>($json) else {
            return;
        };
        let Ok(encoded) = proto_to_json(&decoded) else {
            return;
        };
        let round_trip = json_to_proto::<$message>(&encoded);
        if round_trip.as_ref() != Ok(&decoded) {
            // libFuzzer requires a process failure to retain an input that
            // violates this round-trip invariant.
            std::process::abort();
        }
    }};
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, json_bytes)) = data.split_first() else {
        return;
    };
    let Ok(json) = core::str::from_utf8(json_bytes) else {
        return;
    };

    match selector % 12 {
        0 => assert_round_trip!(pb::CredentialOffer, json),
        1 => assert_round_trip!(pb::IssuerMetadata, json),
        2 => assert_round_trip!(pb::CredentialRequest, json),
        3 => assert_round_trip!(pb::CredentialResponse, json),
        4 => assert_round_trip!(pb::DeferredCredentialRequest, json),
        5 => assert_round_trip!(pb::NonceResponse, json),
        6 => assert_round_trip!(pb::NotificationRequest, json),
        7 => assert_round_trip!(pb::ProblemDetails, json),
        8 => assert_round_trip!(pb::OpenId4VciOperationRequest, json),
        9 => assert_round_trip!(pb::OpenId4VciOperationResponse, json),
        10 => assert_round_trip!(pb::OpenId4VciOperationResult, json),
        _ => assert_round_trip!(pb::OpenId4VciOperationError, json),
    }
});
