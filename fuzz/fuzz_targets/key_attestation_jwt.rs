// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use openid4vci_attestation::{
    parse_key_attestation, KeyAttestationAlgorithm, KeyAttestationJwt,
    KeyAttestationTemporalPolicy, KeyAttestationValidationContext,
};

fuzz_target!(|data: &[u8]| {
    if let Ok(jwt) = core::str::from_utf8(data) {
        if let Ok(jwt) = KeyAttestationJwt::new(jwt.to_owned()) {
            let Ok(temporal_policy) =
                KeyAttestationTemporalPolicy::new(1_700_000_000, 300, 60, false)
            else {
                return;
            };
            let context = KeyAttestationValidationContext {
                nonce_required: false,
                expected_nonce: None,
                temporal_policy,
                accepted_algorithms: vec![KeyAttestationAlgorithm::Es256],
            };
            let _ = parse_key_attestation(&jwt, &context);
        }
    }
});
