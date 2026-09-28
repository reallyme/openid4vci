// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use openid4vci_types::CredentialOffer;

fuzz_target!(|data: &[u8]| {
    if let Ok(body) = core::str::from_utf8(data) {
        let _ = CredentialOffer::parse_json(body);
    }
});
