// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use openid4vci_issuer::CompactProofJwtParser;

fuzz_target!(|data: &[u8]| {
    if let Ok(jwt) = core::str::from_utf8(data) {
        let _ = CompactProofJwtParser::default().parse_unverified(jwt);
    }
});
