// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use openid4vci_http::parse_oauth_form;

fuzz_target!(|data: &[u8]| {
    let _ = parse_oauth_form(data);
});
