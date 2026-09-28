// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use openid4vci_issuer::{
    CredentialRequestDecryptor, JoseJweCredentialRequestDecryptor, JoseJwePrivateKey,
};

fuzz_target!(|data: &[u8]| {
    let Ok(compact) = core::str::from_utf8(data) else {
        return;
    };
    let Ok(key) = JoseJwePrivateKey::p256(vec![17_u8; 32], Some("issuer-key-1".to_owned())) else {
        return;
    };
    let decryptor = JoseJweCredentialRequestDecryptor::new(key);
    let _ = decryptor.decrypt_request(compact);
});
