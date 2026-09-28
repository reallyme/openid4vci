// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Credential Request decryption test boundary.

use openid4vci_issuer::{
    decrypt_credential_request_json, CredentialRequestDecryptor, CredentialRequestJson,
    DecryptedCredentialRequestJson, IssuerResult,
};

struct AuthenticatedTestDecryptor<'a> {
    plaintext: &'a str,
}

impl CredentialRequestDecryptor for AuthenticatedTestDecryptor<'_> {
    fn decrypt_request(&self, _compact_jwe: &str) -> IssuerResult<DecryptedCredentialRequestJson> {
        DecryptedCredentialRequestJson::new(self.plaintext.to_owned())
    }
}

/// Creates test input through the same trusted decryptor boundary as production.
pub(crate) fn authenticated_request_json(value: String) -> IssuerResult<CredentialRequestJson> {
    let decryptor = AuthenticatedTestDecryptor { plaintext: &value };
    decrypt_credential_request_json(&decryptor, "test.compact.jwe.input")
}
