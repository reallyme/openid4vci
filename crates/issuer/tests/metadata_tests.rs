// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Signed Credential Issuer Metadata value tests.

use openid4vci_issuer::{
    IssuerResult, IssuerStatus, SignedIssuerMetadataJwt, MAX_SIGNED_ISSUER_METADATA_JWT_BYTES,
};

#[test]
fn signed_metadata_accepts_bounded_compact_jws() -> IssuerResult<()> {
    let signed = SignedIssuerMetadataJwt::new("e30.e30.AA".to_owned())?;
    assert_eq!(signed.as_str(), "e30.e30.AA");
    Ok(())
}

#[test]
fn signed_metadata_rejects_malformed_or_oversized_values() {
    let oversized = "a".repeat(MAX_SIGNED_ISSUER_METADATA_JWT_BYTES + 1);
    for value in [
        String::new(),
        " e30.e30.AA".to_owned(),
        "e30.e30".to_owned(),
        "e30..AA".to_owned(),
        "e30.e30.AA.extra".to_owned(),
        "not+base64.e30.AA".to_owned(),
        oversized,
    ] {
        assert_eq!(
            SignedIssuerMetadataJwt::new(value)
                .err()
                .map(|error| error.status()),
            Some(IssuerStatus::EncodingFailed)
        );
    }
}
