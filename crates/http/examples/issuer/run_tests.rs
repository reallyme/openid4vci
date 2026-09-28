// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::env::VarError;
use std::ffi::OsString;

use super::run::{resolve_tls_paths, ExampleIssuerError};

#[test]
fn tls_paths_require_a_complete_pair() {
    assert_eq!(
        resolve_tls_paths(Ok("issuer.pem".to_owned()), Err(VarError::NotPresent), true,),
        Err(ExampleIssuerError::InvalidTlsConfig)
    );
    assert_eq!(
        resolve_tls_paths(Err(VarError::NotPresent), Ok("issuer.key".to_owned()), true,),
        Err(ExampleIssuerError::InvalidTlsConfig)
    );
    assert_eq!(
        resolve_tls_paths(Ok(String::new()), Ok("issuer.key".to_owned()), true),
        Err(ExampleIssuerError::InvalidTlsConfig)
    );
}

#[test]
fn tls_paths_reject_non_unicode_configuration() {
    let invalid = VarError::NotUnicode(OsString::from("invalid"));
    assert_eq!(
        resolve_tls_paths(Err(invalid), Ok("issuer.key".to_owned()), true),
        Err(ExampleIssuerError::InvalidTlsConfig)
    );
}

#[test]
fn tls_paths_allow_an_explicit_pair_or_no_tls_configuration() {
    assert_eq!(
        resolve_tls_paths(
            Ok("issuer.pem".to_owned()),
            Ok("issuer.key".to_owned()),
            true,
        ),
        Ok(Some(("issuer.pem".to_owned(), "issuer.key".to_owned())))
    );
    assert_eq!(
        resolve_tls_paths(Err(VarError::NotPresent), Err(VarError::NotPresent), false,),
        Ok(None)
    );
}

#[test]
fn https_issuer_rejects_missing_tls_configuration() {
    assert_eq!(
        resolve_tls_paths(Err(VarError::NotPresent), Err(VarError::NotPresent), true,),
        Err(ExampleIssuerError::InvalidTlsConfig)
    );
}

#[test]
fn http_issuer_rejects_tls_configuration_that_would_mismatch_metadata() {
    assert_eq!(
        resolve_tls_paths(
            Ok("issuer.pem".to_owned()),
            Ok("issuer.key".to_owned()),
            false,
        ),
        Err(ExampleIssuerError::InvalidTlsConfig)
    );
}
