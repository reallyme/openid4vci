// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Holder offer-resolution tests for final OpenID4VCI offer semantics.

use std::sync::Mutex;

use openid4vci_types::{
    build_credential_offer_uri, CredentialOffer, CredentialResponseEncryption, IssuerMetadata,
    Proofs, PublicJwk,
};
use reallyme_openid4vci_wallet::{
    resolve_credential_offer_uri, validate_offer_authorization_servers, AuthorizationCode,
    AuthorizationCodeTokenRequest, CredentialOfferFetcher, CredentialOfferGrantType,
    PreAuthorizedTokenRequest, TransactionCode, ValidatedCredentialOffer, WalletCredentialRequest,
    WalletError, WalletResult, WalletStatus,
};
use reallyme_openid_oauth::PkceVerifier;
use secrecy::SecretString;

struct StaticFetcher {
    offer: Mutex<Option<CredentialOffer>>,
}

impl CredentialOfferFetcher for StaticFetcher {
    fn fetch_offer(&self, _credential_offer_uri: &str) -> WalletResult<CredentialOffer> {
        self.offer
            .lock()
            .map_err(|_| WalletError::new(WalletStatus::InvalidRequest))?
            .take()
            .ok_or_else(|| WalletError::new(WalletStatus::InvalidRequest))
    }
}

#[test]
fn wallet_resolves_inline_offer_uri() -> WalletResult<()> {
    let offer = CredentialOffer::authorization_code(
        "https://issuer.example".to_owned(),
        vec!["pid".to_owned()],
        Some("state-1".to_owned()),
    )
    .map_err(|_| reallyme_openid4vci_wallet::WalletError::new(WalletStatus::InvalidRequest))?;
    let uri = build_credential_offer_uri(
        "openid-credential-offer://",
        &offer.to_json().map_err(|_| {
            reallyme_openid4vci_wallet::WalletError::new(WalletStatus::InvalidRequest)
        })?,
    )
    .map_err(|_| reallyme_openid4vci_wallet::WalletError::new(WalletStatus::InvalidRequest))?;
    let resolved = resolve_credential_offer_uri(&uri, None)?;
    assert_eq!(
        resolved.credential_configuration_ids,
        vec!["pid".to_owned()]
    );
    Ok(())
}

#[test]
fn wallet_requires_fetcher_for_referenced_offer() {
    let result = resolve_credential_offer_uri(
        "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffer%2F1",
        None,
    );
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(WalletStatus::OfferResolutionRequired)
    );
}

#[test]
fn wallet_rejects_ambiguous_offer_uri_before_fetching() {
    let result = resolve_credential_offer_uri(
        [
            "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Fone",
            "&credential_offer_uri=https%3A%2F%2Fissuer.example%2Ftwo",
        ]
        .concat()
        .as_str(),
        None,
    );
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(WalletStatus::InvalidRequest)
    );
}

#[test]
fn wallet_rejects_oversized_offer_uri_before_decoding() {
    let oversized = [
        "openid-credential-offer://?credential_offer_uri=",
        &"a".repeat(65_537),
    ]
    .concat();
    assert_eq!(
        resolve_credential_offer_uri(&oversized, None)
            .err()
            .map(|error| error.status()),
        Some(WalletStatus::InvalidRequest)
    );
}

#[test]
fn wallet_resolves_referenced_offer_with_fetcher() -> WalletResult<()> {
    let offer = CredentialOffer::pre_authorized_code(
        "https://issuer.example".to_owned(),
        vec!["pid".to_owned()],
        "code-1".to_owned(),
        None,
    )
    .map_err(|_| reallyme_openid4vci_wallet::WalletError::new(WalletStatus::InvalidRequest))?;
    let fetcher = StaticFetcher {
        offer: Mutex::new(Some(offer)),
    };
    let resolved = resolve_credential_offer_uri(
        "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffer%2F1",
        Some(&fetcher),
    )?;
    assert_eq!(resolved.credential_issuer, "https://issuer.example");
    Ok(())
}

#[test]
fn wallet_rejects_offer_authorization_server_outside_metadata_allowlist() -> WalletResult<()> {
    let mut offer = CredentialOffer::authorization_code(
        "https://issuer.example".to_owned(),
        vec!["pid".to_owned()],
        None,
    )
    .map_err(|_| WalletError::new(WalletStatus::InvalidRequest))?;
    let grants = offer
        .grants
        .as_mut()
        .ok_or_else(|| WalletError::new(WalletStatus::InvalidRequest))?;
    let grant = grants
        .authorization_code
        .as_mut()
        .ok_or_else(|| WalletError::new(WalletStatus::InvalidRequest))?;
    grant.authorization_server = Some("https://attacker.example".to_owned());
    let metadata = IssuerMetadata::parse_json(
        r#"{
            "credential_issuer":"https://issuer.example",
            "authorization_servers":["https://as.example"],
            "credential_endpoint":"https://issuer.example/credential",
            "credential_configurations_supported":{
                "pid":{"format":"dc+sd-jwt","vct":"urn:example:pid"}
            }
        }"#,
    )
    .map_err(|_| WalletError::new(WalletStatus::InvalidIssuerMetadata))?;

    assert_eq!(
        validate_offer_authorization_servers(&offer, &metadata)
            .err()
            .map(|error| error.status()),
        Some(WalletStatus::InvalidAuthorizationServer)
    );
    Ok(())
}

#[test]
fn validated_offer_rejects_selected_authorization_server_outside_metadata() -> WalletResult<()> {
    let offer = CredentialOffer::authorization_code(
        "https://issuer.example".to_owned(),
        vec!["pid".to_owned()],
        None,
    )
    .map_err(|_| WalletError::new(WalletStatus::InvalidRequest))?;
    assert_eq!(
        ValidatedCredentialOffer::new(
            offer,
            &issuer_metadata()?,
            CredentialOfferGrantType::AuthorizationCode,
            "https://attacker.example".to_owned(),
        )
        .err()
        .map(|error| error.status()),
        Some(WalletStatus::InvalidAuthorizationServer)
    );
    Ok(())
}

#[test]
fn credential_builder_rejects_configuration_not_present_in_validated_offer() -> WalletResult<()> {
    let issuance = validated_authorization_code_offer()?;
    assert_eq!(
        WalletCredentialRequest::for_configuration_id(
            &issuance,
            "not-offered".to_owned(),
            None,
            None,
            None,
        )
        .err()
        .map(|error| error.status()),
        Some(WalletStatus::InvalidRequest)
    );
    Ok(())
}

#[test]
fn wallet_rejects_plaintext_after_requesting_response_encryption() -> WalletResult<()> {
    let issuance = validated_authorization_code_offer_with_response_encryption()?;
    let request = WalletCredentialRequest::for_configuration_id(
        &issuance,
        "pid".to_owned(),
        None,
        Some(response_encryption("ECDH-ES", "A128GCM", None)?),
        None,
    )?;

    assert!(request.requires_request_encryption());
    assert_eq!(
        request.plaintext_json().err().map(|error| error.status()),
        Some(WalletStatus::RequestEncryptionRequired)
    );
    assert_eq!(
        request
            .parse_response(r#"{"credentials":[{"credential":"plaintext"}]}"#, None)
            .err()
            .map(|error| error.status()),
        Some(WalletStatus::ResponseEncryptionRequired)
    );
    Ok(())
}

#[test]
fn wallet_rejects_unadvertised_response_encryption_selections() -> WalletResult<()> {
    let issuance = validated_authorization_code_offer_with_response_encryption()?;
    for encryption in [
        response_encryption("RSA-OAEP", "A128GCM", None)?,
        response_encryption("ECDH-ES", "A256GCM", None)?,
        response_encryption("ECDH-ES", "A128GCM", Some("GZIP"))?,
    ] {
        assert_eq!(
            WalletCredentialRequest::for_configuration_id(
                &issuance,
                "pid".to_owned(),
                None,
                Some(encryption),
                None,
            )
            .err()
            .map(|error| error.status()),
            Some(WalletStatus::InvalidEncryptionParameters)
        );
    }
    Ok(())
}

#[test]
fn wallet_rejects_response_encryption_when_issuer_advertises_no_capability() -> WalletResult<()> {
    let issuance = validated_authorization_code_offer()?;
    assert_eq!(
        WalletCredentialRequest::for_configuration_id(
            &issuance,
            "pid".to_owned(),
            None,
            Some(response_encryption("ECDH-ES", "A128GCM", None)?),
            None,
        )
        .err()
        .map(|error| error.status()),
        Some(WalletStatus::InvalidEncryptionParameters)
    );
    Ok(())
}

#[test]
fn pre_authorized_token_request_redacts_and_serializes_secrets() -> WalletResult<()> {
    let issuance = validated_pre_authorized_offer("secret-pre-auth-code")?;
    let tx_code = TransactionCode::new(SecretString::from("123456".to_owned()))?;
    let request =
        PreAuthorizedTokenRequest::new(&issuance, Some(&tx_code), Some("wallet".to_owned()), None)?;

    // Debug must never surface the bearer secret.
    let debug = format!("{request:?}");
    assert!(!debug.contains("secret-pre-auth-code"));
    assert!(!debug.contains("123456"));
    assert!(debug.contains("<redacted>"));

    // The wire boundary must still transmit the real grant parameters.
    let json = serde_json::to_value(&request)
        .map_err(|_| WalletError::new(WalletStatus::InvalidRequest))?;
    assert_eq!(
        json.get("pre-authorized_code").and_then(|v| v.as_str()),
        Some("secret-pre-auth-code")
    );
    assert_eq!(
        json.get("grant_type").and_then(|v| v.as_str()),
        Some("urn:ietf:params:oauth:grant-type:pre-authorized_code")
    );
    assert_eq!(
        json.get("client_id").and_then(|v| v.as_str()),
        Some("wallet")
    );
    assert_eq!(json.get("tx_code").and_then(|v| v.as_str()), Some("123456"));
    Ok(())
}

#[test]
fn authorization_code_token_request_redacts_and_serializes_secrets() -> WalletResult<()> {
    let issuance = validated_authorization_code_offer()?;
    let code = AuthorizationCode::new(SecretString::from("secret-auth-code".to_owned()))?;
    let verifier = PkceVerifier::new(SecretString::from(valid_code_verifier()))
        .map_err(|_| WalletError::new(WalletStatus::InvalidRequest))?;
    let request = AuthorizationCodeTokenRequest::new(
        &issuance,
        &code,
        "https://wallet.example/callback".to_owned(),
        &verifier,
        Some("wallet".to_owned()),
        None,
    )?;

    // Debug must never surface bearer secrets.
    let debug = format!("{request:?}");
    assert!(!debug.contains("secret-auth-code"));
    assert!(!debug.contains(valid_code_verifier().as_str()));
    assert!(debug.contains("<redacted>"));

    // The wire boundary must still transmit the real grant parameters.
    let json = serde_json::to_value(&request)
        .map_err(|_| WalletError::new(WalletStatus::InvalidRequest))?;
    assert_eq!(
        json.get("grant_type").and_then(|v| v.as_str()),
        Some("authorization_code")
    );
    assert_eq!(
        json.get("code").and_then(|v| v.as_str()),
        Some("secret-auth-code")
    );
    assert_eq!(
        json.get("redirect_uri").and_then(|v| v.as_str()),
        Some("https://wallet.example/callback")
    );
    assert_eq!(
        json.get("code_verifier").and_then(|v| v.as_str()),
        Some(valid_code_verifier().as_str())
    );
    assert_eq!(
        json.get("client_id").and_then(|v| v.as_str()),
        Some("wallet")
    );
    Ok(())
}

#[test]
fn authorization_code_token_request_rejects_invalid_public_values() -> WalletResult<()> {
    let issuance = validated_authorization_code_offer()?;
    let code = AuthorizationCode::new(SecretString::from("secret-auth-code".to_owned()))?;
    let verifier = PkceVerifier::new(SecretString::from(valid_code_verifier()))
        .map_err(|_| WalletError::new(WalletStatus::InvalidRequest))?;
    let result = AuthorizationCodeTokenRequest::new(
        &issuance,
        &code,
        "bad\nredirect".to_owned(),
        &verifier,
        None,
        None,
    );
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(WalletStatus::InvalidString)
    );
    Ok(())
}

#[test]
fn pre_authorized_token_request_rejects_invalid_transaction_code() {
    let result = TransactionCode::new(SecretString::from("bad\ncode".to_owned()));
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(WalletStatus::InvalidString)
    );
}

#[test]
fn wallet_credential_request_rejects_invalid_dpop_header_value() -> WalletResult<()> {
    let issuance = validated_authorization_code_offer()?;
    let result = WalletCredentialRequest::for_configuration_id(
        &issuance,
        "pid".to_owned(),
        Some(Proofs {
            jwt: vec!["a.b.c".to_owned()],
            di_vp: Vec::new(),
            attestation: Vec::new(),
        }),
        None,
        Some("bad\njwt".to_owned()),
    );
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(WalletStatus::InvalidString)
    );
    Ok(())
}

#[test]
fn wallet_builds_configuration_id_request_with_proofs() -> WalletResult<()> {
    let issuance = validated_authorization_code_offer()?;
    let request = WalletCredentialRequest::for_configuration_id(
        &issuance,
        "pid".to_owned(),
        Some(Proofs {
            jwt: vec!["a.b.c".to_owned()],
            di_vp: Vec::new(),
            attestation: Vec::new(),
        }),
        None,
        Some("dpop.jwt.value".to_owned()),
    )?;
    assert_eq!(request.credential_configuration_id(), Some("pid"));
    assert_eq!(request.dpop_proof_jwt(), Some("dpop.jwt.value"));
    let debug = format!("{request:?}");
    assert!(!debug.contains("dpop.jwt.value"));
    assert!(debug.contains("<redacted>"));
    Ok(())
}

fn issuer_metadata() -> WalletResult<IssuerMetadata> {
    IssuerMetadata::parse_json(
        r#"{
            "credential_issuer":"https://issuer.example",
            "credential_endpoint":"https://issuer.example/credential",
            "credential_configurations_supported":{
                "pid":{"format":"dc+sd-jwt","vct":"urn:example:pid"}
            }
        }"#,
    )
    .map_err(|_| WalletError::new(WalletStatus::InvalidIssuerMetadata))
}

fn response_encryption_issuer_metadata() -> WalletResult<IssuerMetadata> {
    IssuerMetadata::parse_json(
        r#"{
            "credential_issuer":"https://issuer.example",
            "credential_endpoint":"https://issuer.example/credential",
            "credential_response_encryption":{
                "alg_values_supported":["ECDH-ES"],
                "enc_values_supported":["A128GCM"],
                "zip_values_supported":["DEF"],
                "encryption_required":false
            },
            "credential_configurations_supported":{
                "pid":{"format":"dc+sd-jwt","vct":"urn:example:pid"}
            }
        }"#,
    )
    .map_err(|_| WalletError::new(WalletStatus::InvalidIssuerMetadata))
}

fn validated_authorization_code_offer() -> WalletResult<ValidatedCredentialOffer> {
    let offer = CredentialOffer::authorization_code(
        "https://issuer.example".to_owned(),
        vec!["pid".to_owned()],
        None,
    )
    .map_err(|_| WalletError::new(WalletStatus::InvalidRequest))?;
    ValidatedCredentialOffer::new(
        offer,
        &issuer_metadata()?,
        CredentialOfferGrantType::AuthorizationCode,
        "https://issuer.example".to_owned(),
    )
}

fn validated_authorization_code_offer_with_response_encryption(
) -> WalletResult<ValidatedCredentialOffer> {
    let offer = CredentialOffer::authorization_code(
        "https://issuer.example".to_owned(),
        vec!["pid".to_owned()],
        None,
    )
    .map_err(|_| WalletError::new(WalletStatus::InvalidRequest))?;
    ValidatedCredentialOffer::new(
        offer,
        &response_encryption_issuer_metadata()?,
        CredentialOfferGrantType::AuthorizationCode,
        "https://issuer.example".to_owned(),
    )
}

fn response_encryption(
    algorithm: &str,
    content_encryption: &str,
    compression: Option<&str>,
) -> WalletResult<CredentialResponseEncryption> {
    Ok(CredentialResponseEncryption {
        jwk: PublicJwk::new(serde_json::json!({"kty":"EC", "alg":algorithm}))
            .map_err(|_| WalletError::new(WalletStatus::InvalidEncryptionParameters))?,
        enc: content_encryption.to_owned(),
        zip: compression.map(str::to_owned),
    })
}

fn validated_pre_authorized_offer(code: &str) -> WalletResult<ValidatedCredentialOffer> {
    let offer = CredentialOffer::pre_authorized_code(
        "https://issuer.example".to_owned(),
        vec!["pid".to_owned()],
        code.to_owned(),
        None,
    )
    .map_err(|_| WalletError::new(WalletStatus::InvalidRequest))?;
    ValidatedCredentialOffer::new(
        offer,
        &issuer_metadata()?,
        CredentialOfferGrantType::PreAuthorizedCode,
        "https://issuer.example".to_owned(),
    )
}

fn valid_code_verifier() -> String {
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ".to_owned()
}
