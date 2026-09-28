// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Holder transition tests over the public request-building boundary.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use openid4vci_types::{
    CredentialOffer, CredentialRequest, IssuerMetadata, Proofs, TxCode, TxCodeInputMode,
};
use reallyme_openid4vci_wallet::{
    resolve_credential_offer_uri, AuthorizationCode, AuthorizationCodeTokenRequest,
    CredentialOfferFetcher, CredentialOfferGrantType, PreAuthorizedTokenRequest, TransactionCode,
    ValidatedCredentialOffer, ValidatedIssuance, WalletCredentialRequest, WalletError,
    WalletResult, WalletStatus,
};
use reallyme_openid_oauth::PkceVerifier;
use secrecy::SecretString;
use serde_json::Value;

#[test]
fn referenced_offer_must_be_resolved_before_request_construction() -> WalletResult<()> {
    let fetcher = CountingFetcher {
        offer: Mutex::new(Some(pre_authorized_offer()?)),
        fetch_count: AtomicUsize::new(0),
    };
    let uri =
        "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffer%2F1";

    let unresolved = resolve_credential_offer_uri(uri, None);
    assert_eq!(
        unresolved.err().map(|error| error.status()),
        Some(WalletStatus::OfferResolutionRequired)
    );
    assert_eq!(fetcher.fetch_count(), 0);

    let resolved = resolve_credential_offer_uri(uri, Some(&fetcher))?;
    assert_eq!(resolved.credential_issuer, "https://issuer.example");
    assert_eq!(fetcher.fetch_count(), 1);
    Ok(())
}

#[test]
fn pre_authorized_offer_transitions_to_token_and_credential_requests() -> WalletResult<()> {
    let offer = pre_authorized_offer()?;
    let uri = offer
        .to_uri()
        .map_err(|_| WalletError::new(WalletStatus::InvalidRequest))?;
    let resolved = resolve_credential_offer_uri(&uri, None)?;
    let grant = resolved
        .grants
        .as_ref()
        .and_then(|grants| grants.pre_authorized_code.as_ref())
        .ok_or_else(|| WalletError::new(WalletStatus::InvalidRequest))?;
    let tx_code = grant
        .tx_code
        .as_ref()
        .ok_or_else(|| WalletError::new(WalletStatus::InvalidRequest))?;
    assert_eq!(tx_code.input_mode, Some(TxCodeInputMode::Numeric));

    let tx_secret = TransactionCode::new(SecretString::from("123456".to_owned()))?;
    let configuration_id = resolved
        .credential_configuration_ids
        .first()
        .cloned()
        .ok_or_else(|| WalletError::new(WalletStatus::InvalidRequest))?;
    let issuance = ValidatedCredentialOffer::new(
        resolved,
        &issuer_metadata()?,
        CredentialOfferGrantType::PreAuthorizedCode,
        "https://issuer.example".to_owned(),
    )?;
    let token_request = PreAuthorizedTokenRequest::new(
        &issuance,
        Some(&tx_secret),
        Some("wallet-client".to_owned()),
        None,
    )?;
    let token_json = serde_json::to_value(&token_request)
        .map_err(|_| WalletError::new(WalletStatus::InvalidRequest))?;
    assert_eq!(
        token_json.get("tx_code").and_then(Value::as_str),
        Some("123456")
    );

    let credential_request = WalletCredentialRequest::for_configuration_id(
        &issuance,
        configuration_id,
        Some(Proofs {
            jwt: vec!["proof.jwt".to_owned()],
            di_vp: Vec::new(),
            attestation: Vec::new(),
        }),
        None,
        Some("dpop.jwt".to_owned()),
    )?;
    assert_eq!(
        credential_request.credential_configuration_id(),
        Some("pid")
    );
    assert_eq!(credential_request.dpop_proof_jwt(), Some("dpop.jwt"));
    Ok(())
}

#[test]
fn authorization_code_offer_transitions_to_token_and_credential_requests() -> WalletResult<()> {
    let offer = CredentialOffer::authorization_code(
        "https://issuer.example".to_owned(),
        vec!["pid".to_owned()],
        Some("state-1".to_owned()),
    )
    .map_err(|_| WalletError::new(WalletStatus::InvalidRequest))?;
    let uri = offer
        .to_uri()
        .map_err(|_| WalletError::new(WalletStatus::InvalidRequest))?;
    let resolved = resolve_credential_offer_uri(&uri, None)?;
    let grant = resolved
        .grants
        .as_ref()
        .and_then(|grants| grants.authorization_code.as_ref())
        .ok_or_else(|| WalletError::new(WalletStatus::InvalidRequest))?;
    assert_eq!(grant.issuer_state.as_deref(), Some("state-1"));

    let configuration_id = resolved
        .credential_configuration_ids
        .first()
        .cloned()
        .ok_or_else(|| WalletError::new(WalletStatus::InvalidRequest))?;
    let issuance = ValidatedCredentialOffer::new(
        resolved,
        &issuer_metadata()?,
        CredentialOfferGrantType::AuthorizationCode,
        "https://issuer.example".to_owned(),
    )?;

    let authorization_code =
        AuthorizationCode::new(SecretString::from("authorization-code".to_owned()))?;
    let pkce_verifier = PkceVerifier::new(SecretString::from(valid_code_verifier()))
        .map_err(|_| WalletError::new(WalletStatus::InvalidRequest))?;
    let token_request = AuthorizationCodeTokenRequest::new(
        &issuance,
        &authorization_code,
        "https://wallet.example/callback".to_owned(),
        &pkce_verifier,
        Some("wallet-client".to_owned()),
        None,
    )?;
    let token_json = serde_json::to_value(&token_request)
        .map_err(|_| WalletError::new(WalletStatus::InvalidRequest))?;
    assert_eq!(
        token_json.get("grant_type").and_then(Value::as_str),
        Some("authorization_code")
    );

    let credential_request = WalletCredentialRequest::for_configuration_id(
        &issuance,
        configuration_id,
        Some(Proofs {
            jwt: vec!["proof.jwt".to_owned()],
            di_vp: Vec::new(),
            attestation: Vec::new(),
        }),
        None,
        None,
    )?;
    assert_eq!(
        credential_request.credential_configuration_id(),
        Some("pid")
    );
    assert!(!credential_request.requires_request_encryption());
    let plaintext = credential_request.plaintext_json()?;
    let plaintext: Value = serde_json::from_str(&plaintext)
        .map_err(|_| WalletError::new(WalletStatus::InvalidRequest))?;
    assert_eq!(
        plaintext
            .get("credential_configuration_id")
            .and_then(Value::as_str),
        Some("pid")
    );
    Ok(())
}

#[test]
fn wallet_initiated_flow_builds_token_and_credential_requests_without_offer() -> WalletResult<()> {
    let metadata = issuer_metadata()?;
    let issuance =
        ValidatedIssuance::wallet_initiated(&metadata, "https://issuer.example".to_owned())?;
    let authorization_code =
        AuthorizationCode::new(SecretString::from("authorization-code".to_owned()))?;
    let pkce_verifier = PkceVerifier::new(SecretString::from(valid_code_verifier()))
        .map_err(|_| WalletError::new(WalletStatus::InvalidRequest))?;

    let token_request = AuthorizationCodeTokenRequest::new(
        &issuance,
        &authorization_code,
        "https://wallet.example/callback".to_owned(),
        &pkce_verifier,
        Some("wallet-client".to_owned()),
        None,
    )?;
    let token_json = serde_json::to_value(&token_request)
        .map_err(|_| WalletError::new(WalletStatus::InvalidRequest))?;
    assert_eq!(
        token_json.get("grant_type").and_then(Value::as_str),
        Some("authorization_code")
    );

    let credential_request = WalletCredentialRequest::for_configuration_id(
        &issuance,
        "pid".to_owned(),
        None,
        None,
        None,
    )?;
    assert_eq!(
        credential_request.credential_configuration_id(),
        Some("pid")
    );
    Ok(())
}

#[test]
fn metadata_aware_request_rejects_plaintext_downgrade() -> WalletResult<()> {
    let metadata = IssuerMetadata::parse_json(
        r#"{
            "credential_issuer":"https://issuer.example",
            "credential_endpoint":"https://issuer.example/credential",
            "credential_response_encryption":{
                "alg_values_supported":["ECDH-ES"],
                "enc_values_supported":["A256GCM"],
                "encryption_required":true
            },
            "credential_configurations_supported":{
                "pid":{"format":"dc+sd-jwt","vct":"urn:example:pid"}
            }
        }"#,
    )
    .map_err(|_| WalletError::new(WalletStatus::InvalidIssuerMetadata))?;
    let request = CredentialRequest {
        credential_configuration_id: Some("pid".to_owned()),
        credential_identifier: None,
        proofs: None,
        credential_response_encryption: None,
    };
    let issuance = validated_authorization_code_offer(&metadata)?;
    let result =
        WalletCredentialRequest::new_with_issuer_metadata(&issuance, request, None, &metadata);
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(WalletStatus::ResponseEncryptionRequired)
    );
    Ok(())
}

#[test]
fn metadata_aware_request_enforces_required_request_encryption() -> WalletResult<()> {
    let metadata = IssuerMetadata::parse_json(
        r#"{
            "credential_issuer":"https://issuer.example",
            "credential_endpoint":"https://issuer.example/credential",
            "credential_request_encryption":{
                "alg_values_supported":["ECDH-ES"],
                "enc_values_supported":["A256GCM"],
                "jwks":{"keys":[{
                    "kty":"EC","crv":"P-256","x":"x","y":"y",
                    "kid":"request-key-1","alg":"ECDH-ES"
                }]},
                "encryption_required":true
            },
            "credential_configurations_supported":{
                "pid":{"format":"dc+sd-jwt","vct":"urn:example:pid"}
            }
        }"#,
    )
    .map_err(|_| WalletError::new(WalletStatus::InvalidIssuerMetadata))?;
    let request = CredentialRequest {
        credential_configuration_id: Some("pid".to_owned()),
        credential_identifier: None,
        proofs: None,
        credential_response_encryption: None,
    };
    let issuance = validated_authorization_code_offer(&metadata)?;
    let request =
        WalletCredentialRequest::new_with_issuer_metadata(&issuance, request, None, &metadata)?;

    assert!(request.requires_request_encryption());
    assert_eq!(
        request.plaintext_json().err().map(|error| error.status()),
        Some(WalletStatus::RequestEncryptionRequired)
    );
    Ok(())
}

#[test]
fn request_encryption_metadata_is_bound_to_exact_issuer_generation() -> WalletResult<()> {
    let first = request_encryption_issuer_metadata("https://issuer.example", "key-1", false)?;
    let rotated = request_encryption_issuer_metadata("https://issuer.example", "key-2", false)?;
    let other_issuer =
        request_encryption_issuer_metadata("https://other-issuer.example", "key-1", false)?;
    let issuance = validated_authorization_code_offer(&first)?;
    let request = CredentialRequest {
        credential_configuration_id: Some("pid".to_owned()),
        credential_identifier: None,
        proofs: None,
        credential_response_encryption: None,
    };

    assert_eq!(
        WalletCredentialRequest::new_with_issuer_metadata(
            &issuance,
            request.clone(),
            None,
            &rotated,
        )
        .err()
        .map(|error| error.status()),
        Some(WalletStatus::IssuerMetadataIssuerMismatch)
    );
    assert_eq!(
        WalletCredentialRequest::new_with_issuer_metadata(
            &issuance,
            request.clone(),
            None,
            &other_issuer,
        )
        .err()
        .map(|error| error.status()),
        Some(WalletStatus::IssuerMetadataIssuerMismatch)
    );

    let refreshed =
        ValidatedIssuance::wallet_initiated(&rotated, "https://issuer.example".to_owned())?;
    assert!(
        WalletCredentialRequest::new_with_issuer_metadata(&refreshed, request, None, &rotated,)
            .is_ok()
    );
    Ok(())
}

#[test]
fn optional_to_required_request_encryption_transition_requires_metadata_refresh() -> WalletResult<()>
{
    let optional = request_encryption_issuer_metadata("https://issuer.example", "key-1", false)?;
    let required = request_encryption_issuer_metadata("https://issuer.example", "key-1", true)?;
    let stale_issuance =
        ValidatedIssuance::wallet_initiated(&optional, "https://issuer.example".to_owned())?;
    let request = CredentialRequest {
        credential_configuration_id: Some("pid".to_owned()),
        credential_identifier: None,
        proofs: None,
        credential_response_encryption: None,
    };
    assert_eq!(
        WalletCredentialRequest::new_with_issuer_metadata(
            &stale_issuance,
            request.clone(),
            None,
            &required,
        )
        .err()
        .map(|error| error.status()),
        Some(WalletStatus::IssuerMetadataIssuerMismatch)
    );

    let refreshed =
        ValidatedIssuance::wallet_initiated(&required, "https://issuer.example".to_owned())?;
    let bound =
        WalletCredentialRequest::new_with_issuer_metadata(&refreshed, request, None, &required)?;
    assert!(bound.requires_request_encryption());
    assert_eq!(
        bound.plaintext_json().err().map(|error| error.status()),
        Some(WalletStatus::RequestEncryptionRequired)
    );
    Ok(())
}

#[test]
fn token_authorized_identifier_transitions_to_identifier_request() -> WalletResult<()> {
    let issuance = validated_authorization_code_offer(&issuer_metadata()?)?;
    let request = WalletCredentialRequest::for_credential_identifier(
        &issuance,
        "credential-id-1".to_owned(),
        Some(Proofs {
            jwt: vec!["proof.jwt".to_owned()],
            di_vp: Vec::new(),
            attestation: Vec::new(),
        }),
        None,
        None,
    )?;
    assert_eq!(request.credential_identifier(), Some("credential-id-1"));
    Ok(())
}

#[test]
fn conflicting_selector_state_is_rejected() -> WalletResult<()> {
    let request = CredentialRequest {
        credential_configuration_id: Some("pid".to_owned()),
        credential_identifier: Some("credential-id-1".to_owned()),
        proofs: Some(Proofs {
            jwt: vec!["proof.jwt".to_owned()],
            di_vp: Vec::new(),
            attestation: Vec::new(),
        }),
        credential_response_encryption: None,
    };
    let issuance = validated_authorization_code_offer(&issuer_metadata()?)?;
    let result = WalletCredentialRequest::new(&issuance, request, None);
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(WalletStatus::InvalidRequest)
    );
    Ok(())
}

fn pre_authorized_offer() -> WalletResult<CredentialOffer> {
    CredentialOffer::pre_authorized_code(
        "https://issuer.example".to_owned(),
        vec!["pid".to_owned()],
        "pre-authorized-code".to_owned(),
        Some(TxCode {
            input_mode: Some(TxCodeInputMode::Numeric),
            length: Some(6),
            description: Some("Enter the issuer code".to_owned()),
        }),
    )
    .map_err(|_| WalletError::new(WalletStatus::InvalidRequest))
}

fn valid_code_verifier() -> String {
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ".to_owned()
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

fn request_encryption_issuer_metadata(
    issuer: &str,
    key_id: &str,
    encryption_required: bool,
) -> WalletResult<IssuerMetadata> {
    let body = serde_json::json!({
        "credential_issuer": issuer,
        "credential_endpoint": format!("{issuer}/credential"),
        "credential_request_encryption": {
            "alg_values_supported": ["ECDH-ES"],
            "enc_values_supported": ["A256GCM"],
            "jwks": {"keys": [{
                "kty": "EC",
                "crv": "P-256",
                "x": "x",
                "y": "y",
                "kid": key_id,
                "alg": "ECDH-ES"
            }]},
            "encryption_required": encryption_required
        },
        "credential_configurations_supported": {
            "pid": {"format": "dc+sd-jwt", "vct": "urn:example:pid"}
        }
    });
    IssuerMetadata::parse_json(&body.to_string())
        .map_err(|_| WalletError::new(WalletStatus::InvalidIssuerMetadata))
}

fn validated_authorization_code_offer(
    metadata: &IssuerMetadata,
) -> WalletResult<ValidatedCredentialOffer> {
    let offer = CredentialOffer::authorization_code(
        "https://issuer.example".to_owned(),
        vec!["pid".to_owned()],
        None,
    )
    .map_err(|_| WalletError::new(WalletStatus::InvalidRequest))?;
    ValidatedCredentialOffer::new(
        offer,
        metadata,
        CredentialOfferGrantType::AuthorizationCode,
        "https://issuer.example".to_owned(),
    )
}

struct CountingFetcher {
    offer: Mutex<Option<CredentialOffer>>,
    fetch_count: AtomicUsize,
}

impl CountingFetcher {
    fn fetch_count(&self) -> usize {
        self.fetch_count.load(Ordering::SeqCst)
    }
}

impl CredentialOfferFetcher for CountingFetcher {
    fn fetch_offer(&self, _credential_offer_uri: &str) -> WalletResult<CredentialOffer> {
        self.fetch_count.fetch_add(1, Ordering::SeqCst);
        self.offer
            .lock()
            .map_err(|_| WalletError::new(WalletStatus::InvalidRequest))?
            .take()
            .ok_or_else(|| WalletError::new(WalletStatus::InvalidRequest))
    }
}
