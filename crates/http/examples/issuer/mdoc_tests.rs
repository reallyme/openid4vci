// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! mdoc proof binding tests for the synthetic conformance issuer.

use ciborium::value::Value as CborValue;
use envelopes_x509::{
    parse_cert_der, parse_cert_pem, CertificateExtensionKind, NameAttributeKind,
    NameAttributeValue, X509Certificate,
};
use openid4vci_issuer::{
    ConfirmationJwk, CredentialIssuer, IssuanceOutcome, IssuerError, IssuerResult, IssuerStatus,
    ProofAlgorithm, ProofKind, VerifiedProof, VerifiedProofSet,
};
use openid4vci_types::{CredentialPayload, CredentialRequest, CredentialSelector, Proofs};
use reallyme_cose::{
    cose_key_from_signature_public_bytes_with_encoding, cose_key_to_vec, CoseEc2PointEncoding,
    CoseSignatureAlgorithm,
};
use reallyme_crypto::core::Algorithm;
use reallyme_crypto::dispatch::generate_keypair;
use reallyme_crypto::p256::decompress_public_key;
use serde_json::json;

use super::issue::ExampleCredentialIssuer;
use super::mdoc::{
    document_signer_certificate_der, iaca_crl_der, mdoc_validity_info, pid_elements,
    PID_MDOC_CONFIGURATION_ID, PID_MDOC_CRL_PATH,
};

const P256_COMPRESSED_SEC1_BYTES: usize = 33;
const P256_UNCOMPRESSED_SEC1_BYTES: usize = 65;
const P256_UNCOMPRESSED_SEC1_PREFIX: u8 = 0x04;
const P256_EVEN_SEC1_PREFIX: u8 = 0x02;
const P256_ODD_SEC1_PREFIX: u8 = 0x03;
const P256_COORDINATE_BYTES: usize = 32;
const ONE_HOUR_SECONDS: u64 = 3_600;
const MAX_DOCUMENT_SIGNER_VALIDITY_DAYS: i64 = 457;
const MAX_IACA_VALIDITY_DAYS: i64 = 7_305;
const OID_ISSUER_ALTERNATIVE_NAME: &str = "2.5.29.18";
const EXPECTED_CRL_DISTRIBUTION_POINT: &str =
    "https://localhost.emobix.co.uk:9443/security/mdoc-iaca.crl";

#[test]
fn mdoc_conformance_certificates_match_iso_profile_invariants() -> IssuerResult<()> {
    let document_signer = parse_cert_der(&document_signer_certificate_der()?)
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    let iaca = parse_cert_pem(include_bytes!(
        "../../../../conformance/fixtures/oidf/openid4vci-conformance-mdoc-iaca.pem"
    ))
    .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;

    assert!(has_country(&document_signer, "DE"));
    assert!(has_country(&iaca, "DE"));
    assert_eq!(document_signer.issuer_der, iaca.subject_der);
    assert_eq!(
        document_signer.authority_key_identifier,
        iaca.subject_key_identifier
    );
    assert_eq!(iaca.issuer_der, iaca.subject_der);
    assert!(
        document_signer.not_after - document_signer.not_before
            <= time::Duration::days(MAX_DOCUMENT_SIGNER_VALIDITY_DAYS)
    );
    assert!(iaca.not_after - iaca.not_before <= time::Duration::days(MAX_IACA_VALIDITY_DAYS));

    let document_signer_usage = document_signer
        .key_usage
        .as_ref()
        .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?;
    assert!(document_signer_usage.digital_signature);
    assert!(!document_signer_usage.key_cert_sign);
    assert!(!document_signer_usage.crl_sign);
    let iaca_usage = iaca
        .key_usage
        .as_ref()
        .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?;
    assert!(iaca_usage.key_cert_sign);
    assert!(iaca_usage.crl_sign);
    assert!(!iaca_usage.digital_signature);

    assert!(document_signer
        .profile
        .extensions
        .iter()
        .any(|extension| extension.critical
            && matches!(extension.kind, CertificateExtensionKind::KeyUsage)));
    assert!(document_signer
        .profile
        .extensions
        .iter()
        .any(|extension| extension.critical
            && matches!(extension.kind, CertificateExtensionKind::ExtendedKeyUsage)));
    assert!(document_signer
        .profile
        .extensions
        .iter()
        .any(|extension| !extension.critical
            && matches!(extension.kind, CertificateExtensionKind::BasicConstraints)));
    assert!(has_noncritical_extension(
        &document_signer,
        OID_ISSUER_ALTERNATIVE_NAME
    ));
    assert!(has_noncritical_extension(
        &iaca,
        OID_ISSUER_ALTERNATIVE_NAME
    ));
    assert!(!document_signer
        .profile
        .crl_distribution_point_uris
        .is_empty());
    assert_eq!(
        document_signer.profile.crl_distribution_point_uris,
        vec![EXPECTED_CRL_DISTRIBUTION_POINT.to_owned()]
    );
    assert_eq!(PID_MDOC_CRL_PATH, "/security/mdoc-iaca.crl");
    assert!(iaca_crl_der().starts_with(&[0x30]));
    Ok(())
}

#[test]
fn pid_mdoc_contains_each_regulated_mandatory_element_once() -> IssuerResult<()> {
    let elements = pid_elements()?;
    let expected = [
        "family_name",
        "given_name",
        "birth_date",
        "place_of_birth",
        "nationality",
        "issuing_authority",
        "issuing_country",
    ];
    assert_eq!(elements.len(), expected.len());
    for identifier in expected {
        assert_eq!(
            elements
                .iter()
                .filter(|element| element.element_identifier == identifier)
                .count(),
            1
        );
    }

    let place_of_birth = elements
        .iter()
        .find(|element| element.element_identifier == "place_of_birth")
        .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?;
    assert!(decode_cbor(&place_of_birth.element_value_cbor)?
        .as_map()
        .is_some());
    let nationality = elements
        .iter()
        .find(|element| element.element_identifier == "nationality")
        .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?;
    assert!(decode_cbor(&nationality.element_value_cbor)?
        .as_array()
        .is_some());
    Ok(())
}

fn has_country(certificate: &X509Certificate, expected: &str) -> bool {
    certificate
        .profile
        .subject
        .rdns
        .iter()
        .flat_map(|rdn| rdn.attributes.iter())
        .any(|attribute| {
            matches!(
                (&attribute.kind, &attribute.value),
                (NameAttributeKind::CountryName, NameAttributeValue::Text(value))
                    if value == expected
            )
        })
}

fn has_noncritical_extension(certificate: &X509Certificate, expected_oid: &str) -> bool {
    certificate.profile.extensions.iter().any(|extension| {
        !extension.critical
            && matches!(
                &extension.kind,
                CertificateExtensionKind::Other(oid) if oid.as_str() == expected_oid
            )
    })
}

#[test]
fn mdoc_validity_rounds_issuance_time_without_crossing_certificate_bounds() -> IssuerResult<()> {
    let certificate_not_before = ONE_HOUR_SECONDS + 43;
    let current_time = 7_199;
    let certificate_not_after = 100_000;
    let validity = mdoc_validity_info(current_time, certificate_not_before, certificate_not_after)?;

    assert_eq!(validity.signed, certificate_not_before);
    assert_eq!(validity.valid_from, certificate_not_before);
    assert_eq!(validity.valid_until, 90_000);
    assert_eq!(validity.valid_until % ONE_HOUR_SECONDS, 0);
    Ok(())
}

#[test]
fn mdoc_validity_keeps_batch_time_claims_on_coarse_boundaries() -> IssuerResult<()> {
    let validity = mdoc_validity_info(10_859, 0, 100_000)?;

    assert_eq!(validity.signed % ONE_HOUR_SECONDS, 0);
    assert_eq!(validity.valid_from % ONE_HOUR_SECONDS, 0);
    assert_eq!(validity.valid_until % ONE_HOUR_SECONDS, 0);
    Ok(())
}

#[test]
fn mdoc_validity_rejects_inactive_or_exhausted_signer_certificates() {
    assert!(mdoc_validity_info(99, 100, 200).is_err());
    assert!(mdoc_validity_info(200, 100, 200).is_err());
    assert!(mdoc_validity_info(10_801, 100, 10_802).is_err());
}

#[test]
fn mdoc_validity_uses_one_shared_bucket_for_nearby_issuances() -> IssuerResult<()> {
    let first = mdoc_validity_info(10_801, 100, 100_000)?;
    let second = mdoc_validity_info(10_859, 100, 100_000)?;

    assert_eq!(first, second);
    assert_eq!(first.signed, 10_800);
    Ok(())
}

#[test]
fn batch_mdoc_credentials_bind_to_corresponding_verified_keys() -> IssuerResult<()> {
    let (first_public, _) = generate_keypair(Algorithm::P256)
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    let (second_public, _) = generate_keypair(Algorithm::P256)
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    let verified = VerifiedProofSet::new(
        vec![
            verified_proof(expand_p256_key(&first_public)?)?,
            verified_proof(expand_p256_key(&second_public)?)?,
        ],
        Vec::new(),
    )?;
    let request = CredentialRequest {
        credential_configuration_id: Some(PID_MDOC_CONFIGURATION_ID.to_owned()),
        credential_identifier: None,
        proofs: Some(Proofs {
            jwt: vec!["first-proof".to_owned(), "second-proof".to_owned()],
            di_vp: Vec::new(),
            attestation: Vec::new(),
        }),
        credential_response_encryption: None,
        reallyme_zk_v1_issuance: None,
    };
    let authorization = openid4vci_issuer::IssuanceAuthorization::new(
        PID_MDOC_CONFIGURATION_ID.to_owned(),
        "subject-1".to_owned(),
        [7_u8; 32],
    )?;
    let outcome = ExampleCredentialIssuer::new("https://issuer.example/".to_owned()).issue(
        &authorization,
        &request,
        &CredentialSelector::ConfigurationId(PID_MDOC_CONFIGURATION_ID.to_owned()),
        Some(&verified),
    )?;
    let IssuanceOutcome::Immediate(response) = outcome else {
        return Err(IssuerError::new(IssuerStatus::EncodingFailed));
    };
    let credentials = response
        .credentials
        .as_ref()
        .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?;
    assert_eq!(credentials.len(), 2);
    assert_eq!(
        extract_device_key(&credentials[0].credential)?,
        expected_device_key(&expand_p256_key(&first_public)?)?,
    );
    assert_eq!(
        extract_device_key(&credentials[1].credential)?,
        expected_device_key(&expand_p256_key(&second_public)?)?,
    );
    assert_ne!(credentials[0].credential, credentials[1].credential);
    Ok(())
}

fn verified_proof(public_key: Vec<u8>) -> IssuerResult<VerifiedProof> {
    VerifiedProof::new(
        ProofKind::Jwt,
        Some("nonce".to_owned()),
        Some("https://issuer.example/".to_owned()),
        None,
        None,
        Some(json!({"kty":"EC","crv":"P-256"})),
        Some(ConfirmationJwk {
            algorithm: ProofAlgorithm::Es256,
            public_key,
            key_id: None,
        }),
    )
}

fn expected_device_key(public_key: &[u8]) -> IssuerResult<Vec<u8>> {
    cose_key_from_signature_public_bytes_with_encoding(
        CoseSignatureAlgorithm::Es256,
        public_key,
        CoseEc2PointEncoding::FullCoordinates,
    )
    .and_then(|key| cose_key_to_vec(&key))
    .map(|encoded| encoded.to_vec())
    .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))
}

fn expand_p256_key(public_key: &[u8]) -> IssuerResult<Vec<u8>> {
    match public_key {
        [P256_UNCOMPRESSED_SEC1_PREFIX, ..] if public_key.len() == P256_UNCOMPRESSED_SEC1_BYTES => {
            Ok(public_key.to_vec())
        }
        [P256_EVEN_SEC1_PREFIX | P256_ODD_SEC1_PREFIX, ..]
            if public_key.len() == P256_COMPRESSED_SEC1_BYTES =>
        {
            decompress_public_key(public_key)
                .map_err(|_| IssuerError::new(IssuerStatus::InvalidProof))
        }
        _ => Err(IssuerError::new(IssuerStatus::InvalidProof)),
    }
}

fn extract_device_key(credential: &CredentialPayload) -> IssuerResult<Vec<u8>> {
    let CredentialPayload::Binary(issuer_signed) = credential else {
        return Err(IssuerError::new(IssuerStatus::EncodingFailed));
    };
    let issuer_signed = decode_cbor(issuer_signed)?;
    let issuer_auth = text_member(&issuer_signed, "issuerAuth")?;
    let fields = issuer_auth
        .as_array()
        .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?;
    let protected = fields
        .first()
        .and_then(CborValue::as_bytes)
        .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?;
    let protected = decode_cbor(protected)?;
    let protected = protected
        .as_map()
        .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?;
    if protected
        .iter()
        .any(|(label, _)| label.as_integer().map(i128::from) == Some(33))
    {
        return Err(IssuerError::new(IssuerStatus::EncodingFailed));
    }
    // ISO/IEC 18013-5 fixes issuerAuth x5chain in the unprotected bucket.
    let unprotected = fields
        .get(1)
        .and_then(CborValue::as_map)
        .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?;
    if !unprotected.iter().any(|(label, value)| {
        label.as_integer().map(i128::from) == Some(33) && value.as_bytes().is_some()
    }) {
        return Err(IssuerError::new(IssuerStatus::EncodingFailed));
    }
    let payload = fields
        .get(2)
        .and_then(CborValue::as_bytes)
        .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?;
    let tagged_mso = decode_cbor(payload)?;
    let (tag, encoded_mso) = tagged_mso
        .as_tag()
        .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?;
    if tag != 24 {
        return Err(IssuerError::new(IssuerStatus::EncodingFailed));
    }
    let mso = decode_cbor(
        encoded_mso
            .as_bytes()
            .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?,
    )?;
    let device_key_info = text_member(&mso, "deviceKeyInfo")?;
    let device_key = text_member(device_key_info, "deviceKey")?;
    let device_key_fields = device_key
        .as_map()
        .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?;
    for coordinate_label in [-2_i128, -3_i128] {
        let coordinate = device_key_fields
            .iter()
            .find_map(|(label, value)| {
                (label.as_integer().map(i128::from) == Some(coordinate_label)).then_some(value)
            })
            .and_then(CborValue::as_bytes)
            .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?;
        if coordinate.len() != P256_COORDINATE_BYTES {
            return Err(IssuerError::new(IssuerStatus::EncodingFailed));
        }
    }
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(device_key, &mut encoded)
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    Ok(encoded)
}

fn text_member<'a>(value: &'a CborValue, name: &str) -> IssuerResult<&'a CborValue> {
    value
        .as_map()
        .and_then(|entries| {
            entries
                .iter()
                .find_map(|(key, value)| (key.as_text() == Some(name)).then_some(value))
        })
        .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))
}

fn decode_cbor(bytes: &[u8]) -> IssuerResult<CborValue> {
    ciborium::de::from_reader(bytes).map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))
}
