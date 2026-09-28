// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! EU PID mdoc construction for the deployable issuer.

use ciborium::value::Value as CborValue;
use envelopes_x509::parse_cert_der;
use openid4vci_issuer::{ConfirmationJwk, IssuerError, IssuerResult, IssuerStatus, ProofAlgorithm};
use openid4vci_types::CredentialEnvelope;
use reallyme_codec::base64url::base64url_to_bytes;
use reallyme_cose::{
    cose_key_from_signature_public_bytes_with_encoding, cose_key_to_vec, CoseEc2PointEncoding,
    CoseSignatureAlgorithm,
};
use reallyme_crypto::core::RngOutputKind;
use reallyme_crypto::csprng::{generate_bytes, OsSecureRandom};
use reallyme_mdoc::{
    build_mso_mdoc, encode_mdoc_issuer_signed_cbor, CoseX5ChainIssuerAuthSigner, MdocElement,
    MdocIssueConfig, ValidityInfo,
};
use zeroize::Zeroizing;

use super::run::{current_unix_seconds_issuer, CREDENTIAL_TIME_ROUNDING_SECONDS};

pub(super) const PID_MDOC_CONFIGURATION_ID: &str = "pid-mdoc";
pub(super) const PID_MDOC_CREDENTIAL_IDENTIFIER: &str = "pid-mdoc-credential-1";
pub(super) const PID_MDOC_DOCTYPE: &str = "eu.europa.ec.eudi.pid.1";
const PID_MDOC_NAMESPACE: &str = "eu.europa.ec.eudi.pid.1";
const MDOC_VALIDITY_SECONDS: u64 = 86_400;
const ISSUER_SIGNED_ITEM_RANDOM_BYTES: usize = 16;
const P256_UNCOMPRESSED_SEC1_BYTES: usize = 65;
const P256_UNCOMPRESSED_SEC1_PREFIX: u8 = 0x04;

// These software-backed keys are public, synthetic conformance fixtures. They
// must never be reused outside this example. Production composition roots must
// inject a managed signer and certificate path without exporting signing keys.
const DOCUMENT_SIGNER_PRIVATE_KEY_D: &str = "1cZHB1z9DEHlTFdl0gRq3Y-9t3t-S5779A2qrQud93Y";
const DOCUMENT_SIGNER_CERTIFICATE_DER: &str = "MIICmTCCAj6gAwIBAgIBAjAKBggqhkjOPQQDAjBZMQswCQYDVQQGEwJERTEfMB0GA1UECgwWT3BlbklENFZDSSBDb25mb3JtYW5jZTEpMCcGA1UEAwwgT3BlbklENFZDSSBDb25mb3JtYW5jZSBtZG9jIElBQ0EwHhcNMjYwOTI4MTQyNTU3WhcNMjcwOTI4MTQyNTU3WjBkMQswCQYDVQQGEwJERTEfMB0GA1UECgwWT3BlbklENFZDSSBDb25mb3JtYW5jZTE0MDIGA1UEAwwrT3BlbklENFZDSSBDb25mb3JtYW5jZSBtZG9jIERvY3VtZW50IFNpZ25lcjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABGqvMs5Ok3sUJD15KPn44bzQPcqfBlfhQiTQCW8fEMzxhGPY-EQWdTyxYxN0FmhN2Xagg_ftgB6cMp7QJ_lIDgejgeswgegwCQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMCB4AwFQYDVR0lAQH_BAswCQYHKIGMXQUBAjAdBgNVHQ4EFgQUkWD24fc77i8Sgdv4juEg9wCQtVowHwYDVR0jBBgwFoAUFKeTXSRE29Ky3WLwyDclVbNmRZcwNAYDVR0SBC0wK4YpaHR0cHM6Ly9pc3N1ZXIuZXhhbXBsZS9zZWN1cml0eS9tZG9jLWlhY2EwPgYDVR0fBDcwNTAzoDGgL4YtaHR0cHM6Ly9pc3N1ZXIuZXhhbXBsZS9zZWN1cml0eS9tZG9jLWlhY2EuY3JsMAoGCCqGSM49BAMCA0kAMEYCIQDLYrji2ciExvmYQTfE04vgR8e8wWVcehCSjOrPzhNMZwIhAO_LtJzQHKy_Yho3gFg7ku2ny9o5CG8bVdFMrfXM_pQy";

pub(super) fn issue_pid_mdoc(binding_key: &ConfirmationJwk) -> IssuerResult<CredentialEnvelope> {
    if binding_key.algorithm != ProofAlgorithm::Es256
        || binding_key.public_key.len() != P256_UNCOMPRESSED_SEC1_BYTES
        || binding_key.public_key.first().copied() != Some(P256_UNCOMPRESSED_SEC1_PREFIX)
    {
        return Err(IssuerError::new(IssuerStatus::InvalidProof));
    }
    let device_key = cose_key_from_signature_public_bytes_with_encoding(
        CoseSignatureAlgorithm::Es256,
        &binding_key.public_key,
        CoseEc2PointEncoding::FullCoordinates,
    )
    .and_then(|key| cose_key_to_vec(&key))
    .map_err(|_| IssuerError::new(IssuerStatus::InvalidProof))?;
    let certificate = document_signer_certificate_der()?;
    let certificate_validity =
        parse_cert_der(&certificate).map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    let certificate_not_before = u64::try_from(certificate_validity.not_before.unix_timestamp())
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    let certificate_not_after = u64::try_from(certificate_validity.not_after.unix_timestamp())
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    let validity = mdoc_validity_info(
        current_unix_seconds_issuer()?,
        certificate_not_before,
        certificate_not_after,
    )?;
    let config = MdocIssueConfig::new(PID_MDOC_DOCTYPE, validity, device_key.to_vec());
    let mut private_key = Zeroizing::new(
        base64url_to_bytes(DOCUMENT_SIGNER_PRIVATE_KEY_D)
            .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?,
    );
    let certificate_path = vec![certificate];
    let signer = CoseX5ChainIssuerAuthSigner {
        algorithm: CoseSignatureAlgorithm::Es256,
        private_key: private_key.as_slice(),
        kid: None,
        x5chain_der: &certificate_path,
    };
    let (document, _) = build_mso_mdoc(&config, &pid_elements()?, &signer)
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    let credential = encode_mdoc_issuer_signed_cbor(&document)
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    private_key.fill(0);
    Ok(CredentialEnvelope::binary(credential))
}

pub(super) fn document_signer_certificate_der() -> IssuerResult<Vec<u8>> {
    base64url_to_bytes(DOCUMENT_SIGNER_CERTIFICATE_DER)
        .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))
}

pub(super) fn mdoc_validity_info(
    current_time: u64,
    certificate_not_before: u64,
    certificate_not_after: u64,
) -> IssuerResult<ValidityInfo> {
    if current_time < certificate_not_before || current_time >= certificate_not_after {
        return Err(IssuerError::new(IssuerStatus::EncodingFailed));
    }
    // A shared time bucket prevents otherwise identical credentials from
    // leaking their exact issuance gap. The certificate boundary remains the
    // lower bound so rounding can never backdate an MSO outside its x5chain.
    let rounded = current_time
        .checked_sub(current_time % CREDENTIAL_TIME_ROUNDING_SECONDS)
        .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?;
    let signed = rounded.max(certificate_not_before);
    let requested_valid_until = signed
        .checked_add(MDOC_VALIDITY_SECONDS)
        .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?;
    let rounded_valid_until = requested_valid_until
        .checked_sub(requested_valid_until % CREDENTIAL_TIME_ROUNDING_SECONDS)
        .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?;
    let certificate_ceiling = certificate_not_after
        .checked_sub(certificate_not_after % CREDENTIAL_TIME_ROUNDING_SECONDS)
        .ok_or(IssuerError::new(IssuerStatus::EncodingFailed))?;
    let valid_until = rounded_valid_until.min(certificate_ceiling);
    if valid_until <= signed {
        return Err(IssuerError::new(IssuerStatus::EncodingFailed));
    }
    Ok(ValidityInfo {
        signed,
        valid_from: signed,
        valid_until,
        expected_update: None,
    })
}

fn pid_elements() -> IssuerResult<Vec<MdocElement>> {
    let values = [
        ("family_name", CborValue::Text("Mustermann".to_owned())),
        ("given_name", CborValue::Text("Erika".to_owned())),
        (
            "birth_date",
            CborValue::Tag(1004, Box::new(CborValue::Text("1970-01-01".to_owned()))),
        ),
        ("age_in_years", CborValue::Integer(56_i64.into())),
        (
            "issuing_authority",
            CborValue::Text("Example Issuing Authority".to_owned()),
        ),
        ("issuing_country", CborValue::Text("DE".to_owned())),
    ];
    let mut rng = OsSecureRandom;
    let mut elements = Vec::with_capacity(values.len());
    for (identifier, value) in values {
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&value, &mut encoded)
            .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
        let random =
            generate_bytes::<ISSUER_SIGNED_ITEM_RANDOM_BYTES>(&mut rng, RngOutputKind::Generic)
                .map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
        elements.push(MdocElement {
            namespace: PID_MDOC_NAMESPACE.to_owned(),
            element_identifier: identifier.to_owned(),
            element_value_cbor: encoded,
            random: random.as_bytes().to_vec(),
        });
    }
    Ok(elements)
}
