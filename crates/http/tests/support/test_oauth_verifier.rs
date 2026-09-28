// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! OAuth verifier fixtures shared by issuer HTTP integration tests.

use envelopes_x509::{
    BasicConstraints, CertificateProfile, KeyUsage, PublicKeyProfile, X509Certificate, X509Chain,
};
use reallyme_openid_oauth::{
    AttestationClientAuthenticationVerifier, CompactJwt, DpopVerifier, JwtSigner, OauthError,
    Reason, VerifiedClientAttestation, WalletAttestationTrustEvidence,
};
use reallyme_revocation::{StatusCheckError, StatusChecker};
use reallyme_trust_core::{
    evaluate_trust_decision, CertificateStatusPolicy, ChainLinkPolicy, DirectTrustEntry,
    SignatureVerifier, SignatureVerifyError, StatusRequirement, TrustConfig,
    TrustEvaluationContext, TrustPolicyId, TrustPurpose, TrustSourceEvidence,
};
use serde_json::Value;

use super::TEST_NOW_UNIX;

const TEST_SIGNER_SPKI_DER: &[u8] = &[1, 2, 3, 4];

pub(crate) struct TestOauthVerifier;

impl JwtSigner for TestOauthVerifier {
    fn algorithm(&self) -> &str {
        "ES256"
    }

    fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, OauthError> {
        Ok(signing_input.to_vec())
    }
}

impl DpopVerifier for TestOauthVerifier {
    fn verify_signature(
        &self,
        _protected_header: &Value,
        _signing_input: &[u8],
        _signature: &[u8],
    ) -> Result<(), OauthError> {
        Ok(())
    }

    fn check_replay(&self, _jti: &str, _iat: i64) -> Result<(), OauthError> {
        Ok(())
    }
}

impl AttestationClientAuthenticationVerifier for TestOauthVerifier {
    fn verify_client_attestation(
        &self,
        client_attestation: &CompactJwt,
    ) -> Result<WalletAttestationTrustEvidence, OauthError> {
        test_wallet_trust_evidence(client_attestation)
    }

    fn verify_pop_signature(
        &self,
        _verified_attestation: &VerifiedClientAttestation,
        _protected_header: &Value,
        _signing_input: &[u8],
        _signature: &[u8],
    ) -> Result<(), OauthError> {
        Ok(())
    }

    fn check_replay(
        &self,
        _verified_attestation: &VerifiedClientAttestation,
        _jti: &str,
        _iat: i64,
    ) -> Result<(), OauthError> {
        Ok(())
    }
}

struct TestSignatureVerifier;

impl SignatureVerifier for TestSignatureVerifier {
    fn verify_chain(
        &self,
        _chain: &X509Chain,
        _now: time::OffsetDateTime,
    ) -> Result<(), SignatureVerifyError> {
        Ok(())
    }
}

struct TestStatusChecker;

impl StatusChecker for TestStatusChecker {
    fn check(
        &self,
        _certificate: &X509Certificate,
        _now_unix: u64,
    ) -> Result<(), StatusCheckError> {
        Ok(())
    }
}

fn test_wallet_trust_evidence(
    client_attestation: &CompactJwt,
) -> Result<WalletAttestationTrustEvidence, OauthError> {
    let evaluated_at = time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(TEST_NOW_UNIX);
    let signer = X509Certificate {
        der: vec![0x30, 0x00],
        subject: "CN=Wallet Attestation Issuer".to_owned(),
        issuer: "CN=Wallet Attestation Root".to_owned(),
        subject_der: vec![0x30, 0x01],
        issuer_der: vec![0x30, 0x02],
        serial: vec![1],
        not_before: time::OffsetDateTime::UNIX_EPOCH,
        not_after: time::OffsetDateTime::UNIX_EPOCH + time::Duration::days(365_000),
        spki_der: TEST_SIGNER_SPKI_DER.to_vec(),
        signature_algorithm_oid: "1.2.840.10045.4.3.2".to_owned(),
        basic_constraints: Some(BasicConstraints {
            ca: false,
            path_len_constraint: None,
        }),
        key_usage: Some(KeyUsage {
            digital_signature: true,
            content_commitment: false,
            key_encipherment: false,
            data_encipherment: false,
            key_cert_sign: false,
            crl_sign: false,
            key_agreement: false,
            encipher_only: false,
            decipher_only: false,
        }),
        extended_key_usage: None,
        subject_key_identifier: None,
        authority_key_identifier: None,
        san_dns: Vec::new(),
        san_ip: Vec::new(),
        certificate_policies: Vec::new(),
        qc_statements: Default::default(),
        profile: {
            let mut profile = CertificateProfile::default();
            profile.public_key = PublicKeyProfile::Ec {
                bits: 256,
                curve: None,
            };
            profile
        },
    };
    let source = TrustSourceEvidence {
        source_id: [7; 32],
        snapshot_id: [8; 32],
    };
    let config = TrustConfig {
        trust_roots: Vec::new(),
        now: evaluated_at,
        policy: Default::default(),
        link_policy: ChainLinkPolicy::default(),
        evaluation: TrustEvaluationContext {
            purpose: TrustPurpose::WalletAttestationIssuer,
            policy_id: TrustPolicyId::WalletAttestationIssuerV1,
            status_policy: CertificateStatusPolicy {
                leaf: StatusRequirement::Required,
                intermediates: StatusRequirement::Required,
                trust_anchor: StatusRequirement::Exempt,
            },
            source: Some(source),
        },
        direct_trust: vec![DirectTrustEntry {
            certificate: signer.clone(),
            purpose: TrustPurpose::WalletAttestationIssuer,
            policy_id: TrustPolicyId::WalletAttestationIssuerV1,
            source,
        }],
    };
    let decision = evaluate_trust_decision(
        &[signer],
        &config,
        &TestSignatureVerifier,
        Some(&TestStatusChecker),
    )
    .map_err(|_| OauthError::new(Reason::InvalidAttestationReceipt))?;
    WalletAttestationTrustEvidence::from_trust_decision(
        &decision,
        client_attestation,
        TEST_SIGNER_SPKI_DER,
    )
}
