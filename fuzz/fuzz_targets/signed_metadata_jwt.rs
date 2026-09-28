// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_openid4vci_wallet::{
    verify_signed_issuer_metadata, ParsedSignedIssuerMetadata, SignedIssuerMetadataJwt,
    SignedIssuerMetadataTrustVerifier, SignedIssuerMetadataValidationContext,
    SignedMetadataAlgorithm, SignedMetadataSignerTrustPurpose, SignedMetadataTrustEvidenceInput,
    SignedMetadataTrustPurpose, WalletResult,
};

struct FuzzTrustVerifier;

impl SignedIssuerMetadataTrustVerifier for FuzzTrustVerifier {
    fn verify_signed_issuer_metadata(
        &self,
        _jwt: &SignedIssuerMetadataJwt,
        parsed: &ParsedSignedIssuerMetadata,
    ) -> WalletResult<SignedMetadataTrustEvidenceInput> {
        Ok(SignedMetadataTrustEvidenceInput {
            verified_signing_input: parsed.signing_input().to_owned(),
            signer_identity: "fuzz-signer".to_owned(),
            asserted_issuer: parsed.issuer().map(str::to_owned),
            policy_version: "fuzz-policy".to_owned(),
            source_snapshot: "fuzz-snapshot".to_owned(),
            anchor: "fuzz-anchor".to_owned(),
            evaluated_at: 1_700_000_000,
            valid_until: 1_700_000_600,
            purpose: SignedMetadataTrustPurpose::CredentialIssuerMetadata,
            signer_trust_purpose: SignedMetadataSignerTrustPurpose::CredentialIssuerMetadataSigner,
        })
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(compact) = core::str::from_utf8(data) else {
        return;
    };
    let Ok(jwt) = SignedIssuerMetadataJwt::new(compact.to_owned()) else {
        return;
    };
    let context = SignedIssuerMetadataValidationContext {
        expected_credential_issuer: "https://issuer.example".to_owned(),
        current_time: 1_700_000_000,
        max_age_seconds: 300,
        allowed_clock_skew_seconds: 60,
        accepted_algorithms: vec![SignedMetadataAlgorithm::Es256],
        required_signer_trust_purpose:
            SignedMetadataSignerTrustPurpose::CredentialIssuerMetadataSigner,
    };
    let _ = verify_signed_issuer_metadata(&jwt, &context, &FuzzTrustVerifier);
});
