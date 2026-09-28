// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 9457 issuer problem mapping tests.

use reallyme_openid4vci_types::{IssuerProblemStatus, ProblemDetails, ProblemType};

#[test]
fn every_issuer_status_maps_to_problem_details() {
    let cases = [
        (
            IssuerProblemStatus::InvalidRequest,
            ProblemType::InvalidRequest,
        ),
        (
            IssuerProblemStatus::UnsupportedCredential,
            ProblemType::UnsupportedCredential,
        ),
        (
            IssuerProblemStatus::ProofRequired,
            ProblemType::InvalidProof,
        ),
        (IssuerProblemStatus::InvalidProof, ProblemType::InvalidProof),
        (IssuerProblemStatus::InvalidNonce, ProblemType::InvalidNonce),
        (
            IssuerProblemStatus::EncryptionRequired,
            ProblemType::EncryptionRequired,
        ),
        (
            IssuerProblemStatus::InvalidTransaction,
            ProblemType::InvalidTransaction,
        ),
        (
            IssuerProblemStatus::InvalidNotificationId,
            ProblemType::InvalidNotificationId,
        ),
        (
            IssuerProblemStatus::StorageUnavailable,
            ProblemType::StorageUnavailable,
        ),
        (
            IssuerProblemStatus::EncodingFailed,
            ProblemType::ServerError,
        ),
    ];

    for (status, problem_type) in cases {
        let problem = ProblemDetails::from_issuer_status(status, None);
        assert_eq!(problem.status, problem_type.status());
        assert_eq!(problem.error.as_deref(), Some(problem_type.error_code()));
    }
}

#[test]
fn wire_error_codes_use_final_spec_vocabulary() {
    // OpenID4VCI 1.0 FINAL §8.3.1.2, §9.3, §11.3 error-code vocabulary.
    assert_eq!(
        ProblemType::UnsupportedCredential.error_code(),
        "unknown_credential_configuration"
    );
    assert_eq!(
        ProblemType::UnknownCredentialIdentifier.error_code(),
        "unknown_credential_identifier"
    );
    assert_eq!(
        ProblemType::EncryptionRequired.error_code(),
        "invalid_encryption_parameters"
    );
    assert_eq!(
        ProblemType::InvalidTransaction.error_code(),
        "invalid_transaction_id"
    );
    assert_eq!(
        ProblemType::InvalidNotificationId.error_code(),
        "invalid_notification_id"
    );
    assert_eq!(
        ProblemType::InvalidNotificationRequest.error_code(),
        "invalid_notification_request"
    );
}
