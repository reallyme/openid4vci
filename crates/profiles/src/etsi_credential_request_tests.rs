// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! ETSI credential request proof-shape regression tests.

use super::{
    validate_etsi_credential_request_proofs, EtsiCredentialProofErrorReason,
    EtsiCredentialProofMechanism,
};
use openid4vci_types::Proofs;
use serde_json::json;

fn proofs(jwt: Vec<&str>, di_vp: Vec<serde_json::Value>, attestation: Vec<&str>) -> Proofs {
    Proofs {
        jwt: jwt.into_iter().map(str::to_owned).collect(),
        di_vp,
        attestation: attestation.into_iter().map(str::to_owned).collect(),
    }
}

#[test]
fn accepts_the_two_single_element_etsi_mechanisms() {
    let jwt = proofs(vec!["header.payload.signature"], Vec::new(), Vec::new());
    assert_eq!(
        validate_etsi_credential_request_proofs(Some(&jwt), true),
        Ok(Some(EtsiCredentialProofMechanism::Jwt))
    );

    let attestation = proofs(Vec::new(), Vec::new(), vec!["header.payload.signature"]);
    assert_eq!(
        validate_etsi_credential_request_proofs(Some(&attestation), true),
        Ok(Some(EtsiCredentialProofMechanism::Attestation))
    );
}

#[test]
fn rejects_missing_multiple_and_di_vp_proofs() {
    assert_eq!(
        validate_etsi_credential_request_proofs(None, true).map_err(|error| error.reason()),
        Err(EtsiCredentialProofErrorReason::ProofRequired)
    );
    let multiple = proofs(vec!["a.b.c", "d.e.f"], Vec::new(), Vec::new());
    assert_eq!(
        validate_etsi_credential_request_proofs(Some(&multiple), true)
            .map_err(|error| error.reason()),
        Err(EtsiCredentialProofErrorReason::InvalidProofCardinality)
    );
    let di_vp = proofs(Vec::new(), vec![json!({"proof": {}})], Vec::new());
    assert_eq!(
        validate_etsi_credential_request_proofs(Some(&di_vp), true).map_err(|error| error.reason()),
        Err(EtsiCredentialProofErrorReason::UnsupportedProofMechanism)
    );
}
