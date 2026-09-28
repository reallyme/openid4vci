// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Security contract tests for generated OpenID4VCI protobuf bindings.

#![allow(missing_docs)]

use buffa::Message;
use reallyme_openid4vci_proto::generated::proto::reallyme::openid4vci::v1::{
    credential_envelope::Credential, CredentialEnvelope, CredentialEnvelopeOwnedView, Proofs,
    ProofsOwnedView,
};

const SENSITIVE_BYTE_1: u8 = 241;
const SENSITIVE_BYTE_2: u8 = 242;
const SENSITIVE_JWT: &str = "sensitive-proof-jwt";
const SENSITIVE_ATTESTATION: &str = "sensitive-attestation-jwt";
const SENSITIVE_COMPACT: &str = "sensitive.compact.credential";

fn assert_redacted(debug: &str, field: &str) {
    assert!(debug.contains(field), "{debug}");
    assert!(debug.contains("<redacted>"), "{debug}");
    assert!(!debug.contains(SENSITIVE_JWT), "{debug}");
    assert!(!debug.contains(SENSITIVE_ATTESTATION), "{debug}");
    assert!(!debug.contains("241"), "{debug}");
    assert!(!debug.contains("242"), "{debug}");
}

fn assert_redacted_view(debug: &str) {
    assert!(debug.contains("<redacted>"), "{debug}");
    assert!(!debug.contains(SENSITIVE_JWT), "{debug}");
    assert!(!debug.contains(SENSITIVE_ATTESTATION), "{debug}");
    assert!(!debug.contains("241"), "{debug}");
    assert!(!debug.contains("242"), "{debug}");
}

#[test]
fn generated_proof_debug_output_is_redacted() -> Result<(), buffa::DecodeError> {
    let proofs = Proofs {
        jwt: vec![SENSITIVE_JWT.to_owned()],
        di_vp_json: vec![vec![SENSITIVE_BYTE_1, SENSITIVE_BYTE_2]],
        attestation: vec![SENSITIVE_ATTESTATION.to_owned()],
        __buffa_unknown_fields: Default::default(),
    };

    let debug = format!("{proofs:?}");
    assert_redacted(&debug, "jwt");
    assert_redacted(&debug, "di_vp_json");
    assert_redacted(&debug, "attestation");

    let view = ProofsOwnedView::from_owned(&proofs)?;
    let view_debug = format!("{:?}", view.view());
    assert_redacted_view(&view_debug);
    assert!(format!("{view:?}").contains("<redacted>"));
    Ok(())
}

#[test]
fn generated_credential_oneof_debug_output_is_redacted() -> Result<(), buffa::DecodeError> {
    let compact = CredentialEnvelope {
        credential: Some(Credential::Compact(SENSITIVE_COMPACT.to_owned())),
        __buffa_unknown_fields: Default::default(),
    };
    let binary = CredentialEnvelope {
        credential: Some(Credential::Binary(vec![SENSITIVE_BYTE_1, SENSITIVE_BYTE_2])),
        __buffa_unknown_fields: Default::default(),
    };

    for envelope in [&compact, &binary] {
        let debug = format!("{envelope:?}");
        assert!(debug.contains("<redacted>"), "{debug}");
        assert!(!debug.contains(SENSITIVE_COMPACT), "{debug}");
        assert!(!debug.contains("241"), "{debug}");

        let view = CredentialEnvelopeOwnedView::from_owned(envelope)?;
        let view_debug = format!("{:?}", view.view());
        assert!(view_debug.contains("<redacted>"), "{view_debug}");
        assert!(!view_debug.contains(SENSITIVE_COMPACT), "{view_debug}");
        assert!(!view_debug.contains("241"), "{view_debug}");
    }
    Ok(())
}

#[test]
fn generated_proto_json_round_trips_hardened_fields() -> Result<(), serde_json::Error> {
    let proofs = Proofs {
        jwt: vec![SENSITIVE_JWT.to_owned()],
        di_vp_json: vec![br#"{"vp_token":"sensitive"}"#.to_vec()],
        attestation: vec![SENSITIVE_ATTESTATION.to_owned()],
        __buffa_unknown_fields: Default::default(),
    };

    let json = serde_json::to_string(&proofs)?;
    assert!(json.contains("diVpJson"), "{json}");
    assert!(!json.contains("vp_token"), "{json}");
    let decoded: Proofs = serde_json::from_str(&json)?;
    assert_eq!(decoded, proofs);
    Ok(())
}

#[test]
fn generated_clear_zeroizes_sensitive_fields() {
    let mut proofs = Proofs {
        jwt: vec![SENSITIVE_JWT.to_owned()],
        di_vp_json: vec![vec![SENSITIVE_BYTE_1, SENSITIVE_BYTE_2]],
        attestation: vec![SENSITIVE_ATTESTATION.to_owned()],
        __buffa_unknown_fields: Default::default(),
    };

    proofs.clear();
    assert!(proofs.jwt.is_empty());
    assert!(proofs.di_vp_json.is_empty());
    assert!(proofs.attestation.is_empty());
}

#[test]
fn generated_sensitive_owners_have_drop_guards() {
    assert!(std::mem::needs_drop::<Proofs>());
    assert!(std::mem::needs_drop::<Credential>());
    assert!(std::mem::needs_drop::<CredentialEnvelope>());
}
