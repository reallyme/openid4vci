// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Emit compiled OpenID4VCI mdoc metadata evidence.

use std::io::{self, Write};

use reallyme_openid4vci_types::{CredentialConfiguration, CredentialFormat};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
enum EvidenceError {
    #[error("ISO transport evidence serialization failed")]
    Serialize,
    #[error("ISO transport evidence output failed")]
    Output,
}

#[derive(Serialize)]
struct Evidence {
    schema: &'static str,
    producer: Producer,
    credential_configuration: CredentialConfigurationEvidence,
}

#[derive(Serialize)]
struct Producer {
    repository: &'static str,
    artifact: &'static str,
}

#[derive(Serialize)]
struct CredentialConfigurationEvidence {
    rust_type: &'static str,
    format: &'static str,
    doctype_cardinality: &'static str,
    claim_metadata_encoding: &'static str,
    issued_credential_semantics: &'static str,
}

fn build_evidence() -> Evidence {
    let configuration = CredentialConfiguration::new(CredentialFormat::MsoMdoc);
    let _compiled_fields = (
        configuration.format,
        configuration.scope,
        configuration.cryptographic_binding_methods_supported,
        configuration.credential_signing_alg_values_supported,
        configuration.proof_types_supported,
        configuration.vct,
        configuration.doctype,
        configuration.credential_metadata,
    );

    Evidence {
        schema: "reallyme.identity.iso_transport_evidence.v1",
        producer: Producer {
            repository: "reallyme/openid4vci",
            artifact: "compiled-rust-credential-configuration",
        },
        credential_configuration: CredentialConfigurationEvidence {
            rust_type: "CredentialConfiguration",
            format: "mso_mdoc",
            doctype_cardinality: "required_for_mso_mdoc_profile",
            claim_metadata_encoding: "untyped_json_metadata",
            issued_credential_semantics: "opaque_credential_payload_from_injected_encoder",
        },
    }
}

fn main() -> Result<(), EvidenceError> {
    let encoded =
        serde_json::to_vec_pretty(&build_evidence()).map_err(|_| EvidenceError::Serialize)?;
    let stdout = io::stdout();
    let mut output = stdout.lock();
    output
        .write_all(&encoded)
        .and_then(|()| output.write_all(b"\n"))
        .map_err(|_| EvidenceError::Output)
}
