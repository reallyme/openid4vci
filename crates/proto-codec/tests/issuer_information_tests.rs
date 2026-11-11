// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strict profile JSON decoding through the canonical metadata protobuf.

use buffa::EnumValue;
use openid4vci_proto::generated::proto::reallyme::openid4vci::v1 as pb;
use openid4vci_proto_codec::convert::{issuer_metadata_from_proto, ProtoError};

fn metadata(data_json: Vec<u8>) -> pb::IssuerMetadata {
    let mut configuration = pb::CredentialConfiguration::default();
    configuration.format = EnumValue::from(pb::CredentialFormat::DcSdJwt);
    configuration.vct = "https://credentials.example/pid".to_owned();
    let mut metadata = pb::IssuerMetadata::default();
    metadata.credential_issuer = "https://issuer.example".to_owned();
    metadata.credential_endpoint = "https://issuer.example/credential".to_owned();
    metadata
        .credential_configurations_supported
        .push(pb::CredentialConfigurationEntry {
            credential_configuration_id: "pid".to_owned(),
            configuration: configuration.into(),
            __buffa_unknown_fields: Default::default(),
        });
    metadata.issuer_info.push(pb::IssuerInformation {
        format: "registrar_dataset".to_owned(),
        data_json,
        __buffa_unknown_fields: Default::default(),
    });
    metadata
}

#[test]
fn issuer_information_rejects_duplicate_json_keys_and_invalid_utf8() {
    for body in [
        br#"{"identifier":"first","identifier":"second"}"#.to_vec(),
        vec![0xff, 0x00],
    ] {
        assert_eq!(
            issuer_metadata_from_proto(metadata(body)),
            Err(ProtoError::InvalidJson)
        );
    }
}

#[test]
fn issuer_information_rejects_an_absent_json_value() {
    assert_eq!(
        issuer_metadata_from_proto(metadata(Vec::new())),
        Err(ProtoError::MissingRequiredField)
    );
}

#[test]
fn issuer_information_preserves_profile_defined_json() {
    let decoded = issuer_metadata_from_proto(metadata(
        br#"{"identifier":"provider","extension":[true,7]}"#.to_vec(),
    ));
    assert!(decoded.is_ok());
}
