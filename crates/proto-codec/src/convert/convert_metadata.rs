// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Credential Issuer Metadata protobuf conversions.

use std::collections::BTreeMap;
use std::mem;

use buffa::EnumValue;
use openid4vci_proto::generated::proto::reallyme::openid4vci::v1 as pb;
use openid4vci_types as types;

use super::convert_messages::{
    insert_unique, json_to_vec, map_wire, option_from_message_field, optional_json_bytes,
    optional_map, optional_string, optional_u64, optional_vec, ProtoError, ProtoResult,
};
use super::convert_values::{credential_format_from_proto, credential_format_to_proto};

/// Converts validated Credential Issuer Metadata into protobuf.
pub fn issuer_metadata_to_proto(value: &types::IssuerMetadata) -> ProtoResult<pb::IssuerMetadata> {
    map_wire(value.validate())?;
    Ok(pb::IssuerMetadata {
        credential_issuer: value.credential_issuer.clone(),
        authorization_servers: value.authorization_servers.clone().unwrap_or_default(),
        credential_endpoint: value.credential_endpoint.clone(),
        nonce_endpoint: value.nonce_endpoint.clone().unwrap_or_default(),
        deferred_credential_endpoint: value
            .deferred_credential_endpoint
            .clone()
            .unwrap_or_default(),
        notification_endpoint: value.notification_endpoint.clone().unwrap_or_default(),
        credential_request_encryption: value
            .credential_request_encryption
            .as_ref()
            .map(credential_request_encryption_metadata_to_proto)
            .transpose()?
            .into(),
        credential_response_encryption: value
            .credential_response_encryption
            .as_ref()
            .map(credential_response_encryption_metadata_to_proto)
            .into(),
        credential_configurations_supported: value
            .credential_configurations_supported
            .iter()
            .map(|(id, configuration)| {
                credential_configuration_to_proto(configuration).map(|proto| {
                    pb::CredentialConfigurationEntry {
                        credential_configuration_id: id.clone(),
                        configuration: proto.into(),
                        __buffa_unknown_fields: Default::default(),
                    }
                })
            })
            .collect::<ProtoResult<_>>()?,
        preferred_client_status_period: value.preferred_client_status_period.unwrap_or_default(),
        batch_credential_issuance: value
            .batch_credential_issuance
            .map(|batch| pb::BatchCredentialIssuance {
                batch_size: batch.batch_size,
                ..Default::default()
            })
            .into(),
        __buffa_unknown_fields: Default::default(),
    })
}

/// Converts protobuf Credential Issuer Metadata into OpenID4VCI.
pub fn issuer_metadata_from_proto(
    mut value: pb::IssuerMetadata,
) -> ProtoResult<types::IssuerMetadata> {
    let credential_configurations_supported =
        mem::take(&mut value.credential_configurations_supported)
            .into_iter()
            .try_fold(BTreeMap::new(), |mut configurations, mut entry| {
                let id = mem::take(&mut entry.credential_configuration_id);
                let configuration = option_from_message_field(mem::take(&mut entry.configuration))
                    .ok_or(ProtoError::MissingRequiredField)
                    .and_then(credential_configuration_from_proto)?;
                insert_unique(&mut configurations, id, configuration)?;
                Ok(configurations)
            })?;
    let metadata = types::IssuerMetadata {
        credential_issuer: mem::take(&mut value.credential_issuer),
        authorization_servers: optional_vec(mem::take(&mut value.authorization_servers)),
        credential_endpoint: mem::take(&mut value.credential_endpoint),
        nonce_endpoint: optional_string(mem::take(&mut value.nonce_endpoint)),
        deferred_credential_endpoint: optional_string(mem::take(
            &mut value.deferred_credential_endpoint,
        )),
        notification_endpoint: optional_string(mem::take(&mut value.notification_endpoint)),
        preferred_client_status_period: optional_u64(value.preferred_client_status_period),
        credential_request_encryption: option_from_message_field(mem::take(
            &mut value.credential_request_encryption,
        ))
        .map(credential_request_encryption_metadata_from_proto)
        .transpose()?,
        credential_response_encryption: option_from_message_field(mem::take(
            &mut value.credential_response_encryption,
        ))
        .map(credential_response_encryption_metadata_from_proto)
        .transpose()?,
        batch_credential_issuance: option_from_message_field(mem::take(
            &mut value.batch_credential_issuance,
        ))
        .map(|batch| types::BatchCredentialIssuance {
            batch_size: batch.batch_size,
        }),
        credential_configurations_supported,
    };
    map_wire(metadata.validate())?;
    Ok(metadata)
}

fn credential_configuration_to_proto(
    value: &types::CredentialConfiguration,
) -> ProtoResult<pb::CredentialConfiguration> {
    Ok(pb::CredentialConfiguration {
        format: EnumValue::from(credential_format_to_proto(&value.format)),
        scope: value.scope.clone().unwrap_or_default(),
        cryptographic_binding_methods_supported: value
            .cryptographic_binding_methods_supported
            .clone()
            .unwrap_or_default(),
        credential_signing_alg_values_supported: value
            .credential_signing_alg_values_supported
            .clone()
            .unwrap_or_default()
            .iter()
            .map(credential_signing_alg_to_proto)
            .collect(),
        proof_types_supported: value
            .proof_types_supported
            .as_ref()
            .map(|proof_types| {
                proof_types
                    .iter()
                    .map(|(id, proof_type)| pb::ProofTypeMetadataEntry {
                        proof_type: id.clone(),
                        metadata: proof_type_metadata_to_proto(proof_type).into(),
                        __buffa_unknown_fields: Default::default(),
                    })
                    .collect()
            })
            .unwrap_or_default(),
        credential_metadata_json: value
            .credential_metadata
            .as_ref()
            .map(json_to_vec)
            .transpose()?
            .unwrap_or_default(),
        claims_json: Vec::new(),
        vct: value.vct.clone().unwrap_or_default(),
        doctype: value.doctype.clone().unwrap_or_default(),
        __buffa_unknown_fields: Default::default(),
    })
}

fn credential_configuration_from_proto(
    mut value: pb::CredentialConfiguration,
) -> ProtoResult<types::CredentialConfiguration> {
    let credential_metadata = if value.credential_metadata_json.is_empty() {
        optional_json_bytes(&value.claims_json)?
    } else {
        optional_json_bytes(&value.credential_metadata_json)?
    };
    let configuration = types::CredentialConfiguration {
        format: credential_format_from_proto(
            value.format.as_known().ok_or(ProtoError::InvalidEnum)?,
        )?,
        scope: optional_string(mem::take(&mut value.scope)),
        cryptographic_binding_methods_supported: optional_vec(mem::take(
            &mut value.cryptographic_binding_methods_supported,
        )),
        credential_signing_alg_values_supported: optional_vec(
            mem::take(&mut value.credential_signing_alg_values_supported)
                .into_iter()
                .map(credential_signing_alg_from_proto)
                .collect::<ProtoResult<Vec<_>>>()?,
        ),
        proof_types_supported: optional_map(
            mem::take(&mut value.proof_types_supported)
                .into_iter()
                .try_fold(BTreeMap::new(), |mut proof_types, mut entry| {
                    let id = mem::take(&mut entry.proof_type);
                    let proof_type = option_from_message_field(entry.metadata)
                        .ok_or(ProtoError::MissingRequiredField)
                        .and_then(proof_type_metadata_from_proto)?;
                    insert_unique(&mut proof_types, id, proof_type)?;
                    Ok(proof_types)
                })?,
        ),
        vct: optional_string(mem::take(&mut value.vct)),
        doctype: optional_string(mem::take(&mut value.doctype)),
        credential_metadata,
    };
    map_wire(configuration.validate())?;
    Ok(configuration)
}

fn credential_signing_alg_to_proto(
    value: &types::CredentialSigningAlg,
) -> pb::CredentialSigningAlg {
    let value = match value {
        types::CredentialSigningAlg::Named(name) => {
            pb::credential_signing_alg::Value::Named(name.clone())
        }
        types::CredentialSigningAlg::Cose(cose) => pb::credential_signing_alg::Value::Cose(*cose),
    };
    pb::CredentialSigningAlg {
        value: Some(value),
        ..Default::default()
    }
}

fn credential_signing_alg_from_proto(
    value: pb::CredentialSigningAlg,
) -> ProtoResult<types::CredentialSigningAlg> {
    match value.value {
        Some(pb::credential_signing_alg::Value::Named(name)) => {
            let alg = types::CredentialSigningAlg::Named(name);
            map_wire(alg.validate())?;
            Ok(alg)
        }
        Some(pb::credential_signing_alg::Value::Cose(cose)) => {
            Ok(types::CredentialSigningAlg::Cose(cose))
        }
        None => Err(ProtoError::MissingRequiredField),
    }
}

fn proof_type_metadata_to_proto(value: &types::ProofTypeMetadata) -> pb::ProofTypeMetadata {
    pb::ProofTypeMetadata {
        proof_signing_alg_values_supported: value.proof_signing_alg_values_supported.clone(),
        key_attestations_required: value
            .key_attestations_required
            .as_ref()
            .map(key_attestations_required_to_proto)
            .into(),
        ..Default::default()
    }
}

fn proof_type_metadata_from_proto(
    value: pb::ProofTypeMetadata,
) -> ProtoResult<types::ProofTypeMetadata> {
    let metadata = types::ProofTypeMetadata {
        proof_signing_alg_values_supported: value.proof_signing_alg_values_supported,
        key_attestations_required: option_from_message_field(value.key_attestations_required)
            .map(key_attestations_required_from_proto)
            .transpose()?,
    };
    map_wire(metadata.validate())?;
    Ok(metadata)
}

fn key_attestations_required_to_proto(
    value: &types::KeyAttestationsRequired,
) -> pb::KeyAttestationsRequired {
    pb::KeyAttestationsRequired {
        key_storage: value.key_storage.clone().unwrap_or_default(),
        user_authentication: value.user_authentication.clone().unwrap_or_default(),
        preferred_key_storage_status_period: value
            .preferred_key_storage_status_period
            .unwrap_or_default(),
        ..Default::default()
    }
}

fn key_attestations_required_from_proto(
    value: pb::KeyAttestationsRequired,
) -> ProtoResult<types::KeyAttestationsRequired> {
    let required = types::KeyAttestationsRequired {
        key_storage: optional_vec(value.key_storage),
        user_authentication: optional_vec(value.user_authentication),
        preferred_key_storage_status_period: optional_u64(
            value.preferred_key_storage_status_period,
        ),
    };
    map_wire(required.validate())?;
    Ok(required)
}

fn credential_request_encryption_metadata_to_proto(
    value: &types::CredentialRequestEncryptionMetadata,
) -> ProtoResult<pb::CredentialRequestEncryptionMetadata> {
    Ok(pb::CredentialRequestEncryptionMetadata {
        alg_values_supported: value.alg_values_supported.clone().unwrap_or_default(),
        enc_values_supported: value.enc_values_supported.clone(),
        encryption_required: value.encryption_required,
        jwks_json: json_to_vec(&value.jwks)?,
        zip_values_supported: value.zip_values_supported.clone().unwrap_or_default(),
        __buffa_unknown_fields: Default::default(),
    })
}

fn credential_request_encryption_metadata_from_proto(
    mut value: pb::CredentialRequestEncryptionMetadata,
) -> ProtoResult<types::CredentialRequestEncryptionMetadata> {
    let metadata = types::CredentialRequestEncryptionMetadata {
        alg_values_supported: optional_vec(mem::take(&mut value.alg_values_supported)),
        enc_values_supported: mem::take(&mut value.enc_values_supported),
        jwks: types::PublicJwkSet::try_from(crate::json::deserialize_value(&value.jwks_json)?)
            .map_err(|_| ProtoError::InvalidWireValue)?,
        zip_values_supported: optional_vec(mem::take(&mut value.zip_values_supported)),
        encryption_required: value.encryption_required,
    };
    map_wire(metadata.validate())?;
    Ok(metadata)
}

fn credential_response_encryption_metadata_to_proto(
    value: &types::CredentialResponseEncryptionMetadata,
) -> pb::CredentialResponseEncryptionMetadata {
    pb::CredentialResponseEncryptionMetadata {
        alg_values_supported: value.alg_values_supported.clone().unwrap_or_default(),
        enc_values_supported: value.enc_values_supported.clone().unwrap_or_default(),
        encryption_required: value.encryption_required,
        zip_values_supported: value.zip_values_supported.clone().unwrap_or_default(),
        ..Default::default()
    }
}

fn credential_response_encryption_metadata_from_proto(
    value: pb::CredentialResponseEncryptionMetadata,
) -> ProtoResult<types::CredentialResponseEncryptionMetadata> {
    let metadata = types::CredentialResponseEncryptionMetadata {
        alg_values_supported: optional_vec(value.alg_values_supported),
        enc_values_supported: optional_vec(value.enc_values_supported),
        zip_values_supported: optional_vec(value.zip_values_supported),
        encryption_required: value.encryption_required,
    };
    map_wire(metadata.validate())?;
    Ok(metadata)
}
