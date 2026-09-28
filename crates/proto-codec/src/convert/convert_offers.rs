// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Converts Credential Offers and their grants.

use std::mem;

use buffa::EnumValue;
use openid4vci_proto::generated::proto::reallyme::openid4vci::v1 as pb;
use openid4vci_types as types;

use super::convert_messages::{
    map_wire, option_from_message_field, optional_string, optional_u64, ProtoError, ProtoResult,
};
use super::convert_values::{tx_code_input_mode_from_proto, tx_code_input_mode_to_proto};

/// Converts an OpenID4VCI Credential Offer into protobuf.
#[must_use]
pub fn credential_offer_to_proto(value: &types::CredentialOffer) -> pb::CredentialOffer {
    pb::CredentialOffer {
        credential_issuer: value.credential_issuer.clone(),
        credential_configuration_ids: value.credential_configuration_ids.clone(),
        grants: value
            .grants
            .as_ref()
            .map(credential_offer_grants_to_proto)
            .into(),
        __buffa_unknown_fields: Default::default(),
    }
}

/// Converts a protobuf Credential Offer into OpenID4VCI.
pub fn credential_offer_from_proto(
    mut value: pb::CredentialOffer,
) -> ProtoResult<types::CredentialOffer> {
    let offer = types::CredentialOffer {
        credential_issuer: mem::take(&mut value.credential_issuer),
        credential_configuration_ids: mem::take(&mut value.credential_configuration_ids),
        grants: option_from_message_field(mem::take(&mut value.grants))
            .map(credential_offer_grants_from_proto)
            .transpose()?,
    };
    map_wire(offer.validate())?;
    Ok(offer)
}

/// Converts a parsed Credential Offer URI payload into protobuf.
#[must_use]
pub fn parsed_credential_offer_to_proto(
    value: &types::ParsedCredentialOffer,
) -> pb::CredentialOfferUri {
    let payload = match value {
        types::ParsedCredentialOffer::Inline(offer) => {
            pb::credential_offer_uri::Payload::CredentialOffer(Box::new(credential_offer_to_proto(
                offer,
            )))
        }
        types::ParsedCredentialOffer::Reference(uri) => {
            pb::credential_offer_uri::Payload::CredentialOfferUri(uri.clone())
        }
    };
    pb::CredentialOfferUri {
        payload: Some(payload),
        __buffa_unknown_fields: Default::default(),
    }
}

/// Converts a protobuf Credential Offer URI payload into OpenID4VCI.
pub fn parsed_credential_offer_from_proto(
    mut value: pb::CredentialOfferUri,
) -> ProtoResult<types::ParsedCredentialOffer> {
    let mut payload = value
        .payload
        .take()
        .ok_or(ProtoError::MissingRequiredField)?;
    match &mut payload {
        pb::credential_offer_uri::Payload::CredentialOffer(offer) => Ok(
            types::ParsedCredentialOffer::Inline(credential_offer_from_proto(*mem::take(offer))?),
        ),
        pb::credential_offer_uri::Payload::CredentialOfferUri(uri) => {
            let wrapper = map_wire(types::build_credential_offer_reference_uri(
                "openid-credential-offer://",
                uri,
            ))?;
            let parsed = map_wire(types::parse_credential_offer_uri(&wrapper))?;
            match parsed {
                types::ParsedCredentialOffer::Reference(validated_uri) => {
                    Ok(types::ParsedCredentialOffer::Reference(validated_uri))
                }
                types::ParsedCredentialOffer::Inline(_) => Err(ProtoError::InvalidWireValue),
            }
        }
    }
}

fn credential_offer_grants_to_proto(
    value: &types::CredentialOfferGrant,
) -> pb::CredentialOfferGrants {
    pb::CredentialOfferGrants {
        authorization_code: value
            .authorization_code
            .as_ref()
            .map(|grant| pb::AuthorizationCodeGrant {
                issuer_state: grant.issuer_state.clone().unwrap_or_default(),
                authorization_server: grant.authorization_server.clone().unwrap_or_default(),
                __buffa_unknown_fields: Default::default(),
            })
            .into(),
        pre_authorized_code: value
            .pre_authorized_code
            .as_ref()
            .map(pre_authorized_code_grant_to_proto)
            .into(),
        ..Default::default()
    }
}

fn credential_offer_grants_from_proto(
    value: pb::CredentialOfferGrants,
) -> ProtoResult<types::CredentialOfferGrant> {
    let grants = types::CredentialOfferGrant {
        authorization_code: option_from_message_field(value.authorization_code).map(|mut grant| {
            types::AuthorizationCodeGrant {
                issuer_state: optional_string(mem::take(&mut grant.issuer_state)),
                authorization_server: optional_string(mem::take(&mut grant.authorization_server)),
            }
        }),
        pre_authorized_code: option_from_message_field(value.pre_authorized_code)
            .map(pre_authorized_code_grant_from_proto)
            .transpose()?,
    };
    map_wire(grants.validate())?;
    Ok(grants)
}

fn pre_authorized_code_grant_to_proto(
    value: &types::PreAuthorizedCodeGrant,
) -> pb::PreAuthorizedCodeGrant {
    pb::PreAuthorizedCodeGrant {
        pre_authorized_code: value.pre_authorized_code.clone(),
        tx_code: value.tx_code.as_ref().map(tx_code_to_proto).into(),
        authorization_server: value.authorization_server.clone().unwrap_or_default(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn pre_authorized_code_grant_from_proto(
    mut value: pb::PreAuthorizedCodeGrant,
) -> ProtoResult<types::PreAuthorizedCodeGrant> {
    let grant = types::PreAuthorizedCodeGrant {
        pre_authorized_code: mem::take(&mut value.pre_authorized_code),
        tx_code: option_from_message_field(mem::take(&mut value.tx_code))
            .map(tx_code_from_proto)
            .transpose()?,
        authorization_server: optional_string(mem::take(&mut value.authorization_server)),
    };
    map_wire(grant.validate())?;
    Ok(grant)
}

fn tx_code_to_proto(value: &types::TxCode) -> pb::TxCode {
    pb::TxCode {
        input_mode: value
            .input_mode
            .map(tx_code_input_mode_to_proto)
            .map(EnumValue::from)
            .unwrap_or_default(),
        length: value.length.unwrap_or_default(),
        description: value.description.clone().unwrap_or_default(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn tx_code_from_proto(mut value: pb::TxCode) -> ProtoResult<types::TxCode> {
    let tx_code = types::TxCode {
        input_mode: tx_code_input_mode_from_proto(value.input_mode)?,
        length: optional_u64(value.length),
        description: optional_string(mem::take(&mut value.description)),
    };
    map_wire(tx_code.validate())?;
    Ok(tx_code)
}
