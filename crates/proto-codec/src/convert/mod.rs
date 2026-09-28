// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Protobuf conversion surface.

mod convert_messages;
mod convert_metadata;
mod convert_offers;
mod convert_values;

pub use convert_messages::{
    credential_envelope_from_proto, credential_envelope_to_proto, credential_request_from_proto,
    credential_request_to_proto, credential_response_from_proto, credential_response_to_proto,
    deferred_credential_request_from_proto, deferred_credential_request_to_proto,
    nonce_response_from_proto, nonce_response_to_proto, notification_request_from_proto,
    notification_request_to_proto, ProtoError, ProtoResult,
};
pub use convert_metadata::{issuer_metadata_from_proto, issuer_metadata_to_proto};
pub use convert_offers::{
    credential_offer_from_proto, credential_offer_to_proto, parsed_credential_offer_from_proto,
    parsed_credential_offer_to_proto,
};
pub use convert_values::{
    credential_format_from_proto, credential_format_to_proto, notification_event_from_proto,
    notification_event_to_proto, problem_details_from_proto, problem_details_to_proto,
    tx_code_input_mode_from_proto, tx_code_input_mode_to_proto,
};
