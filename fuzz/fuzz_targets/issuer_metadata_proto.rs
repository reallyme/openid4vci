// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use openid4vci_proto::generated::proto::reallyme::openid4vci::v1 as pb;
use openid4vci_proto_codec::convert::issuer_metadata_from_proto;
use openid4vci_proto_codec::decode_proto;

fuzz_target!(|data: &[u8]| {
    if let Ok(metadata) = decode_proto::<pb::IssuerMetadata>(data) {
        let _ = issuer_metadata_from_proto(metadata);
    }
});
