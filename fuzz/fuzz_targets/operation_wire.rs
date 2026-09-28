// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use openid4vci_proto::generated::proto::reallyme::openid4vci::v1 as pb;
use openid4vci_proto_codec::{decode_proto, execute_operation_json_v1, execute_operation_v1};

fuzz_target!(|data: &[u8]| {
    let binary_response = execute_operation_v1(data);
    let _ = decode_proto::<pb::OpenId4VciOperationResponse>(&binary_response);

    let json_response = execute_operation_json_v1(data);
    let _ = decode_proto::<pb::OpenId4VciOperationResponse>(&json_response);
});
