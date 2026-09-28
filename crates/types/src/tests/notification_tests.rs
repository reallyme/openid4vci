// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::error::OpenId4VciError;

use super::NotificationRequest;

#[test]
fn notification_request_ignores_unrecognized_top_level_parameters() -> Result<(), OpenId4VciError> {
    let request = NotificationRequest::parse_json(
        r#"{"notification_id":"notification-1","event":"credential_accepted","extension":{"enabled":true}}"#,
    )?;

    assert_eq!(request.notification_id, "notification-1");
    Ok(())
}
