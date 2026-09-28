// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Notification handler used by the Axum issuer integration fixtures.

use openid4vci_issuer::{IssuerError, IssuerResult, IssuerStatus, NotificationHandler};
use openid4vci_types::{NotificationEvent, NotificationRequest};

pub(crate) struct TestNotificationHandler;

impl NotificationHandler for TestNotificationHandler {
    fn handle_notification(&self, request: &NotificationRequest) -> IssuerResult<()> {
        if request.event == NotificationEvent::CredentialAccepted {
            Ok(())
        } else {
            Err(IssuerError::new(IssuerStatus::InvalidNotificationId))
        }
    }
}
