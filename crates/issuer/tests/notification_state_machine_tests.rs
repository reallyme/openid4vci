// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Notification state-transition tests over the pure endpoint engine.

use openid4vci_issuer::{
    handle_notification_request, InMemoryNotificationStore, IssuerError, IssuerResult,
    IssuerStatus, NotificationHandler, NotificationStore,
};
use openid4vci_types::{NotificationEvent, NotificationRequest};

struct StoreBackedNotificationHandler {
    store: InMemoryNotificationStore,
    now_unix: u64,
}

impl NotificationHandler for StoreBackedNotificationHandler {
    fn handle_notification(&self, request: &NotificationRequest) -> IssuerResult<()> {
        self.store
            .record(&request.notification_id, request.event, self.now_unix)
    }
}

#[test]
fn notification_repeat_is_idempotent_but_malformed_state_fails() -> IssuerResult<()> {
    let handler = StoreBackedNotificationHandler {
        store: InMemoryNotificationStore::new(),
        now_unix: 10,
    };
    handler.store.reserve("notification-1", 10, 100)?;
    let accepted = NotificationRequest {
        notification_id: "notification-1".to_owned(),
        event: NotificationEvent::CredentialAccepted,
        event_description: None,
    };

    handle_notification_request(&accepted, &handler)?;
    handle_notification_request(&accepted, &handler)?;
    let record = handler
        .store
        .get("notification-1", 20)?
        .ok_or_else(|| IssuerError::new(IssuerStatus::InvalidNotificationId))?;
    assert_eq!(record.event, NotificationEvent::CredentialAccepted);

    let malformed = NotificationRequest {
        notification_id: String::new(),
        event: NotificationEvent::CredentialAccepted,
        event_description: None,
    };
    let result = handle_notification_request(&malformed, &handler);
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidRequest)
    );
    Ok(())
}

#[test]
fn cancellation_notification_locks_deleted_state() -> IssuerResult<()> {
    let handler = StoreBackedNotificationHandler {
        store: InMemoryNotificationStore::new(),
        now_unix: 10,
    };
    handler.store.reserve("notification-1", 10, 100)?;
    let deleted = NotificationRequest {
        notification_id: "notification-1".to_owned(),
        event: NotificationEvent::CredentialDeleted,
        event_description: Some("user abandoned issuance".to_owned()),
    };
    let accepted = NotificationRequest {
        notification_id: "notification-1".to_owned(),
        event: NotificationEvent::CredentialAccepted,
        event_description: None,
    };

    handle_notification_request(&deleted, &handler)?;
    let conflict = handle_notification_request(&accepted, &handler);
    assert_eq!(
        conflict.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidNotificationId)
    );
    let record = handler
        .store
        .get("notification-1", 20)?
        .ok_or_else(|| IssuerError::new(IssuerStatus::InvalidNotificationId))?;
    assert_eq!(record.event, NotificationEvent::CredentialDeleted);
    Ok(())
}
