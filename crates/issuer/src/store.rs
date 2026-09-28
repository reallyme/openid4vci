// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Storage trait boundaries for issuer adapters.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::sync::{Mutex, MutexGuard};

use openid4vci_types::CredentialRequest;
use openid4vci_types::NotificationEvent;

use crate::encode::{
    encode_immediate_response_with_expected_count, validate_issued_credential_count,
    validate_issued_credential_count_with_verified_proofs, CredentialEncoder, IssuedCredential,
};
use crate::error::{IssuerError, IssuerResult, IssuerStatus};
use crate::proof::VerifiedProofSet;
use openid4vci_types::CredentialResponse;

const DEFAULT_MAX_NOTIFICATION_ENTRIES: usize = 65_536;
const DEFAULT_MAX_DEFERRED_ENTRIES: usize = 65_536;

/// Records notification events idempotently.
pub trait NotificationStore: Send + Sync {
    /// Reserves an issuer-generated notification identifier before returning it
    /// to a wallet. Implementations must use insert-if-absent semantics.
    fn reserve(
        &self,
        notification_id: &str,
        now_unix: u64,
        expires_at_unix: u64,
    ) -> IssuerResult<()>;

    /// Records the notification event for the supplied identifier.
    fn record(
        &self,
        notification_id: &str,
        event: NotificationEvent,
        now_unix: u64,
    ) -> IssuerResult<()>;
}

/// Deferred issuance record stored between the Credential Endpoint and the
/// Deferred Credential Endpoint.
///
/// The record intentionally stores the validated request alongside the
/// already-issued credential payloads so a later resolver can encode the final
/// Credential Response without re-running authorization decisions.
#[derive(PartialEq)]
pub struct DeferredIssuance {
    /// Credential request that started the deferred transaction.
    pub request: CredentialRequest,
    /// Already-issued credential payloads awaiting final response encoding.
    pub issued: Vec<IssuedCredential>,
    expected_credential_count: usize,
}

impl DeferredIssuance {
    /// Creates a deferred issuance record after checking it can later resolve
    /// into at least one credential.
    pub fn new(request: CredentialRequest, issued: Vec<IssuedCredential>) -> IssuerResult<Self> {
        if issued.is_empty() {
            return Err(IssuerError::new(IssuerStatus::InvalidTransaction));
        }
        request
            .validate()
            .map_err(|_| IssuerError::new(IssuerStatus::InvalidRequest))?;
        validate_issued_credential_count(&request, issued.len())?;
        let expected_credential_count = issued.len();
        Ok(Self {
            request,
            issued,
            expected_credential_count,
        })
    }

    /// Creates a deferred record using verified binding-key cardinality.
    ///
    /// Direct key-attestation proofs may bind several keys in a single proof;
    /// retaining the verified count allows the deferred path to issue one
    /// credential per key without reverting to unverified proof-array length.
    pub fn new_with_verified_proofs(
        request: CredentialRequest,
        issued: Vec<IssuedCredential>,
        verified_proofs: Option<&VerifiedProofSet>,
    ) -> IssuerResult<Self> {
        if issued.is_empty() {
            return Err(IssuerError::new(IssuerStatus::InvalidTransaction));
        }
        request
            .validate()
            .map_err(|_| IssuerError::new(IssuerStatus::InvalidRequest))?;
        validate_issued_credential_count_with_verified_proofs(
            &request,
            verified_proofs,
            issued.len(),
        )?;
        let expected_credential_count = issued.len();
        Ok(Self {
            request,
            issued,
            expected_credential_count,
        })
    }

    /// Encodes the final response using the credential count committed when
    /// the deferred record was created.
    pub fn encode_response(
        &self,
        encoder: &dyn CredentialEncoder,
        notification_id: Option<String>,
    ) -> IssuerResult<CredentialResponse> {
        encode_immediate_response_with_expected_count(
            &self.request,
            encoder,
            &self.issued,
            notification_id,
            self.expected_credential_count,
        )
    }
}

/// Stores deferred issuance transactions with single-use take semantics.
pub trait DeferredStore: Send + Sync {
    /// Stores a deferred issuance record under a transaction identifier.
    ///
    /// `expires_at_unix` must be later than `now_unix`. Implementations must
    /// remove expired entries before enforcing capacity so abandoned
    /// transactions cannot exhaust the store permanently.
    fn put(
        &self,
        transaction_id: &str,
        record: DeferredIssuance,
        now_unix: u64,
        expires_at_unix: u64,
    ) -> IssuerResult<()>;

    /// Removes and returns the transaction record atomically.
    fn take(&self, transaction_id: &str, now_unix: u64) -> IssuerResult<DeferredIssuance>;
}

/// Notification event record retained by an issuer adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotificationRecord {
    /// Event reported by the wallet.
    pub event: NotificationEvent,
    /// Timestamp supplied by the adapter.
    pub recorded_at_unix: u64,
}

/// In-memory idempotent notification store.
pub struct InMemoryNotificationStore {
    inner: Mutex<NotificationState>,
    max_entries: usize,
}

#[derive(Default)]
struct NotificationState {
    entries: HashMap<String, NotificationEntry>,
    expirations: BinaryHeap<Reverse<(u64, String)>>,
}

struct NotificationEntry {
    record: Option<NotificationRecord>,
    expires_at_unix: u64,
}

impl NotificationState {
    fn prune(&mut self, now_unix: u64) {
        while let Some(Reverse((expires_at_unix, notification_id))) = self.expirations.peek() {
            if *expires_at_unix > now_unix {
                break;
            }
            let expires_at_unix = *expires_at_unix;
            let notification_id = notification_id.clone();
            self.expirations.pop();
            if self
                .entries
                .get(&notification_id)
                .is_some_and(|entry| entry.expires_at_unix == expires_at_unix)
            {
                self.entries.remove(&notification_id);
            }
        }
    }
}

impl InMemoryNotificationStore {
    /// Creates an empty notification store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(NotificationState::default()),
            max_entries: DEFAULT_MAX_NOTIFICATION_ENTRIES,
        }
    }

    /// Creates a store with an explicit hard entry ceiling.
    pub fn with_max_entries(max_entries: usize) -> IssuerResult<Self> {
        if max_entries == 0 {
            return Err(IssuerError::new(IssuerStatus::StorageUnavailable));
        }
        Ok(Self {
            inner: Mutex::new(NotificationState::default()),
            max_entries,
        })
    }

    /// Returns the stored notification record, if any.
    pub fn get(
        &self,
        notification_id: &str,
        now_unix: u64,
    ) -> IssuerResult<Option<NotificationRecord>> {
        let mut state = self
            .inner
            .lock()
            .map_err(|_| IssuerError::new(IssuerStatus::StorageUnavailable))?;
        state.prune(now_unix);
        Ok(state
            .entries
            .get(notification_id)
            .and_then(|entry| entry.record))
    }
}

impl NotificationStore for InMemoryNotificationStore {
    fn reserve(
        &self,
        notification_id: &str,
        now_unix: u64,
        expires_at_unix: u64,
    ) -> IssuerResult<()> {
        if notification_id.is_empty() || expires_at_unix <= now_unix {
            return Err(IssuerError::new(IssuerStatus::InvalidNotificationId));
        }
        let mut state = self
            .inner
            .lock()
            .map_err(|_| IssuerError::new(IssuerStatus::StorageUnavailable))?;
        state.prune(now_unix);
        if state.entries.len() >= self.max_entries {
            return Err(IssuerError::new(IssuerStatus::StorageUnavailable));
        }
        match state.entries.entry(notification_id.to_owned()) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(NotificationEntry {
                    record: None,
                    expires_at_unix,
                });
                state
                    .expirations
                    .push(Reverse((expires_at_unix, notification_id.to_owned())));
                Ok(())
            }
            std::collections::hash_map::Entry::Occupied(_) => {
                Err(IssuerError::new(IssuerStatus::InvalidNotificationId))
            }
        }
    }

    fn record(
        &self,
        notification_id: &str,
        event: NotificationEvent,
        now_unix: u64,
    ) -> IssuerResult<()> {
        if notification_id.is_empty() {
            return Err(IssuerError::new(IssuerStatus::InvalidNotificationId));
        }
        let mut state = self
            .inner
            .lock()
            .map_err(|_| IssuerError::new(IssuerStatus::StorageUnavailable))?;
        state.prune(now_unix);
        let entry = state
            .entries
            .get_mut(notification_id)
            .ok_or_else(|| IssuerError::new(IssuerStatus::InvalidNotificationId))?;
        match entry.record {
            None => {
                entry.record = Some(NotificationRecord {
                    event,
                    recorded_at_unix: now_unix,
                })
            }
            Some(record) if record.event == event => {}
            Some(_) => return Err(IssuerError::new(IssuerStatus::InvalidNotificationId)),
        }
        Ok(())
    }
}

/// In-memory single-process deferred issuance store.
///
/// Production adapters should back `DeferredStore` with durable storage because
/// deferred transactions usually outlive one HTTP request and may need to cross
/// issuer replicas.
pub struct InMemoryDeferredStore {
    inner: Mutex<DeferredState>,
    max_entries: usize,
}

#[derive(Default)]
struct DeferredState {
    entries: HashMap<String, DeferredEntry>,
    expirations: BinaryHeap<Reverse<(u64, String)>>,
}

struct DeferredEntry {
    record: DeferredIssuance,
    expires_at_unix: u64,
}

impl DeferredState {
    fn prune(&mut self, now_unix: u64) {
        while let Some(Reverse((expires_at_unix, transaction_id))) = self.expirations.peek() {
            if *expires_at_unix > now_unix {
                break;
            }
            let expires_at_unix = *expires_at_unix;
            let transaction_id = transaction_id.clone();
            self.expirations.pop();
            if self
                .entries
                .get(&transaction_id)
                .is_some_and(|entry| entry.expires_at_unix == expires_at_unix)
            {
                self.entries.remove(&transaction_id);
            }
        }
    }
}

impl InMemoryDeferredStore {
    /// Creates an empty deferred issuance store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(DeferredState::default()),
            max_entries: DEFAULT_MAX_DEFERRED_ENTRIES,
        }
    }

    /// Creates a deferred store with an explicit hard entry ceiling.
    pub fn with_max_entries(max_entries: usize) -> IssuerResult<Self> {
        if max_entries == 0 {
            return Err(IssuerError::new(IssuerStatus::StorageUnavailable));
        }
        Ok(Self {
            inner: Mutex::new(DeferredState::default()),
            max_entries,
        })
    }

    fn lock(&self) -> IssuerResult<MutexGuard<'_, DeferredState>> {
        self.inner
            .lock()
            .map_err(|_| IssuerError::new(IssuerStatus::StorageUnavailable))
    }
}

impl Default for InMemoryNotificationStore {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for InMemoryDeferredStore {
    fn default() -> Self {
        Self::new()
    }
}

impl DeferredStore for InMemoryDeferredStore {
    fn put(
        &self,
        transaction_id: &str,
        record: DeferredIssuance,
        now_unix: u64,
        expires_at_unix: u64,
    ) -> IssuerResult<()> {
        if transaction_id.is_empty() || expires_at_unix <= now_unix {
            return Err(IssuerError::new(IssuerStatus::InvalidTransaction));
        }
        let mut state = self.lock()?;
        state.prune(now_unix);
        let at_capacity = state.entries.len() >= self.max_entries;
        match state.entries.entry(transaction_id.to_owned()) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                if at_capacity {
                    return Err(IssuerError::new(IssuerStatus::StorageUnavailable));
                }
                entry.insert(DeferredEntry {
                    record,
                    expires_at_unix,
                });
                state
                    .expirations
                    .push(Reverse((expires_at_unix, transaction_id.to_owned())));
                Ok(())
            }
            std::collections::hash_map::Entry::Occupied(_) => {
                Err(IssuerError::new(IssuerStatus::InvalidTransaction))
            }
        }
    }

    fn take(&self, transaction_id: &str, now_unix: u64) -> IssuerResult<DeferredIssuance> {
        if transaction_id.is_empty() {
            return Err(IssuerError::new(IssuerStatus::InvalidTransaction));
        }
        let mut state = self.lock()?;
        state.prune(now_unix);
        state
            .entries
            .remove(transaction_id)
            .map(|entry| entry.record)
            .ok_or_else(|| IssuerError::new(IssuerStatus::InvalidTransaction))
    }
}
