// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Store lifecycle tests for issuer single-use state.

use std::sync::{Arc, Barrier};
use std::thread;

use openid4vci_issuer::{
    ConfirmationJwk, DeferredIssuance, DeferredStore, InMemoryDeferredStore,
    InMemoryNotificationStore, IssuedCredential, IssuerResult, IssuerStatus, NotificationStore,
    PassThroughCredentialEncoder, ProofAlgorithm, ProofKind, VerifiedProof, VerifiedProofSet,
};
use openid4vci_types::{CredentialFormat, CredentialRequest, NotificationEvent, Proofs};
use serde_json::json;

const CONCURRENT_WORKERS: usize = 8;

#[test]
fn notification_store_records_idempotently() -> IssuerResult<()> {
    let store = InMemoryNotificationStore::new();
    store.reserve("notification-1", 10, 100)?;
    store.record("notification-1", NotificationEvent::CredentialAccepted, 10)?;
    assert_eq!(
        store
            .record("notification-1", NotificationEvent::CredentialDeleted, 20)
            .err()
            .map(|error| error.status()),
        Some(IssuerStatus::InvalidNotificationId)
    );
    let record = store.get("notification-1", 20)?;
    assert_eq!(
        record.map(|value| value.event),
        Some(NotificationEvent::CredentialAccepted)
    );
    Ok(())
}

#[test]
fn notification_store_resists_concurrent_overwrite() -> IssuerResult<()> {
    let store = Arc::new(InMemoryNotificationStore::new());
    store.reserve("notification-1", 10, 100)?;
    store.record("notification-1", NotificationEvent::CredentialAccepted, 10)?;
    let barrier = Arc::new(Barrier::new(CONCURRENT_WORKERS));
    let mut workers = Vec::with_capacity(CONCURRENT_WORKERS);
    for offset in 0..CONCURRENT_WORKERS {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            barrier.wait();
            let now_unix = u64::try_from(offset)
                .ok()
                .and_then(|value| value.checked_add(20))
                .unwrap_or(20);
            store
                .record(
                    "notification-1",
                    NotificationEvent::CredentialDeleted,
                    now_unix,
                )
                .is_err()
        }));
    }
    for worker in workers {
        assert!(worker.join().unwrap_or(false));
    }
    let record = store.get("notification-1", 30)?;
    assert_eq!(
        record.map(|value| (value.event, value.recorded_at_unix)),
        Some((NotificationEvent::CredentialAccepted, 10))
    );
    Ok(())
}

#[test]
fn notification_store_rejects_unreserved_identifiers() {
    let store = InMemoryNotificationStore::new();
    let result = store.record(
        "attacker-selected",
        NotificationEvent::CredentialDeleted,
        10,
    );
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidNotificationId)
    );
}

#[test]
fn notification_store_expires_reservations() -> IssuerResult<()> {
    let store = InMemoryNotificationStore::with_max_entries(1)?;
    store.reserve("expired", 10, 20)?;
    assert_eq!(store.get("expired", 20)?, None);
    store.reserve("replacement", 20, 30)?;
    assert_eq!(
        store
            .record("expired", NotificationEvent::CredentialAccepted, 20)
            .err()
            .map(|error| error.status()),
        Some(IssuerStatus::InvalidNotificationId)
    );
    Ok(())
}

#[test]
fn deferred_store_takes_transaction_once() -> IssuerResult<()> {
    let store = InMemoryDeferredStore::new();
    let request = deferred_request();
    let record = DeferredIssuance::new(
        request,
        vec![IssuedCredential::new(
            CredentialFormat::SdJwtVc,
            json!("credential.jwt"),
        )?],
    )?;
    store.put("tx-1", record, 10, 20)?;

    let taken = store.take("tx-1", 10)?;
    assert_eq!(taken.issued.len(), 1);

    let second = store.take("tx-1", 10);
    assert_eq!(
        second.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidTransaction)
    );
    Ok(())
}

#[test]
fn deferred_store_enforces_entry_ceiling() -> IssuerResult<()> {
    let store = InMemoryDeferredStore::with_max_entries(1)?;
    store.put("tx-1", deferred_record()?, 10, 20)?;
    assert_eq!(
        store
            .put("tx-2", deferred_record()?, 10, 20)
            .err()
            .map(|error| error.status()),
        Some(IssuerStatus::StorageUnavailable)
    );
    Ok(())
}

#[test]
fn deferred_store_allows_one_concurrent_take() -> IssuerResult<()> {
    let store = Arc::new(InMemoryDeferredStore::new());
    store.put("tx-1", deferred_record()?, 10, 20)?;
    let barrier = Arc::new(Barrier::new(CONCURRENT_WORKERS));
    let mut workers = Vec::with_capacity(CONCURRENT_WORKERS);
    for _ in 0..CONCURRENT_WORKERS {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            barrier.wait();
            store.take("tx-1", 10).is_ok()
        }));
    }
    let mut successful_takes = 0_u32;
    for worker in workers {
        if worker.join().unwrap_or(false) {
            successful_takes += 1;
        }
    }
    assert_eq!(successful_takes, 1);
    Ok(())
}

#[test]
fn deferred_store_prunes_expired_transactions_before_enforcing_capacity() -> IssuerResult<()> {
    let store = InMemoryDeferredStore::with_max_entries(1)?;
    store.put("expired", deferred_record()?, 10, 20)?;
    store.put("replacement", deferred_record()?, 20, 30)?;

    assert_eq!(
        store.take("expired", 20).err().map(|error| error.status()),
        Some(IssuerStatus::InvalidTransaction)
    );
    assert!(store.take("replacement", 20).is_ok());
    Ok(())
}

#[test]
fn deferred_store_rejects_non_future_expiry() -> IssuerResult<()> {
    let store = InMemoryDeferredStore::new();
    assert_eq!(
        store
            .put("tx-1", deferred_record()?, 20, 20)
            .err()
            .map(|error| error.status()),
        Some(IssuerStatus::InvalidTransaction)
    );
    Ok(())
}

#[test]
fn deferred_record_rejects_empty_issued_credentials() {
    let result = DeferredIssuance::new(deferred_request(), Vec::new());
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidTransaction)
    );
}

#[test]
fn deferred_record_rejects_mismatched_proof_and_credential_counts() -> IssuerResult<()> {
    let issued = vec![IssuedCredential::new(
        CredentialFormat::SdJwtVc,
        json!("credential.jwt"),
    )?];
    let result = DeferredIssuance::new(deferred_request_with_two_proofs(), issued);
    assert_eq!(
        result.err().map(|error| error.status()),
        Some(IssuerStatus::InvalidProof)
    );
    Ok(())
}

#[test]
fn deferred_record_retains_verified_multi_key_count() -> IssuerResult<()> {
    let request = CredentialRequest {
        credential_configuration_id: Some("pid-sd-jwt".to_owned()),
        credential_identifier: None,
        proofs: Some(Proofs {
            jwt: vec!["proof-1.jwt".to_owned(), "proof-2.jwt".to_owned()],
            di_vp: Vec::new(),
            attestation: Vec::new(),
        }),
        credential_response_encryption: None,
    };
    let verified = VerifiedProofSet::new(
        vec![verified_test_proof(1)?, verified_test_proof(2)?],
        Vec::new(),
    )?;
    let issued = vec![
        IssuedCredential::new(CredentialFormat::SdJwtVc, json!("credential-1.jwt"))?,
        IssuedCredential::new(CredentialFormat::SdJwtVc, json!("credential-2.jwt"))?,
    ];
    let record = DeferredIssuance::new_with_verified_proofs(request, issued, Some(&verified))?;
    let response = record.encode_response(
        &PassThroughCredentialEncoder::new(CredentialFormat::SdJwtVc),
        None,
    )?;
    assert_eq!(response.credentials.as_ref().map(Vec::len), Some(2));
    Ok(())
}

fn verified_test_proof(index: u8) -> IssuerResult<VerifiedProof> {
    VerifiedProof::new(
        ProofKind::Jwt,
        Some("nonce-1".to_owned()),
        None,
        None,
        None,
        Some(json!({"kty": "EC", "x": index})),
        Some(ConfirmationJwk {
            algorithm: ProofAlgorithm::Es256,
            public_key: vec![index; 65],
            key_id: None,
        }),
    )
}

fn deferred_request() -> CredentialRequest {
    CredentialRequest {
        credential_configuration_id: Some("pid-sd-jwt".to_owned()),
        credential_identifier: None,
        proofs: Some(Proofs {
            jwt: vec!["proof.jwt".to_owned()],
            di_vp: Vec::new(),
            attestation: Vec::new(),
        }),
        credential_response_encryption: None,
    }
}

fn deferred_record() -> IssuerResult<DeferredIssuance> {
    DeferredIssuance::new(
        deferred_request(),
        vec![IssuedCredential::new(
            CredentialFormat::SdJwtVc,
            json!("credential.jwt"),
        )?],
    )
}

fn deferred_request_with_two_proofs() -> CredentialRequest {
    CredentialRequest {
        credential_configuration_id: Some("pid-sd-jwt".to_owned()),
        credential_identifier: None,
        proofs: Some(Proofs {
            jwt: vec!["proof-1.jwt".to_owned(), "proof-2.jwt".to_owned()],
            di_vp: Vec::new(),
            attestation: Vec::new(),
        }),
        credential_response_encryption: None,
    }
}
