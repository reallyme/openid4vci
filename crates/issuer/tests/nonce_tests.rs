// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Authenticated nonce issuance and replay-resistance tests.

use openid4vci_issuer::{
    AuthenticatedNonceManager, IssuerError, IssuerResult, IssuerStatus, NonceManager,
};
use reallyme_codec::base64url::{base64url_to_bytes, bytes_to_base64url};
use reallyme_crypto::hmac::HmacKey;

const TEST_KEY: [u8; 32] = [0x5a; 32];
const TEST_PARTITION: [u8; 32] = [0x6b; 32];

fn manager(max_consumed_nonces: usize) -> IssuerResult<AuthenticatedNonceManager> {
    let key = HmacKey::from_slice(&TEST_KEY)
        .map_err(|_| IssuerError::new(IssuerStatus::StorageUnavailable))?;
    AuthenticatedNonceManager::with_max_consumed_nonces(key, max_consumed_nonces)
}

fn manager_with_limits(
    max_consumed_nonces: usize,
    max_consumptions_per_partition: usize,
    max_rate_limit_partitions: usize,
) -> IssuerResult<AuthenticatedNonceManager> {
    let key = HmacKey::from_slice(&TEST_KEY)
        .map_err(|_| IssuerError::new(IssuerStatus::StorageUnavailable))?;
    AuthenticatedNonceManager::with_limits(
        key,
        max_consumed_nonces,
        max_consumptions_per_partition,
        max_rate_limit_partitions,
    )
}

#[test]
fn issued_nonce_is_accepted_once_before_expiry() -> IssuerResult<()> {
    let manager = manager(8)?;
    let nonce = manager.issue(100, 30)?;

    manager.consume(&nonce, &TEST_PARTITION, 129)?;
    assert_eq!(
        manager
            .consume(&nonce, &TEST_PARTITION, 129)
            .err()
            .map(|error| error.status()),
        Some(IssuerStatus::InvalidNonce)
    );
    Ok(())
}

#[test]
fn expired_nonce_is_rejected() -> IssuerResult<()> {
    let manager = manager(8)?;
    let nonce = manager.issue(100, 30)?;

    assert_eq!(
        manager
            .consume(&nonce, &TEST_PARTITION, 130)
            .err()
            .map(|error| error.status()),
        Some(IssuerStatus::InvalidNonce)
    );
    Ok(())
}

#[test]
fn tampered_nonce_is_rejected() -> IssuerResult<()> {
    let manager = manager(8)?;
    let nonce = manager.issue(100, 30)?;
    let mut bytes =
        base64url_to_bytes(&nonce).map_err(|_| IssuerError::new(IssuerStatus::EncodingFailed))?;
    let first = bytes
        .first_mut()
        .ok_or_else(|| IssuerError::new(IssuerStatus::EncodingFailed))?;
    *first ^= 1;
    let tampered = bytes_to_base64url(&bytes);

    assert_eq!(
        manager
            .consume(&tampered, &TEST_PARTITION, 110)
            .err()
            .map(|error| error.status()),
        Some(IssuerStatus::InvalidNonce)
    );
    Ok(())
}

#[test]
fn malformed_and_oversized_nonces_are_rejected() -> IssuerResult<()> {
    let manager = manager(8)?;
    for malformed in ["", "%%%", &"a".repeat(16_384)] {
        assert_eq!(
            manager
                .consume(malformed, &TEST_PARTITION, 110)
                .err()
                .map(|error| error.status()),
            Some(IssuerStatus::InvalidNonce)
        );
    }
    Ok(())
}

#[test]
fn expired_replay_entries_are_pruned_before_capacity_check() -> IssuerResult<()> {
    let manager = manager(1)?;
    let first = manager.issue(100, 5)?;
    let second = manager.issue(101, 20)?;

    manager.consume(&first, &TEST_PARTITION, 101)?;
    assert_eq!(manager.capacity_snapshot(101)?.consumed_nonces, 1);
    manager.consume(&second, &TEST_PARTITION, 105)?;
    let snapshot = manager.capacity_snapshot(105)?;
    assert_eq!(snapshot.consumed_nonces, 1);
    assert_eq!(snapshot.consumed_nonce_limit, 1);
    Ok(())
}

#[test]
fn valid_consumption_fails_closed_when_replay_capacity_is_full() -> IssuerResult<()> {
    let manager = manager(1)?;
    let first = manager.issue(100, 20)?;
    let second = manager.issue(101, 20)?;

    manager.consume(&first, &TEST_PARTITION, 102)?;
    assert_eq!(
        manager
            .consume(&second, &TEST_PARTITION, 102)
            .err()
            .map(|error| error.status()),
        Some(IssuerStatus::StorageUnavailable)
    );
    let full = manager.capacity_snapshot(102)?;
    assert_eq!(full.consumed_nonces, full.consumed_nonce_limit);
    let recovered = manager.capacity_snapshot(120)?;
    assert_eq!(recovered.consumed_nonces, 0);
    Ok(())
}

#[test]
fn one_partition_cannot_exhaust_another_partition_rate_limit() -> IssuerResult<()> {
    let manager = manager_with_limits(8, 1, 8)?;
    let attacker_first = manager.issue(100, 20)?;
    let attacker_second = manager.issue(101, 20)?;
    let legitimate = manager.issue(102, 20)?;
    let legitimate_partition = [0x7c; 32];

    manager.consume(&attacker_first, &TEST_PARTITION, 103)?;
    assert_eq!(
        manager
            .consume(&attacker_second, &TEST_PARTITION, 103)
            .err()
            .map(|error| error.status()),
        Some(IssuerStatus::StorageUnavailable)
    );
    manager.consume(&legitimate, &legitimate_partition, 103)?;
    Ok(())
}

#[test]
fn nonce_reuse_is_rejected_across_partitions() -> IssuerResult<()> {
    let manager = manager_with_limits(8, 8, 8)?;
    let nonce = manager.issue(100, 20)?;
    let other_partition = [0x7c; 32];

    manager.consume(&nonce, &TEST_PARTITION, 101)?;
    assert_eq!(
        manager
            .consume(&nonce, &other_partition, 101)
            .err()
            .map(|error| error.status()),
        Some(IssuerStatus::InvalidNonce)
    );
    Ok(())
}

#[test]
fn rate_partition_capacity_cannot_lock_out_new_clients() -> IssuerResult<()> {
    let manager = manager_with_limits(64, 4, 2)?;
    for partition_number in 0_u8..40 {
        let nonce = manager.issue(100, 20)?;
        let partition = [partition_number; 32];
        manager.consume(&nonce, &partition, 101)?;
    }
    Ok(())
}
