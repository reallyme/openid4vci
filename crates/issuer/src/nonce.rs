// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Authenticated, stateless issuance nonces with bounded replay tracking.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::sync::{Mutex, MutexGuard};

use reallyme_codec::base64url::{base64url_to_bytes, bytes_to_base64url};
use reallyme_crypto::core::RngOutputKind;
use reallyme_crypto::csprng::{generate_bytes, OsSecureRandom};
use reallyme_crypto::hmac::{authenticate, verify, HmacKey, HMAC_SHA256_TAG_LENGTH};
use reallyme_crypto::MacAlgorithm;

use crate::error::{IssuerError, IssuerResult, IssuerStatus};

const NONCE_FORMAT_VERSION: u8 = 1;
const NONCE_IDENTIFIER_LENGTH: usize = 32;
const NONCE_EXPIRY_LENGTH: usize = 8;
const NONCE_PAYLOAD_LENGTH: usize = 1 + NONCE_EXPIRY_LENGTH + NONCE_IDENTIFIER_LENGTH;
const NONCE_TOKEN_LENGTH: usize = NONCE_PAYLOAD_LENGTH + HMAC_SHA256_TAG_LENGTH;
const NONCE_TOKEN_BASE64URL_LENGTH: usize = 98;
const DEFAULT_MAX_CONSUMED_NONCES: usize = 65_536;
const DEFAULT_MAX_CONSUMPTIONS_PER_PARTITION: usize = 2_048;
const DEFAULT_MAX_RATE_LIMIT_PARTITIONS: usize = 4_096;
/// Longest nonce lifetime accepted by the built-in manager.
pub const MAX_NONCE_TTL_SECONDS: u64 = 600;

/// Issues and atomically consumes server-authenticated credential nonces.
///
/// Implementations used by an unauthenticated Nonce Endpoint must not allocate
/// persistent per-nonce state during [`NonceManager::issue`]. Consumption must
/// authenticate the nonce before allocating replay state and must atomically
/// reject reuse across all replicas serving the same issuer.
pub trait NonceManager: Send + Sync {
    /// Issues a fresh nonce that expires after `ttl_seconds`.
    fn issue(&self, now_unix: u64, ttl_seconds: u64) -> IssuerResult<String>;

    /// Authenticates and consumes a nonce exactly once before its expiry.
    fn consume(
        &self,
        nonce: &str,
        rate_limit_partition: &[u8; 32],
        now_unix: u64,
    ) -> IssuerResult<()>;
}

/// Non-secret capacity telemetry for the in-process replay manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonceCapacitySnapshot {
    /// Unexpired nonce identifiers currently retained for replay prevention.
    pub consumed_nonces: usize,
    /// Configured maximum number of unexpired consumed nonces.
    pub consumed_nonce_limit: usize,
    /// Active authorization partitions tracked for admission control.
    pub active_rate_limit_partitions: usize,
    /// Configured maximum number of rate-limit partitions.
    pub rate_limit_partition_limit: usize,
}

/// Stateless nonce issuer with bounded, in-process replay tracking.
///
/// Issuing a nonce does not allocate replay state. Only a successfully
/// authenticated nonce is retained, which prevents unauthenticated callers
/// from exhausting the replay store through the public Nonce Endpoint.
/// Deployments with more than one issuer replica must provide a shared
/// [`NonceManager`] implementation so consumption remains atomic cluster-wide.
pub struct AuthenticatedNonceManager {
    authentication_key: HmacKey,
    state: Mutex<NonceState>,
    max_consumed_nonces: usize,
    max_consumptions_per_partition: usize,
    max_rate_limit_partitions: usize,
}

#[derive(Default)]
struct NonceState {
    replay: ReplayState,
    rate_limits: HashMap<[u8; 32], PartitionRateState>,
}

#[derive(Default)]
struct ReplayState {
    consumed: HashMap<[u8; NONCE_IDENTIFIER_LENGTH], u64>,
    expirations: BinaryHeap<Reverse<(u64, [u8; NONCE_IDENTIFIER_LENGTH])>>,
}

#[derive(Clone, Copy)]
struct PartitionRateState {
    consumed: usize,
    expires_at_unix: u64,
}

struct VerifiedNonce {
    identifier: [u8; NONCE_IDENTIFIER_LENGTH],
    expires_at_unix: u64,
}

impl AuthenticatedNonceManager {
    /// Creates a manager using caller-owned key material and the default cap.
    pub fn new(authentication_key: HmacKey) -> Self {
        Self {
            authentication_key,
            state: Mutex::new(NonceState::default()),
            max_consumed_nonces: DEFAULT_MAX_CONSUMED_NONCES,
            max_consumptions_per_partition: DEFAULT_MAX_CONSUMPTIONS_PER_PARTITION,
            max_rate_limit_partitions: DEFAULT_MAX_RATE_LIMIT_PARTITIONS,
        }
    }

    /// Creates a manager with an explicit cap for unexpired consumed nonces.
    pub fn with_max_consumed_nonces(
        authentication_key: HmacKey,
        max_consumed_nonces: usize,
    ) -> IssuerResult<Self> {
        if max_consumed_nonces == 0 {
            return Err(IssuerError::new(IssuerStatus::StorageUnavailable));
        }
        Ok(Self {
            authentication_key,
            state: Mutex::new(NonceState::default()),
            max_consumed_nonces,
            max_consumptions_per_partition: DEFAULT_MAX_CONSUMPTIONS_PER_PARTITION,
            max_rate_limit_partitions: DEFAULT_MAX_RATE_LIMIT_PARTITIONS,
        })
    }

    /// Creates a manager with explicit replay and per-partition rate limits.
    ///
    /// The replay limit is global because a nonce is globally single-use. The
    /// per-partition limit protects that shared capacity from one authorized
    /// client. A partition should identify the stable authorization grant or
    /// subject, not an individual access-token value that changes on refresh.
    /// Multi-tenant deployments must size both limits for their authorized
    /// population or provide a shared external implementation; no bounded
    /// process-local replay set can resist coordinated exhaustion by an
    /// unbounded number of independently authorized partitions.
    pub fn with_limits(
        authentication_key: HmacKey,
        max_consumed_nonces: usize,
        max_consumptions_per_partition: usize,
        max_rate_limit_partitions: usize,
    ) -> IssuerResult<Self> {
        if max_consumed_nonces == 0
            || max_consumptions_per_partition == 0
            || max_rate_limit_partitions == 0
        {
            return Err(IssuerError::new(IssuerStatus::StorageUnavailable));
        }
        Ok(Self {
            authentication_key,
            state: Mutex::new(NonceState::default()),
            max_consumed_nonces,
            max_consumptions_per_partition,
            max_rate_limit_partitions,
        })
    }

    /// Generates a process-local authentication key with the operating-system
    /// CSPRNG. Outstanding nonces become invalid after process restart; callers
    /// that require restart continuity should inject a stable secret key.
    pub fn with_generated_key() -> IssuerResult<Self> {
        let mut random = OsSecureRandom;
        let key = generate_bytes::<NONCE_IDENTIFIER_LENGTH>(&mut random, RngOutputKind::Generic)
            .map_err(|_| IssuerError::new(IssuerStatus::StorageUnavailable))?;
        let authentication_key = HmacKey::from_slice(key.as_bytes())
            .map_err(|_| IssuerError::new(IssuerStatus::StorageUnavailable))?;
        Ok(Self::new(authentication_key))
    }

    /// Returns current replay/admission capacity after pruning expired state.
    ///
    /// The snapshot intentionally exposes counts only. It does not expose
    /// nonce identifiers, authorization partitions, or expiration timestamps.
    pub fn capacity_snapshot(&self, now_unix: u64) -> IssuerResult<NonceCapacitySnapshot> {
        let mut state = self.lock_state()?;
        prune_replay_state(&mut state.replay, now_unix);
        state
            .rate_limits
            .retain(|_, rate| rate.expires_at_unix > now_unix);
        Ok(NonceCapacitySnapshot {
            consumed_nonces: state.replay.consumed.len(),
            consumed_nonce_limit: self.max_consumed_nonces,
            active_rate_limit_partitions: state.rate_limits.len(),
            rate_limit_partition_limit: self.max_rate_limit_partitions,
        })
    }

    fn lock_state(&self) -> IssuerResult<MutexGuard<'_, NonceState>> {
        self.state
            .lock()
            .map_err(|_| IssuerError::new(IssuerStatus::StorageUnavailable))
    }

    fn verify_nonce(&self, nonce: &str) -> IssuerResult<VerifiedNonce> {
        // Reject oversized input before decoding so attacker-controlled text
        // cannot force an allocation larger than the fixed wire token.
        if nonce.len() != NONCE_TOKEN_BASE64URL_LENGTH {
            return Err(IssuerError::new(IssuerStatus::InvalidNonce));
        }
        let token =
            base64url_to_bytes(nonce).map_err(|_| IssuerError::new(IssuerStatus::InvalidNonce))?;
        if token.len() != NONCE_TOKEN_LENGTH || bytes_to_base64url(&token) != nonce {
            return Err(IssuerError::new(IssuerStatus::InvalidNonce));
        }

        let (payload, tag) = token.split_at(NONCE_PAYLOAD_LENGTH);
        verify(
            MacAlgorithm::HmacSha256,
            &self.authentication_key,
            payload,
            tag,
        )
        .map_err(|_| IssuerError::new(IssuerStatus::InvalidNonce))?;
        if payload.first().copied() != Some(NONCE_FORMAT_VERSION) {
            return Err(IssuerError::new(IssuerStatus::InvalidNonce));
        }

        let mut expiry_bytes = [0_u8; NONCE_EXPIRY_LENGTH];
        expiry_bytes.copy_from_slice(&payload[1..1 + NONCE_EXPIRY_LENGTH]);
        let expires_at_unix = u64::from_be_bytes(expiry_bytes);

        let mut identifier = [0_u8; NONCE_IDENTIFIER_LENGTH];
        identifier.copy_from_slice(&payload[1 + NONCE_EXPIRY_LENGTH..NONCE_PAYLOAD_LENGTH]);
        Ok(VerifiedNonce {
            identifier,
            expires_at_unix,
        })
    }
}

impl NonceManager for AuthenticatedNonceManager {
    fn issue(&self, now_unix: u64, ttl_seconds: u64) -> IssuerResult<String> {
        if ttl_seconds == 0 || ttl_seconds > MAX_NONCE_TTL_SECONDS {
            return Err(IssuerError::new(IssuerStatus::InvalidRequest));
        }
        let expires_at_unix = now_unix
            .checked_add(ttl_seconds)
            .ok_or_else(|| IssuerError::new(IssuerStatus::InvalidRequest))?;
        let mut random = OsSecureRandom;
        let identifier =
            generate_bytes::<NONCE_IDENTIFIER_LENGTH>(&mut random, RngOutputKind::Generic)
                .map_err(|_| IssuerError::new(IssuerStatus::StorageUnavailable))?;

        let mut payload = [0_u8; NONCE_PAYLOAD_LENGTH];
        payload[0] = NONCE_FORMAT_VERSION;
        payload[1..1 + NONCE_EXPIRY_LENGTH].copy_from_slice(&expires_at_unix.to_be_bytes());
        payload[1 + NONCE_EXPIRY_LENGTH..].copy_from_slice(identifier.as_bytes());
        let tag = authenticate(MacAlgorithm::HmacSha256, &self.authentication_key, &payload)
            .map_err(|_| IssuerError::new(IssuerStatus::StorageUnavailable))?;

        let mut token = Vec::with_capacity(NONCE_TOKEN_LENGTH);
        token.extend_from_slice(&payload);
        token.extend_from_slice(tag.as_bytes());
        Ok(bytes_to_base64url(&token))
    }

    fn consume(
        &self,
        nonce: &str,
        rate_limit_partition: &[u8; 32],
        now_unix: u64,
    ) -> IssuerResult<()> {
        let verified = self.verify_nonce(nonce)?;
        if verified.expires_at_unix <= now_unix {
            return Err(IssuerError::new(IssuerStatus::InvalidNonce));
        }

        let mut state = self.lock_state()?;
        prune_replay_state(&mut state.replay, now_unix);
        if state.replay.consumed.contains_key(&verified.identifier) {
            return Err(IssuerError::new(IssuerStatus::InvalidNonce));
        }
        if state.replay.consumed.len() >= self.max_consumed_nonces {
            return Err(IssuerError::new(IssuerStatus::StorageUnavailable));
        }

        state
            .rate_limits
            .retain(|_, rate| rate.expires_at_unix > now_unix);
        if !state.rate_limits.contains_key(rate_limit_partition)
            && state.rate_limits.len() >= self.max_rate_limit_partitions
        {
            evict_oldest_rate_limit(&mut state.rate_limits);
        }
        let rate = state
            .rate_limits
            .entry(*rate_limit_partition)
            .or_insert(PartitionRateState {
                consumed: 0,
                expires_at_unix: verified.expires_at_unix,
            });
        if rate.consumed >= self.max_consumptions_per_partition {
            return Err(IssuerError::new(IssuerStatus::StorageUnavailable));
        }
        rate.consumed = rate
            .consumed
            .checked_add(1)
            .ok_or_else(|| IssuerError::new(IssuerStatus::StorageUnavailable))?;
        rate.expires_at_unix = rate.expires_at_unix.max(verified.expires_at_unix);

        state
            .replay
            .consumed
            .insert(verified.identifier, verified.expires_at_unix);
        state
            .replay
            .expirations
            .push(Reverse((verified.expires_at_unix, verified.identifier)));
        Ok(())
    }
}

fn evict_oldest_rate_limit(rate_limits: &mut HashMap<[u8; 32], PartitionRateState>) {
    let oldest = rate_limits
        .iter()
        .min_by_key(|(partition, rate)| (rate.expires_at_unix, **partition))
        .map(|(partition, _)| *partition);
    if let Some(partition) = oldest {
        rate_limits.remove(&partition);
    }
}

fn prune_replay_state(replay: &mut ReplayState, now_unix: u64) {
    while let Some(Reverse((expires_at_unix, identifier))) = replay.expirations.peek().copied() {
        if expires_at_unix > now_unix {
            break;
        }
        replay.expirations.pop();
        if replay.consumed.get(&identifier).copied() == Some(expires_at_unix) {
            replay.consumed.remove(&identifier);
        }
    }
}
