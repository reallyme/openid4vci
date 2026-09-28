// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared nonce-manager test double.

use std::sync::Mutex;

use openid4vci_issuer::{IssuerError, IssuerResult, IssuerStatus, NonceManager};

pub(crate) struct TestNonceManager {
    nonce: &'static str,
    expires_at_unix: Mutex<Option<u64>>,
}

impl TestNonceManager {
    #[allow(dead_code)]
    pub(crate) fn empty() -> Self {
        Self {
            nonce: "nonce-1",
            expires_at_unix: Mutex::new(None),
        }
    }

    // Each integration test compiles this shared module as a separate crate;
    // state-machine tests issue through the trait and do not pre-seed it.
    #[allow(dead_code)]
    pub(crate) fn seeded(nonce: &'static str, expires_at_unix: u64) -> Self {
        Self {
            nonce,
            expires_at_unix: Mutex::new(Some(expires_at_unix)),
        }
    }
}

impl NonceManager for TestNonceManager {
    fn issue(&self, now_unix: u64, ttl_seconds: u64) -> IssuerResult<String> {
        let expires_at_unix = now_unix
            .checked_add(ttl_seconds)
            .ok_or_else(|| IssuerError::new(IssuerStatus::InvalidRequest))?;
        let mut stored = self
            .expires_at_unix
            .lock()
            .map_err(|_| IssuerError::new(IssuerStatus::StorageUnavailable))?;
        *stored = Some(expires_at_unix);
        Ok(self.nonce.to_owned())
    }

    fn consume(
        &self,
        nonce: &str,
        _replay_partition: &[u8; 32],
        now_unix: u64,
    ) -> IssuerResult<()> {
        let mut stored = self
            .expires_at_unix
            .lock()
            .map_err(|_| IssuerError::new(IssuerStatus::StorageUnavailable))?;
        match *stored {
            Some(expires_at_unix) if nonce == self.nonce && expires_at_unix > now_unix => {
                *stored = None;
                Ok(())
            }
            _ => Err(IssuerError::new(IssuerStatus::InvalidNonce)),
        }
    }
}
