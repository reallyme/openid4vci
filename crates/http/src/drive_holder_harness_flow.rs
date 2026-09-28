// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Flow-driver boundary for the OIDF OpenID4VCI holder harness.
//!
//! OpenID4VCI owns the conformance HTTP launch endpoint, but the complete wallet
//! execution path belongs above this crate in wallet-core and identity.
//! This trait is the narrow adapter seam: the HTTP harness validates the launch
//! shape and delegates issuance sequencing to an injected driver.

use core::fmt;

use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

const MAX_IDEMPOTENCY_KEY_BYTES: usize = 128;

/// Launch request passed from the OpenID4VCI holder harness to a composed wallet driver.
#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct HolderHarnessFlowRequest {
    credential_offer_launch_uri: String,
    idempotency_key: String,
}

impl fmt::Debug for HolderHarnessFlowRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HolderHarnessFlowRequest")
            .field(
                "credential_offer_launch_uri_bytes",
                &self.credential_offer_launch_uri.len(),
            )
            .field("idempotency_key", &"<redacted>")
            .finish()
    }
}

impl HolderHarnessFlowRequest {
    /// Create a holder harness flow request for external adapter tests and custom drivers.
    pub fn new(
        credential_offer_launch_uri: String,
        idempotency_key: String,
    ) -> Result<Self, HolderHarnessFlowError> {
        if credential_offer_launch_uri.is_empty()
            || idempotency_key.is_empty()
            || idempotency_key.len() > MAX_IDEMPOTENCY_KEY_BYTES
            || !idempotency_key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(HolderHarnessFlowError::new(
                HolderHarnessFlowErrorReason::LaunchRejected,
            ));
        }
        Ok(Self {
            credential_offer_launch_uri,
            idempotency_key,
        })
    }

    #[cfg(feature = "axum-holder-harness")]
    pub(crate) fn from_validated_launch(
        credential_offer_launch_uri: String,
        idempotency_key: String,
    ) -> Self {
        Self {
            credential_offer_launch_uri,
            idempotency_key,
        }
    }

    /// Borrow the original OpenID4VCI Credential Offer launch URI.
    #[must_use]
    pub fn credential_offer_launch_uri(&self) -> &str {
        self.credential_offer_launch_uri.as_str()
    }

    /// Borrow the caller-generated key for this exact issuance attempt.
    #[must_use]
    pub fn idempotency_key(&self) -> &str {
        self.idempotency_key.as_str()
    }
}

/// Terminal outcome returned by a composed holder harness flow driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HolderHarnessFlowOutcome {
    status: HolderHarnessFlowStatus,
    rejection_reason: Option<HolderHarnessProtocolRejectionReason>,
}

impl HolderHarnessFlowOutcome {
    /// Construct an outcome for an immediate credential that reached wallet storage.
    #[must_use]
    pub const fn credential_stored() -> Self {
        Self {
            status: HolderHarnessFlowStatus::CredentialStored,
            rejection_reason: None,
        }
    }

    /// Construct an outcome for an accepted deferred credential transaction.
    #[must_use]
    pub const fn deferred_credential_pending() -> Self {
        Self {
            status: HolderHarnessFlowStatus::DeferredCredentialPending,
            rejection_reason: None,
        }
    }

    /// Construct an outcome for a security test rejected for the exact expected reason.
    #[must_use]
    pub const fn protocol_rejected(reason: HolderHarnessProtocolRejectionReason) -> Self {
        Self {
            status: HolderHarnessFlowStatus::ProtocolRejected,
            rejection_reason: Some(reason),
        }
    }

    /// Stable terminal status.
    #[must_use]
    pub const fn status(self) -> HolderHarnessFlowStatus {
        self.status
    }

    /// Return the stable reason for a protocol rejection, when present.
    #[must_use]
    pub const fn rejection_reason(self) -> Option<HolderHarnessProtocolRejectionReason> {
        self.rejection_reason
    }
}

/// Stable holder harness flow status values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HolderHarnessFlowStatus {
    /// The composed wallet driver imported an immediate credential.
    CredentialStored,
    /// The issuer returned a deferred transaction and the wallet can poll later.
    DeferredCredentialPending,
    /// The wallet correctly rejected a deliberately invalid protocol response.
    ProtocolRejected,
}

/// Stable reasons for expected negative conformance outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HolderHarnessProtocolRejectionReason {
    /// Credential Issuer Metadata did not name the issuer that was requested.
    IssuerMetadataIssuerMismatch,
    /// Authorization Server Metadata did not name the issuer that was requested.
    AuthorizationServerIssuerMismatch,
    /// The RFC 9207 authorization-response issuer did not match.
    AuthorizationIssuerMismatch,
    /// The RFC 9207 authorization-response issuer was absent.
    AuthorizationIssuerMissing,
    /// The OAuth authorization-response state did not match.
    AuthorizationStateMismatch,
    /// The OAuth authorization-response state was absent.
    AuthorizationStateMissing,
}

/// Trait implemented by composed wallet drivers outside OpenID4VCI.
pub trait HolderHarnessFlowDriver: Send + Sync {
    /// Drive the validated Credential Offer launch through the composed wallet stack.
    fn drive_offer_launch(
        &self,
        request: &HolderHarnessFlowRequest,
    ) -> Result<HolderHarnessFlowOutcome, HolderHarnessFlowError>;
}

/// Typed holder harness flow-driver error.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("holder harness flow failed: {reason}")]
pub struct HolderHarnessFlowError {
    reason: HolderHarnessFlowErrorReason,
}

impl HolderHarnessFlowError {
    /// Construct a flow-driver error from a stable reason.
    #[must_use]
    pub const fn new(reason: HolderHarnessFlowErrorReason) -> Self {
        Self { reason }
    }

    /// Stable non-sensitive reason code.
    #[must_use]
    pub const fn reason(self) -> HolderHarnessFlowErrorReason {
        self.reason
    }
}

/// Stable holder harness flow-driver failure reasons.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum HolderHarnessFlowErrorReason {
    /// The composed wallet driver rejected the already-validated launch.
    #[error("launch_rejected")]
    LaunchRejected,
    /// Wallet attestation or client authentication was unavailable.
    #[error("wallet_attestation_unavailable")]
    WalletAttestationUnavailable,
    /// Token exchange failed.
    #[error("token_exchange_failed")]
    TokenExchangeFailed,
    /// Credential request construction or submission failed.
    #[error("credential_request_failed")]
    CredentialRequestFailed,
    /// Issuer response could not be stored or resumed.
    #[error("credential_storage_failed")]
    CredentialStorageFailed,
}
