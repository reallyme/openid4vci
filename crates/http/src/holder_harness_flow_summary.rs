// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Serialized terminal outcomes for the OIDF wallet control plane.

use serde::Serialize;

use crate::{
    HolderHarnessFlowOutcome, HolderHarnessFlowStatus, HolderHarnessProtocolRejectionReason,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct HolderHarnessHealthSummary {
    pub(crate) status: &'static str,
    pub(crate) service: &'static str,
    pub(crate) composed_flow_driver_enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct HolderHarnessFlowSummary {
    status: FlowStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<FlowRejectionReason>,
}

impl HolderHarnessFlowSummary {
    pub(crate) fn from_outcome(outcome: HolderHarnessFlowOutcome) -> Self {
        let (status, reason) = match outcome.status() {
            HolderHarnessFlowStatus::CredentialStored => (FlowStatus::CredentialStored, None),
            HolderHarnessFlowStatus::DeferredCredentialPending => {
                (FlowStatus::DeferredCredentialPending, None)
            }
            HolderHarnessFlowStatus::ProtocolRejected => (
                FlowStatus::ProtocolRejected,
                outcome.rejection_reason().map(FlowRejectionReason::from),
            ),
        };
        Self { status, reason }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum FlowStatus {
    CredentialStored,
    DeferredCredentialPending,
    ProtocolRejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum FlowRejectionReason {
    IssuerMetadataIssuerMismatch,
    AuthorizationServerIssuerMismatch,
    AuthorizationIssuerMismatch,
    AuthorizationIssuerMissing,
    AuthorizationStateMismatch,
    AuthorizationStateMissing,
}

impl From<HolderHarnessProtocolRejectionReason> for FlowRejectionReason {
    fn from(reason: HolderHarnessProtocolRejectionReason) -> Self {
        match reason {
            HolderHarnessProtocolRejectionReason::IssuerMetadataIssuerMismatch => {
                Self::IssuerMetadataIssuerMismatch
            }
            HolderHarnessProtocolRejectionReason::AuthorizationServerIssuerMismatch => {
                Self::AuthorizationServerIssuerMismatch
            }
            HolderHarnessProtocolRejectionReason::AuthorizationIssuerMismatch => {
                Self::AuthorizationIssuerMismatch
            }
            HolderHarnessProtocolRejectionReason::AuthorizationIssuerMissing => {
                Self::AuthorizationIssuerMissing
            }
            HolderHarnessProtocolRejectionReason::AuthorizationStateMismatch => {
                Self::AuthorizationStateMismatch
            }
            HolderHarnessProtocolRejectionReason::AuthorizationStateMissing => {
                Self::AuthorizationStateMissing
            }
        }
    }
}
