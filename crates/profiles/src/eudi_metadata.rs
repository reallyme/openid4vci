// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! ETSI TS 119 472-3 Credential Issuer Metadata extensions.
//!
//! OpenID4VCI deliberately leaves `credential_metadata` extensible. This
//! module owns the EUDI profile interpretation of `credential_reuse_policy`
//! so the protocol wire model can remain forward compatible.

use core::fmt;

use serde_json::{Map, Value};

const REUSE_POLICY_MEMBER: &str = "credential_reuse_policy";
const ARF_ANNEX_II_POLICY_ID: &str = "arf_annex_ii";

/// Reuse method defined by ETSI TS 119 472-3 clause 4.2.4.2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReuseMethod {
    /// Each credential instance is presented once.
    OnceOnly,
    /// Credential reuse is bounded by remaining lifetime.
    LimitedTime,
    /// A wallet rotates through a credential batch.
    RotatingBatch,
    /// A wallet uses a stable credential instance per relying party.
    PerRelyingParty,
}

/// A wallet's supported credential reuse methods.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReuseMethodSet(u8);

impl ReuseMethodSet {
    const ALL: u8 =
        Self::ONCE_ONLY | Self::LIMITED_TIME | Self::ROTATING_BATCH | Self::PER_RELYING_PARTY;

    /// Once-only credential instances.
    pub const ONCE_ONLY: u8 = 1 << 0;
    /// Reuse bounded by credential lifetime.
    pub const LIMITED_TIME: u8 = 1 << 1;
    /// Rotation through a credential batch.
    pub const ROTATING_BATCH: u8 = 1 << 2;
    /// Stable credential instances scoped to a relying party.
    pub const PER_RELYING_PARTY: u8 = 1 << 3;

    /// Constructs a capability set, rejecting unknown bits.
    pub const fn new(mask: u8) -> Result<Self, ReusePolicyError> {
        if mask & !Self::ALL == 0 {
            Ok(Self(mask))
        } else {
            Err(ReusePolicyError::new(
                ReusePolicyErrorReason::UnknownCapability,
            ))
        }
    }

    const fn contains(self, method: ReuseMethod) -> bool {
        let bit = match method {
            ReuseMethod::OnceOnly => Self::ONCE_ONLY,
            ReuseMethod::LimitedTime => Self::LIMITED_TIME,
            ReuseMethod::RotatingBatch => Self::ROTATING_BATCH,
            ReuseMethod::PerRelyingParty => Self::PER_RELYING_PARTY,
        };
        self.0 & bit == bit
    }
}

/// One object in the ordered ARF Annex II `options` array.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReusePolicyOption {
    /// Methods in issuer preference order.
    pub details: Vec<ReuseMethod>,
    /// Maximum number of proofs in a Credential Request.
    pub batch_size: Option<u32>,
    /// Remaining unused credentials that trigger reissuance.
    pub reissue_trigger_unused: Option<u32>,
    /// Seconds before expiry that trigger reissuance.
    pub reissue_trigger_lifetime_left_seconds: Option<u64>,
}

/// One issuer-preferred reuse policy selected for wallet enforcement.
///
/// The selected option retains every threshold that controls issuance and
/// reissuance. Returning only the method would force resumable wallet flows to
/// reconstruct security policy from metadata after the interaction starts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectedCredentialReusePolicy {
    /// No ETSI reuse restriction was advertised.
    Unrestricted,
    /// One method selected from an ARF Annex II option.
    ArfAnnexIi {
        /// Selected reuse method.
        method: ReuseMethod,
        /// Credential batch size when required by the selected method.
        batch_size: Option<u32>,
        /// Remaining unused credentials that trigger reissuance.
        reissue_trigger_unused: Option<u32>,
        /// Seconds before expiry that trigger reissuance.
        reissue_trigger_lifetime_left_seconds: Option<u64>,
    },
}

/// Effective credential reuse policy for one credential configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CredentialReusePolicy {
    /// The parameter is absent, which ETSI defines as unrestricted reuse.
    Unrestricted,
    /// The parameter is present with a policy identifier this version does not implement.
    Unsupported,
    /// The ARF Annex II policy, preserving option and method ordering.
    ArfAnnexIi {
        /// Ordered policy options from issuer metadata.
        options: Vec<ReusePolicyOption>,
    },
}

impl CredentialReusePolicy {
    /// Selects the first issuer-preferred method supported by the wallet.
    ///
    /// ETSI makes method order significant. Options and their `details`
    /// arrays are therefore traversed in document order without sorting.
    #[must_use]
    pub fn select_first_supported(&self, supported: ReuseMethodSet) -> Option<ReuseMethod> {
        self.select_first_supported_policy(supported)
            .and_then(|selected| match selected {
                SelectedCredentialReusePolicy::Unrestricted => None,
                SelectedCredentialReusePolicy::ArfAnnexIi { method, .. } => Some(method),
            })
    }

    /// Selects and retains the first complete issuer-preferred policy option.
    ///
    /// An unsupported policy identifier or an ARF Annex II policy with no
    /// locally supported method returns `None`. Unrestricted metadata returns
    /// an explicit value so callers can distinguish it from unsupported input.
    #[must_use]
    pub fn select_first_supported_policy(
        &self,
        supported: ReuseMethodSet,
    ) -> Option<SelectedCredentialReusePolicy> {
        if matches!(self, Self::Unrestricted) {
            return Some(SelectedCredentialReusePolicy::Unrestricted);
        }
        let Self::ArfAnnexIi { options } = self else {
            return None;
        };
        options.iter().find_map(|option| {
            option
                .details
                .iter()
                .copied()
                .find(|method| supported.contains(*method))
                .map(|method| SelectedCredentialReusePolicy::ArfAnnexIi {
                    method,
                    batch_size: option.batch_size,
                    reissue_trigger_unused: option.reissue_trigger_unused,
                    reissue_trigger_lifetime_left_seconds: option
                        .reissue_trigger_lifetime_left_seconds,
                })
        })
    }

    /// Returns whether OpenID4VCI `batch_credential_issuance` must be ignored.
    ///
    /// ETSI applies this precedence whenever `credential_reuse_policy` is
    /// present, including when its identifier is unsupported locally.
    #[must_use]
    pub const fn ignores_openid_batch_metadata(&self) -> bool {
        !matches!(self, Self::Unrestricted)
    }
}

/// Stable reason for rejecting EUDI reuse-policy metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReusePolicyErrorReason {
    /// The surrounding `credential_metadata` value is not an object.
    CredentialMetadataNotObject,
    /// `credential_reuse_policy` is not an object.
    PolicyNotObject,
    /// The required `id` member is absent or is not a non-empty string.
    InvalidPolicyIdentifier,
    /// ARF Annex II requires a non-empty `options` array.
    InvalidOptions,
    /// An option is not a JSON object.
    OptionNotObject,
    /// An option's `details` member is absent, malformed, or empty.
    InvalidDetails,
    /// A `details` entry is outside the closed ETSI method set.
    UnsupportedMethod,
    /// The policy does not contain exactly one base method family.
    InvalidBaseMethodCombination,
    /// A numeric member is not a non-negative integer in the supported range.
    InvalidNumericMember,
    /// A method that uses batching lacks a valid batch size of at least two.
    BatchSizeRequired,
    /// `once_only` lacks a valid unused-credential reissuance threshold.
    ReissueTriggerUnusedRequired,
    /// A time-bounded method lacks its lifetime-left reissuance threshold.
    ReissueTriggerLifetimeLeftRequired,
    /// A wallet capability mask contains an undefined bit.
    UnknownCapability,
}

impl fmt::Display for ReusePolicyErrorReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::CredentialMetadataNotObject => "credential_metadata_not_object",
            Self::PolicyNotObject => "reuse_policy_not_object",
            Self::InvalidPolicyIdentifier => "invalid_reuse_policy_identifier",
            Self::InvalidOptions => "invalid_reuse_policy_options",
            Self::OptionNotObject => "reuse_policy_option_not_object",
            Self::InvalidDetails => "invalid_reuse_policy_details",
            Self::UnsupportedMethod => "unsupported_reuse_method",
            Self::InvalidBaseMethodCombination => "invalid_reuse_base_method_combination",
            Self::InvalidNumericMember => "invalid_reuse_numeric_member",
            Self::BatchSizeRequired => "reuse_batch_size_required",
            Self::ReissueTriggerUnusedRequired => "reuse_trigger_unused_required",
            Self::ReissueTriggerLifetimeLeftRequired => "reuse_trigger_lifetime_left_required",
            Self::UnknownCapability => "unknown_reuse_capability",
        })
    }
}

/// Typed reuse-policy parsing failure without untrusted metadata text.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("{reason}")]
pub struct ReusePolicyError {
    reason: ReusePolicyErrorReason,
}

impl ReusePolicyError {
    const fn new(reason: ReusePolicyErrorReason) -> Self {
        Self { reason }
    }

    /// Returns the stable failure reason.
    #[must_use]
    pub const fn reason(self) -> ReusePolicyErrorReason {
        self.reason
    }
}

/// Parses and validates an ETSI credential reuse policy.
///
/// The input is the complete OpenID4VCI `credential_metadata` value. Unknown
/// policy identifiers are preserved as [`CredentialReusePolicy::Unsupported`]
/// so wallet policy can fail closed without making generic metadata parsing
/// non-extensible.
pub fn parse_credential_reuse_policy(
    credential_metadata: Option<&Value>,
) -> Result<CredentialReusePolicy, ReusePolicyError> {
    let Some(metadata) = credential_metadata else {
        return Ok(CredentialReusePolicy::Unrestricted);
    };
    let metadata = metadata.as_object().ok_or_else(|| {
        ReusePolicyError::new(ReusePolicyErrorReason::CredentialMetadataNotObject)
    })?;
    let Some(policy) = metadata.get(REUSE_POLICY_MEMBER) else {
        return Ok(CredentialReusePolicy::Unrestricted);
    };
    let policy = policy
        .as_object()
        .ok_or_else(|| ReusePolicyError::new(ReusePolicyErrorReason::PolicyNotObject))?;
    let identifier = policy
        .get("id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ReusePolicyError::new(ReusePolicyErrorReason::InvalidPolicyIdentifier))?;
    if identifier != ARF_ANNEX_II_POLICY_ID {
        return Ok(CredentialReusePolicy::Unsupported);
    }

    parse_arf_annex_ii(policy)
}

fn parse_arf_annex_ii(
    policy: &Map<String, Value>,
) -> Result<CredentialReusePolicy, ReusePolicyError> {
    let options = policy
        .get("options")
        .and_then(Value::as_array)
        .filter(|options| !options.is_empty())
        .ok_or_else(|| ReusePolicyError::new(ReusePolicyErrorReason::InvalidOptions))?;
    let parsed = options
        .iter()
        .map(parse_option)
        .collect::<Result<Vec<_>, _>>()?;

    let has_once_only = parsed
        .iter()
        .any(|option| option.details.contains(&ReuseMethod::OnceOnly));
    let has_limited_time = parsed
        .iter()
        .any(|option| option.details.contains(&ReuseMethod::LimitedTime));
    if has_once_only == has_limited_time {
        return Err(ReusePolicyError::new(
            ReusePolicyErrorReason::InvalidBaseMethodCombination,
        ));
    }

    Ok(CredentialReusePolicy::ArfAnnexIi { options: parsed })
}

fn parse_option(value: &Value) -> Result<ReusePolicyOption, ReusePolicyError> {
    let object = value
        .as_object()
        .ok_or_else(|| ReusePolicyError::new(ReusePolicyErrorReason::OptionNotObject))?;
    let details = object
        .get("details")
        .and_then(Value::as_array)
        .filter(|details| !details.is_empty())
        .ok_or_else(|| ReusePolicyError::new(ReusePolicyErrorReason::InvalidDetails))?
        .iter()
        .map(parse_method)
        .collect::<Result<Vec<_>, _>>()?;
    let batch_size = optional_u32(object, "batch_size")?;
    let reissue_trigger_unused = optional_u32(object, "reissue_trigger_unused")?;
    let reissue_trigger_lifetime_left_seconds =
        optional_u64(object, "reissue_trigger_lifetime_left")?;

    let requires_batch = details.iter().any(|method| {
        matches!(
            method,
            ReuseMethod::OnceOnly | ReuseMethod::RotatingBatch | ReuseMethod::PerRelyingParty
        )
    });
    if requires_batch && !batch_size.is_some_and(|size| size >= 2) {
        return Err(ReusePolicyError::new(
            ReusePolicyErrorReason::BatchSizeRequired,
        ));
    }
    if details.contains(&ReuseMethod::OnceOnly)
        && !matches!((reissue_trigger_unused, batch_size), (Some(unused), Some(size)) if unused < size)
    {
        return Err(ReusePolicyError::new(
            ReusePolicyErrorReason::ReissueTriggerUnusedRequired,
        ));
    }
    let requires_lifetime = details.iter().any(|method| {
        matches!(
            method,
            ReuseMethod::LimitedTime | ReuseMethod::RotatingBatch | ReuseMethod::PerRelyingParty
        )
    });
    if requires_lifetime && reissue_trigger_lifetime_left_seconds.is_none() {
        return Err(ReusePolicyError::new(
            ReusePolicyErrorReason::ReissueTriggerLifetimeLeftRequired,
        ));
    }

    Ok(ReusePolicyOption {
        details,
        batch_size,
        reissue_trigger_unused,
        reissue_trigger_lifetime_left_seconds,
    })
}

fn parse_method(value: &Value) -> Result<ReuseMethod, ReusePolicyError> {
    match value.as_str() {
        Some("once_only") => Ok(ReuseMethod::OnceOnly),
        Some("limited_time") => Ok(ReuseMethod::LimitedTime),
        Some("rotating-batch") => Ok(ReuseMethod::RotatingBatch),
        Some("per-relying-party") => Ok(ReuseMethod::PerRelyingParty),
        Some(_) => Err(ReusePolicyError::new(
            ReusePolicyErrorReason::UnsupportedMethod,
        )),
        None => Err(ReusePolicyError::new(
            ReusePolicyErrorReason::InvalidDetails,
        )),
    }
}

fn optional_u32(
    object: &Map<String, Value>,
    member: &str,
) -> Result<Option<u32>, ReusePolicyError> {
    optional_u64(object, member)?
        .map(|value| {
            u32::try_from(value)
                .map_err(|_| ReusePolicyError::new(ReusePolicyErrorReason::InvalidNumericMember))
        })
        .transpose()
}

fn optional_u64(
    object: &Map<String, Value>,
    member: &str,
) -> Result<Option<u64>, ReusePolicyError> {
    object
        .get(member)
        .map(|value| {
            value
                .as_u64()
                .ok_or_else(|| ReusePolicyError::new(ReusePolicyErrorReason::InvalidNumericMember))
        })
        .transpose()
}
