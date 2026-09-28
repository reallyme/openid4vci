// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! OpenID4VCI credential format identifiers.

/// OpenID4VCI credential format identifiers used by ReallyMe protocol crates.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum CredentialFormat {
    /// JWT VC JSON credential format profile.
    #[serde(rename = "jwt_vc_json")]
    JwtVcJson,
    /// JWT VC JSON-LD credential format profile.
    #[serde(rename = "jwt_vc_json-ld")]
    JwtVcJsonLd,
    /// IETF SD-JWT VC credential format profile.
    #[serde(rename = "dc+sd-jwt")]
    SdJwtVc,
    /// ISO mdoc credential format profile.
    #[serde(rename = "mso_mdoc")]
    MsoMdoc,
    /// W3C Verifiable Credential Data Model secured with Data Integrity.
    #[serde(rename = "ldp_vc")]
    LdpVc,
}
