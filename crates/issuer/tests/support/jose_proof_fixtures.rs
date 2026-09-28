// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reusable JOSE proof fixtures kept outside the integration-test entry point.

use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_crypto::ed25519::{generate_ed25519_keypair_from_seed, sign_ed25519};
use reallyme_crypto::jwk::{ed25519_public_key_to_jwk, JwkOptions};
use reallyme_jose::Jwk;
use serde_json::json;

use super::{
    signed_proof_with_header, JoseProofTestError, ISSUER, PROOF_TYP, RESOLVED_KEY_ID, SEED,
    X5C_LEAF,
};

/// Builds a key proof bound through a JOSE `kid` header.
pub(super) fn kid_bound_proof(nonce: &str) -> Result<String, JoseProofTestError> {
    let (_public_key, private_key) =
        generate_ed25519_keypair_from_seed(&SEED).map_err(|_| JoseProofTestError::Key)?;
    let header = json!({"alg": "EdDSA", "typ": PROOF_TYP, "kid": RESOLVED_KEY_ID});
    let claims = json!({"aud": ISSUER, "nonce": nonce, "iat": 1_700_000_000_u64});
    let header_json = serde_json::to_vec(&header).map_err(|_| JoseProofTestError::Sign)?;
    let claims_json = serde_json::to_vec(&claims).map_err(|_| JoseProofTestError::Sign)?;
    let header_b64 = bytes_to_base64url(&header_json);
    let payload_b64 = bytes_to_base64url(&claims_json);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = sign_ed25519(&private_key, signing_input.as_bytes())
        .map_err(|_| JoseProofTestError::Sign)?;
    Ok(format!(
        "{signing_input}.{}",
        bytes_to_base64url(&signature)
    ))
}

/// Builds a key proof bound to the first `x5c` certificate public key.
pub(super) fn x5c_bound_proof(nonce: &str) -> Result<String, JoseProofTestError> {
    let header = json!({"alg": "EdDSA", "typ": PROOF_TYP, "x5c": [X5C_LEAF]});
    let claims = json!({"aud": ISSUER, "nonce": nonce, "iat": 1_700_000_000_u64});
    signed_proof_with_header(header, claims)
}

pub(super) fn public_jwk_value(seed: &[u8; 32]) -> Result<serde_json::Value, JoseProofTestError> {
    serde_json::to_value(public_jwk_from_seed(seed, None)?).map_err(|_| JoseProofTestError::Key)
}

pub(super) fn public_jwk_with_kid(kid: Option<&str>) -> Result<Jwk, JoseProofTestError> {
    public_jwk_from_seed(&SEED, kid)
}

fn public_jwk_from_seed(seed: &[u8; 32], kid: Option<&str>) -> Result<Jwk, JoseProofTestError> {
    let (public_key, _private_key) =
        generate_ed25519_keypair_from_seed(seed).map_err(|_| JoseProofTestError::Key)?;
    ed25519_public_key_to_jwk(
        &public_key,
        JwkOptions {
            alg: true,
            use_sig: true,
            use_enc: false,
            kid: kid.map(str::to_owned),
        },
    )
    .map(|jwk| Jwk::Okp(jwk.into()))
    .map_err(|_| JoseProofTestError::Key)
}
