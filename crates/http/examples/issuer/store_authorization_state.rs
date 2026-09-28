// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Owns the conformance issuer's in-memory OAuth authorization state.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use reallyme_crypto::sha2::digest as digest_sha2_256;
use zeroize::ZeroizeOnDrop;

use super::credential_authorization::CredentialAuthorization;
use super::issue::ExampleDpopVerifier;

#[derive(Clone, ZeroizeOnDrop)]
pub(super) struct ParRecord {
    pub(super) client_id: String,
    pub(super) client_subject: String,
    pub(super) client_instance_key_thumbprint: String,
    pub(super) redirect_uri: String,
    pub(super) state: Option<String>,
    pub(super) code_challenge: String,
    pub(super) dpop_jkt: Option<String>,
    #[zeroize(skip)]
    pub(super) credential_authorizations: Vec<CredentialAuthorization>,
    #[zeroize(skip)]
    pub(super) expires_at: u64,
    #[zeroize(skip)]
    pub(super) used: bool,
}

#[derive(Clone, ZeroizeOnDrop)]
pub(super) struct CodeRecord {
    pub(super) client_id: String,
    pub(super) client_subject: String,
    pub(super) client_instance_key_thumbprint: String,
    pub(super) code_challenge: String,
    pub(super) dpop_jkt: Option<String>,
    #[zeroize(skip)]
    pub(super) credential_authorizations: Vec<CredentialAuthorization>,
    #[zeroize(skip)]
    pub(super) expires_at: u64,
}

#[derive(ZeroizeOnDrop)]
pub(super) struct AccessTokenRecord {
    pub(super) dpop_jkt: String,
    pub(super) client_subject: String,
    #[zeroize(skip)]
    pub(super) credential_authorizations: Vec<CredentialAuthorization>,
    #[zeroize(skip)]
    pub(super) expires_at: u64,
}

#[derive(Clone, ZeroizeOnDrop)]
pub(super) struct RefreshTokenRecord {
    pub(super) client_id: String,
    pub(super) client_subject: String,
    pub(super) client_instance_key_thumbprint: String,
    #[zeroize(skip)]
    pub(super) credential_authorizations: Vec<CredentialAuthorization>,
    #[zeroize(skip)]
    pub(super) expires_at: u64,
}

#[derive(ZeroizeOnDrop)]
pub(super) struct AuthenticatedClient {
    pub(super) subject: String,
    pub(super) instance_key_thumbprint: String,
}

pub(super) struct ExampleOAuthAuthorizationServer {
    pub(super) credential_issuer: String,
    pub(super) authorization_server_issuer: String,
    pub(super) registered_redirect_uris: HashMap<String, HashSet<String>>,
    pub(super) par_records: Mutex<HashMap<String, ParRecord>>,
    pub(super) code_records: Mutex<HashMap<[u8; 32], CodeRecord>>,
    pub(super) access_tokens: Mutex<HashMap<[u8; 32], AccessTokenRecord>>,
    pub(super) refresh_tokens: Mutex<HashMap<[u8; 32], RefreshTokenRecord>>,
    pub(super) used_code_access_tokens: Mutex<HashMap<[u8; 32], [u8; 32]>>,
    pub(super) dpop_verifier: Arc<ExampleDpopVerifier>,
}

impl ExampleOAuthAuthorizationServer {
    pub(super) fn new(credential_issuer: String, authorization_server_issuer: String) -> Self {
        Self {
            credential_issuer,
            authorization_server_issuer,
            registered_redirect_uris: HashMap::new(),
            par_records: Mutex::new(HashMap::new()),
            code_records: Mutex::new(HashMap::new()),
            access_tokens: Mutex::new(HashMap::new()),
            refresh_tokens: Mutex::new(HashMap::new()),
            used_code_access_tokens: Mutex::new(HashMap::new()),
            dpop_verifier: Arc::new(ExampleDpopVerifier::new()),
        }
    }

    pub(super) fn shared_dpop_verifier(&self) -> Arc<ExampleDpopVerifier> {
        self.dpop_verifier.clone()
    }
}

pub(super) fn opaque_token_digest(token: &str) -> [u8; 32] {
    *digest_sha2_256(token.as_bytes()).as_bytes()
}
