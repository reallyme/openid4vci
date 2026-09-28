// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Builds authorization callback URLs from provider-validated inputs.

use openid4vci_http::{OAuthHttpError, OAuthHttpErrorReason, OAuthHttpResult};

pub(super) fn redirect_to_authorization_completion(
    authorization_endpoint: &str,
    client_id: &str,
    request_uri: &str,
    completion_parameter: &str,
    user_rejected: bool,
    user_reject_parameter: &str,
) -> OAuthHttpResult<String> {
    let mut url = url::Url::parse(authorization_endpoint)
        .map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequest))?;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("client_id", client_id);
        query.append_pair("request_uri", request_uri);
        query.append_pair(completion_parameter, "1");
        if user_rejected {
            query.append_pair(user_reject_parameter, "1");
        }
    }
    Ok(url.to_string())
}

pub(super) fn redirect_with_code(
    redirect_uri: &str,
    code: &str,
    state: Option<&str>,
    issuer: &str,
) -> OAuthHttpResult<String> {
    let mut url = url::Url::parse(redirect_uri)
        .map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequest))?;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("code", code);
        query.append_pair("iss", issuer);
        if let Some(value) = state {
            query.append_pair("state", value);
        }
    }
    Ok(url.to_string())
}

pub(super) fn redirect_with_error(
    redirect_uri: &str,
    error: &str,
    state: Option<&str>,
) -> OAuthHttpResult<String> {
    let mut url = url::Url::parse(redirect_uri)
        .map_err(|_| OAuthHttpError::new(OAuthHttpErrorReason::InvalidRequest))?;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("error", error);
        if let Some(value) = state {
            query.append_pair("state", value);
        }
    }
    Ok(url.to_string())
}
