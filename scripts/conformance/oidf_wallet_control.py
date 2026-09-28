#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Authenticated, redirect-free HTTP boundary for the OIDF wallet host."""

from __future__ import annotations

import ssl
import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any


MIN_CONTROL_TOKEN_BYTES = 32
MAX_CONTROL_TOKEN_BYTES = 4096
LOCAL_HTTP_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
WALLET_FLOW_ERROR_CODES = frozenset(
    {
        "launch_rejected",
        "wallet_attestation_unavailable",
        "token_exchange_failed",
        "credential_request_failed",
        "credential_storage_failed",
    }
)


class ControlHttpError(Exception):
    """Privacy-safe control-plane failure."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject redirects before an Authorization header can cross origins."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


@dataclass(frozen=True)
class HarnessEndpoint:
    scheme: str
    host: str
    port: int
    path: str


def validate_control_token(raw: str | None) -> str:
    if raw is None:
        raise ControlHttpError("missing_wallet_harness_token")
    encoded = raw.encode("utf-8")
    if (
        len(encoded) < MIN_CONTROL_TOKEN_BYTES
        or len(encoded) > MAX_CONTROL_TOKEN_BYTES
        or not raw.isascii()
        or not all(character.isprintable() and not character.isspace() for character in raw)
    ):
        raise ControlHttpError("invalid_wallet_harness_token")
    return raw


def validate_harness_endpoint(raw: str, allow_local_http: bool) -> HarnessEndpoint:
    try:
        parsed = urllib.parse.urlsplit(raw)
        port = parsed.port
    except ValueError as error:
        raise ControlHttpError("invalid_harness_endpoint") from error
    host = parsed.hostname
    if (
        host is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query != ""
        or parsed.fragment != ""
        or parsed.path == ""
        or parsed.scheme not in {"http", "https"}
    ):
        raise ControlHttpError("invalid_harness_endpoint")
    normalized_host = host.lower()
    if parsed.scheme == "http" and (
        not allow_local_http or normalized_host not in LOCAL_HTTP_HOSTS
    ):
        raise ControlHttpError("insecure_harness_endpoint")
    effective_port = port if port is not None else (443 if parsed.scheme == "https" else 80)
    return HarnessEndpoint(parsed.scheme, normalized_host, effective_port, parsed.path)


def same_endpoint(candidate: str, expected: HarnessEndpoint) -> bool:
    try:
        parsed = urllib.parse.urlsplit(candidate)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        return False
    if (
        host is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment != ""
    ):
        return False
    effective_port = port if port is not None else (443 if parsed.scheme == "https" else 80)
    return (
        parsed.scheme == expected.scheme
        and host.lower() == expected.host
        and effective_port == expected.port
        and parsed.path == expected.path
    )


def open_authenticated_request(
    request: urllib.request.Request,
    context: ssl.SSLContext,
    token: str,
    expected_endpoint: HarnessEndpoint,
    timeout_seconds: float,
    maximum_response_bytes: int,
) -> bytes:
    if not same_endpoint(request.full_url, expected_endpoint):
        raise ControlHttpError("wallet_harness_endpoint_mismatch")
    if request.has_header("Authorization"):
        raise ControlHttpError("wallet_harness_authorization_conflict")
    request.add_unredirected_header("Authorization", f"Bearer {token}")
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPHandler(),
        urllib.request.HTTPSHandler(context=context),
        NoRedirectHandler(),
    )
    try:
        with opener.open(request, timeout=timeout_seconds) as response:
            return read_bounded_response(response, maximum_response_bytes)
    except urllib.error.HTTPError as error:
        if 300 <= error.code < 400:
            code = "wallet_harness_redirect_rejected"
        elif 400 <= error.code < 500:
            code = "http_client_error"
        elif 500 <= error.code < 600:
            code = wallet_flow_error_code(error, maximum_response_bytes)
        else:
            code = "http_unexpected_status"
        raise ControlHttpError(code) from error
    except urllib.error.URLError as error:
        raise ControlHttpError("network_error") from error


def wallet_flow_error_code(
    response: urllib.error.HTTPError, maximum_response_bytes: int
) -> str:
    content_type = response.headers.get("Content-Type", "")
    if "application/problem+json" not in content_type.lower():
        return "http_server_error"
    try:
        body = read_bounded_response(response, maximum_response_bytes)
        problem = json.loads(body.decode("utf-8"))
    except (ControlHttpError, UnicodeDecodeError, json.JSONDecodeError):
        return "http_server_error"
    if not isinstance(problem, dict) or set(problem) != {
        "type",
        "title",
        "status",
        "error",
    }:
        return "http_server_error"
    reason = problem.get("error")
    if (
        problem.get("type") != "about:blank"
        or problem.get("title") != "wallet_flow_failed"
        or problem.get("status") != 502
        or reason not in WALLET_FLOW_ERROR_CODES
    ):
        return "http_server_error"
    return f"wallet_flow_{reason}"


def read_bounded_response(response: Any, maximum_response_bytes: int) -> bytes:
    content_length = response.headers.get("Content-Length")
    if content_length is not None:
        try:
            declared_length = int(content_length)
        except ValueError as error:
            raise ControlHttpError("invalid_response_length") from error
        if declared_length < 0:
            raise ControlHttpError("invalid_response_length")
        if declared_length > maximum_response_bytes:
            raise ControlHttpError("response_too_large")
    body = response.read(maximum_response_bytes + 1)
    if len(body) > maximum_response_bytes:
        raise ControlHttpError("response_too_large")
    return body
