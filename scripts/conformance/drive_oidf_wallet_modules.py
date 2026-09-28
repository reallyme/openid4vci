#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Drive composed-wallet launches for OIDF OpenID4VCI wallet modules."""

from __future__ import annotations

import json
import math
import os
import re
import signal
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from oidf_wallet_control import (
    ControlHttpError,
    HarnessEndpoint,
    open_authenticated_request,
    same_endpoint as control_same_endpoint,
    validate_control_token,
    validate_harness_endpoint,
)
from oidf_wallet_evidence import (
    WalletEvidenceError,
    redact_launch_evidence,
    write_evidence,
)
from oidf_wallet_driver_state import DriverState, WaitingModule
from oidf_wallet_plan import (
    PlanDiscoveryError, discover_newest_matching_plan, parse_oidf_epoch_seconds,
    plan_listing_path,
)
from oidf_wallet_outcome_policy import OutcomePolicyError, expected_outcome


DEFAULT_CONFORMANCE_SERVER = "https://localhost.emobix.co.uk:8443/"
DEFAULT_INTERVAL_SECONDS = 1.0
DEFAULT_TIMEOUT_SECONDS = 7200.0
MIN_INTERVAL_SECONDS = 0.1
MAX_INTERVAL_SECONDS = 60.0
MIN_TIMEOUT_SECONDS = 1.0
MAX_TIMEOUT_SECONDS = 24.0 * 60.0 * 60.0
HTTP_TIMEOUT_SECONDS = 30.0
MAX_HTTP_RESPONSE_BYTES = 2 * 1024 * 1024
TEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
WALLET_INITIATED_MARKER = "[vci_authorization_code_flow_variant=wallet_initiated]"


class DriverError(Exception):
    """Privacy-safe wallet driver failure."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class DriverConfig:
    conformance_server: str
    plan_id: str
    alias: str | None
    plan_expression: str
    harness_offer_endpoint: str
    harness_initiation_endpoint: str
    harness_offer_target: HarnessEndpoint
    harness_initiation_target: HarnessEndpoint
    harness_token: str = field(repr=False)
    evidence_dir: Path
    conformance_verify_ssl: bool
    conformance_ca_file: Path | None
    interval_seconds: float
    timeout_seconds: float
    started_after_epoch_seconds: float

    @property
    def wallet_initiated(self) -> bool:
        return WALLET_INITIATED_MARKER in self.plan_expression


def main() -> int:
    try:
        config = config_from_env()
        context = build_tls_context(config)
    except DriverError as error:
        sys.stderr.write(f"OIDF wallet module driver failed: {error.code}\n")
        return 2

    state = DriverState()

    def request_stop(_signum: int, _frame: object) -> None:
        state.stop_requested = True

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    deadline = time.monotonic() + config.timeout_seconds
    while not state.stop_requested and time.monotonic() < deadline:
        try:
            drive_once(config, state, context)
        except (DriverError, PlanDiscoveryError) as error:
            sys.stderr.write(f"OIDF wallet module driver warning: {error.code}\n")
        time.sleep(config.interval_seconds)
    return 0


def config_from_env() -> DriverConfig:
    offer_endpoint = required_url_from_env("OPENID4VCI_WALLET_HARNESS_ENDPOINT")
    initiation_endpoint = os.environ.get("OPENID4VCI_WALLET_INITIATION_ENDPOINT")
    if initiation_endpoint is None:
        initiation_endpoint = derive_initiation_endpoint(offer_endpoint)
    local_mode = os.environ.get("OIDF_CONFORMANCE_MODE") == "local"
    try:
        offer_target = validate_harness_endpoint(offer_endpoint, local_mode)
        initiation_target = validate_harness_endpoint(initiation_endpoint, local_mode)
        harness_token = validate_control_token(
            os.environ.get("OPENID4VCI_WALLET_HARNESS_TOKEN")
            or os.environ.get("OIDF_WALLET_HARNESS_TOKEN")
        )
    except ControlHttpError as error:
        raise DriverError(error.code) from error
    evidence_dir_raw = os.environ.get("OPENID4VCI_WALLET_IMPLEMENTATION_EVIDENCE_DIR")
    if evidence_dir_raw is None or evidence_dir_raw == "":
        raise DriverError("missing_evidence_dir")
    plan_expression = os.environ.get("OIDF_WALLET_PLAN_EXPRESSION", "")
    if plan_expression == "":
        raise DriverError("missing_plan_expression")
    verify_ssl = bool_from_env("CONFORMANCE_VERIFY_SSL", True)
    if not verify_ssl and os.environ.get("OIDF_CONFORMANCE_MODE") != "local":
        raise DriverError("insecure_tls_requires_local_mode")
    ca_file_raw = os.environ.get("CONFORMANCE_CA_FILE")
    return DriverConfig(
        conformance_server=os.environ.get(
            "CONFORMANCE_SERVER", DEFAULT_CONFORMANCE_SERVER
        ),
        plan_id=os.environ.get(
            "OIDF_PLAN_ID", "oid4vci-1_0-wallet-haip-test-plan"
        ),
        alias=os.environ.get("OIDF_ALIAS") or None,
        plan_expression=plan_expression,
        harness_offer_endpoint=offer_endpoint,
        harness_initiation_endpoint=initiation_endpoint,
        harness_offer_target=offer_target,
        harness_initiation_target=initiation_target,
        harness_token=harness_token,
        evidence_dir=Path(evidence_dir_raw),
        conformance_verify_ssl=verify_ssl,
        conformance_ca_file=Path(ca_file_raw) if ca_file_raw else None,
        interval_seconds=bounded_float_from_env(
            "OPENID4VCI_OIDF_WALLET_DRIVER_INTERVAL_SECONDS",
            DEFAULT_INTERVAL_SECONDS,
            MIN_INTERVAL_SECONDS,
            MAX_INTERVAL_SECONDS,
        ),
        timeout_seconds=bounded_float_from_env(
            "OPENID4VCI_OIDF_WALLET_DRIVER_TIMEOUT_SECONDS",
            DEFAULT_TIMEOUT_SECONDS,
            MIN_TIMEOUT_SECONDS,
            MAX_TIMEOUT_SECONDS,
        ),
        started_after_epoch_seconds=time.time() - 5.0,
    )


def required_url_from_env(name: str) -> str:
    value = os.environ.get(name)
    if value is None or value == "":
        raise DriverError("missing_harness_endpoint")
    return value


def derive_initiation_endpoint(offer_endpoint: str) -> str:
    suffix = "/oidf/wallet/credential-offer"
    parsed = urllib.parse.urlparse(offer_endpoint)
    if parsed.query != "" or parsed.fragment != "" or not parsed.path.endswith(suffix):
        raise DriverError("missing_initiation_endpoint")
    path = f"{parsed.path[: -len(suffix)]}/oidf/wallet/initiate"
    return urllib.parse.urlunparse(parsed._replace(path=path))


def bool_from_env(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    normalized = raw.lower()
    if normalized in {"1", "true", "yes"}:
        return True
    if normalized in {"0", "false", "no"}:
        return False
    raise DriverError("invalid_boolean_environment")


def bounded_float_from_env(
    name: str,
    default: float,
    minimum: float,
    maximum: float,
) -> float:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = float(raw)
    except ValueError as error:
        raise DriverError("invalid_numeric_environment") from error
    if not math.isfinite(value) or value < minimum or value > maximum:
        raise DriverError("invalid_numeric_environment")
    return value


def build_tls_context(config: DriverConfig) -> ssl.SSLContext:
    if not config.conformance_verify_ssl:
        # Unverified TLS is restricted to an explicitly selected local suite.
        # Hosted certification evidence must always use authenticated TLS.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context

    ca_file = config.conformance_ca_file
    if ca_file is not None and (ca_file.is_symlink() or not ca_file.is_file()):
        raise DriverError("invalid_conformance_ca_file")
    try:
        return ssl.create_default_context(cafile=str(ca_file) if ca_file else None)
    except (OSError, ssl.SSLError) as error:
        raise DriverError("invalid_conformance_ca_file") from error


def drive_once(config: DriverConfig, state: DriverState, context: ssl.SSLContext) -> None:
    plan = discover_newest_matching_plan(
        lambda start: fetch_json(
            config.conformance_server, plan_listing_path(start), context
        ),
        config,
    )
    if plan is None:
        return
    for module in waiting_modules(plan, config, context):
        if module.test_id in state.attempted_test_ids:
            continue
        # A launch can consume an authorization code before its HTTP response is
        # observed. Retrying an indeterminate failure would replay that code and
        # can mutate a finished OIDF module, so each test instance is attempted
        # at most once.
        state.attempted_test_ids.add(module.test_id)
        if config.wallet_initiated:
            evidence = drive_wallet_initiated(module, config, state, context)
        else:
            evidence = drive_issuer_initiated(module, config, context)
        if evidence is None:
            continue
        try:
            write_evidence(config.evidence_dir, module.test_id, evidence)
        except WalletEvidenceError as error:
            raise DriverError(error.code) from error
        sys.stderr.write(f"OIDF wallet module driver launched {module.test_id}\n")


def waiting_modules(
    plan: dict[str, Any], config: DriverConfig, context: ssl.SSLContext
) -> list[WaitingModule]:
    modules = plan.get("modules")
    if not isinstance(modules, list):
        return []
    waiting: list[WaitingModule] = []
    for module in modules:
        if not isinstance(module, dict) or not isinstance(module.get("instances"), list):
            continue
        for test_id in module["instances"]:
            if not isinstance(test_id, str) or not TEST_ID_PATTERN.fullmatch(test_id):
                continue
            info = fetch_json(config.conformance_server, f"/api/info/{test_id}", context)
            module_id = info.get("testName") if isinstance(info, dict) else None
            if not isinstance(info, dict) or info.get("status") != "WAITING":
                continue
            if not isinstance(module_id, str):
                raise DriverError("invalid_waiting_module_info")
            try:
                expected_outcome(module_id)
            except OutcomePolicyError as error:
                raise DriverError(error.code) from error
            waiting.append(WaitingModule(test_id=test_id, module_id=module_id))
    return waiting


def drive_wallet_initiated(
    module: WaitingModule,
    config: DriverConfig,
    state: DriverState,
    context: ssl.SSLContext,
) -> dict[str, Any] | None:
    runner = fetch_json(
        config.conformance_server, f"/api/runner/{module.test_id}", context
    )
    if not isinstance(runner, dict) or not isinstance(runner.get("exposed"), dict):
        return None
    exposed = runner["exposed"]
    credential_issuer = exposed.get("credential_issuer")
    configuration_id = state.resolve_configuration_id_hint(
        exposed.get("credential_configuration_id_hint")
    )
    if not isinstance(credential_issuer, str) or not isinstance(configuration_id, str):
        return None
    response = post_json(
        config.harness_initiation_endpoint,
        {
            "credential_issuer": credential_issuer,
            "credential_configuration_id": configuration_id,
        },
        module.test_id,
        context,
        config,
    )
    return evidence_from_response(module.module_id, "wallet_initiated", response)


def drive_issuer_initiated(
    module: WaitingModule, config: DriverConfig, context: ssl.SSLContext
) -> dict[str, Any] | None:
    browser = fetch_json(
        config.conformance_server,
        f"/api/runner/browser/{module.test_id}",
        context,
    )
    if not isinstance(browser, dict) or not isinstance(browser.get("urls"), list):
        return None
    visited = browser.get("visited")
    visited_urls = set(visited) if isinstance(visited, list) else set()
    for url in browser["urls"]:
        if not isinstance(url, str) or url in visited_urls:
            continue
        if not control_same_endpoint(url, config.harness_offer_target):
            continue
        response = fetch_harness_json_url(url, module.test_id, context, config)
        mark_browser_url_visited(module.test_id, url, config, context)
        return evidence_from_response(
            module.module_id, "issuer_initiated", response
        )
    return None


def same_endpoint(candidate: str, endpoint: str) -> bool:
    try:
        expected = validate_harness_endpoint(endpoint, False)
    except ControlHttpError:
        return False
    return control_same_endpoint(candidate, expected)


def evidence_from_response(
    module_id: str, mode: str, response: Any
) -> dict[str, Any]:
    try:
        return redact_launch_evidence(module_id, mode, response)
    except WalletEvidenceError as error:
        raise DriverError(error.code) from error


def mark_browser_url_visited(
    test_id: str, url: str, config: DriverConfig, context: ssl.SSLContext
) -> None:
    data = urllib.parse.urlencode({"url": url}).encode("utf-8")
    target = urllib.parse.urljoin(
        ensure_trailing_slash(config.conformance_server),
        f"api/runner/browser/{test_id}/visit",
    )
    request = urllib.request.Request(
        target,
        data=data,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    open_request(request, context)


def post_json(
    url: str,
    payload: dict[str, str],
    idempotency_key: str,
    context: ssl.SSLContext,
    config: DriverConfig,
) -> Any:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Idempotency-Key": idempotency_key,
        },
    )
    return decode_json(
        open_harness_request(
            request, context, config, config.harness_initiation_target
        )
    )


def fetch_json(base_url: str, path: str, context: ssl.SSLContext) -> Any:
    url = urllib.parse.urljoin(ensure_trailing_slash(base_url), path.lstrip("/"))
    return fetch_json_url(url, context)


def fetch_json_url(url: str, context: ssl.SSLContext) -> Any:
    return decode_json(open_request(urllib.request.Request(url, method="GET"), context))


def fetch_harness_json_url(
    url: str,
    idempotency_key: str,
    context: ssl.SSLContext,
    config: DriverConfig,
) -> Any:
    request = urllib.request.Request(
        url,
        method="GET",
        headers={"Idempotency-Key": idempotency_key},
    )
    return decode_json(
        open_harness_request(request, context, config, config.harness_offer_target)
    )


def open_harness_request(
    request: urllib.request.Request,
    context: ssl.SSLContext,
    config: DriverConfig,
    expected_endpoint: HarnessEndpoint,
) -> bytes:
    try:
        return open_authenticated_request(
            request,
            context,
            config.harness_token,
            expected_endpoint,
            HTTP_TIMEOUT_SECONDS,
            MAX_HTTP_RESPONSE_BYTES,
        )
    except ControlHttpError as error:
        raise DriverError(error.code) from error


def open_request(request: urllib.request.Request, context: ssl.SSLContext) -> bytes:
    try:
        with urllib.request.urlopen(
            request, timeout=HTTP_TIMEOUT_SECONDS, context=context
        ) as response:
            return read_bounded_response(response)
    except urllib.error.HTTPError as error:
        if 400 <= error.code < 500:
            reason = "http_client_error"
        elif 500 <= error.code < 600:
            reason = "http_server_error"
        else:
            reason = "http_unexpected_status"
        raise DriverError(reason) from error
    except urllib.error.URLError as error:
        raise DriverError("network_error") from error


def read_bounded_response(response: Any) -> bytes:
    content_length = response.headers.get("Content-Length")
    if content_length is not None:
        try:
            declared_length = int(content_length)
        except ValueError as error:
            raise DriverError("invalid_response_length") from error
        if declared_length < 0:
            raise DriverError("invalid_response_length")
        if declared_length > MAX_HTTP_RESPONSE_BYTES:
            raise DriverError("response_too_large")
    body = response.read(MAX_HTTP_RESPONSE_BYTES + 1)
    if len(body) > MAX_HTTP_RESPONSE_BYTES:
        raise DriverError("response_too_large")
    return body


def decode_json(body: bytes) -> Any:
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DriverError("invalid_json") from error


def ensure_trailing_slash(value: str) -> str:
    return value if value.endswith("/") else f"{value}/"


if __name__ == "__main__":
    raise SystemExit(main())
