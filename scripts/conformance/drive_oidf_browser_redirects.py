#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Drive browser-only redirects exposed by OIDF issuer-role test modules."""

from __future__ import annotations

import json
import os
import re
import signal
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


DEFAULT_ALIAS = "openid4vci-haip-issuer"
DEFAULT_CONFORMANCE_SERVER = "https://localhost.emobix.co.uk:8443/"
DEFAULT_INTERVAL_SECONDS = 1.0
DEFAULT_TIMEOUT_SECONDS = 7200.0
DEFAULT_STARTED_AFTER_GRACE_SECONDS = 5.0
HTTP_TIMEOUT_SECONDS = 15.0
LOCAL_HOST_SUFFIX = ".emobix.co.uk"
MAX_REDIRECTS = 8
PLAN_PAGE_SIZE = 200
MAX_PLAN_PAGES = 64
IMPLICIT_URL_PATTERN = re.compile(r"https://[^\"'<>\\s]+/implicit/[A-Za-z0-9_-]+")
USER_REJECT_TEST_NAME = "fapi2-security-profile-final-user-rejects-authentication"
USER_REJECT_QUERY_PARAM = "reallyme_oidf_user_reject"
PAR_REUSE_PRIOR_TO_AUTH_COMPLETION_TEST_NAME = (
    "fapi2-security-profile-final-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds"
)
PAR_ATTEMPT_REUSE_REQUEST_URI_TEST_NAME = (
    "fapi2-security-profile-final-par-attempt-reuse-request_uri"
)


@dataclass(frozen=True)
class DriverConfig:
    conformance_server: str
    plan_id: str
    alias: str
    issuer_netloc: str | None
    healthcheck_netloc: str | None
    credential_issuer_url: str
    credential_configuration_id: str
    interval_seconds: float
    timeout_seconds: float
    started_after_epoch_seconds: float


@dataclass(frozen=True)
class WaitingModule:
    test_id: str
    status: str


class DriverState:
    def __init__(self) -> None:
        self.handled_redirects: set[str] = set()
        self.handled_implicit_submits: set[str] = set()
        self.handled_credential_offers: set[str] = set()
        self.stop_requested = False


def main() -> int:
    config = config_from_env()
    state = DriverState()

    def request_stop(_signum: int, _frame: object) -> None:
        state.stop_requested = True

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)

    context = ssl._create_unverified_context()
    deadline = time.monotonic() + config.timeout_seconds
    while not state.stop_requested and time.monotonic() < deadline:
        try:
            drive_once(config, state, context)
        except DriverError as error:
            sys.stderr.write(f"OIDF browser driver warning: {error.code}\n")
        time.sleep(config.interval_seconds)
    return 0


def config_from_env() -> DriverConfig:
    issuer_base_url = os.environ.get(
        "OPENID4VCI_ISSUER_BASE_URL", "https://localhost.emobix.co.uk:9443/"
    )
    issuer_netloc = netloc_from_url(issuer_base_url)
    healthcheck_netloc = netloc_from_url(os.environ.get("OPENID4VCI_ISSUER_HEALTHCHECK_BASE_URL"))
    started_after_grace_seconds = positive_float_from_env(
        "OPENID4VCI_OIDF_BROWSER_DRIVER_STARTED_AFTER_GRACE_SECONDS",
        DEFAULT_STARTED_AFTER_GRACE_SECONDS,
    )
    return DriverConfig(
        conformance_server=os.environ.get("CONFORMANCE_SERVER", DEFAULT_CONFORMANCE_SERVER),
        plan_id=os.environ.get("OIDF_PLAN_ID", "oid4vci-1_0-issuer-haip-test-plan"),
        alias=os.environ.get("OIDF_ALIAS", DEFAULT_ALIAS),
        issuer_netloc=issuer_netloc,
        healthcheck_netloc=healthcheck_netloc,
        credential_issuer_url=os.environ.get(
            "OPENID4VCI_CREDENTIAL_ISSUER_URL",
            f"{ensure_trailing_slash(issuer_base_url)}openid4vci/example-issuer/",
        ),
        credential_configuration_id=os.environ.get(
            "OPENID4VCI_CREDENTIAL_CONFIGURATION_ID", "pid"
        ),
        interval_seconds=positive_float_from_env(
            "OPENID4VCI_OIDF_BROWSER_DRIVER_INTERVAL_SECONDS", DEFAULT_INTERVAL_SECONDS
        ),
        timeout_seconds=positive_float_from_env(
            "OPENID4VCI_OIDF_BROWSER_DRIVER_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS
        ),
        started_after_epoch_seconds=time.time() - started_after_grace_seconds,
    )


def positive_float_from_env(name: str, default: float) -> float:
    raw_value = os.environ.get(name)
    if raw_value is None:
        return default
    try:
        parsed = float(raw_value)
    except ValueError:
        return default
    if parsed <= 0:
        return default
    return parsed


def netloc_from_url(raw_url: str | None) -> str | None:
    if raw_url is None:
        return None
    parsed = urllib.parse.urlparse(raw_url)
    if parsed.netloc == "":
        return None
    return parsed.netloc


def parse_oidf_epoch_seconds(raw_value: Any) -> float | None:
    if not isinstance(raw_value, str):
        return None
    normalized = raw_value
    if normalized.endswith("Z"):
        normalized = f"{normalized[:-1]}+00:00"
    normalized = trim_fractional_seconds(normalized)
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def trim_fractional_seconds(value: str) -> str:
    separator_index = value.find(".")
    if separator_index < 0:
        return value
    timezone_index = value.find("+", separator_index)
    if timezone_index < 0:
        timezone_index = value.find("-", separator_index)
    if timezone_index < 0:
        fractional = value[separator_index + 1 :]
        suffix = ""
    else:
        fractional = value[separator_index + 1 : timezone_index]
        suffix = value[timezone_index:]
    if len(fractional) <= 6:
        return value
    return f"{value[: separator_index + 1]}{fractional[:6]}{suffix}"


def drive_once(config: DriverConfig, state: DriverState, context: ssl.SSLContext) -> None:
    plan = fetch_newest_matching_plan(config, context)
    if plan is None:
        return

    for module in waiting_modules(plan, config, context):
        log_entries = fetch_json(config.conformance_server, f"/api/log/{module.test_id}", context)
        if not isinstance(log_entries, list):
            continue
        drive_credential_offer(module.test_id, config, state, context)
        drive_browser_control_urls(module.test_id, log_entries, config, state, context)
        drive_redirects(module.test_id, log_entries, config, state, context)
        drive_implicit_submits(module.test_id, log_entries, config, state, context)


def drive_credential_offer(
    test_id: str,
    config: DriverConfig,
    state: DriverState,
    context: ssl.SSLContext,
) -> None:
    runner_status = fetch_json(config.conformance_server, f"/api/runner/{test_id}", context)
    if not isinstance(runner_status, dict):
        return
    exposed = runner_status.get("exposed")
    if not isinstance(exposed, dict):
        return
    credential_offer_endpoint = exposed.get("credential_offer_endpoint")
    if not isinstance(credential_offer_endpoint, str):
        return
    key = f"{test_id}:{credential_offer_endpoint}"
    if key in state.handled_credential_offers:
        return

    offer_url = credential_offer_submission_url(
        credential_offer_endpoint,
        config.credential_issuer_url,
        config.credential_configuration_id,
        test_id,
    )
    fetch_url(offer_url, context)
    state.handled_credential_offers.add(key)
    sys.stderr.write(f"OIDF browser driver submitted credential offer for {test_id}\n")


def credential_offer_submission_url(
    endpoint: str,
    credential_issuer_url: str,
    credential_configuration_id: str,
    test_id: str,
) -> str:
    offer = {
        "credential_issuer": credential_issuer_url,
        "credential_configuration_ids": [credential_configuration_id],
        "grants": {"authorization_code": {"issuer_state": f"oidf-{test_id}"}},
    }
    encoded_query = urllib.parse.urlencode(
        {"credential_offer": json.dumps(offer, separators=(",", ":"))}
    )
    separator = "&" if urllib.parse.urlparse(endpoint).query else "?"
    return f"{endpoint}{separator}{encoded_query}"


def newest_matching_plan(payload: Any, config: DriverConfig) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None
    data = payload.get("data")
    if not isinstance(data, list):
        return None

    matches: list[dict[str, Any]] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        if item.get("planName") != config.plan_id:
            continue
        started_epoch_seconds = parse_oidf_epoch_seconds(item.get("started"))
        if (
            started_epoch_seconds is not None
            and started_epoch_seconds < config.started_after_epoch_seconds
        ):
            continue
        item_config = item.get("config")
        if isinstance(item_config, dict) and item_config.get("alias") != config.alias:
            continue
        matches.append(item)
    if not matches:
        return None
    matches.sort(key=lambda item: str(item.get("started", "")))
    return matches[-1]


def fetch_newest_matching_plan(
    config: DriverConfig, context: ssl.SSLContext
) -> dict[str, Any] | None:
    newest: dict[str, Any] | None = None
    start = 0
    for _ in range(MAX_PLAN_PAGES):
        payload = fetch_json(config.conformance_server, plan_listing_path(start), context)
        if not isinstance(payload, dict):
            raise DriverError("invalid_plan_listing")
        data = payload.get("data")
        if not isinstance(data, list):
            raise DriverError("invalid_plan_listing")

        candidate = newest_matching_plan(payload, config)
        if candidate is not None and (
            newest is None
            or str(candidate.get("started", "")) > str(newest.get("started", ""))
        ):
            newest = candidate

        if len(data) < PLAN_PAGE_SIZE:
            return newest
        start += len(data)

    # A server that ignores pagination or returns an unexpectedly large plan
    # history must not make the browser driver scan without a fixed bound.
    raise DriverError("plan_listing_limit")


def plan_listing_path(start: int = 0) -> str:
    return f"/api/plan?start={start}&length={PLAN_PAGE_SIZE}"


def waiting_modules(
    plan: dict[str, Any], config: DriverConfig, context: ssl.SSLContext
) -> list[WaitingModule]:
    modules = plan.get("modules")
    if not isinstance(modules, list):
        return []

    waiting: list[WaitingModule] = []
    for module in modules:
        if not isinstance(module, dict):
            continue
        instances = module.get("instances")
        if not isinstance(instances, list):
            continue
        for instance in instances:
            if not isinstance(instance, str):
                continue
            info = fetch_json(config.conformance_server, f"/api/info/{instance}", context)
            if not isinstance(info, dict):
                continue
            status = info.get("status")
            if status == "WAITING":
                waiting.append(WaitingModule(test_id=instance, status=status))
    return waiting


def drive_redirects(
    test_id: str,
    log_entries: list[Any],
    config: DriverConfig,
    state: DriverState,
    context: ssl.SSLContext,
) -> None:
    for entry in log_entries:
        if not isinstance(entry, dict):
            continue
        if entry.get("http") != "redirect":
            continue
        if entry.get("method", "GET") != "GET":
            continue
        redirect_url = entry.get("redirect_to")
        if not isinstance(redirect_url, str):
            continue
        key = f"{test_id}:{redirect_url}"
        if key in state.handled_redirects:
            continue
        state.handled_redirects.add(key)
        mark_browser_url_visited_if_available(test_id, redirect_url, config, context)
        target_url = redirect_url_for_module(redirect_url, log_entries)
        final_body = fetch_url(rewrite_for_host_driver(target_url, config), context)
        submit_implicit_urls(test_id, final_body, config, state, context)
        sys.stderr.write(f"OIDF browser driver followed authorization redirect for {test_id}\n")


def drive_browser_control_urls(
    test_id: str,
    log_entries: list[Any],
    config: DriverConfig,
    state: DriverState,
    context: ssl.SSLContext,
) -> None:
    if has_logged_redirect(log_entries) and not is_par_attempt_reuse_request_uri_module(log_entries):
        return

    browser_status = fetch_json(
        config.conformance_server, f"/api/runner/browser/{test_id}", context
    )
    if not isinstance(browser_status, dict):
        return

    urls = browser_status.get("urls")
    visited = browser_status.get("visited")
    if not isinstance(urls, list) or not isinstance(visited, list):
        return

    visited_urls = {url for url in visited if isinstance(url, str)}
    expected_urls = authorization_endpoint_urls_from_log(log_entries)
    allow_visited_callback_probe = is_par_attempt_reuse_request_uri_module(log_entries)
    for url in urls:
        if not isinstance(url, str):
            continue
        if url not in expected_urls:
            continue
        if allow_visited_callback_probe and url not in visited_urls:
            continue
        if url in visited_urls and not allow_visited_callback_probe:
            continue
        key = f"{test_id}:browser:{'visited' if url in visited_urls else 'new'}:{url}"
        if key in state.handled_redirects:
            continue
        state.handled_redirects.add(key)
        if is_par_reuse_prior_to_auth_completion_module(log_entries):
            body = fetch_browser_control_url_without_callback(url, config, context)
        else:
            body = fetch_browser_control_url(url, config, context)
        mark_browser_url_visited(test_id, url, config, context)
        submit_implicit_urls(test_id, body, config, state, context)
        sys.stderr.write(f"OIDF browser driver marked authorization visit for {test_id}\n")


def has_logged_redirect(log_entries: list[Any]) -> bool:
    for entry in log_entries:
        if isinstance(entry, dict) and entry.get("http") == "redirect":
            return True
    return False


def redirect_url_for_module(redirect_url: str, log_entries: list[Any]) -> str:
    if not is_user_reject_module(log_entries):
        return redirect_url
    parsed = urllib.parse.urlparse(redirect_url)
    query_items = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    query_items.append((USER_REJECT_QUERY_PARAM, "1"))
    return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(query_items)))


def is_user_reject_module(log_entries: list[Any]) -> bool:
    return has_log_source(log_entries, USER_REJECT_TEST_NAME)


def is_par_reuse_prior_to_auth_completion_module(log_entries: list[Any]) -> bool:
    return has_log_source(log_entries, PAR_REUSE_PRIOR_TO_AUTH_COMPLETION_TEST_NAME)


def is_par_attempt_reuse_request_uri_module(log_entries: list[Any]) -> bool:
    return has_log_source(log_entries, PAR_ATTEMPT_REUSE_REQUEST_URI_TEST_NAME)


def has_log_source(log_entries: list[Any], expected_source: str) -> bool:
    for entry in log_entries:
        if not isinstance(entry, dict):
            continue
        source = entry.get("src")
        if isinstance(source, str) and source == expected_source:
            return True
    return False


def authorization_endpoint_urls_from_log(log_entries: list[Any]) -> set[str]:
    urls: set[str] = set()
    for entry in log_entries:
        if not isinstance(entry, dict):
            continue
        url = entry.get("redirect_to_authorization_endpoint")
        if isinstance(url, str):
            urls.add(url)
    return urls


def fetch_browser_control_url(
    raw_url: str, config: DriverConfig, context: ssl.SSLContext
) -> bytes:
    rewritten_url = rewrite_for_host_driver(raw_url, config)
    rewritten_url = localhost_fallback_url(rewritten_url)
    try:
        return fetch_url(rewritten_url, context)
    except RedirectRequired:
        return b""


def fetch_browser_control_url_without_callback(
    raw_url: str, config: DriverConfig, context: ssl.SSLContext
) -> bytes:
    rewritten_url = rewrite_for_host_driver(raw_url, config)
    rewritten_url = localhost_fallback_url(rewritten_url)
    try:
        fetch_url_without_redirect(rewritten_url, context)
    except RedirectRequired:
        return b""
    return b""


def mark_browser_url_visited(
    test_id: str, url: str, config: DriverConfig, context: ssl.SSLContext
) -> None:
    encoded_url = urllib.parse.urlencode({"url": url}).encode("utf-8")
    path = f"/api/runner/browser/{test_id}/visit"
    post_url = urllib.parse.urljoin(
        ensure_trailing_slash(config.conformance_server), path.lstrip("/")
    )
    request = urllib.request.Request(
        post_url,
        data=encoded_url,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS, context=context) as response:
            response.read()
    except urllib.error.HTTPError as error:
        raise DriverError(f"http_{error.code}") from error
    except urllib.error.URLError as error:
        raise DriverError("network_error") from error


def mark_browser_url_visited_if_available(
    test_id: str, url: str, config: DriverConfig, context: ssl.SSLContext
) -> None:
    try:
        mark_browser_url_visited(test_id, url, config, context)
    except DriverError:
        return


def drive_implicit_submits(
    test_id: str,
    log_entries: list[Any],
    config: DriverConfig,
    state: DriverState,
    context: ssl.SSLContext,
) -> None:
    for entry in log_entries:
        if not isinstance(entry, dict):
            continue
        implicit_submit = entry.get("implicit_submit")
        if not isinstance(implicit_submit, dict):
            continue
        full_url = implicit_submit.get("fullUrl")
        if not isinstance(full_url, str):
            continue
        submit_implicit_url(test_id, full_url, config, state, context)


def submit_implicit_urls(
    test_id: str,
    body: bytes,
    config: DriverConfig,
    state: DriverState,
    context: ssl.SSLContext,
) -> None:
    decoded = body.decode("utf-8", errors="ignore")
    for match in IMPLICIT_URL_PATTERN.finditer(decoded):
        submit_implicit_url(test_id, match.group(0), config, state, context)


def submit_implicit_url(
    test_id: str,
    implicit_url: str,
    config: DriverConfig,
    state: DriverState,
    context: ssl.SSLContext,
) -> None:
    key = f"{test_id}:{implicit_url}"
    if key in state.handled_implicit_submits:
        return
    state.handled_implicit_submits.add(key)
    fetch_url(rewrite_for_host_driver(implicit_url, config), context)
    sys.stderr.write(f"OIDF browser driver submitted implicit callback for {test_id}\n")


def fetch_json(base_url: str, path: str, context: ssl.SSLContext) -> Any:
    url = urllib.parse.urljoin(ensure_trailing_slash(base_url), path.lstrip("/"))
    body = fetch_url(url, context)
    try:
        return json.loads(body.decode("utf-8"))
    except json.JSONDecodeError as error:
        raise DriverError("invalid_json") from error


def fetch_url(url: str, context: ssl.SSLContext) -> bytes:
    return fetch_url_following_redirects(url, context, MAX_REDIRECTS)


def fetch_url_following_redirects(
    url: str, context: ssl.SSLContext, redirects_remaining: int
) -> bytes:
    rewritten_url = localhost_fallback_url(url)
    try:
        return fetch_url_without_redirect(rewritten_url, context)
    except RedirectRequired as redirect:
        if redirects_remaining <= 0:
            raise DriverError("too_many_redirects") from redirect
        redirected_url = urllib.parse.urljoin(rewritten_url, redirect.location)
        return fetch_url_following_redirects(redirected_url, context, redirects_remaining - 1)


def fetch_url_without_redirect(url: str, context: ssl.SSLContext) -> bytes:
    request = urllib.request.Request(url, method="GET")
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context), NoRedirectHandler
    )
    try:
        with opener.open(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            return response.read()
    except urllib.error.HTTPError as error:
        if 300 <= error.code <= 399:
            location = error.headers.get("Location")
            if location is not None:
                raise RedirectRequired(location) from error
        raise DriverError(f"http_{error.code}") from error
    except urllib.error.URLError as error:
        raise DriverError("network_error") from error


def localhost_fallback_url(raw_url: str) -> str:
    parsed = urllib.parse.urlparse(raw_url)
    hostname = parsed.hostname
    if hostname is None:
        return raw_url
    if hostname == "localhost" or hostname == "127.0.0.1":
        return raw_url
    if hostname != "host.docker.internal" and not hostname.endswith(LOCAL_HOST_SUFFIX):
        return raw_url
    port = f":{parsed.port}" if parsed.port is not None else ""
    return urllib.parse.urlunparse(parsed._replace(netloc=f"localhost{port}"))


def rewrite_for_host_driver(raw_url: str, config: DriverConfig) -> str:
    if config.issuer_netloc is None or config.healthcheck_netloc is None:
        return raw_url
    if config.issuer_netloc == config.healthcheck_netloc:
        return raw_url
    parsed = urllib.parse.urlparse(raw_url)
    if parsed.netloc != config.issuer_netloc:
        return raw_url
    return urllib.parse.urlunparse(parsed._replace(netloc=config.healthcheck_netloc))


def ensure_trailing_slash(value: str) -> str:
    if value.endswith("/"):
        return value
    return f"{value}/"


class DriverError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class RedirectRequired(Exception):
    def __init__(self, location: str) -> None:
        super().__init__("redirect_required")
        self.location = location


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> None:
        return None


if __name__ == "__main__":
    raise SystemExit(main())
