#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Bounded discovery of the current OIDF wallet test-plan execution."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Callable, Protocol


PLAN_PAGE_SIZE = 20
MAX_PLAN_DISCOVERY_PAGES = 64


class PlanDiscoveryError(Exception):
    """Stable plan-discovery failure without retaining suite response data."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class PlanSelection(Protocol):
    plan_id: str
    alias: str | None
    started_after_epoch_seconds: float


def newest_matching_plan(
    payload: Any, selection: PlanSelection
) -> dict[str, Any] | None:
    """Select only a freshly-created plan matching the configured alias."""
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
        return None
    matches: list[dict[str, Any]] = []
    for item in payload["data"]:
        if not isinstance(item, dict) or item.get("planName") != selection.plan_id:
            continue
        started = parse_oidf_epoch_seconds(item.get("started"))
        if started is None or started < selection.started_after_epoch_seconds:
            continue
        item_config = item.get("config")
        if selection.alias is not None and (
            not isinstance(item_config, dict)
            or item_config.get("alias") != selection.alias
        ):
            continue
        matches.append(item)
    if not matches:
        return None
    matches.sort(key=lambda item: str(item.get("started", "")))
    return matches[-1]


def discover_newest_matching_plan(
    fetch_page: Callable[[int], Any], selection: PlanSelection
) -> dict[str, Any] | None:
    """Scan ascending suite pages while bounding every response and the total scan."""
    selected = None
    for page_index in range(MAX_PLAN_DISCOVERY_PAGES):
        start = page_index * PLAN_PAGE_SIZE
        page = fetch_page(start)
        data = plan_page_data(page)
        if data is None:
            raise PlanDiscoveryError("invalid_plan_listing")
        plan = newest_matching_plan(page, selection)
        if plan is not None:
            selected = plan
        if len(data) < PLAN_PAGE_SIZE:
            return selected
    raise PlanDiscoveryError("plan_discovery_limit_exceeded")


def plan_page_data(payload: Any) -> list[Any] | None:
    """Validate one bounded page from the suite's DataTables endpoint."""
    if not isinstance(payload, dict):
        return None
    data = payload.get("data")
    if not isinstance(data, list) or len(data) > PLAN_PAGE_SIZE:
        return None
    return data


def parse_oidf_epoch_seconds(raw: Any) -> float | None:
    """Parse the suite's nanosecond timestamp without losing timezone binding."""
    if not isinstance(raw, str):
        return None
    normalized = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
    normalized = trim_fractional_seconds(normalized)
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def trim_fractional_seconds(value: str) -> str:
    """Trim fractional seconds to the precision accepted by datetime."""
    match = re.match(r"^(.*\.)(\d+)([+-]\d\d:\d\d)?$", value)
    if match is None or len(match.group(2)) <= 6:
        return value
    timezone_suffix = match.group(3) or ""
    return f"{match.group(1)}{match.group(2)[:6]}{timezone_suffix}"


def plan_listing_path(start: int = 0) -> str:
    """Return the bounded plan-listing endpoint."""
    if isinstance(start, bool) or start < 0:
        raise PlanDiscoveryError("invalid_plan_page")
    return f"/api/plan?start={start}&length={PLAN_PAGE_SIZE}"
