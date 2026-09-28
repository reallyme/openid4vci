#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Unit tests for bounded OIDF wallet plan discovery."""

from __future__ import annotations

import importlib
import sys
import unittest
from dataclasses import dataclass
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("oidf_wallet_plan.py")
sys.path.insert(0, str(MODULE_PATH.parent))
PLAN = importlib.import_module("oidf_wallet_plan")


@dataclass(frozen=True)
class Selection:
    plan_id: str = "wallet-plan"
    alias: str | None = "wallet-alias"
    started_after_epoch_seconds: float = 1_700_000_000.0


def page(*plans: dict[str, object]) -> dict[str, object]:
    return {"data": list(plans)}


def plan(started: str, alias: str = "wallet-alias") -> dict[str, object]:
    return {
        "planName": "wallet-plan",
        "started": started,
        "config": {"alias": alias},
    }


class WalletPlanDiscoveryTests(unittest.TestCase):
    def test_fetches_bounded_pages_and_selects_the_newest_match(self) -> None:
        first = [plan("2023-01-01T00:00:00Z") for _ in range(PLAN.PLAN_PAGE_SIZE)]
        pages = {
            0: page(*first),
            PLAN.PLAN_PAGE_SIZE: page(plan("2026-09-21T01:00:00Z")),
        }
        requested: list[int] = []

        def fetch(start: int) -> object:
            requested.append(start)
            return pages[start]

        selected = PLAN.discover_newest_matching_plan(fetch, Selection())

        self.assertEqual(selected, pages[PLAN.PLAN_PAGE_SIZE]["data"][0])
        self.assertEqual(requested, [0, PLAN.PLAN_PAGE_SIZE])

    def test_scans_back_over_a_newer_nonmatching_alias(self) -> None:
        first = [plan("2023-01-01T00:00:00Z") for _ in range(PLAN.PLAN_PAGE_SIZE)]
        matching = plan("2026-09-21T01:00:00Z")
        pages = {
            0: page(*first),
            PLAN.PLAN_PAGE_SIZE: page(
                matching, plan("2026-09-21T02:00:00Z", "other-alias")
            ),
        }

        selected = PLAN.discover_newest_matching_plan(
            lambda start: pages[start], Selection()
        )

        self.assertEqual(selected, matching)

    def test_returns_none_after_the_last_page_when_no_fresh_plan_exists(self) -> None:
        pages = {0: page(plan("2023-01-01T00:00:00Z"))}
        requested: list[int] = []

        def fetch(start: int) -> object:
            requested.append(start)
            return pages[start]

        self.assertIsNone(PLAN.discover_newest_matching_plan(fetch, Selection()))
        self.assertEqual(requested, [0])

    def test_rejects_invalid_and_oversized_pages(self) -> None:
        for payload in ({}, {"data": "invalid"}, {"data": [None] * 21}):
            with self.subTest(payload=payload), self.assertRaisesRegex(
                PLAN.PlanDiscoveryError, "invalid_plan_listing"
            ):
                PLAN.discover_newest_matching_plan(
                    lambda _start, value=payload: value, Selection()
                )

    def test_rejects_a_scan_beyond_the_discovery_bound(self) -> None:
        with self.assertRaisesRegex(
            PLAN.PlanDiscoveryError, "plan_discovery_limit_exceeded"
        ):
            PLAN.discover_newest_matching_plan(
                lambda _start: page(
                    *[
                        plan("2026-09-21T01:00:00Z", "other-alias")
                        for _ in range(PLAN.PLAN_PAGE_SIZE)
                    ]
                ),
                Selection(),
            )

    def test_builds_only_bounded_nonnegative_page_paths(self) -> None:
        self.assertEqual(PLAN.plan_listing_path(40), "/api/plan?start=40&length=20")
        for invalid in (-1, True):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(
                PLAN.PlanDiscoveryError, "invalid_plan_page"
            ):
                PLAN.plan_listing_path(invalid)


if __name__ == "__main__":
    unittest.main()
