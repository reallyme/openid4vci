#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Tests for the PASSED-only OIDF suite export verifier."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("assert_oidf_results.py")
SPEC = importlib.util.spec_from_file_location("assert_oidf_results", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("OIDF result verifier could not be loaded")
VERIFIER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VERIFIER
SPEC.loader.exec_module(VERIFIER)

SUITE_VERSION = "5.3.1"
PLAN_VARIANT = {
    "credential_format": "sd_jwt_vc",
    "grant_management": "disabled",
    "vci_authorization_code_flow_variant": "wallet_initiated",
}
PLAN_VARIANT_KEYS = frozenset(PLAN_VARIANT)
EXPECTED_ALIAS = "reallyme-test-alias"


def suite_log(
    test_id: str,
    test_name: str,
    *,
    module_variant: dict[str, str] | None = None,
    result: str = "PASSED",
    plan_id: str = "execution_plan",
    version: str = SUITE_VERSION,
    status: str = "FINISHED",
    exported_version: str = SUITE_VERSION,
    alias: str = EXPECTED_ALIAS,
) -> dict[str, object]:
    variant = dict(PLAN_VARIANT)
    if module_variant is not None:
        variant.update(module_variant)
    return {
        "exportedVersion": exported_version,
        "testInfo": {
            "testId": test_id,
            "testName": test_name,
            "planId": plan_id,
            "alias": alias,
            "variant": variant,
            "version": version,
            "status": status,
            "result": result,
        },
    }


def inventory(
    modules: tuple[tuple[str, dict[str, str]], ...]
) -> object:
    digest_inputs = [
        VERIFIER.SuiteResult(
            test_name=name,
            module_variant=tuple(sorted(variant.items())),
            execution_plan_id="execution_plan",
        )
        for name, variant in modules
    ]
    return VERIFIER.ModuleInventory(
        module_ids=frozenset(name for name, _ in modules),
        module_variant_sha256=VERIFIER.module_variant_digest(digest_inputs),
        suite_version=SUITE_VERSION,
        expected_plan_variant=tuple(sorted(PLAN_VARIANT.items())),
        plan_variant_keys=PLAN_VARIANT_KEYS,
        expected_alias=EXPECTED_ALIAS,
    )


class OidfResultTests(unittest.TestCase):
    def write_export(
        self, directory: Path, logs: dict[str, dict[str, object]]
    ) -> None:
        directory.mkdir()
        with zipfile.ZipFile(directory / "suite.zip", "w") as bundle:
            for name, payload in logs.items():
                bundle.writestr(name, json.dumps(payload))

    def verify(
        self,
        logs: dict[str, dict[str, object]],
        expected_modules: tuple[tuple[str, dict[str, str]], ...],
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            export_dir = Path(directory) / "export"
            self.write_export(export_dir, logs)
            VERIFIER.verify_results(
                export_dir, len(expected_modules), inventory(expected_modules)
            )

    def test_accepts_exact_complete_passing_inventory(self) -> None:
        modules = (
            ("first_module", {"module_case": "one"}),
            ("second_module", {}),
        )
        self.verify(
            {
                "first.json": suite_log(
                    "first_test", "first_module", module_variant=modules[0][1]
                ),
                "second.json": suite_log("second_test", "second_module"),
            },
            modules,
        )

        nested = suite_log("first_test", "first_module")
        test_info = nested["testInfo"]
        if not isinstance(test_info, dict):
            self.fail("test fixture has invalid testInfo")
        test_info["variant"] = {"variant": dict(PLAN_VARIANT)}
        self.verify({"first.json": nested}, (("first_module", {}),))

    def test_rejects_nonpassing_partial_duplicate_and_replacement_logs(self) -> None:
        modules = (("first_module", {}), ("second_module", {}))
        cases = {
            "skipped": (
                {
                    "first.json": suite_log(
                        "first_test", "first_module", result="SKIPPED"
                    ),
                    "second.json": suite_log("second_test", "second_module"),
                },
                "non_passing_suite_test",
            ),
            "partial": (
                {"first.json": suite_log("first_test", "first_module")},
                "suite_module_count_mismatch",
            ),
            "duplicate": (
                {
                    "first.json": suite_log("same_test", "first_module"),
                    "second.json": suite_log("same_test", "second_module"),
                },
                "duplicate_suite_test_id",
            ),
            "replacement": (
                {
                    "first.json": suite_log("first_test", "first_module"),
                    "second.json": suite_log("second_test", "replacement_module"),
                },
                "suite_module_inventory_mismatch",
            ),
        }
        for name, (logs, error_code) in cases.items():
            with self.subTest(name=name), self.assertRaisesRegex(
                VERIFIER.ResultError, error_code
            ):
                self.verify(logs, modules)

    def test_rejects_wrong_module_variant_and_mixed_execution_plans(self) -> None:
        modules = (("first_module", {"module_case": "one"}),)
        cases = {
            "variant": (
                suite_log(
                    "first_test",
                    "first_module",
                    module_variant={"module_case": "two"},
                ),
                "suite_module_variant_mismatch",
            ),
            "plan_variant": (
                suite_log(
                    "first_test",
                    "first_module",
                    module_variant={"credential_format": "mdoc"},
                ),
                "suite_plan_variant_mismatch",
            ),
        }
        for name, (log, error_code) in cases.items():
            with self.subTest(name=name), self.assertRaisesRegex(
                VERIFIER.ResultError, error_code
            ):
                self.verify({"first.json": log}, modules)

        with self.assertRaisesRegex(
            VERIFIER.ResultError, "mixed_suite_execution_plan_ids"
        ):
            self.verify(
                {
                    "first.json": suite_log("first_test", "first_module"),
                    "second.json": suite_log(
                        "second_test", "second_module", plan_id="other_plan"
                    ),
                },
                (("first_module", {}), ("second_module", {})),
            )

    def test_rejects_wrong_export_metadata(self) -> None:
        modules = (("first_module", {}),)
        cases = {
            "export_version": (
                suite_log(
                    "first_test", "first_module", exported_version="5.2.4"
                ),
                "suite_export_version_mismatch",
            ),
            "test_version": (
                suite_log("first_test", "first_module", version="5.2.4"),
                "suite_test_version_mismatch",
            ),
            "status": (
                suite_log("first_test", "first_module", status="RUNNING"),
                "unfinished_suite_test",
            ),
            "alias": (
                suite_log("first_test", "first_module", alias="other-alias"),
                "suite_alias_mismatch",
            ),
        }
        for name, (log, error_code) in cases.items():
            with self.subTest(name=name), self.assertRaisesRegex(
                VERIFIER.ResultError, error_code
            ):
                self.verify({"first.json": log}, modules)

    def test_rejects_noncanonical_expected_counts_and_plan_expressions(self) -> None:
        for value in ("", "0", "01", "-1", "not-a-number"):
            with self.subTest(value=value), self.assertRaises(
                VERIFIER.ResultError
            ):
                VERIFIER.parse_expected_count(value)
        for expression in (
            "wallet-plan",
            "wallet-plan[credential_format=sd_jwt_vc]junk",
            "wallet-plan[credential_format=sd_jwt_vc][credential_format=mdoc]",
        ):
            with self.subTest(expression=expression), self.assertRaises(
                VERIFIER.ResultError
            ):
                VERIFIER.parse_plan_expression(expression)

    def test_rejects_duplicate_json_object_keys(self) -> None:
        body = b'{"testInfo":{"testId":"first","testId":"second"}}'
        with self.assertRaisesRegex(VERIFIER.ResultError, "invalid_suite_test_log"):
            VERIFIER.decode_json(body)

    def test_reads_one_unique_plan_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            inventory_path = Path(directory) / "inventory.json"
            inventory_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "suite_version": SUITE_VERSION,
                        "plans": [
                            {
                                "plan_id": "wallet-plan",
                                "module_variant_sha256": "a" * 64,
                                "plan_variant_keys": ["credential_format"],
                                "default_plan_variant": {},
                                "module_ids": ["first_module", "second_module"],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            parsed = VERIFIER.read_module_inventory(
                inventory_path,
                "wallet-plan[credential_format=sd_jwt_vc]",
                2,
                EXPECTED_ALIAS,
            )
            self.assertEqual(
                parsed.module_ids,
                frozenset(("first_module", "second_module")),
            )
            self.assertEqual(parsed.suite_version, SUITE_VERSION)


if __name__ == "__main__":
    unittest.main()
