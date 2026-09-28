#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Tests for authenticated local and hosted OIDF plan execution modes."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[2]
WRAPPER = REPOSITORY / "scripts/conformance/execute_oidf_test_plan.sh"


class ExecuteOidfTestPlanTests(unittest.TestCase):
    def run_wrapper(
        self, mode: str | None, extra_environment: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            runner = temporary / "runner.py"
            runner.write_text(
                "import json, os, sys\n"
                "print(json.dumps({'dev': os.getenv('CONFORMANCE_DEV_MODE'), "
                "'token': os.getenv('CONFORMANCE_TOKEN'), 'args': sys.argv[1:]}))\n",
                encoding="utf-8",
            )
            config = temporary / "config.json"
            config.write_text("{}\n", encoding="utf-8")
            environment = os.environ.copy()
            for name in (
                "CONFORMANCE_DEV_MODE",
                "CONFORMANCE_TOKEN",
                "OIDF_CONFORMANCE_MODE",
            ):
                environment.pop(name, None)
            if mode is not None:
                environment["OIDF_CONFORMANCE_MODE"] = mode
            if extra_environment is not None:
                environment.update(extra_environment)
            return subprocess.run(
                [
                    str(WRAPPER),
                    str(runner),
                    str(temporary / "export"),
                    "test-plan[variant=value]",
                    str(config),
                ],
                cwd=REPOSITORY,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )

    def test_local_mode_explicitly_enables_developer_authentication(self) -> None:
        result = self.run_wrapper("local")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["dev"], "1")
        self.assertIsNone(payload["token"])

    def test_hosted_mode_preserves_token_without_developer_mode(self) -> None:
        result = self.run_wrapper(
            "hosted",
            {
                "CONFORMANCE_TOKEN": "test-token",
                "CONFORMANCE_SERVER": "https://certification.example/",
                "CONFORMANCE_SERVER_MTLS": "https://mtls.certification.example/",
            },
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertIsNone(payload["dev"])
        self.assertEqual(payload["token"], "test-token")

    def test_ambiguous_or_unsafe_modes_fail_closed(self) -> None:
        cases = {
            "missing_mode": (None, {}, "mode_must_be_local_or_hosted"),
            "local_with_token": (
                "local",
                {"CONFORMANCE_TOKEN": "test-token"},
                "local_mode_forbids_conformance_token",
            ),
            "hosted_without_token": (
                "hosted",
                {
                    "CONFORMANCE_SERVER": "https://certification.example/",
                    "CONFORMANCE_SERVER_MTLS": "https://mtls.certification.example/",
                },
                "hosted_mode_requires_conformance_token",
            ),
            "hosted_developer_mode": (
                "hosted",
                {
                    "CONFORMANCE_DEV_MODE": "1",
                    "CONFORMANCE_TOKEN": "test-token",
                    "CONFORMANCE_SERVER": "https://certification.example/",
                    "CONFORMANCE_SERVER_MTLS": "https://mtls.certification.example/",
                },
                "hosted_mode_forbids_developer_mode",
            ),
            "hosted_local_server": (
                "hosted",
                {
                    "CONFORMANCE_TOKEN": "test-token",
                    "CONFORMANCE_SERVER": "https://localhost:8443/",
                    "CONFORMANCE_SERVER_MTLS": "https://localhost:8444/",
                },
                "hosted_mode_requires_public_server",
            ),
        }
        for name, (mode, environment, error_code) in cases.items():
            with self.subTest(name=name):
                result = self.run_wrapper(mode, environment)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(error_code, result.stderr)


if __name__ == "__main__":
    unittest.main()
