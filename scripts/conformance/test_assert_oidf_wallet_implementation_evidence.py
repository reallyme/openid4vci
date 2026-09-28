#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Tests for composed wallet evidence binding."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


MODULE_PATH = Path(__file__).with_name(
    "assert_oidf_wallet_implementation_evidence.py"
)
SPEC = importlib.util.spec_from_file_location(
    "assert_oidf_wallet_implementation_evidence", MODULE_PATH
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("wallet implementation evidence verifier could not be loaded")
VERIFIER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VERIFIER
SPEC.loader.exec_module(VERIFIER)


POSITIVE_MODULE = "oid4vci-1_0-wallet-test-credential-issuance"
REJECTION_MODULE = (
    "fapi2-security-profile-final-client-test-discovery-issuer-mismatch"
)


def suite_log(
    test_id: str, result: str, module_id: str = POSITIVE_MODULE
) -> dict[str, object]:
    return {
        "testInfo": {
            "testId": test_id,
            "testName": module_id,
            "result": result,
        }
    }


def implementation_evidence(
    test_id: str,
    module_id: str = POSITIVE_MODULE,
    flow_status: str = "credential_stored",
    flow_reason: str | None = None,
) -> dict[str, object]:
    return {
        "schema_version": 2,
        "test_id": test_id,
        "module_id": module_id,
        "launch_mode": "wallet_initiated",
        "flow_status": flow_status,
        "flow_reason": flow_reason,
    }


class WalletImplementationEvidenceTests(unittest.TestCase):
    def write_export(self, directory: Path, logs: dict[str, dict[str, object]]) -> None:
        directory.mkdir()
        with zipfile.ZipFile(directory / "suite.zip", "w") as bundle:
            for name, payload in logs.items():
                bundle.writestr(name, json.dumps(payload))

    def write_evidence(
        self, directory: Path, records: dict[str, dict[str, object]]
    ) -> None:
        directory.mkdir()
        for test_id, payload in records.items():
            (directory / f"{test_id}.json").write_text(
                json.dumps(payload), encoding="utf-8"
            )

    def test_accepts_bound_evidence_for_every_passing_test(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            export_dir = root / "export"
            evidence_dir = root / "evidence"
            self.write_export(
                export_dir,
                {"passed.json": suite_log("passed_test", "PASSED")},
            )
            self.write_evidence(
                evidence_dir,
                {"passed_test": implementation_evidence("passed_test")},
            )
            VERIFIER.verify_evidence(
                export_dir, evidence_dir, "wallet_initiated"
            )

    def test_rejects_missing_passing_test_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            export_dir = root / "export"
            evidence_dir = root / "evidence"
            self.write_export(
                export_dir,
                {"passed.json": suite_log("passed_test", "PASSED")},
            )
            self.write_evidence(
                evidence_dir,
                {"different_test": implementation_evidence("different_test")},
            )
            with self.assertRaisesRegex(
                VERIFIER.EvidenceError, "missing_implementation_evidence"
            ):
                VERIFIER.verify_evidence(
                    export_dir, evidence_dir, "wallet_initiated"
                )

    def test_rejects_unredacted_or_wrong_mode_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            export_dir = root / "export"
            evidence_dir = root / "evidence"
            self.write_export(
                export_dir,
                {"passed.json": suite_log("passed_test", "PASSED")},
            )
            record = implementation_evidence("passed_test")
            record["credential_issuer"] = "https://issuer.example"
            self.write_evidence(evidence_dir, {"passed_test": record})
            with self.assertRaisesRegex(
                VERIFIER.EvidenceError, "invalid_implementation_evidence"
            ):
                VERIFIER.verify_evidence(
                    export_dir, evidence_dir, "issuer_initiated"
                )

    def test_rejects_failed_and_skipped_suite_logs(self) -> None:
        for result in ("FAILED", "SKIPPED"):
            with self.subTest(result=result), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                export_dir = root / "export"
                evidence_dir = root / "evidence"
                self.write_export(
                    export_dir,
                    {"non_passing.json": suite_log("non_passing_test", result)},
                )
                self.write_evidence(
                    evidence_dir,
                    {
                        "non_passing_test": implementation_evidence(
                            "non_passing_test"
                        )
                    },
                )
                with self.assertRaisesRegex(
                    VERIFIER.EvidenceError, "non_passing_suite_test"
                ):
                    VERIFIER.verify_evidence(
                        export_dir, evidence_dir, "wallet_initiated"
                    )

    def test_rejects_deferred_transaction_before_credential_storage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            export_dir = root / "export"
            evidence_dir = root / "evidence"
            self.write_export(
                export_dir,
                {"passed.json": suite_log("passed_test", "PASSED")},
            )
            record = implementation_evidence("passed_test")
            record["flow_status"] = "deferred_credential_pending"
            self.write_evidence(evidence_dir, {"passed_test": record})
            with self.assertRaisesRegex(
                VERIFIER.EvidenceError, "wallet_flow_outcome_mismatch"
            ):
                VERIFIER.verify_evidence(
                    export_dir, evidence_dir, "wallet_initiated"
                )

    def test_accepts_source_bound_protocol_rejection_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            export_dir = root / "export"
            evidence_dir = root / "evidence"
            self.write_export(
                export_dir,
                {
                    "rejected.json": suite_log(
                        "rejected_test", "PASSED", REJECTION_MODULE
                    )
                },
            )
            self.write_evidence(
                evidence_dir,
                {
                    "rejected_test": implementation_evidence(
                        "rejected_test",
                        REJECTION_MODULE,
                        "protocol_rejected",
                        "authorization_server_issuer_mismatch",
                    )
                },
            )
            VERIFIER.verify_evidence(
                export_dir, evidence_dir, "wallet_initiated"
            )

    def test_rejects_evidence_bound_to_a_different_suite_module(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            export_dir = root / "export"
            evidence_dir = root / "evidence"
            self.write_export(
                export_dir,
                {
                    "rejected.json": suite_log(
                        "rejected_test", "PASSED", REJECTION_MODULE
                    )
                },
            )
            self.write_evidence(
                evidence_dir,
                {"rejected_test": implementation_evidence("rejected_test")},
            )
            with self.assertRaisesRegex(
                VERIFIER.EvidenceError, "implementation_module_mismatch"
            ):
                VERIFIER.verify_evidence(
                    export_dir, evidence_dir, "wallet_initiated"
                )


if __name__ == "__main__":
    unittest.main()
