#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Bind passing OIDF wallet logs to redacted composed-implementation evidence."""

from __future__ import annotations

import json
import re
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from oidf_wallet_outcome_policy import (
    OutcomePolicyError,
    expected_outcome,
    validate_observed_outcome,
)


MAX_ARCHIVES = 8
MAX_LOGS_PER_ARCHIVE = 2048
MAX_LOG_BYTES = 16 * 1024 * 1024
TEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
EXPECTED_EVIDENCE_KEYS = {
    "schema_version",
    "test_id",
    "module_id",
    "launch_mode",
    "flow_status",
    "flow_reason",
}
ALLOWED_LAUNCH_MODES = {"wallet_initiated", "issuer_initiated"}


@dataclass(frozen=True)
class ExportedResult:
    module_id: str
    result: str


class EvidenceError(Exception):
    """Privacy-safe evidence validation failure."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def main(arguments: list[str]) -> int:
    if len(arguments) != 4:
        sys.stderr.write(
            "usage: assert_oidf_wallet_implementation_evidence.py "
            "<suite-export-dir> <implementation-evidence-dir> <launch-mode>\n"
        )
        return 64
    try:
        verify_evidence(Path(arguments[1]), Path(arguments[2]), arguments[3])
    except EvidenceError as error:
        sys.stderr.write(f"OIDF wallet implementation evidence failed: {error.code}\n")
        return 70
    return 0


def verify_evidence(export_dir: Path, evidence_dir: Path, launch_mode: str) -> None:
    if launch_mode not in ALLOWED_LAUNCH_MODES:
        raise EvidenceError("invalid_launch_mode")
    exported_results = read_exported_results(export_dir)
    passed_ids = {
        test_id
        for test_id, exported in exported_results.items()
        if exported.result == "PASSED"
    }
    if not passed_ids:
        raise EvidenceError("missing_passing_suite_tests")
    evidence = read_implementation_evidence(evidence_dir, launch_mode)
    evidence_ids = set(evidence)
    if not passed_ids.issubset(evidence_ids):
        raise EvidenceError("missing_implementation_evidence")
    if not evidence_ids.issubset(set(exported_results)):
        raise EvidenceError("unbound_implementation_evidence")
    for test_id in passed_ids:
        if evidence[test_id].get("module_id") != exported_results[test_id].module_id:
            raise EvidenceError("implementation_module_mismatch")


def read_exported_results(export_dir: Path) -> dict[str, ExportedResult]:
    if not export_dir.is_dir():
        raise EvidenceError("missing_suite_export_dir")
    archives = sorted(export_dir.glob("*.zip"))
    if not archives or len(archives) > MAX_ARCHIVES:
        raise EvidenceError("invalid_suite_export_count")
    results: dict[str, ExportedResult] = {}
    for archive in archives:
        read_export_archive(archive, results)
    if not results:
        raise EvidenceError("missing_suite_test_logs")
    return results


def read_export_archive(
    archive: Path, results: dict[str, ExportedResult]
) -> None:
    try:
        with zipfile.ZipFile(archive) as bundle:
            log_entries = [
                entry
                for entry in bundle.infolist()
                if not entry.is_dir() and entry.filename.endswith(".json")
            ]
            if not log_entries or len(log_entries) > MAX_LOGS_PER_ARCHIVE:
                raise EvidenceError("invalid_suite_log_count")
            for entry in log_entries:
                if entry.file_size <= 0 or entry.file_size > MAX_LOG_BYTES:
                    raise EvidenceError("invalid_suite_log_size")
                payload = decode_json(bundle.read(entry))
                record_exported_result(payload, results)
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        raise EvidenceError("invalid_suite_export") from error


def record_exported_result(
    payload: Any, results: dict[str, ExportedResult]
) -> None:
    if not isinstance(payload, dict) or not isinstance(payload.get("testInfo"), dict):
        raise EvidenceError("invalid_suite_test_log")
    test_info = payload["testInfo"]
    test_id = test_info.get("testId")
    module_id = test_info.get("testName")
    result = test_info.get("result")
    if not isinstance(test_id, str) or TEST_ID_PATTERN.fullmatch(test_id) is None:
        raise EvidenceError("invalid_suite_test_id")
    if result != "PASSED":
        raise EvidenceError("non_passing_suite_test")
    if not isinstance(module_id, str):
        raise EvidenceError("invalid_suite_module_id")
    try:
        expected_outcome(module_id)
    except OutcomePolicyError as error:
        raise EvidenceError(error.code) from error
    existing = results.get(test_id)
    exported = ExportedResult(module_id=module_id, result=result)
    if existing is not None and existing != exported:
        raise EvidenceError("conflicting_suite_test_result")
    results[test_id] = exported


def read_implementation_evidence(
    evidence_dir: Path, launch_mode: str
) -> dict[str, dict[str, Any]]:
    if not evidence_dir.is_dir():
        raise EvidenceError("missing_implementation_evidence_dir")
    records: dict[str, dict[str, Any]] = {}
    try:
        entries = sorted(evidence_dir.iterdir())
    except OSError as error:
        raise EvidenceError("implementation_evidence_read_failed") from error
    if not entries:
        raise EvidenceError("missing_implementation_evidence")
    for entry in entries:
        if not entry.is_file() or entry.suffix != ".json":
            raise EvidenceError("invalid_implementation_evidence_entry")
        test_id = entry.stem
        if TEST_ID_PATTERN.fullmatch(test_id) is None:
            raise EvidenceError("invalid_implementation_test_id")
        try:
            if entry.stat().st_size <= 0 or entry.stat().st_size > MAX_LOG_BYTES:
                raise EvidenceError("invalid_implementation_evidence_size")
            payload = decode_json(entry.read_bytes())
        except OSError as error:
            raise EvidenceError("implementation_evidence_read_failed") from error
        validate_implementation_record(payload, test_id, launch_mode)
        records[test_id] = payload
    return records


def validate_implementation_record(
    payload: Any, test_id: str, launch_mode: str
) -> None:
    if not isinstance(payload, dict) or set(payload) != EXPECTED_EVIDENCE_KEYS:
        raise EvidenceError("invalid_implementation_evidence")
    if payload.get("schema_version") != 2 or payload.get("test_id") != test_id:
        raise EvidenceError("invalid_implementation_evidence")
    if payload.get("launch_mode") != launch_mode:
        raise EvidenceError("implementation_launch_mode_mismatch")
    module_id = payload.get("module_id")
    if not isinstance(module_id, str):
        raise EvidenceError("invalid_implementation_evidence")
    try:
        validate_observed_outcome(
            module_id, payload.get("flow_status"), payload.get("flow_reason")
        )
    except OutcomePolicyError as error:
        raise EvidenceError(error.code) from error


def decode_json(body: bytes) -> Any:
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError("invalid_json") from error


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
