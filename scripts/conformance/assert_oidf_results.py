#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Verify one complete, PASSED-only OIDF suite export."""

from __future__ import annotations

import hashlib
import json
import re
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


MAX_ARCHIVES = 8
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_LOGS_PER_ARCHIVE = 2_048
MAX_LOG_BYTES = 16 * 1024 * 1024
MAX_TOTAL_LOG_BYTES = 64 * 1024 * 1024
MAX_VARIANT_VALUE_LENGTH = 128
TEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
ALIAS_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
PLAN_SELECTION_PATTERN = re.compile(
    r"\[([A-Za-z0-9_]{1,128})=([A-Za-z0-9_.-]{1,128})\]"
)


class ResultError(Exception):
    """Stable verification failure without exported test content."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class InvalidJsonValueError(ValueError):
    """Internal marker for ambiguous or non-standard JSON values."""


@dataclass(frozen=True)
class ModuleInventory:
    """Pinned suite contract needed to verify one selected plan."""

    module_ids: frozenset[str]
    module_variant_sha256: str
    suite_version: str
    expected_plan_variant: tuple[tuple[str, str], ...]
    plan_variant_keys: frozenset[str]
    expected_alias: str


@dataclass(frozen=True)
class SuiteResult:
    """Security-relevant fields retained from one exported test log."""

    test_name: str
    module_variant: tuple[tuple[str, str], ...]
    execution_plan_id: str


def main(arguments: list[str]) -> int:
    if len(arguments) != 6:
        sys.stderr.write(
            "usage: assert_oidf_results.py <suite-export-dir> "
            "<expected-log-count> <module-inventory> <plan-expression> "
            "<expected-alias>\n"
        )
        return 64
    try:
        expected_log_count = parse_expected_count(arguments[2])
        inventory = read_module_inventory(
            Path(arguments[3]), arguments[4], expected_log_count, arguments[5]
        )
        verify_results(Path(arguments[1]), expected_log_count, inventory)
    except ResultError as error:
        sys.stderr.write(f"OIDF suite export verification failed: {error.code}\n")
        return 70
    return 0


def parse_expected_count(value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as error:
        raise ResultError("invalid_expected_log_count") from error
    if parsed <= 0 or str(parsed) != value:
        raise ResultError("invalid_expected_log_count")
    return parsed


def parse_plan_expression(plan_expression: str) -> tuple[str, dict[str, str]]:
    plan_id, separator, selections = plan_expression.partition("[")
    if TEST_ID_PATTERN.fullmatch(plan_id) is None or not separator:
        raise ResultError("invalid_plan_expression")
    selections = f"[{selections}"
    parsed: dict[str, str] = {}
    position = 0
    while position < len(selections):
        match = PLAN_SELECTION_PATTERN.match(selections, position)
        if match is None or match.group(1) in parsed:
            raise ResultError("invalid_plan_expression")
        parsed[match.group(1)] = match.group(2)
        position = match.end()
    if not parsed:
        raise ResultError("invalid_plan_expression")
    return plan_id, parsed


def read_module_inventory(
    inventory_path: Path,
    plan_expression: str,
    expected_log_count: int,
    expected_alias: str,
) -> ModuleInventory:
    if ALIAS_PATTERN.fullmatch(expected_alias) is None:
        raise ResultError("invalid_expected_alias")
    try:
        payload = json.loads(
            inventory_path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonfinite_number,
        )
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        InvalidJsonValueError,
        RecursionError,
    ) as error:
        raise ResultError("invalid_module_inventory") from error
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise ResultError("invalid_module_inventory")

    suite_version = payload.get("suite_version")
    plans = payload.get("plans")
    if (
        not isinstance(suite_version, str)
        or VERSION_PATTERN.fullmatch(suite_version) is None
        or not isinstance(plans, list)
    ):
        raise ResultError("invalid_module_inventory")

    plan_id, expected_plan_variant = parse_plan_expression(plan_expression)
    matching = [
        plan
        for plan in plans
        if isinstance(plan, dict) and plan.get("plan_id") == plan_id
    ]
    if len(matching) != 1:
        raise ResultError("invalid_module_inventory")
    plan = matching[0]
    module_ids = plan.get("module_ids")
    module_variant_sha256 = plan.get("module_variant_sha256")
    plan_variant_keys = plan.get("plan_variant_keys")
    default_plan_variant = plan.get("default_plan_variant")
    if (
        not isinstance(module_ids, list)
        or not isinstance(module_variant_sha256, str)
        or SHA256_PATTERN.fullmatch(module_variant_sha256) is None
        or not isinstance(plan_variant_keys, list)
        or not plan_variant_keys
        or not isinstance(default_plan_variant, dict)
    ):
        raise ResultError("invalid_module_inventory")
    if (
        not module_ids
        or len(module_ids) > expected_log_count
        or any(
            not isinstance(module_id, str)
            or TEST_ID_PATTERN.fullmatch(module_id) is None
            for module_id in module_ids
        )
        or any(
            not isinstance(key, str) or TEST_ID_PATTERN.fullmatch(key) is None
            for key in plan_variant_keys
        )
        or any(
            not isinstance(key, str)
            or TEST_ID_PATTERN.fullmatch(key) is None
            or not isinstance(value, str)
            or not value
            or len(value) > MAX_VARIANT_VALUE_LENGTH
            for key, value in default_plan_variant.items()
        )
    ):
        raise ResultError("invalid_module_inventory")
    unique_ids = frozenset(module_ids)
    unique_plan_keys = frozenset(plan_variant_keys)
    if (
        len(unique_ids) != len(module_ids)
        or len(unique_plan_keys) != len(plan_variant_keys)
        or not frozenset(expected_plan_variant).issubset(unique_plan_keys)
        or not frozenset(default_plan_variant).issubset(unique_plan_keys)
    ):
        raise ResultError("invalid_module_inventory")
    resolved_plan_variant = dict(default_plan_variant)
    resolved_plan_variant.update(expected_plan_variant)
    return ModuleInventory(
        module_ids=unique_ids,
        module_variant_sha256=module_variant_sha256,
        suite_version=suite_version,
        expected_plan_variant=tuple(sorted(resolved_plan_variant.items())),
        plan_variant_keys=unique_plan_keys,
        expected_alias=expected_alias,
    )


def verify_results(
    export_dir: Path,
    expected_log_count: int,
    inventory: ModuleInventory,
) -> None:
    if not export_dir.is_dir():
        raise ResultError("missing_suite_export_dir")
    archives = sorted(export_dir.glob("*.zip"))
    if not archives or len(archives) > MAX_ARCHIVES:
        raise ResultError("invalid_suite_export_count")

    results: dict[str, SuiteResult] = {}
    total_log_bytes = 0
    for archive in archives:
        try:
            if (
                archive.is_symlink()
                or not archive.is_file()
                or archive.stat().st_size <= 0
                or archive.stat().st_size > MAX_ARCHIVE_BYTES
            ):
                raise ResultError("invalid_suite_archive")
            total_log_bytes = read_archive(
                archive, results, total_log_bytes, inventory
            )
        except OSError as error:
            raise ResultError("suite_export_read_failed") from error

    if len(results) != expected_log_count:
        raise ResultError("suite_module_count_mismatch")
    if frozenset(result.test_name for result in results.values()) != inventory.module_ids:
        raise ResultError("suite_module_inventory_mismatch")
    if len({result.execution_plan_id for result in results.values()}) != 1:
        raise ResultError("mixed_suite_execution_plan_ids")
    if module_variant_digest(results.values()) != inventory.module_variant_sha256:
        raise ResultError("suite_module_variant_mismatch")


def read_archive(
    archive: Path,
    results: dict[str, SuiteResult],
    total_log_bytes: int,
    inventory: ModuleInventory,
) -> int:
    try:
        with zipfile.ZipFile(archive) as bundle:
            entries = [
                entry
                for entry in bundle.infolist()
                if not entry.is_dir() and entry.filename.endswith(".json")
            ]
            if not entries or len(entries) > MAX_LOGS_PER_ARCHIVE:
                raise ResultError("invalid_suite_log_count")
            for entry in entries:
                if entry.flag_bits & 0x1:
                    raise ResultError("encrypted_suite_log")
                if entry.file_size <= 0 or entry.file_size > MAX_LOG_BYTES:
                    raise ResultError("invalid_suite_log_size")
                total_log_bytes = checked_total_size(total_log_bytes, entry.file_size)
                with bundle.open(entry) as stream:
                    body = stream.read(MAX_LOG_BYTES + 1)
                if len(body) != entry.file_size or len(body) > MAX_LOG_BYTES:
                    raise ResultError("invalid_suite_log_size")
                record_result(decode_json(body), results, inventory)
    except (zipfile.BadZipFile, RuntimeError) as error:
        raise ResultError("invalid_suite_archive") from error
    return total_log_bytes


def checked_total_size(current: int, additional: int) -> int:
    total = current + additional
    if total > MAX_TOTAL_LOG_BYTES:
        raise ResultError("suite_logs_too_large")
    return total


def record_result(
    payload: Any, results: dict[str, SuiteResult], inventory: ModuleInventory
) -> None:
    if not isinstance(payload, dict) or not isinstance(payload.get("testInfo"), dict):
        raise ResultError("invalid_suite_test_log")
    test_info = payload["testInfo"]
    test_id = test_info.get("testId")
    test_name = test_info.get("testName")
    execution_plan_id = test_info.get("planId")
    alias = test_info.get("alias")
    variant = normalize_variant(test_info.get("variant"))
    if not isinstance(test_id, str) or TEST_ID_PATTERN.fullmatch(test_id) is None:
        raise ResultError("invalid_suite_test_id")
    if not isinstance(test_name, str) or TEST_ID_PATTERN.fullmatch(test_name) is None:
        raise ResultError("invalid_suite_test_name")
    if (
        not isinstance(execution_plan_id, str)
        or TEST_ID_PATTERN.fullmatch(execution_plan_id) is None
    ):
        raise ResultError("invalid_suite_execution_plan_id")
    if alias != inventory.expected_alias:
        raise ResultError("suite_alias_mismatch")
    if payload.get("exportedVersion") != inventory.suite_version:
        raise ResultError("suite_export_version_mismatch")
    if test_info.get("version") != inventory.suite_version:
        raise ResultError("suite_test_version_mismatch")
    if test_info.get("status") != "FINISHED":
        raise ResultError("unfinished_suite_test")
    if test_info.get("result") != "PASSED":
        raise ResultError("non_passing_suite_test")
    if any(
        not isinstance(key, str)
        or TEST_ID_PATTERN.fullmatch(key) is None
        or not isinstance(value, str)
        or not value
        or len(value) > MAX_VARIANT_VALUE_LENGTH
        for key, value in variant.items()
    ):
        raise ResultError("invalid_suite_test_variant")
    for key, expected_value in inventory.expected_plan_variant:
        if variant.get(key) != expected_value:
            raise ResultError("suite_plan_variant_mismatch")
    if test_id in results:
        raise ResultError("duplicate_suite_test_id")

    module_variant = tuple(
        sorted(
            (key, value)
            for key, value in variant.items()
            if key not in inventory.plan_variant_keys
        )
    )
    results[test_id] = SuiteResult(
        test_name=test_name,
        module_variant=module_variant,
        execution_plan_id=execution_plan_id,
    )


def normalize_variant(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ResultError("invalid_suite_test_variant")
    if set(value) == {"variant"} and isinstance(value.get("variant"), dict):
        value = value["variant"]
    if any(not isinstance(key, str) or not isinstance(item, str) for key, item in value.items()):
        raise ResultError("invalid_suite_test_variant")
    return value


def module_variant_digest(results: Iterable[SuiteResult]) -> str:
    entries = [
        {"testModule": result.test_name, "variant": dict(result.module_variant)}
        for result in results
    ]
    entries.sort(
        key=lambda entry: (
            entry["testModule"],
            canonical_json(entry["variant"]),
        )
    )
    canonical = f"{canonical_json(entries)}\n".encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InvalidJsonValueError
        result[key] = value
    return result


def reject_nonfinite_number(_: str) -> None:
    raise InvalidJsonValueError


def decode_json(body: bytes) -> Any:
    try:
        return json.loads(
            body.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonfinite_number,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        InvalidJsonValueError,
        RecursionError,
    ) as error:
        raise ResultError("invalid_suite_test_log") from error


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
