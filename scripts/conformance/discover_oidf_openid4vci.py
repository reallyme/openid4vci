#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Discover OpenID4VCI-related OIDF conformance-suite plans and modules.

The OIDF conformance suite is an external, moving project. This script inspects
the exact checked-out tree used by CI, rejects drift from the reviewed contract,
and writes machine-readable discovery artifacts. Only published plans and test
modules are evidence; incidental strings in tests, resources, or legacy aliases
must never be mistaken for executable certification coverage.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


MAX_FILE_BYTES = 1_000_000
DEFAULT_CONTRACT = Path("conformance/oidf/suite-contract.json")
PLAN_ANNOTATION_PATTERN = re.compile(
    r"@PublishTestPlan\s*\((?P<body>.*?)\)\s*public\s+class\s+"
    r"(?P<class_name>[A-Za-z][A-Za-z0-9_]*)",
    re.DOTALL,
)
MODULE_ANNOTATION_PATTERN = re.compile(
    r"@PublishTestModule\s*\((?P<body>.*?)\)\s*public\s+class\s+"
    r"(?P<class_name>[A-Za-z][A-Za-z0-9_]*)",
    re.DOTALL,
)


@dataclass(frozen=True)
class SourceMatch:
    """One suite source file relevant to OpenID4VCI discovery."""

    path: str
    text: str


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Discover OpenID4VCI OIDF conformance-suite artifacts."
    )
    parser.add_argument("suite_dir", help="Checked-out OIDF conformance-suite directory")
    parser.add_argument(
        "output_dir",
        help="Directory that will receive suite.lock, plans.json, modules.json, and oidf-discovery.json",
    )
    parser.add_argument(
        "--contract",
        default=str(DEFAULT_CONTRACT),
        help="Reviewed suite contract used to reject commit or plan inventory drift",
    )
    args = parser.parse_args()

    suite_dir = Path(args.suite_dir).resolve()
    output_dir = Path(args.output_dir).resolve()
    if not suite_dir.is_dir():
        print("suite directory does not exist", file=sys.stderr)
        return 66

    contract_path = Path(args.contract).resolve()
    contract = read_contract(contract_path)
    if contract is None:
        print("OIDF suite contract is missing or invalid", file=sys.stderr)
        return 66

    matches = list(discover_source_matches(suite_dir))
    suite_lock = build_suite_lock(suite_dir)
    plans = build_plans(matches)
    modules = build_modules(matches, plans)
    contract_errors = validate_contract(contract, suite_lock, plans)
    if contract_errors:
        for error in contract_errors:
            print(error, file=sys.stderr)
        return 65

    output_dir.mkdir(parents=True, exist_ok=True)
    discovery = {
        "schema_version": 1,
        "suite": suite_lock,
        "plans": plans["plans"],
        "modules": modules["modules"],
    }

    write_json(output_dir / "suite.lock", suite_lock)
    write_json(output_dir / "plans.json", plans)
    write_json(output_dir / "modules.json", modules)
    write_json(output_dir / "oidf-discovery.json", discovery)
    return 0


def discover_source_matches(suite_dir: Path) -> Iterable[SourceMatch]:
    source_roots = (
        suite_dir / "src/main/java/net/openid/conformance/vci10issuer",
        suite_dir / "src/main/java/net/openid/conformance/vci10wallet",
    )
    for source_root in source_roots:
        if not source_root.is_dir():
            continue
        for path in sorted(source_root.glob("*.java")):
            text = read_text(path)
            if text is not None:
                yield SourceMatch(
                    path=path.relative_to(suite_dir).as_posix(),
                    text=text,
                )


def read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None
    except OSError:
        return None


def build_suite_lock(suite_dir: Path) -> dict[str, object]:
    return {
        "schema_version": 1,
        "repository": "https://gitlab.com/openid/conformance-suite",
        "commit": git_output(suite_dir, "rev-parse", "HEAD"),
        "describe": git_output(suite_dir, "describe", "--tags", "--always"),
        "discovery_status": "generated-from-checked-out-suite",
    }


def build_plans(matches: list[SourceMatch]) -> dict[str, object]:
    discovered: dict[str, dict[str, object]] = {}
    for match in matches:
        for annotation in PLAN_ANNOTATION_PATTERN.finditer(match.text):
            body = annotation.group("body")
            plan_id = string_attribute(body, "testPlanName")
            display_name = string_attribute(body, "displayName")
            if plan_id is None or display_name is None:
                continue
            normalized = plan_id.lower()
            discovered[plan_id] = {
                "plan_id": plan_id,
                "entity_under_test": infer_entity(normalized),
                "profile": infer_profile(normalized),
                "certification": "not part of certification program"
                not in display_name.lower(),
                "display_name": display_name,
                "class_name": annotation.group("class_name"),
                "source": match.path,
                "automated": True,
                "supported": True,
                "status": "discovered",
            }
    return {
        "schema_version": 1,
        "plans": sorted(discovered.values(), key=lambda item: str(item["plan_id"])),
    }


def build_modules(matches: list[SourceMatch], plans: dict[str, object]) -> dict[str, object]:
    typed_plans = [plan for plan in plans["plans"] if isinstance(plan, dict)]
    modules: list[dict[str, object]] = []
    for match in matches:
        for annotation in MODULE_ANNOTATION_PATTERN.finditer(match.text):
            body = annotation.group("body")
            module_id = string_attribute(body, "testName")
            display_name = string_attribute(body, "displayName")
            if module_id is None or display_name is None:
                continue
            entity = infer_entity(match.path.lower())
            candidate_plan_ids = sorted(
                str(plan["plan_id"])
                for plan in typed_plans
                if plan.get("entity_under_test") == entity
            )
            modules.append(
                {
                    "module_id": module_id,
                    "class_name": annotation.group("class_name"),
                    "display_name": display_name,
                    "candidate_plan_ids": candidate_plan_ids,
                    "entity_under_test": entity,
                    "topic": infer_topic((module_id + " " + display_name).lower()),
                    "specification": "openid4vci-1.0",
                    "supported": True,
                    "automated": True,
                    "source": match.path,
                    "exclusion_reason": None,
                }
            )
    modules.sort(key=lambda item: (str(item["module_id"]), str(item["source"])))
    return {"schema_version": 1, "modules": modules}


def string_attribute(annotation_body: str, name: str) -> str | None:
    match = re.search(rf'\b{re.escape(name)}\s*=\s*"([^"]+)"', annotation_body)
    if match is None:
        return None
    return match.group(1)


def infer_entity(text: str) -> str:
    if "wallet" in text or "holder" in text:
        return "wallet"
    if "issuer" in text or "credential_issuer" in text or "credential issuer" in text:
        return "credential_issuer"
    return "unknown"


def infer_profile(text: str) -> str:
    if "haip" in text or "high assurance" in text:
        return "haip"
    return "base"


def infer_topic(text: str) -> str:
    if "metadata" in text:
        return "metadata"
    if "nonce" in text:
        return "nonce"
    if "dpop" in text:
        return "dpop"
    if "notification" in text:
        return "notification"
    if "deferred" in text:
        return "deferred_issuance"
    if "attestation" in text:
        return "attestation"
    if "encryption" in text or "jwe" in text:
        return "encryption"
    if "credential" in text:
        return "credential_endpoint"
    return "unspecified"


def git_output(workdir: Path, *args: str) -> str | None:
    try:
        completed = subprocess.run(
            ("git", *args),
            cwd=workdir,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    value = completed.stdout.strip()
    if value:
        return value
    return None


def read_contract(path: Path) -> dict[str, object] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict):
        return None
    return value


def validate_contract(
    contract: dict[str, object],
    suite_lock: dict[str, object],
    plans: dict[str, object],
) -> list[str]:
    errors: list[str] = []
    expected_commit = contract.get("commit")
    actual_commit = suite_lock.get("commit")
    if not isinstance(expected_commit, str) or expected_commit != actual_commit:
        errors.append("OIDF conformance suite commit does not match reviewed contract")

    expected_plans_value = contract.get("plans")
    actual_plans_value = plans.get("plans")
    if not isinstance(expected_plans_value, list) or not isinstance(
        actual_plans_value, list
    ):
        errors.append("OIDF conformance suite plan contract is malformed")
        return errors

    expected_plan_ids = {
        item.get("plan_id")
        for item in expected_plans_value
        if isinstance(item, dict) and isinstance(item.get("plan_id"), str)
    }
    actual_plan_ids = {
        item.get("plan_id")
        for item in actual_plans_value
        if isinstance(item, dict) and isinstance(item.get("plan_id"), str)
    }
    if expected_plan_ids != actual_plan_ids:
        errors.append("OIDF OpenID4VCI published plan inventory drifted from reviewed contract")

    for expected in expected_plans_value:
        if not isinstance(expected, dict):
            continue
        plan_id = expected.get("plan_id")
        actual = next(
            (
                item
                for item in actual_plans_value
                if isinstance(item, dict) and item.get("plan_id") == plan_id
            ),
            None,
        )
        if actual is None:
            continue
        for field in ("entity_under_test", "profile", "certification"):
            if actual.get(field) != expected.get(field):
                errors.append(
                    f"OIDF plan {plan_id!s} changed reviewed field {field!s}"
                )
    return errors


def write_json(path: Path, value: dict[str, object]) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
