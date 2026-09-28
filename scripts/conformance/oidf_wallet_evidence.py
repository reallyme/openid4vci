#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Redacted implementation evidence for OIDF wallet module executions."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from oidf_wallet_outcome_policy import (
    OutcomePolicyError,
    validate_observed_outcome,
)


TEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


class WalletEvidenceError(Exception):
    """Stable failure raised while validating or writing redacted evidence."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def redact_launch_evidence(
    module_id: str, mode: str, response: Any
) -> dict[str, Any]:
    """Bind a non-secret host result to the exact suite-module outcome policy."""
    if not isinstance(response, dict):
        raise WalletEvidenceError("invalid_harness_response")
    flow = response.get("flow")
    status = flow.get("status") if isinstance(flow, dict) else None
    reason = flow.get("reason") if isinstance(flow, dict) else None
    try:
        outcome = validate_observed_outcome(module_id, status, reason)
    except OutcomePolicyError as error:
        raise WalletEvidenceError(error.code) from error
    return {
        "schema_version": 2,
        "module_id": module_id,
        "launch_mode": mode,
        "flow_status": outcome.flow_status,
        "flow_reason": outcome.flow_reason,
    }


def write_evidence(
    evidence_dir: Path, test_id: str, evidence: dict[str, Any]
) -> None:
    """Atomically replace one bounded, redacted module evidence record."""
    if not TEST_ID_PATTERN.fullmatch(test_id):
        raise WalletEvidenceError("invalid_test_id")
    evidence_dir.mkdir(parents=True, exist_ok=True)
    destination = evidence_dir / f"{test_id}.json"
    temporary = evidence_dir / f".{test_id}.json.tmp"
    try:
        temporary.write_text(
            json.dumps({"test_id": test_id, **evidence}, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(destination)
    except OSError as error:
        raise WalletEvidenceError("evidence_write_failed") from error
