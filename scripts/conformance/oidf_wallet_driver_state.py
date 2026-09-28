#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Bounded in-memory state for one OIDF wallet plan execution."""

from __future__ import annotations

from dataclasses import dataclass


class DriverState:
    def __init__(self) -> None:
        self.attempted_test_ids: set[str] = set()
        self.credential_configuration_id_hint: str | None = None
        self.stop_requested = False

    def resolve_configuration_id_hint(self, candidate: object) -> str | None:
        if isinstance(candidate, str) and candidate:
            self.credential_configuration_id_hint = candidate
        return self.credential_configuration_id_hint


@dataclass(frozen=True)
class WaitingModule:
    test_id: str
    module_id: str
