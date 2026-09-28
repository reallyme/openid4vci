#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Unit tests for the OIDF wallet module control-plane driver."""

from __future__ import annotations

import importlib.util
import io
import json
import os
import ssl
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).with_name("drive_oidf_wallet_modules.py")
sys.path.insert(0, str(MODULE_PATH.parent))
POLICY = importlib.import_module("oidf_wallet_outcome_policy")
PLAN = importlib.import_module("oidf_wallet_plan")

SPEC = importlib.util.spec_from_file_location("drive_oidf_wallet_modules", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("wallet module driver could not be loaded")
DRIVER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = DRIVER
SPEC.loader.exec_module(DRIVER)

POSITIVE_MODULE = "oid4vci-1_0-wallet-test-credential-issuance"
ENGINEERING_POSITIVE_MODULE = (
    "oid4vci-1_0-wallet-happy-path-with-scopes-without-authorization-details-"
    "in-token-response"
)
REJECTION_MODULE = (
    "fapi2-security-profile-final-client-test-discovery-issuer-mismatch"
)


class WalletModuleDriverTests(unittest.TestCase):
    def test_outcome_policy_covers_the_locked_wallet_inventory(self) -> None:
        inventory_path = (
            MODULE_PATH.parents[2]
            / "conformance"
            / "oidf"
            / "certification-module-inventory.json"
        )
        inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
        wallet_plans = [
            plan
            for plan in inventory["plans"]
            if plan["plan_id"] == "oid4vci-1_0-wallet-haip-test-plan"
        ]
        self.assertEqual(len(wallet_plans), 1)
        self.assertEqual(
            set(wallet_plans[0]["module_ids"]),
            set(POLICY.CERTIFICATION_WALLET_MODULES),
        )

    def test_scope_based_engineering_module_requires_a_stored_credential(
        self,
    ) -> None:
        expected = POLICY.expected_outcome(ENGINEERING_POSITIVE_MODULE)
        self.assertEqual(expected.flow_status, POLICY.CREDENTIAL_STORED)
        self.assertIsNone(expected.flow_reason)

    def test_parses_suite_nanosecond_timestamp(self) -> None:
        parsed = DRIVER.parse_oidf_epoch_seconds("2026-09-18T13:31:12.443960126Z")
        expected = datetime(
            2026, 9, 18, 13, 31, 12, 443960, tzinfo=timezone.utc
        ).timestamp()
        self.assertEqual(parsed, expected)

    def test_requires_matching_alias_configuration(self) -> None:
        config = DRIVER.DriverConfig(
            conformance_server="https://suite.example/",
            plan_id="wallet-plan",
            alias="expected-alias",
            plan_expression="wallet-plan",
            harness_offer_endpoint=(
                "https://wallet.example/oidf/wallet/credential-offer"
            ),
            harness_initiation_endpoint="https://wallet.example/oidf/wallet/initiate",
            harness_offer_target=DRIVER.validate_harness_endpoint(
                "https://wallet.example/oidf/wallet/credential-offer", False
            ),
            harness_initiation_target=DRIVER.validate_harness_endpoint(
                "https://wallet.example/oidf/wallet/initiate", False
            ),
            harness_token="wallet-control-token-with-at-least-32-bytes",
            evidence_dir=Path("evidence"),
            conformance_verify_ssl=True,
            conformance_ca_file=None,
            interval_seconds=1.0,
            timeout_seconds=30.0,
            started_after_epoch_seconds=0.0,
        )
        payload = {
            "data": [
                {
                    "planName": "wallet-plan",
                    "started": "2026-09-18T13:31:12.443960126Z",
                }
            ]
        }
        self.assertIsNone(PLAN.newest_matching_plan(payload, config))

    def test_rejects_plan_without_valid_start_time(self) -> None:
        config = DRIVER.DriverConfig(
            conformance_server="https://suite.example/",
            plan_id="wallet-plan",
            alias=None,
            plan_expression="wallet-plan",
            harness_offer_endpoint=(
                "https://wallet.example/oidf/wallet/credential-offer"
            ),
            harness_initiation_endpoint="https://wallet.example/oidf/wallet/initiate",
            harness_offer_target=DRIVER.validate_harness_endpoint(
                "https://wallet.example/oidf/wallet/credential-offer", False
            ),
            harness_initiation_target=DRIVER.validate_harness_endpoint(
                "https://wallet.example/oidf/wallet/initiate", False
            ),
            harness_token="wallet-control-token-with-at-least-32-bytes",
            evidence_dir=Path("evidence"),
            conformance_verify_ssl=True,
            conformance_ca_file=None,
            interval_seconds=1.0,
            timeout_seconds=30.0,
            started_after_epoch_seconds=0.0,
        )
        payload = {"data": [{"planName": "wallet-plan", "started": "invalid"}]}
        self.assertIsNone(PLAN.newest_matching_plan(payload, config))

    def test_derives_initiation_endpoint_only_from_expected_offer_path(self) -> None:
        self.assertEqual(
            DRIVER.derive_initiation_endpoint(
                "https://wallet.example/oidf/wallet/credential-offer"
            ),
            "https://wallet.example/oidf/wallet/initiate",
        )
        with self.assertRaises(DRIVER.DriverError):
            DRIVER.derive_initiation_endpoint("https://wallet.example/launch")

    def test_matches_only_exact_harness_endpoint(self) -> None:
        endpoint = "https://wallet.example/oidf/wallet/credential-offer"
        self.assertTrue(
            DRIVER.same_endpoint(
                f"{endpoint}?credential_offer=%7B%7D",
                endpoint,
            )
        )
        self.assertFalse(
            DRIVER.same_endpoint(
                "https://attacker.example/oidf/wallet/credential-offer",
                endpoint,
            )
        )

    def test_redacts_harness_response_to_terminal_status(self) -> None:
        evidence = DRIVER.evidence_from_response(
            POSITIVE_MODULE,
            "wallet_initiated",
            {
                "session_id": 7,
                "offer": {"credential_issuer": "https://issuer.example"},
                "flow": {"status": "credential_stored"},
            },
        )
        self.assertEqual(
            evidence,
            {
                "schema_version": 2,
                "module_id": POSITIVE_MODULE,
                "launch_mode": "wallet_initiated",
                "flow_status": "credential_stored",
                "flow_reason": None,
            },
        )
        with self.assertRaises(DRIVER.DriverError):
            DRIVER.evidence_from_response(
                POSITIVE_MODULE, "wallet_initiated", {"flow": None}
            )
        with self.assertRaisesRegex(
            DRIVER.DriverError, "wallet_flow_outcome_mismatch"
        ):
            DRIVER.evidence_from_response(
                POSITIVE_MODULE,
                "wallet_initiated",
                {"flow": {"status": "deferred_credential_pending"}},
            )

    def test_accepts_only_the_module_specific_protocol_rejection(self) -> None:
        evidence = DRIVER.evidence_from_response(
            REJECTION_MODULE,
            "wallet_initiated",
            {
                "flow": {
                    "status": "protocol_rejected",
                    "reason": "authorization_server_issuer_mismatch",
                }
            },
        )
        self.assertEqual(evidence["flow_status"], "protocol_rejected")
        self.assertEqual(
            evidence["flow_reason"], "authorization_server_issuer_mismatch"
        )
        with self.assertRaisesRegex(
            DRIVER.DriverError, "wallet_flow_outcome_mismatch"
        ):
            DRIVER.evidence_from_response(
                REJECTION_MODULE,
                "wallet_initiated",
                {
                    "flow": {
                        "status": "protocol_rejected",
                        "reason": "credential_storage_failed",
                    }
                },
            )

    def test_writes_one_redacted_evidence_file_per_test(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            DRIVER.write_evidence(
                root,
                "test_ABC-123",
                {
                    "schema_version": 2,
                    "module_id": POSITIVE_MODULE,
                    "launch_mode": "issuer_initiated",
                    "flow_status": "credential_stored",
                    "flow_reason": None,
                },
            )
            content = json.loads((root / "test_ABC-123.json").read_text(encoding="utf-8"))
            self.assertEqual(content["test_id"], "test_ABC-123")
            self.assertNotIn("credential_issuer", content)
            with self.assertRaises(DRIVER.WalletEvidenceError):
                DRIVER.write_evidence(root, "../escape", {})

    def test_rejects_insecure_tls_outside_explicit_local_mode(self) -> None:
        environment = {
            "OPENID4VCI_WALLET_HARNESS_ENDPOINT": (
                "https://wallet.example/oidf/wallet/credential-offer"
            ),
            "OPENID4VCI_WALLET_IMPLEMENTATION_EVIDENCE_DIR": "evidence",
            "OIDF_WALLET_PLAN_EXPRESSION": "wallet-plan",
            "OPENID4VCI_WALLET_HARNESS_TOKEN": (
                "wallet-control-token-with-at-least-32-bytes"
            ),
            "CONFORMANCE_VERIFY_SSL": "false",
            "OIDF_CONFORMANCE_MODE": "hosted",
        }
        with mock.patch.dict(os.environ, environment, clear=True):
            with self.assertRaisesRegex(
                DRIVER.DriverError, "insecure_tls_requires_local_mode"
            ):
                DRIVER.config_from_env()

    def test_allows_explicit_local_unverified_tls(self) -> None:
        environment = {
            "OPENID4VCI_WALLET_HARNESS_ENDPOINT": (
                "https://wallet.example/oidf/wallet/credential-offer"
            ),
            "OPENID4VCI_WALLET_IMPLEMENTATION_EVIDENCE_DIR": "evidence",
            "OIDF_WALLET_PLAN_EXPRESSION": "wallet-plan",
            "OPENID4VCI_WALLET_HARNESS_TOKEN": (
                "wallet-control-token-with-at-least-32-bytes"
            ),
            "CONFORMANCE_VERIFY_SSL": "false",
            "OIDF_CONFORMANCE_MODE": "local",
        }
        with mock.patch.dict(os.environ, environment, clear=True):
            config = DRIVER.config_from_env()
        context = DRIVER.build_tls_context(config)
        self.assertFalse(context.check_hostname)
        self.assertEqual(context.verify_mode, DRIVER.ssl.CERT_NONE)

    def test_rejects_malformed_and_unbounded_timing_configuration(self) -> None:
        for value in ("invalid", "nan", "0", "60.1"):
            with self.subTest(value=value):
                with mock.patch.dict(
                    os.environ,
                    {"OPENID4VCI_OIDF_WALLET_DRIVER_INTERVAL_SECONDS": value},
                    clear=True,
                ):
                    with self.assertRaisesRegex(
                        DRIVER.DriverError, "invalid_numeric_environment"
                    ):
                        DRIVER.bounded_float_from_env(
                            "OPENID4VCI_OIDF_WALLET_DRIVER_INTERVAL_SECONDS",
                            DRIVER.DEFAULT_INTERVAL_SECONDS,
                            DRIVER.MIN_INTERVAL_SECONDS,
                            DRIVER.MAX_INTERVAL_SECONDS,
                        )

    def test_rejects_missing_custom_ca_file(self) -> None:
        config = DRIVER.DriverConfig(
            conformance_server="https://suite.example/",
            plan_id="wallet-plan",
            alias=None,
            plan_expression="wallet-plan",
            harness_offer_endpoint=(
                "https://wallet.example/oidf/wallet/credential-offer"
            ),
            harness_initiation_endpoint="https://wallet.example/oidf/wallet/initiate",
            harness_offer_target=DRIVER.validate_harness_endpoint(
                "https://wallet.example/oidf/wallet/credential-offer", False
            ),
            harness_initiation_target=DRIVER.validate_harness_endpoint(
                "https://wallet.example/oidf/wallet/initiate", False
            ),
            harness_token="wallet-control-token-with-at-least-32-bytes",
            evidence_dir=Path("evidence"),
            conformance_verify_ssl=True,
            conformance_ca_file=Path("missing-ca.pem"),
            interval_seconds=1.0,
            timeout_seconds=30.0,
            started_after_epoch_seconds=0.0,
        )
        with self.assertRaisesRegex(
            DRIVER.DriverError, "invalid_conformance_ca_file"
        ):
            DRIVER.build_tls_context(config)

    def test_requires_a_bounded_wallet_control_token(self) -> None:
        base_environment = {
            "OPENID4VCI_WALLET_HARNESS_ENDPOINT": (
                "https://wallet.example/oidf/wallet/credential-offer"
            ),
            "OPENID4VCI_WALLET_IMPLEMENTATION_EVIDENCE_DIR": "evidence",
            "OIDF_WALLET_PLAN_EXPRESSION": "wallet-plan",
        }
        for token in (None, "short", "x" * 4097, "token with whitespace" * 2):
            environment = dict(base_environment)
            if token is not None:
                environment["OPENID4VCI_WALLET_HARNESS_TOKEN"] = token
            with self.subTest(token_present=token is not None):
                with mock.patch.dict(os.environ, environment, clear=True):
                    with self.assertRaisesRegex(
                        DRIVER.DriverError, "wallet_harness_token"
                    ):
                        DRIVER.config_from_env()

    def test_allows_plain_http_only_for_explicit_local_loopback(self) -> None:
        environment = {
            "OPENID4VCI_WALLET_HARNESS_ENDPOINT": (
                "http://127.0.0.1:8788/oidf/wallet/credential-offer"
            ),
            "OPENID4VCI_WALLET_IMPLEMENTATION_EVIDENCE_DIR": "evidence",
            "OPENID4VCI_WALLET_HARNESS_TOKEN": (
                "wallet-control-token-with-at-least-32-bytes"
            ),
            "OIDF_WALLET_PLAN_EXPRESSION": "wallet-plan",
            "OIDF_CONFORMANCE_MODE": "local",
        }
        with mock.patch.dict(os.environ, environment, clear=True):
            self.assertEqual(
                DRIVER.config_from_env().harness_offer_target.host, "127.0.0.1"
            )
        environment["OIDF_CONFORMANCE_MODE"] = "hosted"
        with mock.patch.dict(os.environ, environment, clear=True):
            with self.assertRaisesRegex(
                DRIVER.DriverError, "insecure_harness_endpoint"
            ):
                DRIVER.config_from_env()

    def test_rejects_oversized_or_invalid_http_response_length(self) -> None:
        class Response:
            def __init__(self, body: bytes, content_length: str | None) -> None:
                self._body = io.BytesIO(body)
                self.headers = (
                    {}
                    if content_length is None
                    else {"Content-Length": content_length}
                )

            def read(self, size: int) -> bytes:
                return self._body.read(size)

        oversized = str(DRIVER.MAX_HTTP_RESPONSE_BYTES + 1)
        with self.assertRaisesRegex(DRIVER.DriverError, "response_too_large"):
            DRIVER.read_bounded_response(Response(b"", oversized))
        with self.assertRaisesRegex(
            DRIVER.DriverError, "invalid_response_length"
        ):
            DRIVER.read_bounded_response(Response(b"", "invalid"))

    def test_rejects_chunked_body_over_limit(self) -> None:
        class Response:
            headers: dict[str, str] = {}

            @staticmethod
            def read(size: int) -> bytes:
                return b"x" * size

        with self.assertRaisesRegex(DRIVER.DriverError, "response_too_large"):
            DRIVER.read_bounded_response(Response())

    def test_does_not_repeat_an_indeterminate_wallet_launch(self) -> None:
        config = DRIVER.DriverConfig(
            conformance_server="https://suite.example/",
            plan_id="wallet-plan",
            alias=None,
            plan_expression=(
                "wallet-plan[vci_authorization_code_flow_variant=wallet_initiated]"
            ),
            harness_offer_endpoint=(
                "https://wallet.example/oidf/wallet/credential-offer"
            ),
            harness_initiation_endpoint="https://wallet.example/oidf/wallet/initiate",
            harness_offer_target=DRIVER.validate_harness_endpoint(
                "https://wallet.example/oidf/wallet/credential-offer", False
            ),
            harness_initiation_target=DRIVER.validate_harness_endpoint(
                "https://wallet.example/oidf/wallet/initiate", False
            ),
            harness_token="wallet-control-token-with-at-least-32-bytes",
            evidence_dir=Path("evidence"),
            conformance_verify_ssl=True,
            conformance_ca_file=None,
            interval_seconds=1.0,
            timeout_seconds=30.0,
            started_after_epoch_seconds=0.0,
        )
        module = DRIVER.WaitingModule("test-123", POSITIVE_MODULE)
        state = DRIVER.DriverState()
        with (
            mock.patch.object(DRIVER, "fetch_json", return_value={}),
            mock.patch.object(DRIVER, "discover_newest_matching_plan", return_value={}),
            mock.patch.object(DRIVER, "waiting_modules", return_value=[module]),
            mock.patch.object(
                DRIVER,
                "drive_wallet_initiated",
                side_effect=DRIVER.DriverError("network_error"),
            ) as launch,
        ):
            with self.assertRaisesRegex(DRIVER.DriverError, "network_error"):
                DRIVER.drive_once(config, state, ssl.create_default_context())
            DRIVER.drive_once(config, state, ssl.create_default_context())
        self.assertEqual(launch.call_count, 1)

    def test_reuses_the_plan_configuration_hint_for_fapi_modules(self) -> None:
        state = DRIVER.DriverState()
        self.assertEqual(
            state.resolve_configuration_id_hint("pid-sd-jwt"), "pid-sd-jwt"
        )
        self.assertEqual(state.resolve_configuration_id_hint(None), "pid-sd-jwt")
        self.assertEqual(state.resolve_configuration_id_hint(""), "pid-sd-jwt")

    def test_binds_each_harness_launch_to_the_oidf_test_id(self) -> None:
        context = ssl.create_default_context()
        config = DRIVER.DriverConfig(
            conformance_server="https://suite.example/",
            plan_id="wallet-plan",
            alias=None,
            plan_expression="wallet-plan",
            harness_offer_endpoint=(
                "https://wallet.example/oidf/wallet/credential-offer"
            ),
            harness_initiation_endpoint="https://wallet.example/oidf/wallet/initiate",
            harness_offer_target=DRIVER.validate_harness_endpoint(
                "https://wallet.example/oidf/wallet/credential-offer", False
            ),
            harness_initiation_target=DRIVER.validate_harness_endpoint(
                "https://wallet.example/oidf/wallet/initiate", False
            ),
            harness_token="wallet-control-token-with-at-least-32-bytes",
            evidence_dir=Path("evidence"),
            conformance_verify_ssl=True,
            conformance_ca_file=None,
            interval_seconds=1.0,
            timeout_seconds=30.0,
            started_after_epoch_seconds=0.0,
        )
        with mock.patch.object(
            DRIVER, "open_harness_request", return_value=b"{}"
        ) as open_request:
            DRIVER.post_json(
                config.harness_initiation_endpoint,
                {
                    "credential_issuer": "https://issuer.example",
                    "credential_configuration_id": "pid",
                },
                "test-123",
                context,
                config,
            )
        request = open_request.call_args.args[0]
        self.assertEqual(dict(request.header_items())["Idempotency-key"], "test-123")


if __name__ == "__main__":
    unittest.main()
