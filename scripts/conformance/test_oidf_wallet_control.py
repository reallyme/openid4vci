#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Negative tests for the authenticated wallet-host HTTP boundary."""

from __future__ import annotations

import io
import json
import ssl
import sys
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parent))
import oidf_wallet_control as CONTROL  # noqa: E402


class WalletControlHttpTests(unittest.TestCase):
    def test_rejects_credentials_fragments_and_remote_plain_http(self) -> None:
        invalid = (
            "https://user@wallet.example/oidf/wallet/credential-offer",
            "https://wallet.example/oidf/wallet/credential-offer#fragment",
            "http://wallet.example/oidf/wallet/credential-offer",
        )
        for endpoint in invalid:
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(CONTROL.ControlHttpError):
                    CONTROL.validate_harness_endpoint(endpoint, True)

    def test_endpoint_match_is_exact_for_origin_port_and_path(self) -> None:
        expected = CONTROL.validate_harness_endpoint(
            "https://wallet.example:8443/oidf/wallet/credential-offer", False
        )
        self.assertTrue(
            CONTROL.same_endpoint(
                "https://wallet.example:8443/oidf/wallet/credential-offer?offer=x",
                expected,
            )
        )
        self.assertFalse(
            CONTROL.same_endpoint(
                "https://wallet.example.evil:8443/oidf/wallet/credential-offer",
                expected,
            )
        )
        self.assertFalse(
            CONTROL.same_endpoint(
                "https://wallet.example/oidf/wallet/credential-offer", expected
            )
        )

    def test_authenticated_request_rejects_redirect_without_following(self) -> None:
        endpoint = CONTROL.validate_harness_endpoint(
            "https://wallet.example/oidf/wallet/credential-offer", False
        )
        request = urllib.request.Request(
            "https://wallet.example/oidf/wallet/credential-offer", method="GET"
        )
        opener = mock.Mock()
        response = urllib.error.HTTPError(
            request.full_url,
            302,
            "redirect",
            {"Location": "https://attacker.example/steal"},
            None,
        )
        self.addCleanup(response.close)
        opener.open.side_effect = response
        with mock.patch.object(CONTROL.urllib.request, "build_opener", return_value=opener):
            with self.assertRaisesRegex(
                CONTROL.ControlHttpError, "wallet_harness_redirect_rejected"
            ):
                CONTROL.open_authenticated_request(
                    request,
                    ssl.create_default_context(),
                    "wallet-control-token-with-at-least-32-bytes",
                    endpoint,
                    1.0,
                    1024,
                )
        self.assertEqual(
            request.get_header("Authorization"),
            "Bearer wallet-control-token-with-at-least-32-bytes",
        )

    def test_bounded_reader_rejects_chunked_overflow(self) -> None:
        class Response:
            headers: dict[str, str] = {}

            def __init__(self) -> None:
                self.body = io.BytesIO(b"x" * 9)

            def read(self, size: int) -> bytes:
                return self.body.read(size)

        with self.assertRaisesRegex(CONTROL.ControlHttpError, "response_too_large"):
            CONTROL.read_bounded_response(Response(), 8)

    def test_surfaces_only_allowlisted_wallet_flow_problem(self) -> None:
        endpoint = CONTROL.validate_harness_endpoint(
            "https://wallet.example/oidf/wallet/initiate", False
        )
        request = urllib.request.Request(
            "https://wallet.example/oidf/wallet/initiate", method="POST"
        )
        body = json.dumps(
            {
                "type": "about:blank",
                "title": "wallet_flow_failed",
                "status": 502,
                "error": "credential_storage_failed",
            }
        ).encode("utf-8")
        opener = mock.Mock()
        response = urllib.error.HTTPError(
            request.full_url,
            502,
            "bad gateway",
            {
                "Content-Type": "application/problem+json",
                "Content-Length": str(len(body)),
            },
            io.BytesIO(body),
        )
        self.addCleanup(response.close)
        opener.open.side_effect = response
        with mock.patch.object(CONTROL.urllib.request, "build_opener", return_value=opener):
            with self.assertRaisesRegex(
                CONTROL.ControlHttpError, "wallet_flow_credential_storage_failed"
            ):
                CONTROL.open_authenticated_request(
                    request,
                    ssl.create_default_context(),
                    "wallet-control-token-with-at-least-32-bytes",
                    endpoint,
                    1.0,
                    1024,
                )

    def test_rejects_unrecognized_wallet_flow_problem(self) -> None:
        body = json.dumps(
            {
                "type": "about:blank",
                "title": "wallet_flow_failed",
                "status": 502,
                "error": "untrusted_remote_detail",
            }
        ).encode("utf-8")
        response = urllib.error.HTTPError(
            "https://wallet.example/oidf/wallet/initiate",
            502,
            "bad gateway",
            {
                "Content-Type": "application/problem+json",
                "Content-Length": str(len(body)),
            },
            io.BytesIO(body),
        )
        self.addCleanup(response.close)
        self.assertEqual(CONTROL.wallet_flow_error_code(response, 1024), "http_server_error")


if __name__ == "__main__":
    unittest.main()
