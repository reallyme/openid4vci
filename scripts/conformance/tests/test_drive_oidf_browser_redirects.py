# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

import importlib.util
import json
import pathlib
import sys
import unittest
import urllib.parse


SCRIPT_PATH = pathlib.Path(__file__).parents[1] / "drive_oidf_browser_redirects.py"
SPEC = importlib.util.spec_from_file_location("oidf_browser_driver", SCRIPT_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load OIDF browser driver")
DRIVER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = DRIVER
SPEC.loader.exec_module(DRIVER)


class CredentialOfferSubmissionTests(unittest.TestCase):
    def test_builds_final_authorization_code_offer(self) -> None:
        submission_url = DRIVER.credential_offer_submission_url(
            "https://suite.example/test/a/profile/module/credential_offer",
            "https://issuer.example/openid4vci/example-issuer/",
            "pid",
            "module-id",
        )

        parsed = urllib.parse.urlparse(submission_url)
        query = urllib.parse.parse_qs(parsed.query, strict_parsing=True)
        offer = json.loads(query["credential_offer"][0])

        self.assertEqual(parsed.scheme, "https")
        self.assertEqual(offer["credential_configuration_ids"], ["pid"])
        self.assertEqual(
            offer["credential_issuer"],
            "https://issuer.example/openid4vci/example-issuer/",
        )
        self.assertEqual(
            offer["grants"]["authorization_code"]["issuer_state"],
            "oidf-module-id",
        )

    def test_preserves_existing_endpoint_query(self) -> None:
        submission_url = DRIVER.credential_offer_submission_url(
            "https://suite.example/credential_offer?existing=1",
            "https://issuer.example/",
            "pid",
            "module-id",
        )

        parsed = urllib.parse.urlparse(submission_url)
        query = urllib.parse.parse_qs(parsed.query, strict_parsing=True)

        self.assertEqual(query["existing"], ["1"])
        self.assertIn("credential_offer", query)


class PlanPaginationTests(unittest.TestCase):
    def test_finds_newest_matching_plan_beyond_first_page(self) -> None:
        config = DRIVER.DriverConfig(
            conformance_server="https://suite.example/",
            plan_id="issuer-plan",
            alias="release-candidate",
            issuer_netloc=None,
            healthcheck_netloc=None,
            credential_issuer_url="https://issuer.example/",
            credential_configuration_id="pid",
            interval_seconds=1.0,
            timeout_seconds=60.0,
            started_after_epoch_seconds=0.0,
        )
        first_page_item = {
            "planName": "unrelated-plan",
            "started": "2026-01-01T00:00:00Z",
            "config": {"alias": "other"},
        }
        expected = {
            "planName": "issuer-plan",
            "started": "2026-09-21T19:55:53Z",
            "config": {"alias": "release-candidate"},
        }
        responses = {
            DRIVER.plan_listing_path(0): {"data": [first_page_item] * DRIVER.PLAN_PAGE_SIZE},
            DRIVER.plan_listing_path(DRIVER.PLAN_PAGE_SIZE): {"data": [expected]},
        }
        requested_paths: list[str] = []
        original_fetch_json = DRIVER.fetch_json

        def fake_fetch_json(
            _base_url: str, path: str, _context: object
        ) -> dict[str, object]:
            requested_paths.append(path)
            return responses[path]

        DRIVER.fetch_json = fake_fetch_json
        self.addCleanup(setattr, DRIVER, "fetch_json", original_fetch_json)

        actual = DRIVER.fetch_newest_matching_plan(config, object())

        self.assertEqual(actual, expected)
        self.assertEqual(
            requested_paths,
            [
                DRIVER.plan_listing_path(0),
                DRIVER.plan_listing_path(DRIVER.PLAN_PAGE_SIZE),
            ],
        )


if __name__ == "__main__":
    unittest.main()
