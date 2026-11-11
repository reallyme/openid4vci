# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

import importlib.util
import json
import pathlib
import sys
import unittest
import urllib.parse
from unittest.mock import patch


SCRIPT_PATH = pathlib.Path(__file__).parents[1] / "drive_oidf_browser_redirects.py"
SPEC = importlib.util.spec_from_file_location("oidf_browser_driver", SCRIPT_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load OIDF browser driver")
DRIVER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = DRIVER
SPEC.loader.exec_module(DRIVER)


class CredentialOfferSubmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = DRIVER.DriverConfig(
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

    def test_submits_again_for_a_second_wait_at_the_same_endpoint(self) -> None:
        endpoint = "https://suite.example/credential_offer"
        state = DRIVER.DriverState()
        submitted_urls: list[str] = []
        original_fetch_json = DRIVER.fetch_json
        original_fetch_url = DRIVER.fetch_url

        def fake_fetch_json(
            _base_url: str, _path: str, _context: object
        ) -> dict[str, object]:
            return {"exposed": {"credential_offer_endpoint": endpoint}}

        def fake_fetch_url(url: str, _context: object) -> None:
            submitted_urls.append(url)

        DRIVER.fetch_json = fake_fetch_json
        DRIVER.fetch_url = fake_fetch_url
        self.addCleanup(setattr, DRIVER, "fetch_json", original_fetch_json)
        self.addCleanup(setattr, DRIVER, "fetch_url", original_fetch_url)

        first_wait = [{"src": "VCIWaitForCredentialOffer"}]
        DRIVER.drive_credential_offer("module-id", first_wait, self.config, state, object())
        DRIVER.drive_credential_offer("module-id", first_wait, self.config, state, object())
        second_wait = [*first_wait, {"src": "VCIWaitForCredentialOffer"}]
        DRIVER.drive_credential_offer("module-id", second_wait, self.config, state, object())

        self.assertEqual(len(submitted_urls), 2)
        self.assertEqual(
            state.handled_credential_offers[f"module-id:{endpoint}"],
            2,
        )

    def test_does_not_submit_without_a_suite_wait_signal(self) -> None:
        state = DRIVER.DriverState()
        submitted_urls: list[str] = []
        original_fetch_json = DRIVER.fetch_json
        original_fetch_url = DRIVER.fetch_url

        def fake_fetch_json(
            _base_url: str, _path: str, _context: object
        ) -> dict[str, object]:
            return {
                "exposed": {
                    "credential_offer_endpoint": "https://suite.example/credential_offer"
                }
            }

        def fake_fetch_url(url: str, _context: object) -> None:
            submitted_urls.append(url)

        DRIVER.fetch_json = fake_fetch_json
        DRIVER.fetch_url = fake_fetch_url
        self.addCleanup(setattr, DRIVER, "fetch_json", original_fetch_json)
        self.addCleanup(setattr, DRIVER, "fetch_url", original_fetch_url)

        DRIVER.drive_credential_offer("module-id", [], self.config, state, object())

        self.assertEqual(submitted_urls, [])


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


class AuthorizationVisitDeduplicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = DRIVER.DriverConfig(
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
        self.url = "https://issuer.example/authorize?request_uri=first"
        self.state = DRIVER.DriverState()
        self.context = object()
        self.control_log = [{"redirect_to_authorization_endpoint": self.url}]
        self.redirect_log = [
            *self.control_log,
            {"http": "redirect", "method": "GET", "redirect_to": self.url},
        ]
        self.browser_status = {"urls": [self.url], "visited": []}

    def test_control_visit_is_not_replayed_when_redirect_log_arrives_later(self) -> None:
        with (
            patch.object(DRIVER, "fetch_json", return_value=self.browser_status),
            patch.object(DRIVER, "fetch_browser_control_url", return_value=b"") as control,
            patch.object(DRIVER, "mark_browser_url_visited"),
            patch.object(DRIVER, "fetch_url", return_value=b"") as redirect,
        ):
            DRIVER.drive_browser_control_urls(
                "module-id", self.control_log, self.config, self.state, self.context
            )
            DRIVER.drive_redirects(
                "module-id", self.redirect_log, self.config, self.state, self.context
            )
            control.assert_called_once()
            redirect.assert_not_called()

    def test_logged_redirect_visit_is_not_replayed_by_a_stale_control_snapshot(self) -> None:
        with (
            patch.object(DRIVER, "fetch_json", return_value=self.browser_status),
            patch.object(DRIVER, "fetch_browser_control_url", return_value=b"") as control,
            patch.object(DRIVER, "mark_browser_url_visited"),
            patch.object(DRIVER, "fetch_url", return_value=b"") as redirect,
        ):
            DRIVER.drive_redirects(
                "module-id", self.redirect_log, self.config, self.state, self.context
            )
            DRIVER.drive_browser_control_urls(
                "module-id", self.control_log, self.config, self.state, self.context
            )
            redirect.assert_called_once()
            control.assert_not_called()

    def test_a_distinct_authorization_in_the_same_module_is_still_visited(self) -> None:
        second_url = "https://issuer.example/authorize?request_uri=second"
        with (
            patch.object(DRIVER, "fetch_json", return_value=self.browser_status),
            patch.object(DRIVER, "fetch_browser_control_url", return_value=b"") as control,
            patch.object(DRIVER, "mark_browser_url_visited"),
            patch.object(DRIVER, "fetch_url", return_value=b"") as redirect,
        ):
            DRIVER.drive_browser_control_urls(
                "module-id", self.control_log, self.config, self.state, self.context
            )
            DRIVER.drive_browser_control_urls(
                "module-id", self.control_log, self.config, self.state, self.context
            )
            DRIVER.drive_redirects(
                "module-id",
                [{"http": "redirect", "redirect_to": second_url}],
                self.config,
                self.state,
                self.context,
            )
            control.assert_called_once()
            redirect.assert_called_once_with(second_url, self.context)

    def test_intentional_completed_par_reuse_probe_remains_available_once(self) -> None:
        self.state.handled_redirects.add(f"module-id:{self.url}")
        log = [
            *self.control_log,
            {"src": DRIVER.PAR_ATTEMPT_REUSE_REQUEST_URI_TEST_NAME},
        ]
        status = {"urls": [self.url], "visited": [self.url]}
        with (
            patch.object(DRIVER, "fetch_json", return_value=status),
            patch.object(DRIVER, "fetch_browser_control_url", return_value=b"") as control,
            patch.object(DRIVER, "mark_browser_url_visited"),
        ):
            DRIVER.drive_browser_control_urls(
                "module-id", log, self.config, self.state, self.context
            )
            DRIVER.drive_browser_control_urls(
                "module-id", log, self.config, self.state, self.context
            )
            control.assert_called_once()

    def test_deferred_par_authentication_preserves_its_required_second_visit(self) -> None:
        log = [
            *self.control_log,
            {"src": DRIVER.PAR_REUSE_PRIOR_TO_AUTH_COMPLETION_TEST_NAME},
        ]
        with (
            patch.object(DRIVER, "fetch_json", return_value=self.browser_status),
            patch.object(
                DRIVER, "fetch_browser_control_url_without_callback", return_value=b""
            ) as deferred,
            patch.object(DRIVER, "mark_browser_url_visited"),
            patch.object(DRIVER, "fetch_url", return_value=b"") as redirect,
        ):
            DRIVER.drive_browser_control_urls(
                "module-id", log, self.config, self.state, self.context
            )
            DRIVER.drive_redirects(
                "module-id", [*log, *self.redirect_log], self.config, self.state, self.context
            )
            deferred.assert_called_once()
            redirect.assert_called_once_with(self.url, self.context)


if __name__ == "__main__":
    unittest.main()
