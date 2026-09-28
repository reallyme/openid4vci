#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import {
  formatRequiredCiOutputs,
  RequiredCiError,
  REQUIRED_WORKFLOWS,
  resolveRequiredCiWithWait,
  selectRequiredCiRun,
} from "./verify_required_ci.mjs";

const RELEASE_SHA = "0123456789abcdef0123456789abcdef01234567";
const WORKFLOW_ID = 41;
const WORKFLOW_FILE = "fuzz.yml";
const expected = {
  allowedEvents: ["push", "workflow_dispatch"],
  releaseSha: RELEASE_SHA,
  workflowFile: WORKFLOW_FILE,
  workflowId: WORKFLOW_ID,
};

const workflowRun = (overrides = {}) => ({
  conclusion: "success",
  event: "push",
  head_branch: "main",
  head_sha: RELEASE_SHA,
  id: 100,
  path: `.github/workflows/${WORKFLOW_FILE}`,
  run_attempt: 1,
  status: "completed",
  workflow_id: WORKFLOW_ID,
  ...overrides,
});

test("accepts exact successful first-attempt push or dispatch evidence", () => {
  assert.equal(
    selectRequiredCiRun({ workflow_runs: [workflowRun()] }, expected).event,
    "push",
  );
  assert.equal(
    selectRequiredCiRun(
      { workflow_runs: [workflowRun({ event: "workflow_dispatch" })] },
      expected,
    ).event,
    "workflow_dispatch",
  );
});

test("distinguishes failed, cancelled, pending, and rerun evidence", () => {
  for (const [latest, code] of [
    [workflowRun({ conclusion: "failure", id: 101 }), "required-ci-run-failed"],
    [workflowRun({ conclusion: "cancelled", id: 101 }), "required-ci-run-cancelled"],
    [
      workflowRun({ conclusion: null, id: 101, status: "in_progress" }),
      "required-ci-run-pending",
    ],
    [workflowRun({ id: 101, run_attempt: 2 }), "required-ci-rerun-not-accepted"],
  ]) {
    assert.throws(
      () =>
        selectRequiredCiRun(
          { workflow_runs: [workflowRun(), latest] },
          expected,
        ),
      (error) =>
        error instanceof RequiredCiError &&
        error.code === `${code}:${WORKFLOW_FILE}`,
    );
  }
});

test("rejects missing, malformed, or incorrectly bound evidence", () => {
  assert.throws(
    () => selectRequiredCiRun({ workflow_runs: [] }, expected),
    (error) =>
      error instanceof RequiredCiError &&
      error.code === `missing-required-ci-run:${WORKFLOW_FILE}`,
  );
  for (const malformed of [
    null,
    {},
    { workflow_runs: "invalid" },
    { workflow_runs: [null] },
    { workflow_runs: [workflowRun({ id: "100" })] },
  ]) {
    assert.throws(
      () => selectRequiredCiRun(malformed, expected),
      RequiredCiError,
    );
  }
  for (const mismatch of [
    { workflow_id: WORKFLOW_ID + 1 },
    { path: ".github/workflows/other.yml" },
    { head_branch: "feature" },
    { head_sha: "fedcba9876543210fedcba9876543210fedcba98" },
    { event: "schedule" },
  ]) {
    assert.throws(
      () =>
        selectRequiredCiRun(
          { workflow_runs: [workflowRun(mismatch)] },
          expected,
        ),
      RequiredCiError,
    );
  }
});

test("serializes the fixed prerequisite evidence mapping", () => {
  assert.equal(
    formatRequiredCiOutputs([{ id: 11 }, { id: 12 }, { id: 13 }, { id: 14 }]),
    [
      "rust_ci_run_id=11",
      "protobuf_ci_run_id=12",
      "fuzz_run_id=13",
      "oidf_conformance_run_id=14",
    ].join("\n"),
  );
  assert.deepEqual(
    REQUIRED_WORKFLOWS.map(({ workflowFile }) => workflowFile),
    ["rust-ci.yml", "protobuf-ci.yml", "fuzz.yml", "oidf-conformance.yml"],
  );
  assert.throws(
    () => formatRequiredCiOutputs([{ id: 11 }]),
    RequiredCiError,
  );
});

test("bounded polling waits for missing and pending exact-commit evidence", () => {
  let currentTime = 1_000;
  let attempts = 0;
  const sleeps = [];
  const expectedRuns = [{ id: 11 }, { id: 12 }, { id: 13 }, { id: 14 }];
  const resolved = resolveRequiredCiWithWait({
    pollSeconds: 20,
    releaseSha: RELEASE_SHA,
    repository: "reallyme/openid4vci",
    waitSeconds: 60,
    now: () => currentTime,
    resolve: () => {
      attempts += 1;
      if (attempts === 1) {
        throw new RequiredCiError("required-ci-run-pending:fuzz.yml");
      }
      if (attempts === 2) {
        throw new RequiredCiError("missing-required-ci-run:oidf-conformance.yml");
      }
      return expectedRuns;
    },
    sleep: (seconds) => {
      sleeps.push(seconds);
      currentTime += seconds * 1_000;
    },
  });

  assert.equal(attempts, 3);
  assert.deepEqual(sleeps, [20, 20]);
  assert.equal(resolved, expectedRuns);
});

test("bounded polling fails immediately for terminal outcomes", () => {
  let sleeps = 0;
  assert.throws(
    () =>
      resolveRequiredCiWithWait({
        pollSeconds: 20,
        releaseSha: RELEASE_SHA,
        repository: "reallyme/openid4vci",
        waitSeconds: 60,
        resolve: () => {
          throw new RequiredCiError("required-ci-run-failed:fuzz.yml");
        },
        sleep: () => {
          sleeps += 1;
        },
      }),
    (error) =>
      error instanceof RequiredCiError &&
      error.code === "required-ci-run-failed:fuzz.yml",
  );
  assert.equal(sleeps, 0);
});

test("bounded polling stops at its deadline", () => {
  let currentTime = 1_000;
  const sleeps = [];
  assert.throws(
    () =>
      resolveRequiredCiWithWait({
        pollSeconds: 20,
        releaseSha: RELEASE_SHA,
        repository: "reallyme/openid4vci",
        waitSeconds: 30,
        now: () => currentTime,
        resolve: () => {
          throw new RequiredCiError("required-ci-run-pending:fuzz.yml");
        },
        sleep: (seconds) => {
          sleeps.push(seconds);
          currentTime += seconds * 1_000;
        },
      }),
    (error) =>
      error instanceof RequiredCiError &&
      error.code === "required-ci-run-pending:fuzz.yml",
  );
  assert.deepEqual(sleeps, [20, 10]);
});
