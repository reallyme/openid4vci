#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { spawnSync } from "node:child_process";
import { appendFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const FULL_SHA_PATTERN = /^[0-9a-f]{40}$/u;
const NON_NEGATIVE_INTEGER_PATTERN = /^(?:0|[1-9][0-9]*)$/u;
const REPOSITORY_PATTERN = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u;
const MAX_COMMAND_OUTPUT_BYTES = 1_048_576;
const MAX_WAIT_SECONDS = 7_200;
const MAX_POLL_SECONDS = 300;
const DEFAULT_POLL_SECONDS = 20;
const PUSH_OR_DISPATCH = Object.freeze(["push", "workflow_dispatch"]);

export const REQUIRED_WORKFLOWS = Object.freeze([
  Object.freeze({
    allowedEvents: PUSH_OR_DISPATCH,
    outputName: "rust_ci_run_id",
    workflowFile: "rust-ci.yml",
  }),
  Object.freeze({
    allowedEvents: PUSH_OR_DISPATCH,
    outputName: "protobuf_ci_run_id",
    workflowFile: "protobuf-ci.yml",
  }),
  Object.freeze({
    allowedEvents: PUSH_OR_DISPATCH,
    outputName: "fuzz_run_id",
    workflowFile: "fuzz.yml",
  }),
]);

export class RequiredCiError extends Error {
  constructor(code) {
    super(code);
    this.name = "RequiredCiError";
    this.code = code;
  }
}

const fail = (code, workflowFile) => {
  throw new RequiredCiError(
    workflowFile === undefined ? code : `${code}:${workflowFile}`,
  );
};

const isRecord = (value) =>
  value !== null && typeof value === "object" && !Array.isArray(value);

const parseSeconds = (value, defaultValue, code, maximum) => {
  if (value === undefined || value === "") {
    return defaultValue;
  }
  if (typeof value !== "string" || !NON_NEGATIVE_INTEGER_PATTERN.test(value)) {
    fail(code);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed > maximum) {
    fail(code);
  }
  return parsed;
};

const sleepSeconds = (seconds) => {
  if (seconds === 0) {
    return;
  }
  const waitBuffer = new SharedArrayBuffer(4);
  Atomics.wait(new Int32Array(waitBuffer), 0, 0, seconds * 1_000);
};

const runJson = (arguments_, code) => {
  const result = spawnSync("gh", arguments_, {
    encoding: "utf8",
    maxBuffer: MAX_COMMAND_OUTPUT_BYTES,
    stdio: ["ignore", "pipe", "ignore"],
  });
  if (
    result.error !== undefined ||
    result.status !== 0 ||
    typeof result.stdout !== "string"
  ) {
    fail(code);
  }
  try {
    return JSON.parse(result.stdout);
  } catch {
    fail(code);
  }
};

const validateRun = (value) => {
  if (!isRecord(value)) {
    fail("invalid-required-ci-run-list");
  }
  const {
    conclusion,
    event,
    head_branch: headBranch,
    head_sha: headSha,
    id,
    path,
    run_attempt: runAttempt,
    status,
    workflow_id: workflowId,
  } = value;
  if (
    !Number.isSafeInteger(id) ||
    id < 1 ||
    !Number.isSafeInteger(workflowId) ||
    workflowId < 1 ||
    !Number.isSafeInteger(runAttempt) ||
    runAttempt < 1 ||
    typeof event !== "string" ||
    typeof headBranch !== "string" ||
    typeof headSha !== "string" ||
    typeof path !== "string" ||
    typeof status !== "string" ||
    (conclusion !== null && typeof conclusion !== "string")
  ) {
    fail("invalid-required-ci-run-list");
  }
  return {
    conclusion,
    event,
    headBranch,
    headSha,
    id,
    path,
    runAttempt,
    status,
    workflowId,
  };
};

export const selectRequiredCiRun = (value, expected) => {
  if (!isRecord(value) || !Array.isArray(value.workflow_runs)) {
    fail("invalid-required-ci-run-list");
  }
  const candidates = value.workflow_runs
    .map((run) => validateRun(run))
    .filter(
      (run) =>
        run.workflowId === expected.workflowId &&
        expected.allowedEvents.includes(run.event) &&
        run.headBranch === "main" &&
        run.headSha === expected.releaseSha &&
        run.path === `.github/workflows/${expected.workflowFile}`,
    )
    .sort((left, right) =>
      left.id === right.id
        ? right.runAttempt - left.runAttempt
        : right.id - left.id,
    );
  const latest = candidates[0];
  if (latest === undefined) {
    fail("missing-required-ci-run", expected.workflowFile);
  }
  if (latest.runAttempt !== 1) {
    fail("required-ci-rerun-not-accepted", expected.workflowFile);
  }
  if (latest.status !== "completed") {
    fail("required-ci-run-pending", expected.workflowFile);
  }
  if (latest.conclusion === "failure") {
    fail("required-ci-run-failed", expected.workflowFile);
  }
  if (latest.conclusion === "cancelled") {
    fail("required-ci-run-cancelled", expected.workflowFile);
  }
  if (latest.conclusion !== "success") {
    fail("required-ci-run-not-successful", expected.workflowFile);
  }
  return latest;
};

const resolveRequiredCi = ({ repository, releaseSha }) =>
  REQUIRED_WORKFLOWS.map((requirement) => {
    const workflow = runJson(
      ["api", `repos/${repository}/actions/workflows/${requirement.workflowFile}`],
      `required-ci-workflow-query-failed:${requirement.workflowFile}`,
    );
    if (
      !isRecord(workflow) ||
      !Number.isSafeInteger(workflow.id) ||
      workflow.id < 1
    ) {
      fail("invalid-required-ci-workflow-response", requirement.workflowFile);
    }
    const runs = runJson(
      [
        "api",
        `repos/${repository}/actions/workflows/${workflow.id}/runs?branch=main&head_sha=${releaseSha}&per_page=100`,
      ],
      `required-ci-run-list-query-failed:${requirement.workflowFile}`,
    );
    return selectRequiredCiRun(runs, {
      allowedEvents: requirement.allowedEvents,
      releaseSha,
      workflowFile: requirement.workflowFile,
      workflowId: workflow.id,
    });
  });

const isWaitableRequiredCiError = (error) =>
  error instanceof RequiredCiError &&
  (error.code.startsWith("missing-required-ci-run:") ||
    error.code.startsWith("required-ci-run-pending:"));

export const resolveRequiredCiWithWait = ({
  pollSeconds,
  releaseSha,
  repository,
  waitSeconds,
  now = Date.now,
  onWait = () => {},
  resolve = resolveRequiredCi,
  sleep = sleepSeconds,
}) => {
  const deadline = now() + waitSeconds * 1_000;
  for (;;) {
    try {
      return resolve({ repository, releaseSha });
    } catch (error) {
      if (!isWaitableRequiredCiError(error) || now() >= deadline) {
        throw error;
      }
      const remainingSeconds = Math.max(
        1,
        Math.ceil((deadline - now()) / 1_000),
      );
      const retrySeconds = Math.min(pollSeconds, remainingSeconds);
      onWait({
        code: error.code,
        remainingSeconds,
        retrySeconds,
      });
      sleep(retrySeconds);
    }
  }
};

export const verifyRequiredCi = ({ env = process.env, onWait } = {}) => {
  const repository = env.GITHUB_REPOSITORY;
  const releaseSha = env.RELEASE_SHA;
  if (typeof repository !== "string" || !REPOSITORY_PATTERN.test(repository)) {
    fail("invalid-repository");
  }
  if (typeof releaseSha !== "string" || !FULL_SHA_PATTERN.test(releaseSha)) {
    fail("invalid-release-sha");
  }
  if (env.GITHUB_SHA !== releaseSha) {
    fail("workflow-head-mismatch");
  }
  if (typeof env.GH_TOKEN !== "string" || env.GH_TOKEN.length === 0) {
    fail("missing-github-token");
  }
  const waitSeconds = parseSeconds(
    env.REQUIRED_CI_WAIT_SECONDS,
    0,
    "invalid-required-ci-wait-seconds",
    MAX_WAIT_SECONDS,
  );
  const pollSeconds = parseSeconds(
    env.REQUIRED_CI_POLL_SECONDS,
    DEFAULT_POLL_SECONDS,
    "invalid-required-ci-poll-seconds",
    MAX_POLL_SECONDS,
  );
  if (waitSeconds > 0 && pollSeconds === 0) {
    fail("invalid-required-ci-poll-seconds");
  }

  return resolveRequiredCiWithWait({
    onWait,
    pollSeconds,
    releaseSha,
    repository,
    waitSeconds,
  });
};

export const formatRequiredCiOutputs = (runs) => {
  if (!Array.isArray(runs) || runs.length !== REQUIRED_WORKFLOWS.length) {
    fail("invalid-required-ci-output-set");
  }
  return runs
    .map((run, index) => {
      if (!isRecord(run) || !Number.isSafeInteger(run.id) || run.id < 1) {
        fail("invalid-required-ci-output-set");
      }
      return `${REQUIRED_WORKFLOWS[index].outputName}=${run.id}`;
    })
    .join("\n");
};

const isMain =
  process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  try {
    const runs = verifyRequiredCi({
      onWait: ({ code, remainingSeconds, retrySeconds }) => {
        console.log(
          `required CI evidence pending: ${code}; retrying in ${retrySeconds}s (${remainingSeconds}s remain)`,
        );
      },
    });
    if (process.env.REQUIRED_CI_WRITE_GITHUB_OUTPUT === "1") {
      const outputPath = process.env.GITHUB_OUTPUT;
      if (typeof outputPath !== "string" || outputPath.length === 0) {
        fail("missing-github-output");
      }
      appendFileSync(outputPath, `${formatRequiredCiOutputs(runs)}\n`, {
        encoding: "utf8",
      });
    }
    console.log("exact release commit has successful required workflow evidence");
  } catch (error) {
    const code =
      error instanceof RequiredCiError ? error.code : "unexpected-failure";
    console.error(`required CI verification failed: ${code}`);
    process.exit(1);
  }
}
