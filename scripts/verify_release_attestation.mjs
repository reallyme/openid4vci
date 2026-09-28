#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

// SPDX-License-Identifier: MIT OR Apache-2.0

import { createHash } from "node:crypto";
import { appendFileSync, lstatSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const FULL_SHA_PATTERN = /^[0-9a-f]{40}$/u;
const POSITIVE_INTEGER_PATTERN = /^[1-9][0-9]*$/u;
const NON_NEGATIVE_INTEGER_PATTERN = /^(?:0|[1-9][0-9]*)$/u;
const REPOSITORY_PATTERN = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u;
const VERSION_PATTERN = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;
const PREFLIGHT_WORKFLOW = "crates-package-preflight.yml";
const PREFLIGHT_PATH = `.github/workflows/${PREFLIGHT_WORKFLOW}`;
const PREFLIGHT_TITLE = "Crates package preflight";
const ATTESTATION_SCHEMA = "reallyme.openid4vci.crates_preflight.v5";
const DEFAULT_ATTESTATION_PATH = "release-attestation/crates-preflight.json";
const DEFAULT_CRATE_DIRECTORY = "release-attestation/crates";
const MAX_COMMAND_OUTPUT_BYTES = 1_048_576;
const MAX_ATTESTATION_BYTES = 16_384;
const MAX_WAIT_SECONDS = 7_200;
const MAX_POLL_SECONDS = 300;
const DEFAULT_POLL_SECONDS = 20;
const ATTESTATION_KEYS = Object.freeze([
  "crates",
  "prerequisites",
  "release_sha",
  "repository",
  "run_attempt",
  "run_id",
  "schema",
  "version",
  "workflow",
]);
const PREREQUISITE_KEYS = Object.freeze([
  "fuzz",
  "protobuf_ci",
  "rust_ci",
]);
const CRATE_DIGEST_PATTERN = /^[0-9a-f]{64}$/u;
const PUBLIC_CRATE_FILES = Object.freeze([
  "reallyme-openid4vci-proto-{version}.crate",
  "reallyme-openid4vci-types-{version}.crate",
  "openid4vci-attestation-{version}.crate",
  "reallyme-openid4vci-wallet-{version}.crate",
  "openid4vci-profiles-{version}.crate",
  "openid4vci-issuer-{version}.crate",
  "openid4vci-proto-codec-{version}.crate",
  "openid4vci-http-{version}.crate",
  "reallyme-openid4vci-{version}.crate",
]);

export class ReleaseAttestationError extends Error {
  constructor(code) {
    super(code);
    this.name = "ReleaseAttestationError";
    this.code = code;
  }
}

const fail = (code) => {
  throw new ReleaseAttestationError(code);
};

const parsePositiveInteger = (value, code) => {
  if (typeof value !== "string" || !POSITIVE_INTEGER_PATTERN.test(value)) {
    fail(code);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    fail(code);
  }
  return parsed;
};

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
  if (result.error !== undefined || result.status !== 0 || typeof result.stdout !== "string") {
    fail(code);
  }
  try {
    return JSON.parse(result.stdout);
  } catch {
    fail(code);
  }
};

const readAttestation = (path) => {
  let status;
  let contents;
  try {
    status = lstatSync(path);
    if (
      status.isSymbolicLink() ||
      !status.isFile() ||
      status.size === 0 ||
      status.size > MAX_ATTESTATION_BYTES
    ) {
      fail("invalid-attestation-file");
    }
    contents = readFileSync(path, "utf8");
  } catch (error) {
    if (error instanceof ReleaseAttestationError) {
      throw error;
    }
    fail("invalid-attestation-file");
  }
  try {
    return JSON.parse(contents);
  } catch {
    fail("invalid-attestation-json");
  }
};

const isRecord = (value) => value !== null && typeof value === "object" && !Array.isArray(value);

export const verifyAttestationDocument = (value, expected) => {
  if (!isRecord(value)) {
    fail("invalid-attestation-document");
  }
  const keys = Object.keys(value).sort();
  if (keys.length !== ATTESTATION_KEYS.length || keys.some((key, index) => key !== ATTESTATION_KEYS[index])) {
    fail("invalid-attestation-document");
  }
  if (
    value.schema !== ATTESTATION_SCHEMA ||
    value.repository !== expected.repository ||
    value.workflow !== PREFLIGHT_WORKFLOW ||
    value.run_id !== expected.runId ||
    value.run_attempt !== 1 ||
    value.release_sha !== expected.releaseSha ||
    value.version !== expected.releaseVersion
  ) {
    fail("attestation-input-mismatch");
  }
  if (!Array.isArray(value.crates) || value.crates.length !== PUBLIC_CRATE_FILES.length) {
    fail("invalid-crate-attestation");
  }
  if (
    !isRecord(value.prerequisites) ||
    Object.keys(value.prerequisites).sort().join(",") !== PREREQUISITE_KEYS.join(",") ||
    PREREQUISITE_KEYS.some(
      (key) =>
        !Number.isSafeInteger(value.prerequisites[key]) || value.prerequisites[key] < 1,
    )
  ) {
    fail("invalid-prerequisite-attestation");
  }
  const expectedFiles = PUBLIC_CRATE_FILES.map((file) =>
    file.replace("{version}", expected.releaseVersion),
  );
  for (const [index, crate] of value.crates.entries()) {
    if (
      !isRecord(crate) ||
      Object.keys(crate).sort().join(",") !== "file,sha256,size" ||
      crate.file !== expectedFiles[index] ||
      typeof crate.sha256 !== "string" ||
      !CRATE_DIGEST_PATTERN.test(crate.sha256) ||
      !Number.isSafeInteger(crate.size) ||
      crate.size < 1
    ) {
      fail("invalid-crate-attestation");
    }
  }
  return value;
};

export const verifyAttestedCrateArchives = (attestation, crateDirectory) => {
  if (!isRecord(attestation) || !Array.isArray(attestation.crates)) {
    fail("invalid-crate-attestation");
  }
  if (typeof crateDirectory !== "string" || crateDirectory.length === 0) {
    fail("invalid-crate-directory");
  }
  for (const crate of attestation.crates) {
    if (!isRecord(crate) || typeof crate.file !== "string") {
      fail("invalid-crate-attestation");
    }
    const archivePath = join(crateDirectory, crate.file);
    try {
      const status = lstatSync(archivePath);
      if (status.isSymbolicLink() || !status.isFile() || status.size !== crate.size) {
        fail("crate-archive-mismatch");
      }
      const digest = createHash("sha256").update(readFileSync(archivePath)).digest("hex");
      if (digest !== crate.sha256) {
        fail("crate-archive-mismatch");
      }
    } catch (error) {
      if (error instanceof ReleaseAttestationError) {
        throw error;
      }
      fail("crate-archive-mismatch");
    }
  }
};

export const verifyWorkflowRun = (value, expected) => {
  if (!isRecord(value)) {
    fail("invalid-preflight-run");
  }
  if (
    value.workflow_id !== expected.workflowId ||
    value.id !== expected.runId ||
    value.event !== "workflow_dispatch" ||
    value.head_branch !== "main" ||
    value.head_sha !== expected.releaseSha ||
    value.status !== "completed" ||
    value.conclusion !== "success" ||
    value.run_attempt !== 1 ||
    value.path !== PREFLIGHT_PATH
  ) {
    fail("preflight-run-mismatch");
  }
};

const validateListedRun = (value) => {
  if (!isRecord(value)) {
    fail("invalid-preflight-run-list");
  }
  const {
    conclusion,
    display_title: displayTitle,
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
    typeof displayTitle !== "string" ||
    typeof event !== "string" ||
    typeof headBranch !== "string" ||
    typeof headSha !== "string" ||
    typeof path !== "string" ||
    typeof status !== "string" ||
    (conclusion !== null && typeof conclusion !== "string")
  ) {
    fail("invalid-preflight-run-list");
  }
  return {
    conclusion,
    displayTitle,
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

export const selectLatestPreflightRun = (value, expected) => {
  if (!isRecord(value) || !Array.isArray(value.workflow_runs)) {
    fail("invalid-preflight-run-list");
  }
  const candidates = value.workflow_runs
    .map((run) => validateListedRun(run))
    .filter(
      (run) =>
        run.workflowId === expected.workflowId &&
        run.event === "workflow_dispatch" &&
        run.headBranch === "main" &&
        run.headSha === expected.releaseSha &&
        run.path === PREFLIGHT_PATH,
    )
    .sort((left, right) =>
      left.id === right.id ? right.runAttempt - left.runAttempt : right.id - left.id,
    );
  const latest = candidates[0];
  if (latest === undefined) {
    fail("missing-preflight-run");
  }
  const expectedTitle = `${PREFLIGHT_TITLE} ${expected.releaseVersion} @ ${expected.releaseSha}`;
  if (latest.displayTitle !== expectedTitle) {
    fail("preflight-version-mismatch");
  }
  if (latest.status !== "completed" || latest.conclusion !== "success") {
    fail("latest-preflight-run-not-successful");
  }
  if (latest.runAttempt !== 1) {
    fail("preflight-rerun-not-accepted");
  }
  return latest;
};

const resolvePreflightRun = ({ repository, releaseSha, releaseVersion }) => {
  const workflow = runJson(
    ["api", `repos/${repository}/actions/workflows/${PREFLIGHT_WORKFLOW}`],
    "workflow-query-failed",
  );
  if (!isRecord(workflow) || !Number.isSafeInteger(workflow.id) || workflow.id < 1) {
    fail("invalid-workflow-response");
  }
  const runs = runJson(
    [
      "api",
      `repos/${repository}/actions/workflows/${workflow.id}/runs?branch=main&event=workflow_dispatch&per_page=100`,
    ],
    "preflight-run-list-query-failed",
  );
  const latest = selectLatestPreflightRun(runs, {
    workflowId: workflow.id,
    releaseSha,
    releaseVersion,
  });
  return { runId: latest.id, workflowId: workflow.id };
};

const resolvePreflightRunWithWait = ({
  pollSeconds,
  releaseSha,
  releaseVersion,
  repository,
  waitSeconds,
}) => {
  const deadline = Date.now() + waitSeconds * 1_000;
  for (;;) {
    try {
      return resolvePreflightRun({ repository, releaseSha, releaseVersion });
    } catch (error) {
      const waitable =
        error instanceof ReleaseAttestationError &&
        (error.code === "missing-preflight-run" ||
          error.code === "latest-preflight-run-not-successful");
      if (!waitable || Date.now() >= deadline) {
        throw error;
      }
      const remainingSeconds = Math.max(1, Math.ceil((deadline - Date.now()) / 1_000));
      sleepSeconds(Math.min(pollSeconds, remainingSeconds));
    }
  }
};

export const verifyReleaseAttestation = ({ env = process.env } = {}) => {
  const repository = env.GITHUB_REPOSITORY;
  const releaseSha = env.RELEASE_SHA;
  const releaseVersion = env.RELEASE_VERSION;
  if (typeof repository !== "string" || !REPOSITORY_PATTERN.test(repository)) {
    fail("invalid-repository");
  }
  if (typeof releaseSha !== "string" || !FULL_SHA_PATTERN.test(releaseSha)) {
    fail("invalid-release-sha");
  }
  if (typeof releaseVersion !== "string" || !VERSION_PATTERN.test(releaseVersion)) {
    fail("invalid-release-version");
  }
  if (typeof env.GH_TOKEN !== "string" || env.GH_TOKEN.length === 0) {
    fail("missing-github-token");
  }
  if (env.GITHUB_SHA !== releaseSha) {
    fail("workflow-head-mismatch");
  }
  const waitSeconds = parseSeconds(
    env.RELEASE_ATTESTATION_WAIT_SECONDS,
    0,
    "invalid-release-attestation-wait-seconds",
    MAX_WAIT_SECONDS,
  );
  const pollSeconds = parseSeconds(
    env.RELEASE_ATTESTATION_POLL_SECONDS,
    DEFAULT_POLL_SECONDS,
    "invalid-release-attestation-poll-seconds",
    MAX_POLL_SECONDS,
  );
  // Waiting with a zero interval would repeatedly query the API without backoff.
  if (waitSeconds > 0 && pollSeconds === 0) {
    fail("invalid-release-attestation-poll-seconds");
  }
  const resolved = resolvePreflightRunWithWait({
    pollSeconds,
    releaseSha,
    releaseVersion,
    repository,
    waitSeconds,
  });
  const suppliedRunId = env.PREFLIGHT_RUN_ID;
  const runId =
    suppliedRunId === undefined || suppliedRunId === ""
      ? resolved.runId
      : parsePositiveInteger(suppliedRunId, "invalid-preflight-run-id");
  if (runId !== resolved.runId) {
    fail("preflight-run-id-changed");
  }
  const resolvesOnly = env.RELEASE_ATTESTATION_RESOLVE_ONLY === "1";
  if (resolvesOnly) {
    return { releaseSha, releaseVersion, runId };
  }
  const run = runJson(
    ["api", `repos/${repository}/actions/runs/${runId}`],
    "preflight-run-query-failed",
  );
  verifyWorkflowRun(run, { workflowId: resolved.workflowId, runId, releaseSha });
  const mainRef = runJson(
    ["api", `repos/${repository}/git/ref/heads/main`],
    "main-ref-query-failed",
  );
  if (!isRecord(mainRef) || !isRecord(mainRef.object) || mainRef.object.sha !== releaseSha) {
    fail("release-sha-is-not-current-main");
  }
  const attestationPath = env.RELEASE_ATTESTATION_PATH ?? DEFAULT_ATTESTATION_PATH;
  if (typeof attestationPath !== "string" || attestationPath.length === 0) {
    fail("invalid-attestation-path");
  }
  const attestation = verifyAttestationDocument(readAttestation(attestationPath), {
    repository,
    runId,
    releaseSha,
    releaseVersion,
  });
  verifyAttestedCrateArchives(
    attestation,
    env.RELEASE_ATTESTATION_CRATE_DIRECTORY ?? DEFAULT_CRATE_DIRECTORY,
  );
  return { releaseSha, releaseVersion, runId };
};

const isMain = process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  try {
    const attestation = verifyReleaseAttestation();
    if (process.env.RELEASE_ATTESTATION_WRITE_GITHUB_OUTPUT === "1") {
      const outputPath = process.env.GITHUB_OUTPUT;
      if (typeof outputPath !== "string" || outputPath.length === 0) {
        fail("missing-github-output");
      }
      appendFileSync(
        outputPath,
        `release_sha=${attestation.releaseSha}\nrelease_version=${attestation.releaseVersion}\npreflight_run_id=${attestation.runId}\n`,
        { encoding: "utf8" },
      );
    }
    console.log("reviewed crates package preflight attestation verified");
  } catch (error) {
    const code = error instanceof ReleaseAttestationError ? error.code : "unexpected-failure";
    console.error(`release attestation verification failed: ${code}`);
    process.exit(1);
  }
}
