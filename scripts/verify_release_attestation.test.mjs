#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  ReleaseAttestationError,
  selectLatestPreflightRun,
  verifyAttestationDocument,
  verifyAttestedCrateArchives,
  verifyWorkflowRun,
  verifyReleaseAttestation,
} from "./verify_release_attestation.mjs";

const releaseSha = "a".repeat(40);
const expected = Object.freeze({
  repository: "reallyme/cose",
  runId: 123,
  releaseSha,
  releaseVersion: "0.2.1",
});
const attestation = (overrides = {}) => ({
  schema: "reallyme.openid4vci.crates_preflight.v4",
  crates: [
    { file: "reallyme-openid4vci-wallet-0.2.1.crate", sha256: "1".repeat(64), size: 101 },
    { file: "reallyme-openid4vci-proto-0.2.1.crate", sha256: "2".repeat(64), size: 102 },
    { file: "reallyme-openid4vci-types-0.2.1.crate", sha256: "3".repeat(64), size: 103 },
  ],
  prerequisites: {
    fuzz: 201,
    protobuf_ci: 203,
    rust_ci: 204,
  },
  repository: expected.repository,
  workflow: "crates-package-preflight.yml",
  run_id: expected.runId,
  run_attempt: 1,
  release_sha: releaseSha,
  version: expected.releaseVersion,
  ...overrides,
});
const workflowRun = (overrides = {}) => ({
  workflow_id: 456,
  id: expected.runId,
  event: "workflow_dispatch",
  head_branch: "main",
  head_sha: releaseSha,
  status: "completed",
  conclusion: "success",
  run_attempt: 1,
  path: ".github/workflows/crates-package-preflight.yml",
  ...overrides,
});
const listedWorkflowRun = (overrides = {}) => ({
  workflow_id: 456,
  id: expected.runId,
  event: "workflow_dispatch",
  head_branch: "main",
  head_sha: releaseSha,
  status: "completed",
  conclusion: "success",
  run_attempt: 1,
  path: ".github/workflows/crates-package-preflight.yml",
  display_title: `Crates package preflight ${expected.releaseVersion} @ ${releaseSha}`,
  ...overrides,
});

test("reviewed attestation accepts the exact run, SHA, and version", () => {
  assert.doesNotThrow(() => verifyAttestationDocument(attestation(), expected));
  assert.doesNotThrow(() =>
    verifyWorkflowRun(workflowRun(), {
      workflowId: 456,
      runId: expected.runId,
      releaseSha,
    }),
  );
});

test("attestation rejects mismatched inputs and unreviewed fields", () => {
  for (const candidate of [
    attestation({ version: "0.1.0" }),
    attestation({ release_sha: "b".repeat(40) }),
    attestation({ run_id: 124 }),
    attestation({ extra: true }),
    attestation({ crates: [] }),
    attestation({ prerequisites: { fuzz: 201 } }),
    attestation({ prerequisites: {
      fuzz: 201,
      protobuf_ci: 203,
      rust_ci: 0,
    } }),
  ]) {
    assert.throws(
      () => verifyAttestationDocument(candidate, expected),
      ReleaseAttestationError,
    );
  }
});

test("crate archive verification hashes the reviewed bytes", () => {
  const directory = mkdtempSync(join(tmpdir(), "openid4vci-attestation-"));
  try {
    const document = attestation();
    for (const [index, crate] of document.crates.entries()) {
      const bytes = Buffer.alloc(index + 1, index + 1);
      writeFileSync(join(directory, crate.file), bytes);
      crate.size = bytes.length;
      crate.sha256 = createHash("sha256").update(bytes).digest("hex");
    }
    assert.doesNotThrow(() => verifyAttestedCrateArchives(document, directory));
    writeFileSync(join(directory, document.crates[0].file), Buffer.from([9]));
    assert.throws(
      () => verifyAttestedCrateArchives(document, directory),
      { name: "ReleaseAttestationError", code: "crate-archive-mismatch" },
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("crate archive verification rejects missing files and symbolic links", () => {
  const directory = mkdtempSync(join(tmpdir(), "openid4vci-attestation-"));
  try {
    const document = attestation();
    assert.throws(
      () => verifyAttestedCrateArchives(document, directory),
      { name: "ReleaseAttestationError", code: "crate-archive-mismatch" },
    );
    const target = join(directory, "target.crate");
    writeFileSync(target, Buffer.alloc(101, 1));
    symlinkSync(target, join(directory, document.crates[0].file));
    assert.throws(
      () => verifyAttestedCrateArchives(document, directory),
      { name: "ReleaseAttestationError", code: "crate-archive-mismatch" },
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("failed, rerun, wrong-branch, and wrong-workflow runs fail closed", () => {
  for (const candidate of [
    workflowRun({ conclusion: "failure" }),
    workflowRun({ run_attempt: 2 }),
    workflowRun({ head_branch: "feature" }),
    workflowRun({ workflow_id: 457 }),
    workflowRun({ path: ".github/workflows/other.yml@refs/heads/main" }),
  ]) {
    assert.throws(
      () =>
        verifyWorkflowRun(candidate, {
          workflowId: 456,
          runId: expected.runId,
          releaseSha,
        }),
      ReleaseAttestationError,
    );
  }
});

test("automatic resolution selects the latest exact successful preflight", () => {
  const latest = selectLatestPreflightRun(
    {
      workflow_runs: [
        listedWorkflowRun({ id: 121 }),
        listedWorkflowRun({ id: 123 }),
        listedWorkflowRun({ id: 124, head_sha: "b".repeat(40) }),
      ],
    },
    {
      workflowId: 456,
      releaseSha,
      releaseVersion: expected.releaseVersion,
    },
  );
  assert.equal(latest.id, 123);
});

test("newer failed, running, wrong-version, and rerun preflights fail closed", () => {
  const rejectedLatestRuns = [
    listedWorkflowRun({ id: 124, conclusion: "failure" }),
    listedWorkflowRun({ id: 124, conclusion: null, status: "in_progress" }),
    listedWorkflowRun({
      id: 124,
      display_title: `Crates package preflight 0.1.0 @ ${releaseSha}`,
    }),
    listedWorkflowRun({ id: 124, run_attempt: 2 }),
  ];
  for (const rejected of rejectedLatestRuns) {
    assert.throws(
      () =>
        selectLatestPreflightRun(
          { workflow_runs: [listedWorkflowRun({ id: 123 }), rejected] },
          {
            workflowId: 456,
            releaseSha,
            releaseVersion: expected.releaseVersion,
          },
        ),
      ReleaseAttestationError,
    );
  }
});

test("automatic resolution rejects missing and malformed workflow results", () => {
  for (const candidate of [{}, { workflow_runs: [] }, { workflow_runs: [null] }]) {
    assert.throws(
      () =>
        selectLatestPreflightRun(candidate, {
          workflowId: 456,
          releaseSha,
          releaseVersion: expected.releaseVersion,
        }),
      ReleaseAttestationError,
    );
  }
});

test("waiting rejects zero polling intervals before querying GitHub", () => {
  assert.throws(() => verifyReleaseAttestation({ env: {
    GITHUB_REPOSITORY: expected.repository,
    RELEASE_SHA: releaseSha,
    RELEASE_VERSION: expected.releaseVersion,
    GITHUB_SHA: releaseSha,
    GH_TOKEN: "test-placeholder",
    RELEASE_ATTESTATION_WAIT_SECONDS: "60",
    RELEASE_ATTESTATION_POLL_SECONDS: "0",
  } }), { name: "ReleaseAttestationError", code: "invalid-release-attestation-poll-seconds" });
});
