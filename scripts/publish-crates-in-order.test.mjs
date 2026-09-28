// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import test from "node:test";

const script = fileURLToPath(new URL("./publish-crates-in-order.mjs", import.meta.url));

function runFixture({ mode = "publish", scenario = "success", requirement = "^0.2.2", version = "0.2.2" } = {}) {
  const directory = mkdtempSync(join(tmpdir(), "openid4vci-publish-test-"));
  try {
    const callsPath = join(directory, "calls.json");
    const preload = join(directory, "mock.mjs");
    const packageDirectory = join(directory, "package");
    const reviewedDirectory = join(directory, "reviewed");
    const publicationLedgerPath = join(directory, "publication-ledger.json");
    mkdirSync(packageDirectory);
    mkdirSync(reviewedDirectory);
    for (const name of [
      "reallyme-openid4vci-proto",
      "reallyme-openid4vci-types",
      "reallyme-openid4vci-wallet",
    ]) {
      const archive = `${name}-${version}.crate`;
      writeFileSync(join(packageDirectory, archive), `reviewed:${archive}`);
      writeFileSync(join(reviewedDirectory, archive), `reviewed:${archive}`);
    }
    // Intercept every child process: these tests must never invoke Cargo,
    // access a registry, publish a crate, or perform real retry waits.
    writeFileSync(preload, `
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { writeFileSync } from "node:fs";
const calls = [];
const scenario = ${JSON.stringify(scenario)};
let attempts = 0;
Atomics.wait = (_array, _index, _value, delay) => {
  calls.push(["wait", delay]);
  writeFileSync(${JSON.stringify(callsPath)}, JSON.stringify(calls));
  return "timed-out";
};
childProcess.spawnSync = (command, args) => {
  calls.push([command, ...args]);
  writeFileSync(${JSON.stringify(callsPath)}, JSON.stringify(calls));
  const ok = { status: 0, stdout: "", stderr: "" };
  if (command === "tar") return ok;
  if (command === "curl") {
    const outputIndex = args.indexOf("--output");
    const output = args[outputIndex + 1];
    const archive = args[args.length - 1].split("/").at(-1);
    writeFileSync(output, "reviewed:" + archive);
    return ok;
  }
  if (command !== "cargo") return { ...ok, status: 99 };
  if (args[0] === "metadata") return { ...ok, stdout: JSON.stringify({
    target_directory: ${JSON.stringify(directory)},
    packages: [
      { name: "reallyme-openid4vci-types", version: ${JSON.stringify(version)}, publish: null,
        dependencies: [] },
      { name: "reallyme-openid4vci-proto", version: ${JSON.stringify(version)}, publish: null,
        dependencies: [] },
      { name: "reallyme-openid4vci-wallet", version: ${JSON.stringify(version)}, publish: null,
        dependencies: [{ name: "reallyme-openid4vci-types", source: null, path: "crates/types",
          kind: null, req: ${JSON.stringify(requirement)} }] },
    ],
  }) };
  if (args[0] === "package") return ok;
  if (args[0] === "fetch" || args[0] === "update" || args[0] === "check") return ok;
  if (args[0] !== "publish") return { ...ok, status: 99 };
  attempts += 1;
  if (scenario === "exhausted" || (scenario === "retry" && attempts === 1)) {
    return { ...ok, status: 101, stderr: "too many requests" };
  }
  if (scenario === "retry-429" && attempts === 1) {
    return { ...ok, status: 101, stderr: "registry returned HTTP 429" };
  }
  if (scenario === "retry-after" && attempts === 1) {
    return { ...ok, status: 101,
      stderr: "rate limit exceeded; try again after Thu, 01 Jan 1970 00:00:00 GMT" };
  }
  if (scenario === "index-missing" && attempts === 1) {
    return { ...ok, status: 101, stderr: "no matching package named dependency" };
  }
  if (scenario === "index-version" && attempts === 1) {
    return { ...ok, status: 101,
      stderr: "failed to select a version for the requirement dependency = ^0.2.2" };
  }
  if (scenario === "failure") return { ...ok, status: 101, stderr: "package verification failed" };
  return ok;
};
syncBuiltinESMExports();
`);
    const result = spawnSync(process.execPath, ["--import", pathToFileURL(preload).href, script, mode], {
      cwd: directory,
      encoding: "utf8",
      timeout: 10_000,
      env: {
        ...process.env,
        PUBLICATION_LEDGER_PATH: publicationLedgerPath,
        RELEASE_SHA: "a".repeat(40),
        RELEASE_VERSION: version,
        REVIEWED_CRATE_DIRECTORY: reviewedDirectory,
      },
    });
    assert.equal(result.error, undefined);
    const ledger = existsSync(publicationLedgerPath)
      ? JSON.parse(readFileSync(publicationLedgerPath, "utf8"))
      : null;
    return { ...result, calls: JSON.parse(readFileSync(callsPath, "utf8")), ledger };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test("successful publication respects dependency order", () => {
  const result = runFixture();
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.calls.filter((call) => call[1] === "publish").map((call) => call[3]),
    ["reallyme-openid4vci-types", "reallyme-openid4vci-proto", "reallyme-openid4vci-wallet"]);
  assert.equal(result.ledger.state, "completed");
  assert.deepEqual(
    result.ledger.crates.map((crate) => crate.state),
    ["published", "published", "published"],
  );
  assert.ok(result.ledger.crates.every((crate) => /^[0-9a-f]{64}$/u.test(crate.archive_sha256)));
});

test("package inspection isolates targets and skips duplicate verification builds", () => {
  const result = runFixture({ mode: "inspect" });
  assert.equal(result.status, 0, result.stderr);

  const checks = result.calls.filter((call) => call[0] === "cargo" && call[1] === "check");
  assert.equal(checks.length, 3);
  const targetDirectories = checks.map((call) => {
    const targetIndex = call.indexOf("--target-dir");
    assert.notEqual(targetIndex, -1);
    return call[targetIndex + 1];
  });
  assert.equal(new Set(targetDirectories).size, 3);
  assert.deepEqual(
    targetDirectories.map((directory) => directory.split("/").at(-1)),
    [
      "reallyme-openid4vci-types",
      "reallyme-openid4vci-proto",
      "reallyme-openid4vci-wallet",
    ],
  );

  const dryRuns = result.calls.filter(
    (call) => call[0] === "cargo" && call[1] === "publish",
  );
  assert.equal(dryRuns.length, 3);
  assert.ok(dryRuns.every((call) => call.includes("--dry-run")));
  assert.ok(dryRuns.every((call) => call.includes("--no-verify")));

  const resolutionCalls = result.calls.filter(
    (call) =>
      call[0] === "cargo" && (call[1] === "fetch" || call[1] === "update"),
  );
  assert.deepEqual(
    resolutionCalls.map((call) => call[1]),
    ["fetch", "fetch", "update"],
  );
  const patchConfigs = resolutionCalls.map((call) =>
    call
      .filter((argument) => argument.startsWith("patch.crates-io."))
      .map((argument) => argument.match(/^patch\.crates-io\.'([^']+)'\.path=/u)?.[1]),
  );
  assert.deepEqual(patchConfigs, [
    [],
    [],
    ["reallyme-openid4vci-types"],
  ]);
  assert.ok(resolutionCalls[2].includes("--offline"));
  assert.deepEqual(
    resolutionCalls[2].slice(
      resolutionCalls[2].indexOf("-p"),
      resolutionCalls[2].indexOf("-p") + 2,
    ),
    ["-p", "reallyme-openid4vci-types"],
  );
});

test("rate-limit exhaustion fails without publishing dependent crates", () => {
  const result = runFixture({ scenario: "exhausted" });
  assert.equal(result.status, 101);
  const publishes = result.calls.filter((call) => call[1] === "publish");
  assert.equal(publishes.length, 12);
  assert.ok(publishes.every((call) => call[3] === "reallyme-openid4vci-types"));
  assert.equal(result.calls.filter((call) => call[0] === "wait").length, 11);
  assert.equal(result.ledger.state, "in_progress");
  assert.deepEqual(
    result.ledger.crates.map((crate) => crate.state),
    ["attempting", "pending", "pending"],
  );
});

test("transient rate limits retry before publishing dependent crates", () => {
  const result = runFixture({ scenario: "retry" });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.calls.filter((call) => call[0] === "wait"), [["wait", 60000]]);
});

test("HTTP 429 retries before publishing dependent crates", () => {
  const result = runFixture({ scenario: "retry-429" });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.calls.filter((call) => call[0] === "wait"), [["wait", 60000]]);
});

test("crates.io retry timestamps take precedence over the default delay", () => {
  const result = runFixture({ scenario: "retry-after" });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.calls.filter((call) => call[0] === "wait"), [["wait", 10000]]);
});

test("missing registry dependencies wait for index propagation", () => {
  const result = runFixture({ scenario: "index-missing" });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.calls.filter((call) => call[0] === "wait"), [["wait", 15000]]);
});

test("unselectable dependency versions wait for index propagation", () => {
  const result = runFixture({ scenario: "index-version" });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.calls.filter((call) => call[0] === "wait"), [["wait", 15000]]);
});

test("non-retryable publication errors fail immediately", () => {
  const result = runFixture({ scenario: "failure" });
  assert.equal(result.status, 101);
  assert.equal(result.calls.filter((call) => call[1] === "publish").length, 1);
  assert.equal(result.calls.filter((call) => call[0] === "wait").length, 0);
  assert.equal(result.ledger.state, "in_progress");
  assert.deepEqual(
    result.ledger.crates.map((crate) => crate.state),
    ["attempting", "pending", "pending"],
  );
});

test("zero-major caret requirements match Cargo compatibility boundaries", () => {
  for (const [requirement, version, accepted] of [
    ["^0.0.1", "0.0.1", true],
    ["^0.0.1", "0.0.2", false],
    ["^0.2.1", "0.2.2", true],
    ["^0.2.2", "0.3.0", false],
    ["^0.2.1junk", "0.2.2", false],
  ]) {
    const result = runFixture({ mode: "order", requirement, version });
    assert.equal(result.status === 0, accepted, `${requirement} / ${version}`);
    assert.ok(result.calls.every((call) => call[1] === "metadata"));
  }
});
