#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const PUBLIC_CRATES = Object.freeze([
  "reallyme-openid4vci-proto",
  "reallyme-openid4vci-types",
  "reallyme-openid4vci-wallet",
]);

const REGISTRY_LOOKUP_FAILURE =
  "error: failed to retrieve index of crate versions from registry";
const CAUSED_BY = "Caused by:";

function nonEmptyLines(output) {
  return output
    .replaceAll("\r\n", "\n")
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length !== 0);
}

export function isExactInitialReleaseResult(crateName, stdout, stderr) {
  const lines = nonEmptyLines(`${stdout}\n${stderr}`);
  const absencePrefix = `${crateName} not found in registry (crates.io).`;

  return (
    lines.length === 3 &&
    lines[0] === REGISTRY_LOOKUP_FAILURE &&
    lines[1] === CAUSED_BY &&
    lines[2].startsWith(absencePrefix)
  );
}

export function runPublishedSemverChecks({
  runCommand = spawnSync,
  stdout = process.stdout,
  stderr = process.stderr,
} = {}) {
  for (const crateName of PUBLIC_CRATES) {
    const result = runCommand(
      "cargo",
      ["semver-checks", "check-release", "--package", crateName],
      {
        encoding: "utf8",
        env: { ...process.env, CARGO_TERM_COLOR: "never" },
        stdio: "pipe",
      },
    );

    if (result.error !== undefined) {
      stderr.write(`unable to execute cargo-semver-checks for ${crateName}\n`);
      return 1;
    }

    const commandStdout = result.stdout ?? "";
    const commandStderr = result.stderr ?? "";
    if (result.status === 0) {
      stdout.write(commandStdout);
      stderr.write(commandStderr);
      continue;
    }

    // A package with no registry entry has no public API baseline. Accept only
    // cargo-semver-checks' exact crate-specific absence shape; rate limits,
    // transport failures, and unrelated registry errors remain fatal.
    if (isExactInitialReleaseResult(crateName, commandStdout, commandStderr)) {
      stdout.write(`${crateName}: no published baseline; initial release check is not applicable\n`);
      continue;
    }

    stdout.write(commandStdout);
    stderr.write(commandStderr);
    return result.status ?? 1;
  }

  return 0;
}

const invokedPath = process.argv[1];
if (invokedPath !== undefined && fileURLToPath(import.meta.url) === resolve(invokedPath)) {
  process.exitCode = runPublishedSemverChecks();
}
