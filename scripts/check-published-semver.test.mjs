// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import {
  PUBLIC_CRATES,
  isExactInitialReleaseResult,
  runPublishedSemverChecks,
} from "./check-published-semver.mjs";

const NOT_FOUND_HEADER =
  "error: failed to retrieve index of crate versions from registry\n\nCaused by:\n";

function captureStream() {
  let value = "";
  return {
    stream: {
      write(chunk) {
        value += chunk;
      },
    },
    value: () => value,
  };
}

test("exact crates.io absence is accepted only for the requested crate", () => {
  const crateName = PUBLIC_CRATES[0];
  const stderr = `${NOT_FOUND_HEADER}    ${crateName} not found in registry (crates.io). For workarounds check https://example.invalid\n`;

  assert.equal(isExactInitialReleaseResult(crateName, "", stderr), true);
  assert.equal(isExactInitialReleaseResult(PUBLIC_CRATES[1], "", stderr), false);
  assert.equal(
    isExactInitialReleaseResult(crateName, "", `${stderr}unexpected additional failure\n`),
    false,
  );
});

test("initial releases and successful published-baseline checks both pass", () => {
  const calls = [];
  const output = captureStream();
  const errors = captureStream();
  const status = runPublishedSemverChecks({
    runCommand(command, args, options) {
      calls.push({ command, args, options });
      const crateName = args[3];
      if (crateName === PUBLIC_CRATES[1]) {
        return { status: 0, stdout: "semver check passed\n", stderr: "" };
      }
      return {
        status: 1,
        stdout: "",
        stderr: `${NOT_FOUND_HEADER}    ${crateName} not found in registry (crates.io). For workarounds check https://example.invalid\n`,
      };
    },
    stdout: output.stream,
    stderr: errors.stream,
  });

  assert.equal(status, 0);
  assert.deepEqual(
    calls.map((call) => call.args),
    PUBLIC_CRATES.map((crateName) => [
      "semver-checks",
      "check-release",
      "--package",
      crateName,
    ]),
  );
  assert.ok(calls.every((call) => call.options.env.CARGO_TERM_COLOR === "never"));
  assert.match(output.value(), /no published baseline/u);
  assert.match(output.value(), /semver check passed/u);
  assert.equal(errors.value(), "");
});

test("rate limits and unrelated registry failures fail closed immediately", () => {
  const calls = [];
  const output = captureStream();
  const errors = captureStream();
  const status = runPublishedSemverChecks({
    runCommand(_command, args) {
      calls.push(args);
      return {
        status: 1,
        stdout: "",
        stderr: "error: registry request returned HTTP 429\n",
      };
    },
    stdout: output.stream,
    stderr: errors.stream,
  });

  assert.equal(status, 1);
  assert.equal(calls.length, 1);
  assert.equal(output.value(), "");
  assert.match(errors.value(), /HTTP 429/u);
});

test("process launch failures fail closed without exposing host error details", () => {
  const output = captureStream();
  const errors = captureStream();
  const status = runPublishedSemverChecks({
    runCommand() {
      return { error: new Error("sensitive host path"), status: null };
    },
    stdout: output.stream,
    stderr: errors.stream,
  });

  assert.equal(status, 1);
  assert.equal(output.value(), "");
  assert.doesNotMatch(errors.value(), /sensitive host path/u);
});
