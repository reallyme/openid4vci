#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  CHECK_IDEMPOTENCE_ARGUMENT,
  hardenGeneratedProto,
} from "./proto-hardening/core.mjs";
import { OPENID4VCI_SCALAR_FIELD_CLASSIFICATIONS } from "./proto-hardening/openid4vci-scalar-policy.mjs";

const supportedArguments = new Set([CHECK_IDEMPOTENCE_ARGUMENT]);
const suppliedArguments = new Set();

function fail(message) {
  console.error(`generated OpenID4VCI proto hardening failed: ${message}`);
  process.exit(1);
}

for (const argument of process.argv.slice(2)) {
  if (!supportedArguments.has(argument)) {
    fail(`unsupported argument ${argument}`);
  }
  if (suppliedArguments.has(argument)) {
    fail(`argument ${argument} was specified more than once`);
  }
  suppliedArguments.add(argument);
}

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const generatedRoot = resolve(
  root,
  "crates/proto/src/generated/buffa",
);
const generatedStem = "reallyme.openid4vci.v1.openid4vci";

hardenGeneratedProto({
  checkIdempotent: suppliedArguments.has(CHECK_IDEMPOTENCE_ARGUMENT),
  failurePrefix: "generated OpenID4VCI proto hardening failed",
  protoPath: resolve(
    root,
    "crates/proto/proto/reallyme/openid4vci/v1/openid4vci.proto",
  ),
  generatedPath: resolve(generatedRoot, `${generatedStem}.rs`),
  oneofPath: resolve(generatedRoot, `${generatedStem}.__oneof.rs`),
  viewPath: resolve(generatedRoot, `${generatedStem}.__view.rs`),
  viewOneofPath: resolve(generatedRoot, `${generatedStem}.__view_oneof.rs`),
  scalarFieldClassifications: OPENID4VCI_SCALAR_FIELD_CLASSIFICATIONS,
});
