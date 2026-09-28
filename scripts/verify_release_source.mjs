#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

// SPDX-License-Identifier: MIT OR Apache-2.0

import { appendFileSync, lstatSync, readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const FULL_SHA_PATTERN = /^[0-9a-f]{40}$/u;
const VERSION_PATTERN = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;
const MAX_COMMAND_OUTPUT_BYTES = 1_048_576;
const MAX_MANIFEST_BYTES = 65_536;
const PUBLISHABLE_MANIFESTS = Object.freeze([
  "crates/proto/Cargo.toml",
  "crates/types/Cargo.toml",
  "crates/attestation/Cargo.toml",
  "crates/wallet/Cargo.toml",
  "crates/profiles/Cargo.toml",
  "crates/issuer/Cargo.toml",
  "crates/proto-codec/Cargo.toml",
  "crates/http/Cargo.toml",
  "crates/openid4vci/Cargo.toml",
]);

export class ReleaseSourceError extends Error {
  constructor(code) {
    super(code);
    this.name = "ReleaseSourceError";
    this.code = code;
  }
}

const fail = (code) => {
  throw new ReleaseSourceError(code);
};

const run = (command, arguments_, { capture = true } = {}) => {
  const result = spawnSync(command, arguments_, {
    encoding: "utf8",
    maxBuffer: MAX_COMMAND_OUTPUT_BYTES,
    stdio: capture ? ["ignore", "pipe", "ignore"] : "inherit",
  });
  if (result.error !== undefined || result.status !== 0) {
    fail("source-command-failed");
  }
  return capture && typeof result.stdout === "string" ? result.stdout.trim() : "";
};

const readManifestVersion = (path) => {
  let status;
  let contents;
  try {
    status = lstatSync(path);
    if (status.isSymbolicLink() || !status.isFile() || status.size > MAX_MANIFEST_BYTES) {
      fail("invalid-release-manifest");
    }
    contents = readFileSync(path, "utf8");
  } catch (error) {
    if (error instanceof ReleaseSourceError) {
      throw error;
    }
    fail("invalid-release-manifest");
  }
  const versions = [...contents.matchAll(/^version = "([^"]+)"$/gmu)];
  if (versions.length !== 1 || versions[0][1] === undefined) {
    fail("invalid-release-manifest");
  }
  return versions[0][1];
};

export const resolveReleaseVersion = ({ derivesVersion, manifestVersions, requestedVersion }) => {
  if (!Array.isArray(manifestVersions) || manifestVersions.length === 0) {
    fail("manifest-version-mismatch");
  }
  const derivedVersion = manifestVersions[0];
  if (
    typeof derivedVersion !== "string" ||
    !VERSION_PATTERN.test(derivedVersion) ||
    manifestVersions.some((version) => version !== derivedVersion)
  ) {
    fail("manifest-version-mismatch");
  }
  if (
    !derivesVersion &&
    (typeof requestedVersion !== "string" || !VERSION_PATTERN.test(requestedVersion))
  ) {
    fail("invalid-release-version");
  }
  if (!derivesVersion && requestedVersion !== derivedVersion) {
    fail("manifest-version-mismatch");
  }
  return derivesVersion ? derivedVersion : requestedVersion;
};

export const verifyReleaseSource = ({ env = process.env } = {}) => {
  const releaseSha = env.RELEASE_SHA;
  if (typeof releaseSha !== "string" || !FULL_SHA_PATTERN.test(releaseSha)) {
    fail("invalid-release-sha");
  }
  if (env.GITHUB_SHA !== undefined && env.GITHUB_SHA !== releaseSha) {
    fail("workflow-head-mismatch");
  }
  if (run("git", ["rev-parse", "HEAD"]) !== releaseSha) {
    fail("checkout-mismatch");
  }
  run(
    "git",
    ["fetch", "--force", "--no-tags", "origin", "main:refs/remotes/origin/main"],
    { capture: false },
  );
  if (run("git", ["rev-parse", "refs/remotes/origin/main"]) !== releaseSha) {
    fail("origin-main-mismatch");
  }
  const manifestVersions = PUBLISHABLE_MANIFESTS.map((manifest) =>
    readManifestVersion(manifest),
  );
  const derivesVersion = env.RELEASE_SOURCE_DERIVE_VERSION === "1";
  const releaseVersion = resolveReleaseVersion({
    derivesVersion,
    manifestVersions,
    requestedVersion: env.RELEASE_VERSION,
  });
  return { releaseSha, releaseVersion };
};

const isMain = process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  try {
    const identity = verifyReleaseSource();
    if (process.env.RELEASE_SOURCE_WRITE_GITHUB_OUTPUT === "1") {
      const outputPath = process.env.GITHUB_OUTPUT;
      if (typeof outputPath !== "string" || outputPath.length === 0) {
        fail("missing-github-output");
      }
      appendFileSync(
        outputPath,
        `release_sha=${identity.releaseSha}\nrelease_version=${identity.releaseVersion}\n`,
        { encoding: "utf8" },
      );
    }
    console.log("release source matches the workflow head, current main, and crate manifests");
  } catch (error) {
    const code = error instanceof ReleaseSourceError ? error.code : "unexpected-failure";
    console.error(`release source verification failed: ${code}`);
    process.exit(1);
  }
}
