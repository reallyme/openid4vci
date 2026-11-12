// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repositoryRoot = fileURLToPath(new URL("..", import.meta.url));
const fixtureFiles = [
  "scripts/check-ssi-remote-resolution.mjs",
  "Cargo.toml",
  "Cargo.lock",
  "crates/http/Cargo.toml",
  "fuzz/Cargo.toml",
  "fuzz/Cargo.lock",
];

function withFixture(mutate, verify) {
  const directory = mkdtempSync(join(tmpdir(), "openid4vci-dependency-policy-"));
  const root = join(directory, "openid4vci");
  try {
    for (const relativePath of fixtureFiles) {
      const destination = join(root, relativePath);
      mkdirSync(dirname(destination), { recursive: true });
      writeFileSync(destination, readFileSync(join(repositoryRoot, relativePath)));
    }
    mutate(root);
    const result = spawnSync(process.execPath, [join(root, fixtureFiles[0])], {
      cwd: root,
      encoding: "utf8",
    });
    assert.equal(result.error, undefined);
    verify(result);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

function rewrite(path, transform) {
  writeFileSync(path, transform(readFileSync(path, "utf8")));
}

function rewritePackage(path, name, transform) {
  rewrite(path, (contents) => {
    const blocks = contents.split("[[package]]");
    let matches = 0;
    const result = blocks.map((block) => {
      if (!block.includes(`\nname = "${name}"\n`)) return block;
      matches += 1;
      return transform(block);
    });
    assert.equal(matches, 1);
    return result.join("[[package]]");
  });
}

function rejected(result, reason) {
  assert.equal(result.status, 1);
  assert.ok(result.stderr.includes(reason));
  assert.equal(result.stdout, "");
}

test("registry SSI 0.6.2 and ZK API 0.3.2 are accepted together", () => {
  withFixture(() => {}, (result) => {
    assert.equal(result.status, 0);
    assert.equal(result.stderr, "");
    assert.ok(result.stdout.includes("registry crates"));
  });
});

test("SSI path and Git overrides remain prohibited", () => {
  for (const override of ['path = "../ssi/crates/credential"', 'git = "https://example.invalid/ssi"']) {
    withFixture((root) => {
      rewrite(join(root, "Cargo.toml"), (contents) => contents.replace(
        'reallyme-credential = { version = "=0.6.2",',
        `reallyme-credential = { version = "=0.6.2", ${override},`,
      ));
    }, (result) => rejected(result, "reallyme-credential must resolve from crates.io"));
  }
});

test("SSI versions must match the exact published release", () => {
  withFixture((root) => {
    rewrite(join(root, "Cargo.toml"), (contents) => contents.replace(
      'reallyme-credential = { version = "=0.6.2",',
      'reallyme-credential = { version = "=0.5.0",',
    ));
  }, (result) => rejected(result, "reallyme-credential must use exact version =0.6.2"));
});

test("both lockfiles require registry sources and checksums for SSI", () => {
  for (const lockfile of ["Cargo.lock", "fuzz/Cargo.lock"]) {
    for (const field of ["source", "checksum"]) {
      withFixture((root) => {
        rewritePackage(join(root, lockfile), "reallyme-credential", (block) => block.replace(
          new RegExp(`^${field} = .*\\n`, "mu"),
          "",
        ));
      }, (result) => rejected(result, field === "source"
        ? `${lockfile} must resolve reallyme-credential 0.6.2 from crates.io`
        : `${lockfile} must lock the crates.io checksum for reallyme-credential`));
    }
  }
});

test("both lockfiles reject duplicate SSI packages", () => {
  for (const lockfile of ["Cargo.lock", "fuzz/Cargo.lock"]) {
    withFixture((root) => {
      rewrite(join(root, lockfile), (contents) => `${contents}\n[[package]]\nname = "reallyme-credential"\nversion = "0.6.2"\n`);
    }, (result) => rejected(result, `${lockfile} must contain exactly one reallyme-credential package`));
  }
});

test("ZK API rejects the previous exact dependency pin", () => {
  withFixture((root) => {
    rewrite(join(root, "Cargo.toml"), (contents) => contents.replace(
      'reallyme-zk-api = { version = "=0.3.2",',
      'reallyme-zk-api = { version = "=0.3.0",',
    ));
  }, (result) => rejected(result, "reallyme-zk-api must use exact version =0.3.2"));
});

test("ZK API rejects alternate dependency sources", () => {
  for (const override of [
    'path = "../zk/crates/api"',
    'git = "https://example.invalid/zk"',
    'registry = "other"',
  ]) {
    withFixture((root) => {
      rewrite(join(root, "Cargo.toml"), (contents) => contents.replace(
        'reallyme-zk-api = { version = "=0.3.2",',
        `reallyme-zk-api = { version = "=0.3.2", ${override},`,
      ));
    }, (result) => rejected(result, "reallyme-zk-api must resolve from crates.io"));
  }
});

test("both lockfiles require one published ZK API package with its checksum", () => {
  for (const lockfile of ["Cargo.lock", "fuzz/Cargo.lock"]) {
    for (const [transform, reason] of [
      [(block) => block.replace(/^source = .*\n/mu, ""), "must resolve reallyme-zk-api 0.3.2 from crates.io"],
      [(block) => block.replace(/^checksum = .*\n/mu, ""), "must lock the crates.io checksum for reallyme-zk-api"],
      [(block) => block.replace('version = "0.3.2"', 'version = "0.2.1"'), "must resolve reallyme-zk-api 0.3.2 from crates.io"],
      [(block) => block.replace('version = "0.3.2"', 'version = "0.3.0"'), "must resolve reallyme-zk-api 0.3.2 from crates.io"],
      [() => "\n", "must contain exactly one reallyme-zk-api package"],
      [(block) => block + "\n[[package]]\nname = \"reallyme-zk-api\"\nversion = \"0.3.2\"\n", "must contain exactly one reallyme-zk-api package"],
    ]) {
      withFixture((root) => {
        rewritePackage(join(root, lockfile), "reallyme-zk-api", transform);
      }, (result) => rejected(result, `${lockfile} ${reason}`));
    }
  }
});
