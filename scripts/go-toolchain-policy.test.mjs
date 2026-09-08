import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  goSecurityBaseline,
  parseGoModPolicy,
  parseSetupGoSteps,
  verifyGoToolchainPolicy,
} from "./check-go-toolchain-policy.mjs";

const sourceRoot = path.resolve(import.meta.dirname, "..");

function copySourceTree(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-go-policy-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const relative of [
    "toolchains.json", "flowersec-go/go.mod", "tools/releasenotes/go.mod",
    "tools/stabilitycheck/go.mod", "docker/flowersec-runtime/Dockerfile",
    ".github/workflows/ci.yml", ".github/workflows/codeql.yml", ".github/workflows/release.yml", "scripts/test-host-init.sh",
  ]) {
    fs.mkdirSync(path.dirname(path.join(root, relative)), { recursive: true });
    fs.copyFileSync(path.join(sourceRoot, relative), path.join(root, relative));
  }
  return root;
}

function mutate(root, relative, from, to) {
  const filename = path.join(root, relative);
  const source = fs.readFileSync(filename, "utf8");
  assert.ok(source.includes(from), `${relative} mutation source is absent`);
  fs.writeFileSync(filename, source.replace(from, to));
  return () => fs.writeFileSync(filename, source);
}

test("the maintained Go security baseline is exactly 1.27.1", () => {
  assert.equal(goSecurityBaseline, "1.27.1");
  assert.doesNotThrow(() => verifyGoToolchainPolicy(sourceRoot));
});

test("Go module policy rejects the previous patch and ambiguous toolchain directives", () => {
  assert.equal(parseGoModPolicy("module example.com/ok\n\ngo 1.27.1\n", "fixture"), "1.27.1");
  const staleVersion = [1, 26, 5].join(".");
  assert.equal(parseGoModPolicy(`module example.com/stale\n\ngo ${staleVersion}\n`, "fixture"), staleVersion);
  assert.throws(
    () => parseGoModPolicy(`module example.com/ambiguous\n\ngo 1.27.1\ntoolchain go${staleVersion}\n`, "fixture"),
    /must not contain a toolchain directive/,
  );
});

test("workflow setup-go policy parses action steps instead of matching comments", () => {
  const source = `jobs:\n  build:\n    steps:\n      # uses: actions/setup-go@comment-only\n      - name: Setup Go\n        uses: actions/setup-go@immutable-sha # v5\n        with:\n          go-version-file: flowersec-go/go.mod\n          cache: true\n`;
  assert.deepEqual(parseSetupGoSteps(source, "fixture.yml"), [{
    uses: "actions/setup-go@immutable-sha",
    versionFile: "flowersec-go/go.mod",
  }]);
});

test("workflow setup-go parsing ends schedule and matrix items at their indentation boundary", () => {
  const source = `on:
  schedule:
    - cron: "17 3 * * *"
jobs:
  analyze:
    strategy:
      matrix:
        include:
          - language: go
    steps:
      - uses: actions/checkout@immutable-sha
      - uses: actions/setup-go@immutable-sha
        with:
          go-version-file: flowersec-go/go.mod
`;
  assert.deepEqual(parseSetupGoSteps(source, "scheduled.yml"), [{
    uses: "actions/setup-go@immutable-sha",
    versionFile: "flowersec-go/go.mod",
  }]);
});

test("each maintained toolchain source rejects a stale structured value", (t) => {
  const root = copySourceTree(t);
  const stale = [1, 26, 5].join(".");
  for (const fixture of [
    {
      relative: "flowersec-go/go.mod",
      from: "go 1.27.1",
      to: `go ${stale}`,
      error: /flowersec-go\/go\.mod must be 1\.27\.1/,
    },
    {
      relative: "docker/flowersec-runtime/Dockerfile",
      from: "golang:1.27.1-alpine",
      to: `golang:${stale}-alpine`,
      error: /runtime Dockerfile Go builder tag must be 1\.27\.1-alpine/,
    },
    {
      relative: ".github/workflows/ci.yml",
      from: "go-version-file: flowersec-go/go.mod",
      to: "go-version-file: tools/releasenotes/go.mod",
      error: /ci\.yml setup-go version file must be flowersec-go\/go\.mod/,
    },
    {
      relative: ".github/workflows/release.yml",
      from: "go-version-file: flowersec-go/go.mod",
      to: "go-version-file: tools/releasenotes/go.mod",
      error: /release\.yml setup-go version file must be flowersec-go\/go\.mod/,
    },
    {
      relative: ".github/workflows/codeql.yml",
      from: "go-version-file: flowersec-go/go.mod",
      to: "go-version-file: tools/releasenotes/go.mod",
      error: /codeql\.yml setup-go version file must be flowersec-go\/go\.mod/,
    },
    {
      relative: "scripts/test-host-init.sh",
      from: "readonly go_version=1.27.1",
      to: `readonly go_version=${stale}`,
      error: /test host Go version must be 1\.27\.1/,
    },
  ]) {
    const restore = mutate(root, fixture.relative, fixture.from, fixture.to);
    assert.throws(() => verifyGoToolchainPolicy(root), fixture.error, fixture.relative);
    restore();
  }
});

test("repository policy explicitly rejects a stale Go patch source", (t) => {
  const root = copySourceTree(t);
  fs.writeFileSync(path.join(root, "stale-version.txt"), `go${[1, 26, 5].join(".")}\n`);
  assert.throws(() => verifyGoToolchainPolicy(root), /Go 1\.26\.5 is forbidden.*stale-version\.txt/);
});

test("Go declarations are checked against the supplied repository config", (t) => {
  const root = copySourceTree(t);
  const file = path.join(root, "toolchains.json");
  const config = JSON.parse(fs.readFileSync(file, "utf8"));
  config.go.version = "1.27.2";
  fs.writeFileSync(file, JSON.stringify(config));
  assert.throws(() => verifyGoToolchainPolicy(root), /go\.mod must be 1\.27\.2/);
});

test("new Go modules must use the authoritative version", (t) => {
  const root = copySourceTree(t);
  fs.mkdirSync(path.join(root, "tools/new-module"), { recursive: true });
  fs.writeFileSync(path.join(root, "tools/new-module/go.mod"), "module example.com/new\n\ngo 1.27.0\n");
  assert.throws(() => verifyGoToolchainPolicy(root), /new-module\/go\.mod must be 1\.27\.1/);
});
