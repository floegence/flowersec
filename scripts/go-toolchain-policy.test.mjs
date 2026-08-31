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
  fs.cpSync(sourceRoot, root, {
    recursive: true,
    filter: (source) => !source.split(path.sep).some((part) => [".build", ".git", "node_modules", "target"].includes(part)),
  });
  return root;
}

function mutate(root, relative, from, to) {
  const filename = path.join(root, relative);
  const source = fs.readFileSync(filename, "utf8");
  assert.ok(source.includes(from), `${relative} mutation source is absent`);
  fs.writeFileSync(filename, source.replace(from, to));
  return () => fs.writeFileSync(filename, source);
}

test("the maintained Go security baseline is exactly 1.27.0", () => {
  assert.equal(goSecurityBaseline, "1.27.0");
  assert.doesNotThrow(() => verifyGoToolchainPolicy(sourceRoot));
});

test("Go module policy rejects the previous patch and ambiguous toolchain directives", () => {
  assert.equal(parseGoModPolicy("module example.com/ok\n\ngo 1.27.0\n", "fixture"), "1.27.0");
  const staleVersion = [1, 26, 5].join(".");
  assert.equal(parseGoModPolicy(`module example.com/stale\n\ngo ${staleVersion}\n`, "fixture"), staleVersion);
  assert.throws(
    () => parseGoModPolicy(`module example.com/ambiguous\n\ngo 1.27.0\ntoolchain go${staleVersion}\n`, "fixture"),
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

test("each maintained toolchain source rejects a stale structured value", (t) => {
  const root = copySourceTree(t);
  const stale = [1, 26, 5].join(".");
  for (const fixture of [
    {
      relative: "flowersec-go/go.mod",
      from: "go 1.27.0",
      to: `go ${stale}`,
      error: /flowersec-go\/go\.mod must be 1\.27\.0/,
    },
    {
      relative: "docker/flowersec-runtime/Dockerfile",
      from: "golang:1.27.0-alpine",
      to: `golang:${stale}-alpine`,
      error: /runtime Dockerfile Go builder tag must be 1\.27\.0-alpine/,
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
      relative: "scripts/check-go-security.mjs",
      from: 'goToolchain: "go1.27.0"',
      to: `goToolchain: "go${stale}"`,
      error: /Go security scanner toolchain must be go1\.27\.0/,
    },
    {
      relative: "scripts/test-host-init.sh",
      from: "readonly go_version=1.27.0",
      to: `readonly go_version=${stale}`,
      error: /test host Go version must be 1\.27\.0/,
    },
    {
      relative: "scripts/generate-source-inventory.mjs",
      from: 'GOTOOLCHAIN: "go1.27.0"',
      to: `GOTOOLCHAIN: "go${stale}"`,
      error: /source inventory Go toolchain must be go1\.27\.0/,
    },
    {
      relative: "scripts/run-final-stage.mjs",
      from: 'state.version !== "go1.27.0"',
      to: `state.version !== "go${stale}"`,
      error: /final stage Go toolchain must be go1\.27\.0/,
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
