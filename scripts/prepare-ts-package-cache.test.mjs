import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  prepareTSPackageCache,
  productionCacheManifest,
} from "./prepare-ts-package-cache.mjs";

const sourceRoot = path.resolve(import.meta.dirname, "..");
const packageRoot = path.join(sourceRoot, "flowersec-ts");
const packageJSON = JSON.parse(fs.readFileSync(path.join(packageRoot, "package.json"), "utf8"));
const lock = JSON.parse(fs.readFileSync(path.join(packageRoot, "package-lock.json"), "utf8"));

test("derives the published production dependency ranges with lock coverage", () => {
  assert.deepEqual(productionCacheManifest(packageJSON, lock), {
    name: "flowersec-package-cache-preflight",
    private: true,
    dependencies: {
      "@fails-components/webtransport": "1.6.7",
      "@fails-components/webtransport-transport-http3-quiche": "1.6.7",
      "@noble/ciphers": "^2.2.0",
      "@noble/curves": "^2.3.0",
      "@noble/hashes": "^2.3.0",
      tr46: "5.0.0",
      ws: "^8.21.2",
    },
  });
});

test("prepares one bounded consumer install and cleans its scratch directory", () => {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-cache-test-"));
  let invocation;
  prepareTSPackageCache(packageJSON, lock, {
    makeScratch: () => scratch,
    run(command, args, options) {
      invocation = { command, args, options };
      assert.deepEqual(
        JSON.parse(fs.readFileSync(path.join(scratch, "package.json"), "utf8")),
        productionCacheManifest(packageJSON, lock),
      );
      return { status: 0 };
    },
  });
  assert.equal(fs.existsSync(scratch), false);
  assert.equal(invocation.command, "npm");
  assert.deepEqual(invocation.args, [
    "install",
    "--ignore-scripts",
    "--no-package-lock",
    "--audit=false",
    "--fund=false",
    "--offline=false",
    "--prefer-online",
  ]);
  assert.equal(invocation.options.cwd, scratch);

  const failingScratch = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-cache-test-"));
  assert.throws(() => prepareTSPackageCache(packageJSON, lock, {
    makeScratch: () => failingScratch,
    run: () => ({ status: 1 }),
  }), /failed to prepare npm package cache/i);
  assert.equal(fs.existsSync(failingScratch), false);
});

test("rejects local ranges and missing production lock entries", () => {
  const invalidPackage = { dependencies: { local: "file:../local" } };
  assert.throws(
    () => productionCacheManifest(invalidPackage, { packages: {} }),
    /registry range and lock entry/i,
  );
});
