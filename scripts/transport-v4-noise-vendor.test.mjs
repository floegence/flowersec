import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { verifyNoiseVendor } from "./transport-v4-noise-vendor.mjs";

const root = path.resolve(import.meta.dirname, "..");
const original = verifyNoiseVendor(root);
const hash = value => createHash("sha256").update(value).digest("hex");

function withCopy(run) {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-noise-source-"));
  try {
    const directory = path.join(scratch, "flowersec-go/internal/noisehandshake");
    fs.cpSync(original.directory, directory, { recursive: true });
    run(scratch, directory);
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
}

test("v4.noise.source: reverse patch recovers exact pinned upstream bytes", () => {
  withCopy((scratch, directory) => {
    const { manifest } = verifyNoiseVendor(scratch);
    // Standard git patch application outside a repository. Exact reconstructed
    // upstream hashes establish lineage without trusting a cache or a label.
    const reversed = spawnSync("git", ["apply", "--reverse", "upstream.patch"], { cwd: directory, encoding: "utf8" });
    assert.equal(reversed.status, 0, reversed.stderr);
    for (const [file, info] of Object.entries(manifest.files)) {
      assert.equal(hash(fs.readFileSync(path.join(directory, file))), info.upstream_sha256, file);
    }
    const state = fs.readFileSync(path.join(directory, "state.go"), "utf8");
    assert.equal(state.split("s.ss.cs.DHLen()").length - 1, 4);
    assert.equal(hash(state.replaceAll("s.ss.cs.DHLen()", "s.ss.cs.DHPublicLen()")), manifest.files["state.go"].sha256);
    const reapplied = spawnSync("git", ["apply", "upstream.patch"], { cwd: directory, encoding: "utf8" });
    assert.equal(reapplied.status, 0, reapplied.stderr);
    verifyNoiseVendor(scratch);
  });
});

test("v4.noise.source: source, patch, license and unregistered file drift fail", () => {
  for (const name of ["state.go", "cipher_suite.go", "hkdf.go", "patterns.go", "LICENSE", "upstream.patch"]) {
    withCopy((scratch, directory) => {
      fs.appendFileSync(path.join(directory, name), "\n");
      assert.throws(() => verifyNoiseVendor(scratch), /drift/u, name);
    });
  }
  withCopy((scratch, directory) => {
    fs.writeFileSync(path.join(directory, "extra.go"), "package noise\n");
    assert.throws(() => verifyNoiseVendor(scratch));
  });
  withCopy((scratch, directory) => {
    const manifest = JSON.parse(fs.readFileSync(path.join(directory, "UPSTREAM.json"), "utf8"));
    manifest.upstream.module_sum = "h1:unverified";
    fs.writeFileSync(path.join(directory, "UPSTREAM.json"), JSON.stringify(manifest));
    assert.throws(() => verifyNoiseVendor(scratch));
  });
});

test("v4.noise.source: source directory, manifest and file symlinks fail", () => {
  for (const name of ["UPSTREAM.json", "state.go", "upstream.patch", "LICENSE"]) {
    withCopy((scratch, directory) => {
      const file = path.join(directory, name);
      fs.unlinkSync(file);
      fs.symlinkSync(path.join(original.directory, name), file);
      assert.throws(() => verifyNoiseVendor(scratch), /regular file/u, name);
    });
  }
  withCopy((scratch, directory) => {
    fs.rmSync(directory, { recursive: true });
    fs.symlinkSync(original.directory, directory);
    assert.throws(() => verifyNoiseVendor(scratch), /symlink/u);
  });
});
