#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const [crateName, version, sourceSHA] = process.argv.slice(2);
assert.match(crateName ?? "", /^flowersec(?:-native-transport)?$/);
assert.match(version ?? "", /^\d+\.\d+\.\d+$/);
assert.match(sourceSHA ?? "", /^[0-9a-f]{40}$/);
const requestHeaders = Object.freeze({
  "User-Agent": `flowersec-release-readback/${version} (https://github.com/floegence/flowersec)`,
});

let metadata;
for (let attempt = 1; attempt <= 30; attempt++) {
  const response = await fetch(`https://crates.io/api/v1/crates/${crateName}/${version}`, { headers: requestHeaders });
  if (response.ok) {
    metadata = await response.json();
    break;
  }
  if (response.status !== 404 || attempt === 30) throw new Error(`${crateName}@${version} registry status ${response.status}`);
  await new Promise((resolve) => setTimeout(resolve, 10_000));
}
assert.equal(metadata.version?.num, version);
assert.match(metadata.version?.checksum ?? "", /^[0-9a-f]{64}$/);
const response = await fetch(`https://crates.io/api/v1/crates/${crateName}/${version}/download`, { headers: requestHeaders });
assert.equal(response.ok, true);
const archiveBytes = new Uint8Array(await response.arrayBuffer());
assert.equal(crypto.createHash("sha256").update(archiveBytes).digest("hex"), metadata.version.checksum);
const temporary = await fs.mkdtemp(path.join(os.tmpdir(), "flowersec-crate-readback-"));
try {
  const archive = path.join(temporary, "package.crate");
  await fs.writeFile(archive, archiveBytes);
  await execFileAsync("tar", ["-xzf", archive, "-C", temporary]);
  const root = path.join(temporary, `${crateName}-${version}`);
  const cargo = await fs.readFile(path.join(root, "Cargo.toml"), "utf8");
  const vcs = JSON.parse(await fs.readFile(path.join(root, ".cargo_vcs_info.json"), "utf8"));
  assert.match(cargo, new RegExp(`^name = "${crateName}"$`, "m"));
  assert.match(cargo, new RegExp(`^version = "${version.replaceAll(".", "\\.")}"$`, "m"));
  assert.equal(vcs.git?.sha1, sourceSHA);
  if (crateName === "flowersec") {
    assert.match(
      cargo,
      new RegExp(`\\[dependencies\\.flowersec-native-transport\\][\\s\\S]*?^version = "=${version.replaceAll(".", "\\.")}"$`, "m"),
    );
  }
} finally {
  await fs.rm(temporary, { recursive: true, force: true });
}
