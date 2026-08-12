#!/usr/bin/env node

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const [crateName, version] = process.argv.slice(2);
assert.match(crateName ?? "", /^flowersec(?:-native-transport)?$/);
assert.match(version ?? "", /^\d+\.\d+\.\d+$/);

let lastError;
for (let attempt = 1; attempt <= 30; attempt++) {
  const temporary = await fs.mkdtemp(path.join(os.tmpdir(), "flowersec-crate-consumer-"));
  try {
    await execFileAsync("cargo", ["init", "--lib", "--name", "flowersec_registry_consumer", "--quiet"], { cwd: temporary });
    await execFileAsync("cargo", ["add", `${crateName}@=${version}`, "--quiet"], { cwd: temporary });
    await execFileAsync("cargo", ["check", "--quiet"], { cwd: temporary });
    lastError = undefined;
    break;
  } catch (error) {
    lastError = error;
  } finally {
    await fs.rm(temporary, { recursive: true, force: true });
  }
  if (attempt < 30) await new Promise((resolve) => setTimeout(resolve, 10_000));
}

if (lastError !== undefined) {
  throw new Error(`${crateName}@=${version} did not become resolvable by Cargo`, { cause: lastError });
}
