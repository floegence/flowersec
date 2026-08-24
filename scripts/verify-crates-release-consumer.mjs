#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { execFileBounded } from "./release-readback.mjs";
const COMMAND_TIMEOUT_MS = 60_000;
const MAX_ATTEMPTS = 12;
const [crateName, version] = process.argv.slice(2);
assert.match(crateName ?? "", /^flowersec(?:-native-transport)?$/);
assert.match(version ?? "", /^\d+\.\d+\.\d+$/);

let lastError;
for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
  const temporary = await fs.mkdtemp(path.join(os.tmpdir(), "flowersec-crate-consumer-"));
  try {
    const commandOptions = { cwd: temporary, maxStdoutBytes: 4 * 1024 * 1024, maxStderrBytes: 64 * 1024 };
    await execFileBounded("cargo", ["init", "--lib", "--name", "flowersec_registry_consumer", "--quiet"], commandOptions, COMMAND_TIMEOUT_MS);
    await execFileBounded("cargo", ["add", `${crateName}@=${version}`, "--quiet"], commandOptions, COMMAND_TIMEOUT_MS);
    await execFileBounded("cargo", ["check", "--quiet"], commandOptions, COMMAND_TIMEOUT_MS);
    lastError = undefined;
    break;
  } catch (error) {
    lastError = error;
  } finally {
    await fs.rm(temporary, { recursive: true, force: true });
  }
  if (attempt < MAX_ATTEMPTS) await new Promise((resolve) => setTimeout(resolve, 10_000));
}

if (lastError !== undefined) throw new Error(`${crateName}@=${version} did not become resolvable by Cargo: ${lastError.message}`, { cause: lastError });
