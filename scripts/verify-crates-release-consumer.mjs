#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { execCargoCheckBounded } from "./release-readback.mjs";
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
    await fs.mkdir(path.join(temporary, "src"));
    await fs.writeFile(path.join(temporary, "src", "lib.rs"), "");
    await fs.writeFile(
      path.join(temporary, "Cargo.toml"),
      `[package]\nname = "flowersec_registry_consumer"\nversion = "0.0.0"\nedition = "2021"\npublish = false\n\n[dependencies]\n${crateName} = { version = "=${version}" }\n`,
    );
    await execCargoCheckBounded(commandOptions, COMMAND_TIMEOUT_MS);
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
