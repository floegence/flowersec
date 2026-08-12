#!/usr/bin/env node

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const version = process.argv[2];
assert.match(version ?? "", /^\d+\.\d+\.\d+$/);
const root = await fs.mkdtemp(path.join(os.tmpdir(), "flowersec-npm-consumer-"));
try {
  await fs.writeFile(path.join(root, "package.json"), '{"private":true,"type":"module"}\n');
  await execFileAsync("npm", ["install", "--ignore-scripts", "--audit=false", `@floegence/flowersec-core@${version}`, `@floegence/flowersec-node-native@${version}`], { cwd: root });
  const wrapper = await import(path.join(root, "node_modules/@floegence/flowersec-node-native/index.js"));
  const addon = wrapper.default ?? wrapper;
  assert.equal(addon.contractVersion(), 1);
  const addonPath = path.join(root, "node_modules/@floegence/flowersec-node-native/index.js");
  await execFileAsync(process.execPath, [path.resolve("scripts/native-addon-smoke.mjs")], {
    env: { ...process.env, FLOWERSEC_NATIVE_ADDON_PATH: addonPath },
  });

  const browserRoot = path.join(root, "browser-only");
  await fs.mkdir(browserRoot);
  await fs.writeFile(path.join(browserRoot, "package.json"), '{"private":true,"type":"module"}\n');
  await execFileAsync("npm", ["install", "--ignore-scripts", "--omit=optional", "--audit=false", `@floegence/flowersec-core@${version}`], { cwd: browserRoot });
  await execFileAsync(process.execPath, ["--input-type=module", "--eval", "await import('@floegence/flowersec-core/browser')"], { cwd: browserRoot });
} finally {
  await fs.rm(root, { recursive: true, force: true });
}
