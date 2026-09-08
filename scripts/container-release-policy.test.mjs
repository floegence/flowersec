import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  containerDockerfileContracts,
  verifyContainerDockerfile,
  verifyContainerReleasePolicy,
} from "./check-container-release-policy.mjs";
import { readToolchains } from "./toolchains.mjs";

const sourceRoot = path.resolve(import.meta.dirname, "..");
const relative = "docker/flowersec-runtime/Dockerfile";
const source = fs.readFileSync(path.join(sourceRoot, relative), "utf8");
const contract = containerDockerfileContracts[relative];

test("runtime image uses the configured Go version and reviewed immutable image", () => {
  assert.doesNotThrow(() => verifyContainerReleasePolicy(sourceRoot));
  for (const changed of [
    source.replace(`golang:${readToolchains().go.version}-alpine`, "golang:1.27.0-alpine"),
    source.replace(/(FROM .*?@sha256:)[0-9a-f]{64}/, `$1${"0".repeat(64)}`),
    source.replace(/^(FROM .*?)@sha256:[0-9a-f]{64}/m, "$1"),
  ]) {
    assert.notEqual(changed, source);
    assert.throws(() => verifyContainerDockerfile(changed, contract), /build stage base changed/);
  }
  assert.throws(
    () => verifyContainerDockerfile(`${source}\nRUN touch /extra\n`, contract),
    /final instruction sequence changed/,
  );
});

test("builder disables Go toolchain downloads before any build commands and rejects overrides", () => {
  for (const changed of [
    source.replace("ENV GOTOOLCHAIN=local\n", ""),
    source.replace("ENV GOTOOLCHAIN=local", "ENV GOTOOLCHAIN=auto"),
    source.replace("ENV GOTOOLCHAIN=local", "ARG GOTOOLCHAIN=local"),
    source.replace("ENV GOTOOLCHAIN=local", "ENV GOTOOLCHAIN=local\nENV GOTOOLCHAIN=auto"),
    source.replace("RUN go mod download", "RUN GOTOOLCHAIN=auto go mod download"),
    source.replace("ENV GOTOOLCHAIN=local\n", "").replace("RUN go mod download", "RUN go mod download\nENV GOTOOLCHAIN=local"),
  ]) {
    assert.notEqual(changed, source);
    assert.throws(() => verifyContainerDockerfile(changed, contract), /exactly ENV GOTOOLCHAIN=local/);
  }
});

test("container policy reads configuration from the repository being checked", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-container-policy-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.mkdirSync(path.dirname(path.join(root, relative)), { recursive: true });
  fs.writeFileSync(path.join(root, relative), source);
  const config = { ...readToolchains(), go: { version: "1.27.2" } };
  fs.writeFileSync(path.join(root, "toolchains.json"), JSON.stringify(config));
  assert.throws(() => verifyContainerReleasePolicy(root), /build stage base changed/);
});
