#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

function parseDockerfile(source) {
  if (typeof source !== "string" || source === "") throw new Error("Dockerfile is empty");
  const logicalLines = [];
  let pending = "";
  for (const rawLine of source.split("\n")) {
    const line = rawLine.trim();
    if (line === "" || (line.startsWith("#") && pending === "")) continue;
    const continued = line.endsWith("\\");
    const fragment = continued ? line.slice(0, -1).trimEnd() : line;
    pending = pending === "" ? fragment : `${pending} ${fragment}`;
    if (!continued) {
      const match = /^([A-Za-z]+)\s+(.+)$/.exec(pending);
      if (!match) throw new Error(`invalid Dockerfile instruction: ${pending}`);
      logicalLines.push({
        instruction: match[1].toUpperCase(),
        value: match[2].replace(/\s+/g, " ").trim(),
      });
      pending = "";
    }
  }
  if (pending !== "") throw new Error("Dockerfile ends with a continued instruction");
  return logicalLines;
}

export const containerDockerfileContracts = Object.freeze({
  "docker/flowersec-runtime/Dockerfile": Object.freeze({
    syntax: "# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e",
    buildFrom: "--platform=$BUILDPLATFORM golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build",
    buildOutput: "/out/flowersec-runtime",
    buildPackage: "./cmd/flowersec-runtime",
    final: [
      { instruction: "FROM", value: "gcr.io/distroless/static-debian12:nonroot@sha256:f5b485ea962d9bd1186b2f6b3a061191539b905b82ec395de78cbfae51f20e35" },
      { instruction: "COPY", value: "--from=build /out/flowersec-runtime /usr/local/bin/flowersec-runtime" },
      { instruction: "COPY", value: "LICENSE /usr/share/doc/flowersec/LICENSE" },
      { instruction: "COPY", value: "release-compliance/runtime-image/THIRD_PARTY_NOTICES.md /usr/share/doc/flowersec/THIRD_PARTY_NOTICES.md" },
      { instruction: "COPY", value: "release-compliance/runtime-image/SBOM_SCOPE.md /usr/share/doc/flowersec/SBOM_SCOPE.md" },
      { instruction: "COPY", value: "release-compliance/runtime-image/sbom /usr/share/doc/flowersec/sbom" },
      { instruction: "EXPOSE", value: "8080 443/udp" },
      { instruction: "ENTRYPOINT", value: "[\"/usr/local/bin/flowersec-runtime\"]" },
    ],
  }),
});

export function verifyContainerDockerfile(source, contract) {
  if (!contract) throw new Error("missing container Dockerfile contract");
  const syntaxDirectives = source.split("\n").filter((line) => /^\s*#\s*syntax\s*=/.test(line));
  if (syntaxDirectives.length !== 1 || source.split("\n", 1)[0] !== contract.syntax) {
    throw new Error("container Dockerfile syntax frontend must match the pinned reviewed digest");
  }
  const instructions = parseDockerfile(source);
  const fromIndexes = instructions.flatMap((entry, index) => (
    entry.instruction === "FROM" ? [index] : []
  ));
  if (fromIndexes.length !== 2 || fromIndexes[0] !== 0) {
    throw new Error("container Dockerfile must contain exactly one build stage and one final stage");
  }
  if (instructions[0].value !== contract.buildFrom) {
    throw new Error("container Dockerfile build stage base changed");
  }
  const buildStage = instructions.slice(0, fromIndexes[1]);
  const buildCommands = buildStage.filter((entry) => (
    entry.instruction === "RUN" && /\bgo build\b/.test(entry.value)
  ));
  if (buildCommands.length !== 1
    || !buildCommands[0].value.includes(`-o ${contract.buildOutput} `)
    || !buildCommands[0].value.endsWith(contract.buildPackage)) {
    throw new Error("container Dockerfile build target or output changed");
  }
  const finalStage = instructions.slice(fromIndexes[1]);
  if (JSON.stringify(finalStage) !== JSON.stringify(contract.final)) {
    throw new Error("container Dockerfile final instruction sequence changed");
  }
}

export function verifyContainerReleasePolicy(repoRoot) {
  for (const [relative, contract] of Object.entries(containerDockerfileContracts)) {
    verifyContainerDockerfile(fs.readFileSync(path.join(repoRoot, relative), "utf8"), contract);
  }
}

function main() {
  if (process.argv.length !== 2) {
    throw new Error("usage: check-container-release-policy.mjs");
  }
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  verifyContainerReleasePolicy(repoRoot);
  process.stdout.write("container release policy is valid\n");
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
