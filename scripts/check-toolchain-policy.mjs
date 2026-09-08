#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { readToolchains, repositoryRoot } from "./toolchains.mjs";

export function verifyToolchainPolicy(root = repositoryRoot) {
  const config = readToolchains(root);
  const read = (file) => fs.readFileSync(path.join(root, file), "utf8");
  const equal = (actual, expected, label) => {
    if (actual !== expected) throw new Error(`${label}: expected ${expected}, found ${actual ?? "missing"}`);
  };
  const capture = (file, pattern, expected, label = file) => {
    const matches = [...read(file).matchAll(pattern)];
    if (matches.length !== 1) throw new Error(`${label}: expected one version declaration, found ${matches.length}`);
    equal(matches[0][1], expected, label);
  };

  equal(read(".nvmrc").trim(), config.node.version, ".nvmrc");
  capture("rust-toolchain.toml", /^channel = "([^"]+)"$/gm, config.rust.version);
  const msrv = config.rust.msrv.replace(/\.0$/, "");
  for (const crate of ["flowersec-rust", "flowersec-native-transport", "flowersec-node-native"]) {
    capture(`${crate}/Cargo.toml`, /^rust-version = "([^"]+)"$/gm, msrv);
  }
  for (const manifest of ["Package.swift", "examples/swift/Package.swift"]) {
    capture(manifest, /^\/\/ swift-tools-version: (\S+)$/gm, config.swift.toolsVersion);
  }
  const packages = ["flowersec-ts/package.json", "flowersec-node-native/package.json",
    ...["darwin-arm64", "darwin-x64", "linux-arm64-gnu", "linux-x64-gnu"].map((platform) => `flowersec-node-native/npm/${platform}/package.json`)];
  for (const file of packages) equal(JSON.parse(read(file)).engines.node, `>=${config.node.minimum}`, `${file} Node minimum`);
  const pkg = JSON.parse(read("flowersec-ts/package.json"));
  equal(pkg.devDependencies["@typescript/native"], `npm:typescript@${config.typescript.version}`, "TypeScript compiler");
  equal(pkg.devDependencies.typescript, `npm:@typescript/typescript6@${config.typescript.apiVersion}`, "TypeScript lint API");
  const lock = JSON.parse(read("flowersec-ts/package-lock.json")).packages;
  equal(lock[""]?.engines?.node, `>=${config.node.minimum}`, "locked package Node minimum");
  equal(lock["node_modules/@typescript/native"]?.version, config.typescript.version, "locked TypeScript compiler");
  equal(lock["node_modules/typescript"]?.version, config.typescript.apiVersion, "locked TypeScript API wrapper");
  equal(lock["node_modules/@typescript/old"]?.version, config.typescript.compatibilityVersion, "locked TypeScript compatibility compiler");
  for (const name of ["build", "typecheck:native-integration"]) {
    if (!pkg.scripts[name].includes("node ./node_modules/@typescript/native/bin/tsc")) {
      throw new Error(`TypeScript ${name} must explicitly select the primary compiler`);
    }
  }

  const host = "scripts/test-host-init.sh";
  for (const language of ["go", "node", "rust", "swift"]) {
    capture(host, new RegExp(`^readonly ${language}_version=(\\S+)$`, "gm"), config[language].version, `test host ${language}`);
  }
  const swiftlyVersion = /^readonly swiftly_version=(\S+)$/m.exec(read(host))?.[1];
  const marker = createHash("sha256").update(`${config.swift.version}\n${swiftlyVersion}\npgp-verified\n/var/lib/flowersec-test/cache/toolchains/swift\n`).digest("hex");
  capture(host, /^readonly swift_verification_marker=(\S+)$/gm, marker, "Swift authentication marker");

  const make = read("Makefile");
  if (!/^export GOTOOLCHAIN := local$/m.test(make)) throw new Error("Makefile must disable automatic Go toolchain switching");
  for (const target of ["test", "test-resume", "precommit", "precommit-source", "check"]) {
    const recipe = new RegExp(`^${target}:[^\\n]*\\n((?:\\t.*\\n)*)`, "m").exec(make)?.[1];
    if (!recipe?.startsWith("\tnode scripts/toolchains.mjs --check-runtime go node rust swift\n")) {
      throw new Error(`${target} must validate actual toolchain versions before execution`);
    }
  }
  if (!make.includes("\tnode scripts/check-toolchain-policy.mjs\n") || !make.includes("scripts/toolchains.test.mjs")) {
    throw new Error("Makefile must run toolchain policy and regression tests");
  }
  const msrvRecipe = /^rust-msrv-check:\n((?:\t.*\n)*)/m.exec(make)?.[1] ?? "";
  const msrvCommands = [...msrvRecipe.matchAll(/rustup run (\S+) cargo check/g)];
  if (msrvCommands.length !== 3 || msrvCommands.some((match) => match[1] !== config.rust.msrv)
    || !msrvRecipe.includes("flowersec-native-transport/Cargo.toml") || !msrvRecipe.includes("flowersec-node-native/Cargo.toml")) {
    throw new Error("rust-msrv-check must cover all published Rust crates with the declared minimum compiler");
  }
  // Only the dedicated minimum-version lane may pin an older compiler in Make.
  if (/rustup run|cargo \+(?:stable|nightly)(?:\s|$)/m.test(make.replace(msrvRecipe, ""))) {
    throw new Error("primary Rust recipes must use rust-toolchain.toml; floating toolchains are forbidden");
  }
  if (!make.includes("cargo +$$(node ../scripts/toolchains.mjs --get rust.nightly) fuzz")) {
    throw new Error("fuzzing must use the configured dated nightly");
  }
  const ignored = new Set([".git", ".build", ".swiftpm", ".flowersec", "node_modules", "target", "dist", "coverage", "sbom"]);
  const scan = (directory) => {
    for (const entry of fs.readdirSync(path.join(root, directory), { withFileTypes: true })) {
      if (entry.isSymbolicLink() || ignored.has(entry.name)) continue;
      const relative = path.join(directory, entry.name);
      if (entry.isDirectory()) { scan(relative); continue; }
      if (!/\.(?:mjs|sh|go|yml|yaml)$/.test(entry.name) || /(?:\.test\.mjs|_test\.go)$/.test(entry.name)) continue;
      const source = read(relative);
      if (/cargo\s+\+(?:stable|nightly)(?:\s|$)/m.test(source)) throw new Error(`${relative} uses a floating Rust toolchain`);
      if (/\btoolchain:\s*["']?(?:stable|nightly|beta)(?:["']?\s|$)/m.test(source)) throw new Error(`${relative} uses a floating Rust toolchain`);
      if ((/rustup[^\n]*["']\d+\.\d+\.\d+["']/.test(source)
        || /["']run["']\s*,\s*["']\d+\.\d+\.\d+["']\s*,\s*["']cargo["']/.test(source))
        && !relative.startsWith(".github/") && relative !== "scripts/check-release-workflows.rb") {
        throw new Error(`${relative} must obtain Rust versions from toolchains.json`);
      }
      if (/GOTOOLCHAIN\s*:\s*["']go\d+\.\d+\.\d+["']/.test(source)) {
        throw new Error(`${relative} must obtain Go versions from toolchains.json`);
      }
    }
  };
  for (const directory of ["scripts", "flowersec-go", "tools", ".github"]) scan(directory);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { verifyToolchainPolicy(); process.stdout.write("verified repository toolchain consistency\n"); }
  catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
