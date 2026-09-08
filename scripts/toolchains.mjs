#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

export const repositoryRoot = path.resolve(import.meta.dirname, "..");
const fields = {
  go: ["version"], rust: ["version", "msrv", "nightly"],
  node: ["version", "compatibility"], swift: ["version", "xcode", "toolsVersion"],
  typescript: ["version", "apiVersion", "compatibilityVersion"],
};

export function readToolchains(root = repositoryRoot) {
  const config = JSON.parse(fs.readFileSync(path.join(root, "toolchains.json"), "utf8"));
  const sameKeys = (value, keys) => value && typeof value === "object" && !Array.isArray(value)
    && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort());
  if (!sameKeys(config, Object.keys(fields))) throw new Error("toolchains.json has invalid language fields");
  for (const [language, keys] of Object.entries(fields)) {
    if (!sameKeys(config[language], keys)) throw new Error(`toolchains.json has invalid ${language} fields`);
    for (const key of keys) {
      const pattern = key === "nightly" ? /^nightly-\d{4}-\d{2}-\d{2}$/
        : key === "toolsVersion" ? /^\d+\.\d+$/ : /^\d+\.\d+\.\d+$/;
      if (typeof config[language][key] !== "string" || !pattern.test(config[language][key])) {
        throw new Error(`toolchains.json ${language}.${key} must be an exact version`);
      }
    }
    Object.freeze(config[language]);
  }
  return Object.freeze(config);
}

function output(command, args, env, run) {
  const result = run(command, args, { env, encoding: "utf8" });
  if (result.error || result.status !== 0) throw new Error(`cannot inspect ${command}: ${result.error?.message ?? result.stderr ?? "command failed"}`);
  return result.stdout.trim();
}

export function checkRuntime(languages, { config = readToolchains(), env = process.env, run = spawnSync, platform = process.platform } = {}) {
  for (const language of languages) {
    let actual;
    let expected;
    let install;
    switch (language) {
      case "go":
        expected = config.go.version;
        actual = /^go version go(\S+)/.exec(output("go", ["version"], { ...env, GOTOOLCHAIN: "local" }, run))?.[1];
        install = `install Go ${expected} and put its bin directory first in PATH`;
        if (env.GOTOOLCHAIN && env.GOTOOLCHAIN !== "local" && env.GOTOOLCHAIN !== `go${expected}`) {
          throw new Error(`GOTOOLCHAIN must be local or go${expected}; found ${env.GOTOOLCHAIN}`);
        }
        break;
      case "node":
      case "node-compatibility":
        expected = language === "node" ? config.node.version : config.node.compatibility;
        actual = output("node", ["--version"], env, run).replace(/^v/, "");
        install = `nvm install ${expected} && nvm use ${expected}`;
        break;
      case "rust":
      case "rust-msrv":
        expected = language === "rust" ? config.rust.version : config.rust.msrv;
        for (const key of ["RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER"]) {
          if (env[key]) throw new Error(`${key} must be unset for the repository Rust toolchain; found an override`);
        }
        actual = /^rustc (\S+)/.exec(output("rustc", ["--version"], env, run))?.[1];
        install = `rustup toolchain install ${expected}; select the repository toolchain`;
        break;
      case "swift":
        expected = config.swift.version;
        actual = /Swift version (\S+)/.exec(output("swift", ["--version"], env, run))?.[1];
        install = platform === "darwin" ? `select Xcode ${config.swift.xcode}` : `swiftly install ${expected} --use --verify`;
        if (platform === "darwin") {
          const xcode = /^Xcode (\S+)/.exec(output("xcodebuild", ["-version"], env, run))?.[1];
          if (xcode !== config.swift.xcode) throw new Error(`Xcode: expected ${config.swift.xcode}, actual ${xcode ?? "unknown"}; ${install}`);
        }
        break;
      case "typescript": {
        expected = config.typescript.version;
        const compiler = path.join(repositoryRoot, "flowersec-ts/node_modules/@typescript/native/bin/tsc");
        actual = /^Version (\S+)/.exec(output("node", [compiler, "--version"], env, run))?.[1];
        install = "run npm ci in flowersec-ts";
        const compatibilityCompiler = path.join(repositoryRoot, "flowersec-ts/node_modules/typescript/bin/tsc6");
        const compatibility = /^Version (\S+)/.exec(output("node", [compatibilityCompiler, "--version"], env, run))?.[1];
        if (compatibility !== config.typescript.compatibilityVersion) {
          throw new Error(`TypeScript compatibility compiler: expected ${config.typescript.compatibilityVersion}, actual ${compatibility ?? "unknown"}; ${install}`);
        }
        break;
      }
      default: throw new Error(`unknown toolchain: ${language}`);
    }
    if (actual !== expected) throw new Error(`${language}: expected ${expected}, actual ${actual ?? "unknown"}; ${install}`);
  }
}

function main() {
  const [mode, ...args] = process.argv.slice(2);
  if (mode === "--check-runtime" && args.length) {
    checkRuntime(args);
  } else if (mode === "--get" && args.length === 1) {
    const [language, key, extra] = args[0].split(".");
    const config = readToolchains();
    if (extra || !Object.hasOwn(config, language) || !Object.hasOwn(config[language], key)) throw new Error("unknown toolchain field");
    process.stdout.write(`${config[language][key]}\n`);
  } else {
    throw new Error("usage: toolchains.mjs --check-runtime <language>... | --get <language.field>");
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(); } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
