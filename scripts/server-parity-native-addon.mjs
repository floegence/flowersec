import { execFile } from "node:child_process";
import { copyFile, mkdir, mkdtemp, rm } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const platforms = Object.freeze({
  "darwin-arm64": Object.freeze({ package: "darwin-arm64", library: "libflowersec_node_native.dylib" }),
  "darwin-x64": Object.freeze({ package: "darwin-x64", library: "libflowersec_node_native.dylib" }),
  "linux-arm64": Object.freeze({ package: "linux-arm64-gnu", library: "libflowersec_node_native.so" }),
  "linux-x64": Object.freeze({ package: "linux-x64-gnu", library: "libflowersec_node_native.so" }),
});

export async function prepareServerParityNativeAddon(repositoryRoot, required) {
  if (!required) return Object.freeze({ environment: Object.freeze({}), cleanup: async () => {} });

  const platform = platforms[`${process.platform}-${process.arch}`];
  if (platform === undefined) throw new Error("server parity native addon is unavailable on this platform");

  await execFileAsync("rustup", [
    "run", "1.88.0", "cargo", "build", "--locked", "--manifest-path",
    path.join(repositoryRoot, "flowersec-node-native/Cargo.toml"),
  ], { cwd: repositoryRoot });

  const scratchRoot = path.join(repositoryRoot, ".flowersec");
  await mkdir(scratchRoot, { recursive: true });
  const stagingRoot = await mkdtemp(path.join(scratchRoot, "server-parity-native-"));
  try {
    const scopeRoot = path.join(stagingRoot, "node_modules/@floegence");
    const wrapperRoot = path.join(scopeRoot, "flowersec-node-native");
    const platformRoot = path.join(scopeRoot, `flowersec-node-native-${platform.package}`);
    await mkdir(wrapperRoot, { recursive: true });
    await mkdir(platformRoot, { recursive: true });
    await Promise.all([
      copyFile(path.join(repositoryRoot, "flowersec-node-native/index.js"), path.join(wrapperRoot, "index.js")),
      copyFile(path.join(repositoryRoot, "flowersec-node-native/package.json"), path.join(wrapperRoot, "package.json")),
      copyFile(
        path.join(repositoryRoot, `flowersec-node-native/npm/${platform.package}/package.json`),
        path.join(platformRoot, "package.json"),
      ),
      copyFile(
        path.join(repositoryRoot, `flowersec-node-native/target/debug/${platform.library}`),
        path.join(platformRoot, `flowersec-node-native.${platform.package}.node`),
      ),
    ]);
    const moduleRoot = path.join(stagingRoot, "node_modules");
    const nodePath = process.env.NODE_PATH === undefined || process.env.NODE_PATH === ""
      ? moduleRoot
      : `${moduleRoot}${path.delimiter}${process.env.NODE_PATH}`;
    const addonPath = path.join(platformRoot, `flowersec-node-native.${platform.package}.node`);
    return Object.freeze({
      environment: Object.freeze({
        NODE_PATH: nodePath,
        FLOWERSEC_SERVER_PARITY_NATIVE_ADDON: path.join(wrapperRoot, "index.js"),
        FLOWERSEC_NATIVE_ADDON_PATH: addonPath,
      }),
      cleanup: async () => { await rm(stagingRoot, { recursive: true, force: true }); },
    });
  } catch (error) {
    await rm(stagingRoot, { recursive: true, force: true });
    throw error;
  }
}

async function runNativeIntegration(repositoryRoot, title) {
  const arguments_ = [
    "run", "src/node/nativeRawQuic.integration.test.ts",
  ];
  if (title !== undefined) arguments_.push("-t", `(^|\\s)${escapeRegex(title)}$`);
  await runVitestWithNativeAddon(repositoryRoot, arguments_);
}

async function runCoverage(repositoryRoot) {
  await runVitestWithNativeAddon(repositoryRoot, ["run", "--coverage"]);
}

async function runVitestWithNativeAddon(repositoryRoot, vitestArguments) {
  const fixture = await prepareServerParityNativeAddon(repositoryRoot, true);
  try {
    const result = await execFileAsync("npm", ["exec", "--", "vitest", ...vitestArguments], {
      cwd: path.join(repositoryRoot, "flowersec-ts"),
      env: { ...process.env, ...fixture.environment },
      maxBuffer: 16 * 1024 * 1024,
    });
    process.stdout.write(result.stdout);
    process.stderr.write(result.stderr);
  } finally {
    await fixture.cleanup();
  }
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const runAll = process.argv.length === 3 && process.argv[2] === "--test-native-integration";
  const runAllCoverage = process.argv.length === 3 && process.argv[2] === "--test-coverage";
  const runTitle = process.argv.length === 4 && process.argv[2] === "--test-title" && process.argv[3].trim() !== "";
  if (!runAll && !runAllCoverage && !runTitle) {
    throw new Error(
      "usage: server-parity-native-addon.mjs <--test-native-integration|--test-coverage|--test-title TITLE>",
    );
  }
  const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  if (runAllCoverage) await runCoverage(repositoryRoot);
  else await runNativeIntegration(repositoryRoot, runTitle ? process.argv[3] : undefined);
}
