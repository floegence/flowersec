import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import { access, copyFile, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { readToolchains } from "./toolchains.mjs";
import { signalParityProcess, parityProcessDeadline, cleanupParityArtifact } from "./server-parity-browser-installation.mjs";
import { addNodePeerCoverage, nodePeerCoverageEnvironment, readNodePeerCoverage } from "./ts-peer-coverage.mjs";

const platforms = Object.freeze({
  "darwin-arm64": Object.freeze({ package: "darwin-arm64", library: "libflowersec_node_native.dylib" }),
  "darwin-x64": Object.freeze({ package: "darwin-x64", library: "libflowersec_node_native.dylib" }),
  "linux-arm64": Object.freeze({ package: "linux-arm64-gnu", library: "libflowersec_node_native.so" }),
  "linux-x64": Object.freeze({ package: "linux-x64-gnu", library: "libflowersec_node_native.so" }),
});

export function resolveRustTargetDirectory(repositoryRoot, environment = process.env) {
  const configured = environment.CARGO_TARGET_DIR?.trim();
  return configured === undefined || configured === ""
    ? path.join(repositoryRoot, "flowersec-rust", "target")
    : path.resolve(repositoryRoot, configured);
}

export async function prepareServerParityNativeAddon(repositoryRoot, required, { signal } = {}) {
  if (!required) return Object.freeze({ environment: Object.freeze({}), cleanup: async () => {} });

  const platform = platforms[`${process.platform}-${process.arch}`];
  if (platform === undefined) throw new Error("server parity native addon is unavailable on this platform");

  await buildRustTarget(repositoryRoot, "flowersec-node-native/Cargo.toml", [], "native addon", signal);

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
    if (signal?.aborted) throw signal.reason ?? new Error("native addon preparation canceled");
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
    await cleanupParityArtifact(error, () => rm(stagingRoot, { recursive: true, force: true }));
    throw error;
  }
}

// Compilation has its own bounded preparation lifetime. It must not consume
// a peer's handshake/application deadline on a cold checkout.
export async function prepareServerParityRustPeer(repositoryRoot, required, { signal, environment = {} } = {}) {
  if (!required) return;
  const targetDirectory = resolveRustTargetDirectory(repositoryRoot, { ...process.env, ...environment });
  const peerPath = path.join(targetDirectory, "debug", "examples", process.platform === "win32" ? "server_parity_peer.exe" : "server_parity_peer");
  if (environment.FLOWERSEC_PARITY_RUST_PEER_READY === "1") {
    await access(peerPath);
    return peerPath;
  }
  await buildRustTarget(repositoryRoot, "flowersec-rust/Cargo.toml",
    ["--example", "server_parity_peer"], "Rust parity peer", signal, {
      ...environment,
      CARGO_TARGET_DIR: targetDirectory,
    });
  return peerPath;
}

export async function prepareServerParitySwiftClient(repositoryRoot, required, { signal } = {}) {
  if (required) await buildParityTarget(repositoryRoot, "swift", [
    "build", "--build-tests", "--cache-path", ".flowersec/swiftpm-cache", "--skip-update", "--only-use-versions-from-resolved-file",
  ], "Swift parity client", signal);
}

async function buildRustTarget(repositoryRoot, manifest, arguments_, label, signal, environment) {
  await buildParityTarget(repositoryRoot, "rustup", [
    "run", readToolchains(repositoryRoot).rust.version, "cargo", "build", "--locked", "--manifest-path",
    path.join(repositoryRoot, manifest), ...arguments_,
  ], label, signal, environment);
}

async function buildParityTarget(repositoryRoot, command, arguments_, label, signal, environment) {
  if (signal?.aborted) throw signal.reason ?? new Error(`${label} preparation canceled`);
  const child = spawn(command, arguments_, { cwd: repositoryRoot, env: { ...process.env, ...environment }, detached: process.platform !== "win32", stdio: ["ignore", "pipe", "pipe"] });
  let diagnostic = "", failure;
  child.on("error", error => { failure ??= error; });
  for (const stream of [child.stdout, child.stderr]) {
    stream.setEncoding("utf8");
    stream.on("data", chunk => { diagnostic = `${diagnostic}${chunk}`.slice(-65_536); });
    stream.on("error", error => { failure ??= error; });
  }
  const completion = new Promise(resolve => child.once("close", (code, signal) => resolve({ code, signal })));
  const deadline = parityProcessDeadline(() => [{ child, completion }], 300_000, `${label} preparation exceeded its 300-second bound`);
  const canceled = () => deadline.cancel(signal.reason ?? new Error(`${label} preparation canceled`));
  signal?.addEventListener("abort", canceled, { once: true });
  if (signal?.aborted) canceled();
  try {
    const exit = await deadline.wait(completion);
    if (failure !== undefined || exit.code !== 0) {
      throw new Error(`${label} preparation failed: ${failure?.message ?? `code=${exit.code} signal=${exit.signal}`}\n${diagnostic}`, { cause: failure });
    }
  } catch (error) {
    failure = error;
  } finally {
    signal?.removeEventListener("abort", canceled);
    await deadline.finish(failure);
  }
}

// Every CLI child owns a process group. Cancellation joins the real runtime and
// its output pipes before its addon or independent installation is removed.
async function runNativeCommand(command, arguments_, options, signal, stopDelay = 10_000) {
  if (signal.aborted) throw signal.reason;
  const child = spawn(command, arguments_, {
    ...options, detached: process.platform !== "win32", stdio: ["ignore", "pipe", "pipe"],
  });
  let diagnostic = "", failure, complete = false, killTimer;
  child.on("error", error => { failure ??= error; });
  for (const [stream, output] of [[child.stdout, process.stdout], [child.stderr, process.stderr]]) {
    stream.setEncoding("utf8");
    stream.on("data", chunk => {
      diagnostic = `${diagnostic}${chunk}`.slice(-65_536);
      output.write(chunk);
    });
    stream.on("error", error => { failure ??= error; });
  }
  const completion = new Promise(resolve => child.once("close", (code, exitSignal) => {
    complete = true; resolve({ code, signal: exitSignal });
  }));
  const deadline = parityProcessDeadline(() => [{ child, completion }]);
  const stop = () => {
    if (complete || killTimer !== undefined) return;
    failure ??= signal.reason ?? new Error("native addon gate canceled");
    try { signalParityProcess(child, "SIGTERM"); }
    catch (error) {
      // The bounded SIGKILL/join path resolves a possible reaping race and
      // retains any actual permission failure in its cleanup result.
      deadline.cancel(failure);
      return;
    }
    killTimer = setTimeout(() => deadline.cancel(failure), stopDelay);
  };
  signal.addEventListener("abort", stop, { once: true });
  if (signal.aborted) stop();
  try {
    const exit = await deadline.wait(completion);
    if (failure !== undefined || exit.code !== 0) {
      throw new Error(`${command} failed: ${failure?.message ?? `code=${exit.code} signal=${exit.signal}`}\n${diagnostic}`, { cause: failure });
    }
  } catch (error) {
    failure = error;
  } finally {
    clearTimeout(killTimer);
    signal.removeEventListener("abort", stop);
    await deadline.finish(failure);
  }
}

async function runNativeIntegration(repositoryRoot, title, signal) {
  const arguments_ = ["run", "src/node/nativeRawQuic.integration.test.ts"];
  let resultDirectory;
  let resultFile;
  if (title !== undefined) {
    arguments_.push("-t", `(^|\\s)${escapeRegex(title)}$`, "--reporter=json");
    resultDirectory = await mkdtemp(path.join(repositoryRoot, ".flowersec", "native-integration-result-"));
    resultFile = path.join(resultDirectory, "result.json");
    arguments_.push("--outputFile", resultFile);
  }
  try {
    try {
      await runVitestWithNativeAddon(repositoryRoot, arguments_, signal);
    } catch (error) {
      // Vitest can exit before the normal JSON assertion path runs. Preserve
      // any result it did write in the thrown diagnostic so the outer Go gate
      // records the failing title, assertion status, and execution pattern
      // before the disposable result directory is removed.
      if (resultFile !== undefined) {
        try {
          const raw = await readFile(resultFile, "utf8");
          const result = JSON.parse(raw);
          const assertions = Array.isArray(result.testResults)
            ? result.testResults.flatMap(testResult => Array.isArray(testResult.assertionResults) ? testResult.assertionResults : [])
            : [];
          error = new Error(`${error.message}\nnative integration result: ${JSON.stringify({
            title,
            executed: assertions.map(assertion => ({ fullName: assertion.fullName, status: assertion.status, failureMessages: assertion.failureMessages })),
          })}`, { cause: error });
        } catch (diagnosticError) {
          error = new Error(`${error.message}\nnative integration result unavailable: ${diagnosticError.message}`, { cause: error });
        }
      }
      throw error;
    }
    if (resultFile !== undefined) {
      const result = JSON.parse(await readFile(resultFile, "utf8"));
      validateSuccessfulResult(result, "native integration title", title);
    }
  } finally {
    if (resultDirectory !== undefined) await rm(resultDirectory, { recursive: true, force: true });
  }
}

async function runNativeSmoke(repositoryRoot, signal) {
  const fixture = await prepareServerParityNativeAddon(repositoryRoot, true, { signal });
  let failure;
  try {
    await runNativeCommand(process.execPath, [
      path.join(repositoryRoot, "scripts/native-addon-smoke.mjs"),
    ], {
      cwd: repositoryRoot,
      env: { ...process.env, ...fixture.environment },
    }, signal);
  } catch (error) {
    failure = error; throw error;
  } finally {
    await cleanupParityArtifact(failure, () => fixture.cleanup());
  }
}

async function runCoverage(repositoryRoot, signal) {
  await runVitestWithNativeAddon(repositoryRoot, ["run", "--coverage"], signal);
}

async function runCoverageTitle(repositoryRoot, file, title, shard, config, signal) {
  const resultFile = path.join(shard, "test-result.json");
  try {
    await runVitestWithNativeAddon(repositoryRoot, [
      "run", file, "-t", `(^|\\s)${escapeRegex(title)}$`, "--config", config,
      "--coverage", "--coverage.reportsDirectory", shard, "--coverage.reporter", "json",
      "--reporter=default", "--reporter=json", "--outputFile", resultFile,
    ], signal);
  } catch (error) {
    let details = "";
    try {
      const result = JSON.parse(await readFile(resultFile, "utf8"));
      const assertions = Array.isArray(result.testResults)
        ? result.testResults.flatMap(testResult => Array.isArray(testResult.assertionResults) ? testResult.assertionResults : [])
        : [];
      const failed = assertions.filter(assertion => assertion.status === "failed");
      details = `; failed assertions: ${JSON.stringify(failed.map(assertion => ({
        fullName: assertion.fullName,
        failureMessages: assertion.failureMessages,
      })))}; suiteSuccess=${String(result.success)}`;
    } catch (diagnosticError) {
      details = `; result diagnostics unavailable: ${diagnosticError instanceof Error ? diagnosticError.message : String(diagnosticError)}`;
    }
    throw new Error(`coverage title command failed for ${file} ${JSON.stringify(title)}${details}`, { cause: error });
  }
  const result = await readJsonFile(resultFile, "coverage title test result");
  const coverageFile = path.join(shard, "coverage-final.json");
  await readCoverageFile(coverageFile);
  validateSuccessfulResult(result, `coverage title ${file}`, title);
}

// These processes have separate test, transport and report owners. A failure
// cancels its sibling, and both physical process tails join before cleanup.
export async function runCoverageLanes(integration, unit, signal) {
  const cancellation = new AbortController();
  const laneSignal = signal === undefined ? cancellation.signal : AbortSignal.any([signal, cancellation.signal]);
  laneSignal.throwIfAborted();
  const results = await Promise.allSettled([integration, unit].map(async run => {
    try { await run(laneSignal); }
    catch (error) { cancellation.abort(error); throw error; }
  }));
  const failures = results.filter(result => result.status === "rejected").map(result => result.reason);
  if (failures.length !== 0) throw new AggregateError(failures, "TypeScript coverage lane failed");
}

async function runCoverageGate(repositoryRoot, signal) {
  const scratchRoot = await mkdtemp(path.join(repositoryRoot, ".flowersec", "ts-coverage-"));
  const shardRoot = path.join(scratchRoot, "shards");
  const unitShard = path.join(shardRoot, "unit");
  const configPath = path.join(scratchRoot, "vitest.config.mjs");
  let fixture;
  let failure;
  try {
    await mkdir(shardRoot, { recursive: true });
    await mkdir(unitShard, { recursive: true });
    await writeFile(configPath, coverageShardConfig(repositoryRoot), "utf8");
    fixture = await prepareServerParityNativeAddon(repositoryRoot, true, { signal });
    // Build before acquiring any Go-owned installation. Shards launch this
    // exact binary directly so Cargo locks cannot consume the peer's lifetime.
    const rustPeerPath = await prepareServerParityRustPeer(repositoryRoot, true, { signal });
    const unitResultFile = path.join(unitShard, "test-result.json");
    await runCoverageLanes(async laneSignal => {
      await runNativeCommand("go", [
        "run", "./internal/cmd/native-addon-gate", repositoryRoot, process.execPath, "--test-coverage",
      ], {
        cwd: path.join(repositoryRoot, "flowersec-go"),
        env: {
          ...process.env,
          ...fixture.environment,
          FLOWERSEC_SERVER_PARITY_RUST_PEER_BINARY: rustPeerPath,
          FLOWERSEC_SERVER_PARITY_PEER: "1",
          FLOWERSEC_COVERAGE_SHARD_ROOT: shardRoot,
          FLOWERSEC_COVERAGE_SHARD_CONFIG: configPath,
        },
      }, laneSignal, 30_000);
    }, async laneSignal => {
      try {
        await runVitestWithNativeAddon(repositoryRoot, [
          // Keep instrumented encryption workers bounded while native peers
          // run independently in the other lane.
          "run", "--maxWorkers=2", "--exclude", "src/**/*.integration.test.ts", "--config", configPath,
          "--coverage", "--coverage.reportsDirectory", unitShard, "--coverage.reporter", "json",
          "--reporter=default", "--reporter=json", "--outputFile", unitResultFile,
        ], laneSignal, fixture.environment);
      } catch (error) {
        let details;
        try {
          const result = await readJsonFile(unitResultFile, "unit test result");
          details = JSON.stringify({
            success: result.success,
            failed: resultAssertions(result).filter(assertion => assertion.status === "failed")
              .map(({ fullName, failureMessages }) => ({ fullName, failureMessages })),
            suites: result.testResults?.filter(suite => suite.message).map(({ name, message }) => ({ name, message })),
          });
        } catch (diagnosticError) {
          details = `result diagnostics unavailable: ${diagnosticError instanceof Error ? diagnosticError.message : String(diagnosticError)}`;
        }
        // Preserve the failed assertions before the original scratch owner removes
        // its JSON report; the child exit remains a failure even without a report.
        throw new Error(`unit coverage command failed: ${details}`, { cause: error });
      }
    }, signal);
    const integrationCoverageFiles = await validateIntegrationCoverage(shardRoot);
    await validateUnitCoverage(unitShard, unitResultFile);
    const peerCoverage = await runNodePeerCoverage(repositoryRoot, scratchRoot, signal);
    await mergeCoverage(repositoryRoot, [
      ...integrationCoverageFiles,
      path.join(unitShard, "coverage-final.json"),
    ], peerCoverage);
  } catch (error) {
    failure = error; throw error;
  } finally {
    if (fixture !== undefined) await cleanupParityArtifact(failure, () => fixture.cleanup());
    await cleanupParityArtifact(failure, () => rm(scratchRoot, { recursive: true, force: true }));
  }
}

export async function runNodePeerCoverage(repositoryRoot, scratchRoot, signal) {
  const environment = { ...process.env };
  for (const key of Object.keys(environment)) {
    if (key.startsWith("FLOWERSEC_PARITY_") || key.startsWith("__CARGO_LLVM_COV_")
        || key.startsWith("CARGO_LLVM_COV") || ["LLVM_PROFILE_FILE", "RUSTC_WRAPPER"].includes(key)) delete environment[key];
  }
  const workflows = [
    { name: "pool-endpoints", source: "preauthorized_pool", a: "node-typescript", relay: "go", b: "node-typescript", roles: ["tunnel-endpoint-a", "tunnel-endpoint-b"] },
    { name: "pool-relay", source: "preauthorized_pool", a: "go", relay: "node-typescript", b: "node-typescript", roles: ["relay", "tunnel-endpoint-b"] },
    { name: "live-endpoints", source: "live_authority", a: "rust,node-typescript", relay: "rust", b: "node-typescript,go", roles: ["tunnel-endpoint-a", "tunnel-endpoint-b"] },
    { name: "live-native", source: "live_authority", a: "rust,node-typescript", relay: "rust", b: "node-typescript,go", carrier: "raw-quic", roles: ["tunnel-endpoint-a", "tunnel-endpoint-b"] },
    { name: "live-native-client-listener", source: "live_authority", a: "rust,node-typescript", relay: "rust", b: "node-typescript,go", carrier: "raw-quic", clientListener: "endpoint", roles: ["tunnel-endpoint-a", "tunnel-endpoint-b"] },
    { name: "live-native-server-dialer", source: "live_authority", a: "rust,node-typescript", relay: "rust", b: "node-typescript,go", carrier: "raw-quic", serverListener: "relay", roles: ["tunnel-endpoint-a", "tunnel-endpoint-b"] },
    { name: "pool-native-endpoints", source: "preauthorized_pool", a: "node-typescript", relay: "go", b: "node-typescript", carrier: "raw-quic", roles: ["tunnel-endpoint-a", "tunnel-endpoint-b"] },
    { name: "pool-native-relay", source: "preauthorized_pool", a: "go", relay: "node-typescript", b: "node-typescript", carrier: "raw-quic", roles: ["relay", "tunnel-endpoint-b"] },
    { name: "pool-client-listener", source: "preauthorized_pool", a: "node-typescript", relay: "go", b: "node-typescript", clientListener: "endpoint", roles: ["tunnel-endpoint-a", "tunnel-endpoint-b"] },
    { name: "live-client-listener-server-dialer", source: "live_authority", a: "rust,node-typescript", relay: "rust", b: "node-typescript,go", clientListener: "endpoint", serverListener: "relay", roles: ["tunnel-endpoint-a", "tunnel-endpoint-b"] },
  ];
  const coverage = [];
  // Each workflow owns its installation, processes and profile directory.
  // Reuse the bounded sibling cancellation/join before collecting any result.
  const lane = async (offset, laneSignal) => {
    for (let index = offset; index < workflows.length; index += 2) {
      laneSignal.throwIfAborted();
      const workflow = workflows[index], directory = path.join(scratchRoot, workflow.name);
      await mkdir(directory);
      console.log(`TypeScript peer coverage: ${workflow.name}`);
      await runNativeCommand(process.execPath, [path.join(repositoryRoot, "scripts/test-server-parity-tunnel.mjs")], {
        cwd: repositoryRoot,
        env: { ...environment, ...nodePeerCoverageEnvironment(directory),
          FLOWERSEC_PARITY_ACTIVATION_SOURCE: workflow.source, FLOWERSEC_PARITY_ENDPOINT_AS: workflow.a,
          FLOWERSEC_PARITY_RELAYS: workflow.relay, FLOWERSEC_PARITY_ENDPOINT_BS: workflow.b,
          FLOWERSEC_PARITY_CARRIERS: workflow.carrier ?? "websocket",
          FLOWERSEC_PARITY_CLIENT_LISTENER: workflow.clientListener ?? "relay",
          FLOWERSEC_PARITY_SERVER_LISTENER: workflow.serverListener ?? "endpoint",
        },
      }, laneSignal);
      coverage[index] = await readNodePeerCoverage(directory, workflow.roles);
    }
  };
  await runCoverageLanes(signal => lane(0, signal), signal => lane(1, signal), signal);
  return coverage;
}

function coverageShardConfig(repositoryRoot) {
  const vitestConfig = pathToFileURL(path.join(repositoryRoot, "flowersec-ts", "node_modules", "vitest", "dist", "config.js")).href;
  const originalConfig = pathToFileURL(path.join(repositoryRoot, "flowersec-ts", "vitest.config.ts")).href;
  return `import { defineConfig } from ${JSON.stringify(vitestConfig)};
import original from ${JSON.stringify(originalConfig)};
export default defineConfig({ ...original, test: { ...original.test, coverage: { ...original.test.coverage, thresholds: {} } } });
`;
}

async function readJsonFile(file, label) {
  try {
    return JSON.parse(await readFile(file, "utf8"));
  } catch (error) {
    throw new Error(`unable to read ${label} at ${file}: ${error instanceof Error ? error.message : String(error)}`, { cause: error });
  }
}

async function readCoverageFile(file) {
  const coverage = await readJsonFile(file, "coverage-final.json");
  if (coverage === null || typeof coverage !== "object" || Array.isArray(coverage)) {
    throw new Error(`coverage-final.json at ${file} is not a JSON object`);
  }
  return coverage;
}

function resultAssertions(result) {
  return Array.isArray(result?.testResults)
    ? result.testResults.flatMap(testResult => Array.isArray(testResult.assertionResults) ? testResult.assertionResults : [])
    : [];
}

export function validateSuccessfulResult(result, label, expectedTitle) {
  if (result?.success !== true) {
    throw new Error(`${label} did not report suiteSuccess=true: ${JSON.stringify({ success: result?.success })}`);
  }
  const assertions = resultAssertions(result);
  const failed = assertions.filter(assertion => assertion.status === "failed");
  if (failed.length !== 0) {
    throw new Error(`${label} reported failed assertions: ${JSON.stringify(failed.map(assertion => ({
      fullName: assertion.fullName,
      failureMessages: assertion.failureMessages,
    })))}`);
  }
  if (expectedTitle !== undefined) {
    const executed = assertions.filter(assertion => assertion.status === "passed" || assertion.status === "failed");
    // Vitest's fullName includes suite ancestors; title is the exact leaf name.
    // Accept either explicit name while still requiring one executed test.
    const matching = assertions.filter(assertion => assertion.status === "passed"
      && (assertion.fullName === expectedTitle || assertion.title === expectedTitle));
    if (executed.length !== 1 || matching.length !== 1) {
      throw new Error(`${label} did not execute exactly one passing test: ${JSON.stringify({
        title: expectedTitle,
        executed: executed.map(assertion => ({ fullName: assertion.fullName, status: assertion.status })),
        matching: matching.map(assertion => assertion.fullName),
      })}`);
    }
  }
}

async function validateIntegrationCoverage(shardRoot) {
  const manifestPath = path.join(shardRoot, "integration-manifest.json");
  const manifest = await readJsonFile(manifestPath, "integration coverage manifest");
  if (!Array.isArray(manifest?.tests) || manifest.tests.length === 0) {
    throw new Error(`integration coverage manifest has no tests: ${manifestPath}`);
  }
  const seen = new Set();
  const coverageFiles = [];
  for (const [index, test] of manifest.tests.entries()) {
    if (typeof test?.file !== "string" || test.file.trim() === "" || typeof test?.name !== "string" || test.name.trim() === "") {
      throw new Error(`integration coverage manifest contains an invalid test at index ${index}`);
    }
    const key = `${test.file}\x00${test.name}`;
    if (seen.has(key)) throw new Error(`integration coverage manifest contains duplicate test ${JSON.stringify(key)}`);
    seen.add(key);
    const shard = path.join(shardRoot, String(index).padStart(4, "0"));
    try {
      await readdir(shard);
    } catch (error) {
      throw new Error(`integration coverage shard directory is missing: ${shard}`, { cause: error });
    }
    const resultPath = path.join(shard, "test-result.json");
    const coveragePath = path.join(shard, "coverage-final.json");
    const result = await readJsonFile(resultPath, `integration test result for ${test.file} ${JSON.stringify(test.name)}`);
    await readCoverageFile(coveragePath);
    validateSuccessfulResult(result, `integration shard ${String(index).padStart(4, "0")}`, test.name);
    coverageFiles.push(coveragePath);
  }
  const entries = await readdir(shardRoot, { withFileTypes: true });
  const numberedShards = entries.filter(entry => entry.isDirectory() && /^\d{4}$/.test(entry.name)).map(entry => entry.name).sort();
  const expectedShards = manifest.tests.map((_, index) => String(index).padStart(4, "0"));
  if (numberedShards.length !== expectedShards.length || numberedShards.some((name, index) => name !== expectedShards[index])) {
    throw new Error(`integration coverage shard count or mapping mismatch: ${JSON.stringify({ expected: expectedShards, actual: numberedShards })}`);
  }
  return coverageFiles;
}

async function validateUnitCoverage(unitShard, resultFile) {
  const result = await readJsonFile(resultFile, "unit test result");
  validateSuccessfulResult(result, "unit test suite");
  await readCoverageFile(path.join(unitShard, "coverage-final.json"));
}

async function mergeCoverage(repositoryRoot, coverageFiles, peerCoverage) {
  const requireFromTS = createRequire(path.join(repositoryRoot, "flowersec-ts", "package.json"));
  const { createCoverageMap } = requireFromTS("istanbul-lib-coverage");
  const libReport = requireFromTS("istanbul-lib-report");
  const reports = requireFromTS("istanbul-reports");
  if (coverageFiles.length === 0) throw new Error("coverage shards produced no coverage-final.json");
  const coverageMap = createCoverageMap({});
  for (const file of coverageFiles) coverageMap.merge(await readCoverageFile(file));
  for (const peer of peerCoverage) addNodePeerCoverage(coverageMap, peer);
  const outputDirectory = path.join(repositoryRoot, "flowersec-ts", "coverage");
  await rm(outputDirectory, { recursive: true, force: true });
  await mkdir(outputDirectory, { recursive: true });
  const context = libReport.createContext({ dir: outputDirectory, coverageMap, projectRoot: path.join(repositoryRoot, "flowersec-ts") });
  for (const reporter of ["text-summary", "json-summary", "json"]) reports.create(reporter).execute(context);
  const originalConfig = await import(`${pathToFileURL(path.join(repositoryRoot, "flowersec-ts", "vitest.config.ts")).href}?coverage-merge=${Date.now()}`);
  const thresholds = originalConfig.default?.test?.coverage?.thresholds;
  if (thresholds === undefined || typeof thresholds !== "object") throw new Error("vitest coverage thresholds are missing");
  const summary = coverageMap.getCoverageSummary().toJSON();
  const failures = Object.entries(thresholds).filter(([key, threshold]) => summary[key].pct < threshold)
    .map(([key, threshold]) => `${key} ${summary[key].pct}% < ${threshold}%`);
  if (failures.length !== 0) throw new Error(`merged TypeScript coverage is below threshold: ${failures.join(", ")}`);
}

export async function runVitestWithNativeAddon(repositoryRoot, vitestArguments, signal, inheritedEnvironment = {}) {
  await runWithNativeAddon(repositoryRoot, "vitest", vitestArguments, signal, inheritedEnvironment);
}

async function runWithNativeAddon(repositoryRoot, runner, arguments_, signal, inheritedEnvironment = {}) {
  const environment = { ...process.env, ...inheritedEnvironment };
  if (runner === "vitest" && arguments_.some(argument => argument.includes("proxyServerMatrix.integration.test.ts"))
      && environment.FLOWERSEC_SERVER_PARITY_RUST_PEER_BINARY === undefined) {
    environment.FLOWERSEC_SERVER_PARITY_RUST_PEER_BINARY = await prepareServerParityRustPeer(repositoryRoot, true, { signal });
  }
  const reuse = environment.FLOWERSEC_NATIVE_ADDON_PATH !== undefined;
  const fixture = reuse
    ? Object.freeze({ environment: Object.freeze({}), cleanup: async () => {} })
    : await prepareServerParityNativeAddon(repositoryRoot, true, { signal });
  let failure;
  try {
    await runNativeCommand("npm", ["exec", "--", runner, ...arguments_], {
      cwd: path.join(repositoryRoot, "flowersec-ts"),
      env: { ...environment, ...fixture.environment },
    }, signal);
  } catch (error) {
    failure = error; throw error;
  } finally {
    await cleanupParityArtifact(failure, () => fixture.cleanup());
  }
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const runPlaywright = process.argv.length >= 4 && process.argv[2] === "--playwright";
  const runVitest = process.argv.length >= 4 && process.argv[2] === "--vitest";
  const runAll = process.argv.length === 3 && process.argv[2] === "--test-native-integration";
  const runSmoke = process.argv.length === 3 && process.argv[2] === "--test-native-smoke";
  const runAllCoverage = process.argv.length === 3 && process.argv[2] === "--test-coverage";
  const runTitle = process.argv.length === 4 && process.argv[2] === "--test-title" && process.argv[3].trim() !== "";
  const runCoverageTitleMode = process.argv.length === 7 && process.argv[2] === "--test-coverage-title"
    && process.argv.slice(3).every(value => value.trim() !== "");
  if (!runAll && !runAllCoverage && !runSmoke && !runTitle && !runCoverageTitleMode && !runVitest && !runPlaywright) {
    throw new Error(
      "usage: server-parity-native-addon.mjs <--test-native-integration|--test-native-smoke|--test-coverage|--test-title TITLE|--vitest ARGS...|--playwright ARGS...>",
    );
  }
  const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  if (runSmoke && !process.env.FLOWERSEC_NATIVE_TUNNEL_INSTALLATION) {
    throw new Error("--test-native-smoke requires FLOWERSEC_NATIVE_TUNNEL_INSTALLATION");
  }
  const cancellation = new AbortController();
  const stop = received => cancellation.abort(new Error(`native addon gate received ${received}`));
  const interrupt = () => stop("SIGINT"), terminate = () => stop("SIGTERM");
  process.on("SIGINT", interrupt); process.on("SIGTERM", terminate);
  try {
    if (runPlaywright) {
      await runWithNativeAddon(repositoryRoot, "playwright", process.argv.slice(3), cancellation.signal);
    } else if (runVitest) {
      // Current SQLite-backed integration tests own their own HTTP/WSS peers.
      // They still install the exact native extension and join its real process
      // before removing the staged package, using the common native runner.
      await runVitestWithNativeAddon(repositoryRoot, process.argv.slice(3), cancellation.signal);
    } else if (!process.env.FLOWERSEC_NATIVE_TUNNEL_INSTALLATION) {
      // Coverage builds the addon before the Go owner acquires any original
      // installation. Other native gates retain the Go-owned lifecycle.
      if (runAllCoverage) await runCoverageGate(repositoryRoot, cancellation.signal);
      else await runNativeCommand("go", [
        "run", "./internal/cmd/native-addon-gate", repositoryRoot, process.execPath, ...process.argv.slice(2),
      ], { cwd: path.join(repositoryRoot, "flowersec-go") }, cancellation.signal, 30_000);
    } else if (runAllCoverage) await runCoverage(repositoryRoot, cancellation.signal);
    else if (runCoverageTitleMode) await runCoverageTitle(repositoryRoot, process.argv[3], process.argv[4], process.argv[5], process.argv[6], cancellation.signal);
    else if (runSmoke) await runNativeSmoke(repositoryRoot, cancellation.signal);
    else {
      await runNativeIntegration(repositoryRoot, runTitle ? process.argv[3] : undefined, cancellation.signal);
      if (runAll) await runNativeSmoke(repositoryRoot, cancellation.signal);
    }
  } catch (error) {
    console.error(error);
    process.exitCode = 1;
  } finally {
    process.removeListener("SIGINT", interrupt); process.removeListener("SIGTERM", terminate);
  }
}
