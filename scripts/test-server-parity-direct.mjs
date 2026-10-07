import { spawn } from "node:child_process";
import { readFile, readdir, stat } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import net from "node:net";
import path from "node:path";

import {
  SERVER_PARITY_CARRIERS,
  SERVER_PARITY_RUNTIMES,
} from "./server-parity-matrix.mjs";
import { prepareBrowserParityInstallation, signalParityProcess, parityProcessDeadline, cleanupParityArtifact } from "./server-parity-browser-installation.mjs";
import { prepareServerParityNativeAddon, prepareServerParityRustPeer, prepareServerParitySwiftClient, resolveRustTargetDirectory } from "./server-parity-native-addon.mjs";
import { readToolchains } from "./toolchains.mjs";
import { assertCurrentPeer, assertCurrentMaterial } from "./server-parity-material.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const toolchains = readToolchains(repositoryRoot);
const rustCoverageEnvironment = readRustCoverageEnvironment();
const rustEnvironment = rustCoverageEnvironment === undefined ? {} : { ...rustCoverageEnvironment, FLOWERSEC_PARITY_RUST_PEER_READY: "1" };
const rustTargetDirectory = resolveRustTargetDirectory(repositoryRoot, { ...process.env, ...rustEnvironment });
const matrix = JSON.parse(await readFile(path.join(repositoryRoot, "stability/interop_matrix.json"), "utf8"));
const clientProfile = process.env.FLOWERSEC_PARITY_CLIENT_PROFILE?.trim();
const clientProfileTestID = process.env.FLOWERSEC_PARITY_TEST_ID?.trim();
const runtimeValues = SERVER_PARITY_RUNTIMES;
const carrierValues = SERVER_PARITY_CARRIERS;
const clients = selectedValues("FLOWERSEC_PARITY_CLIENTS", runtimeValues);
const servers = selectedValues("FLOWERSEC_PARITY_SERVERS", runtimeValues);
const carriers = selectedValues("FLOWERSEC_PARITY_CARRIERS", carrierValues);
const commonCases = [
  "admission",
  "rpc",
  "notification",
  "stream-metadata",
  "stream-fin",
  "stream-reset",
  "rekey",
  "liveness",
  "close",
  "cancel",
  "cleanup",
];
const datagramCarriers = new Set(["raw-quic"]);
const cellTimeoutMS = 45_000;

const peers = {
  go: {
    cwd: path.join(repositoryRoot, "flowersec-go"),
    command: "go",
    arguments: ["run", "./internal/cmd/server-parity-peer"],
  },
  rust: {
    cwd: repositoryRoot,
    command: path.join(rustTargetDirectory, "debug/examples", process.platform === "win32" ? "server_parity_peer.exe" : "server_parity_peer"),
    arguments: [],
  },
  "node-typescript": {
    cwd: path.join(repositoryRoot, "flowersec-ts"),
    command: process.execPath,
    arguments: ["--import", "tsx", "src/interop/serverParityPeer.ts"],
  },
};
validateDirectContract(matrix.direct_cells);
const selectedCells = clientProfile === undefined
  ? matrix.direct_cells.filter((cell) => cell.status === "supported" && clients.includes(cell.client) && servers.includes(cell.server) && carriers.includes(cell.carrier))
  : [selectClientProfileCell()];
if (clientProfile === undefined && selectedCells.length === 0) {
  throw new Error("server parity direct matrix selected no supported current cells");
}
await prepareServerParitySwiftClient(repositoryRoot, clientProfile === "swift");
await prepareServerParityRustPeer(repositoryRoot, selectedCells.some(cell =>
  cell.client === "rust" || cell.server === "rust"), { environment: rustEnvironment });
const nativeAddon = await prepareServerParityNativeAddon(repositoryRoot, selectedCells.some((cell) =>
  cell.client === "node-typescript" || cell.server === "node-typescript"
));
let processFailure;
try {
  for (const cell of selectedCells) await runCell(cell);
  console.log(`server parity direct matrix OK: ${selectedCells.length} supported production cells`);
} catch (error) {
  processFailure = error; throw error;
} finally {
  await cleanupParityArtifact(processFailure, () => nativeAddon.cleanup());
}

function selectedValues(environmentName, allowed) {
  const raw = process.env[environmentName]?.trim();
  if (raw === undefined || raw === "") return allowed;
  const selected = [...new Set(raw.split(",").map((value) => value.trim()).filter(Boolean))];
  if (selected.length === 0 || selected.some((value) => !allowed.includes(value))) {
    throw new Error(`${environmentName} contains an unsupported matrix value`);
  }
  return selected;
}

function validateDirectContract(cells) {
  if (!Array.isArray(cells)) throw new Error("direct matrix must declare every runtime and carrier tuple");
  const seen = new Set();
  for (const cell of cells) {
    const key = `${cell.client}/${cell.server}/${cell.carrier}`;
    if (!runtimeValues.includes(cell.client) || !runtimeValues.includes(cell.server) || !carrierValues.includes(cell.carrier) || seen.has(key)) throw new Error(`${cell.id}: invalid or duplicate direct tuple`);
    seen.add(key);
    const expectedCases = [...commonCases, ...(datagramCarriers.has(cell.carrier) ? ["datagram"] : [])];
    if (!sameValues(cell.cases, expectedCases)) throw new Error(`${cell.id}: cases do not match the executable direct contract`);
    if (cell.status === "supported") {
      if (!Array.isArray(cell.test_ids) || cell.test_ids.length !== 1 || "reason" in cell) throw new Error(`${cell.id}: supported tuple must bind exactly one test ID and no reason`);
    } else if (cell.status === "unsupported") {
      if ((Array.isArray(cell.test_ids) && cell.test_ids.length !== 0) || typeof cell.reason !== "string" || cell.reason.length === 0) throw new Error(`${cell.id}: unsupported tuple must carry only a reason`);
    } else {
      throw new Error(`${cell.id}: forbidden status ${String(cell.status)}`);
    }
  }
  for (const client of runtimeValues) for (const server of runtimeValues) for (const carrier of carrierValues) {
    if (!seen.has(`${client}/${server}/${carrier}`)) throw new Error(`missing direct tuple ${client}/${server}/${carrier}`);
  }
}

function sameValues(actual, expected) {
  return Array.isArray(actual) && actual.length === expected.length && expected.every((value, index) => actual[index] === value);
}

async function runCell(cell) {
  if (clientProfile !== undefined) return await runClientProfileCell(cell);
  const id = `${cell.client}/${cell.server}/${cell.carrier}`;
  const expectedCases = [...commonCases, ...(datagramCarriers.has(cell.carrier) ? ["datagram"] : [])];
  const serverPeer = startPeer(cell.server, ["server", "--carrier", cell.carrier]);
  let clientPeer, failure;
  const deadline = parityProcessDeadline(() => [serverPeer, clientPeer], cellTimeoutMS, `${id}: cell deadline exceeded`);
  try {
    const ready = await deadline.wait(nextPeerJSON(serverPeer, `${id} server protocol`));
    assertMessage(ready, "ready", id);
    if (ready.runtime !== cell.server || ready.carrier !== cell.carrier || ready.path !== "direct") {
      throw new Error(`${id}: server ready dimensions do not match the requested cell`);
    }
    assertCurrentMaterial(ready.artifact_json, id, ready);

    clientPeer = startPeer(cell.client, ["client", "--carrier", cell.carrier]);
    clientPeer.child.stdin.end(`${JSON.stringify(ready)}\n`);
    const clientResult = await deadline.wait(nextPeerJSON(clientPeer, `${id} client protocol`));
    assertResult(clientResult, "client-result", cell.client, cell.carrier, expectedCases, id);
    assertNoSyntheticCleanupCounters(clientResult, id);
    await deadline.wait(requireSuccessfulExit(clientPeer, `${id} client`));

    const serverResult = await deadline.wait(nextPeerJSON(serverPeer, `${id} server protocol`));
    assertResult(serverResult, "server-result", cell.server, cell.carrier, expectedCases, id);
    assertNoSyntheticCleanupCounters(serverResult, id);
    await deadline.wait(requireSuccessfulExit(serverPeer, `${id} server`));
  } catch (error) {
    await deadline.stop();
    const diagnostics = [serverPeer, clientPeer]
      .filter(Boolean)
      .map((peer) => peer.stderr.text())
      .filter((value) => value.length > 0)
      .join("\n");
    failure = new Error(`${id}: ${error instanceof Error ? error.message : String(error)}${diagnostics === "" ? "" : `\n${diagnostics}`}`, { cause: error });
  } finally {
    await deadline.finish(failure);
  }
}

function selectClientProfileCell() {
  if (!['swift', 'browser'].includes(clientProfile) || clientProfileTestID === undefined) {
    throw new Error("FLOWERSEC_PARITY_CLIENT_PROFILE and FLOWERSEC_PARITY_TEST_ID must select a supported client-profile cell");
  }
  const cells = [
    { profile: "browser", client: "typescript-browser", server: "go", carrier: "websocket", path: "direct", test_id: "interop/browser-go/wss/direct" },
    { profile: "swift", client: "swift", server: "go", carrier: "websocket", path: "direct", test_id: "interop/swift-go/wss/direct" },
  ].filter((cell) => cell.profile === clientProfile && cell.test_id === clientProfileTestID);
  if (cells.length !== 1) throw new Error(`${clientProfileTestID}: client-profile direct cell is absent or ambiguous`);
  return cells[0];
}

async function runClientProfileCell(cell) {
  const id = cell.test_id;
  const browserPort = clientProfile === "browser" ? await reserveLoopbackPort() : undefined;
  const origin = browserPort === undefined ? "https://client.example" : `http://127.0.0.1:${browserPort}`;
  const browserInstallation = clientProfile === "browser" ? await prepareBrowserParityInstallation(repositoryRoot, id) : undefined;
  const serverPeer = startPeer(cell.server, ["server", "--carrier", "websocket"], {
    ...browserInstallation?.environment,
    FLOWERSEC_PARITY_CLIENT_PROFILE: clientProfile,
    FLOWERSEC_PARITY_ORIGIN: origin,
  });
  let externalClient;
  let failure;
  const deadline = parityProcessDeadline(() => [serverPeer, externalClient], cellTimeoutMS, `${id}: cell deadline exceeded`);
  try {
    const ready = await deadline.wait(nextPeerJSON(serverPeer, `${id} server protocol`));
    assertMessage(ready, "ready", id);
    if (ready.runtime !== cell.server || ready.carrier !== "websocket" || ready.path !== "direct" || ready.origin !== origin) {
      throw new Error(`${id}: server ready dimensions do not match the client-profile cell`);
    }
    assertCurrentMaterial(ready.artifact_json, id, ready);
    externalClient = startExternalClient(ready, "direct", browserPort, browserInstallation);
    await deadline.wait(requireSuccessfulExit(externalClient, `${id} ${clientProfile} client`));
    const serverResult = await deadline.wait(nextPeerJSON(serverPeer, `${id} server protocol`));
    assertResult(serverResult, "server-result", cell.server, "websocket", commonCases, id);
    await deadline.wait(requireSuccessfulExit(serverPeer, `${id} server`));
  } catch (error) {
    await deadline.stop();
    const diagnostics = [serverPeer, externalClient].filter(Boolean).map((peer) => peer.stderr.text()).filter(Boolean).join("\n");
    failure = new Error(`${id}: ${error instanceof Error ? error.message : String(error)}${diagnostics === "" ? "" : `\n${diagnostics}`}`, { cause: error });
  } finally {
    await deadline.finish(failure, () => browserInstallation?.cleanup(failure));
  }
}

function startExternalClient(ready, pathKind, browserPort, browserInstallation) {
  const encoded = Buffer.from(JSON.stringify(ready)).toString("base64");
  if (clientProfile === "swift") {
    return startProcess("swift", ["test", "--skip-build", "--cache-path", ".flowersec/swiftpm-cache", "--skip-update", "--only-use-versions-from-resolved-file", "--filter", "ServerParityTests/testClientProfile"], repositoryRoot, {
      FLOWERSEC_PARITY_READY_BASE64: encoded,
      FLOWERSEC_PARITY_PATH: pathKind,
    });
  }
  return startProcess("npm", ["--prefix", "flowersec-ts", "run", "test:browser:chromium", "--", "--grep", "Chromium runs the current WebSocket client profile"], repositoryRoot, {
    FLOWERSEC_PARITY_READY_BASE64: encoded,
    FLOWERSEC_PARITY_PATH: pathKind,
    FLOWERSEC_BROWSER_SITE_PORT: String(browserPort),
    ...browserInstallation?.environment,
  });
}

async function reserveLoopbackPort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => server.once("error", reject).listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("failed to reserve browser site port");
  await new Promise((resolve, reject) => server.close((error) => error === undefined ? resolve() : reject(error)));
  return address.port;
}

function startPeer(runtime, roleArguments, environment = {}) {
  const peer = peers[runtime];
  const coveragePrefix = runtime === "rust" && rustCoverageEnvironment !== undefined ? `direct-${randomUUID()}-` : undefined;
  const profileDirectory = coveragePrefix === undefined ? undefined : path.dirname(rustCoverageEnvironment.LLVM_PROFILE_FILE);
  const profileEnvironment = coveragePrefix === undefined ? {} : {
    LLVM_PROFILE_FILE: path.join(profileDirectory, `${coveragePrefix}%p-%m.profraw`),
  };
  const child = spawn(peer.command, [...peer.arguments, ...roleArguments], {
    cwd: peer.cwd,
    detached: process.platform !== "win32",
    env: { ...process.env, ...nativeAddon.environment, ...environment, ...(runtime === "rust" ? rustEnvironment : {}), ...profileEnvironment, FLOWERSEC_SERVER_PARITY_PEER: "1", FLOWERSEC_PARITY_TEST_ONLY: "1" },
    stdio: ["pipe", "pipe", "pipe"],
  });
  const observation = observeProcess(child);
  if (coveragePrefix !== undefined) {
    observation.completion = observation.completion.then(async exit => {
      if (exit.code !== 0 || exit.error !== undefined) return exit;
      try {
        const files = (await readdir(profileDirectory)).filter(name => name.startsWith(coveragePrefix) && name.endsWith(".profraw"));
        const sizes = await Promise.all(files.map(name => stat(path.join(profileDirectory, name))));
        if (sizes.length !== 1 || !sizes[0].isFile() || sizes[0].size === 0) {
          throw new Error(`Rust ${roleArguments[0]} exited without its fresh nonempty coverage profile`);
        }
        return exit;
      } catch (error) { return { ...exit, error }; }
    });
  }
  const stderr = collectText(child.stderr);
  return { child, ...observation, stderr, stdout: jsonLines(child.stdout), kill(signal) { if (!observation.isComplete()) signalParityProcess(child, signal); } };
}

function readRustCoverageEnvironment() {
  const raw = process.env.FLOWERSEC_PARITY_RUST_COVERAGE_ENV;
  if (raw === undefined) return undefined;
  const environment = JSON.parse(raw);
  if (environment === null || typeof environment !== "object" || Array.isArray(environment)
      || Object.values(environment).some(value => typeof value !== "string")
      || !path.isAbsolute(environment.CARGO_TARGET_DIR ?? "")
      || !path.isAbsolute(environment.LLVM_PROFILE_FILE ?? "")
      || !(environment.__CARGO_LLVM_COV_RUSTC_WRAPPER_RUSTFLAGS ?? "").includes("instrument-coverage")
      || typeof environment.RUSTC_WRAPPER !== "string" || environment.RUSTC_WRAPPER.length === 0) {
    throw new Error("Rust parity coverage requires the instrumented show-env environment and absolute target/profile paths");
  }
  return environment;
}
function startProcess(command, arguments_, cwd, environment) {
  const child = spawn(command, arguments_, { cwd, detached: process.platform !== "win32", env: { ...process.env, ...environment }, stdio: ["ignore", "pipe", "pipe"] });
  const observation = observeProcess(child);
  const stdout = collectText(child.stdout);
  const stderr = collectText(child.stderr);
  return { child, ...observation, stderr: { text: () => `${stdout.text()}\n${stderr.text()}` }, kill(signal) { if (!observation.isComplete()) signalParityProcess(child, signal); } };
}
function observeProcess(child) {
  let failure, complete = false;
  child.on("error", error => { failure ??= error; });
  for (const stream of [child.stdin, child.stdout, child.stderr]) stream?.on("error", error => { failure ??= error; });
  const completion = new Promise(resolve => child.once("close", (code, signal) => { complete = true; resolve({ code, signal, error: failure }); }));
  return { completion, isComplete: () => complete };
}

function assertMessage(message, type, cellID) {
  if (message === null || typeof message !== "object" || message.type !== type) {
    throw new Error(`${cellID}: expected ${type} peer message`);
  }
  assertCurrentPeer(message, cellID);
}

function assertResult(message, type, runtime, carrier, expectedCases, cellID) {
  assertMessage(message, type, cellID);
  if (message.runtime !== runtime || message.carrier !== carrier || message.path !== "direct") {
    throw new Error(`${cellID}: ${type} dimensions do not match the requested cell`);
  }
  if (!Array.isArray(message.cases) || message.cases.length !== expectedCases.length ||
      !expectedCases.every((caseID) => message.cases.includes(caseID))) {
    throw new Error(`${cellID}: ${type} did not prove every required semantic case (got=${JSON.stringify(message.cases)} expected=${JSON.stringify(expectedCases)})`);
  }
}

function assertNoSyntheticCleanupCounters(message, cellID) {
  for (const field of ["active_sessions", "active_streams"]) {
    if (Object.hasOwn(message, field)) throw new Error(`${cellID}: peer reported unverifiable cleanup field ${field}`);
  }
}

async function requireSuccessfulExit(peer, label) {
  const exit = await peer.completion;
  if (exit.error !== undefined) throw new Error(`${label} failed: ${exit.error.message}`);
  if (exit.code !== 0) throw new Error(`${label} exited with code=${exit.code} signal=${exit.signal}`);
}
async function nextPeerJSON(peer, label) {
  try {
    return await Promise.race([
      peer.stdout.nextJSON(),
      peer.completion.then(exit => { throw new Error(exit.error === undefined
        ? `peer closed before its next protocol message: code=${exit.code} signal=${exit.signal}`
        : `peer failed before its next protocol message: ${exit.error.message}`); }),
    ]);
  } catch (error) {
    const diagnostic = peer.stderr.text();
    throw new Error(`${label}: ${error instanceof Error ? error.message : String(error)}${diagnostic === "" ? "" : `; stderr=${diagnostic}`}`);
  }
}

function collectText(stream) {
  let value = "";
  stream.setEncoding("utf8");
  stream.on("data", (chunk) => { value = `${value}${chunk}`.slice(-65_536); });
  return { text: () => value.trim() };
}

function jsonLines(stream) {
  stream.setEncoding("utf8");
  const maximumLineBytes = 16_777_216, maximumQueuedMessages = 4;
  let buffered = "", bufferedBytes = 0, ended = false, failure;
  const queued = [], waiters = [];
  function fail(error) {
    if (failure !== undefined) return;
    failure = error; buffered = ""; bufferedBytes = 0; queued.length = 0;
    for (const waiter of waiters.splice(0)) waiter.reject(error);
    stream.destroy();
  }
  stream.on("data", chunk => {
    if (failure !== undefined) return;
    bufferedBytes += Buffer.byteLength(chunk);
    buffered += chunk;
    while (true) {
      const newline = buffered.indexOf("\n"); if (newline < 0) break;
      const raw = buffered.slice(0, newline + 1), rawBytes = Buffer.byteLength(raw), line = raw.trim();
      if (rawBytes > maximumLineBytes) { fail(new Error("peer JSON output exceeds its input bound")); return; }
      buffered = buffered.slice(newline + 1); bufferedBytes -= rawBytes;
      if (line === "") continue;
      try {
        const value = JSON.parse(line);
        if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("peer JSON output must be an object");
        const waiter = waiters.shift();
        if (waiter !== undefined) waiter.resolve(value);
        else { if (queued.length >= maximumQueuedMessages) throw new Error("peer JSON output exceeds its message queue bound"); queued.push(value); }
      } catch { fail(new Error("peer emitted invalid or excessive protocol JSON")); return; }
    }
    if (bufferedBytes > maximumLineBytes) fail(new Error("peer JSON output exceeds its input bound"));
  });
  stream.on("error", fail);
  stream.on("end", () => {
    ended = true;
    if (buffered.trim() !== "") { fail(new Error("peer stdout ended during a protocol message")); return; }
    buffered = ""; bufferedBytes = 0;
    for (const waiter of waiters.splice(0)) waiter.reject(new Error("peer stdout ended before the next protocol message"));
  });
  return {
    async nextJSON() {
      if (failure !== undefined) throw failure;
      if (queued.length > 0) return queued.shift();
      if (ended) throw new Error("peer stdout ended before the next protocol message");
      return await new Promise((resolve, reject) => waiters.push({ resolve, reject }));
    },
  };
}
