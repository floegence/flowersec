import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

import {
  generateTunnelTopologyDimensions,
  SERVER_PARITY_CARRIERS,
  SERVER_PARITY_RUNTIMES,
} from "./server-parity-matrix.mjs";
import { prepareServerParityNativeAddon } from "./server-parity-native-addon.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const matrix = JSON.parse(await readFile(path.join(repositoryRoot, "stability/interop_matrix.json"), "utf8"));
const runtimes = SERVER_PARITY_RUNTIMES;
const carriers = SERVER_PARITY_CARRIERS;
const endpointAs = selectedValues("FLOWERSEC_PARITY_ENDPOINT_AS", runtimes);
const endpointBs = selectedValues("FLOWERSEC_PARITY_ENDPOINT_BS", runtimes);
const relayRuntimes = selectedValues("FLOWERSEC_PARITY_RELAYS", runtimes);
const selectedCarriers = selectedValues("FLOWERSEC_PARITY_CARRIERS", carriers);
const endpointCases = ["rpc", "notification", "stream-metadata", "stream-fin", "stream-reset", "rekey", "liveness", "close", "cancel", "cleanup"];
const relayCases = ["admission", "pairing", "opaque-forwarding", "close", "cancel", "cleanup"];
const datagramCarriers = new Set(["raw-quic"]);
const forbiddenRelayKeys = /(?:artifact|session|psk|secret|handler)/i;
const cellTimeoutMS = 60_000;

const peers = {
  go: { cwd: path.join(repositoryRoot, "flowersec-go"), command: "go", arguments: ["run", "./internal/cmd/server-parity-peer"] },
  rust: { cwd: repositoryRoot, command: "rustup", arguments: ["run", "1.88.0", "cargo", "run", "--quiet", "--manifest-path", "flowersec-rust/Cargo.toml", "--example", "server_parity_peer", "--"] },
  "node-typescript": { cwd: path.join(repositoryRoot, "flowersec-ts"), command: process.execPath, arguments: ["--import", "tsx", "src/interop/serverParityPeer.ts"] },
};

validateTopologyContract(matrix.tunnel_topologies);
const selectedTopologies = matrix.tunnel_topologies.filter((topology) => endpointAs.includes(topology.endpoint_a) && endpointBs.includes(topology.endpoint_b) && relayRuntimes.includes(topology.tunnel_runtime) && selectedCarriers.includes(topology.ingress_carrier_a));
const nativeAddon = await prepareServerParityNativeAddon(repositoryRoot, selectedTopologies.some((topology) =>
  topology.ingress_carrier_a === "raw-quic" && [topology.endpoint_a, topology.endpoint_b, topology.tunnel_runtime].includes("node-typescript")
));
try {
  for (const topology of selectedTopologies) await runTopology(topology);
  if (selectedTopologies.length === 0) console.log("server parity tunnel matrix: no topologies selected by the requested filters");
  else console.log(`server parity tunnel matrix OK: ${selectedTopologies.length} supported production topologies`);
} finally {
  await nativeAddon.cleanup();
}

function selectedValues(environmentName, allowed) {
  const raw = process.env[environmentName]?.trim();
  if (raw === undefined || raw === "") return allowed;
  const selected = [...new Set(raw.split(",").map((value) => value.trim()).filter(Boolean))];
  if (selected.length === 0 || selected.some((value) => !allowed.includes(value))) throw new Error(`${environmentName} contains an unsupported matrix value`);
  return selected;
}

async function runTopology(topology) {
  const id = topology.id;
  const carrierA = topology.ingress_carrier_a;
  const carrierB = topology.ingress_carrier_b;
  const relay = startPeer(topology.tunnel_runtime, ["relay", "--carrier", carrierA]);
  let endpointA;
  let endpointB;
  const timer = setTimeout(() => [relay, endpointA, endpointB].filter(Boolean).forEach((peer) => peer.kill("SIGKILL")), cellTimeoutMS);
  try {
    const relayReady = await nextPeerJSON(relay, `${id} relay ready`);
    assertDimensions(relayReady, "relay-ready", topology.tunnel_runtime, carrierA, id);
    assertNoRelaySessionMaterial(relayReady, id);

    endpointB = startPeer(topology.endpoint_b, ["tunnel-endpoint-b", "--carrier", carrierB]);
    endpointB.child.stdin.write(`${JSON.stringify({ topology, relay: relayReady })}\n`);
    const endpointBReady = await nextPeerJSON(endpointB, `${id} endpoint B ready`);
    assertDimensions(endpointBReady, "endpoint-b-ready", topology.endpoint_b, carrierB, id);
    if (typeof endpointBReady.endpoint_a_artifact_json !== "string" || endpointBReady.endpoint_a_artifact_json.length === 0) {
      throw new Error(`${id}: endpoint B did not issue endpoint A's opaque artifact`);
    }
    if (!Array.isArray(endpointBReady.authorizations) || endpointBReady.authorizations.length !== 2) {
      throw new Error(`${id}: endpoint B did not publish two secret-free relay authorizations`);
    }
    relay.child.stdin.write(`${JSON.stringify({ type: "configure", authorizations: endpointBReady.authorizations })}\n`);

    endpointA = startPeer(topology.endpoint_a, ["tunnel-endpoint-a", "--carrier", carrierA]);
    endpointA.child.stdin.end(`${JSON.stringify({ topology, endpoint_b: endpointBReady })}\n`);
    endpointB.child.stdin.end(`${JSON.stringify({ type: "connect" })}\n`);

    const endpointAResult = await nextPeerJSON(endpointA, `${id} endpoint A result`);
    assertResult(endpointAResult, "endpoint-a-result", topology.endpoint_a, carrierA, endpointExpectedCases(carrierA), `${id} endpoint A`);
    assertNoSyntheticCleanupCounters(endpointAResult, id);
    await requireSuccessfulExit(endpointA, `${id} endpoint A`);
    const endpointBResult = await nextPeerJSON(endpointB, `${id} endpoint B result`);
    assertResult(endpointBResult, "endpoint-b-result", topology.endpoint_b, carrierB, endpointExpectedCases(carrierB), `${id} endpoint B`);
    assertNoSyntheticCleanupCounters(endpointBResult, id);
    await requireSuccessfulExit(endpointB, `${id} endpoint B`);

    relay.child.stdin.end(`${JSON.stringify({ type: "close" })}\n`);
    const relayResult = await nextPeerJSON(relay, `${id} relay result`);
    assertDimensions(relayResult, "relay-result", topology.tunnel_runtime, carrierA, id);
    assertCases(relayResult, relayExpectedCases(carrierA), `${id} relay`);
    assertNoRelaySessionMaterial(relayResult, id);
    assertNoSyntheticCleanupCounters(relayResult, id);
    if (relayResult.observed_plaintext !== false) throw new Error(`${id}: relay observed application plaintext`);
    if (relayResult.released_leases !== endpointBReady.authorizations.length) throw new Error(`${id}: relay released ${relayResult.released_leases}, want exactly ${endpointBReady.authorizations.length}`);
    await requireSuccessfulExit(relay, `${id} relay`);
  } catch (error) {
    [relay, endpointA, endpointB].filter(Boolean).forEach((peer) => peer.kill("SIGKILL"));
    const diagnostics = [relay, endpointA, endpointB].filter(Boolean).map((peer) => peer.stderr.text()).filter(Boolean).join("\n");
    throw new Error(`${id}: ${error instanceof Error ? error.message : String(error)}${diagnostics === "" ? "" : `\n${diagnostics}`}`);
  } finally {
    clearTimeout(timer);
  }
}

async function nextPeerJSON(peer, label) {
  try {
    return await peer.stdout.nextJSON();
  } catch (error) {
    const diagnostic = peer.stderr.text();
    throw new Error(`${label}: ${error instanceof Error ? error.message : String(error)}${diagnostic === "" ? "" : `; stderr=${diagnostic}`}`);
  }
}

function validateTopologyContract(topologies) {
  const generated = generateTunnelTopologyDimensions();
  if (!Array.isArray(topologies) || topologies.length !== generated.length) throw new Error(`tunnel matrix must contain exactly ${generated.length} generated topologies`);
  const generatedByID = new Map(generated.map((topology) => [topology.id, topology]));
  for (const topology of topologies) {
    if (!runtimes.includes(topology.endpoint_a) || !runtimes.includes(topology.endpoint_b) || !runtimes.includes(topology.tunnel_runtime)) throw new Error(`${topology.id}: unknown runtime`);
    if (!carriers.includes(topology.ingress_carrier_a) || topology.ingress_carrier_a !== topology.ingress_carrier_b) throw new Error(`${topology.id}: mixed or unknown ingress carrier`);
    const expectedCases = ["admission", ...endpointCases, "pairing", "opaque-forwarding", ...(datagramCarriers.has(topology.ingress_carrier_a) ? ["datagram", "datagram-forwarding"] : [])];
    if (!sameValues(topology.cases, expectedCases)) throw new Error(`${topology.id}: cases do not match the executable tunnel contract`);
    if (topology.status === "supported") {
      if (!Array.isArray(topology.test_ids) || topology.test_ids.length !== 1 || "reason" in topology) throw new Error(`${topology.id}: supported topology must bind exactly one test ID and no reason`);
    } else if (topology.status === "unsupported") {
      if ((Array.isArray(topology.test_ids) && topology.test_ids.length !== 0) || typeof topology.reason !== "string" || topology.reason.length === 0) throw new Error(`${topology.id}: unsupported topology must carry only a reason`);
      throw new Error(`${topology.id}: required tunnel topology cannot be unsupported`);
    } else {
      throw new Error(`${topology.id}: forbidden status ${String(topology.status)}`);
    }
    const expected = generatedByID.get(topology.id);
    if (expected === undefined || !Object.entries(expected).every(([key, value]) => topology[key] === value)) {
      throw new Error(`${topology.id}: topology does not match the generated pairwise covering set`);
    }
    generatedByID.delete(topology.id);
  }
  if (generatedByID.size !== 0) throw new Error(`tunnel matrix misses generated topology ${generatedByID.keys().next().value}`);
}

function sameValues(actual, expected) {
  return Array.isArray(actual) && actual.length === expected.length && expected.every((value, index) => actual[index] === value);
}

function endpointExpectedCases(carrier) { return ["admission", ...endpointCases, ...(datagramCarriers.has(carrier) ? ["datagram"] : [])]; }
function relayExpectedCases(carrier) { return [...relayCases, ...(datagramCarriers.has(carrier) ? ["datagram-forwarding"] : [])]; }

function assertDimensions(message, type, runtime, carrier, id) {
  if (message === null || typeof message !== "object" || message.type !== type || message.runtime !== runtime || message.carrier !== carrier || message.path !== "tunnel") {
    throw new Error(`${id}: invalid ${type} dimensions`);
  }
}
function assertResult(message, type, runtime, carrier, cases, id) {
  assertDimensions(message, type, runtime, carrier, id);
  assertCases(message, cases, id);
}
function assertCases(message, expected, id) {
  if (!Array.isArray(message.cases) || message.cases.length !== expected.length || !expected.every((value) => message.cases.includes(value))) {
    throw new Error(`${id}: peer did not prove every required case; actual=${JSON.stringify(message.cases ?? null)} expected=${JSON.stringify(expected)}`);
  }
}
function assertNoSyntheticCleanupCounters(message, id) {
  for (const field of ["active_pairs", "active_legs", "active_sessions", "active_streams", "application_handlers"]) {
    if (Object.hasOwn(message, field)) throw new Error(`${id}: peer reported unverifiable cleanup field ${field}`);
  }
}
function assertNoRelaySessionMaterial(value, id, allowedKeys = new Set()) {
  if (value === null || typeof value !== "object") return;
  for (const [key, nested] of Object.entries(value)) {
    if (forbiddenRelayKeys.test(key) && !allowedKeys.has(key)) throw new Error(`${id}: relay exposed forbidden field ${key}`);
    assertNoRelaySessionMaterial(nested, id, allowedKeys);
  }
}

function startPeer(runtime, roleArguments) {
  const peer = peers[runtime];
  const child = spawn(peer.command, [...peer.arguments, ...roleArguments], { cwd: peer.cwd, env: { ...process.env, ...nativeAddon.environment, FLOWERSEC_SERVER_PARITY_PEER: "1" }, stdio: ["pipe", "pipe", "pipe"] });
  const stderr = collectText(child.stderr);
  return { child, stderr, stdout: jsonLines(child.stdout), kill(signal) { if (child.exitCode === null && child.signalCode === null) child.kill(signal); } };
}
async function requireSuccessfulExit(peer, label) {
  const exit = await new Promise((resolve) => peer.child.exitCode !== null ? resolve({ code: peer.child.exitCode, signal: peer.child.signalCode }) : peer.child.once("exit", (code, signal) => resolve({ code, signal })));
  if (exit.code !== 0) throw new Error(`${label} exited with code=${exit.code} signal=${exit.signal}`);
}
function collectText(stream) {
  let value = "";
  stream.setEncoding("utf8");
  stream.on("data", (chunk) => { value = `${value}${chunk}`.slice(-65_536); });
  return { text: () => value.trim() };
}
function jsonLines(stream) {
  stream.setEncoding("utf8");
  let buffered = "";
  const queued = [];
  const waiters = [];
  let ended = false;
  stream.on("data", (chunk) => {
    buffered += chunk;
    while (true) {
      const newline = buffered.indexOf("\n");
      if (newline < 0) break;
      const line = buffered.slice(0, newline).trim();
      buffered = buffered.slice(newline + 1);
      if (line !== "") deliver(JSON.parse(line));
    }
  });
  stream.on("end", () => { ended = true; for (const waiter of waiters.splice(0)) waiter.reject(new Error("peer stdout ended before the next protocol message")); });
  function deliver(value) { const waiter = waiters.shift(); if (waiter === undefined) queued.push(value); else waiter.resolve(value); }
  return { async nextJSON() { if (queued.length > 0) return queued.shift(); if (ended) throw new Error("peer stdout ended before the next protocol message"); return await new Promise((resolve, reject) => waiters.push({ resolve, reject })); } };
}
