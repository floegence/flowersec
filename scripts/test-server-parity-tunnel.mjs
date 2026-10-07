import { spawn } from "node:child_process";
import { isDeepStrictEqual } from "node:util";
import { mkdir, open, readFile, readdir, realpath, rm, stat, writeFile } from "node:fs/promises";
import { createHash, randomUUID } from "node:crypto";
import os from "node:os";
import { fileURLToPath } from "node:url";
import net from "node:net";
import path from "node:path";

import {
  generateTunnelTopologyDimensions,
  executableTunnelTopologies,
  SERVER_PARITY_CARRIERS,
  SERVER_PARITY_RUNTIMES,
} from "./server-parity-matrix.mjs";
import { prepareBrowserParityInstallation, signalParityProcess, parityProcessDeadline, cleanupParityArtifact } from "./server-parity-browser-installation.mjs";
import { prepareServerParityNativeAddon, prepareServerParityRustPeer, prepareServerParitySwiftClient, resolveRustTargetDirectory } from "./server-parity-native-addon.mjs";
import { readToolchains } from "./toolchains.mjs";
import { assertCurrentPeer, assertTunnelPublication, assertEndpointTunnelPublication, assertRoleBoundLiveTunnelPublication, assertNoSyntheticCleanupCounters } from "./server-parity-material.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const toolchains = readToolchains(repositoryRoot);
const rustCoverageEnvironment = readRustCoverageEnvironment();
const rustEnvironment = rustCoverageEnvironment === undefined ? {} : { ...rustCoverageEnvironment, FLOWERSEC_PARITY_RUST_PEER_READY: "1" };
const rustTargetDirectory = resolveRustTargetDirectory(repositoryRoot, { ...process.env, ...rustEnvironment });
// Both preparations run from repositoryRoot, including Cargo's relative target paths.
if (rustCoverageEnvironment !== undefined) rustEnvironment.CARGO_TARGET_DIR = rustTargetDirectory;
const matrix = JSON.parse(await readFile(path.join(repositoryRoot, "stability/interop_matrix.json"), "utf8"));
const clientProfile = process.env.FLOWERSEC_PARITY_CLIENT_PROFILE?.trim() || undefined;
const clientProfileTestID = process.env.FLOWERSEC_PARITY_TEST_ID?.trim();
const activationSource = process.env.FLOWERSEC_PARITY_ACTIVATION_SOURCE?.trim() || "preauthorized_pool";
if (!["preauthorized_pool", "live_authority"].includes(activationSource)) {
  throw new Error("FLOWERSEC_PARITY_ACTIVATION_SOURCE must be preauthorized_pool or live_authority");
}
const registeredPool = process.env.FLOWERSEC_PARITY_REGISTERED_POOL?.trim();
if (registeredPool !== undefined && (registeredPool !== "1" || activationSource !== "preauthorized_pool")) {
  throw new Error("FLOWERSEC_PARITY_REGISTERED_POOL requires 1 and the preauthorized_pool source");
}
const runtimes = SERVER_PARITY_RUNTIMES;
const carriers = SERVER_PARITY_CARRIERS;
const endpointAs = selectedValues("FLOWERSEC_PARITY_ENDPOINT_AS", runtimes);
const endpointBs = selectedValues("FLOWERSEC_PARITY_ENDPOINT_BS", runtimes);
const relayRuntimes = selectedValues("FLOWERSEC_PARITY_RELAYS", runtimes);
const selectedCarriers = selectedValues("FLOWERSEC_PARITY_CARRIERS", carriers);
const clientCarriers = selectedValues("FLOWERSEC_PARITY_CLIENT_CARRIERS", selectedCarriers);
const serverCarriers = selectedValues("FLOWERSEC_PARITY_SERVER_CARRIERS", selectedCarriers);
const clientListener = selectedListener("FLOWERSEC_PARITY_CLIENT_LISTENER", "relay");
const serverListener = selectedListener("FLOWERSEC_PARITY_SERVER_LISTENER", "endpoint");
const endpointCases = ["rpc", "notification", "stream-metadata", "stream-fin", "stream-reset", "rekey", "liveness", "close", "cancel", "cleanup"];
const relayCases = ["admission", "pairing", "opaque-forwarding", "close", "cancel", "cleanup"];
const datagramCarriers = new Set(["raw-quic"]);
const hopCapacityProbe = process.env.FLOWERSEC_PARITY_HOP_CAPACITY_PROBE?.trim();
const cellTimeoutMS = hopCapacityProbe === "insufficient" ? 180_000 : 60_000;

const peers = {
  go: { cwd: path.join(repositoryRoot, "flowersec-go"), command: "go", arguments: ["run", "./internal/cmd/server-parity-peer"] },
  rust: { cwd: repositoryRoot, command: path.join(rustTargetDirectory, "debug/examples", process.platform === "win32" ? "server_parity_peer.exe" : "server_parity_peer"), arguments: [] },
  "node-typescript": { cwd: path.join(repositoryRoot, "flowersec-ts"), command: process.execPath, arguments: ["--import", "tsx", "src/interop/serverParityPeer.ts"] },
};
const tunnelTopologies = executableTunnelTopologies(matrix.tunnel_topologies);
validateTopologyContract(tunnelTopologies);
const selectedTopologies = clientProfile === undefined
  ? tunnelTopologies.filter((topology) => topology.status === "supported" && endpointAs.includes(topology.endpoint_a) && endpointBs.includes(topology.endpoint_b) && relayRuntimes.includes(topology.tunnel_runtime) && clientCarriers.includes(topology.ingress_carrier_a) && serverCarriers.includes(topology.ingress_carrier_b))
  : selectClientProfileTopology();
if (clientProfile === undefined && selectedTopologies.length === 0) {
  throw new Error("server parity tunnel matrix selected no supported current topologies");
}
const usesRegisteredLive = activationSource === "live_authority" || Boolean(process.env.FLOWERSEC_PARITY_CURRENT_V4_DEPLOYMENT);
if (usesRegisteredLive && selectedTopologies.some(topology => topology.tunnel_runtime !== "rust")) {
  throw new Error("registered live selection requires the independently staged Rust relay for every selected topology");
}
const nativeAddonRequired = selectedTopologies.some(topology =>
  [topology.endpoint_a, topology.endpoint_b, topology.tunnel_runtime].includes("node-typescript"));
let nativeAddon, processFailure;
try {
  await prepareServerParitySwiftClient(repositoryRoot, clientProfile === "swift" && !usesRegisteredLive);
  await prepareServerParityRustPeer(repositoryRoot, !usesRegisteredLive && selectedTopologies.some(topology =>
    [topology.endpoint_a, topology.endpoint_b, topology.tunnel_runtime].includes("rust")), { environment: rustEnvironment });
  nativeAddon = usesRegisteredLive ? await prepareRegisteredLivePeers()
    : await prepareServerParityNativeAddon(repositoryRoot, nativeAddonRequired);
  if (hopCapacityProbe !== undefined && hopCapacityProbe !== "insufficient") {
    throw new Error("FLOWERSEC_PARITY_HOP_CAPACITY_PROBE must be insufficient");
  }
  if (hopCapacityProbe !== undefined) {
    const probes = selectedTopologies.filter((topology) =>
      topology.endpoint_a === "rust" && topology.endpoint_b === "rust" && topology.tunnel_runtime === "go"
      && topology.ingress_carrier_a === "raw-quic" && topology.ingress_carrier_b === "raw-quic");
    if (probes.length !== 1) {
      throw new Error("HOP capacity probe requires exactly one Rust/Go/Rust raw QUIC topology");
    }
    await runHopCapacityProbe(probes[0]);
    console.log("server parity Rust HOP capacity probe OK");
  } else {
    for (const topology of selectedTopologies) await runTopology(topology);
    console.log(`server parity tunnel matrix OK: ${selectedTopologies.length} supported production topologies`);
  }
} catch (error) {
  processFailure = error; throw error;
} finally {
  await cleanupParityArtifact(processFailure, () => nativeAddon?.cleanup());
}

function selectedValues(environmentName, allowed) {
  const raw = process.env[environmentName]?.trim();
  if (raw === undefined || raw === "") return allowed;
  const selected = [...new Set(raw.split(",").map((value) => value.trim()).filter(Boolean))];
  if (selected.length === 0 || selected.some((value) => !allowed.includes(value))) throw new Error(`${environmentName} contains an unsupported matrix value`);
  return selected;
}

function selectedListener(environmentName, fallback) {
  const value = process.env[environmentName]?.trim();
  if (value === undefined || value === "") return fallback;
  if (value !== "endpoint" && value !== "relay") throw new Error(`${environmentName} must be endpoint or relay`);
  return value;
}

function requiresRegisteredPool(topology) {
  return registeredPool === "1" || topology.tunnel_runtime === "node-typescript" || topology.endpoint_b === "node-typescript";
}

async function installPoolTopology(topology, id, deadline, pool) {
  pool.relayArguments = ["relay", "--carrier", topology.ingress_carrier_a, "--server-carrier", topology.ingress_carrier_b];
  if (clientListener !== "relay" || serverListener !== "endpoint") {
    pool.relayArguments.push("--client-listener", clientListener, "--server-listener", serverListener);
  }
  pool.installation = await createLiveInstallationDirectory(id);
  if (requiresRegisteredPool(topology)) {
    deadline.check();
    pool.fixture = startPeer("go", ["pool-installation", "--carrier", topology.ingress_carrier_a,
      "--server-carrier", topology.ingress_carrier_b, "--client-listener", clientListener,
      "--server-listener", serverListener, "--directory", pool.installation.directory], ownedLivePeerEnvironment());
    const installed = await deadline.wait(nextPeerJSON(pool.fixture, `${id} independent pool installation`));
    assertDimensions(installed, "pool-installation-ready", "go", topology.ingress_carrier_a, id);
    const fields = new Set(["type", "runtime", "wire_revision", "path", "source", "profile", "carrier", "server_carrier", "relay_deployment_path", "server_deployment_path", "client_deployment_path"]);
    if (Object.keys(installed).some(field => !fields.has(field)) || installed.source !== "preauthorized_pool"
        || installed.server_carrier !== topology.ingress_carrier_b
        || new Set([installed.relay_deployment_path, installed.server_deployment_path, installed.client_deployment_path]).size !== 3) {
      throw new Error(`${id}: pool provisioning did not return separate original installations`);
    }
    for (const value of [installed.relay_deployment_path, installed.server_deployment_path, installed.client_deployment_path]) {
      if (typeof value !== "string" || value.length > 4096 || !path.isAbsolute(value)
          || path.dirname(value) !== pool.installation.directory) {
        throw new Error(`${id}: pool installation path is not owned by this topology`);
      }
    }
    pool.serverDeployment = installed.server_deployment_path;
    pool.clientDeployment = installed.client_deployment_path;
    pool.relayArguments.push("--deployment", installed.relay_deployment_path);
  } else {
    pool.clientDeployment = path.join(pool.installation.directory, "pool-client-deployment.json");
  }
  pool.serverEnvironment = {
    ...ownedLivePeerEnvironment(),
    FLOWERSEC_PARITY_SERVER_CONTROL_DEPLOYMENT: pool.serverDeployment ?? "",
    FLOWERSEC_PARITY_POOL_CLIENT_DEPLOYMENT_OUTPUT: pool.serverDeployment === undefined ? pool.clientDeployment : "",
  };
}

async function runHopCapacityProbe(topology) {
  const id = `${topology.id}-hop-capacity`;
  const carrierA = topology.ingress_carrier_a;
  const carrierB = topology.ingress_carrier_b;
  const pool = {};
  let relay, endpointA, endpointB, failure;
  const processes = () => [pool.fixture, relay, endpointA, endpointB].filter(Boolean);
  const deadline = parityProcessDeadline(processes, cellTimeoutMS, `${id}: cell deadline exceeded`);
  try {
    await installPoolTopology(topology, id, deadline, pool);
    deadline.check();
    relay = startPeer(topology.tunnel_runtime, pool.relayArguments, {
      ...ownedLivePeerEnvironment(), FLOWERSEC_PARITY_HOP_CAPACITY_PROBE: "",
    });
    const serverEnvironment = { ...pool.serverEnvironment, FLOWERSEC_PARITY_HOP_CAPACITY_PROBE: "" };
    const relayReady = await deadline.wait(acquireRelayReady(relay, topology, carrierA, id, () => {
      deadline.check();
      endpointB = startPeer(topology.endpoint_b, ["tunnel-endpoint-b", "--carrier", carrierB], serverEnvironment);
    }, pool.serverDeployment));
    assertDimensions(relayReady, "relay-ready", topology.tunnel_runtime, carrierA, id);
    assertTunnelPublication(relayReady, id);
    endpointB ??= startPeer(topology.endpoint_b, ["tunnel-endpoint-b", "--carrier", carrierB], serverEnvironment);
    const endpointBPublication = relayForEndpoint(relayReady, 1, id);
    endpointB.child.stdin.write(`${JSON.stringify({ topology, relay: endpointBPublication })}\n`);
    const endpointBReady = await deadline.wait(nextPeerJSON(endpointB, `${id} endpoint B ready`));
    assertDimensions(endpointBReady, "endpoint-b-ready", topology.endpoint_b, carrierB, id);
    assertEndpointTunnelPublication(endpointBReady, endpointBPublication, id);
    await readPoolClientInstallation(pool.clientDeployment, endpointBReady.server_allow, id);
    endpointA = startPeer(topology.endpoint_a, ["tunnel-endpoint-a", "--carrier", carrierA], {
      ...ownedLivePeerEnvironment(),
      FLOWERSEC_PARITY_HOP_CAPACITY_PROBE: "insufficient", FLOWERSEC_PARITY_POOL_DEPLOYMENT: pool.clientDeployment,
    });
    endpointA.child.stdin.end(`${JSON.stringify({ topology, endpoint_b: readyForClient(endpointBReady, relayReady, id) })}\n`);
    const probe = await deadline.wait(nextPeerJSON(endpointA, `${id} endpoint A HOP capacity probe`));
    if (probe.type !== "endpoint-a-hop-capacity-probe" || probe.runtime !== "rust"
        || probe.carrier !== carrierA || probe.path !== "tunnel" || probe.wire_revision !== 4
        || probe.source !== "preauthorized_pool" || probe.spend !== "unspent"
        || probe.credential_send !== "not_started") {
      throw new Error(`${id}: invalid HOP capacity probe result ${JSON.stringify(probe)}`);
    }
    await deadline.wait(requireSuccessfulExit(endpointA, `${id} endpoint A`));
  } catch (error) {
    await deadline.stop();
    const diagnostics = processes().map((peer) => peer.stderr.text()).filter(Boolean).join("\n");
    failure = new Error(`${id}: ${error instanceof Error ? error.message : String(error)}${diagnostics === "" ? "" : `\n${diagnostics}`}`, { cause: error });
  } finally {
    await deadline.finish(failure, () => pool.installation?.cleanup(failure, processes().map(peer => peer.stderr.text()).filter(Boolean).join("\n")));
  }
}

async function runTopology(topology) {
  if (clientProfile !== undefined) return activationSource === "live_authority"
    ? await runRegisteredLiveTopology(topology) : await runClientProfileTopology(topology);
  if (topology.tunnel_runtime === "rust" && (activationSource === "live_authority" || process.env.FLOWERSEC_PARITY_CURRENT_V4_DEPLOYMENT)) {
    return await runRegisteredLiveTopology(topology);
  }
  if (activationSource === "live_authority") {
    throw new Error(`${topology.id}: this driver requires an independently staged live relay entry for ${topology.tunnel_runtime}`);
  }
  const id = topology.id;
  const carrierA = topology.ingress_carrier_a;
  const carrierB = topology.ingress_carrier_b;
  const pool = {};
  let relay, endpointA, endpointB, failure;
  const processes = () => [pool.fixture, relay, endpointA, endpointB].filter(Boolean);
  const deadline = parityProcessDeadline(processes, cellTimeoutMS, `${id}: cell deadline exceeded`);
  try {
    await installPoolTopology(topology, id, deadline, pool);
    deadline.check();
    relay = startPeer(topology.tunnel_runtime, pool.relayArguments, ownedLivePeerEnvironment());
    const serverEnvironment = pool.serverEnvironment;
    const relayReady = await deadline.wait(acquireRelayReady(relay, topology, carrierA, id, () => {
      deadline.check();
      endpointB = startPeer(topology.endpoint_b, ["tunnel-endpoint-b", "--carrier", carrierB], serverEnvironment);
    }, pool.serverDeployment));
    assertDimensions(relayReady, "relay-ready", topology.tunnel_runtime, carrierA, id);
    assertTunnelPublication(relayReady, id);

    endpointB ??= startPeer(topology.endpoint_b, ["tunnel-endpoint-b", "--carrier", carrierB], serverEnvironment);
    const endpointBPublication = relayForEndpoint(relayReady, 1, id);
    endpointB.child.stdin.write(`${JSON.stringify({ topology, relay: endpointBPublication })}\n`);
    const endpointBReady = await deadline.wait(nextPeerJSON(endpointB, `${id} endpoint B ready`));
    assertDimensions(endpointBReady, "endpoint-b-ready", topology.endpoint_b, carrierB, id);
    assertEndpointTunnelPublication(endpointBReady, endpointBPublication, id);
    await readPoolClientInstallation(pool.clientDeployment, endpointBReady.server_allow, id);
    const clientEnvironment = { ...ownedLivePeerEnvironment(), FLOWERSEC_PARITY_POOL_DEPLOYMENT: pool.clientDeployment };
    endpointA = startPeer(topology.endpoint_a, ["tunnel-endpoint-a", "--carrier", carrierA], clientEnvironment);
    endpointA.child.stdin.end(`${JSON.stringify({ topology, endpoint_b: readyForClient(endpointBReady, relayReady, id) })}\n`);
    if (clientListener === "endpoint") {
      const prepared = await deadline.wait(nextPeerJSON(endpointA, `${id} endpoint A prepared`));
      assertDimensions(prepared, "endpoint-a-prepared", topology.endpoint_a, carrierA, id);
    }
    relay.child.stdin.write(`${JSON.stringify({
      type: "configure",
      wire_revision: 4,
      route_digest: relayReady.route_digest,
      authorizations: endpointBReady.authorizations,
      verification_records: endpointBReady.verification_records,
    })}\n`);
    endpointB.child.stdin.end(`${JSON.stringify({ type: "connect" })}\n`);

    const endpointAResult = await deadline.wait(nextPeerJSON(endpointA, `${id} endpoint A result`));
    assertResult(endpointAResult, "endpoint-a-result", topology.endpoint_a, carrierA, endpointExpectedCases(carrierA, carrierB), `${id} endpoint A`);
    assertNoSyntheticCleanupCounters(endpointAResult, id);
    await deadline.wait(requireSuccessfulExit(endpointA, `${id} endpoint A`));
    const endpointBResult = await deadline.wait(nextPeerJSON(endpointB, `${id} endpoint B result`));
    assertResult(endpointBResult, "endpoint-b-result", topology.endpoint_b, carrierB, endpointExpectedCases(carrierB, carrierA), `${id} endpoint B`);
    assertNoSyntheticCleanupCounters(endpointBResult, id);
    await deadline.wait(requireSuccessfulExit(endpointB, `${id} endpoint B`));

    relay.child.stdin.end(`${JSON.stringify({ type: "close" })}\n`);
    const relayResult = await deadline.wait(nextPeerJSON(relay, `${id} relay result`));
    assertDimensions(relayResult, "relay-result", topology.tunnel_runtime, carrierA, id);
    assertCases(relayResult, relayExpectedCases(carrierA, carrierB), `${id} relay`);
    assertNoSyntheticCleanupCounters(relayResult, id);
    if (relayResult.observed_plaintext !== false) throw new Error(`${id}: relay observed application plaintext`);
    await deadline.wait(requireSuccessfulExit(relay, `${id} relay`));
    if (pool.fixture !== undefined) {
      pool.fixture.child.stdin.end(`${JSON.stringify({ type: "close" })}\n`);
      const retired = await deadline.wait(nextPeerJSON(pool.fixture, `${id} independent pool installation cleanup`));
      assertDimensions(retired, "pool-installation-result", "go", carrierA, id);
      if (retired.source !== "preauthorized_pool" || retired.server_carrier !== carrierB || retired.cleanup_complete !== true) throw new Error(`${id}: pool installation did not join its bootstrap owners`);
      await deadline.wait(requireSuccessfulExit(pool.fixture, `${id} independent pool installation`));
    }
  } catch (error) {
    await deadline.stop();
    const diagnostics = processes().map((peer) => peer.stderr.text()).filter(Boolean).join("\n");
    failure = new Error(`${id}: ${error instanceof Error ? error.message : String(error)}${diagnostics === "" ? "" : `\n${diagnostics}`}`, { cause: error });
  } finally {
    await deadline.finish(failure, () => pool.installation?.cleanup(failure, processes().map(peer => peer.stderr.text()).filter(Boolean).join("\n")));
  }
}

function selectClientProfileTopology() {
  if (!['swift', 'browser'].includes(clientProfile) || clientProfileTestID === undefined) {
    throw new Error("FLOWERSEC_PARITY_CLIENT_PROFILE and FLOWERSEC_PARITY_TEST_ID must select a supported client-profile topology");
  }
  const cells = [
    { source: "preauthorized_pool", profile: "browser", client: "typescript-browser", tunnel_runtime: "go", endpoint_b: "go", carrier: "websocket", path: "tunnel", test_id: "interop/browser-go/wss/tunnel" },
    { source: "preauthorized_pool", profile: "swift", client: "swift", tunnel_runtime: "go", endpoint_b: "go", carrier: "websocket", path: "tunnel", test_id: "interop/swift-go/wss/tunnel" },
    { source: "live_authority", profile: "swift", client: "swift", tunnel_runtime: "rust", endpoint_b: "go", carrier: "websocket", path: "tunnel", test_id: "interop/swift-rust-go/wss/live-tunnel" },
  ].filter((cell) => cell.source === activationSource && cell.profile === clientProfile && cell.test_id === clientProfileTestID);
  if (cells.length !== 1) throw new Error(`${clientProfileTestID}: client-profile tunnel cell is absent or ambiguous`);
  const cell = cells[0];
  const topologyID = `${cell.tunnel_runtime}-${cell.endpoint_b}-websocket-client-profile`;
  return [{
    id: topologyID,
    test_id: cell.test_id,
    endpoint_a: cell.client,
    endpoint_b: cell.endpoint_b,
    tunnel_runtime: cell.tunnel_runtime,
    ingress_carrier_a: "websocket",
    ingress_carrier_b: "websocket",
  }];
}

async function runClientProfileTopology(topology) {
  const id = topology.test_id;
  const browserPort = clientProfile === "browser" ? await reserveLoopbackPort() : undefined;
  const origin = browserPort === undefined ? "https://client.example" : `http://127.0.0.1:${browserPort}`;
  const browserInstallation = clientProfile === "browser" ? await prepareBrowserParityInstallation(repositoryRoot, id) : undefined;
  const environment = { ...browserInstallation?.environment, FLOWERSEC_PARITY_CLIENT_PROFILE: clientProfile, FLOWERSEC_PARITY_ORIGIN: origin };
  const relay = startPeer(topology.tunnel_runtime, ["relay", "--carrier", "websocket"], environment);
  let endpointA;
  let endpointB;
  let failure, poolInstallation;
  const deadline = parityProcessDeadline(() => [relay, endpointA, endpointB], cellTimeoutMS, `${id}: cell deadline exceeded`);
  try {
    poolInstallation = await createLiveInstallationDirectory(id);
    const clientDeployment = path.join(poolInstallation.directory, "pool-client-deployment.json");
    const serverEnvironment = { ...environment, FLOWERSEC_PARITY_POOL_CLIENT_DEPLOYMENT_OUTPUT: clientDeployment };
    const relayReady = await deadline.wait(acquireRelayReady(relay, topology, "websocket", id, () => {
      deadline.check();
      endpointB = startPeer(topology.endpoint_b, ["tunnel-endpoint-b", "--carrier", "websocket"], serverEnvironment);
    }));
    assertDimensions(relayReady, "relay-ready", topology.tunnel_runtime, "websocket", id);
    if (relayReady.origin !== origin) throw new Error(`${id}: relay did not bind the requested client origin`);
    assertTunnelPublication(relayReady, id);

    endpointB ??= startPeer(topology.endpoint_b, ["tunnel-endpoint-b", "--carrier", "websocket"], serverEnvironment);
    const endpointBPublication = relayForEndpoint(relayReady, 1, id);
    endpointB.child.stdin.write(`${JSON.stringify({ topology, relay: endpointBPublication })}\n`);
    const endpointBReady = await deadline.wait(nextPeerJSON(endpointB, `${id} endpoint B ready`));
    assertDimensions(endpointBReady, "endpoint-b-ready", topology.endpoint_b, "websocket", id);
    assertEndpointTunnelPublication(endpointBReady, endpointBPublication, id);
    const poolClient = await readPoolClientInstallation(clientDeployment, endpointBReady.server_allow, id);
    relay.child.stdin.write(`${JSON.stringify({
      type: "configure",
      wire_revision: 4,
      route_digest: relayReady.route_digest,
      authorizations: endpointBReady.authorizations,
      verification_records: endpointBReady.verification_records,
      ...(clientProfile === "browser" ? { browser_application: endpointBReady.browser_application } : {}),
    })}\n`);

    endpointB.child.stdin.end(`${JSON.stringify({ type: "connect" })}\n`);
    endpointA = startExternalClient({
      type: "ready",
      wire_revision: 4,
      profile: endpointBReady.profile,
      source: endpointBReady.source,
      runtime: topology.endpoint_b,
      carrier: "websocket",
      path: "tunnel",
      artifact_json: relayReady.endpoint_a_artifact_json,
      trust_pem: relayReady.trust_pem,
      origin,
      server_allow: endpointBReady.server_allow,
      ...(clientProfile === "browser" ? { pool_server_allow: { installation: poolClient, binding: endpointBReady.server_allow } } : {}),
    }, browserPort, browserInstallation, { FLOWERSEC_PARITY_POOL_DEPLOYMENT: clientDeployment });
    await deadline.wait(requireSuccessfulExit(endpointA, `${id} ${clientProfile} endpoint A`));

    const endpointBResult = await deadline.wait(nextPeerJSON(endpointB, `${id} endpoint B result`));
    assertResult(endpointBResult, "endpoint-b-result", topology.endpoint_b, "websocket", endpointExpectedCases("websocket"), `${id} endpoint B`);
    await deadline.wait(requireSuccessfulExit(endpointB, `${id} endpoint B`));

    relay.child.stdin.end(`${JSON.stringify({ type: "close" })}\n`);
    const relayResult = await deadline.wait(nextPeerJSON(relay, `${id} relay result`));
    assertDimensions(relayResult, "relay-result", topology.tunnel_runtime, "websocket", id);
    assertCases(relayResult, relayExpectedCases("websocket"), `${id} relay`);
    if (relayResult.observed_plaintext !== false) {
      throw new Error(`${id}: relay did not preserve opaque forwarding`);
    }
    await deadline.wait(requireSuccessfulExit(relay, `${id} relay`));
  } catch (error) {
    await deadline.stop();
    const diagnostics = [relay, endpointA, endpointB].filter(Boolean).map((peer) => peer.stderr.text()).filter(Boolean).join("\n");
    failure = new Error(`${id}: ${error instanceof Error ? error.message : String(error)}${diagnostics === "" ? "" : `\n${diagnostics}`}`, { cause: error });
  } finally {
    await deadline.finish(failure, async () => {
      await browserInstallation?.cleanup(failure);
      await poolInstallation?.cleanup(failure, [relay, endpointA, endpointB].filter(Boolean).map(peer => peer.stderr.text()).filter(Boolean).join("\n"));
    });
  }
}

function startExternalClient(ready, browserPort, browserInstallation, environment = {}) {
  const encoded = Buffer.from(JSON.stringify(ready)).toString("base64");
  if (clientProfile === "swift") {
    return startProcess("swift", ["test", "--cache-path", ".flowersec/swiftpm-cache", "--skip-update", "--only-use-versions-from-resolved-file",
      "--skip-build", "--filter", "ServerParityTests/testClientProfile"], repositoryRoot, {
      FLOWERSEC_PARITY_READY_BASE64: encoded, FLOWERSEC_PARITY_PATH: "tunnel", ...environment,
    });
  }
  return startProcess("npm", ["--prefix", "flowersec-ts", "run", "test:browser:chromium", "--", "--grep", "Chromium runs the current WebSocket client profile"], repositoryRoot, {
    FLOWERSEC_PARITY_READY_BASE64: encoded, FLOWERSEC_PARITY_PATH: "tunnel", FLOWERSEC_BROWSER_SITE_PORT: String(browserPort), ...browserInstallation?.environment, ...environment,
  });
}

async function prepareRegisteredLivePeers() {
  // Compiler work precedes original installation and security deadlines.
  // Every process below only builds the existing peer; it acquires no material.
  const plans = [
    { command: "go", args: ["build", "-o", process.platform === "win32" ? "NUL" : "/dev/null", "./internal/cmd/server-parity-peer"], cwd: peers.go.cwd },
    ...(process.env.FLOWERSEC_PARITY_RUST_PEER_READY === "1" ? [] : [{ command: "rustup", args: ["run", toolchains.rust.version, "cargo", "build", "--quiet", "--locked", "--manifest-path", "flowersec-rust/Cargo.toml", "--example", "server_parity_peer"], cwd: repositoryRoot, environment: rustEnvironment }]),
    ...(clientProfile === "swift" ? [{ command: "swift", args: ["build", "--build-tests", "--cache-path", ".flowersec/swiftpm-cache", "--skip-update", "--only-use-versions-from-resolved-file"], cwd: repositoryRoot }] : []),
  ];
  const artifacts = await createLiveInstallationDirectory("registered live peer preparation");
  const owners = [], abort = new AbortController();
  let failure, nativePreparation, preparedAddon, nativeDiagnostic = "";
  const deadline = parityProcessDeadline(() => owners, 300_000, "registered live peer preparation exceeded its 300-second bound", error => abort.abort(error));
  try {
    for (const plan of plans) owners.push(startProcess(plan.command, plan.args, plan.cwd, { ...ownedLivePeerEnvironment(), ...plan.environment }));
    nativePreparation = prepareServerParityNativeAddon(repositoryRoot, nativeAddonRequired, { signal: abort.signal })
      .then(result => { preparedAddon = result; })
      .catch(error => { nativeDiagnostic = error instanceof Error ? error.message : String(error); throw error; });
    await deadline.wait(Promise.all([
      ...owners.map((owner, index) => requireSuccessfulExit(owner, `original live ${plans[index].command} peer build`)),
      nativePreparation,
    ]));
    return preparedAddon;
  } catch (error) {
    failure = error;
    abort.abort(failure);
    await deadline.stop();
  } finally {
    if (nativePreparation !== undefined) {
      const [native] = await Promise.allSettled([nativePreparation]);
      if (native.status === "rejected" && native.reason !== failure) {
        failure = failure === undefined ? native.reason : new AggregateError([failure, native.reason], "live peer and native preparation failed");
      }
    }
    await deadline.finish(failure, async () => {
      try {
        await artifacts.cleanup(failure, [nativeDiagnostic, ...owners.map(owner => owner.stderr.text())].filter(Boolean).join("\n"));
      } catch (error) {
        await cleanupParityArtifact(error, () => preparedAddon?.cleanup()); throw error;
      }
      if (failure !== undefined) await preparedAddon?.cleanup();
    });
  }
}

async function reserveLoopbackPort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => server.once("error", reject).listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("failed to reserve browser site port");
  await new Promise((resolve, reject) => server.close((error) => error === undefined ? resolve() : reject(error)));
  return address.port;
}

// The independent authority owns endpoint credentials and signer material.
// The Rust relay receives only its separately exported public installation;
// the driver sends the original endpoint envelope directly to A and B.
async function runRegisteredLiveTopology(topology) {
  const id = topology.test_id ?? topology.id, carrierA = topology.ingress_carrier_a, carrierB = topology.ingress_carrier_b;
  const arguments_ = ["--carrier", carrierA, "--server-carrier", carrierB,
    "--client-listener", clientListener, "--server-listener", serverListener];
  if (clientProfile !== undefined && (clientProfile !== "swift" || clientListener !== "relay")) {
    throw new Error(`${id}: live external client entry requires the declared Swift dialer profile`);
  }
  let installation, fixture, authority, relay, endpointA, endpointB, failure;
  const processes = () => [fixture, authority, relay, endpointA, endpointB].filter(Boolean);
  const deadline = parityProcessDeadline(processes, cellTimeoutMS, `${id}: cell deadline exceeded`);
  try {
    let paths;
    if (process.env.FLOWERSEC_PARITY_CURRENT_V4_DEPLOYMENT) {
      paths = {
        authority: process.env.FLOWERSEC_PARITY_CURRENT_V4_DEPLOYMENT,
        client: process.env.FLOWERSEC_PARITY_LIVE_DEPLOYMENT,
        server: process.env.FLOWERSEC_PARITY_SERVER_CONTROL_DEPLOYMENT,
      };
      if (new Set(Object.values(paths)).size !== 3) throw new Error(`${id}: external live owners require distinct installation paths`);
      for (const value of Object.values(paths)) {
        if (typeof value !== "string" || !path.isAbsolute(value) || value.length > 4096) {
          throw new Error(`${id}: external live topology requires all three independently installed authority/A/B paths`);
        }
      }
    } else {
      installation = await createLiveInstallationDirectory(id);
      deadline.check();
      fixture = startPeer("go", ["live-installation", ...arguments_, "--directory", installation.directory], ownedLivePeerEnvironment());
      const installed = await deadline.wait(nextPeerJSON(fixture, `${id} independent live installation`));
      assertDimensions(installed, "live-installation-ready", "go", carrierA, id);
      const allowed = new Set(["type", "runtime", "wire_revision", "path", "source", "profile", "carrier", "server_carrier",
        "authority_deployment_path", "client_deployment_path", "server_deployment_path"]);
      if (Object.keys(installed).some(field => !allowed.has(field)) || installed.source !== "live_authority" || installed.server_carrier !== carrierB) {
        throw new Error(`${id}: provisioning must return only separate original installation paths`);
      }
      paths = { authority: installed.authority_deployment_path, client: installed.client_deployment_path, server: installed.server_deployment_path };
      const unique = new Set();
      for (const value of Object.values(paths)) {
        if (typeof value !== "string" || value.length === 0 || value.length > 4096 || !path.isAbsolute(value)
            || path.dirname(value) !== installation.directory || unique.has(value)) {
          throw new Error(`${id}: provisioning returned overlapping or foreign installation paths`);
        }
        unique.add(value);
      }
    }
    deadline.check();
    authority = startPeer("go", ["live-authority", ...arguments_], ownedLivePeerEnvironment(paths, "authority"));
    const prepared = await deadline.wait(nextPeerJSON(authority, `${id} original authority prepared`));
    assertDimensions(prepared, "authority-prepared", "go", carrierA, id);
    if (prepared.source !== "live_authority" || prepared.server_carrier !== carrierB
        || typeof prepared.relay_installation_path !== "string" || prepared.relay_installation_path.length === 0
        || prepared.relay_installation_path.length > 4096 || !path.isAbsolute(prepared.relay_installation_path)) {
      throw new Error(`${id}: original authority did not export its independently installed relay projection`);
    }
    relay = startPeer("rust", ["relay", ...arguments_], {
      FLOWERSEC_PARITY_RELAY_LIVE_DEPLOYMENT: prepared.relay_installation_path,
      FLOWERSEC_PARITY_CURRENT_V4_DEPLOYMENT: "",
      FLOWERSEC_PARITY_LIVE_DEPLOYMENT: "",
      FLOWERSEC_PARITY_SERVER_CONTROL_DEPLOYMENT: "",
    });
    const publicRelay = await deadline.wait(nextPeerJSON(relay, `${id} public relay prepared`));
    assertDimensions(publicRelay, "relay-prepared", "rust", carrierA, id);
    const publicFields = new Set(["type", "runtime", "wire_revision", "path", "source", "profile", "carrier",
      "server_carrier", "control_endpoint", "route_digest", "verification_records"]);
    if (Object.keys(publicRelay).some((field) => !publicFields.has(field)) || publicRelay.source !== "live_authority"
        || publicRelay.server_carrier !== carrierB) throw new Error(`${id}: relay readiness is not a public installation acknowledgement`);
    await deadline.wait(requireRegisteredServerInstallation(prepared.control_endpoint, id, publicRelay.control_endpoint, paths.server));
    endpointB = startPeer(topology.endpoint_b, ["tunnel-endpoint-b", "--carrier", carrierB], ownedLivePeerEnvironment(paths, "server"));
    const original = await deadline.wait(nextPeerJSON(authority, `${id} original authority endpoint publication`));
    assertDimensions(original, "authority-ready", "go", carrierA, id);
    if (original.source !== "live_authority" || original.server_carrier !== carrierB
        || original.profile !== publicRelay.profile || original.route_digest !== publicRelay.route_digest
        || !isDeepStrictEqual(original.verification_records, publicRelay.verification_records)) {
      throw new Error(`${id}: authority endpoint records differ from the relay's independent public installation`);
    }
    const relayReady = { ...original, type: "relay-ready", runtime: "rust" };
    assertTunnelPublication(relayReady, id);
    const endpointBPublication = relayForEndpoint(relayReady, 1, id);
    endpointB.child.stdin.write(`${JSON.stringify({ topology, relay: endpointBPublication })}\n`);
    const endpointBReady = await deadline.wait(nextPeerJSON(endpointB, `${id} endpoint B ready`));
    assertDimensions(endpointBReady, "endpoint-b-ready", topology.endpoint_b, carrierB, id);
    assertEndpointTunnelPublication(endpointBReady, endpointBPublication, id);
    if (clientProfile === "swift") {
      endpointA = startExternalClient({ type: "ready", wire_revision: 4, profile: endpointBReady.profile,
        source: endpointBReady.source, runtime: topology.endpoint_b, carrier: carrierA, path: "tunnel",
        artifact_json: relayReady.endpoint_a_artifact_json, trust_pem: relayReady.trust_pem,
        client_tls_certificate_pem: relayReady.client_tls_certificate_pem,
        client_tls_private_key_pem: relayReady.client_tls_private_key_pem, origin: relayReady.origin },
        undefined, undefined, { ...ownedLivePeerEnvironment(paths, "client"),
          FLOWERSEC_TEST_ARTIFACT_DIR: installation?.directory ?? process.env.FLOWERSEC_TEST_ARTIFACT_DIR });
    } else {
      endpointA = startPeer(topology.endpoint_a, ["tunnel-endpoint-a", "--carrier", carrierA], ownedLivePeerEnvironment(paths, "client"));
      endpointA.child.stdin.end(`${JSON.stringify({ topology, endpoint_b: readyForClient(endpointBReady, relayReady, id) })}\n`);
      if (clientListener === "endpoint") {
        const preparedA = await deadline.wait(nextPeerJSON(endpointA, `${id} endpoint A prepared`));
        assertDimensions(preparedA, "endpoint-a-prepared", topology.endpoint_a, carrierA, id);
      }
    }
    relay.child.stdin.write(`${JSON.stringify({ type: "configure", wire_revision: 4,
      route_digest: relayReady.route_digest, authorizations: endpointBReady.authorizations,
      verification_records: endpointBReady.verification_records })}\n`);
    endpointB.child.stdin.end(`${JSON.stringify({ type: "connect" })}\n`);
    if (clientProfile === undefined) {
      const resultA = await deadline.wait(nextPeerJSON(endpointA, `${id} endpoint A result`));
      assertResult(resultA, "endpoint-a-result", topology.endpoint_a, carrierA, endpointExpectedCases(carrierA, carrierB), `${id} endpoint A`);
      assertNoSyntheticCleanupCounters(resultA, id);
    }
    await deadline.wait(requireSuccessfulExit(endpointA, `${id} endpoint A`));
    const resultB = await deadline.wait(nextPeerJSON(endpointB, `${id} endpoint B result`));
    assertResult(resultB, "endpoint-b-result", topology.endpoint_b, carrierB, endpointExpectedCases(carrierB, carrierA), `${id} endpoint B`);
    assertNoSyntheticCleanupCounters(resultB, id);
    await deadline.wait(requireSuccessfulExit(endpointB, `${id} endpoint B`));
    relay.child.stdin.end(`${JSON.stringify({ type: "close" })}\n`);
    const relayResult = await deadline.wait(nextPeerJSON(relay, `${id} live relay result`));
    assertDimensions(relayResult, "relay-result", "rust", carrierA, id);
    assertCases(relayResult, relayExpectedCases(carrierA, carrierB), `${id} relay`);
    assertNoSyntheticCleanupCounters(relayResult, id);
    if (relayResult.observed_plaintext !== false) throw new Error(`${id}: relay observed application plaintext`);
    await deadline.wait(requireSuccessfulExit(relay, `${id} relay`));
    authority.child.stdin.end(`${JSON.stringify({ type: "close" })}\n`);
    const authorityResult = await deadline.wait(nextPeerJSON(authority, `${id} authority cleanup result`));
    assertDimensions(authorityResult, "authority-result", "go", carrierA, id);
    if (authorityResult.source !== "live_authority" || authorityResult.cleanup_complete !== true) {
      throw new Error(`${id}: original authority did not join its actual control and store owners`);
    }
    await deadline.wait(requireSuccessfulExit(authority, `${id} authority`));
    if (fixture !== undefined) {
      fixture.child.stdin.end(`${JSON.stringify({ type: "close" })}\n`);
      const retired = await deadline.wait(nextPeerJSON(fixture, `${id} independent installation cleanup`));
      assertDimensions(retired, "live-installation-result", "go", carrierA, id);
      if (retired.source !== "live_authority" || retired.server_carrier !== carrierB || retired.cleanup_complete !== true) {
        throw new Error(`${id}: independent installation did not join its original bootstrap owners`);
      }
      await deadline.wait(requireSuccessfulExit(fixture, `${id} independent installation`));
    }
  } catch (error) {
    await deadline.stop();
    const diagnostics = processes().map((peer) => peer.stderr.text()).filter(Boolean).join("\n");
    failure = new Error(`${id}: ${error instanceof Error ? error.message : String(error)}${diagnostics === "" ? "" : `\n${diagnostics}`}`, { cause: error });
  } finally {
    await deadline.finish(failure, () => installation?.cleanup(failure, processes().map(peer => peer.stderr.text()).filter(Boolean).join("\n")));
  }
}

async function requireRegisteredServerInstallation(endpoint, id, relayEndpoint, installationPath = process.env.FLOWERSEC_PARITY_SERVER_CONTROL_DEPLOYMENT) {
  if (typeof installationPath !== "string" || installationPath.length === 0 || installationPath.length > 4096) {
    throw new Error(`${id}: registered B requires its existing independent FLOWERSEC_PARITY_SERVER_CONTROL_DEPLOYMENT`);
  }
  const file = await open(installationPath, "r"), storage = Buffer.alloc(4194305);
  let length = 0;
  try {
    for (;;) {
      if (length === storage.length) throw new Error(`${id}: B installation exceeds its input bound`);
      const result = await file.read(storage, length, storage.length - length, null);
      if (result.bytesRead === 0) break;
      length += result.bytesRead;
    }
    if (length === 0 || length > 4194304) throw new Error(`${id}: B installation exceeds its input bound`);
    const installation = JSON.parse(storage.subarray(0, length).toString("utf8"));
    if (installation === null || typeof installation !== "object" || installation.wire_revision !== 4
        || typeof installation.registration_json !== "string" || installation.registration_json.length === 0
        || Buffer.byteLength(installation.registration_json) > 1048576 || installation.control?.endpoint !== endpoint
        || relayEndpoint !== undefined && installation.relay_control?.endpoint !== relayEndpoint) {
      throw new Error(`${id}: prepared authority or relay differs from B's independent installation`);
    }
  } finally { storage.fill(0); await file.close(); }
}

function relayForEndpoint(original, role, id) {
  if (original.source !== "live_authority") return original;
  const projected = { ...original,
    endpoint_a_artifact_json: role === 0 ? original.endpoint_a_artifact_json : "",
    endpoint_b_artifact_json: role === 1 ? original.endpoint_b_artifact_json : "",
    client_tls_private_key_pem: role === 0 ? original.client_tls_private_key_pem : "",
    server_tls_private_key_pem: role === 1 ? original.server_tls_private_key_pem : "",
  };
  assertRoleBoundLiveTunnelPublication(projected, role, id);
  return projected;
}

function readyForClient(endpoint, original, id) {
  if (original.source !== "live_authority") return endpoint;
  return { type: endpoint.type, runtime: endpoint.runtime, carrier: endpoint.carrier,
    path: endpoint.path, wire_revision: endpoint.wire_revision,
    endpoint_a_artifact_json: original.endpoint_a_artifact_json, endpoint_b_artifact_json: "",
    relay: relayForEndpoint(original, 0, id), profile: endpoint.profile, source: endpoint.source,
    authorizations: endpoint.authorizations, verification_records: endpoint.verification_records,
    ...(endpoint.browser_application === undefined ? {} : { browser_application: endpoint.browser_application }),
  };
}

async function readPoolClientInstallation(installationPath, binding, id) {
  if (typeof installationPath !== "string" || !path.isAbsolute(installationPath) || installationPath.length > 4096) throw new Error(`${id}: original A pool installation requires its owned absolute path`);
  const file = await open(installationPath, "r"), storage = Buffer.alloc(4194305);
  let length = 0;
  try {
    const metadata = await file.stat();
    if (!metadata.isFile() || (metadata.mode & 0o077) !== 0) throw new Error(`${id}: original A pool installation must be a private regular file`);
    for (;;) {
      if (length === storage.length) throw new Error(`${id}: original A pool installation exceeds its bounded input`);
      const result = await file.read(storage, length, storage.length - length, null);
      if (result.bytesRead === 0) break;
      length += result.bytesRead;
    }
    if (length === 0 || length > 4194304) throw new Error(`${id}: original A pool installation is empty or oversized`);
    const installed = JSON.parse(storage.subarray(0, length).toString("utf8"));
    if (installed === null || typeof installed !== "object" || Array.isArray(installed) || Object.keys(installed).some(key => !["wire_revision", "tenant", "audience", "server_allow"].includes(key))) throw new Error(`${id}: original A pool installation has an invalid shape`);
    const allow = installed.server_allow;
    if (allow === null || typeof allow !== "object" || Array.isArray(allow) || Object.keys(allow).some(key => !["endpoint", "tls", "workMS"].includes(key))) throw new Error(`${id}: original A pool Allow policy has an invalid shape`);
    if (installed.wire_revision !== 4 || typeof installed.tenant !== "string" || installed.tenant.length === 0 || installed.tenant.length > 128 || typeof installed.audience !== "string" || installed.audience.length === 0 || installed.audience.length > 128 ||
        binding === undefined || allow === undefined || binding.endpoint !== allow.endpoint || allow.clientCertificateDER !== undefined ||
        typeof allow.workMS !== "string" || !/^[1-9][0-9]*$/.test(allow.workMS) || BigInt(allow.workMS) > 2000n) throw new Error(`${id}: original A pool installation differs from B's registered public binding`);
    const endpoint = new URL(allow.endpoint);
    if (endpoint.protocol !== "https:" || !["127.0.0.1", "[::1]"].includes(endpoint.hostname) || (endpoint.port === "" || endpoint.port === "0") || endpoint.pathname !== "/tunnel/server-allow" || endpoint.username !== "" || endpoint.password !== "" || endpoint.search !== "" || endpoint.hash !== "") throw new Error(`${id}: original A pool Allow destination is not its fixed installed HTTPS endpoint`);
    if (allow.tls === null || typeof allow.tls !== "object" || Array.isArray(allow.tls) || Object.keys(allow.tls).some(key => !["certificatePEM", "privateKeyPEM", "trustPEM"].includes(key))) throw new Error(`${id}: original A pool Allow TLS has an invalid shape`);
    for (const field of ["certificatePEM", "privateKeyPEM", "trustPEM"]) {
      if (typeof allow.tls?.[field] !== "string" || allow.tls[field].length === 0 || allow.tls[field].length > (field === "privateKeyPEM" ? 65536 : 262144)) throw new Error(`${id}: original A pool installation lacks its bounded independent TLS material`);
    }
    return installed;
  } finally { storage.fill(0); await file.close(); }
}

function ownedLivePeerEnvironment(paths, owner) {
  return {
    FLOWERSEC_PARITY_CURRENT_V4_DEPLOYMENT: owner === "authority" ? paths.authority : "",
    FLOWERSEC_PARITY_LIVE_DEPLOYMENT: owner === "client" ? paths.client : "",
    FLOWERSEC_PARITY_SERVER_CONTROL_DEPLOYMENT: owner === "server" ? paths.server : "",
    FLOWERSEC_PARITY_RELAY_LIVE_DEPLOYMENT: "",
    FLOWERSEC_PARITY_POOL_DEPLOYMENT: "",
    FLOWERSEC_PARITY_POOL_CLIENT_DEPLOYMENT_OUTPUT: "",
  };
}

async function createLiveInstallationDirectory(id) {
  const requested = process.env.FLOWERSEC_TEST_ARTIFACT_DIR || path.resolve(repositoryRoot, "..", "flowersec-test-artifacts");
  if (!path.isAbsolute(requested)) throw new Error(`${id}: live installation artifact root must be absolute`);
  const outside = (root, forbidden) => {
    const relative = path.relative(forbidden, root);
    return relative !== "" && (relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative));
  };
  const forbidden = await Promise.all([repositoryRoot, os.tmpdir(), "/tmp", "/private/tmp"].map(async root => {
    try { return await realpath(root); } catch (error) { if (error?.code === "ENOENT") return path.resolve(root); throw error; }
  }));
  for (const root of forbidden) {
    if (!outside(path.resolve(requested), root)) throw new Error(`${id}: live installation must be outside repository and temporary roots`);
  }
  await mkdir(requested, { recursive: true, mode: 0o700 });
  const root = await realpath(requested);
  for (const entry of forbidden) {
    if (!outside(root, entry)) throw new Error(`${id}: resolved live installation artifact root is not independent`);
  }
  const identity = randomUUID(), directory = path.join(root, `live-tunnel-${identity}`);
  await mkdir(directory, { mode: 0o700 });
  let cleaned = false;
  return {
    directory,
    async cleanup(failure, diagnostics) {
      if (cleaned) return;
      try {
        if (failure !== undefined) {
          const body = Buffer.from(`${id}: ${failure instanceof Error ? failure.message : String(failure)}\n${diagnostics}\n`);
          try {
            const name = `live-tunnel-failure-${identity}.log`;
            const digest = createHash("sha256").update(body).digest("hex");
            await writeFile(path.join(root, name), body, { flag: "wx", mode: 0o600 });
            await writeFile(path.join(root, `${name}.sha256`), `${digest}  ${name}\n`, { flag: "wx", mode: 0o600 });
            const recorded = await readFile(path.join(root, name));
            try {
              if (createHash("sha256").update(recorded).digest("hex") !== digest) throw new Error(`${id}: retained failure log checksum differs`);
            } finally { recorded.fill(0); }
          } finally { body.fill(0); }
        }
      } catch (error) { throw error; }
      await rm(directory, { recursive: true }); cleaned = true;
    },
  };
}

// Registered relays expose their original control listener before awaiting B.
// B reads the existing independent deployment; the event supplies no trust,
// identity, store selection or permission to reconstruct an installation.
async function acquireRelayReady(relay, topology, carrier, id, startRegisteredB, serverDeployment) {
  let message = await nextPeerJSON(relay, `${id} relay prepared or ready`);
  if (message.type === "relay-prepared") {
    assertDimensions(message, "relay-prepared", topology.tunnel_runtime, carrier, id);
    if (message.source !== "preauthorized_pool" && message.source !== "live_authority" || message.server_carrier !== topology.ingress_carrier_b) throw new Error(`${id}: invalid registered relay source or server carrier`);
    await requireRegisteredServerInstallation(message.control_endpoint, id, undefined, serverDeployment);
    startRegisteredB();
    message = await nextPeerJSON(relay, `${id} relay ready after original B registration`);
  }
  return message;
}

async function nextPeerJSON(peer, label) {
  try {
    return await Promise.race([
      peer.stdout.nextJSON(),
      peer.completion.then(exit => {
        throw new Error(exit.error === undefined
          ? `peer closed before its next protocol message: code=${exit.code} signal=${exit.signal}`
          : `peer failed before its next protocol message: ${exit.error.message}`);
      }),
    ]);
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
    if (!carriers.includes(topology.ingress_carrier_a) || !carriers.includes(topology.ingress_carrier_b)) throw new Error(`${topology.id}: unknown ingress carrier`);
    const expectedCases = ["admission", ...endpointCases, "pairing", "opaque-forwarding", ...(datagramCarriers.has(topology.ingress_carrier_a) && datagramCarriers.has(topology.ingress_carrier_b) ? ["datagram", "datagram-forwarding"] : [])];
    if (!sameValues(topology.cases, expectedCases)) throw new Error(`${topology.id}: cases do not match the executable tunnel contract`);
    if (topology.status === "supported") {
      if (!Array.isArray(topology.test_ids) || topology.test_ids.length !== 1 || "reason" in topology) throw new Error(`${topology.id}: supported topology must bind exactly one test ID and no reason`);
    } else if (topology.status === "unsupported") {
      if ((Array.isArray(topology.test_ids) && topology.test_ids.length !== 0) || typeof topology.reason !== "string" || topology.reason.length === 0) throw new Error(`${topology.id}: unsupported topology must carry only a reason`);
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

function endpointExpectedCases(carrier, peerCarrier = carrier) { return ["admission", ...endpointCases, ...(datagramCarriers.has(carrier) && datagramCarriers.has(peerCarrier) ? ["datagram"] : [])]; }
function relayExpectedCases(carrier, peerCarrier = carrier) { return [...relayCases, ...(datagramCarriers.has(carrier) && datagramCarriers.has(peerCarrier) ? ["datagram-forwarding"] : [])]; }

function assertDimensions(message, type, runtime, carrier, id) {
  if (message === null || typeof message !== "object" || message.type !== type || message.runtime !== runtime || message.carrier !== carrier || message.path !== "tunnel") {
    throw new Error(`${id}: invalid ${type} dimensions`);
  }
  assertCurrentPeer(message, id);
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


function startPeer(runtime, roleArguments, environment = {}) {
  const peer = peers[runtime];
  const coveragePrefix = runtime === "rust" && rustCoverageEnvironment !== undefined ? `parity-${randomUUID()}-` : undefined;
  const profileDirectory = coveragePrefix === undefined ? undefined : path.dirname(rustCoverageEnvironment.LLVM_PROFILE_FILE);
  const profileEnvironment = coveragePrefix === undefined ? {} : {
    LLVM_PROFILE_FILE: path.join(profileDirectory, `${coveragePrefix}%p-%m.profraw`),
  };
  const child = spawn(peer.command, [...peer.arguments, ...roleArguments], { cwd: peer.cwd, detached: process.platform !== "win32", env: { ...process.env, ...nativeAddon.environment, ...environment, ...(runtime === "rust" ? rustEnvironment : {}), ...profileEnvironment, FLOWERSEC_SERVER_PARITY_PEER: "1", FLOWERSEC_PARITY_TEST_ONLY: "1" }, stdio: ["pipe", "pipe", "pipe"] });
  const observation = observeProcess(child);
  if (coveragePrefix !== undefined) {
    // Attach the check to the observed exit so it stays inside the cell deadline.
    observation.completion = observation.completion.then(async exit => {
      if (exit.code !== 0 || exit.error !== undefined) return exit;
      try {
        const files = (await readdir(profileDirectory)).filter(name => name.startsWith(coveragePrefix) && name.endsWith(".profraw"));
        const sizes = await Promise.all(files.map(name => stat(path.join(profileDirectory, name))));
        if (sizes.length === 0 || sizes.some(file => !file.isFile() || file.size === 0)) {
          throw new Error(`Rust ${roleArguments[0]} exited without a fresh nonempty coverage profile`);
        }
        console.log(`Rust coverage profiles: ${roleArguments[0]} ${coveragePrefix} (${sizes.length})`);
        return exit;
      } catch (error) { return { ...exit, error }; }
    });
  }
  const stderr = collectText(child.stderr);
  return { child, ...observation, stderr, stdout: jsonLines(child.stdout), kill(signal) { if (!observation.isComplete()) signalParityProcess(child, signal); } };
}
function startProcess(command, arguments_, cwd, environment) {
  const child = spawn(command, arguments_, { cwd, detached: process.platform !== "win32", env: { ...process.env, ...environment }, stdio: ["ignore", "pipe", "pipe"] });
  const observation = observeProcess(child);
  const stdout = collectText(child.stdout);
  const stderr = collectText(child.stderr);
  return { child, ...observation, stderr: { text: () => `${stdout.text()}\n${stderr.text()}` }, kill(signal) { if (!observation.isComplete()) signalParityProcess(child, signal); } };
}
function observeProcess(child) {
  // Observe from spawn through close so an absent executable, an early signal,
  // or a failed stdin write cannot become an unhandled event or a missed exit.
  let failure, complete = false;
  child.on("error", error => { failure ??= error; });
  for (const stream of [child.stdin, child.stdout, child.stderr]) {
    stream?.on("error", error => { failure ??= error; });
  }
  const completion = new Promise(resolve => child.once("close", (code, signal) => {
    complete = true; resolve({ code, signal, error: failure });
  }));
  return { completion, isComplete: () => complete };
}

async function requireSuccessfulExit(peer, label) {
  const exit = await peer.completion;
  if (exit.error !== undefined) throw new Error(`${label} failed: ${exit.error.message}`);
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
      const newline = buffered.indexOf("\n");
      if (newline < 0) break;
      const raw = buffered.slice(0, newline + 1), rawBytes = Buffer.byteLength(raw), line = raw.trim();
      if (rawBytes > maximumLineBytes) { fail(new Error("peer JSON output exceeds its input bound")); return; }
      buffered = buffered.slice(newline + 1); bufferedBytes -= rawBytes;
      if (line === "") continue;
      try {
        const value = JSON.parse(line);
        if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("peer JSON output must be an object");
        const waiter = waiters.shift();
        if (waiter !== undefined) waiter.resolve(value);
        else {
          if (queued.length === maximumQueuedMessages) throw new Error("peer JSON output exceeds its message queue bound");
          queued.push(value);
        }
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
