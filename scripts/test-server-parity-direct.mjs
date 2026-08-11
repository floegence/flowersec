import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const matrix = JSON.parse(await readFile(path.join(repositoryRoot, "stability/interop_matrix.json"), "utf8"));
const runtimeValues = ["go", "rust", "node-typescript"];
const carrierValues = ["websocket", "raw-quic", "webtransport"];
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
const datagramCarriers = new Set(["raw-quic", "webtransport"]);
const cellTimeoutMS = 45_000;
const semanticContract = Object.freeze({
  rpc: Object.freeze({ type_id: 7001, request: Object.freeze({ value: "ping" }), response: Object.freeze({ value: "ping" }) }),
  notification: Object.freeze({ type_id: 7002, payload: Object.freeze({ value: "notify" }) }),
  stream: Object.freeze({ kind: "parity.echo", metadata: Object.freeze({ cell: "direct" }), request: "hello", response: "world" }),
  reset_stream: Object.freeze({ kind: "parity.reset" }),
  datagram: Object.freeze([1, 2, 3]),
});

const peers = {
  go: {
    cwd: path.join(repositoryRoot, "flowersec-go"),
    command: "go",
    arguments: ["run", "./internal/cmd/server-parity-peer"],
  },
  rust: {
    cwd: repositoryRoot,
    command: "rustup",
    arguments: [
      "run", "1.88.0", "cargo", "run", "--quiet", "--manifest-path", "flowersec-rust/Cargo.toml",
      "--example", "server_parity_peer", "--",
    ],
  },
  "node-typescript": {
    cwd: path.join(repositoryRoot, "flowersec-ts"),
    command: process.execPath,
    arguments: ["--import", "tsx", "src/interop/serverParityPeer.ts"],
  },
};

validateDirectContract(matrix.direct_cells);
const selectedCells = matrix.direct_cells.filter((cell) => cell.status === "supported" && clients.includes(cell.client) && servers.includes(cell.server) && carriers.includes(cell.carrier));
for (const cell of selectedCells) await runCell(cell);
if (selectedCells.length === 0) console.log("server parity direct matrix: no supported cells selected; unsupported tuples were not executed");
else console.log(`server parity direct matrix OK: ${selectedCells.length} supported production cells`);

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
  const id = `${cell.client}/${cell.server}/${cell.carrier}`;
  const expectedCases = [...commonCases, ...(datagramCarriers.has(cell.carrier) ? ["datagram"] : [])];
  const serverPeer = startPeer(cell.server, ["server", "--carrier", cell.carrier]);
  let clientPeer;
  const timer = setTimeout(() => {
    serverPeer.kill("SIGKILL");
    clientPeer?.kill("SIGKILL");
  }, cellTimeoutMS);
  try {
    const ready = await serverPeer.stdout.nextJSON();
    assertMessage(ready, "ready", id);
    if (ready.runtime !== cell.server || ready.carrier !== cell.carrier || ready.path !== "direct") {
      throw new Error(`${id}: server ready dimensions do not match the requested cell`);
    }
    if (typeof ready.artifact_json !== "string" || ready.artifact_json.length === 0) {
      throw new Error(`${id}: server did not publish an artifact issued through its public control plane`);
    }

    clientPeer = startPeer(cell.client, ["client", "--carrier", cell.carrier]);
    clientPeer.child.stdin.end(`${JSON.stringify({ ...ready, semantic_contract: semanticContract })}\n`);
    const clientResult = await clientPeer.stdout.nextJSON();
    assertResult(clientResult, "client-result", cell.client, cell.carrier, expectedCases, id);
    await requireSuccessfulExit(clientPeer, `${id} client`);

    const serverResult = await serverPeer.stdout.nextJSON();
    assertResult(serverResult, "server-result", cell.server, cell.carrier, expectedCases, id);
    if (serverResult.active_sessions !== 0 || serverResult.active_streams !== 0) {
      throw new Error(`${id}: server leaked sessions=${serverResult.active_sessions} streams=${serverResult.active_streams}`);
    }
    await requireSuccessfulExit(serverPeer, `${id} server`);
  } catch (error) {
    serverPeer.kill("SIGKILL");
    clientPeer?.kill("SIGKILL");
    const diagnostics = [serverPeer, clientPeer]
      .filter(Boolean)
      .map((peer) => peer.stderr.text())
      .filter((value) => value.length > 0)
      .join("\n");
    throw new Error(`${id}: ${error instanceof Error ? error.message : String(error)}${diagnostics === "" ? "" : `\n${diagnostics}`}`);
  } finally {
    clearTimeout(timer);
  }
}

function startPeer(runtime, roleArguments) {
  const peer = peers[runtime];
  const child = spawn(peer.command, [...peer.arguments, ...roleArguments], {
    cwd: peer.cwd,
    env: { ...process.env, FLOWERSEC_SERVER_PARITY_PEER: "1" },
    stdio: ["pipe", "pipe", "pipe"],
  });
  const stderr = collectText(child.stderr);
  return {
    child,
    stderr,
    stdout: jsonLines(child.stdout),
    kill(signal) {
      if (child.exitCode === null && child.signalCode === null) child.kill(signal);
    },
  };
}

function assertMessage(message, type, cellID) {
  if (message === null || typeof message !== "object" || message.type !== type) {
    throw new Error(`${cellID}: expected ${type} peer message`);
  }
}

function assertResult(message, type, runtime, carrier, expectedCases, cellID) {
  assertMessage(message, type, cellID);
  if (message.runtime !== runtime || message.carrier !== carrier || message.path !== "direct") {
    throw new Error(`${cellID}: ${type} dimensions do not match the requested cell`);
  }
  if (!Array.isArray(message.cases) || message.cases.length !== expectedCases.length ||
      !expectedCases.every((caseID) => message.cases.includes(caseID))) {
    throw new Error(`${cellID}: ${type} did not prove every required semantic case`);
  }
}

async function requireSuccessfulExit(peer, label) {
  const exit = await new Promise((resolve) => {
    if (peer.child.exitCode !== null) resolve({ code: peer.child.exitCode, signal: peer.child.signalCode });
    else peer.child.once("exit", (code, signal) => resolve({ code, signal }));
  });
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
  stream.on("end", () => {
    ended = true;
    for (const waiter of waiters.splice(0)) waiter.reject(new Error("peer stdout ended before the next protocol message"));
  });
  function deliver(value) {
    const waiter = waiters.shift();
    if (waiter === undefined) queued.push(value);
    else waiter.resolve(value);
  }
  return {
    async nextJSON() {
      if (queued.length > 0) return queued.shift();
      if (ended) throw new Error("peer stdout ended before the next protocol message");
      return await new Promise((resolve, reject) => waiters.push({ resolve, reject }));
    },
  };
}
