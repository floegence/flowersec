import { isIP } from "node:net";
import path from "node:path";

import { chromiumExecutablePath } from "./browser-test-runner-core.mjs";

export { chromiumExecutablePath };

export function normalizeBrowserCapacityPlan(input) {
  const plan = object(input, "browser capacity plan");
  const topology = string(plan.topology, "topology");
  const workload = plan.workload === undefined ? "held_sessions" : string(plan.workload, "workload");
  const heldSessions = workload === "held_sessions";
  const streamCapacity = workload === "stream_capacity";
  if (!heldSessions && !streamCapacity) throw new TypeError("browser capacity workload is invalid");
  if (heldSessions && topology !== "browser_tunnel_wt_wss" && topology !== "browser_tunnel_wt_quic") {
    throw new TypeError("browser held-session capacity topology must be browser_tunnel_wt_wss or browser_tunnel_wt_quic");
  }
  if (streamCapacity && topology !== "browser_webtransport" && topology !== "browser_tunnel_wt_wss" && topology !== "browser_tunnel_wt_quic") {
    throw new TypeError("browser stream capacity topology is invalid");
  }
  return Object.freeze({
    schema_version: exactInteger(plan.schema_version, "schema_version", 1, 1),
    topology,
    workload,
    profile_id: string(plan.profile_id, "profile_id"),
    sessions: exactInteger(plan.sessions, "sessions", heldSessions ? 1000 : 100, heldSessions ? 1000 : 100),
    connections_per_session: exactInteger(plan.connections_per_session ?? 1, "connections_per_session", 1, 1),
    streams_per_session: exactInteger(plan.streams_per_session ?? (heldSessions ? 0 : 128), "streams_per_session", heldSessions ? 0 : 128, heldSessions ? 0 : 128),
    stream_workers_per_session: streamCapacity ? 4 : 0,
    certificate_hash: certificateHash(plan.certificate_hash),
    client_netns: namespace(plan.client_netns),
    module_bind_address: ipAddress(plan.module_bind_address, "module_bind_address"),
    module_advertise_host: ipAddress(plan.module_advertise_host, "module_advertise_host"),
    control_bind_address: ipAddress(plan.control_bind_address, "control_bind_address"),
    event_sink_url: httpURL(plan.event_sink_url, "event_sink_url"),
    output_directory: absolutePath(plan.output_directory, "output_directory"),
    operation_deadline_ms: exactInteger(plan.operation_deadline_ms, "operation_deadline_ms", streamCapacity ? 60_000 : 30_000, streamCapacity ? 60_000 : 30_000),
  });
}

export function capacityStreamAssignments(streams, workers) {
  positiveInteger(streams, "streams");
  exactInteger(workers, "workers", 1, streams);
  const assignments = Array.from({ length: workers }, () => []);
  for (let index = 0; index < streams; index++) assignments[index % workers].push(index);
  return assignments.map((indexes) => Object.freeze(indexes));
}

export function createBrowserCapacityCloseBatcher(executeBatch, options = {}) {
  if (typeof executeBatch !== "function") throw new TypeError("browser capacity close batch callback is required");
  const delayMs = options.delayMs ?? 250;
  finiteNumber(delayMs, "browser capacity close batch delay", 0);
  const schedule = options.schedule ?? ((flush) => setTimeout(flush, delayMs));
  if (typeof schedule !== "function") throw new TypeError("browser capacity close batch scheduler is required");
  let pending = [];
  let scheduled = false;
  let running = false;
  const scheduleFlush = () => {
    if (scheduled || running || pending.length === 0) return;
    scheduled = true;
    schedule(() => {
      scheduled = false;
      void flush();
    });
  };
  const flush = async () => {
    if (running || pending.length === 0) return;
    const batch = pending;
    pending = [];
    running = true;
    try {
      await executeBatch(batch.map((entry) => entry.value));
      for (const entry of batch) entry.resolve();
    } catch (error) {
      for (const entry of batch) entry.reject(error);
    } finally {
      running = false;
      scheduleFlush();
    }
  };
  return (value) => new Promise((resolve, reject) => {
    pending.push({ value, resolve, reject });
    scheduleFlush();
  });
}

export function chromiumCapacityLaunchOptions(plan, chromiumExecutable, launcherPath, moduleOrigin) {
  const normalized = normalizeBrowserCapacityPlan(plan);
  const executable = absolutePath(chromiumExecutable, "Chromium executable");
  const launcher = absolutePath(launcherPath, "Chromium netns launcher");
  const secureOrigin = browserModuleOrigin(moduleOrigin, normalized.module_advertise_host);
  return {
    headless: true,
    executablePath: launcher,
    args: [
      `--unsafely-treat-insecure-origin-as-secure=${secureOrigin}`,
      "--quic-client-connection-options=TBBR",
      `--log-net-log=${path.join(normalized.output_directory, "chromium-netlog.json")}`,
      "--net-log-capture-mode=IncludeSensitive",
    ],
    env: {
      ...process.env,
      FLOWERSEC_CLIENT_NETNS: normalized.client_netns,
      FLOWERSEC_CHROMIUM_EXECUTABLE: executable,
    },
  };
}

function browserModuleOrigin(value, advertiseHost) {
  let origin;
  try {
    origin = new URL(value);
  } catch {
    throw new TypeError("browser module origin must be a valid URL");
  }
  if (origin.protocol !== "http:" || origin.hostname !== advertiseHost || origin.username !== "" || origin.password !== "" || origin.pathname !== "/" || origin.search !== "" || origin.hash !== "") {
    throw new TypeError("browser module origin must use the advertised IP");
  }
  return origin.origin;
}

function certificateHash(value) {
  const hash = string(value, "certificate_hash");
  if (!/^[A-Za-z0-9_-]{43}$/.test(hash)) throw new TypeError("certificate_hash must be unpadded base64url SHA-256");
  return hash;
}

function namespace(value) {
  const name = string(value, "client_netns");
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$/.test(name)) throw new TypeError("client_netns is invalid");
  return name;
}

function ipAddress(value, name) {
  const address = string(value, name);
  if (isIP(address) !== 4) throw new TypeError(`${name} must be an IPv4 address`);
  return address;
}

function httpURL(value, name) {
  const raw = string(value, name);
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw new TypeError(`${name} must be a valid URL`);
  }
  if (parsed.protocol !== "http:" || parsed.username !== "" || parsed.password !== "") throw new TypeError(`${name} must be an HTTP URL without credentials`);
  return parsed.toString();
}

function absolutePath(value, name) {
  const candidate = string(value, name);
  if (!path.isAbsolute(candidate) || path.normalize(candidate) !== candidate) throw new TypeError(`${name} must be an absolute normalized path`);
  return candidate;
}

function object(value, name) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new TypeError(`${name} must be an object`);
  return value;
}

function string(value, name) {
  if (typeof value !== "string" || value.length === 0) throw new TypeError(`${name} must be a non-empty string`);
  return value;
}

function positiveInteger(value, name) {
  if (!Number.isSafeInteger(value) || value <= 0) throw new TypeError(`${name} must be a positive integer`);
  return value;
}

function exactInteger(value, name, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new TypeError(`${name} must be between ${minimum} and ${maximum}`);
  return value;
}

function finiteNumber(value, name, minimum) {
  if (!Number.isFinite(value) || value < minimum) throw new TypeError(`${name} must be a finite number >= ${minimum}`);
  return value;
}
