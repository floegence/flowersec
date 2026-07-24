import { isIP } from "node:net";
import path from "node:path";

const TOPOLOGIES = new Set([
  "browser_webtransport",
  "browser_tunnel_wt_wss",
  "browser_tunnel_wt_quic",
  "adaptive_web",
]);
const NETNS_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$/;

export function normalizeCollectorPlan(input) {
  const plan = object(input, "collector plan");
  const topology = string(plan.topology, "topology");
  if (!TOPOLOGIES.has(topology)) throw new TypeError(`unsupported topology ${JSON.stringify(topology)}`);
  const mode = string(plan.mode, "mode");
  const adaptive = topology === "adaptive_web";
  if (mode !== (adaptive ? "adaptive" : "forced")) {
    throw new TypeError(`${topology} requires mode ${adaptive ? "adaptive" : "forced"}`);
  }
  const artifactSourceURL = httpURL(plan.artifact_source_url, "artifact_source_url");
  const clientNetns = namespace(plan.client_netns);
  const moduleBindAddress = ipAddress(plan.module_bind_address, "module_bind_address");
  const moduleAdvertiseHost = ipAddress(plan.module_advertise_host, "module_advertise_host");
  const normalized = {
    schema_version: exactInteger(plan.schema_version, "schema_version", 1, 1),
    topology,
    profile_id: string(plan.profile_id, "profile_id"),
    run_number: positiveInteger(plan.run_number, "run_number"),
    mode,
    artifact_source_url: artifactSourceURL,
    certificate_hash: certificateHash(plan.certificate_hash),
    client_netns: clientNetns,
    module_bind_address: moduleBindAddress,
    module_advertise_host: moduleAdvertiseHost,
    cell_deadline_ms: positiveInteger(plan.cell_deadline_ms, "cell_deadline_ms"),
  };
  if (adaptive) {
    if (plan.rpc !== undefined) throw new TypeError("adaptive_web must not define rpc");
    if (plan.bulk !== undefined) throw new TypeError("adaptive_web must not define bulk");
    if (plan.cleanup_deadline_ms !== undefined) {
      throw new TypeError("adaptive_web cleanup deadline belongs to each stage");
    }
    if (!Array.isArray(plan.stages) || plan.stages.length !== 2) {
      throw new TypeError("adaptive_web requires exactly two cold-only stages");
    }
    normalized.stages = plan.stages.map((stage, index) => normalizeAdaptiveStage(stage, index));
  } else {
    if (plan.stages !== undefined) throw new TypeError("forced browser topology must not define stages");
    normalized.cold = normalizeCold(plan.cold, "cold");
    normalized.rpc = normalizeRPC(plan.rpc);
    normalized.bulk = normalizeBulk(plan.bulk);
    normalized.cleanup_deadline_ms = positiveInteger(plan.cleanup_deadline_ms, "cleanup_deadline_ms");
  }
  return Object.freeze(normalized);
}

export function chromiumLaunchOptions(plan, chromiumExecutable, launcherPath, moduleOrigin) {
  const normalized = normalizeCollectorPlan(plan);
  const executable = absolutePath(chromiumExecutable, "Chromium executable");
  const launcher = absolutePath(launcherPath, "Chromium netns launcher");
  const secureOrigin = browserModuleOrigin(moduleOrigin, normalized.module_advertise_host);
  return {
    headless: true,
    executablePath: launcher,
    args: [`--unsafely-treat-insecure-origin-as-secure=${secureOrigin}`],
    env: {
      ...process.env,
      FLOWERSEC_CLIENT_NETNS: namespace(normalized.client_netns),
      FLOWERSEC_CHROMIUM_EXECUTABLE: executable,
    },
  };
}

function browserModuleOrigin(value, advertiseHost) {
  let origin;
  try {
    origin = new URL(string(value, "browser module origin"));
  } catch {
    throw new TypeError("browser module origin must be an absolute HTTP origin");
  }
  if (origin.protocol !== "http:" || origin.username !== "" || origin.password !== "" ||
      origin.pathname !== "/" || origin.search !== "" || origin.hash !== "" ||
      origin.hostname !== advertiseHost || origin.port === "") {
    throw new TypeError("browser module origin must use the advertised IP and an explicit HTTP port");
  }
  return origin.origin;
}

export async function runOpenLoop({
  operations,
  maxInflight,
  intervalMs,
  operation,
  now = () => performance.now(),
  waitUntil = defaultWaitUntil,
}) {
  positiveInteger(operations, "operations");
  exactInteger(maxInflight, "maxInflight", 1, operations);
  finiteNumber(intervalMs, "intervalMs", 0);
  if (typeof operation !== "function" || typeof now !== "function" || typeof waitUntil !== "function") {
    throw new TypeError("open-loop callbacks are required");
  }
  const phaseStart = now();
  const pending = new Set();
  const results = new Array(operations);
  for (let ordinal = 1; ordinal <= operations; ordinal++) {
    const scheduledAtMs = phaseStart + ((ordinal - 1) * intervalMs);
    await waitUntil(scheduledAtMs, now);
    while (pending.size >= maxInflight) await Promise.race(pending);
    let task;
    task = Promise.resolve()
      .then(() => operation(ordinal, scheduledAtMs))
      .then((result) => { results[ordinal - 1] = result; })
      .finally(() => pending.delete(task));
    pending.add(task);
  }
  await Promise.all(pending);
  return results;
}

export async function acquireArtifactBatch(plan, request, fetchImpl = globalThis.fetch) {
  const normalized = normalizeCollectorPlan(plan);
  const acquisition = normalizeAcquisitionRequest(request);
  if (typeof fetchImpl !== "function") throw new TypeError("fetch implementation is required");
  const response = await fetchImpl(normalized.artifact_source_url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      schema_version: 1,
      action: "acquire",
      topology: normalized.topology,
      profile_id: acquisition.profile_id,
      run_number: normalized.run_number,
      phase: acquisition.phase,
      count: acquisition.count,
    }),
  });
  if (!response.ok) throw new Error(`artifact acquisition failed with HTTP ${response.status}`);
  const payload = object(await response.json(), "artifact acquisition response");
  if (payload.schema_version !== 1 || !Array.isArray(payload.artifacts) || payload.artifacts.length !== acquisition.count) {
    throw new Error("artifact acquisition response does not match the requested batch");
  }
  const tokens = new Set();
  return Object.freeze(payload.artifacts.map((entry, index) => {
    const item = object(entry, `artifact ${index + 1}`);
    const artifactJSON = string(item.artifact_json, `artifact ${index + 1} artifact_json`);
    JSON.parse(artifactJSON);
    const spendToken = string(item.spend_token, `artifact ${index + 1} spend_token`);
    if (tokens.has(spendToken)) throw new Error("artifact acquisition returned a duplicate spend token");
    tokens.add(spendToken);
    return Object.freeze({ artifact_json: artifactJSON, spend_token: spendToken });
  }));
}

export async function commitArtifactSpend(plan, spendToken, fetchImpl = globalThis.fetch) {
  const normalized = normalizeCollectorPlan(plan);
  const token = string(spendToken, "spend token");
  if (typeof fetchImpl !== "function") throw new TypeError("fetch implementation is required");
  const response = await fetchImpl(normalized.artifact_source_url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ schema_version: 1, action: "spend", spend_token: token }),
  });
  if (!response.ok) throw new Error(`artifact spend failed with HTTP ${response.status}`);
}

function normalizeAdaptiveStage(input, index) {
  const stage = object(input, `stage ${index + 1}`);
  return Object.freeze({
    profile_id: string(stage.profile_id, `stage ${index + 1} profile_id`),
    cold: normalizeCold(stage.cold, `stage ${index + 1} cold`),
    cleanup_deadline_ms: positiveInteger(stage.cleanup_deadline_ms, `stage ${index + 1} cleanup_deadline_ms`),
  });
}

function normalizeCold(input, name) {
  const value = object(input, name);
  const operations = positiveInteger(value.operations, `${name}.operations`);
  return Object.freeze({
    operations,
    max_inflight: exactInteger(value.max_inflight, `${name}.max_inflight`, 1, operations),
    start_rate_per_second: positiveInteger(value.start_rate_per_second, `${name}.start_rate_per_second`),
    operation_deadline_ms: positiveInteger(value.operation_deadline_ms, `${name}.operation_deadline_ms`),
    phase_deadline_ms: positiveInteger(value.phase_deadline_ms, `${name}.phase_deadline_ms`),
  });
}

function normalizeRPC(input) {
  const value = object(input, "rpc");
  const operations = positiveInteger(value.operations, "rpc.operations");
  return Object.freeze({
    operations,
    workers: exactInteger(value.workers, "rpc.workers", 1, operations),
    request_bytes: exactInteger(value.request_bytes, "rpc.request_bytes", 2, 1 << 24),
    operation_deadline_ms: positiveInteger(value.operation_deadline_ms, "rpc.operation_deadline_ms"),
    phase_deadline_ms: positiveInteger(value.phase_deadline_ms, "rpc.phase_deadline_ms"),
  });
}

function normalizeBulk(input) {
  const value = object(input, "bulk");
  return Object.freeze({
    warmup_bytes_per_direction: positiveInteger(value.warmup_bytes_per_direction, "bulk.warmup_bytes_per_direction"),
    score_bytes_per_direction: positiveInteger(value.score_bytes_per_direction, "bulk.score_bytes_per_direction"),
    phase_deadline_ms: positiveInteger(value.phase_deadline_ms, "bulk.phase_deadline_ms"),
  });
}

function normalizeAcquisitionRequest(input) {
  const value = object(input, "artifact acquisition request");
  const phase = string(value.phase, "artifact acquisition phase");
  if (phase !== "cold" && phase !== "session") throw new TypeError("artifact acquisition phase is invalid");
  return {
    profile_id: string(value.profile_id, "artifact acquisition profile_id"),
    phase,
    count: positiveInteger(value.count, "artifact acquisition count"),
  };
}

function certificateHash(value) {
  const encoded = string(value, "certificate_hash");
  if (!/^[A-Za-z0-9+/_-]{43}=?$/.test(encoded)) throw new TypeError("certificate_hash must encode a SHA-256 digest");
  const standard = encoded.replaceAll("-", "+").replaceAll("_", "/");
  if (Buffer.from(standard, "base64").length !== 32) throw new TypeError("certificate_hash must encode a SHA-256 digest");
  return encoded;
}

function namespace(value) {
  const name = string(value, "client namespace");
  if (!NETNS_PATTERN.test(name)) throw new TypeError("client namespace contains unsafe characters");
  return name;
}

function ipAddress(value, name) {
  const address = string(value, name);
  if (isIP(address) === 0) throw new TypeError(`${name} must be an IP address`);
  return address;
}

function httpURL(value, name) {
  let url;
  try {
    url = new URL(string(value, name));
  } catch {
    throw new TypeError(`${name} must be an absolute HTTP URL`);
  }
  if ((url.protocol !== "http:" && url.protocol !== "https:") || url.username !== "" || url.password !== "") {
    throw new TypeError(`${name} must be an absolute HTTP URL without credentials`);
  }
  return url.href;
}

function absolutePath(value, name) {
  const candidate = string(value, name);
  if (!path.isAbsolute(candidate)) throw new TypeError(`${name} must be absolute`);
  return candidate;
}

function object(value, name) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new TypeError(`${name} must be an object`);
  return value;
}

function string(value, name) {
  if (typeof value !== "string" || value.length === 0 || value.length > 4096) throw new TypeError(`${name} must be a non-empty string`);
  return value;
}

function positiveInteger(value, name) {
  return exactInteger(value, name, 1, Number.MAX_SAFE_INTEGER);
}

function exactInteger(value, name, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new TypeError(`${name} must be an integer in ${minimum}..${maximum}`);
  }
  return value;
}

function finiteNumber(value, name, minimum) {
  if (!Number.isFinite(value) || value < minimum) throw new TypeError(`${name} must be at least ${minimum}`);
  return value;
}

async function defaultWaitUntil(target, now) {
  const remaining = target - now();
  if (remaining > 0) await new Promise((resolve) => setTimeout(resolve, remaining));
}
