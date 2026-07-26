import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";

import { installWebTransportCertificateHash, navigateBrowserModule } from "./browser-release-collector.mjs";

import {
  acquireArtifactBatch,
  capacityStreamAssignments,
  chromiumCapacityLaunchOptions,
  chromiumLaunchOptions,
  commitArtifactSpend,
  createBrowserCapacityCloseBatcher,
  normalizeBrowserCapacityPlan,
  normalizeCollectorPlan,
  runOpenLoop,
} from "./browser-release-collector-core.mjs";

const forcedPlan = {
  schema_version: 1,
  topology: "browser_webtransport",
  profile_id: "clean-v1",
  run_number: 1,
  mode: "forced",
  artifact_source_url: "http://127.0.0.1:9000/artifacts",
  certificate_hash: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  client_netns: "flowersec-client-01",
  module_bind_address: "192.0.2.1",
  module_advertise_host: "192.0.2.1",
  cell_deadline_ms: 900_000,
  cold: {
    operations: 4,
    max_inflight: 2,
    start_rate_per_second: 100,
    operation_deadline_ms: 10_000,
    phase_deadline_ms: 30_000,
  },
  rpc: {
    operations: 4,
    workers: 2,
    request_bytes: 1024,
    operation_deadline_ms: 2_000,
    phase_deadline_ms: 10_000,
  },
  bulk: {
    warmup_bytes_per_direction: 1024,
    score_bytes_per_direction: 4096,
    phase_deadline_ms: 15_000,
  },
  cleanup_deadline_ms: 5_000,
};

test("normalizes only frozen Chromium WebTransport topologies", () => {
  const normalized = normalizeCollectorPlan(forcedPlan);
  assert.equal(normalized.topology, "browser_webtransport");
  assert.equal(normalized.cold.operations, 4);

  for (const topology of ["direct_quic", "ww", "browser_unknown"]) {
    assert.throws(
      () => normalizeCollectorPlan({ ...forcedPlan, topology }),
      /topology/,
    );
  }
});

test("adaptive_web accepts cold-only stages and rejects forced payload phases", () => {
  const adaptive = normalizeCollectorPlan({
    ...forcedPlan,
    topology: "adaptive_web",
    profile_id: "adaptive-selection-v1",
    mode: "adaptive",
    stages: [
      { profile_id: "clean-v1", cold: forcedPlan.cold, cleanup_deadline_ms: 5_000 },
      { profile_id: "mobile-v1", cold: { ...forcedPlan.cold, phase_deadline_ms: 150_000 }, cleanup_deadline_ms: 5_000 },
    ],
    rpc: undefined,
    bulk: undefined,
    cleanup_deadline_ms: undefined,
  });
  assert.equal(adaptive.stages.length, 2);
  assert.throws(
    () => normalizeCollectorPlan({ ...adaptive, rpc: forcedPlan.rpc }),
    /adaptive.*rpc/i,
  );
});

test("launches the actual Chromium process inside the named client netns", () => {
  const launcher = path.resolve("scripts/chromium-netns-launcher.sh");
  const options = chromiumLaunchOptions(
    normalizeCollectorPlan(forcedPlan),
    "/cache/playwright/chromium/chrome",
    launcher,
    "http://192.0.2.1:38123",
  );
  assert.equal(options.executablePath, launcher);
  assert.equal(options.env.FLOWERSEC_CLIENT_NETNS, "flowersec-client-01");
  assert.equal(options.env.FLOWERSEC_CHROMIUM_EXECUTABLE, "/cache/playwright/chromium/chrome");
  assert.equal(options.headless, true);
  assert.deepEqual(options.args, [
    "--unsafely-treat-insecure-origin-as-secure=http://192.0.2.1:38123",
    "--quic-client-connection-options=TBBR",
  ]);
  assert.throws(
    () => chromiumLaunchOptions(normalizeCollectorPlan({ ...forcedPlan, client_netns: "bad;namespace" }), "/chrome", launcher, "http://192.0.2.1:38123"),
    /namespace/,
  );
	assert.throws(
	  () => chromiumLaunchOptions(normalizeCollectorPlan(forcedPlan), "/chrome", launcher, "http://192.0.2.2:38123"),
	  /advertised IP/,
	);
});

test("freezes Chromium tunnel capacity at exactly 1000 live sessions", () => {
  const evidenceDirectory = path.resolve("capacity-evidence");
  const capacity = {
    schema_version: 1,
    topology: "browser_tunnel_wt_quic",
    profile_id: "capacity-tunnel-webtransport-quic-1000",
    sessions: 1000,
    certificate_hash: forcedPlan.certificate_hash,
    client_netns: forcedPlan.client_netns,
    module_bind_address: forcedPlan.module_bind_address,
    module_advertise_host: forcedPlan.module_advertise_host,
    control_bind_address: forcedPlan.module_bind_address,
    event_sink_url: "http://192.0.2.1:32123/events",
    evidence_directory: evidenceDirectory,
    operation_deadline_ms: 30_000,
  };
  const normalized = normalizeBrowserCapacityPlan(capacity);
  assert.equal(normalized.sessions, 1000);
  assert.throws(() => normalizeBrowserCapacityPlan({ ...capacity, sessions: 999 }), /1000/);
  assert.throws(() => normalizeBrowserCapacityPlan({ ...capacity, topology: "browser_webtransport" }), /capacity topology/);

  const options = chromiumCapacityLaunchOptions(
    normalized,
    "/cache/playwright/chromium/chrome",
    path.resolve("scripts/chromium-netns-launcher.sh"),
    "http://192.0.2.1:38123",
  );
  assert.equal(options.env.FLOWERSEC_CLIENT_NETNS, forcedPlan.client_netns);
  assert.ok(options.args.includes(`--log-net-log=${path.join(evidenceDirectory, "chromium-netlog.json")}`));
  assert.ok(options.args.includes("--net-log-capture-mode=IncludeSensitive"));
});

test("gives every WebTransport constructor an independent certificate hash buffer", async () => {
  let initScript;
  let initValue;
  await installWebTransportCertificateHash({
    addInitScript: async (script, value) => {
      initScript = script;
      initValue = value;
    },
  }, forcedPlan.certificate_hash);

  const original = globalThis.WebTransport;
  const instances = [];
  class NativeWebTransport {
    constructor(_url, options) {
      instances.push(options.serverCertificateHashes[0].value);
    }
  }
  try {
    globalThis.WebTransport = NativeWebTransport;
    initScript(initValue);
    const WrappedWebTransport = globalThis.WebTransport;
    new WrappedWebTransport("https://192.0.2.1:443");
    new WrappedWebTransport("https://192.0.2.1:443");
    assert.equal(instances.length, 2);
    assert.notStrictEqual(instances[0], instances[1]);
    instances[0][0] ^= 0xff;
    assert.notEqual(instances[0][0], instances[1][0]);
  } finally {
    if (original === undefined) delete globalThis.WebTransport;
    else globalThis.WebTransport = original;
  }
});

test("retries only transient initial module navigation failures", async () => {
  let attempts = 0;
  const waits = [];
  await navigateBrowserModule({
    goto: async () => {
      attempts++;
      if (attempts === 1) throw new Error("net::ERR_NETWORK_CHANGED");
    },
  }, "http://192.0.2.1:38123", async (milliseconds) => waits.push(milliseconds));
  assert.equal(attempts, 2);
  assert.deepEqual(waits, [250]);

  attempts = 0;
  await assert.rejects(
    navigateBrowserModule({
      goto: async () => {
        attempts++;
        throw new Error("net::ERR_CONNECTION_REFUSED");
      },
    }, "http://192.0.2.1:38123", async () => undefined),
    /ERR_CONNECTION_REFUSED/,
  );
  assert.equal(attempts, 1);
});

test("freezes Chromium stream capacity at 100 sessions and 128 streams each", () => {
  const plan = {
    schema_version: 1, workload: "stream_capacity", topology: "browser_webtransport",
    profile_id: "capacity-streams-webtransport-100x128", sessions: 100,
    connections_per_session: 1, streams_per_session: 128,
    certificate_hash: forcedPlan.certificate_hash, client_netns: forcedPlan.client_netns,
    module_bind_address: forcedPlan.module_bind_address, module_advertise_host: forcedPlan.module_advertise_host,
    control_bind_address: forcedPlan.module_bind_address, event_sink_url: "http://192.0.2.1:32123/events",
    evidence_directory: path.resolve("stream-capacity-evidence"), operation_deadline_ms: 60_000,
  };
  const normalized = normalizeBrowserCapacityPlan(plan);
  assert.equal(normalized.sessions * normalized.connections_per_session * normalized.streams_per_session, 12_800);
  assert.equal(normalized.stream_workers_per_session, 4);
  assert.throws(() => normalizeBrowserCapacityPlan({ ...plan, sessions: 101 }), /100/);
  assert.throws(() => normalizeBrowserCapacityPlan({ ...plan, streams_per_session: 127 }), /128/);
});

test("partitions all 128 capacity stream indexes across four bounded workers", () => {
  const assignments = capacityStreamAssignments(128, 4);
  assert.deepEqual(assignments.map((indexes) => indexes.length), [32, 32, 32, 32]);
  assert.deepEqual(assignments.flat().toSorted((left, right) => left - right), Array.from({ length: 128 }, (_, index) => index));
  assert.throws(() => capacityStreamAssignments(128, 0), /workers/);
  assert.throws(() => capacityStreamAssignments(3, 4), /workers/);
});

test("batches browser capacity closes into one browser-context operation", async () => {
  const scheduled = [];
  const batches = [];
  const closeSession = createBrowserCapacityCloseBatcher(async (batch) => {
    batches.push(batch);
  }, {
    schedule: (flush) => scheduled.push(flush),
  });
  const closes = Array.from({ length: 1000 }, (_, index) => closeSession({
    id: `session-${index + 1}`,
    token: `token-${index + 1}`,
  }));
  assert.equal(scheduled.length, 1);
  scheduled.shift()();
  await Promise.all(closes);
  assert.equal(batches.length, 1);
  assert.equal(batches[0].length, 1000);
  assert.equal(batches[0][999].id, "session-1000");
});

test("open-loop scheduler preserves ordinals, rate schedule, and inflight cap", async () => {
  let active = 0;
  let maximum = 0;
  const results = await runOpenLoop({
    operations: 8,
    maxInflight: 3,
    intervalMs: 1,
    now: (() => {
      let value = 0;
      return () => value++;
    })(),
    waitUntil: async () => undefined,
    operation: async (ordinal, scheduledAtMs) => {
      active++;
      maximum = Math.max(maximum, active);
      await Promise.resolve();
      active--;
      return { ordinal, scheduled_at_ms: scheduledAtMs };
    },
  });
  assert.deepEqual(results.map((entry) => entry.ordinal), [1, 2, 3, 4, 5, 6, 7, 8]);
  assert.ok(maximum <= 3, `maximum inflight ${maximum}`);
});

test("open-loop scheduler captures an early operation rejection", async () => {
  await assert.rejects(
    runOpenLoop({
      operations: 2,
      maxInflight: 1,
      intervalMs: 10,
      operation: async (ordinal) => {
        if (ordinal === 1) throw new Error("first operation failed");
        return ordinal;
      },
    }),
    /first operation failed/,
  );
});

test("acquires an exact fresh artifact batch from the runner-owned endpoint", async () => {
  let request;
  const artifacts = await acquireArtifactBatch(forcedPlan, {
    profile_id: "clean-v1",
    phase: "cold",
    count: 2,
  }, async (url, options) => {
    request = { url, options };
    return new Response(JSON.stringify({
      schema_version: 1,
      artifacts: [
        { artifact_json: "{\"version\":2}", spend_token: "spend-1" },
        { artifact_json: "{\"version\":2}", spend_token: "spend-2" },
      ],
    }), { status: 200, headers: { "content-type": "application/json" } });
  });

  assert.deepEqual(artifacts.map((item) => item.spend_token), ["spend-1", "spend-2"]);
  assert.equal(request.url, forcedPlan.artifact_source_url);
  assert.deepEqual(JSON.parse(request.options.body), {
    schema_version: 1,
    action: "acquire",
    topology: "browser_webtransport",
    profile_id: "clean-v1",
    run_number: 1,
    phase: "cold",
    count: 2,
  });

  await assert.rejects(
    acquireArtifactBatch(forcedPlan, {
      profile_id: "clean-v1",
      phase: "cold",
      count: 2,
    }, async () => new Response(JSON.stringify({
      schema_version: 1,
      artifacts: [
        { artifact_json: "{}", spend_token: "duplicate" },
        { artifact_json: "{}", spend_token: "duplicate" },
      ],
    }), { status: 200 })),
    /duplicate spend token/,
  );
});

test("commits artifact spend through the runner-owned endpoint", async () => {
  let request;
  await commitArtifactSpend(forcedPlan, "spend-1", async (url, options) => {
    request = { url, options };
    return new Response(null, { status: 204 });
  });
  assert.equal(request.url, forcedPlan.artifact_source_url);
  assert.deepEqual(JSON.parse(request.options.body), {
    schema_version: 1,
    action: "spend",
    spend_token: "spend-1",
  });
  await assert.rejects(
    commitArtifactSpend(forcedPlan, "spend-1", async () => new Response(null, { status: 409 })),
    /HTTP 409/,
  );
});
