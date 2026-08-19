import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";

import {
  disableBrowserWebSocket,
  inspectFirefoxWebTransportCapability,
  navigateBrowserModule,
  runColdPhase,
  runSessionWorkload,
} from "./browser-test-runner.mjs";

import {
  acquireArtifactBatch,
  chromiumExecutablePath,
  chromiumLaunchOptions,
  commitArtifactSpend,
  firefoxExecutablePath,
  firefoxLaunchOptions,
  normalizeRunnerPlan,
  runOpenLoop,
  startArtifactPeer,
  verifyChromiumWebTransportCapability,
} from "./browser-test-runner-core.mjs";
import {
  capacityStreamAssignments,
  chromiumCapacityLaunchOptions,
  createBrowserCapacityCloseBatcher,
  normalizeBrowserCapacityPlan,
} from "./browser-capacity-runner-core.mjs";

test("configured Chromium overrides Playwright's bundled executable", () => {
  let fallbackCalls = 0;
  const playwright = { executablePath: () => { fallbackCalls++; return "/cache/playwright/chrome"; } };
  assert.equal(
    chromiumExecutablePath(playwright, { FLOWERSEC_CHROMIUM_EXECUTABLE: "/usr/bin/chromium-browser" }),
    "/usr/bin/chromium-browser",
  );
  assert.equal(fallbackCalls, 0);
  assert.equal(chromiumExecutablePath(playwright, {}), "/cache/playwright/chrome");
  assert.equal(fallbackCalls, 1);
  assert.throws(() => chromiumExecutablePath(playwright, { FLOWERSEC_CHROMIUM_EXECUTABLE: "chromium" }), /absolute/);
});

test("configured Firefox overrides Playwright's bundled executable", () => {
  let fallbackCalls = 0;
  const playwright = { executablePath: () => { fallbackCalls++; return "/cache/playwright/firefox"; } };
  assert.equal(
    firefoxExecutablePath(playwright, { FLOWERSEC_FIREFOX_EXECUTABLE: "/cache/firefox/firefox" }),
    "/cache/firefox/firefox",
  );
  assert.equal(fallbackCalls, 0);
  assert.equal(firefoxExecutablePath(playwright, {}), "/cache/playwright/firefox");
  assert.equal(fallbackCalls, 1);
  assert.throws(() => firefoxExecutablePath(playwright, { FLOWERSEC_FIREFOX_EXECUTABLE: "firefox" }), /absolute/);
});

const forcedPlan = {
  schema_version: 1,
  topology: "browser_webtransport",
  profile_id: "clean-v1",
  run_number: 1,
  mode: "forced",
  diagnostics_enabled: true,
  policy: "require_quic_family",
  artifact_source_url: "http://127.0.0.1:9000/artifacts",
  certificate_hash: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  client_netns: "flowersec-client-01",
  module_bind_address: "192.0.2.1",
  module_advertise_host: "192.0.2.1",
  output_directory: path.resolve("browser-test-output"),
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
  const normalized = normalizeRunnerPlan(forcedPlan);
  assert.equal(normalized.browser, "chromium");
  assert.equal(normalized.topology, "browser_webtransport");
  assert.equal(normalized.cold.operations, 4);
  assert.equal(normalized.policy, "require_quic_family");
  assert.throws(() => normalizeRunnerPlan({ ...forcedPlan, policy: "adaptive" }), /policy/);

  for (const topology of ["direct_quic", "ww", "browser_unknown"]) {
    assert.throws(
      () => normalizeRunnerPlan({ ...forcedPlan, topology }),
      /topology/,
    );
  }
});

test("Firefox selection preserves the Chromium workload and uses only its HTTPS launch adapter", () => {
  const chromiumPlan = normalizeRunnerPlan(forcedPlan);
  const firefoxPlan = normalizeRunnerPlan({ ...forcedPlan, browser: "firefox" });
  assert.deepEqual(
    { ...firefoxPlan, browser: "chromium" },
    chromiumPlan,
  );
  assert.throws(() => normalizeRunnerPlan({ ...forcedPlan, browser: "webkit" }), /browser/);

  const options = firefoxLaunchOptions(
    { ...forcedPlan, browser: "firefox" },
    "/cache/playwright/firefox/firefox",
    "https://192.0.2.1:38123",
  );
  assert.deepEqual(options, {
    headless: true,
    executablePath: "/cache/playwright/firefox/firefox",
  });
  assert.throws(
    () => firefoxLaunchOptions({ ...forcedPlan, browser: "firefox" }, "/cache/firefox", "http://192.0.2.1:38123"),
    /HTTPS/,
  );
});

test("cold diagnostic preserves the frozen cold workload and excludes post-connect phases", () => {
  const diagnostic = normalizeRunnerPlan({ ...forcedPlan, cold_diagnostic: true });
  assert.equal(diagnostic.cold_diagnostic, true);
  assert.equal(diagnostic.cold.operations, forcedPlan.cold.operations);
  assert.equal(diagnostic.rpc.operations, forcedPlan.rpc.operations);
  assert.equal(diagnostic.bulk.score_bytes_per_direction, forcedPlan.bulk.score_bytes_per_direction);

  const ordinary = normalizeRunnerPlan(forcedPlan);
  assert.equal(ordinary.cold_diagnostic, false);

  const runnerSource = readFileSync(new URL("./browser-test-runner.mjs", import.meta.url), "utf8");
  assert.match(runnerSource, /if \(!plan\.cold_diagnostic\) \{[\s\S]*runSessionWorkload/);
});

test("binds held-session establishment to the cold phase deadline", async () => {
  const plan = normalizeRunnerPlan({
    ...forcedPlan,
    cold: { ...forcedPlan.cold, operation_deadline_ms: 6_000 },
    rpc: { ...forcedPlan.rpc, phase_deadline_ms: 5_000 },
  });
  let payload;
  let evaluatorSource = "";
  const page = {
    evaluate: async (operation, value) => {
      evaluatorSource = operation.toString();
      payload = value;
      return {};
    },
  };

  await runSessionWorkload(page, {}, plan);
  assert.equal(payload.connectDeadlineMs, 30_000);
  assert.equal("policy" in payload, false);
  assert.match(
    evaluatorSource,
    /connect\(lease, \{ signal \}\)/,
  );
});

test("binds every cold connection to its operation deadline", async () => {
  const cold = {
    ...forcedPlan.cold,
    operations: 1,
    max_inflight: 1,
    operation_deadline_ms: 53_000,
    phase_deadline_ms: 55_000,
  };
  let payload;
  let evaluatorSource = "";
  const page = {
    evaluate: async (operation, value) => {
      evaluatorSource = operation.toString();
      payload = value;
      return {};
    },
  };

  await runColdPhase(page, [{ artifact_json: "{}", spend_token: "spend-1" }], cold, 12_000);
  assert.equal(payload.operationDeadlineMs, 53_000);
  assert.ok(payload.connectDeadlineMs > 0 && payload.connectDeadlineMs <= 53_000);
  assert.equal("policy" in payload, false);
  const timerIndex = evaluatorSource.indexOf("const timer = setTimeout");
  const peerReadyIndex = evaluatorSource.indexOf("await Promise.race([peerStart, peerStartDeadline])");
  const connectIndex = evaluatorSource.indexOf("sdk.connect");
  assert.ok(timerIndex >= 0 && timerIndex < peerReadyIndex, "peer start must consume the operation deadline");
  assert.ok(peerReadyIndex < connectIndex, "the paired leg must be ready before the browser candidate connects");
  assert.match(
    evaluatorSource,
    /connect\(lease, \{ signal: controller\.signal \}\)/,
  );
});

test("bounds peer startup before importing or dialing the browser candidate", async () => {
  const previousStart = globalThis.__flowersecStartArtifact;
  globalThis.__flowersecStartArtifact = () => new Promise(() => {});
  const page = {
    evaluate: async (operation, payload) => await operation(payload),
    close: async () => {},
  };
  try {
    await assert.rejects(
      runColdPhase(
        page,
        [{ artifact_json: "{}", spend_token: "spend-1" }],
        { operations: 1, max_inflight: 1, start_rate_per_second: 1, operation_deadline_ms: 20, phase_deadline_ms: 40 },
        10,
      ),
      /cold operation deadline exceeded/,
    );
  } finally {
    if (previousStart === undefined) delete globalThis.__flowersecStartArtifact;
    else globalThis.__flowersecStartArtifact = previousStart;
  }
});

test("reports the exact cold ordinal and elapsed time on first failure", async () => {
  const page = {
    evaluate: async () => { throw new Error("dial lost"); },
    close: async () => {},
  };
  await assert.rejects(
    runColdPhase(
      page,
      [{ artifact_json: "{}", spend_token: "spend-1" }],
      { operations: 1, max_inflight: 1, start_rate_per_second: 1, operation_deadline_ms: 20, phase_deadline_ms: 40 },
      10,
    ),
    /cold operation 1 failed elapsed_ms=\d+: dial lost/,
  );
});

test("cold phase drains post-connect work after every connection meets the phase deadline", async () => {
  const cold = {
    ...forcedPlan.cold,
    operations: 30,
    max_inflight: 30,
    start_rate_per_second: 750,
    operation_deadline_ms: 100,
    phase_deadline_ms: 140,
  };
  const startedAt = performance.now();
  const connectionCompletions = [];
  const connectBudgets = [];
  const pending = new Set();
  const page = {
    evaluate: async (_operation, value) => {
      const started = performance.now();
      connectBudgets.push(value.connectDeadlineMs);
      const task = new Promise((resolve) => {
        // The connection finishes inside its budget. Liveness and cleanup are
        // deliberately modeled after it so the last operation drains after
        // the connection phase boundary.
        setTimeout(() => {
          connectionCompletions.push(performance.now() - startedAt);
          setTimeout(resolve, 20);
        }, Math.max(1, value.connectDeadlineMs - 15));
      });
      pending.add(task);
      try {
        await task;
        return {};
      } finally {
        pending.delete(task);
      }
    },
    close: async () => {
      throw new Error("page closed while compliant cold operations were draining");
    },
  };

  await runColdPhase(
    page,
    Array.from({ length: cold.operations }, (_, index) => ({
      artifact_json: "{}",
      spend_token: `spend-${index + 1}`,
    })),
    cold,
    20,
  );

  assert.equal(pending.size, 0);
  assert.equal(connectionCompletions.length, cold.operations);
  assert.ok(Math.max(...connectionCompletions) <= cold.phase_deadline_ms);
  assert.ok(connectBudgets.every((budget) => budget > 0 && budget <= cold.operation_deadline_ms));
});

test("records only the public v3 connect classification before preserving the failure", async () => {
  let evaluatorSource = "";
  const page = {
    evaluate: async (operation) => {
      evaluatorSource = operation.toString();
      return {};
    },
  };

  await runColdPhase(
    page,
    [{ artifact_json: "{}", spend_token: "spend-1" }],
    { ...forcedPlan.cold, operations: 1, max_inflight: 1 },
    5_000,
  );
  assert.match(evaluatorSource, /error instanceof sdk\.ConnectError/);
  assert.match(evaluatorSource, /__flowersecRecordDiagnostic/);
  assert.match(evaluatorSource, /error\.disposition\.kind/);
  assert.match(evaluatorSource, /throw error/);
  assert.doesNotMatch(evaluatorSource, /connectErrorDetailsInternal|internal_code|candidates|candidateId|normalized_url/);
  const runnerSource = readFileSync(new URL("./browser-test-runner.mjs", import.meta.url), "utf8");
  assert.match(runnerSource, /exposeBinding\("__flowersecRecordDiagnostic"/);
});

test("production browser runners leave WebTransport certificate options to the SDK", () => {
  const runnerSource = readFileSync(new URL("./browser-test-runner.mjs", import.meta.url), "utf8");
  const capacitySource = readFileSync(new URL("./browser-capacity-controller.mjs", import.meta.url), "utf8");
  const v3PlaywrightSource = readFileSync(new URL("../browser-e2e/transport-v3.spec.ts", import.meta.url), "utf8");
  for (const source of [runnerSource, capacitySource, v3PlaywrightSource]) {
    assert.doesNotMatch(source, /serverCertificateHashes/);
    assert.doesNotMatch(source, /globalThis\.WebTransport\s*=/);
  }
});

test("uses one native bidirectional stream for both bulk directions", async () => {
  let evaluatorSource = "";
  const page = {
    evaluate: async (operation) => {
      evaluatorSource = operation.toString();
      return {};
    },
  };

  await runSessionWorkload(page, {}, normalizeRunnerPlan(forcedPlan));
  assert.match(
    evaluatorSource,
    /const outgoingWrite = writeExact\(outgoing,[\s\S]*Promise\.all\(\[[\s\S]*outgoingWrite,[\s\S]*readExact\(outgoing,/,
  );
  assert.doesNotMatch(evaluatorSource, /activeSession\.acceptStream|incoming\.stream/);
  assert.doesNotMatch(evaluatorSource, /finally\s*{[\s\S]*outgoing\.close\(\)/);
});

test("resets the same bidirectional stream after a bulk failure", async () => {
  let evaluatorSource = "";
  const page = {
    evaluate: async (operation) => {
      evaluatorSource = operation.toString();
      return {};
    },
  };

  await runSessionWorkload(page, {}, normalizeRunnerPlan(forcedPlan));
  assert.match(
    evaluatorSource,
    /catch \(error\) \{[\s\S]*Promise\.allSettled\(\[outgoingWrite, outgoing\.reset\(\)\]\)/,
  );
});

test("opens each browser bulk phase only after the previous phase completes", async () => {
  let evaluatorSource = "";
  const page = {
    evaluate: async (operation) => {
      evaluatorSource = operation.toString();
      return {};
    },
  };

  await runSessionWorkload(page, {}, normalizeRunnerPlan(forcedPlan));
  assert.match(
    evaluatorSource,
    /const warmupOutgoing = await prepareTransfer[\s\S]*await transfer\(activeSession, warmupOutgoing,[\s\S]*const scoreOutgoing = await prepareTransfer[\s\S]*await transfer\(activeSession, scoreOutgoing,/,
  );
  assert.doesNotMatch(evaluatorSource, /scoreOutgoingPromise|scorePrepareController/);
});

test("constructs opaque stream metadata through the public browser API", async () => {
  let evaluatorSource = "";
  const page = {
    evaluate: async (operation) => {
      evaluatorSource = operation.toString();
      return {};
    },
  };

  await runSessionWorkload(page, {}, normalizeRunnerPlan(forcedPlan));
  assert.match(evaluatorSource, /sdk\.createStreamMetadata\(\{ stream_index: index \}\)/);
  assert.match(evaluatorSource, /sdk\.createStreamMetadata\(\{ direction: "client-to-server" \}\)/);

  const capacitySource = readFileSync(new URL("./browser-capacity-controller.mjs", import.meta.url), "utf8");
  assert.match(
    capacitySource,
    /sdk\.createStreamMetadata\(\{ session_index: sessionIndex, stream_index: streamIndex \}\)/,
  );
  assert.match(capacitySource, /__flowersecCapacityRecordDiagnostic/);
  assert.match(capacitySource, /browserDiagnostics/);
  assert.match(capacitySource, /session\.waitTermination\(\)/);
  assert.doesNotMatch(capacitySource, /waitClosed/);
  assert.doesNotMatch(capacitySource, /openStream\([^\n]+\{ metadata: \{/);
});

test("passes explicit response decoders before browser RPC abort signals", async () => {
  let evaluatorSource = "";
  const page = {
    evaluate: async (operation) => {
      evaluatorSource = operation.toString();
      return {};
    },
  };

  await runSessionWorkload(page, {}, normalizeRunnerPlan(forcedPlan));
  assert.match(
    evaluatorSource,
    /activeSession\.rpc\.call\(\s*1,\s*payload,\s*decodeRPCString,\s*operationController\.signal,?\s*\)/,
  );
  assert.match(
    evaluatorSource,
    /activeSession\.rpc\.call\(\s*1,\s*"native-isolation-survivor",\s*decodeRPCString,\s*phaseSignal,?\s*\)/,
  );
  assert.match(evaluatorSource, /function decodeRPCString\(value\)[\s\S]*typeof value !== "string"/);
});

test("adaptive_web accepts cold-only stages and rejects forced payload phases", () => {
  const adaptive = normalizeRunnerPlan({
    ...forcedPlan,
    topology: "adaptive_web",
    profile_id: "adaptive-selection-v1",
    mode: "adaptive",
    policy: "adaptive",
    stages: [
      { profile_id: "clean-v1", cold: forcedPlan.cold, cleanup_deadline_ms: 5_000 },
      { profile_id: "periodic-loss-v1", cold: { ...forcedPlan.cold, phase_deadline_ms: 150_000 }, cleanup_deadline_ms: 5_000 },
    ],
    rpc: undefined,
    bulk: undefined,
    cleanup_deadline_ms: undefined,
  });
  assert.equal(adaptive.stages.length, 2);
  assert.throws(
    () => normalizeRunnerPlan({ ...adaptive, rpc: forcedPlan.rpc }),
    /adaptive.*rpc/i,
  );
});

test("launches the actual Chromium process inside the named client netns", () => {
  const launcher = path.resolve("scripts/chromium-netns-launcher.sh");
  const options = chromiumLaunchOptions(
    normalizeRunnerPlan(forcedPlan),
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
    `--log-net-log=${path.resolve("browser-test-output", "chromium-netlog.json")}`,
    "--net-log-capture-mode=IncludeSensitive",
  ]);
  assert.throws(
    () => chromiumLaunchOptions(normalizeRunnerPlan({ ...forcedPlan, client_netns: "bad;namespace" }), "/chrome", launcher, "http://192.0.2.1:38123"),
    /namespace/,
  );
  assert.throws(
    () => chromiumLaunchOptions(normalizeRunnerPlan(forcedPlan), "/chrome", launcher, "http://192.0.2.2:38123"),
    /advertised IP/,
  );
});

test("does not tune Chromium transport timeouts", () => {
  const plan = normalizeRunnerPlan({ ...forcedPlan, diagnostics_enabled: false });
  const options = chromiumLaunchOptions(
    plan,
    "/cache/playwright/chromium/chrome",
    path.resolve("scripts/chromium-netns-launcher.sh"),
    "http://192.0.2.1:38123",
  );
  assert.deepEqual(options.args, ["--unsafely-treat-insecure-origin-as-secure=http://192.0.2.1:38123"]);
  assert.doesNotMatch(options.args.join("\n"), /timeout|fieldtrial|quic-client-connection-options/i);
});

test("ordinary acceptance launches Chromium without qlog or netlog outputs", () => {
  const plan = normalizeRunnerPlan({ ...forcedPlan, diagnostics_enabled: false });
  const options = chromiumLaunchOptions(
    plan,
    "/cache/playwright/chromium/chrome",
    path.resolve("scripts/chromium-netns-launcher.sh"),
    "http://192.0.2.1:38123",
  );
  assert.doesNotMatch(options.args.join("\n"), /log-net-log|net-log-capture-mode|qlog/i);
});

test("freezes Chromium tunnel capacity at exactly 1000 live sessions", () => {
  const outputDirectory = path.resolve("capacity-output");
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
    output_directory: outputDirectory,
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
    "https://192.0.2.1:38123",
  );
  assert.equal(options.env.FLOWERSEC_CLIENT_NETNS, forcedPlan.client_netns);
  assert.ok(!options.args.some((argument) => argument.startsWith("--unsafely-treat-insecure-origin-as-secure=")));
  assert.ok(options.args.includes(`--log-net-log=${path.join(outputDirectory, "chromium-netlog.json")}`));
  assert.ok(options.args.includes("--net-log-capture-mode=IncludeSensitive"));
});

test("can disable the competing WebSocket candidate without replacing WebTransport", async () => {
  let initScript;
  await disableBrowserWebSocket({
    addInitScript: async (script) => {
      initScript = script;
    },
  });

  const originalWebTransport = globalThis.WebTransport;
  const originalWebSocket = globalThis.WebSocket;
  class NativeWebTransport {}
  try {
    globalThis.WebTransport = NativeWebTransport;
    globalThis.WebSocket = class WebSocket {};
    initScript();
    assert.equal(globalThis.WebSocket, undefined);
    assert.equal(globalThis.WebTransport, NativeWebTransport);
  } finally {
    if (originalWebTransport === undefined) delete globalThis.WebTransport;
    else globalThis.WebTransport = originalWebTransport;
    if (originalWebSocket === undefined) delete globalThis.WebSocket;
    else globalThis.WebSocket = originalWebSocket;
  }
});

test("Firefox runtime canary requires the complete WebTransport lifecycle surface", async () => {
  let origin;
  const result = await inspectFirefoxWebTransportCapability({
    evaluate: async (_source, value) => {
      origin = value;
      return {
        secure_context: true,
        webtransport: "function",
        bidirectional_stream: true,
        datagrams: true,
        closed: true,
      };
    },
  }, "https://198.18.0.1:38123");
  assert.equal(origin, "https://198.18.0.1:38123");
  assert.equal(result.closed, true);
  await assert.rejects(
    inspectFirefoxWebTransportCapability({ evaluate: async () => ({ secure_context: true, webtransport: "function", bidirectional_stream: false, datagrams: true, closed: true }) }, "http://198.18.0.1:38123"),
    /HTTPS/,
  );
});

test("preflight requires WebTransport in a secure non-loopback browser origin", async () => {
  const launches = [];
  let closed = 0;
  const chromium = {
    async launch(options) {
      launches.push(options);
      return {
        async newPage() {
          return {
            async route(pattern, handler) {
              assert.equal(pattern, "http://198.18.0.1:38123/**");
              await handler({ fulfill: async () => {} });
            },
            async goto(url) { assert.equal(url, "http://198.18.0.1:38123/"); },
            async evaluate() { return { secureContext: true, webTransport: "function" }; },
          };
        },
        async close() { closed++; },
      };
    },
  };
  assert.deepEqual(
    await verifyChromiumWebTransportCapability(chromium, "/cache/ms-playwright/chrome"),
    { secure_context: true, webtransport: "function" },
  );
  assert.equal(launches[0].executablePath, "/cache/ms-playwright/chrome");
  assert.ok(launches[0].args.includes("--unsafely-treat-insecure-origin-as-secure=http://198.18.0.1:38123"));
  assert.equal(closed, 1);

  chromium.launch = async () => ({
    newPage: async () => ({
      route: async () => {},
      goto: async () => {},
      evaluate: async () => ({ secureContext: false, webTransport: "undefined" }),
    }),
    close: async () => { closed++; },
  });
  await assert.rejects(
    verifyChromiumWebTransportCapability(chromium, "/cache/ms-playwright/chrome"),
    /secure non-loopback origin with WebTransport/,
  );
  assert.equal(closed, 2);
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
    output_directory: path.resolve("stream-capacity-output"), operation_deadline_ms: 60_000,
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

test("open-loop scheduler aborts sibling operations after the first failure", async () => {
  let siblingStarted;
  const siblingReady = new Promise((resolve) => { siblingStarted = resolve; });
  let siblingSignal;
  const loop = runOpenLoop({
    operations: 2,
    maxInflight: 2,
    intervalMs: 0,
    waitUntil: async () => undefined,
    operation: async (ordinal, _scheduledAtMs, signal) => {
      if (ordinal === 1) {
        await siblingReady;
        throw new Error("first operation failed");
      }
      siblingStarted();
      if (signal === undefined) return await new Promise(() => undefined);
      siblingSignal = signal;
      await new Promise((_, reject) => {
        const abort = () => reject(signal.reason);
        signal.addEventListener("abort", abort, { once: true });
        if (signal.aborted) abort();
      });
    },
  });
  await assert.rejects(
    Promise.race([
      loop,
      new Promise((_, reject) => setTimeout(() => reject(new Error("open-loop siblings were not aborted")), 100)),
    ]),
    /first operation failed/,
  );
  assert.equal(siblingSignal?.aborted, true);
});

test("open-loop scheduler preserves the parent phase abort reason", async () => {
  const phase = new AbortController();
  const loop = runOpenLoop({
    operations: 1,
    maxInflight: 1,
    intervalMs: 0,
    signal: phase.signal,
    waitUntil: async () => undefined,
    operation: async (_ordinal, _scheduledAtMs, signal) => {
      await new Promise((_, reject) => {
        const abort = () => reject(new Error("page closed after abort"));
        signal.addEventListener("abort", abort, { once: true });
        if (signal.aborted) abort();
      });
    },
  });
  phase.abort(new Error("cold phase deadline exceeded"));
  await assert.rejects(loop, /cold phase deadline exceeded/);
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

test("starts the paired artifact leg through the runner-owned endpoint", async () => {
  let request;
  await startArtifactPeer(forcedPlan, "spend-1", async (url, options) => {
    request = { url, options };
    return new Response(null, { status: 204 });
  });
  assert.equal(request.url, forcedPlan.artifact_source_url);
  assert.deepEqual(JSON.parse(request.options.body), {
    schema_version: 1,
    action: "start",
    spend_token: "spend-1",
  });
  await assert.rejects(
    startArtifactPeer(forcedPlan, "spend-1", async () => new Response(null, { status: 409 })),
    /HTTP 409/,
  );
});
