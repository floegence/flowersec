import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";

import {
  chromiumLaunchOptions,
  normalizeRunnerPlan,
} from "./browser-test-runner-core.mjs";

const plan = {
  schema_version: 1,
  topology: "browser_webtransport",
  profile_id: "mobile-v1",
  run_number: 1,
  mode: "forced",
  cold_diagnostic: false,
  diagnostics_enabled: false,
  policy: "require_quic_family",
  artifact_source_url: "http://192.0.2.1:9000/artifacts",
  certificate_hash: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  client_netns: "flowersec-client-01",
  module_bind_address: "192.0.2.1",
  module_advertise_host: "192.0.2.1",
  output_directory: path.resolve("browser-acceptance-output"),
  cell_deadline_ms: 300_000,
  cold: {
    operations: 30,
    max_inflight: 30,
    start_rate_per_second: 15,
    operation_deadline_ms: 5_000,
    phase_deadline_ms: 7_000,
  },
  rpc: {
    operations: 60,
    workers: 20,
    request_bytes: 1024,
    operation_deadline_ms: 3_000,
    phase_deadline_ms: 5_000,
  },
  bulk: {
    warmup_bytes_per_direction: 65_536,
    score_bytes_per_direction: 262_144,
    phase_deadline_ms: 4_000,
  },
  cleanup_deadline_ms: 2_000,
};

test("acceptance launches Chromium without transport timeout tuning", () => {
  const normalized = normalizeRunnerPlan(plan);
  const options = chromiumLaunchOptions(
    normalized,
    "/cache/ms-playwright/chromium/chrome",
    path.resolve("scripts/chromium-netns-launcher.sh"),
    "http://192.0.2.1:38123",
  );
  assert.deepEqual(options.args, ["--unsafely-treat-insecure-origin-as-secure=http://192.0.2.1:38123"]);
  assert.doesNotMatch(options.args.join("\n"), /timeout|fieldtrial|quic-client-connection-options/i);
});

test("ordinary acceptance does not configure diagnostic output", () => {
  const options = chromiumLaunchOptions(
    normalizeRunnerPlan(plan),
    "/cache/ms-playwright/chromium/chrome",
    path.resolve("scripts/chromium-netns-launcher.sh"),
    "http://192.0.2.1:38123",
  );
  assert.doesNotMatch(options.args.join("\n"), /log-net-log|net-log-capture-mode|qlog/i);
});
