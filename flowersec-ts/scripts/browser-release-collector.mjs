#!/usr/bin/env node

import { promises as fs } from "node:fs";
import http from "node:http";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import { chromium } from "playwright";

import {
  acquireArtifactBatch,
  chromiumLaunchOptions,
  commitArtifactSpend,
  normalizeCollectorPlan,
  runOpenLoop,
} from "./browser-release-collector-core.mjs";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const launcherPath = path.join(packageRoot, "scripts", "chromium-netns-launcher.sh");

export async function collectBrowserReleaseWorkload(input, dependencies = {}) {
  const plan = normalizeCollectorPlan(input);
  const playwright = dependencies.chromium ?? chromium;
  const fetchImpl = dependencies.fetch ?? globalThis.fetch;
  const startedAt = new Date();
  const report = {
    schema_version: 1,
    classification: "raw_browser_transport_workload",
    status: "failed",
    topology: plan.topology,
    profile_id: plan.profile_id,
    run_number: plan.run_number,
    started_at: startedAt.toISOString(),
    finished_at: startedAt.toISOString(),
    browser: { engine: "chromium", version: "" },
    spend_count: 0,
  };
  let site;
  let browser;
  let phase = "setup";
  const ledger = createSpendLedger(plan, fetchImpl);
  try {
    if (process.platform !== "linux") throw new Error("browser release collection requires Linux");
    site = await startBrowserModuleSite(plan.module_bind_address, plan.module_advertise_host);
    browser = await playwright.launch(chromiumLaunchOptions(plan, playwright.executablePath(), launcherPath, site.origin));
    report.browser.version = browser.version();
    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    const page = await context.newPage();
    await page.exposeBinding("__flowersecCommitArtifactSpend", async (_source, token) => {
      await ledger.commit(token);
    });
    await installWebTransportCertificateHash(page, plan.certificate_hash);
    await page.goto(site.origin, { waitUntil: "networkidle" });

    const execute = async () => {
      if (plan.mode === "adaptive") {
        report.stages = [];
        for (const stage of plan.stages) {
          phase = `cold:${stage.profile_id}`;
          const artifacts = await acquireArtifactBatch(plan, {
            profile_id: stage.profile_id,
            phase: "cold",
            count: stage.cold.operations,
          }, fetchImpl);
          ledger.admit(artifacts);
          report.stages.push({
            profile_id: stage.profile_id,
            cold: await runColdPhase(page, artifacts, stage.cold, stage.cleanup_deadline_ms),
          });
        }
      } else {
        phase = "cold";
        const coldArtifacts = await acquireArtifactBatch(plan, {
          profile_id: plan.profile_id,
          phase: "cold",
          count: plan.cold.operations,
        }, fetchImpl);
        ledger.admit(coldArtifacts);
        report.cold = await runColdPhase(page, coldArtifacts, plan.cold, plan.cleanup_deadline_ms);

        phase = "session";
        const sessionArtifacts = await acquireArtifactBatch(plan, {
          profile_id: plan.profile_id,
          phase: "session",
          count: 1,
        }, fetchImpl);
        ledger.admit(sessionArtifacts);
        const workload = await runSessionWorkload(page, sessionArtifacts[0], plan);
        report.rpc = workload.rpc;
        report.bulk = workload.bulk;
        report.cleanup_duration_ns = workload.cleanup_duration_ns;
      }
    };
    await withTimeout(execute(), plan.cell_deadline_ms, "cell deadline");
    ledger.assertFullySpent();
    report.spend_count = ledger.spendCount;
    report.status = "passed";
  } catch (error) {
    report.spend_count = ledger.spendCount;
    report.failure = failureDetails(phase, error);
  } finally {
    phase = "cleanup";
    const cleanupErrors = [];
    if (browser !== undefined) {
      try {
        await browser.close();
      } catch (error) {
        cleanupErrors.push(error);
      }
    }
    if (site !== undefined) {
      try {
        await site.close();
      } catch (error) {
        cleanupErrors.push(error);
      }
    }
    if (cleanupErrors.length > 0) {
      report.status = "failed";
      report.failure = failureDetails(phase, new AggregateError(cleanupErrors, "collector cleanup failed"));
    }
    report.finished_at = new Date().toISOString();
  }
  return report;
}

async function runColdPhase(page, artifacts, cold, cleanupDeadlineMs) {
  return await withTimeout(runOpenLoop({
    operations: cold.operations,
    maxInflight: cold.max_inflight,
    intervalMs: 1_000 / cold.start_rate_per_second,
    operation: async (ordinal, scheduledAtMs) => {
      const scheduledAt = new Date(Date.now() - (performance.now() - scheduledAtMs)).toISOString();
      return await page.evaluate(async ({ item, ordinalValue, scheduledAtValue, operationDeadlineMs, cleanupMs }) => {
        const sdk = await import("/dist/browser/index.js");
        const lease = sdk.createArtifactLeaseV2(
          sdk.parseArtifact(item.artifact_json),
          async () => await globalThis.__flowersecCommitArtifactSpend(item.spend_token),
        );
        const startedAt = new Date().toISOString();
        const started = performance.now();
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(new Error("cold operation deadline exceeded")), operationDeadlineMs);
        let session;
        try {
          session = await sdk.connectBrowserSessionV2(lease, { signal: controller.signal });
        } finally {
          clearTimeout(timer);
        }
        const durationNs = Math.max(1, Math.round((performance.now() - started) * 1_000_000));
        const cleanupStarted = performance.now();
        await Promise.race([
          session.close(),
          new Promise((_, reject) => setTimeout(() => reject(new Error("cold cleanup deadline exceeded")), cleanupMs)),
        ]);
        return {
          ordinal: ordinalValue,
          scheduled_at: scheduledAtValue,
          started_at: startedAt,
          duration_ns: durationNs,
          cleanup_duration_ns: Math.max(1, Math.round((performance.now() - cleanupStarted) * 1_000_000)),
        };
      }, {
        item: artifacts[ordinal - 1],
        ordinalValue: ordinal,
        scheduledAtValue: scheduledAt,
        operationDeadlineMs: cold.operation_deadline_ms,
        cleanupMs: cleanupDeadlineMs,
      });
    },
  }), cold.phase_deadline_ms, "cold phase deadline");
}

async function runSessionWorkload(page, artifact, plan) {
  return await page.evaluate(async ({ item, rpcPlan, bulkPlan, cleanupDeadlineMs }) => {
    const sdk = await import("/dist/browser/index.js");
    const lease = sdk.createArtifactLeaseV2(
      sdk.parseArtifact(item.artifact_json),
      async () => await globalThis.__flowersecCommitArtifactSpend(item.spend_token),
    );
    let session;
    try {
      session = await withSignalDeadline(
        (signal) => sdk.connectBrowserSessionV2(lease, { signal }),
        rpcPlan.phase_deadline_ms,
        "session connect deadline exceeded",
      );
      const rpc = await withSignalDeadline(
        (phaseSignal) => runRPC(session, rpcPlan, phaseSignal),
        rpcPlan.phase_deadline_ms,
        "RPC phase deadline exceeded",
      );
      const bulk = await withSignalDeadline(
        (phaseSignal) => runBulk(session, bulkPlan, phaseSignal),
        bulkPlan.phase_deadline_ms,
        "bulk phase deadline exceeded",
      );
      const cleanupStarted = performance.now();
      await Promise.race([
        session.close(),
        new Promise((_, reject) => setTimeout(() => reject(new Error("session cleanup deadline exceeded")), cleanupDeadlineMs)),
      ]);
      session = undefined;
      return {
        rpc,
        bulk,
        cleanup_duration_ns: Math.max(1, Math.round((performance.now() - cleanupStarted) * 1_000_000)),
      };
    } finally {
      if (session !== undefined) await session.close().catch(() => undefined);
    }

    async function runRPC(activeSession, config, phaseSignal) {
      const payload = "x".repeat(config.request_bytes - 2);
      const encoded = new TextEncoder().encode(JSON.stringify(payload));
      if (encoded.byteLength !== config.request_bytes) throw new Error("RPC request does not match the requested byte count");
      const digest = await sha256(encoded);
      const records = new Array(config.operations);
      let nextOrdinal = 1;
      const workers = Array.from({ length: config.workers }, async () => {
        while (true) {
          const ordinal = nextOrdinal++;
          if (ordinal > config.operations) return;
          if (phaseSignal.aborted) throw phaseSignal.reason;
          const startedAt = new Date().toISOString();
          const started = performance.now();
          const operationController = new AbortController();
          const forwardAbort = () => operationController.abort(phaseSignal.reason);
          phaseSignal.addEventListener("abort", forwardAbort, { once: true });
          const timer = setTimeout(
            () => operationController.abort(new Error("RPC operation deadline exceeded")),
            config.operation_deadline_ms,
          );
          try {
            const response = await activeSession.rpc.call(1, payload, operationController.signal);
            if (response.error !== undefined || response.payload !== payload) throw new Error("RPC echo payload mismatch");
            const output = new TextEncoder().encode(JSON.stringify(response.payload));
            if (output.byteLength !== config.request_bytes) throw new Error("RPC response byte count mismatch");
            records[ordinal - 1] = {
              ordinal,
              started_at: startedAt,
              duration_ns: Math.max(1, Math.round((performance.now() - started) * 1_000_000)),
              input_bytes: encoded.byteLength,
              output_bytes: output.byteLength,
              payload_sha256: digest,
            };
          } finally {
            clearTimeout(timer);
            phaseSignal.removeEventListener("abort", forwardAbort);
          }
        }
      });
      await Promise.all(workers);
      return records;
    }

    async function runBulk(activeSession, config, phaseSignal) {
      await transfer(activeSession, config.warmup_bytes_per_direction, phaseSignal);
      const result = await transfer(activeSession, config.score_bytes_per_direction, phaseSignal);
      return {
        started_at: result.started_at,
        duration_ns: result.duration_ns,
        bytes_per_direction: config.score_bytes_per_direction,
      };
    }

    async function transfer(activeSession, byteCount, signal) {
      const accepting = activeSession.acceptStream({ signal });
      const outgoing = await activeSession.openStream("release-bulk", {
        metadata: { direction: "client-to-server" },
        signal,
      });
      let incoming;
      try {
        incoming = await accepting;
        if (incoming.kind !== "release-bulk" || incoming.metadata.direction !== "server-to-client") {
          throw new Error("bulk stream metadata mismatch");
        }
        const startedAt = new Date().toISOString();
        const started = performance.now();
        await Promise.all([
          writeExact(outgoing, byteCount, 0xa5, signal),
          readExact(incoming.stream, byteCount, 0x5a, signal),
        ]);
        return {
          started_at: startedAt,
          duration_ns: Math.max(1, Math.round((performance.now() - started) * 1_000_000)),
        };
      } catch (error) {
        await Promise.allSettled([outgoing.reset(), incoming?.stream.reset()]);
        throw error;
      } finally {
        await Promise.allSettled([outgoing.close(), incoming?.stream.close()]);
      }
    }

    async function writeExact(stream, total, fill, signal) {
      const chunk = new Uint8Array(32 * 1024).fill(fill);
      let remaining = total;
      while (remaining > 0) {
        const current = chunk.subarray(0, Math.min(chunk.byteLength, remaining));
        const written = await stream.write(current, { signal });
        if (written !== current.byteLength) throw new Error("bulk stream short write");
        remaining -= written;
      }
      await stream.closeWrite();
    }

    async function readExact(stream, total, fill, signal) {
      let remaining = total;
      while (remaining > 0) {
        const chunk = await stream.read({ signal });
        if (chunk === null || chunk.byteLength === 0 || chunk.byteLength > remaining) {
          throw new Error("bulk stream byte count mismatch");
        }
        for (const value of chunk) if (value !== fill) throw new Error("bulk stream payload mismatch");
        remaining -= chunk.byteLength;
      }
      if (await stream.read({ signal }) !== null) throw new Error("bulk stream did not end at the exact byte count");
    }

    async function sha256(value) {
      const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", value));
      return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
    }

    async function withSignalDeadline(operation, milliseconds, message) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(new Error(message)), milliseconds);
      try {
        return await operation(controller.signal);
      } finally {
        clearTimeout(timer);
      }
    }
  }, {
    item: artifact,
    rpcPlan: plan.rpc,
    bulkPlan: plan.bulk,
    cleanupDeadlineMs: plan.cleanup_deadline_ms,
  });
}

function createSpendLedger(plan, fetchImpl) {
  const admitted = new Set();
  const spent = new Set();
  return {
    get spendCount() { return spent.size; },
    admit(artifacts) {
      for (const artifact of artifacts) {
        if (admitted.has(artifact.spend_token)) throw new Error("artifact spend token was issued more than once");
        admitted.add(artifact.spend_token);
      }
    },
    async commit(token) {
      if (typeof token !== "string" || !admitted.has(token)) throw new Error("browser attempted to spend an unknown artifact");
      if (spent.has(token)) throw new Error("browser attempted to spend an artifact more than once");
      await commitArtifactSpend(plan, token, fetchImpl);
      spent.add(token);
    },
    assertFullySpent() {
      if (spent.size !== admitted.size) throw new Error(`artifact spend count ${spent.size} does not match acquired count ${admitted.size}`);
    },
  };
}

async function startBrowserModuleSite(bindAddress, advertiseHost) {
  const distRoot = path.join(packageRoot, "dist");
  const nobleRoot = path.join(packageRoot, "node_modules", "@noble");
  const server = http.createServer(async (request, response) => {
    try {
      const url = new URL(request.url ?? "/", "http://invalid.invalid");
      if (url.pathname === "/") return respond(response, 200, "text/html; charset=utf-8", browserPage());
      if (url.pathname.startsWith("/dist/")) {
        return await serveFile(response, distRoot, url.pathname.slice(6), false);
      }
      if (url.pathname.startsWith("/node_modules/@noble/")) {
        return await serveFile(response, nobleRoot, url.pathname.slice(21), true);
      }
      response.writeHead(404).end();
    } catch {
      response.writeHead(404).end();
    }
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, bindAddress, resolve);
  });
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("browser module server did not bind TCP");
  const host = advertiseHost.includes(":") ? `[${advertiseHost}]` : advertiseHost;
  let closing;
  return {
    origin: `http://${host}:${address.port}`,
    close() {
      closing ??= new Promise((resolve, reject) => {
        server.close((error) => error === undefined ? resolve() : reject(error));
        server.closeAllConnections?.();
      });
      return closing;
    },
  };
}

async function serveFile(response, root, encodedRelative, allowExtensionFallback) {
  const relative = decodeURIComponent(encodedRelative);
  let file = path.resolve(root, relative);
  if (!file.startsWith(`${root}${path.sep}`)) return response.writeHead(404).end();
  let contents;
  try {
    contents = await fs.readFile(file);
  } catch (error) {
    if (!allowExtensionFallback || path.extname(file) !== "" || error?.code !== "ENOENT") throw error;
    file += ".js";
    contents = await fs.readFile(file);
  }
  respond(response, 200, file.endsWith(".json") ? "application/json; charset=utf-8" : "text/javascript; charset=utf-8", contents);
}

function respond(response, status, contentType, body) {
  response.writeHead(status, { "cache-control": "no-store", "content-type": contentType });
  response.end(body);
}

function browserPage() {
  return `<!doctype html>
<html><head><meta charset="utf-8"><title>Flowersec release collector</title>
<script type="importmap">{"imports":{
"@noble/ciphers/aes":"/node_modules/@noble/ciphers/esm/aes.js",
"@noble/ciphers/crypto":"/node_modules/@noble/ciphers/esm/crypto.js",
"@noble/ciphers/":"/node_modules/@noble/ciphers/esm/",
"@noble/curves/ed25519":"/node_modules/@noble/curves/esm/ed25519.js",
"@noble/curves/p256":"/node_modules/@noble/curves/esm/p256.js",
"@noble/curves/":"/node_modules/@noble/curves/esm/",
"@noble/hashes/hkdf":"/node_modules/@noble/hashes/esm/hkdf.js",
"@noble/hashes/hmac":"/node_modules/@noble/hashes/esm/hmac.js",
"@noble/hashes/sha256":"/node_modules/@noble/hashes/esm/sha256.js",
"@noble/hashes/utils":"/node_modules/@noble/hashes/esm/utils.js",
"@noble/hashes/":"/node_modules/@noble/hashes/esm/"}}</script>
</head><body></body></html>`;
}

async function installWebTransportCertificateHash(page, encodedHash) {
  await page.addInitScript((value) => {
    const NativeWebTransport = globalThis.WebTransport;
    const standard = value.replaceAll("-", "+").replaceAll("_", "/");
    const padded = standard + "=".repeat((4 - (standard.length % 4)) % 4);
    const hash = Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
    globalThis.WebTransport = class extends NativeWebTransport {
      constructor(url, options) {
        super(url, { ...options, serverCertificateHashes: [{ algorithm: "sha-256", value: hash }] });
      }
    };
  }, encodedHash);
}

function withTimeout(promise, milliseconds, name) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`${name} exceeded`)), milliseconds); }),
  ]).finally(() => clearTimeout(timer));
}

function failureDetails(phase, error) {
  return {
    phase,
    name: error instanceof Error ? error.name : "Error",
    message: error instanceof Error ? error.message : String(error),
  };
}

async function main(args) {
  const { planPath, resultPath } = parseArguments(args);
  const raw = await fs.readFile(planPath, "utf8");
  const report = await collectBrowserReleaseWorkload(JSON.parse(raw));
  await fs.writeFile(resultPath, `${JSON.stringify(report, null, 2)}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
  if (report.status !== "passed") throw new Error(`browser release collection failed during ${report.failure?.phase ?? "unknown"}`);
}

function parseArguments(args) {
  if (args.length !== 4 || args[0] !== "--plan" || args[2] !== "--result") {
    throw new Error("usage: browser-release-collector.mjs --plan ABSOLUTE_PATH --result ABSOLUTE_PATH");
  }
  const planPath = path.resolve(args[1]);
  const resultPath = path.resolve(args[3]);
  if (planPath !== args[1] || resultPath !== args[3] || planPath === resultPath) {
    throw new Error("plan and result must be distinct absolute paths");
  }
  return { planPath, resultPath };
}

if (process.argv[1] !== undefined && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
