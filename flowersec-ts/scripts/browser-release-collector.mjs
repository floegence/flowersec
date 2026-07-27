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
    const diagnostics = [];
    const recordDiagnostic = (value) => {
      if (diagnostics.length < 32) diagnostics.push(value.slice(0, 512));
    };
    page.on("requestfailed", (request) => recordDiagnostic(`request failed: ${request.url()} ${request.failure()?.errorText ?? "unknown"}`));
    page.on("response", (response) => {
      if (response.status() >= 400) recordDiagnostic(`response ${response.status()}: ${response.url()}`);
    });
    page.on("pageerror", (error) => recordDiagnostic(`page error: ${error.message}`));
    page.on("console", (message) => {
      if (message.type() === "error") recordDiagnostic(`console error: ${message.text()}`);
    });
    report.browser.diagnostics = diagnostics;
    await page.exposeBinding("__flowersecCommitArtifactSpend", async (_source, token) => {
      await ledger.commit(token);
    });
    await installWebTransportCertificateHash(page, plan.certificate_hash);
    await navigateBrowserModule(page, site.origin);
    await preloadBrowserSDK(page);

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
		if (workload.native_isolation !== undefined) report.native_isolation = workload.native_isolation;
		report.session_connected_at = workload.session_connected_at;
		report.session_closed_at = workload.session_closed_at;
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
  const phaseController = new AbortController();
  const phaseTimer = setTimeout(
    () => phaseController.abort(new Error("cold phase deadline exceeded")),
    cold.phase_deadline_ms,
  );
  try {
    return await runOpenLoop({
      operations: cold.operations,
      maxInflight: cold.max_inflight,
      intervalMs: 1_000 / cold.start_rate_per_second,
      signal: phaseController.signal,
      operation: async (ordinal, scheduledAtMs, phaseSignal) => {
        const closePage = () => { void page.close({ runBeforeUnload: false }).catch(() => undefined); };
        phaseSignal.addEventListener("abort", closePage, { once: true });
        const scheduledAt = new Date(Date.now() - (performance.now() - scheduledAtMs)).toISOString();
        try {
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
            let cleanupDurationNs;
            try {
              const readinessController = new AbortController();
              const readinessTimer = setTimeout(
                () => readinessController.abort(new Error("cold readiness confirmation deadline exceeded")),
                operationDeadlineMs,
              );
              try {
                await session.probeLiveness({ signal: readinessController.signal });
              } finally {
                clearTimeout(readinessTimer);
              }
            } finally {
              const cleanupStarted = performance.now();
              await Promise.race([
                session.close(),
                new Promise((_, reject) => setTimeout(() => reject(new Error("cold cleanup deadline exceeded")), cleanupMs)),
              ]);
              cleanupDurationNs = Math.max(1, Math.round((performance.now() - cleanupStarted) * 1_000_000));
            }
            return {
              ordinal: ordinalValue,
              scheduled_at: scheduledAtValue,
              started_at: startedAt,
              duration_ns: durationNs,
              cleanup_duration_ns: cleanupDurationNs,
            };
          }, {
            item: artifacts[ordinal - 1],
            ordinalValue: ordinal,
            scheduledAtValue: scheduledAt,
            operationDeadlineMs: cold.operation_deadline_ms,
            cleanupMs: cleanupDeadlineMs,
          });
        } finally {
          phaseSignal.removeEventListener("abort", closePage);
        }
      },
    });
  } finally {
    clearTimeout(phaseTimer);
  }
}

export async function runSessionWorkload(page, artifact, plan) {
  return await page.evaluate(async ({ item, profileID, connectDeadlineMs, rpcPlan, bulkPlan, cleanupDeadlineMs }) => {
    const sdk = await import("/dist/browser/index.js");
    const lease = sdk.createArtifactLeaseV2(
      sdk.parseArtifact(item.artifact_json),
      async () => await globalThis.__flowersecCommitArtifactSpend(item.spend_token),
    );
    let session;
    try {
      session = await withSignalDeadline(
        (signal) => sdk.connectBrowserSessionV2(lease, { signal }),
        connectDeadlineMs,
        "session connect deadline exceeded",
      );
	  const sessionConnectedAt = new Date().toISOString();
	  const nativeIsolation = profileID === "webtransport-native-isolation"
	    ? await withSignalDeadline(
	      (phaseSignal) => runNativeIsolation(session, phaseSignal),
	      rpcPlan.phase_deadline_ms,
	      "native isolation phase deadline exceeded",
	    )
	    : undefined;
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
	  const sessionClosedAt = new Date().toISOString();
      session = undefined;
      return {
        rpc,
        bulk,
		native_isolation: nativeIsolation,
		session_connected_at: sessionConnectedAt,
		session_closed_at: sessionClosedAt,
        cleanup_duration_ns: Math.max(1, Math.round((performance.now() - cleanupStarted) * 1_000_000)),
      };
    } finally {
      if (session !== undefined) await session.close().catch(() => undefined);
    }

    async function runRPC(activeSession, config, phaseSignal) {
      const phaseStarted = performance.now();
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
            () => operationController.abort(new DOMException("RPC operation deadline exceeded", "TimeoutError")),
            config.operation_deadline_ms,
          );
          try {
            let response;
            try {
              response = await activeSession.rpc.call(1, payload, operationController.signal);
            } catch (error) {
              const durationMs = Math.max(0, performance.now() - started).toFixed(1);
              const code = typeof error?.code === "string" ? error.code : "unclassified";
              throw new Error(`RPC operation ${ordinal} failed after ${durationMs}ms with public code ${code}`, { cause: error });
            }
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
      try {
        await Promise.all(workers);
      } catch (error) {
        const completed = records.filter((record) => record !== undefined);
        const durations = completed
          .map((record) => record.duration_ns / 1_000_000)
          .sort((left, right) => left - right);
        const percentile = (quantile) => durations.length === 0
          ? "unavailable"
          : `${durations[Math.ceil(quantile * durations.length) - 1].toFixed(1)}ms`;
        const progress = [
          `completed ${completed.length}/${config.operations}`,
          `phase elapsed ${Math.max(0, performance.now() - phaseStarted).toFixed(1)}ms`,
          `completed latency p50=${percentile(0.50)}`,
          `p95=${percentile(0.95)}`,
          `p99=${percentile(0.99)}`,
        ].join("; ");
        const livenessController = new AbortController();
        const livenessTimer = setTimeout(
          () => livenessController.abort(new DOMException("post-failure liveness deadline exceeded", "TimeoutError")),
          config.operation_deadline_ms,
        );
        let liveness = "failed:unclassified";
        try {
          const durationMs = await activeSession.probeLiveness({ signal: livenessController.signal });
          liveness = `passed:${durationMs.toFixed(1)}ms`;
        } catch (livenessError) {
          const code = typeof livenessError?.code === "string" ? livenessError.code : "unclassified";
          liveness = `failed:${code}`;
        } finally {
          clearTimeout(livenessTimer);
        }
        throw new Error(`RPC workload failed; ${progress}; post-failure liveness ${liveness}; ${error instanceof Error ? error.message : String(error)}`, { cause: error });
      }
      return records;
    }

	async function runNativeIsolation(activeSession, phaseSignal) {
	  const streams = [];
	  const events = [];
	  try {
		for (let index = 0; index < 4; index++) {
		  const stream = await activeSession.openStream("native-isolation", {
			metadata: { stream_index: index },
			signal: phaseSignal,
		  });
		  streams.push(stream);
		  if (await stream.write(new Uint8Array([index]), { signal: phaseSignal }) !== 1) {
			throw new Error("native isolation handshake short write");
		  }
		  const handshake = await stream.read({ signal: phaseSignal });
		  if (handshake === null || handshake.byteLength !== 1 || handshake[0] !== (index ^ 0xff)) {
			throw new Error("native isolation handshake mismatch");
		  }
		}
		events.push({ event: "native_streams_opened", at: new Date().toISOString(), stream_count: 4 });
		await streams[0].reset();
		events.push({ event: "native_stream_reset", at: new Date().toISOString(), stream_count: 1 });
		await Promise.all(streams.slice(1).map(async (stream, sibling) => {
		  const value = 0x41 + sibling;
		  if (await stream.write(new Uint8Array([value]), { signal: phaseSignal }) !== 1) {
			throw new Error("native isolation sibling short write");
		  }
		  await stream.closeWrite();
		  const response = await stream.read({ signal: phaseSignal });
		  if (response === null || response.byteLength !== 1 || response[0] !== (value ^ 0xff)) {
			throw new Error("native isolation sibling response mismatch");
		  }
		  if (await stream.read({ signal: phaseSignal }) !== null) {
			throw new Error("native isolation sibling did not finish cleanly");
		  }
		}));
		events.push({ event: "native_siblings_completed", at: new Date().toISOString(), stream_count: 3 });
		const response = await activeSession.rpc.call(1, "native-isolation-survivor", phaseSignal);
		if (response.error !== undefined || response.payload !== "native-isolation-survivor") {
		  throw new Error("native isolation post-reset RPC mismatch");
		}
		events.push({ event: "rpc_completed", at: new Date().toISOString(), request_id: "native-isolation-survivor", status: "ok" });
		return {
		  opened_streams: 4,
		  reset_streams: 1,
		  sibling_streams: 3,
		  completed_rpcs: 1,
		  residual_streams: 0,
		  residual_sessions: 0,
		  events,
		};
	  } finally {
		await Promise.allSettled(streams.slice(1).map(async (stream) => await stream.close()));
	  }
	}

    async function runBulk(activeSession, config, phaseSignal) {
      const warmupOutgoing = await prepareTransfer(activeSession, phaseSignal);
      const scorePrepareController = new AbortController();
      const scorePrepareSignal = AbortSignal.any([phaseSignal, scorePrepareController.signal]);
      const scoreOutgoingPromise = prepareTransfer(activeSession, scorePrepareSignal);
      void scoreOutgoingPromise.catch(() => undefined);
      try {
        await transfer(activeSession, warmupOutgoing, config.warmup_bytes_per_direction, phaseSignal);
        const scoreOutgoing = await scoreOutgoingPromise;
        const result = await transfer(activeSession, scoreOutgoing, config.score_bytes_per_direction, phaseSignal);
        return {
          started_at: result.started_at,
          duration_ns: result.duration_ns,
          bytes_per_direction: config.score_bytes_per_direction,
        };
      } catch (error) {
        scorePrepareController.abort(error);
        await Promise.allSettled([scoreOutgoingPromise.then((stream) => stream.reset())]);
        throw error;
      }
    }

    async function prepareTransfer(activeSession, signal) {
      return await activeSession.openStream("release-bulk", {
        metadata: { direction: "client-to-server" },
        signal,
      });
    }

    async function transfer(activeSession, outgoing, byteCount, signal) {
      const accepting = activeSession.acceptStream({ signal });
      let incoming;
      const startedAt = new Date().toISOString();
      const started = performance.now();
      const outgoingWrite = writeExact(outgoing, byteCount, 0xa5, signal);
      void outgoingWrite.catch(() => undefined);
      try {
        incoming = await accepting;
        if (incoming.kind !== "release-bulk" || incoming.metadata.direction !== "server-to-client") {
          throw new Error("bulk stream metadata mismatch");
        }
        await Promise.all([
          outgoingWrite,
          readExact(incoming.stream, byteCount, 0x5a, signal).then(async () => await incoming.stream.closeWrite()),
        ]);
        return {
          started_at: startedAt,
          duration_ns: Math.max(1, Math.round((performance.now() - started) * 1_000_000)),
        };
      } catch (error) {
        await Promise.allSettled([outgoingWrite, outgoing.reset(), incoming?.stream.reset()]);
        throw error;
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
      const timer = setTimeout(() => controller.abort(new DOMException(message, "TimeoutError")), milliseconds);
      try {
        return await operation(controller.signal);
      } finally {
        clearTimeout(timer);
      }
    }
  }, {
    item: artifact,
	profileID: plan.profile_id,
	connectDeadlineMs: plan.cold.phase_deadline_ms,
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

export async function startBrowserModuleSite(bindAddress, advertiseHost) {
  const distRoot = path.join(packageRoot, "dist");
  const nobleRoot = path.join(packageRoot, "node_modules", "@noble");
  const server = http.createServer(async (request, response) => {
    try {
      const url = new URL(request.url ?? "/", "http://invalid.invalid");
      if (url.pathname === "/") return respond(response, 200, "text/html; charset=utf-8", browserPage());
      if (url.pathname === "/favicon.ico") return respond(response, 204, "image/x-icon", "");
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

export async function preloadBrowserSDK(page) {
  let failure;
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      await page.evaluate(async () => { await import("/dist/browser/index.js"); });
      return;
    } catch (error) {
      failure = error;
      if (!/ERR_NETWORK_CHANGED|Failed to fetch dynamically imported module/.test(String(error)) || attempt === 3) break;
      await new Promise((resolve) => setTimeout(resolve, 250 * attempt));
      await page.reload({ waitUntil: "networkidle" });
    }
  }
  throw failure;
}

export async function navigateBrowserModule(page, origin, wait = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds))) {
  let failure;
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      await page.goto(origin, { waitUntil: "networkidle" });
      return;
    } catch (error) {
      failure = error;
      if (!/ERR_NETWORK_CHANGED/.test(String(error)) || attempt === 3) break;
      await wait(250 * attempt);
    }
  }
  throw failure;
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

export async function installWebTransportCertificateHash(page, encodedHash) {
  await page.addInitScript((value) => {
    const NativeWebTransport = globalThis.WebTransport;
    const standard = value.replaceAll("-", "+").replaceAll("_", "/");
    const padded = standard + "=".repeat((4 - (standard.length % 4)) % 4);
    const hash = Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
    globalThis.WebTransport = class extends NativeWebTransport {
      constructor(url, options) {
        super(url, { ...options, serverCertificateHashes: [{ algorithm: "sha-256", value: hash.slice() }] });
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
