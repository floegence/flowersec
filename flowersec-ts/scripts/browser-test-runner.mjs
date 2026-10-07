#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { promises as fs } from "node:fs";
import https from "node:https";
import http from "node:http";
import { networkInterfaces } from "node:os";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import { chromium, firefox } from "playwright";

import {
  acquireArtifactBatch,
  cancelArtifactPeer,
  chromiumExecutablePath,
  chromiumLaunchOptions,
  commitArtifactSpend,
  firefoxExecutablePath,
  firefoxLaunchOptions,
  normalizeRunnerPlan,
  runOpenLoop,
  retireArtifactPeer,
  startArtifactPeer,
  verifyChromiumWebTransportCapability,
} from "./browser-test-runner-core.mjs";

import { createBrowserRunnerHost } from "./browser-runner-installation.mjs";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const launcherPath = path.join(packageRoot, "scripts", "chromium-netns-launcher.sh");

export async function runBrowserWorkload(input, dependencies = {}) {
  const plan = normalizeRunnerPlan(input);
  const fetchImpl = dependencies.fetch ?? globalThis.fetch;
  const startedAt = new Date();
  const result = {
    schema_version: 1,
    classification: "browser_transport_result",
    status: "failed",
    topology: plan.topology,
    profile_id: plan.profile_id,
    run_number: plan.run_number,
    started_at: startedAt.toISOString(),
    finished_at: startedAt.toISOString(),
    browser: { engine: plan.browser, version: "" },
    spend_count: 0,
  };
  let site;
  let host;
  let browser;
  let phase = "setup";
  let runFailure;
  let closeAbortedPage;
  const cellController = new AbortController();
  const abortFromCaller = () => cellController.abort(dependencies.signal.reason);
  dependencies.signal?.addEventListener("abort", abortFromCaller, { once: true });
  if (dependencies.signal?.aborted) abortFromCaller();
  let cellTimer;
  const ledger = createSpendLedger(plan, fetchImpl, cellController.signal);
  try {
    cellController.signal.throwIfAborted();
    if (process.platform !== "linux") throw new Error("browser release collection requires Linux");
    host = await createBrowserRunnerHost(plan.installation_manifest_path, plan.history_directory);
    site = await startBrowserModuleSite(plan.module_bind_address, plan.module_advertise_host, {
      secure: plan.browser === "firefox",
      outputDirectory: plan.output_directory,
      host,
    });
    host.setOrigin(site.origin);
    const playwright = plan.browser === "firefox" ? (dependencies.firefox ?? firefox) : (dependencies.chromium ?? chromium);
    const executable = plan.browser === "firefox"
      ? firefoxExecutablePath(playwright)
      : chromiumExecutablePath(playwright);
    const launchOptions = plan.browser === "firefox"
      ? firefoxLaunchOptions(plan, executable, site.origin)
      : chromiumLaunchOptions(plan, executable, launcherPath, site.origin);
    browser = await playwright.launch(launchOptions);
    result.browser.version = browser.version();
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
    result.browser.diagnostics = diagnostics;
    await page.exposeBinding("__flowersecInstallArtifact", async (_source, raw) => await host.install(raw, { signal: cellController.signal }));
    await page.exposeBinding("__flowersecCommitArtifactSpend", async (_source, token, count, deadlineMs) => {
      if (count !== 1) throw new Error("original durable store did not commit exactly one spend");
      await ledger.commit(token, deadlineMs);
    });
    await page.exposeBinding("__flowersecStartArtifact", async (_source, token, deadlineMs) => {
      await ledger.start(token, deadlineMs);
    });
    await page.exposeBinding("__flowersecCancelArtifact", async (_source, token) => {
      await ledger.cancel(token);
    });
    await page.exposeBinding("__flowersecRetireArtifact", async (_source, token) => {
      await ledger.retire(token);
    });
    closeAbortedPage = () => { void page.close({ runBeforeUnload: false }).catch(() => undefined); };
    cellController.signal.addEventListener("abort", closeAbortedPage, { once: true });
    if (cellController.signal.aborted) closeAbortedPage();
    await page.exposeBinding("__flowersecRecordDiagnostic", async (_source, value) => {
      if (typeof value === "string") recordDiagnostic(value);
    });
    await navigateBrowserModule(page, site.origin);
    await preloadBrowserSDK(page);
    await host.publishRuntime({ engine: plan.browser, version: browser.version(), userAgent: await page.evaluate(() => navigator.userAgent) });

    const execute = async () => {
      if (plan.mode === "adaptive") {
        result.stages = [];
        for (const stage of plan.stages) {
          phase = `cold:${stage.profile_id}`;
          const artifacts = await acquireArtifactBatch(plan, {
            profile_id: stage.profile_id,
            phase: "cold",
            count: stage.cold.operations,
          }, fetchImpl, { signal: cellController.signal });
          ledger.admit(artifacts, stage.cold.operation_deadline_ms, stage.cleanup_deadline_ms);
          cellController.signal.throwIfAborted();
          result.stages.push({
            profile_id: stage.profile_id,
            cold: await runColdPhase(page, artifacts, stage.cold, stage.cleanup_deadline_ms, cellController.signal),
          });
        }
      } else {
        phase = "cold";
        const coldArtifacts = await acquireArtifactBatch(plan, {
          profile_id: plan.profile_id,
          phase: "cold",
          count: plan.cold.operations,
        }, fetchImpl, { signal: cellController.signal });
        ledger.admit(coldArtifacts, plan.cold.operation_deadline_ms, plan.cleanup_deadline_ms);
        cellController.signal.throwIfAborted();
        result.cold = await runColdPhase(page, coldArtifacts, plan.cold, plan.cleanup_deadline_ms, cellController.signal);

        if (!plan.cold_diagnostic) {
          phase = "session";
          const sessionArtifacts = await acquireArtifactBatch(plan, {
            profile_id: plan.profile_id,
            phase: "session",
            count: 1,
          }, fetchImpl, { signal: cellController.signal });
          ledger.admit(sessionArtifacts, plan.cold.operation_deadline_ms, plan.cleanup_deadline_ms);
          cellController.signal.throwIfAborted();
          const workload = await runSessionWorkload(page, sessionArtifacts[0], plan);
          result.rpc = workload.rpc;
          result.bulk = workload.bulk;
          if (workload.native_isolation !== undefined) result.native_isolation = workload.native_isolation;
          result.session_connected_at = workload.session_connected_at;
          result.session_closed_at = workload.session_closed_at;
          result.cleanup_duration_ns = workload.cleanup_duration_ns;
        }
      }
    };
    cellTimer = setTimeout(() => cellController.abort(new Error("cell deadline exceeded")), plan.cell_deadline_ms);
    await execute();
    cellController.signal.throwIfAborted();
    ledger.assertFullySpent();
    result.spend_count = ledger.spendCount;
    result.status = "passed";
  } catch (error) {
    runFailure = error;
    if (!cellController.signal.aborted) cellController.abort(error);
    result.spend_count = ledger.spendCount;
    result.failure = failureDetails(phase, error);
  } finally {
    clearTimeout(cellTimer);
    dependencies.signal?.removeEventListener("abort", abortFromCaller);
    if (closeAbortedPage !== undefined) cellController.signal.removeEventListener("abort", closeAbortedPage);
    phase = "cleanup";
    const cleanupErrors = [];
    let browserClosed = browser === undefined;
    if (browser !== undefined) {
      try {
        await browser.close();
        browserClosed = true;
      } catch (error) {
        cleanupErrors.push(error);
      }
    }
    try {
      await ledger.finish(result.status === "passed" && browserClosed);
    } catch (error) {
      cleanupErrors.push(error);
    }
    if (site !== undefined) {
      try {
        await site.close();
      } catch (error) {
        cleanupErrors.push(error);
      }
    }
    try { await host?.close(); } catch (error) { cleanupErrors.push(error); }
    if (cleanupErrors.length > 0) {
      result.status = "failed";
      result.failure = failureDetails(phase, new AggregateError(runFailure === undefined ? cleanupErrors : [runFailure, ...cleanupErrors], "runner cleanup failed"));
      result.cleanup_failures = cleanupErrors.map((error) => failureDetails(phase, error));
    }
    result.finished_at = new Date().toISOString();
  }
  return result;
}

export async function runColdPhase(page, artifacts, cold, cleanupDeadlineMs, signal) {
  const phaseStartedAt = performance.now();
  const drainageController = new AbortController();
  const abortFromParent = () => drainageController.abort(signal.reason);
  signal?.addEventListener("abort", abortFromParent, { once: true });
  if (signal?.aborted) abortFromParent();
  const drainageTimer = setTimeout(
    () => drainageController.abort(new Error("cold phase drainage deadline exceeded")),
    cold.phase_deadline_ms + cold.operation_deadline_ms + cleanupDeadlineMs,
  );
  try {
    return await runOpenLoop({
      operations: cold.operations,
      maxInflight: cold.max_inflight,
      intervalMs: 1_000 / cold.start_rate_per_second,
      signal: drainageController.signal,
      operation: async (ordinal, scheduledAtMs, drainageSignal) => {
        const phaseRemainingMs = Math.floor(cold.phase_deadline_ms - (performance.now() - phaseStartedAt));
        if (phaseRemainingMs <= 0) throw new Error("cold phase deadline exceeded");
        const connectDeadlineMs = Math.min(cold.operation_deadline_ms, phaseRemainingMs);
        const closePage = () => { void page.close({ runBeforeUnload: false }).catch(() => undefined); };
        drainageSignal.addEventListener("abort", closePage, { once: true });
        const scheduledAt = new Date(Date.now() - (performance.now() - scheduledAtMs)).toISOString();
        try {
          return await page.evaluate(async ({
            item,
            ordinalValue,
            scheduledAtValue,
            connectDeadlineMs,
            connectDeadlineMessage,
            operationDeadlineMs,
            cleanupMs,
          }) => {
            const startedAt = new Date().toISOString();
            const started = performance.now();
            const controller = new AbortController();
            const timer = setTimeout(() => controller.abort(new Error(connectDeadlineMessage)), connectDeadlineMs);
            let owner;
            let cancellation;
            const cancelPeer = () => cancellation ??= globalThis.__flowersecCancelArtifact(item.spend_token);
            const abortPeer = () => { void cancelPeer().catch(() => undefined); };
            controller.signal.addEventListener("abort", abortPeer, { once: true });
            async function closeOwner() {
              if (owner === undefined) return;
              let cleanupTimer;
              try {
                await Promise.race([
                  owner.close(),
                  new Promise((_, reject) => { cleanupTimer = setTimeout(() => reject(new Error("cold cleanup deadline exceeded")), cleanupMs); }),
                ]);
              } finally {
                clearTimeout(cleanupTimer);
              }
            }
            try {
              await globalThis.__flowersecStartArtifact(item.spend_token, remainingConnectTime());
              controller.signal.throwIfAborted();
              const current = await import("/dist/interop/browserRunner.js");
              owner = await current.installBrowserRunner(await globalThis.__flowersecInstallArtifact(item.artifact_json), item.artifact_json);
              controller.signal.throwIfAborted();
              const session = await owner.connect(controller.signal);
              await globalThis.__flowersecCommitArtifactSpend(item.spend_token, await owner.spendCount(), remainingConnectTime());
              controller.signal.throwIfAborted();
              clearTimeout(timer);
              const durationNs = Math.max(1, Math.round((performance.now() - started) * 1_000_000));
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
              const cleanupStarted = performance.now();
              await closeOwner();
              const cleanupDurationNs = Math.max(1, Math.round((performance.now() - cleanupStarted) * 1_000_000));
              await globalThis.__flowersecRetireArtifact(item.spend_token);
              return {
                ordinal: ordinalValue,
                scheduled_at: scheduledAtValue,
                started_at: startedAt,
                duration_ns: durationNs,
                cleanup_duration_ns: cleanupDurationNs,
              };
            } catch (error) {
              try {
                await globalThis.__flowersecRecordDiagnostic(JSON.stringify({ type: "connect", public_code: typeof error?.code === "string" ? error.code : error instanceof Error ? error.message : "unclassified" }));
              } catch {
                // Raw diagnostics must never replace the public connection failure.
              }
              const cleanup = await Promise.allSettled([closeOwner(), cancelPeer()]);
              const errors = cleanup.filter((result) => result.status === "rejected").map((result) => result.reason);
              if (errors.length > 0) throw new AggregateError([error, ...errors], "cold operation and original cleanup failed", { cause: error });
              throw error;
            } finally {
              controller.signal.removeEventListener("abort", abortPeer);
              clearTimeout(timer);
            }
            function remainingConnectTime() {
              controller.signal.throwIfAborted();
              const remaining = Math.floor(connectDeadlineMs - (performance.now() - started));
              if (remaining <= 0) {
                controller.abort(new Error(connectDeadlineMessage));
                throw controller.signal.reason;
              }
              return remaining;
            }
          }, {
            item: artifacts[ordinal - 1],
            ordinalValue: ordinal,
            scheduledAtValue: scheduledAt,
            connectDeadlineMs,
            connectDeadlineMessage: connectDeadlineMs < cold.operation_deadline_ms
              ? "cold phase deadline exceeded"
              : "cold operation deadline exceeded",
            operationDeadlineMs: cold.operation_deadline_ms,
            cleanupMs: cleanupDeadlineMs,
          });
        } catch (error) {
          const elapsedMs = Math.max(0, Math.round(performance.now() - scheduledAtMs));
          const message = error instanceof Error ? error.message : String(error);
          throw new Error(`cold operation ${ordinal} failed elapsed_ms=${elapsedMs}: ${message}`, { cause: error });
        } finally {
          drainageSignal.removeEventListener("abort", closePage);
        }
      },
    });
  } finally {
    clearTimeout(drainageTimer);
    signal?.removeEventListener("abort", abortFromParent);
  }
}

export async function runSessionWorkload(page, artifact, plan) {
  return await page.evaluate(async ({ item, profileID, connectDeadlineMs, rpcPlan, bulkPlan, cleanupDeadlineMs }) => {
    let owner;
    let echo;
    let session;
    let sdk;
    let cancellation;
    const cancelPeer = () => cancellation ??= globalThis.__flowersecCancelArtifact(item.spend_token);
    async function closeOwner() {
      let cleanupTimer;
      try {
        echo?.close();
        if (owner === undefined) return;
        await Promise.race([
          owner.close(),
          new Promise((_, reject) => { cleanupTimer = setTimeout(() => reject(new Error("session cleanup deadline exceeded")), cleanupDeadlineMs); }),
        ]);
      } finally {
        clearTimeout(cleanupTimer);
      }
    }
    try {
      session = await withSignalDeadline(
        async (signal) => {
          const connectStarted = performance.now();
          const abortPeer = () => { void cancelPeer().catch(() => undefined); };
          signal.addEventListener("abort", abortPeer, { once: true });
          try {
            await globalThis.__flowersecStartArtifact(item.spend_token, remainingConnectTime());
            signal.throwIfAborted();
            sdk = await import("/dist/browser/index.js");
            const current = await import("/dist/interop/browserRunner.js");
            owner = await current.installBrowserRunner(await globalThis.__flowersecInstallArtifact(item.artifact_json), item.artifact_json);
            signal.throwIfAborted();
            const connected = await owner.connect(signal);
            await globalThis.__flowersecCommitArtifactSpend(item.spend_token, await owner.spendCount(), remainingConnectTime());
            signal.throwIfAborted();
            return connected;
          } finally {
            signal.removeEventListener("abort", abortPeer);
          }
          function remainingConnectTime() {
            signal.throwIfAborted();
            const remaining = Math.floor(connectDeadlineMs - (performance.now() - connectStarted));
            if (remaining <= 0) throw new Error("session connect deadline exceeded");
            return remaining;
          }
        },
        connectDeadlineMs,
        "session connect deadline exceeded",
      );
      echo = await owner.bindEcho();
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
      await closeOwner();
      await globalThis.__flowersecRetireArtifact(item.spend_token);
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
    } catch (error) {
      const cleanup = await Promise.allSettled([closeOwner(), cancelPeer()]);
      const errors = cleanup.filter((result) => result.status === "rejected").map((result) => result.reason);
      if (errors.length > 0) throw new AggregateError([error, ...errors], "session workload and original cleanup failed", { cause: error });
      throw error;
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
              const result = await echo.call(owner.method, encoded, { signal: operationController.signal, responseLimitBytes: config.request_bytes });
              if (result.kind !== "value" || result.encoding !== "typed") throw new Error("RPC echo did not return a typed value");
              try { response = { payload: decodeRPCString(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(result.value))) }; }
              finally { result.release(); }
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
          const response = await activeSession.probeLiveness({ signal: livenessController.signal });
          liveness = `passed:${Number(response.elapsedMS).toFixed(1)}ms`;
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
			metadata: sdk.createStreamMetadata({ stream_index: index }),
			signal: phaseSignal,
		  });
		  streams.push(stream);
		  if ((await stream.write(new Uint8Array([index]), { signal: phaseSignal })).accepted_bytes !== 1n) {
			throw new Error("native isolation handshake short write");
		  }
		  const handshake = await readChunk(stream, 1, phaseSignal);
		  if (handshake === null || handshake.byteLength !== 1 || handshake[0] !== (index ^ 0xff)) {
			throw new Error("native isolation handshake mismatch");
		  }
		}
		events.push({ event: "native_streams_opened", at: new Date().toISOString(), stream_count: 4 });
		await streams[0].reset();
		events.push({ event: "native_stream_reset", at: new Date().toISOString(), stream_count: 1 });
		await Promise.all(streams.slice(1).map(async (stream, sibling) => {
		  const value = 0x41 + sibling;
		  if ((await stream.write(new Uint8Array([value]), { signal: phaseSignal })).accepted_bytes !== 1n) {
			throw new Error("native isolation sibling short write");
		  }
		  await stream.closeWrite();
		  const response = await readChunk(stream, 1, phaseSignal);
		  if (response === null || response.byteLength !== 1 || response[0] !== (value ^ 0xff)) {
			throw new Error("native isolation sibling response mismatch");
		  }
		  if (await readChunk(stream, 1, phaseSignal) !== null) {
			throw new Error("native isolation sibling did not finish cleanly");
		  }
          const finished = await stream.finish({ signal: phaseSignal });
          if (!finished.send_drained || finished.read_terminal !== "eof") throw new Error("native isolation sibling output did not drain");
		}));
		events.push({ event: "native_siblings_completed", at: new Date().toISOString(), stream_count: 3 });
        const result = await echo.call(owner.method, new TextEncoder().encode(JSON.stringify("native-isolation-survivor")), { signal: phaseSignal, responseLimitBytes: 1048576 });
        if (result.kind !== "value" || result.encoding !== "typed") throw new Error("native isolation post-reset RPC did not return a value");
        try { if (JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(result.value)) !== "native-isolation-survivor") throw new Error("native isolation post-reset RPC mismatch"); }
        finally { result.release(); }
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

    function decodeRPCString(value) {
      if (typeof value !== "string") {
        throw new TypeError("RPC response must be a string");
      }
      return value;
    }

    async function runBulk(activeSession, config, phaseSignal) {
      const warmupOutgoing = await prepareTransfer(activeSession, phaseSignal);
      await transfer(activeSession, warmupOutgoing, config.warmup_bytes_per_direction, phaseSignal);
      const scoreOutgoing = await prepareTransfer(activeSession, phaseSignal);
      const result = await transfer(activeSession, scoreOutgoing, config.score_bytes_per_direction, phaseSignal);
      return {
        started_at: result.started_at,
        duration_ns: result.duration_ns,
        bytes_per_direction: config.score_bytes_per_direction,
      };
    }

    async function prepareTransfer(activeSession, signal) {
      return await activeSession.openStream("release-bulk", {
        metadata: sdk.createStreamMetadata({ direction: "client-to-server" }),
        signal,
      });
    }

    async function transfer(activeSession, outgoing, byteCount, signal) {
      const startedAt = new Date().toISOString();
      const started = performance.now();
      const outgoingWrite = writeExact(outgoing, byteCount, 0xa5, signal);
      void outgoingWrite.catch(() => undefined);
      try {
        await Promise.all([
          outgoingWrite,
          readExact(outgoing, byteCount, 0x5a, signal),
        ]);
        const finished = await outgoing.finish({ signal });
        if (!finished.send_drained || finished.read_terminal !== "eof") throw new Error("bulk stream did not authenticate its complete drain");
        return {
          started_at: startedAt,
          duration_ns: Math.max(1, Math.round((performance.now() - started) * 1_000_000)),
        };
      } catch (error) {
        await Promise.allSettled([outgoingWrite, outgoing.reset()]);
        throw error;
      }
    }

    async function writeExact(stream, total, fill, signal) {
      const chunk = new Uint8Array(32 * 1024).fill(fill);
      let remaining = total;
      while (remaining > 0) {
        const current = chunk.subarray(0, Math.min(chunk.byteLength, remaining));
        const written = await stream.write(current, { signal });
        if (written.accepted_bytes !== BigInt(current.byteLength) || written.terminal_reason !== "complete") throw new Error("bulk stream short write");
        remaining -= Number(written.accepted_bytes);
      }
      await stream.closeWrite();
    }

    async function readExact(stream, total, fill, signal) {
      let remaining = total;
      while (remaining > 0) {
        const chunk = await readChunk(stream, Math.min(32768, remaining), signal);
        if (chunk === null || chunk.byteLength === 0 || chunk.byteLength > remaining) {
          throw new Error("bulk stream byte count mismatch");
        }
        for (const value of chunk) if (value !== fill) throw new Error("bulk stream payload mismatch");
        remaining -= chunk.byteLength;
      }
      if (await readChunk(stream, 1, signal) !== null) throw new Error("bulk stream did not end at the exact byte count");
    }

    async function readChunk(stream, maximum, signal) {
      const result = await stream.read(BigInt(maximum), { signal });
      if (result.wait_status !== "ready" || !["open", "eof"].includes(result.stream_status)) throw new Error("stream read failed to make reliable progress");
      if (result.data.length === 0 && result.stream_status === "eof") return null;
      return result.data;
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
	connectDeadlineMs: plan.cold.operation_deadline_ms,
    rpcPlan: plan.rpc,
    bulkPlan: plan.bulk,
    cleanupDeadlineMs: plan.cleanup_deadline_ms,
  });
}

function createSpendLedger(plan, fetchImpl, signal) {
  const records = new Map();
  const spent = new Set();
  function recordFor(token) {
    if (typeof token !== "string" || !records.has(token)) throw new Error("browser attempted to use an unknown artifact");
    return records.get(token);
  }
  async function sourceOperation(record, action, deadlineMs) {
    signal.throwIfAborted();
    if (!Number.isSafeInteger(deadlineMs) || deadlineMs <= 0 || deadlineMs > record.operationDeadlineMs) {
      throw new Error("browser source operation exceeds its original deadline");
    }
    const controller = new AbortController();
    const abortFromRun = () => controller.abort(signal.reason);
    signal.addEventListener("abort", abortFromRun, { once: true });
    if (signal.aborted) abortFromRun();
    const timer = setTimeout(() => controller.abort(new Error(`artifact ${action} deadline exceeded`)), deadlineMs);
    record.operationController = controller;
    const pending = (action === "start" ? startArtifactPeer : commitArtifactSpend)(plan, record.token, fetchImpl, { signal: controller.signal });
    record.pending = pending;
    try {
      await pending;
      controller.signal.throwIfAborted();
    } finally {
      clearTimeout(timer);
      signal.removeEventListener("abort", abortFromRun);
      record.operationController = undefined;
      record.pending = undefined;
    }
  }
  async function cleanup(record, action) {
    if (record.cleanupComplete) return;
    if (record.cleanupPending !== undefined) {
      const pending = record.cleanupPending;
      if (action !== "cancel" || record.cleanupAction === "cancel") return await pending;
      record.cleanupController.abort(new Error("original retirement canceled with the run"));
      await Promise.allSettled([pending]);
      if (record.cleanupPending === pending) record.cleanupPending = undefined;
      if (record.cleanupComplete) return;
    }
    if (record.cleanupAttempts.has(action)) throw record.cleanupError ?? new Error("original artifact cleanup delivery remains unknown");
    if (action === "retire" && !record.spent) throw new Error("browser attempted retirement before original spend observation");
    record.cleanupAttempts.add(action);
    record.cleanupAction = action;
    if (action === "cancel") record.operationController?.abort(new Error("original artifact canceled"));
    const controller = new AbortController();
    record.cleanupController = controller;
    const timer = setTimeout(() => controller.abort(new Error(`artifact ${action} cleanup deadline exceeded`)), record.cleanupDeadlineMs);
    const operation = record.pending;
    const pending = (async () => {
      // The source cancellation joins the retained position even if start delivery
      // was lost. The locally aborted request must also settle before completion.
      await (action === "cancel" ? cancelArtifactPeer : retireArtifactPeer)(plan, record.token, fetchImpl, { signal: controller.signal });
      if (operation !== undefined) await Promise.allSettled([operation]);
      controller.signal.throwIfAborted();
      record.cleanupComplete = true;
    })();
    record.cleanupPending = pending;
    try {
      await pending;
    } catch (error) {
      record.cleanupError = error;
      throw error;
    } finally {
      clearTimeout(timer);
      if (record.cleanupPending === pending) {
        record.cleanupPending = undefined;
        record.cleanupController = undefined;
      }
    }
  }
  return {
    get spendCount() { return spent.size; },
    admit(artifacts, operationDeadlineMs, cleanupDeadlineMs) {
      for (const artifact of artifacts) {
        if (records.has(artifact.spend_token)) throw new Error("artifact spend token was issued more than once");
        records.set(artifact.spend_token, {
          token: artifact.spend_token, operationDeadlineMs, cleanupDeadlineMs,
          startAttempted: false, started: false, spendAttempted: false, spent: false, cleanupComplete: false, cleanupAttempts: new Set(),
        });
      }
    },
    async start(token, deadlineMs) {
      const record = recordFor(token);
      if (record.startAttempted || record.cleanupPending !== undefined || record.cleanupComplete) throw new Error("browser attempted to start an occupied artifact");
      // Occupy the local position before delivery; an unknown HTTP result cannot reopen it.
      record.startAttempted = true;
      await sourceOperation(record, "start", deadlineMs);
      record.started = true;
    },
    async commit(token, deadlineMs) {
      const record = recordFor(token);
      if (!record.started) throw new Error("browser attempted to spend an artifact before peer start");
      if (record.spendAttempted || record.cleanupPending !== undefined || record.cleanupComplete) throw new Error("browser attempted to spend an occupied artifact");
      record.spendAttempted = true;
      await sourceOperation(record, "spend", deadlineMs);
      record.spent = true;
      spent.add(token);
    },
    async cancel(token) { await cleanup(recordFor(token), "cancel"); },
    async retire(token) { await cleanup(recordFor(token), "retire"); },
    async finish(success) {
      const remaining = Array.from(records.values()).filter((record) => !record.cleanupComplete);
      let next = 0;
      const errors = [];
      await Promise.all(Array.from({ length: Math.min(128, remaining.length) }, async () => {
        while (next < remaining.length) {
          const record = remaining[next++];
          try { await cleanup(record, success ? "retire" : "cancel"); }
          catch (error) { errors.push(error); }
        }
      }));
      if (errors.length > 0) throw new AggregateError(errors, "original artifact cleanup did not complete");
    },
    assertFullySpent() {
      if (spent.size !== records.size) throw new Error(`artifact spend count ${spent.size} does not match acquired count ${records.size}`);
    },
  };
}

export async function startBrowserModuleSite(bindAddress, advertiseHost, options = {}) {
  const distRoot = path.join(packageRoot, "dist");
  const nobleRoot = path.join(packageRoot, "node_modules", "@noble");
  const secure = options.secure === true;
  const server = secure
    ? https.createServer(await createModuleTLS(options.outputDirectory, advertiseHost), moduleRequestHandler)
    : http.createServer(moduleRequestHandler);
  async function moduleRequestHandler(request, response) {
    try {
      if (options.host !== undefined && await options.host.handle(request, response)) return;
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
  }
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, bindAddress, resolve);
  });
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("browser module server did not bind TCP");
  const host = advertiseHost.includes(":") ? `[${advertiseHost}]` : advertiseHost;
  const scheme = secure ? "https" : "http";
  let closing;
  return {
    origin: `${scheme}://${host}:${address.port}`,
    close() {
      closing ??= new Promise((resolve, reject) => {
        server.close((error) => error === undefined ? resolve() : reject(error));
        server.closeAllConnections?.();
      });
      return closing;
    },
  };
}

export async function inspectFirefoxWebTransportCapability(page, origin) {
  if (typeof origin !== "string" || !origin.startsWith("https://")) {
    throw new TypeError("Firefox WebTransport canary requires an HTTPS origin");
  }
  const observed = await page.evaluate(async (targetOrigin) => {
    if (globalThis.isSecureContext !== true || typeof globalThis.WebTransport !== "function") {
      return { secure_context: globalThis.isSecureContext === true, webtransport: typeof globalThis.WebTransport };
    }
    const transportPrototype = globalThis.WebTransport.prototype;
    const transport = new globalThis.WebTransport(targetOrigin);
    const shape = {
      secure_context: true,
      webtransport: "function",
      bidirectional_stream: typeof transport.createBidirectionalStream === "function",
      datagrams: transport.datagrams !== undefined,
    };
    // The canary endpoint is HTTPS-only, so Firefox reports the failed
    // connection before close can be requested. Drain that bounded outcome
    // first, then exercise the normal close path without masking crashes.
    await Promise.race([
      transport.ready,
      new Promise((_, reject) => setTimeout(() => reject(new Error("Firefox WebTransport connect exceeded")), 2_000)),
    ]).catch(() => undefined);
    transport.close();
    await Promise.race([
      transport.closed,
      new Promise((_, reject) => setTimeout(() => reject(new Error("Firefox WebTransport close exceeded")), 2_000)),
    ]);
    shape.closed = true;
    shape.prototype_datagrams = "datagrams" in transportPrototype;
    return shape;
  }, origin);
  if (observed.secure_context !== true || observed.webtransport !== "function") {
    throw new Error("Firefox must expose WebTransport in a secure HTTPS origin");
  }
  if (observed.bidirectional_stream !== true || observed.datagrams !== true) {
    throw new Error("Firefox WebTransport bidirectional stream and datagram APIs are required");
  }
  if (observed.closed !== true) throw new Error("Firefox WebTransport close lifecycle did not settle");
  return Object.freeze(observed);
}

export async function verifyFirefoxWebTransportCapability(playwright, firefoxExecutable) {
  if (playwright === null || typeof playwright !== "object" || typeof playwright.launch !== "function") {
    throw new TypeError("Playwright Firefox launcher is required");
  }
  const executablePath = path.resolve(firefoxExecutable);
  if (executablePath !== firefoxExecutable || !path.isAbsolute(executablePath)) {
    throw new TypeError("Firefox executable must be an absolute path");
  }
  const advertiseHost = findCanaryAddress();
  const temporaryOutput = await fs.mkdtemp(path.join(process.env.TMPDIR ?? os.tmpdir(), "flowersec-firefox-canary-"));
  let site;
  let browser;
  let context;
  try {
    site = await startBrowserModuleSite(advertiseHost, advertiseHost, { secure: true, outputDirectory: temporaryOutput });
    browser = await playwright.launch(firefoxLaunchOptionsForCanary(executablePath));
    context = await browser.newContext({ ignoreHTTPSErrors: true });
    const page = await context.newPage();
    await navigateBrowserModule(page, site.origin);
    const result = await inspectFirefoxWebTransportCapability(page, site.origin);
    if (typeof browser.isConnected === "function" && !browser.isConnected()) {
      throw new Error("Firefox exited during WebTransport lifecycle canary");
    }
    return result;
  } finally {
    await context?.close().catch(() => undefined);
    await browser?.close().catch(() => undefined);
    await site?.close().catch(() => undefined);
    await fs.rm(temporaryOutput, { recursive: true, force: true });
  }
}

function firefoxLaunchOptionsForCanary(executablePath) {
  return { headless: true, executablePath };
}

function findCanaryAddress() {
  for (const interfaces of Object.values(networkInterfaces())) {
    for (const entry of interfaces ?? []) {
      if (entry.family === "IPv4" && !entry.internal && entry.address !== "0.0.0.0") return entry.address;
    }
  }
  throw new Error("Firefox WebTransport canary requires a non-loopback IPv4 address");
}

async function createModuleTLS(outputDirectory, advertiseHost) {
  if (typeof outputDirectory !== "string" || !path.isAbsolute(outputDirectory)) {
    throw new TypeError("Firefox module TLS output directory must be absolute");
  }
  const certificate = path.join(outputDirectory, "firefox-module-cert.pem");
  const key = path.join(outputDirectory, "firefox-module-key.pem");
  execFileSync("openssl", [
    "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
    "-subj", `/CN=${advertiseHost}`,
    "-addext", `subjectAltName=IP:${advertiseHost}`,
    "-keyout", key, "-out", certificate,
  ], { stdio: "ignore" });
  return { key: await fs.readFile(key), cert: await fs.readFile(certificate) };
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
<html><head><meta charset="utf-8"><title>Flowersec test runner</title>
<script type="importmap">{"imports":{
"@noble/ciphers/":"/node_modules/@noble/ciphers/",
"@noble/curves/":"/node_modules/@noble/curves/",
"@noble/hashes/":"/node_modules/@noble/hashes/"}}</script>
</head><body></body></html>`;
}

export async function disableBrowserWebSocket(page) {
  await page.addInitScript(() => {
    Object.defineProperty(globalThis, "WebSocket", { value: undefined, configurable: true });
  });
}

function failureDetails(phase, error) {
  return {
    phase,
    name: error instanceof Error ? error.name : "Error",
    message: error instanceof Error ? error.message : String(error),
  };
}

async function main(args) {
  if (args[0] === "--runtime-canary") {
    if (args.length !== 2) throw new Error("usage: browser-test-runner.mjs --runtime-canary ABSOLUTE_CHROMIUM_PATH");
    const result = await verifyChromiumWebTransportCapability(chromium, args[1]);
    process.stdout.write(`${JSON.stringify(result)}\n`);
    return;
  }
  if (args[0] === "--firefox-runtime-canary") {
    if (args.length !== 2) throw new Error("usage: browser-test-runner.mjs --firefox-runtime-canary ABSOLUTE_FIREFOX_PATH");
    const result = await verifyFirefoxWebTransportCapability(firefox, args[1]);
    process.stdout.write(`${JSON.stringify({ status: "GREEN", ...result })}\n`);
    return;
  }
  const { planPath, resultPath } = parseArguments(args);
  const raw = await fs.readFile(planPath, "utf8");
  const result = await runBrowserWorkload(JSON.parse(raw));
  await fs.writeFile(resultPath, `${JSON.stringify(result, null, 2)}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
  if (result.status !== "passed") throw new Error(`browser release collection failed during ${result.failure?.phase ?? "unknown"}`);
}

function parseArguments(args) {
  if (args.length !== 4 || args[0] !== "--plan" || args[2] !== "--result") {
    throw new Error("usage: browser-test-runner.mjs --plan ABSOLUTE_PATH --result ABSOLUTE_PATH");
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
