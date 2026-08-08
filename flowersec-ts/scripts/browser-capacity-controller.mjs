#!/usr/bin/env node

import { promises as fs } from "node:fs";
import http from "node:http";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import { chromium } from "playwright";

import {
  capacityStreamAssignments,
  chromiumCapacityLaunchOptions,
  chromiumExecutablePath,
  createBrowserCapacityCloseBatcher,
  normalizeBrowserCapacityPlan,
} from "./browser-capacity-runner-core.mjs";
import {
  installWebTransportCertificateHash,
  preloadBrowserSDK,
  startBrowserModuleSite,
} from "./browser-test-runner.mjs";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const launcherPath = path.join(packageRoot, "scripts", "chromium-netns-launcher.sh");
const sessionIDPattern = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/;

export async function startBrowserCapacityController(input, dependencies = {}) {
  if (process.platform !== "linux") throw new Error("browser capacity controller requires Linux");
  const plan = normalizeBrowserCapacityPlan(input);
  const playwright = dependencies.chromium ?? chromium;
  const fetchImpl = dependencies.fetch ?? globalThis.fetch;
  const startedAt = new Date();
  const events = [];
  const records = new Map();
  const resourceSamples = [];
  const browserDiagnostics = [];
  let connected = 0;
  let terminated = 0;
  let closedSessions = 0;
  let peak = 0;
  let completedStreams = 0;
  let closedStreams = 0;
  let peakActiveStreams = 0;
  let streamProgress = { opened_streams: 0, writes_completed: 0, acks_read: 0 };
  let livenessSweeps = 0;
  let livenessFailures = 0;
  let livenessEnabled = true;
  let livenessError;
  let livenessTask = Promise.resolve();
  let livenessTimer;
  let sequence = 0;
  let site;
  let browser;
  let browserVersion = "";
  let context;
  let page;
  let cdp;
  let server;
  let quiesced = false;
  let lastChromiumMetrics = {};
  let finalized = false;

  const recordEvent = (event, sessionID = "") => {
    events.push({
      sequence: ++sequence,
      at: new Date().toISOString(),
      monotonic_ms: performance.now(),
      event,
      ...(sessionID === "" ? {} : { session_id: sessionID }),
    });
  };

  const recordBrowserDiagnostic = (value) => {
    if (typeof value !== "string" || browserDiagnostics.length >= 32) return;
    browserDiagnostics.push(value.slice(0, 1024));
  };

  const notifyTermination = async (value) => {
    const sessionID = sessionIDValue(value?.session_id);
    const token = stringValue(value?.token, "termination token");
    const record = records.get(sessionID);
    if (record === undefined || record.token !== token) return;
    if (record.status !== "terminated" && record.status !== "closed") {
      record.status = "terminated";
      terminated++;
      recordEvent("session_terminated", sessionID);
    }
    let lastError;
    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        const response = await fetchImpl(plan.event_sink_url, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ schema_version: 1, action: "terminated", session_id: sessionID, token }),
        });
        if (!response.ok) throw new Error(`termination event sink returned HTTP ${response.status}`);
        return;
      } catch (error) {
        lastError = error;
        if (attempt < 3) await new Promise((resolve) => setTimeout(resolve, attempt * 50));
      }
    }
    recordEvent("termination_delivery_failed", sessionID);
    throw lastError;
  };

  try {
    await ensureEmptyOutputDirectory(plan.output_directory);
    site = await startBrowserModuleSite(plan.module_bind_address, plan.module_advertise_host, {
      secure: true,
      outputDirectory: plan.output_directory,
    });
    browser = await playwright.launch(chromiumCapacityLaunchOptions(
      plan,
      chromiumExecutablePath(playwright),
      launcherPath,
      site.origin,
    ));
    browserVersion = browser.version();
    context = await browser.newContext({ ignoreHTTPSErrors: true });
    await context.tracing.start({ screenshots: false, snapshots: false, sources: false });
    page = await context.newPage();
    page.on("requestfailed", (request) => recordBrowserDiagnostic(
      `request failed: ${request.url()} ${request.failure()?.errorText ?? "unknown"}`,
    ));
    page.on("response", (response) => {
      if (response.status() >= 400) recordBrowserDiagnostic(`response ${response.status()}: ${response.url()}`);
    });
    page.on("pageerror", (error) => recordBrowserDiagnostic(`page error: ${error.message}`));
    page.on("console", (message) => {
      if (message.type() === "error") recordBrowserDiagnostic(`console error: ${message.text()}`);
    });
    await page.exposeBinding("__flowersecCapacitySpend", async (_source, token) => {
      const response = await fetchImpl(plan.event_sink_url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ schema_version: 1, action: "spend", token: stringValue(token, "spend token") }),
      });
      if (!response.ok) throw new Error(`artifact spend failed with HTTP ${response.status}`);
    });
    await page.exposeBinding("__flowersecCapacityTerminated", async (_source, value) => {
      await notifyTermination(value);
    });
    await page.exposeBinding("__flowersecCapacityRecordDiagnostic", async (_source, value) => {
      recordBrowserDiagnostic(value);
    });
    await installWebTransportCertificateHash(
      page,
      plan.certificate_hash,
      "chromium",
      plan.topology === "browser_tunnel_wt_wss",
    );
    await page.goto(site.origin, { waitUntil: "networkidle" });
    await preloadBrowserSDK(page);
    cdp = await context.newCDPSession(page);
    await cdp.send("Performance.enable");

    const closeSession = createBrowserCapacityCloseBatcher(async (batch) => {
      await withTimeout(page.evaluate(async (entries) => {
        const sessions = globalThis.__flowersecCapacitySessions;
        const results = await Promise.allSettled(entries.map(async ({ id, spendToken }) => {
          const entry = sessions?.get(id);
          if (entry === undefined || entry.token !== spendToken) throw new Error("browser capacity session is unavailable");
          await Promise.allSettled((entry.streams ?? []).map(async (stream) => await stream.close()));
          await entry.session.close();
          await entry.session.waitClosed();
          sessions.delete(id);
        }));
        const failed = results.find((result) => result.status === "rejected");
        if (failed !== undefined) throw failed.reason;
      }, batch), plan.operation_deadline_ms, "browser session cleanup batch");
    });

    server = http.createServer(async (request, response) => {
      try {
        if (request.method === "POST" && request.url === "/v1/connect") {
          const body = await readJSONBody(request);
          const sessionID = sessionIDValue(body.session_id);
          const token = stringValue(body.token, "session token");
          const artifactJSON = stringValue(body.artifact_json, "artifact_json");
          JSON.parse(artifactJSON);
          if (records.has(sessionID)) return respondJSON(response, 409, { error: "duplicate session_id" });
          if (records.size >= plan.sessions) return respondJSON(response, 409, { error: "capacity exceeded" });
          const record = { token, status: "connecting", activeStreams: 0 };
          records.set(sessionID, record);
          recordEvent("connect_started", sessionID);
          try {
            await withTimeout(page.evaluate(async ({ id, spendToken, rawArtifact }) => {
              const sdk = await import("/dist/browser/index.js");
              globalThis.__flowersecCapacitySessions ??= new Map();
              if (globalThis.__flowersecCapacitySessions.has(id)) throw new Error("duplicate browser capacity session ID");
              const lease = sdk.createArtifactLease(
                sdk.parseArtifact(rawArtifact),
                async () => await globalThis.__flowersecCapacitySpend(spendToken),
              );
              let session;
              try {
                session = await sdk.connect(lease);
                globalThis.__flowersecCapacitySessions.set(id, { session, token: spendToken });
                void session.waitClosed().then(async () => {
                  await globalThis.__flowersecCapacityTerminated({ session_id: id, token: spendToken });
                });
                await session.probeLiveness();
              } catch (error) {
                try {
                  await globalThis.__flowersecCapacityRecordDiagnostic(JSON.stringify({
                    type: "connect_error",
                    name: error instanceof Error ? error.name : "Error",
                    message: error instanceof Error ? error.message : String(error),
                  }));
                  const internal = await import("/dist/utils/errors.js");
                  if (error instanceof internal.ConnectError) {
                    const details = internal.connectErrorDetailsInternal(error);
                    await globalThis.__flowersecCapacityRecordDiagnostic(JSON.stringify({
                      type: "connect",
                      public_code: error.code,
                      internal_code: details.code,
                      stage: details.stage,
                      candidates: details.diagnostics.slice(0, 4).map((diagnostic) => ({
                        carrier: diagnostic.carrier,
                        stage: diagnostic.stage,
                        code: diagnostic.code,
                        message: diagnostic.message.slice(0, 256),
                      })),
                    }));
                  }
                } catch {
                  // Internal diagnostics must never replace the public connection failure.
                }
                globalThis.__flowersecCapacitySessions.delete(id);
                if (session !== undefined) await session.close().catch(() => undefined);
                throw error;
              }
            }, { id: sessionID, spendToken: token, rawArtifact: artifactJSON }), plan.operation_deadline_ms, "browser session connect");
          } catch (error) {
            records.delete(sessionID);
            recordBrowserDiagnostic(JSON.stringify({
              type: "controller_connect_error",
              session_id: sessionID,
              name: error instanceof Error ? error.name : "Error",
              message: error instanceof Error ? error.message : String(error),
            }));
            recordEvent("connect_failed", sessionID);
            throw error;
          }
          if (record.status === "terminated") throw new Error("browser session terminated during connect");
          record.status = "connected";
          connected++;
          peak = Math.max(peak, activeSessions(records));
          recordEvent("connect_completed", sessionID);
          return respondJSON(response, 201, { schema_version: 1, session_id: sessionID, active_sessions: activeSessions(records) });
        }
        if (request.method === "POST" && request.url === "/v1/open-streams") {
          const body = await readJSONBody(request);
          if (plan.workload !== "stream_capacity" || body.sessions !== 100 || body.connections_per_session !== 1 || body.streams_per_session !== 128 ||
              records.size !== 100 || activeSessions(records) !== 100 || completedStreams !== 0) {
            return respondJSON(response, 409, { error: "stream capacity precondition failed" });
          }
          let streamResult;
          try {
            streamResult = await withTimeout(page.evaluate(async ({ sessionCount, streamsPerSession, assignments }) => {
              const sdk = await import("/dist/browser/index.js");
              const entries = [...(globalThis.__flowersecCapacitySessions?.entries() ?? [])].sort(([left], [right]) => left.localeCompare(right));
              if (entries.length !== sessionCount) throw new Error("browser stream capacity session count mismatch");
              globalThis.__flowersecCapacityStreamProgress = { opened_streams: 0, writes_completed: 0, acks_read: 0 };
			  const results = await Promise.all(entries.map(async ([id, entry], sessionIndex) => {
				const streams = new Array(streamsPerSession);
				await Promise.all(assignments.map(async (indexes) => {
				  for (const streamIndex of indexes) {
					const stream = await entry.session.openStream("capacity-bidi", {
					  metadata: sdk.createStreamMetadata({ session_index: sessionIndex, stream_index: streamIndex }),
					});
					globalThis.__flowersecCapacityStreamProgress.opened_streams++;
					const payload = new Uint8Array([sessionIndex & 255, streamIndex & 255]);
					const written = await stream.write(payload);
					if (written !== payload.byteLength) throw new Error("browser stream capacity short write");
					globalThis.__flowersecCapacityStreamProgress.writes_completed++;
					await stream.closeWrite();
					const ack = await stream.read();
					if (!(ack instanceof Uint8Array) || ack.byteLength !== 2 || ack[0] !== (payload[0] ^ 255) || ack[1] !== (payload[1] ^ 255)) {
					  throw new Error("browser stream capacity acknowledgement mismatch");
					}
					globalThis.__flowersecCapacityStreamProgress.acks_read++;
					streams[streamIndex] = stream;
				  }
				}));
				if (streams.some((stream) => stream === undefined)) throw new Error("browser stream capacity assignment was incomplete");
                entry.streams = streams;
                return { id, streams: streams.length };
              }));
              return { sessions: results.length, streams: results.reduce((total, result) => total + result.streams, 0), progress: globalThis.__flowersecCapacityStreamProgress };
            }, {
              sessionCount: 100,
              streamsPerSession: 128,
              assignments: capacityStreamAssignments(128, plan.stream_workers_per_session),
            }), plan.operation_deadline_ms, "browser 12800-stream capacity");
          } catch (error) {
            streamProgress = await page.evaluate(() => globalThis.__flowersecCapacityStreamProgress ?? { opened_streams: 0, writes_completed: 0, acks_read: 0 }).catch(() => streamProgress);
            const reason = error instanceof Error ? error.message : String(error);
            throw new Error(`browser stream capacity failed: opened=${streamProgress.opened_streams} writes=${streamProgress.writes_completed} acks=${streamProgress.acks_read}: ${reason}`, { cause: error });
          }
          if (streamResult.sessions !== 100 || streamResult.streams !== 12_800) throw new Error("browser stream capacity result mismatch");
          streamProgress = streamResult.progress;
          completedStreams = streamResult.streams;
          for (const record of records.values()) record.activeStreams = 128;
          peakActiveStreams = completedStreams;
          recordEvent("stream_capacity_completed");
          return respondJSON(response, 200, { schema_version: 1, completed_streams: completedStreams, active_streams: activeStreamsCount(records) });
        }
        if (request.method === "POST" && request.url === "/v1/close") {
		  livenessEnabled = false;
		  await livenessTask;
		  if (livenessError !== undefined) throw livenessError;
          const body = await readJSONBody(request);
          const sessionID = sessionIDValue(body.session_id);
          const token = stringValue(body.token, "session token");
          const record = records.get(sessionID);
          if (record === undefined || record.token !== token) return respondJSON(response, 404, { error: "unknown session" });
          await closeSession({ id: sessionID, spendToken: token });
          if (record.status !== "closed") {
			closedStreams += record.activeStreams;
			record.activeStreams = 0;
            record.status = "closed";
            closedSessions++;
            recordEvent("session_closed", sessionID);
          }
          return respondJSON(response, 200, { schema_version: 1, session_id: sessionID, active_sessions: activeSessions(records) });
        }
        if (request.method === "GET" && request.url === "/v1/snapshot") {
		  if (livenessError !== undefined) throw livenessError;
          const snapshot = await captureResourceSnapshot(cdp, records, lastChromiumMetrics);
          lastChromiumMetrics = snapshot.chromium;
          resourceSamples.push(snapshot);
          return respondJSON(response, 200, { schema_version: 1, ...snapshot });
        }
        if (request.method === "POST" && request.url === "/v1/quiesce") {
          await quiesce();
          return respondJSON(response, 200, { schema_version: 1, status: "quiesced" });
        }
        if (request.method === "POST" && request.url === "/v1/shutdown") {
		  livenessEnabled = false;
		  await livenessTask;
          if (activeSessions(records) !== 0) {
            await page.evaluate(async () => {
              const entries = [...(globalThis.__flowersecCapacitySessions?.values() ?? [])];
              await Promise.allSettled(entries.map(async (entry) => await entry.session.close()));
              globalThis.__flowersecCapacitySessions?.clear();
            });
            for (const [sessionID, record] of records) {
              if (record.status === "connecting" || record.status === "connected" || record.status === "terminated") {
				closedStreams += record.activeStreams;
				record.activeStreams = 0;
                record.status = "closed";
                closedSessions++;
                recordEvent("session_force_closed", sessionID);
              }
            }
          }
          respondJSON(response, 202, { schema_version: 1, status: "closing" });
          setImmediate(() => finalize().catch((error) => {
            process.stderr.write(`${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
            process.exitCode = 1;
          }));
          return;
        }
        respondJSON(response, 404, { error: "not found" });
      } catch (error) {
        respondJSON(response, 500, { error: error instanceof Error ? error.message : String(error) });
      }
    });
    await listen(server, plan.control_bind_address);
    recordEvent("controller_ready");
	  livenessTimer = setInterval(() => {
		if (!livenessEnabled || livenessError !== undefined) return;
		const sessionIDs = [...records.entries()].filter(([, record]) => record.status === "connected").map(([sessionID]) => sessionID);
		if (sessionIDs.length === 0) return;
		livenessTask = livenessTask.then(async () => {
		  await withTimeout(page.evaluate(async (ids) => {
			const sessions = globalThis.__flowersecCapacitySessions;
			await Promise.all(ids.map(async (id) => {
			  const entry = sessions?.get(id);
			  if (entry === undefined) throw new Error("browser capacity liveness session is unavailable");
			  await entry.session.probeLiveness();
			}));
		  }, sessionIDs), plan.operation_deadline_ms, "browser capacity liveness sweep");
		  livenessSweeps++;
		  recordEvent("liveness_sweep_completed");
		}).catch((error) => {
		  livenessFailures++;
		  livenessError = error instanceof Error ? error : new Error(String(error));
		  recordEvent("liveness_sweep_failed");
		});
	  }, 15_000);
	  livenessTimer.unref();
  } catch (error) {
    await forceClose().catch(() => undefined);
    throw error;
  }

  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("browser capacity controller did not bind TCP");
  const host = plan.control_bind_address.includes(":") ? `[${plan.control_bind_address}]` : plan.control_bind_address;
  const controllerClosed = new Promise((resolve) => server.once("close", resolve));
  return {
    url: `http://${host}:${address.port}`,
    chromiumVersion: browserVersion,
    closed: controllerClosed,
    async close() { await finalize(); },
  };

  async function finalize() {
    if (finalized) return;
    finalized = true;
    await quiesce();
    const residualSessions = activeSessions(records);
    recordEvent("controller_shutdown");
    const output = {
      schema_version: 1,
      classification: "raw_chromium_webtransport_capacity",
      topology: plan.topology,
      profile_id: plan.profile_id,
      browser: { engine: "chromium", version: browserVersion, diagnostics: browserDiagnostics },
      started_at: startedAt.toISOString(),
      finished_at: new Date().toISOString(),
      connected_sessions: connected,
      unique_sessions: records.size,
      peak_active_sessions: peak,
      terminated_sessions: terminated,
      closed_sessions: closedSessions,
      residual_sessions: residualSessions,
      completed_streams: completedStreams,
      peak_active_streams: peakActiveStreams,
      closed_streams: closedStreams,
      residual_streams: activeStreamsCount(records),
      stream_progress: streamProgress,
      liveness_sweeps: livenessSweeps,
      liveness_failures: livenessFailures,
      events,
      resource_samples: resourceSamples,
    };
    await writeOutput(plan.output_directory, "controller-result.json", output);
    await writeOutput(plan.output_directory, "controller-config.json", plan);
    await ensureNonemptyFile(path.join(plan.output_directory, "chromium-netlog.json"));
    await closeServer(server);
  }

  async function quiesce() {
    if (quiesced) return;
	if (livenessTimer !== undefined) clearInterval(livenessTimer);
	livenessEnabled = false;
	await livenessTask;
    if (livenessError !== undefined) throw livenessError;
    if (activeSessions(records) !== 0 || activeStreamsCount(records) !== 0) {
      throw new Error("browser capacity quiesce requires zero active sessions and streams");
    }
    recordEvent("controller_quiescing");
    const finalChromiumSnapshot = await captureResourceSnapshot(cdp, records, lastChromiumMetrics);
    lastChromiumMetrics = finalChromiumSnapshot.chromium;
    resourceSamples.push(finalChromiumSnapshot);
    await context.tracing.stop({ path: path.join(plan.output_directory, "chromium-trace.zip") });
    await browser.close();
    browser = undefined;
    cdp = undefined;
    await site.close();
    site = undefined;
    quiesced = true;
    recordEvent("controller_quiesced");
  }

  async function forceClose() {
	if (livenessTimer !== undefined) clearInterval(livenessTimer);
	livenessEnabled = false;
    if (context !== undefined) await context.close().catch(() => undefined);
    if (browser !== undefined) await browser.close().catch(() => undefined);
    if (site !== undefined) await site.close().catch(() => undefined);
    if (server !== undefined) await closeServer(server).catch(() => undefined);
  }
}

function activeSessions(records) {
  let active = 0;
  for (const record of records.values()) if (record.status === "connecting" || record.status === "connected") active++;
  return active;
}

function activeStreamsCount(records) {
  let active = 0;
  for (const record of records.values()) active += record.activeStreams ?? 0;
  return active;
}

async function captureResourceSnapshot(cdp, records, previousChromium = {}) {
  const performanceMetrics = cdp === undefined ? undefined : await cdp.send("Performance.getMetrics");
  const memory = process.memoryUsage();
  const usage = process.resourceUsage();
  return {
    at: new Date().toISOString(),
    active_sessions: activeSessions(records),
    process: {
      rss_bytes: memory.rss,
      heap_total_bytes: memory.heapTotal,
      heap_used_bytes: memory.heapUsed,
      user_cpu_microseconds: usage.userCPUTime,
      system_cpu_microseconds: usage.systemCPUTime,
      max_rss_kib: usage.maxRSS,
    },
    chromium: performanceMetrics === undefined
      ? previousChromium
      : Object.fromEntries(performanceMetrics.metrics.map(({ name, value }) => [name, value])),
  };
}

async function ensureEmptyOutputDirectory(directory) {
  const entries = await fs.readdir(directory);
  if (entries.length !== 0) throw new Error("browser capacity output directory must be empty");
}

async function writeOutput(directory, name, value) {
  await fs.writeFile(path.join(directory, name), `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
}

async function ensureNonemptyFile(file) {
  const stat = await fs.stat(file);
  if (!stat.isFile() || stat.size === 0) throw new Error(`${path.basename(file)} is empty`);
}

async function readJSONBody(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > (1 << 20)) throw new Error("request body is too large");
    chunks.push(chunk);
  }
  const value = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  if (value === null || typeof value !== "object" || Array.isArray(value) || value.schema_version !== 1) {
    throw new Error("request body is invalid");
  }
  return value;
}

function respondJSON(response, status, value) {
  if (response.headersSent) return;
  const body = `${JSON.stringify(value)}\n`;
  response.writeHead(status, { "cache-control": "no-store", "content-type": "application/json", "content-length": Buffer.byteLength(body) });
  response.end(body);
}

function listen(server, address) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, address, resolve);
  });
}

function closeServer(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => error === undefined ? resolve() : reject(error));
    server.closeAllConnections?.();
  });
}

function withTimeout(promise, milliseconds, name) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`${name} exceeded`)), milliseconds); }),
  ]).finally(() => clearTimeout(timer));
}

function sessionIDValue(value) {
  const id = stringValue(value, "session_id");
  if (!sessionIDPattern.test(id)) throw new Error("session_id contains unsafe characters");
  return id;
}

function stringValue(value, name) {
  if (typeof value !== "string" || value.length === 0 || value.length > (1 << 18)) throw new Error(`${name} is invalid`);
  return value;
}

async function main(args) {
  if (args.length !== 2 || args[0] !== "--plan" || path.resolve(args[1]) !== args[1]) {
    throw new Error("usage: browser-capacity-controller.mjs --plan ABSOLUTE_PATH");
  }
  const plan = JSON.parse(await fs.readFile(args[1], "utf8"));
  const controller = await startBrowserCapacityController(plan);
  process.stdout.write(`${JSON.stringify({ schema_version: 1, status: "ready", control_url: controller.url, chromium_version: controller.chromiumVersion })}\n`);
  await controller.closed;
}

if (process.argv[1] !== undefined && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
