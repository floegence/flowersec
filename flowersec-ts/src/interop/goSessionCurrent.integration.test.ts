import { execFile, spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import {
  MethodDefinition, ServiceDefinition, bytesMessageCodec, connect, createHandlerPlan, createStaticServiceContracts,
  type HandlerPlan, type Session, type Stream, type ServiceClient, type PoolServerAllowBinding,
} from "../node/index.js";
import {
  configureCurrentPeerWSS, createCurrentPeerClient, peerBytes, peerJSONBytes, peerJSONValue, peerRequirements,
  installCurrentPoolServerAllow, type CurrentPoolClientInstallation, type CurrentPeerClient,
} from "./currentPeer.js";

interface OriginalSessionReady {
  readonly type: "ready";
  readonly runtime: "go";
  readonly carrier: "websocket";
  readonly path: "direct" | "tunnel";
  readonly wire_revision: 4;
  readonly artifact_json: string;
  readonly trust_pem: string;
  readonly origin: string;
  readonly profile: string;
  readonly source: "preauthorized_pool";
  readonly application_namespace: "flowersec.session.exchange";
  readonly service_query_type: number;
  readonly service_query_digest: string;
  readonly service_schema_digest: string;
  readonly service_contracts: readonly Readonly<{ type_id: number; contract: string }>[];
  readonly client_listener_tls: Readonly<{ certificatePEM: string; privateKeyPEM: string }> | null;
  readonly pool_client_deployment?: CurrentPoolClientInstallation;
  readonly server_allow?: PoolServerAllowBinding;
}
const namespace = "flowersec.session.exchange";
const encoder = new TextEncoder();
let peerDirectory: string | undefined;
let peerExecutable: string;
beforeAll(async () => {
  peerDirectory = await mkdtemp(join(tmpdir(), "flowersec-ts-session-peer-"));
  peerExecutable = join(peerDirectory, process.platform === "win32" ? "session-peer.exe" : "session-peer");
  try {
    await promisify(execFile)("go", ["build", "-o", peerExecutable, "./internal/cmd/ts-session-peer"], {
      cwd: new URL("../../../flowersec-go/", import.meta.url), timeout: 60000, maxBuffer: 65536,
    });
  } catch (error) { await rm(peerDirectory, { recursive: true, force: true }); peerDirectory = undefined; throw error; }
}, 65000);
afterAll(async () => { if (peerDirectory !== undefined) await rm(peerDirectory, { recursive: true, force: true }); });

async function bounded<T>(operation: Promise<T>, milliseconds: number, message: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([operation, new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error(message)), milliseconds);
    })]);
  } finally { if (timer !== undefined) clearTimeout(timer); }
}

/** Starts only the original current Go source. Original credentials, contracts,
 * TLS installation and admission remain owned by that concrete deployment. */
async function startOriginalSessionPeer(path: "direct" | "tunnel") {
  // Own the executable directly so Close joins the actual peer rather than a
  // compiler process whose child can outlive process-group signaling.
  const child = spawn(peerExecutable, ["--path", path, "--server-notify"], {
    cwd: new URL("../../../flowersec-go/", import.meta.url),
    env: { ...process.env, FLOWERSEC_SERVER_PARITY_PEER: "1" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let diagnostic = "", output = "", exited = false, launchError: Error | undefined;
  const completed = new Promise<Readonly<{ code: number | null; signal: NodeJS.Signals | null; error?: Error }>>(resolve => {
    child.once("error", error => { launchError = error; });
    child.once("close", (code, signal) => { exited = true; resolve({ code, signal, ...(launchError === undefined ? {} : { error: launchError }) }); });
  });
  child.stderr.setEncoding("utf8"); child.stderr.on("data", (chunk: string) => { diagnostic = (diagnostic + chunk).slice(-65536); });
  const terminate = (signal: NodeJS.Signals) => {
    if (exited || child.pid === undefined) return;
    try { child.kill(signal); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== "ESRCH") throw error; }
  };
  let stopping: Promise<void> | undefined;
  const stop = () => stopping ??= (async () => {
    if (exited) return;
    terminate("SIGTERM");
    const escalation = setTimeout(() => { try { terminate("SIGKILL"); } catch { child.kill("SIGKILL"); } }, 1000);
    try { await bounded(completed, 5000, "original session peer cleanup timed out"); }
    finally { clearTimeout(escalation); }
  })();
  let receiveLine!: (line: string) => void, rejectLine!: (error: Error) => void;
  const firstLine = new Promise<string>((resolve, reject) => { receiveLine = resolve; rejectLine = reject; });
  child.stdout.setEncoding("utf8");
  const receive = (chunk: string) => {
    if (output.length + chunk.length > 1048576) { rejectLine(new Error("original session readiness exceeds its bound")); return; }
    output += chunk;
    const newline = output.indexOf("\n");
    if (newline >= 0) { child.stdout.removeListener("data", receive); child.stdout.resume(); receiveLine(output.slice(0, newline)); }
  };
  child.stdout.on("data", receive);
  void completed.then(result => rejectLine(result.error ?? new Error(`original session peer exited ${String(result.code)} before readiness: ${diagnostic}`)));
  try {
    const ready = JSON.parse(await bounded(firstLine, 15000, "original session peer readiness timed out")) as OriginalSessionReady;
    if (ready === null || typeof ready !== "object" || ready.type !== "ready" || ready.runtime !== "go" || ready.carrier !== "websocket" ||
        ready.path !== path || ready.wire_revision !== 4 || ready.source !== "preauthorized_pool" || ready.application_namespace !== namespace ||
        typeof ready.artifact_json !== "string" || typeof ready.trust_pem !== "string" || typeof ready.origin !== "string" || typeof ready.profile !== "string" ||
        !Number.isSafeInteger(ready.service_query_type) || ready.service_query_type <= 0 || ready.service_query_type > 0xffffffff ||
        !Array.isArray(ready.service_contracts) || ready.service_contracts.length !== 2) throw new Error("invalid original session readiness");
    if (path === "tunnel" && (ready.client_listener_tls === null || typeof ready.client_listener_tls?.certificatePEM !== "string" || typeof ready.client_listener_tls.privateKeyPEM !== "string")) {
      throw new Error("original tunnel client TLS installation is absent");
    }
    return Object.freeze({ ready, stop, get diagnostics() { return diagnostic; }, async wait() {
      const result = await bounded(completed, 20000, "original session peer completion timed out");
      if (result.error !== undefined) throw result.error;
      if (result.code !== 0 || result.signal !== null) throw new Error(`original session peer failed ${String(result.code)} (${String(result.signal)}): ${diagnostic}`);
    } });
  } catch (error) { await stop(); throw error; }
  finally { child.stdout.removeListener("data", receive); }
}

describe("current TypeScript-Go original Session exchange", () => {
  test("runs direct original notification/payload/rekey Session semantics over current Go WSS", async () => {
    await runOriginalSessionExchange("direct");
  }, 75000);
  test("runs tunnel-role original notification/payload/rekey Session semantics through current Go WSS", async () => {
    await runOriginalSessionExchange("tunnel");
  }, 75000);
});

function notificationMethod(typeID: number, codec: ReturnType<typeof bytesMessageCodec>) {
  return new MethodDefinition({ typeID, shape: "notify", notifySemantics: "observation", request: codec,
    requestMaxBytes: 4096, responseRevision: "1", restartFlush: false });
}

async function runOriginalSessionExchange(path: "direct" | "tunnel"): Promise<void> {
  const peer = await startOriginalSessionPeer(path), { ready } = peer;
  const signal = AbortSignal.timeout(25000), owned: Uint8Array[] = [];
  let fixture: CurrentPeerClient | undefined, plan: HandlerPlan | undefined, session: Session | undefined, stream: Stream | undefined;
  let contracts: ReturnType<typeof createStaticServiceContracts> | undefined;
  let poolServerAllow: ReturnType<typeof installCurrentPoolServerAllow> | undefined;
  let service: ServiceClient<{ ready: ReturnType<typeof notificationMethod>; accepted: ReturnType<typeof notificationMethod> }> | undefined;
  let phase = "installation";
  let failure: Error | undefined;
  try {
    const schema = peerBytes(ready.service_schema_digest, 32, 32), query = peerBytes(ready.service_query_digest, 32, 32); owned.push(schema, query);
    const codec = bytesMessageCodec({ schemaDigest: schema, revision: "1", maxMessageBytes: 4096 });
    const clientNotification = notificationMethod(9001, codec), serverNotification = notificationMethod(9002, codec);
    const definition = new ServiceDefinition({ namespace, methods: { ready: clientNotification, accepted: serverNotification } });
    const installed = new Map<number, Uint8Array>();
    for (const record of ready.service_contracts) {
      if (record === null || typeof record !== "object" || ![9001, 9002].includes(record.type_id) || installed.has(record.type_id)) throw new Error("original notification contracts differ");
      const wire = peerBytes(record.contract, 65536); owned.push(wire); installed.set(record.type_id, wire);
    }
    if (installed.size !== 2) throw new Error("original notification contracts are incomplete");
    fixture = await createCurrentPeerClient(ready.artifact_json, { trustPEM: ready.trust_pem });
    if (fixture.path !== path || fixture.carrierKind !== "websocket" || fixture.material.profile !== ready.profile || fixture.material.source !== ready.source) throw new Error("original Session material disagrees with its deployment");
    let notifications = 0, acceptNotification!: () => void;
    const accepted = new Promise<void>(resolve => { acceptNotification = resolve; });
    plan = createHandlerPlan(fixture.environment, { applicationBytes: 16384n, services: {
      profile: "services", query: { typeID: ready.service_query_type, contractDigest: query }, definitions: [definition], maxMethods: 2, maxCaptureBytes: 1048576,
      queryPermissions: [clientNotification, serverNotification].map(method => ({ namespace, method, permission: "allowed" as const })),
      notificationMethods: [{ namespace, method: clientNotification, contract: installed.get(9001)!, permission: "allowed" }],
      notificationHandlers: [{ namespace, method: serverNotification, contract: installed.get(9002)!, handler: async (_context, request: Uint8Array) => {
        expect(peerJSONValue(request)).toEqual({ state: "accepted" });
        if (++notifications !== 1) throw new Error("original reverse notification exceeded its one position");
        acceptNotification();
      }, options: { workClass: "short", applicationBytes: 16384n, authorization: "authenticated", applicationTimeoutMS: 10000n } }],
    }, streams: [] });
    if (path === "tunnel") poolServerAllow = installCurrentPoolServerAllow(fixture, ready.pool_client_deployment, ready.server_allow);
    const connector = configureCurrentPeerWSS(fixture, ready.origin, ready.trust_pem, plan, ready.client_listener_tls ?? undefined, poolServerAllow);
    phase = "connect";
    session = await connect(fixture.environment, fixture.registerSource(connector), peerRequirements, { signal });
    expect(fixture.spentCount()).toBe(1);
    phase = "liveness";
    const probe = await session.probeLiveness({ signal });
    // An authenticated PONG may precede the local provider completion callback.
    expect(probe.submitted).toBe(true);
    expect(probe.elapsedMS).toBeGreaterThanOrEqual(0n);
    const target = { authority: fixture.policy.authorities[0]!, tenant: fixture.policy.tenant, audience: fixture.policy.audience,
      localSubject: fixture.policy.clientSubject, peers: [{ subject: fixture.policy.serverSubject, identityDigest: fixture.serverIdentity }] };
    contracts = createStaticServiceContracts(fixture.environment, definition,
      [clientNotification, serverNotification].map(method => ({ method, contract: installed.get(method.typeID)! })), { target, maximumOfferWindowMS: 10000n });
    service = await session.bindService(definition, { target, contractSource: contracts, maximumOfferWindowMS: 10000n, signal });
    phase = "server-notify";
    const notification = await service.notify(clientNotification, peerJSONBytes({ state: "ready" }), { signal, timeoutMS: 10000n });
    expect(notification.submission).toBe("submitted");
    await bounded(accepted, 5000, "original reverse notification timed out"); expect(notifications).toBe(1);
    stream = await session.openStream("interop.echo", { signal });
    phase = "first-data"; await writeExact(stream, "hello-go", signal); await readExact(stream, "hello-ts", signal);
    phase = "go-rekey"; await readExact(stream, "go-rekey-ok", signal);
    phase = "ts-rekey"; await session.rekey({ signal }); await writeExact(stream, "ts-rekey-ok", signal);
    await stream.closeWrite({ signal }); await readExact(stream, "done", signal);
    const end = await stream.read(1n, { signal }); expect(end.wait_status).toBe("ready"); expect(end.stream_status).toBe("eof"); expect(end.data).toEqual(new Uint8Array());
    const finished = await stream.finish({ signal }); expect(finished.send_drained).toBe(true); expect(finished.read_terminal).toBe("eof");
    phase = "close"; service.close(); contracts.close(); plan.close(); await stream.close(); await session.close();
    expect((await session.waitCleanup({ signal })).status).toBe("complete"); expect(fixture.spentCount()).toBe(1); expect(notifications).toBe(1);
    await fixture.close(); await peer.wait();
  } catch (error) {
    failure = new Error(`current original Session exchange failed during ${phase}: ${error instanceof Error ? error.message : String(error)}`, { cause: error });
    throw failure;
  } finally {
    service?.close(); contracts?.close(); plan?.close();
    const cleanup = await Promise.allSettled([stream?.close(), session?.close(), poolServerAllow?.close(), fixture?.close(), peer.stop()]);
    for (const bytes of owned) bytes.fill(0);
    const errors = cleanup.filter((result): result is PromiseRejectedResult => result.status === "rejected").map(result => result.reason);
    if (errors.length > 0) throw new AggregateError(failure === undefined ? errors : [failure, ...errors], `original Session exchange cleanup failed: ${peer.diagnostics}`, { cause: failure });
    if (failure !== undefined && peer.diagnostics.length > 0) throw new Error(`${failure.message}; Go peer: ${peer.diagnostics}`, { cause: failure });
  }
}

async function writeExact(stream: Stream, payload: string, signal: AbortSignal): Promise<void> {
  const bytes = encoder.encode(payload), result = await stream.write(bytes, { signal });
  expect(result.phase).toBe("terminal"); expect(result.terminal_reason).toBe("complete"); expect(result.accepted_bytes).toBe(BigInt(bytes.length));
}
async function readExact(stream: Stream, payload: string, signal: AbortSignal): Promise<void> {
  const expected = encoder.encode(payload), actual = new Uint8Array(expected.length); let length = 0;
  while (length < actual.length) {
    const result = await stream.read(BigInt(actual.length - length), { signal });
    if (result.wait_status !== "ready" || !["open", "eof"].includes(result.stream_status) || result.data.length === 0 || result.data.length > actual.length - length) {
      throw new Error(`original Session payload ended early or failed reliable progress: wait=${result.wait_status}, stream=${result.stream_status}, received=${length}+${result.data.length}/${actual.length}`);
    }
    actual.set(result.data, length); length += result.data.length;
  }
  expect(actual).toEqual(expected);
}
