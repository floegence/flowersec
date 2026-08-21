import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, test } from "vitest";

import {
  AdmissionStatusV3,
  buildFSB3RequestV3,
  decodeArtifactV3JSON,
  decodeFSA3ResponseV3,
  encodeArtifactV3JSON,
  encodeFSB3RequestV3,
  type ArtifactCandidateV3,
  type ArtifactV3,
} from "../v3/artifact.js";
import { createArtifactLeaseV3Internal } from "../v3/artifactLease.js";
import { parseArtifactV3 } from "../v3/publicApi.js";
import { connectV3 } from "./connectSessionV3.js";
import {
  verifyTunnelAuthorizationGrantV3,
  type RuntimeAuthorizationRequestV3,
} from "./runtimeAuthorizationV3.js";
import {
  createTunnelRuntimeV3,
  type TunnelAuthorizationDecisionV3,
} from "./tunnelRuntimeV3.js";

const fixture = JSON.parse(readFileSync(
  new URL("../../../testdata/transport_v3/artifact_vectors.json", import.meta.url),
  "utf8",
)) as Readonly<{ positive: readonly Readonly<{ artifact_json: string }>[] }>;
const tunnelBase = decodeArtifactV3JSON(fixture.positive.find(({ artifact_json }) =>
  JSON.parse(artifact_json).path.kind === "tunnel")!.artifact_json);

type Deferred<T> = Readonly<{
  promise: Promise<T>;
  resolve(value: T): void;
}>;

let directory = "";
let certificate = "";
let privateKey = "";

describe("Node TunnelRuntimeV3 bounded admission and cleanup", () => {
  beforeAll(() => {
    directory = mkdtempSync(join(tmpdir(), "flowersec-node-tunnel-v3-bounds-"));
    const certificatePath = join(directory, "certificate.pem");
    const privateKeyPath = join(directory, "private-key.pem");
    execFileSync("openssl", [
      "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
      "-nodes", "-days", "1", "-sha256", "-subj", "/CN=localhost",
      "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
      "-keyout", privateKeyPath, "-out", certificatePath,
    ], { stdio: "ignore" });
    certificate = readFileSync(certificatePath, "utf8");
    privateKey = readFileSync(privateKeyPath, "utf8");
  });

  afterAll(() => {
    if (directory !== "") rmSync(directory, { recursive: true, force: true });
  });

  test("rejects a concurrent silent admission and releases the slot after timeout", async () => {
    let authorizations = 0;
    const runtime = createTunnelRuntimeV3({
      listeners: [listener()],
      maxInboundStreams: tunnelBase.session.max_inbound_streams,
      maxConcurrentAdmissions: 1,
      maxPendingLegs: 1,
      admissionTimeoutMs: 1_000,
      authorize: async () => {
        authorizations += 1;
        return { decision: "reject", reason: "invalid_credential" };
      },
    });
    let silent: any;
    let probe: any;
    try {
      await runtime.start();
      const port = runtime.addresses()[0]!.port;
      silent = await openSilentAdmission(port);
      const silentClosed = once(silent, "close");

      probe = await openSilentAdmission(port);
      const probeClosed = once(probe, "close");
      await expect(Promise.race([
        probeClosed.then(() => "probe" as const),
        silentClosed.then(() => "silent" as const),
      ])).resolves.toBe("probe");
      expect(authorizations).toBe(0);

      await expect(Promise.race([
        silentClosed.then(() => "closed" as const),
        delay(3_000).then(() => "timed-out" as const),
      ])).resolves.toBe("closed");
      await connect(port, 1).catch(() => undefined);
      await waitFor(() => authorizations === 1);
    } finally {
      probe?.terminate();
      silent?.terminate();
      await runtime.close();
    }
  }, 10_000);

  test("applies the cleanup deadline to a non-responsive WebSocket listener peer", async () => {
    const runtime = createTunnelRuntimeV3({
      listeners: [listener()],
      maxInboundStreams: tunnelBase.session.max_inbound_streams,
      cleanupTimeoutMs: 50,
      authorize: async () => ({ decision: "reject", reason: "invalid_credential" }),
    });
    let silent: any;
    try {
      await runtime.start();
      silent = await openSilentAdmission(runtime.addresses()[0]!.port);
      silent._socket.pause();
      await expect(Promise.race([
        runtime.close().then(() => "closed" as const),
        delay(500).then(() => "timed-out" as const),
      ])).resolves.toBe("closed");
    } finally {
      silent?.terminate();
      await runtime.close();
    }
  });

  test("releases one late allow after a hung authorization admission is canceled", async () => {
    const authorization = deferred<TunnelAuthorizationDecisionV3>();
    const authorizeStarted = deferred<void>();
    let authorizationSignal: AbortSignal | undefined;
    let authorizationRequest: RuntimeAuthorizationRequestV3 | undefined;
    let authorizationCalls = 0;
    const releases: Array<Readonly<{ leaseId: string; signal: AbortSignal }>> = [];
    const runtime = createTunnelRuntimeV3({
      listeners: [listener()],
      maxInboundStreams: tunnelBase.session.max_inbound_streams,
      maxConcurrentAdmissions: 1,
      admissionTimeoutMs: 50,
      cleanupTimeoutMs: 100,
      authorize: async (request, options) => {
        authorizationCalls += 1;
        authorizationRequest = request;
        authorizationSignal = options.signal;
        authorizeStarted.resolve();
        return await authorization.promise;
      },
      release: (leaseId, options) => {
        releases.push({ leaseId, signal: options.signal });
      },
    });
    let connecting: Promise<unknown> | undefined;
    try {
      await runtime.start();
      const port = runtime.addresses()[0]!.port;
      const artifact = tunnelArtifact(port, 1);
      connecting = connectV3(lease(artifact), {
        origin: "https://app.example",
        roots: certificate,
        connectTimeoutMs: 1_000,
      }).catch(() => undefined);
      await authorizeStarted.promise;
      await waitFor(() => authorizationSignal?.aborted === true);
      await connect(port, 1).catch(() => undefined);
      expect(authorizationCalls).toBe(1);
      if (authorizationRequest === undefined) throw new Error("authorization request was not observed");
      authorization.resolve(allow(authorizationRequest, artifact, "late-admission-lease"));
      await waitFor(() => releases.length === 1);
      await delay(20);
      expect(releases.map(({ leaseId }) => leaseId)).toEqual(["late-admission-lease"]);
      expect(releases[0]!.signal.aborted).toBe(false);
    } finally {
      await runtime.close();
      await connecting;
    }
  }, 10_000);

  test("rejects a structurally forged allow decision without spending a lease", async () => {
    const released: string[] = [];
    const runtime = createTunnelRuntimeV3({
      listeners: [listener()],
      maxInboundStreams: tunnelBase.session.max_inbound_streams,
      admissionTimeoutMs: 100,
      authorize: async () => ({ decision: "allow", grant: {} } as never),
      release: (leaseId) => { released.push(leaseId); },
    });
    try {
      await runtime.start();
      await expect(connectV3(lease(tunnelArtifact(runtime.addresses()[0]!.port, 1)), {
        origin: "https://app.example",
        roots: certificate,
        connectTimeoutMs: 1_000,
      })).rejects.toBeDefined();
      expect(released).toEqual([]);
    } finally {
      await runtime.close();
    }
  });

  test("cancels a stuck release callback at its cleanup deadline", async () => {
    const authorizeStarted = deferred<void>();
    const releaseStarted = deferred<AbortSignal>();
    let artifact!: ArtifactV3;
    const runtime = createTunnelRuntimeV3({
      listeners: [listener()],
      maxInboundStreams: tunnelBase.session.max_inbound_streams,
      admissionTimeoutMs: 500,
      cleanupTimeoutMs: 50,
      authorize: async (request) => {
        authorizeStarted.resolve();
        return allow(request, artifact, "bounded-release-lease");
      },
      release: async (_leaseId, options) => {
        releaseStarted.resolve(options.signal);
        await aborted(options.signal);
      },
    });
    let connecting: Promise<unknown> | undefined;
    try {
      await runtime.start();
      artifact = tunnelArtifact(runtime.addresses()[0]!.port, 1);
      connecting = connectV3(lease(artifact), {
        origin: "https://app.example",
        roots: certificate,
        connectTimeoutMs: 1_000,
      }).catch(() => undefined);
      await authorizeStarted.promise;
      await new Promise<void>((resolve) => setImmediate(resolve));

      const startedAt = Date.now();
      const closing = runtime.close();
      const signal = await releaseStarted.promise;
      expect(signal.aborted).toBe(false);
      await expect(Promise.race([
        closing.then(() => "closed" as const),
        delay(500).then(() => "unbounded" as const),
      ])).resolves.toBe("closed");
      expect(signal.aborted).toBe(true);
      expect(Date.now() - startedAt).toBeLessThan(500);
    } finally {
      await runtime.close();
      await connecting;
    }
  }, 10_000);

  test("releases activation leases and active-pair quota when control streams never arrive", async () => {
    const artifacts = new Map<string, ArtifactV3>();
    const released: string[] = [];
    const runtime = createTunnelRuntimeV3({
      listeners: [listener()],
      maxInboundStreams: tunnelBase.session.max_inbound_streams,
      maxActivePairs: 1,
      admissionTimeoutMs: 50,
      cleanupTimeoutMs: 50,
      authorize: async (request) => {
        const artifact = artifacts.get(request.lookupKey());
        return artifact === undefined
          ? { decision: "reject" as const, reason: "invalid_credential" }
          : allow(request, artifact, `activation-${artifact.path.kind === "tunnel" ? artifact.path.token : "invalid"}`);
      },
      release: (leaseId) => { released.push(leaseId); },
    });
    const sockets: any[] = [];
    try {
      await runtime.start();
      const port = runtime.addresses()[0]!.port;
      for (const generation of ["first", "second"]) {
        const first = tunnelArtifactGeneration(port, 1, generation);
        const second = tunnelArtifactGeneration(port, 2, generation);
        artifacts.set(firstRequestKey(first), first);
        artifacts.set(firstRequestKey(second), second);
        const firstAdmission = await openTunnelAdmission(port, first);
        const secondAdmission = await openTunnelAdmission(port, second);
        sockets.push(firstAdmission.socket, secondAdmission.socket);
        const firstClosed = once(firstAdmission.socket, "close");
        const secondClosed = once(secondAdmission.socket, "close");
        await expect(firstAdmission.response).resolves.toBe(AdmissionStatusV3.Success);
        await expect(secondAdmission.response).resolves.toBe(AdmissionStatusV3.Success);
        await Promise.all([firstClosed, secondClosed]);
      }
      await waitFor(() => released.length === 4);
    } finally {
      for (const socket of sockets) socket.terminate();
      await runtime.close();
    }
  }, 10_000);

  test("force-closes each replaced generation before reusing pair quotas", async () => {
    const artifacts = new Map<string, ArtifactV3>();
    const released: string[] = [];
    const runtime = createTunnelRuntimeV3({
      listeners: [listener()],
      maxInboundStreams: tunnelBase.session.max_inbound_streams,
      maxPendingLegs: 1,
      maxActivePairs: 1,
      admissionTimeoutMs: 500,
      cleanupTimeoutMs: 50,
      authorize: async (request) => {
        const artifact = artifacts.get(request.lookupKey());
        return artifact === undefined
          ? { decision: "reject" as const, reason: "invalid_credential" }
          : allow(
              request,
              artifact,
              `replacement-${artifact.path.kind === "tunnel" ? artifact.path.token : "invalid"}`,
              true,
            );
      },
      release: (leaseId) => { released.push(leaseId); },
    });
    const sockets: any[] = [];
    try {
      await runtime.start();
      const port = runtime.addresses()[0]!.port;
      const initialFirst = tunnelArtifactGeneration(port, 1, "initial");
      const initialSecond = tunnelArtifactGeneration(port, 2, "initial");
      for (const artifact of [initialFirst, initialSecond]) {
        artifacts.set(firstRequestKey(artifact), artifact);
      }
      const oldFirst = await openTunnelAdmission(port, initialFirst);
      const oldSecond = await openTunnelAdmission(port, initialSecond);
      sockets.push(oldFirst.socket, oldSecond.socket);
      const oldFirstClosed = once(oldFirst.socket, "close");
      const oldSecondClosed = once(oldSecond.socket, "close");
      await expect(oldFirst.response).resolves.toBe(AdmissionStatusV3.Success);
      await expect(oldSecond.response).resolves.toBe(AdmissionStatusV3.Success);

      const replacementOne = tunnelArtifactGeneration(port, 1, "replacement-one");
      artifacts.set(firstRequestKey(replacementOne), replacementOne);
      const pendingOne = await openTunnelAdmission(port, replacementOne);
      sockets.push(pendingOne.socket);
      const pendingOneClosed = once(pendingOne.socket, "close");
      await Promise.all([oldFirstClosed, oldSecondClosed]);
      expect(oldFirst.messageCount()).toBe(1);
      expect(oldSecond.messageCount()).toBe(1);

      const replacementTwo = tunnelArtifactGeneration(port, 1, "replacement-two");
      artifacts.set(firstRequestKey(replacementTwo), replacementTwo);
      const pendingTwo = await openTunnelAdmission(port, replacementTwo);
      sockets.push(pendingTwo.socket);
      await pendingOneClosed;

      const replacementPeer = tunnelArtifactGeneration(port, 2, "replacement-two");
      artifacts.set(firstRequestKey(replacementPeer), replacementPeer);
      const finalPeer = await openTunnelAdmission(port, replacementPeer);
      sockets.push(finalPeer.socket);
      const pendingTwoClosed = once(pendingTwo.socket, "close");
      const finalPeerClosed = once(finalPeer.socket, "close");
      await expect(pendingTwo.response).resolves.toBe(AdmissionStatusV3.Success);
      await expect(finalPeer.response).resolves.toBe(AdmissionStatusV3.Success);
      await Promise.all([pendingTwoClosed, finalPeerClosed]);
      await waitFor(() => released.length === 5);
      expect(new Set(released).size).toBe(5);
    } finally {
      for (const socket of sockets) socket.terminate();
      await runtime.close();
    }
  }, 10_000);
});

function listener() {
  return {
    carrier: "websocket" as const,
    host: "127.0.0.1",
    port: 0,
    tls: { certificate, privateKey },
    allowedOrigins: ["https://app.example"],
  };
}

function tunnelArtifact(port: number, role: 1 | 2): ArtifactV3 {
  if (tunnelBase.path.kind !== "tunnel") throw new Error("invalid tunnel fixture");
  return {
    ...tunnelBase,
    path: {
      ...tunnelBase.path,
      role,
      local_endpoint_instance_id: role === 1 ? "endpoint-client" : "endpoint-server",
      expected_peer_endpoint_instance_id: role === 1 ? "endpoint-server" : "endpoint-client",
      token: role === 1 ? "attach-token-client-v3" : "attach-token-server-v3",
      candidates: [candidate(port)],
    },
  };
}

function tunnelArtifactGeneration(port: number, role: 1 | 2, generation: string): ArtifactV3 {
  const artifact = tunnelArtifact(port, role);
  if (artifact.path.kind !== "tunnel") throw new Error("invalid tunnel fixture");
  return {
    ...artifact,
    path: {
      ...artifact.path,
      token: `${artifact.path.token}-${generation}`,
    },
  };
}

function candidate(port: number): ArtifactCandidateV3 {
  return {
    carrier: "websocket",
    id: "w-ca",
    url: `wss://localhost:${port}/flowersec/v3/tunnel`,
    tls: { mode: "ca" },
    wire_profile: "flowersec-tunnel/3",
  };
}

function lease(artifact: ArtifactV3) {
  return createArtifactLeaseV3Internal(artifact, async () => undefined);
}

function connect(port: number, role: 1 | 2): Promise<unknown> {
  return connectV3(lease(tunnelArtifact(port, role)), {
    origin: "https://app.example",
    roots: certificate,
    connectTimeoutMs: 500,
  });
}

function allow(
  request: RuntimeAuthorizationRequestV3,
  artifact: ArtifactV3,
  leaseId: string,
  allowReplacement = false,
): Extract<TunnelAuthorizationDecisionV3, Readonly<{ decision: "allow" }>> {
  if (artifact.path.kind !== "tunnel") throw new Error("invalid tunnel fixture");
  return {
    decision: "allow",
    grant: verifyTunnelAuthorizationGrantV3(
      request,
      parseArtifactV3(encodeArtifactV3JSON(artifact)),
      { leaseId, allowReplacement },
    ),
  };
}

function firstRequestKey(artifact: ArtifactV3): string {
  if (artifact.path.kind !== "tunnel") throw new Error("invalid tunnel fixture");
  return createHash("sha256").update(artifact.path.token).digest("base64url");
}

async function openTunnelAdmission(
  port: number,
  artifact: ArtifactV3,
): Promise<Readonly<{
  socket: any;
  response: Promise<AdmissionStatusV3>;
  messageCount(): number;
}>> {
  const require = createRequire(import.meta.url);
  const wsModule = require("ws") as { WebSocket: new (...args: unknown[]) => any };
  const socket = new wsModule.WebSocket(
    `wss://localhost:${port}/flowersec/v3/tunnel`,
    ["flowersec.tunnel.v3"],
    { ca: certificate, origin: "https://app.example" },
  );
  await once(socket, "open");
  let messages = 0;
  socket.on("message", () => { messages += 1; });
  const response = new Promise<AdmissionStatusV3>((resolve, reject) => {
    socket.once("message", (data: Uint8Array) => {
      try {
        resolve(decodeFSA3ResponseV3(new Uint8Array(data)).status);
      } catch (error) {
        reject(error);
      }
    });
    socket.once("error", reject);
  });
  const chosen = artifact.path.candidates[0];
  if (chosen === undefined) throw new Error("tunnel artifact has no candidate");
  socket.send(encodeFSB3RequestV3(buildFSB3RequestV3(artifact, chosen.id)));
  return { socket, response, messageCount: () => messages };
}

async function openSilentAdmission(port: number): Promise<any> {
  const require = createRequire(import.meta.url);
  const wsModule = require("ws") as { WebSocket: new (...args: unknown[]) => any };
  const socket = new wsModule.WebSocket(
    `wss://localhost:${port}/flowersec/v3/tunnel`,
    ["flowersec.tunnel.v3"],
    { ca: certificate, origin: "https://app.example" },
  );
  await once(socket, "open");
  return socket;
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((resolvePromise) => { resolve = resolvePromise; });
  return { promise, resolve };
}

function once(emitter: any, event: string): Promise<void> {
  return new Promise((resolve, reject) => {
    emitter.once(event, resolve);
    emitter.once("error", reject);
  });
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function aborted(signal: AbortSignal): Promise<void> {
  if (signal.aborted) return Promise.resolve();
  return new Promise((resolve) => signal.addEventListener("abort", () => resolve(), { once: true }));
}

async function waitFor(predicate: () => boolean): Promise<void> {
  const deadline = Date.now() + 2_000;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error("timed out waiting for TunnelRuntimeV3 state");
    await delay(5);
  }
}
