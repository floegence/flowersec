import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, test } from "vitest";

import {
  decodeArtifactV3JSON,
  encodeArtifactV3JSON,
  type ArtifactCandidateV3,
  type ArtifactV3,
} from "../v3/artifact.js";
import { createArtifactLeaseV3Internal } from "../v3/artifactLease.js";
import { parseArtifactV3 } from "../v3/publicApi.js";
import { connectV3 } from "./connectSessionV3.js";
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
    let authorizationCalls = 0;
    const releases: Array<Readonly<{ leaseId: string; signal: AbortSignal }>> = [];
    const runtime = createTunnelRuntimeV3({
      listeners: [listener()],
      maxInboundStreams: tunnelBase.session.max_inbound_streams,
      maxConcurrentAdmissions: 1,
      admissionTimeoutMs: 50,
      cleanupTimeoutMs: 100,
      authorize: async (_request, options) => {
        authorizationCalls += 1;
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
      authorization.resolve(allow(artifact, "late-admission-lease"));
      await waitFor(() => releases.length === 1);
      await delay(20);
      expect(releases.map(({ leaseId }) => leaseId)).toEqual(["late-admission-lease"]);
      expect(releases[0]!.signal.aborted).toBe(false);
    } finally {
      await runtime.close();
      await connecting;
    }
  }, 10_000);

  test("cancels a stuck release callback at its cleanup deadline", async () => {
    const authorizeStarted = deferred<void>();
    const releaseStarted = deferred<AbortSignal>();
    let artifact!: ArtifactV3;
    const runtime = createTunnelRuntimeV3({
      listeners: [listener()],
      maxInboundStreams: tunnelBase.session.max_inbound_streams,
      admissionTimeoutMs: 500,
      cleanupTimeoutMs: 50,
      authorize: async () => {
        authorizeStarted.resolve();
        return allow(artifact, "bounded-release-lease");
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
  artifact: ArtifactV3,
  leaseId: string,
): Extract<TunnelAuthorizationDecisionV3, Readonly<{ decision: "allow" }>> {
  if (artifact.path.kind !== "tunnel") throw new Error("invalid tunnel fixture");
  return {
    decision: "allow",
    artifact: parseArtifactV3(encodeArtifactV3JSON(artifact)),
    credentialId: createHash("sha256").update(artifact.path.token).digest("base64url"),
    leaseId,
    expiresAtUnixSeconds: artifact.session.init_expire_at_unix_s,
    expectedPeerEndpointInstanceId: artifact.path.expected_peer_endpoint_instance_id,
  };
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
