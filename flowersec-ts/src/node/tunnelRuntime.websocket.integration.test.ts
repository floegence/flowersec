import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";

import { expect, test, vi } from "vitest";

import { createArtifactLeaseV2 } from "../v2/artifactLease.js";
import { parseArtifact } from "../v2/opaqueArtifact.js";
import { connect } from "./connectSession.js";
import { createEndpointSet, Issuer } from "./controlplane.js";
import { createTunnelRuntime } from "./tunnelRuntime.js";

type TunnelArtifact = {
  session: { init_expire_at_unix_s: number; max_inbound_streams: number };
  path: {
    role: 1 | 2;
    token: string;
    local_endpoint_instance_id: string;
    expected_peer_endpoint_instance_id: string;
    candidates: Array<{ url: string }>;
  };
};

type Deferred<T> = Readonly<{
  promise: Promise<T>;
  resolve(value: T): void;
}>;

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((resolvePromise) => { resolve = resolvePromise; });
  return { promise, resolve };
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function createTLSFixture(prefix: string): Readonly<{
  temporary: string;
  certificate: string;
  privateKey: string;
}> {
  const temporary = mkdtempSync(path.join(os.tmpdir(), prefix));
  const certificatePath = path.join(temporary, "certificate.pem");
  const privateKeyPath = path.join(temporary, "private-key.pem");
  execFileSync("openssl", [
    "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
    "-nodes", "-days", "1", "-sha256", "-subj", "/CN=localhost",
    "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
    "-keyout", privateKeyPath, "-out", certificatePath,
  ], { stdio: "ignore" });
  return {
    temporary,
    certificate: readFileSync(certificatePath, "utf8"),
    privateKey: readFileSync(privateKeyPath, "utf8"),
  };
}

test("Node TunnelRuntime relays opaque WSS streams and cleans up paired and timed-out leases", async () => {
  const temporary = mkdtempSync(path.join(os.tmpdir(), "flowersec-node-wss-tunnel-"));
  const certificatePath = path.join(temporary, "certificate.pem");
  const privateKeyPath = path.join(temporary, "private-key.pem");
  execFileSync("openssl", [
    "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
    "-nodes", "-days", "1", "-sha256", "-subj", "/CN=localhost",
    "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
    "-keyout", privateKeyPath, "-out", certificatePath,
  ], { stdio: "ignore" });

  const pair = new Issuer().issueTunnelPair({
    session: { channelId: "node-opaque-tunnel", maxInboundStreams: 8 },
    endpoints: createEndpointSet("wss://localhost/flowersec/v2/tunnel"),
    rendezvousGroupId: "node-opaque-group",
    listenerAudience: "node-opaque-listener",
    firstEndpointId: "endpoint-a",
    secondEndpointId: "endpoint-b",
  });
  const artifacts = [pair.first, pair.second].map((issued) =>
    JSON.parse(new TextDecoder().decode(issued.artifactJSON())) as TunnelArtifact);
  const decisions = new Map<string, Readonly<{
    credentialId: string;
    leaseId: string;
    expiresAtUnixSeconds: number;
    expectedPeerEndpointInstanceId: string;
  }>>();
  const released: string[] = [];
  const runtime = createTunnelRuntime({
    listeners: [{
      carrier: "websocket",
      host: "127.0.0.1",
      port: 0,
      tls: {
        certificate: readFileSync(certificatePath, "utf8"),
        privateKey: readFileSync(privateKeyPath, "utf8"),
      },
      allowedOrigins: ["https://app.example"],
    }],
    maxInboundStreams: artifacts[0]!.session.max_inbound_streams,
    maxPendingLegs: 1,
    pairTimeoutMs: 50,
    authorize: async (request) => {
      const decision = decisions.get(request.lookupKey());
      return decision === undefined
        ? { decision: "reject" as const, reason: "invalid_credential" }
        : { decision: "allow" as const, ...decision };
    },
    release: (leaseId) => { released.push(leaseId); },
  });
  try {
    await runtime.start();
    const address = runtime.addresses()[0];
    if (address === undefined) throw new Error("TunnelRuntime did not bind its WSS listener");
    for (const [index, artifact] of artifacts.entries()) {
      artifact.path.candidates[0]!.url = `wss://localhost:${address.port}/flowersec/v2/tunnel`;
      const credentialId = createHash("sha256").update(artifact.path.token).digest("base64url");
      decisions.set(credentialId, {
        credentialId,
        leaseId: `lease-${index + 1}`,
        expiresAtUnixSeconds: artifact.session.init_expire_at_unix_s,
        expectedPeerEndpointInstanceId: artifact.path.expected_peer_endpoint_instance_id,
      });
    }
    const [first, second] = await Promise.all(artifacts.map(async (artifact) => await connect(
      createArtifactLeaseV2(parseArtifact(JSON.stringify(artifact)), async () => undefined),
      { origin: "https://app.example", tls: { ca: readFileSync(certificatePath, "utf8") } },
    )));
    try {
      const outgoing = await first!.openStream("opaque-e2ee");
      const incoming = await second!.acceptStream();
      expect(incoming.kind).toBe("opaque-e2ee");
      await outgoing.write(new TextEncoder().encode("endpoint-only plaintext"));
      await outgoing.closeWrite();
      const payload = await incoming.stream.read();
      if (payload === null) throw new Error("tunnel stream ended before its payload");
      expect(new TextDecoder().decode(payload)).toBe("endpoint-only plaintext");
      expect(await incoming.stream.read()).toBeNull();

      const resetOutgoing = await first!.openStream("reset-after-fin");
      const resetIncoming = await second!.acceptStream();
      await resetOutgoing.write(new TextEncoder().encode("reset payload"));
      await resetOutgoing.closeWrite();
      const resetPayload = await resetIncoming.stream.read();
      if (resetPayload === null) throw new Error("tunnel reset stream ended before its payload");
      expect(new TextDecoder().decode(resetPayload)).toBe("reset payload");
      await resetIncoming.stream.reset();
      await expect(resetOutgoing.read()).rejects.toMatchObject({ code: "stream_reset" });

      const siblingOutgoing = await first!.openStream("after-reset");
      const siblingIncoming = await second!.acceptStream();
      await siblingOutgoing.write(Uint8Array.of(7));
      expect(await siblingIncoming.stream.read()).toEqual(Uint8Array.of(7));
      await siblingOutgoing.reset();
      await expect(siblingIncoming.stream.read()).rejects.toMatchObject({ code: "stream_reset" });
    } finally {
      await Promise.all([first!.close(), second!.close()]);
    }
    await vi.waitFor(() => expect(new Set(released)).toEqual(new Set(["lease-1", "lease-2"])));

    const danglingPair = new Issuer().issueTunnelPair({
      session: { channelId: "node-timeout-tunnel", maxInboundStreams: 8 },
      endpoints: createEndpointSet("wss://localhost/flowersec/v2/tunnel"),
      rendezvousGroupId: "node-timeout-group",
      listenerAudience: "node-opaque-listener",
      firstEndpointId: "timeout-a",
      secondEndpointId: "timeout-b",
    });
    const dangling = JSON.parse(new TextDecoder().decode(danglingPair.first.artifactJSON())) as TunnelArtifact;
    dangling.path.candidates[0]!.url = `wss://localhost:${address.port}/flowersec/v2/tunnel`;
    const danglingCredential = createHash("sha256").update(dangling.path.token).digest("base64url");
    decisions.set(danglingCredential, {
      credentialId: danglingCredential,
      leaseId: "lease-timeout",
      expiresAtUnixSeconds: dangling.session.init_expire_at_unix_s,
      expectedPeerEndpointInstanceId: dangling.path.expected_peer_endpoint_instance_id,
    });
    await expect(connect(
      createArtifactLeaseV2(parseArtifact(JSON.stringify(dangling)), async () => undefined),
      { origin: "https://app.example", tls: { ca: readFileSync(certificatePath, "utf8") } },
    )).rejects.toThrow();
    await vi.waitFor(() => expect(released).toContain("lease-timeout"));

    const capacityArtifacts = ["capacity-a", "capacity-b"].map((channelId, index) => {
      const issued = new Issuer().issueTunnelPair({
        session: { channelId, maxInboundStreams: 8 },
        endpoints: createEndpointSet("wss://localhost/flowersec/v2/tunnel"),
        rendezvousGroupId: `${channelId}-group`,
        listenerAudience: "node-opaque-listener",
        firstEndpointId: `${channelId}-first`,
        secondEndpointId: `${channelId}-second`,
      });
      const artifact = JSON.parse(new TextDecoder().decode(issued.first.artifactJSON())) as TunnelArtifact;
      artifact.path.candidates[0]!.url = `wss://localhost:${address.port}/flowersec/v2/tunnel`;
      const credentialId = createHash("sha256").update(artifact.path.token).digest("base64url");
      decisions.set(credentialId, {
        credentialId,
        leaseId: `lease-capacity-${index + 1}`,
        expiresAtUnixSeconds: artifact.session.init_expire_at_unix_s,
        expectedPeerEndpointInstanceId: artifact.path.expected_peer_endpoint_instance_id,
      });
      return artifact;
    });
    const capacityResults = await Promise.allSettled(capacityArtifacts.map(async (artifact) => await connect(
      createArtifactLeaseV2(parseArtifact(JSON.stringify(artifact)), async () => undefined),
      { origin: "https://app.example", tls: { ca: readFileSync(certificatePath, "utf8") } },
    )));
    expect(capacityResults.every((result) => result.status === "rejected")).toBe(true);
    await vi.waitFor(() => {
      expect(released).toContain("lease-capacity-1");
      expect(released).toContain("lease-capacity-2");
    });
  } finally {
    await runtime.close();
    rmSync(temporary, { recursive: true, force: true });
  }
}, 30_000);

test("Node TunnelRuntime close waits for an asynchronous lease release", async () => {
  const tls = createTLSFixture("flowersec-node-tunnel-release-");
  const issued = new Issuer().issueTunnelPair({
    session: { channelId: "node-release-barrier", maxInboundStreams: 8 },
    endpoints: createEndpointSet("wss://localhost/flowersec/v2/tunnel"),
    rendezvousGroupId: "node-release-group",
    listenerAudience: "node-release-listener",
    firstEndpointId: "release-a",
    secondEndpointId: "release-b",
  }).first;
  const artifact = JSON.parse(new TextDecoder().decode(issued.artifactJSON())) as TunnelArtifact;
  const credentialId = createHash("sha256").update(artifact.path.token).digest("base64url");
  const authorized = deferred<void>();
  const releaseStarted = deferred<void>();
  const releaseAllowed = deferred<void>();
  const runtime = createTunnelRuntime({
    listeners: [{
      carrier: "websocket",
      host: "127.0.0.1",
      port: 0,
      tls: { certificate: tls.certificate, privateKey: tls.privateKey },
      allowedOrigins: ["https://app.example"],
    }],
    maxInboundStreams: artifact.session.max_inbound_streams,
    cleanupTimeoutMs: 1_000,
    authorize: async () => {
      authorized.resolve();
      return {
        decision: "allow",
        credentialId,
        leaseId: "lease-release-barrier",
        expiresAtUnixSeconds: artifact.session.init_expire_at_unix_s,
        expectedPeerEndpointInstanceId: artifact.path.expected_peer_endpoint_instance_id,
      };
    },
    release: async () => {
      releaseStarted.resolve();
      await releaseAllowed.promise;
    },
  });
  let connecting: Promise<unknown> | undefined;
  let closing: Promise<void> | undefined;
  try {
    await runtime.start();
    const address = runtime.addresses()[0]!;
    artifact.path.candidates[0]!.url = `wss://localhost:${address.port}/flowersec/v2/tunnel`;
    connecting = connect(
      createArtifactLeaseV2(parseArtifact(JSON.stringify(artifact)), async () => undefined),
      { origin: "https://app.example", tls: { ca: tls.certificate } },
    ).catch(() => undefined);
    await authorized.promise;
    await delay(0);

    closing = runtime.close();
    await releaseStarted.promise;
    await expect(Promise.race([
      closing.then(() => "closed" as const),
      delay(200).then(() => "release-pending" as const),
    ])).resolves.toBe("release-pending");
    releaseAllowed.resolve();
    await closing;
  } finally {
    releaseAllowed.resolve();
    await closing?.catch(() => undefined);
    await runtime.close().catch(() => undefined);
    await connecting;
    rmSync(tls.temporary, { recursive: true, force: true });
  }
}, 10_000);

test("Node TunnelRuntime close abandons an authorizer that ignores cancellation", async () => {
  const tls = createTLSFixture("flowersec-node-tunnel-authorize-");
  const issued = new Issuer().issueTunnelPair({
    session: { channelId: "node-authorize-cancel", maxInboundStreams: 8 },
    endpoints: createEndpointSet("wss://localhost/flowersec/v2/tunnel"),
    rendezvousGroupId: "node-authorize-group",
    listenerAudience: "node-authorize-listener",
    firstEndpointId: "authorize-a",
    secondEndpointId: "authorize-b",
  }).first;
  const artifact = JSON.parse(new TextDecoder().decode(issued.artifactJSON())) as TunnelArtifact;
  const authorizeStarted = deferred<void>();
  const authorizeAllowed = deferred<never>();
  const runtime = createTunnelRuntime({
    listeners: [{
      carrier: "websocket",
      host: "127.0.0.1",
      port: 0,
      tls: { certificate: tls.certificate, privateKey: tls.privateKey },
      allowedOrigins: ["https://app.example"],
    }],
    maxInboundStreams: artifact.session.max_inbound_streams,
    cleanupTimeoutMs: 100,
    authorize: async () => {
      authorizeStarted.resolve();
      return await authorizeAllowed.promise;
    },
  });
  let connecting: Promise<unknown> | undefined;
  try {
    await runtime.start();
    const address = runtime.addresses()[0]!;
    artifact.path.candidates[0]!.url = `wss://localhost:${address.port}/flowersec/v2/tunnel`;
    connecting = connect(
      createArtifactLeaseV2(parseArtifact(JSON.stringify(artifact)), async () => undefined),
      { origin: "https://app.example", tls: { ca: tls.certificate } },
    ).catch(() => undefined);
    await authorizeStarted.promise;
    await expect(Promise.race([
      runtime.close().then(() => "closed" as const),
      delay(500).then(() => "timed-out" as const),
    ])).resolves.toBe("closed");
  } finally {
    await runtime.close().catch(() => undefined);
    await connecting;
    rmSync(tls.temporary, { recursive: true, force: true });
  }
}, 10_000);
