import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, test } from "vitest";

import { createProxyRuntime } from "../proxy/runtime.js";
import { testCertificatePEM, testPrivateKeyPEM } from "../testSupport/tlsFixture.js";
import { createAcceptor, createArtifactLease, connect, parseArtifact, ProxyServer, SessionHandlers } from "./index.js";

const repositoryRoot = fileURLToPath(new URL("../../..", import.meta.url));
const cleanups: Array<() => Promise<void> | void> = [];

afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

describe("Node ProxyServer real Session integration", () => {
  test("forwards HTTP over a real WebSocket Session with bounded policy and cleanup", async () => {
    const observed: Array<Readonly<{ body: string; authorization?: string; host?: string }>> = [];
    let slowStartedResolve: (() => void) | undefined;
    const slowStarted = new Promise<void>((resolve) => { slowStartedResolve = resolve; });
    const upstream = createServer(async (request: IncomingMessage, response: ServerResponse) => {
      if (request.url === "/slow") {
        slowStartedResolve?.();
        await new Promise<void>((resolve) => request.once("aborted", resolve));
        return;
      }
      const chunks: Buffer[] = [];
      for await (const chunk of request) chunks.push(Buffer.from(chunk));
      observed.push({
        body: Buffer.concat(chunks).toString("utf8"),
        ...(request.headers.authorization === undefined ? {} : { authorization: request.headers.authorization }),
        ...(request.headers.host === undefined ? {} : { host: request.headers.host }),
      });
      response.writeHead(201, { "content-type": "text/plain" });
      response.end("proxied");
    });
    await new Promise<void>((resolve, reject) => {
      upstream.once("error", reject);
      upstream.listen(0, "127.0.0.1", resolve);
    });
    cleanups.push(async () => await new Promise<void>((resolve) => upstream.close(() => resolve())));
    const address = upstream.address();
    if (address === null || typeof address === "string") throw new Error("upstream did not bind TCP");
    const upstreamOrigin = `http://127.0.0.1:${address.port}`;

    const artifact = directWebSocketArtifact();
    const proxy = new ProxyServer({
      upstream: upstreamOrigin,
      upstreamOrigin,
      allowedOrigins: ["https://app.example"],
      maxBodyBytes: 8,
      maxChunkBytes: 8,
    });
    cleanups.push(async () => await proxy.close());
    const handlers = new SessionHandlers({ maxConcurrentStreams: 2 });
    proxy.register(handlers);
    const acceptor = await createAcceptor({
      listeners: [{
        carrier: "websocket",
        path: "direct",
        host: "127.0.0.1",
        port: 0,
        allowedOrigins: ["https://app.example"],
        tls: { certificate: testCertificatePEM, privateKey: testPrivateKeyPEM },
      }],
      maxInboundStreams: artifact.session.max_inbound_streams,
      authorize: async () => ({ accepted: true, artifact: parseArtifact(JSON.stringify(artifact)) }),
      resolveHandlers: () => handlers,
    });
    cleanups.push(async () => await acceptor.close());
    const acceptAddress = acceptor.addresses()[0];
    if (acceptAddress === undefined) throw new Error("WebSocket listener did not bind");
    artifact.path.candidates[0]!.url = `wss://localhost:${acceptAddress.port}/flowersec/v3/direct`;

    const acceptedPromise = acceptor.accept();
    const client = await connect(
      createArtifactLease(parseArtifact(JSON.stringify(artifact)), async () => undefined),
      { origin: "https://app.example", roots: testCertificatePEM },
    );
    cleanups.push(async () => await client.close().catch(() => undefined));
    const accepted = await acceptedPromise;
    cleanups.push(async () => await accepted.close().catch(() => undefined));
    const serving = accepted.serve().catch((error: unknown) => error);

    const runtime = createProxyRuntime({ session: client, externalOrigin: "https://app.example", maxBodyBytes: 32 });
    cleanups.push(() => runtime.dispose());
    const success = await dispatch(runtime, {
      id: "success",
      method: "POST",
      path: "/resource",
      headers: [
        { name: "content-type", value: "text/plain" },
        { name: "authorization", value: "secret" },
        { name: "host", value: "attacker.example" },
      ],
      body: new TextEncoder().encode("request").buffer,
    });
    expect(success.map((message) => message.type)).toEqual([
      "flowersec-proxy:response_meta",
      "flowersec-proxy:response_chunk",
      "flowersec-proxy:response_end",
    ]);
    expect(success[0]).toMatchObject({ status: 201 });
    expect(new TextDecoder().decode(new Uint8Array(success[1]!.data as ArrayBuffer))).toBe("proxied");
    expect(observed).toEqual([{ body: "request", host: `127.0.0.1:${address.port}` }]);

    const wrongOrigin = createProxyRuntime({ session: client, externalOrigin: "https://other.example" });
    cleanups.push(() => wrongOrigin.dispose());
    await expect(dispatch(wrongOrigin, { id: "origin", method: "GET", path: "/", headers: [] }))
      .resolves.toContainEqual(expect.objectContaining({ type: "flowersec-proxy:response_error", code: "operation_failed" }));
    await expect(dispatch(runtime, {
      id: "oversized",
      method: "POST",
      path: "/",
      headers: [],
      body: new Uint8Array(9).buffer,
    })).resolves.toContainEqual(expect.objectContaining({ type: "flowersec-proxy:response_error", code: "operation_failed" }));
    expect(observed).toHaveLength(1);

    const slowDispatch = dispatch(runtime, { id: "slow", method: "GET", path: "/slow", headers: [] });
    await slowStarted;
    expect(proxy.activeCount).toBe(1);
    const closing = proxy.close();
    expect(proxy.activeCount).toBe(1);
    await closing;
    expect(proxy.activeCount).toBe(0);
    await expect(slowDispatch).resolves.toContainEqual(expect.objectContaining({ type: "flowersec-proxy:response_error" }));
    await expect(dispatch(runtime, { id: "closed", method: "GET", path: "/", headers: [] }))
      .resolves.toContainEqual(expect.objectContaining({ type: "flowersec-proxy:response_error" }));

    runtime.dispose();
    await proxy.close();
    await client.close();
    await expect(serving).resolves.toMatchObject({ code: "closed" });
  });
});

type ProxyRuntime = ReturnType<typeof createProxyRuntime>;
type ProxyRequest = Parameters<ProxyRuntime["dispatchFetch"]>[0];

async function dispatch(runtime: ProxyRuntime, request: ProxyRequest): Promise<Record<string, unknown>[]> {
  const channel = new MessageChannel();
  const result = new Promise<Record<string, unknown>[]>((resolve, reject) => {
    const messages: Record<string, unknown>[] = [];
    const timeout = setTimeout(() => reject(new Error("proxy response timed out")), 5_000);
    channel.port2.onmessage = (event) => {
      const message = event.data as Record<string, unknown>;
      messages.push(message);
      if (message.type === "flowersec-proxy:response_end" || message.type === "flowersec-proxy:response_error") {
        clearTimeout(timeout);
        channel.port2.close();
        resolve(messages);
      }
    };
    channel.port2.start();
  });
  runtime.dispatchFetch(request, channel.port1);
  return await result;
}

function directWebSocketArtifact(): {
  session: { max_inbound_streams: number };
  path: { candidates: Array<{ id: string; carrier: string; url: string; tls: { mode: string } }> };
} {
  const vectors = JSON.parse(readFileSync(`${repositoryRoot}/testdata/transport_v3/artifact_vectors.json`, "utf8")) as {
    positive: Array<{ id: string; artifact_json: string }>;
  };
  const source = vectors.positive.find((entry) => entry.id === "direct-mixed-security");
  if (source === undefined) throw new Error("missing direct artifact fixture");
  const artifact = JSON.parse(source.artifact_json) as ReturnType<typeof directWebSocketArtifact>;
  artifact.path.candidates = artifact.path.candidates.filter((candidate) =>
    candidate.carrier === "websocket" && candidate.tls.mode === "ca");
  return artifact;
}
