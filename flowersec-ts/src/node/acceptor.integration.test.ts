import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, test } from "vitest";

import { createArtifactLeaseV2 } from "../v2/artifactLease.js";
import { parseArtifact } from "../v2/opaqueArtifact.js";
import { createAcceptor, SessionHandlers } from "./acceptor.js";
import { connect } from "./connectSession.js";

const repositoryRoot = fileURLToPath(new URL("../../..", import.meta.url));

describe("Node Acceptor handler lifecycle", () => {
  test("close waits for in-flight admission cleanup", async () => {
    const raw = directWebSocketArtifact();
    let authorizationStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      authorizationStarted = resolve;
    });
    let releaseAuthorization!: () => void;
    const authorizationGate = new Promise<void>((resolve) => {
      releaseAuthorization = resolve;
    });
    const acceptor = await createAcceptor({
      listeners: [
        {
          carrier: "websocket",
          path: "direct",
          host: "127.0.0.1",
          port: 0,
          allowedOrigins: ["https://app.example"],
        },
      ],
      maxInboundStreams: raw.session.max_inbound_streams,
      authorize: async () => {
        authorizationStarted();
        await authorizationGate;
        return {
          decision: "allow",
          artifact: parseArtifact(JSON.stringify(raw)),
        };
      },
    });
    const address = acceptor.addresses()[0];
    if (address === undefined)
      throw new Error("WebSocket listener did not bind");
    raw.path.candidates[0]!.url = `ws://127.0.0.1:${address.port}/flowersec/v2/direct`;
    const accepted = acceptor.accept().catch((error: unknown) => error);
    const client = connect(
      createArtifactLeaseV2(
        parseArtifact(JSON.stringify(raw)),
        async () => undefined,
      ),
      { origin: "https://app.example" },
    ).catch((error: unknown) => error);
    await started;
    let closed = false;
    const closing = acceptor.close().then(() => {
      closed = true;
    });
    await new Promise((resolve) => setTimeout(resolve, 25));
    const returnedBeforeAdmissionCleanup = closed;
    releaseAuthorization();
    await Promise.allSettled([accepted, client, closing]);
    expect(returnedBeforeAdmissionCleanup).toBe(false);
  });

  test("freezes handlers before establishing a direct WebSocket Session", async () => {
    const raw = directWebSocketArtifact();
    const handlers = new SessionHandlers({ maxConcurrentStreams: 2 });
    handlers.handleRPC(17, async (payload) => ({ payload }));
    handlers.handleStream("accepted-handler", async (incoming) => {
      expect(new TextDecoder().decode(await incoming.stream.read())).toBe(
        "handled",
      );
    });
    const acceptor = await createAcceptor({
      listeners: [
        {
          carrier: "websocket",
          path: "direct",
          host: "127.0.0.1",
          port: 0,
          allowedOrigins: ["https://app.example"],
        },
      ],
      maxInboundStreams: raw.session.max_inbound_streams,
      authorize: async () => ({
        decision: "allow",
        artifact: parseArtifact(JSON.stringify(raw)),
      }),
      resolveHandlers: () => handlers,
    });
    let accepted;
    try {
      const address = acceptor.addresses()[0];
      if (address === undefined)
        throw new Error("WebSocket listener did not bind");
      raw.path.candidates[0]!.url = `ws://127.0.0.1:${address.port}/flowersec/v2/direct`;
      const acceptedPromise = acceptor.accept();
      const client = await connect(
        createArtifactLeaseV2(
          parseArtifact(JSON.stringify(raw)),
          async () => undefined,
        ),
        { origin: "https://app.example" },
      );
      accepted = await acceptedPromise;
      expect(() =>
        handlers.handleRPC(18, async (payload) => ({ payload })),
      ).toThrow(/frozen/);
      const serving = accepted.serve().catch((error: unknown) => error);
      expect(
        await client.rpc.call(17, { value: "rpc" }, (payload) => payload),
      ).toEqual({ ok: true, payload: { value: "rpc" } });
      const stream = await client.openStream("accepted-handler");
      await stream.write(new TextEncoder().encode("handled"));
      await stream.closeWrite();
      await client.close();
      await expect(serving).resolves.toMatchObject({ code: "closed" });
    } finally {
      await accepted?.close().catch(() => undefined);
      await acceptor.close();
    }
  });

  test("resets only a rejected handler stream and continues serving", async () => {
    const raw = directWebSocketArtifact();
    let calls = 0;
    let resolveSecond!: (payload: string) => void;
    const secondHandled = new Promise<string>((resolve) => {
      resolveSecond = resolve;
    });
    const handlers = new SessionHandlers({ maxConcurrentStreams: 1 });
    handlers.handleStream("handler-failure", async (incoming) => {
      const payload = new TextDecoder().decode(await incoming.stream.read());
      calls++;
      if (calls === 1) throw new Error("application handler failed");
      resolveSecond(payload);
    });
    const acceptor = await createAcceptor({
      listeners: [
        {
          carrier: "websocket",
          path: "direct",
          host: "127.0.0.1",
          port: 0,
          allowedOrigins: ["https://app.example"],
        },
      ],
      maxInboundStreams: raw.session.max_inbound_streams,
      authorize: async () => ({
        decision: "allow",
        artifact: parseArtifact(JSON.stringify(raw)),
      }),
      resolveHandlers: () => handlers,
    });
    let accepted;
    try {
      const address = acceptor.addresses()[0];
      if (address === undefined)
        throw new Error("WebSocket listener did not bind");
      raw.path.candidates[0]!.url = `ws://127.0.0.1:${address.port}/flowersec/v2/direct`;
      const acceptedPromise = acceptor.accept();
      const client = await connect(
        createArtifactLeaseV2(
          parseArtifact(JSON.stringify(raw)),
          async () => undefined,
        ),
        { origin: "https://app.example" },
      );
      accepted = await acceptedPromise;
      const serving = accepted.serve().catch((error: unknown) => error);
      const failed = await client.openStream("handler-failure");
      await failed.write(new TextEncoder().encode("failed"));
      await failed.closeWrite();
      await expect(failed.read()).rejects.toMatchObject({
        code: "stream_reset",
      });

      const succeeded = await client.openStream("handler-failure");
      await succeeded.write(new TextEncoder().encode("succeeded"));
      await succeeded.closeWrite();
      await expect(secondHandled).resolves.toBe("succeeded");
      await client.close();
      await expect(serving).resolves.toMatchObject({ code: "closed" });
    } finally {
      await accepted?.close().catch(() => undefined);
      await acceptor.close();
    }
  });
});

function directWebSocketArtifact(): {
  session: { max_inbound_streams: number };
  path: { candidates: Array<{ id: string; carrier: string; url: string }> };
} {
  const fixture = JSON.parse(
    readFileSync(
      `${repositoryRoot}/testdata/transport_v2/artifact_vectors.json`,
      "utf8",
    ),
  ) as Readonly<{
    positive: readonly Readonly<{ id: string; artifact_json: string }>[];
  }>;
  const source = fixture.positive.find(
    (entry) => entry.id === "direct-three-carriers",
  );
  if (source === undefined) throw new Error("missing direct artifact fixture");
  const raw = JSON.parse(source.artifact_json) as ReturnType<
    typeof directWebSocketArtifact
  >;
  raw.path.candidates = raw.path.candidates.filter(
    (candidate) => candidate.carrier === "websocket",
  );
  return raw;
}
