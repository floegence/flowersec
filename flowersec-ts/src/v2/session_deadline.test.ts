import { describe, expect, test } from "vitest";

import type { CarrierSessionV2, CarrierStreamV2 } from "./carrier.js";
import { createMemoryCarrierPairV2 } from "./carrier.js";
import { CipherSuiteV2 } from "./protocol.js";
import {
  SessionV2Error,
  establishSessionV2,
  type SessionConfigV2,
  type SessionDeadlineFactoryV2,
  type SessionDeadlinePhaseV2,
} from "./session.js";

function config(role: "client" | "server", factory?: SessionDeadlineFactoryV2): SessionConfigV2 {
  return {
    role,
    path: "direct",
    channelID: "session-v2-deadline",
    sessionContractHash: new Uint8Array(32).fill(0x71),
    suite: CipherSuiteV2.ChaCha20Poly1305,
    psk: new Uint8Array(32).fill(0x72),
    maxInboundStreams: 4,
    localAdmissionBinding: new Uint8Array(32).fill(0x73),
    peerAdmissionBinding: new Uint8Array(32).fill(0x73),
    localEndpointInstanceID: "",
    expectedPeerEndpointInstanceID: "",
    ...(factory === undefined ? {} : {
      deadlines: {
        establishTimeoutMs: 30_000,
        rekeyPrepareTimeoutMs: 10_000,
        rekeyCompletionTimeoutMs: 30_000,
        factory,
      },
    }),
  };
}

describe("SessionV2 internal deadlines", () => {
  test("keeps the session recoverable when rekey prepare times out before the commit boundary", async () => {
    const controllers = new Map<SessionDeadlinePhaseV2, AbortController>();
    const factory: SessionDeadlineFactoryV2 = (timeoutMs, phase) => {
      expect(timeoutMs).toBe(phase === "rekey_prepare" ? 10_000 : 30_000);
      const controller = new AbortController();
      controllers.set(phase, controller);
      return { signal: controller.signal, cancel: () => undefined };
    };
    const [clientCarrier, rawServerCarrier] = createMemoryCarrierPairV2({ kind: "webtransport", path: "direct", inboundBidirectionalStreamCapacity: 6 });
    const delayedServerCarrier = new DelayedApplicationAcceptCarrier(rawServerCarrier);
    const [client, server] = await Promise.all([
      establishSessionV2(clientCarrier, config("client", factory)),
      establishSessionV2(delayedServerCarrier, config("server")),
    ]);

    const opening = client.openStream("prepare-timeout");
    await eventually(() => expect(delayedServerCarrier.applicationAcceptWaiting).toBe(true));
    const rekeying = client.rekey();
    await eventually(() => expect(controllers.has("rekey_prepare")).toBe(true));
    controllers.get("rekey_prepare")!.abort(new SessionV2Error("timeout", "prepare timeout"));
    await expect(rekeying).rejects.toMatchObject({ code: "timeout" });
    expect(client.terminalError).toBeUndefined();

    delayedServerCarrier.releaseApplicationAccept();
    const incoming = await server.acceptStream();
    const outgoing = await opening;
    await outgoing.write(Uint8Array.of(5));
    expect(await incoming.stream.read()).toEqual(Uint8Array.of(5));
    await client.close();
  });

  test("closes the session when rekey completion deadline expires after commit starts", async () => {
    const factory: SessionDeadlineFactoryV2 = (_timeoutMs, phase) => {
      const controller = new AbortController();
      if (phase === "rekey_completion") {
        controller.abort(new SessionV2Error("timeout", "completion timeout"));
      }
      return { signal: controller.signal, cancel: () => undefined };
    };
    const [clientCarrier, serverCarrier] = createMemoryCarrierPairV2({ kind: "webtransport", path: "direct", inboundBidirectionalStreamCapacity: 6 });
    const [client, server] = await Promise.all([
      establishSessionV2(clientCarrier, config("client", factory)),
      establishSessionV2(serverCarrier, config("server")),
    ]);
    const opening = client.openStream("completion-timeout");
    await server.acceptStream();
    await opening;
    await expect(client.rekey()).rejects.toMatchObject({ code: "timeout" });
    expect(client.terminalError).toMatchObject({ code: "timeout" });
    await expect(client.openStream("after-timeout")).rejects.toMatchObject({ code: "timeout" });
  });

  test("applies the receiver completion deadline to peer-initiated rekey", async () => {
    const receiverFactory: SessionDeadlineFactoryV2 = (_timeoutMs, phase) => {
      const controller = new AbortController();
      if (phase === "rekey_completion") {
        controller.abort(new SessionV2Error("timeout", "peer rekey completion timeout"));
      }
      return { signal: controller.signal, cancel: () => undefined };
    };
    const [clientCarrier, serverCarrier] = createMemoryCarrierPairV2({ kind: "webtransport", path: "direct", inboundBidirectionalStreamCapacity: 6 });
    const [client, server] = await Promise.all([
      establishSessionV2(clientCarrier, config("client")),
      establishSessionV2(serverCarrier, config("server", receiverFactory)),
    ]);
    const opening = client.openStream("peer-rekey-completion-timeout");
    await server.acceptStream();
    await opening;

    void client.rekey().catch(() => undefined);
    await expect(server.waitClosed()).resolves.toMatchObject({ error: { code: "timeout" } });
    void client.close();
  });
});

class DelayedApplicationAcceptCarrier implements CarrierSessionV2 {
  readonly kind;
  readonly path;
  readonly inboundBidirectionalStreamCapacity: number;
  applicationAcceptWaiting = false;
  private accepts = 0;
  private readonly applicationGate = deferred<void>();

  constructor(private readonly inner: CarrierSessionV2) {
    this.kind = inner.kind;
    this.path = inner.path;
    this.inboundBidirectionalStreamCapacity = inner.inboundBidirectionalStreamCapacity;
  }

  async openStream(options = {}): Promise<CarrierStreamV2> {
    return await this.inner.openStream(options);
  }

  async acceptStream(options = {}): Promise<CarrierStreamV2> {
    const stream = await this.inner.acceptStream(options);
    this.accepts++;
    if (this.accepts > 1) {
      this.applicationAcceptWaiting = true;
      await this.applicationGate.promise;
    }
    return stream;
  }

  async close(error?: Readonly<{ code: number; reason: string }>): Promise<void> {
    await this.inner.close(error);
  }

  abort(error?: Readonly<{ code: number; reason: string }>): void {
    this.applicationGate.resolve();
    this.inner.abort(error);
  }

  releaseApplicationAccept(): void {
    this.applicationGate.resolve();
  }
}

type Deferred<T> = Readonly<{ promise: Promise<T>; resolve: (value: T | PromiseLike<T>) => void }>;

function deferred<T = void>(): Deferred<T> {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((resolvePromise) => { resolve = resolvePromise; });
  return { promise, resolve };
}

async function eventually(assertion: () => void): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt++) {
    try { assertion(); return; } catch { await new Promise((resolve) => setTimeout(resolve, 0)); }
  }
  assertion();
}
