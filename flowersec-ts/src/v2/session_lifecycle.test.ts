import { describe, expect, test } from "vitest";

import { createMemoryCarrierPairV2, type CarrierSessionV2, type CarrierStreamV2 } from "./carrier.js";
import type { OperationOptionsV2 } from "./contract.js";
import { CipherSuiteV2 } from "./protocol.js";
import { establishSessionV2, type SessionConfigV2, type SessionV2 } from "./session.js";

function config(
  role: "client" | "server",
  options: Readonly<{ idleTimeoutMs: number; closeTimeoutMs: number }>,
): SessionConfigV2 {
  return {
    role,
    path: "direct",
    channelID: "session-v2-lifecycle",
    sessionContractHash: new Uint8Array(32).fill(0x71),
    suite: CipherSuiteV2.ChaCha20Poly1305,
    psk: new Uint8Array(32).fill(0x72),
    maxInboundStreams: 1,
    localAdmissionBinding: new Uint8Array(32).fill(0x73),
    peerAdmissionBinding: new Uint8Array(32).fill(0x73),
    localEndpointInstanceID: "",
    expectedPeerEndpointInstanceID: "",
    idleTimeoutMs: options.idleTimeoutMs,
    closeTimeoutMs: options.closeTimeoutMs,
  };
}

async function establishLifecyclePair(
  idleTimeoutMs: number,
  closeTimeoutMs = 50,
): Promise<readonly [SessionV2, SessionV2]> {
  const [clientCarrier, serverCarrier] = createMemoryCarrierPairV2({ kind: "webtransport", path: "direct", inboundBidirectionalStreamCapacity: 3 });
  return await Promise.all([
    establishSessionV2(clientCarrier, config("client", { idleTimeoutMs, closeTimeoutMs })),
    establishSessionV2(serverCarrier, config("server", { idleTimeoutMs, closeTimeoutMs })),
  ]);
}

describe("SessionV2 lifecycle bounds", () => {
  test("terminates an idle READY session and refreshes the watchdog on authenticated activity", async () => {
    const [client, server] = await establishLifecyclePair(100);
    await new Promise((resolve) => setTimeout(resolve, 45));
    await client.probeLiveness();
    await new Promise((resolve) => setTimeout(resolve, 45));
    await server.probeLiveness();
    await new Promise((resolve) => setTimeout(resolve, 45));
    expect(client.terminalError).toBeUndefined();
    expect(server.terminalError).toBeUndefined();

    await eventually(() => {
      expect(client.terminalError).toMatchObject({ code: "timeout" });
      expect(server.terminalError).toBeInstanceOf(Error);
    }, 250);
    await expect(client.waitClosed()).resolves.toMatchObject({ error: { code: "timeout" } });
    await expect(client.termination).resolves.toMatchObject({ error: { code: "timeout" } });
  });

  test("bounds close when the carrier close promise never settles", async () => {
    const [rawClient, serverCarrier] = createMemoryCarrierPairV2({ kind: "webtransport", path: "direct", inboundBidirectionalStreamCapacity: 3 });
    const clientCarrier = new HangingCloseCarrier(rawClient);
    const [client] = await Promise.all([
      establishSessionV2(clientCarrier, config("client", { idleTimeoutMs: 0, closeTimeoutMs: 25 })),
      establishSessionV2(serverCarrier, config("server", { idleTimeoutMs: 0, closeTimeoutMs: 25 })),
    ]);

    const started = performance.now();
    await client.close();
    expect(performance.now() - started).toBeLessThan(150);
    expect(client.terminalError).toMatchObject({ code: "closed" });
    await expect(client.waitClosed()).resolves.toMatchObject({ error: { code: "closed" } });
    expect(clientCarrier.activeCloses).toBe(0);
    expect(clientCarrier.aborts).toBe(1);
  });

  test("aborts rather than retaining a hanging carrier close after idle termination", async () => {
    const [rawClient, serverCarrier] = createMemoryCarrierPairV2({ kind: "webtransport", path: "direct", inboundBidirectionalStreamCapacity: 3 });
    const clientCarrier = new HangingCloseCarrier(rawClient);
    const [client] = await Promise.all([
      establishSessionV2(clientCarrier, config("client", { idleTimeoutMs: 20, closeTimeoutMs: 25 })),
      establishSessionV2(serverCarrier, config("server", { idleTimeoutMs: 0, closeTimeoutMs: 25 })),
    ]);

    await expect(client.waitClosed()).resolves.toMatchObject({ error: { code: "timeout" } });
    await eventually(() => {
      expect(clientCarrier.activeCloses).toBe(0);
      expect(clientCarrier.aborts).toBe(1);
    }, 100);
  });
});

class HangingCloseCarrier implements CarrierSessionV2 {
  readonly kind: CarrierSessionV2["kind"];
  readonly path: CarrierSessionV2["path"];
  readonly inboundBidirectionalStreamCapacity: number;
  activeCloses = 0;
  aborts = 0;
  private readonly closeRelease = deferred<void>();

  constructor(private readonly inner: CarrierSessionV2) {
    this.kind = inner.kind;
    this.path = inner.path;
    this.inboundBidirectionalStreamCapacity = inner.inboundBidirectionalStreamCapacity;
  }

  async openStream(options: OperationOptionsV2 = {}): Promise<CarrierStreamV2> {
    return await this.inner.openStream(options);
  }

  async acceptStream(options: OperationOptionsV2 = {}): Promise<CarrierStreamV2> {
    return await this.inner.acceptStream(options);
  }

  async close(): Promise<void> {
    this.activeCloses++;
    await this.closeRelease.promise;
    this.activeCloses--;
  }

  abort(error?: Readonly<{ code: number; reason: string }>): void {
    this.aborts++;
    this.closeRelease.resolve();
    this.inner.abort(error);
  }
}

type Deferred<T> = Readonly<{
  promise: Promise<T>;
  resolve: (value: T | PromiseLike<T>) => void;
}>;

function deferred<T = void>(): Deferred<T> {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((resolvePromise) => { resolve = resolvePromise; });
  return { promise, resolve };
}

async function eventually(assertion: () => void, timeoutMs: number): Promise<void> {
  const deadline = performance.now() + timeoutMs;
  while (performance.now() < deadline) {
    try {
      assertion();
      return;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
  }
  assertion();
}
