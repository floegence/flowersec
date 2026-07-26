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

  test("returns after abort even when an earlier graceful carrier close never settles", async () => {
    const [rawClient, serverCarrier] = createMemoryCarrierPairV2({ kind: "webtransport", path: "direct", inboundBidirectionalStreamCapacity: 3 });
    const clientCarrier = new UnsettledCloseAfterAbortCarrier(rawClient);
    const [client] = await Promise.all([
      establishSessionV2(clientCarrier, config("client", { idleTimeoutMs: 0, closeTimeoutMs: 25 })),
      establishSessionV2(serverCarrier, config("server", { idleTimeoutMs: 0, closeTimeoutMs: 25 })),
    ]);

    const result = await Promise.race([
      client.close().then(() => "closed"),
      new Promise<"timed_out">((resolve) => setTimeout(() => resolve("timed_out"), 100)),
    ]);
    expect(result).toBe("closed");
    expect(client.terminalError).toMatchObject({ code: "closed" });
    expect(clientCarrier.aborts).toBe(1);
  });

  test("completes reciprocal close before carrier teardown when peer reads are delayed", async () => {
    const [clientCarrier, rawServerCarrier] = createMemoryCarrierPairV2({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const serverCarrier = new DelayedReadCarrier(rawServerCarrier, 25);
    const [client, server] = await Promise.all([
      establishSessionV2(clientCarrier, config("client", { idleTimeoutMs: 0, closeTimeoutMs: 250 })),
      establishSessionV2(serverCarrier, config("server", { idleTimeoutMs: 0, closeTimeoutMs: 250 })),
    ]);

    await client.close();
    await expect(server.waitClosed()).resolves.toMatchObject({ error: { code: "closed" } });
    expect(serverCarrier.closes).toBe(1);
    expect(serverCarrier.aborts).toBe(0);
  });

  test("flushes the session close record with a control FIN", async () => {
    const [rawClientCarrier, serverCarrier] = createMemoryCarrierPairV2({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const clientCarrier = new CloseWriteFlushingCarrier(rawClientCarrier);
    const [client, server] = await Promise.all([
      establishSessionV2(clientCarrier, config("client", { idleTimeoutMs: 0, closeTimeoutMs: 100 })),
      establishSessionV2(serverCarrier, config("server", { idleTimeoutMs: 0, closeTimeoutMs: 100 })),
    ]);
    clientCarrier.deferControlWrites = true;

    await client.close();
    await expect(server.waitClosed()).resolves.toMatchObject({ error: { code: "closed" } });
    expect(clientCarrier.controlCloseWrites).toBe(1);
    expect(clientCarrier.aborts).toBe(0);
  });

  test("accepts normal peer carrier close as reciprocal close completion", async () => {
    const [rawClientCarrier, serverCarrier] = createMemoryCarrierPairV2({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const clientCarrier = new DelayedReadCarrier(rawClientCarrier, 25);
    const [client] = await Promise.all([
      establishSessionV2(clientCarrier, config("client", { idleTimeoutMs: 0, closeTimeoutMs: 100 })),
      establishSessionV2(serverCarrier, config("server", { idleTimeoutMs: 0, closeTimeoutMs: 100 })),
    ]);

    await client.close();
    expect(clientCarrier.closes).toBe(1);
    expect(clientCarrier.aborts).toBe(0);
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

class UnsettledCloseAfterAbortCarrier implements CarrierSessionV2 {
  readonly kind: CarrierSessionV2["kind"];
  readonly path: CarrierSessionV2["path"];
  readonly inboundBidirectionalStreamCapacity: number;
  aborts = 0;

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
    await new Promise<void>(() => undefined);
  }

  abort(error?: Readonly<{ code: number; reason: string }>): void {
    this.aborts++;
    this.inner.abort(error);
  }
}

class DelayedReadCarrier implements CarrierSessionV2 {
  readonly kind: CarrierSessionV2["kind"];
  readonly path: CarrierSessionV2["path"];
  readonly inboundBidirectionalStreamCapacity: number;
  readonly unreliableDatagrams: CarrierSessionV2["unreliableDatagrams"];
  closes = 0;
  aborts = 0;

  constructor(private readonly inner: CarrierSessionV2, private readonly delayMs: number) {
    this.kind = inner.kind;
    this.path = inner.path;
    this.inboundBidirectionalStreamCapacity = inner.inboundBidirectionalStreamCapacity;
    this.unreliableDatagrams = inner.unreliableDatagrams;
  }

  async openStream(options: OperationOptionsV2 = {}): Promise<CarrierStreamV2> {
    return new DelayedReadStream(await this.inner.openStream(options), this.delayMs);
  }

  async acceptStream(options: OperationOptionsV2 = {}): Promise<CarrierStreamV2> {
    return new DelayedReadStream(await this.inner.acceptStream(options), this.delayMs);
  }

  async close(error?: Readonly<{ code: number; reason: string }>): Promise<void> {
    this.closes++;
    await this.inner.close(error);
  }

  abort(error?: Readonly<{ code: number; reason: string }>): void {
    this.aborts++;
    this.inner.abort(error);
  }
}

class CloseWriteFlushingCarrier implements CarrierSessionV2 {
  readonly kind: CarrierSessionV2["kind"];
  readonly path: CarrierSessionV2["path"];
  readonly inboundBidirectionalStreamCapacity: number;
  readonly unreliableDatagrams: CarrierSessionV2["unreliableDatagrams"];
  deferControlWrites = false;
  controlCloseWrites = 0;
  aborts = 0;

  constructor(private readonly inner: CarrierSessionV2) {
    this.kind = inner.kind;
    this.path = inner.path;
    this.inboundBidirectionalStreamCapacity = inner.inboundBidirectionalStreamCapacity;
    this.unreliableDatagrams = inner.unreliableDatagrams;
  }

  async openStream(options: OperationOptionsV2 = {}): Promise<CarrierStreamV2> {
    return new CloseWriteFlushingStream(await this.inner.openStream(options), this);
  }

  async acceptStream(options: OperationOptionsV2 = {}): Promise<CarrierStreamV2> {
    return await this.inner.acceptStream(options);
  }

  async close(error?: Readonly<{ code: number; reason: string }>): Promise<void> {
    await this.inner.close(error);
  }

  abort(error?: Readonly<{ code: number; reason: string }>): void {
    this.aborts++;
    this.inner.abort(error);
  }
}

class CloseWriteFlushingStream implements CarrierStreamV2 {
  private readonly pending: Uint8Array[] = [];

  constructor(private readonly inner: CarrierStreamV2, private readonly owner: CloseWriteFlushingCarrier) {}

  async read(options: OperationOptionsV2 = {}): Promise<Uint8Array | null> {
    return await this.inner.read(options);
  }

  async write(data: Uint8Array, options: OperationOptionsV2 = {}): Promise<number> {
    if (!this.owner.deferControlWrites) return await this.inner.write(data, options);
    this.pending.push(data.slice());
    return data.length;
  }

  async closeWrite(): Promise<void> {
    this.owner.controlCloseWrites++;
    for (const data of this.pending.splice(0)) await this.inner.write(data);
    await this.inner.closeWrite();
  }

  async reset(): Promise<void> {
    await this.inner.reset();
  }

  abort(error?: Error): void {
    this.inner.abort(error);
  }
}

class DelayedReadStream implements CarrierStreamV2 {
  constructor(private readonly inner: CarrierStreamV2, private readonly delayMs: number) {}

  async read(options: OperationOptionsV2 = {}): Promise<Uint8Array | null> {
    await new Promise((resolve) => setTimeout(resolve, this.delayMs));
    return await this.inner.read(options);
  }

  async write(data: Uint8Array, options: OperationOptionsV2 = {}): Promise<number> {
    return await this.inner.write(data, options);
  }

  async closeWrite(): Promise<void> {
    await this.inner.closeWrite();
  }

  async reset(): Promise<void> {
    await this.inner.reset();
  }

  abort(error?: Error): void {
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
