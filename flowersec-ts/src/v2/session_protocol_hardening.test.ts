import { describe, expect, test } from "vitest";

import type { CarrierSessionV2, CarrierStreamV2 } from "./carrier.js";
import { createMemoryCarrierPairV2 } from "./carrier.js";
import type { OperationOptionsV2 } from "./contract.js";
import { CipherSuiteV2 } from "./protocol.js";
import { establishSessionV2, type SessionConfigV2, type SessionV2 } from "./session.js";

function config(role: "client" | "server"): SessionConfigV2 {
  return {
    role,
    path: "direct",
    channelID: "session-v2-hardening",
    sessionContractHash: new Uint8Array(32).fill(0x81),
    suite: CipherSuiteV2.ChaCha20Poly1305,
    psk: new Uint8Array(32).fill(0x82),
    maxInboundStreams: 4,
    localAdmissionBinding: new Uint8Array(32).fill(0x83),
    peerAdmissionBinding: new Uint8Array(32).fill(0x83),
    localEndpointInstanceID: "",
    expectedPeerEndpointInstanceID: "",
  };
}

describe("SessionV2 protocol hardening", () => {
  test("isolates an anonymous truncated data stream and keeps the session usable", async () => {
    const [rawClient, serverCarrier] = createMemoryCarrierPairV2({ kind: "webtransport", path: "direct", inboundBidirectionalStreamCapacity: 6 });
    const [client, server] = await Promise.all([
      establishSessionV2(rawClient, config("client")),
      establishSessionV2(serverCarrier, config("server")),
    ]);

    const anonymous = await rawClient.openStream();
    await anonymous.write(Uint8Array.of(1, 2, 3));
    await anonymous.closeWrite();
    await eventually(() => expect(server.terminalError).toBeUndefined());

    const opening = client.openStream("after-anonymous");
    const incoming = await server.acceptStream();
    const stream = await opening;
    await stream.write(Uint8Array.of(9));
    expect(await incoming.stream.read()).toEqual(Uint8Array.of(9));
    await client.close();
  });

  test("treats a duplicate authenticated logical identity as session-fatal", async () => {
    const [rawClient, serverCarrier] = createMemoryCarrierPairV2({ kind: "webtransport", path: "direct", inboundBidirectionalStreamCapacity: 6 });
    const capturingClient = new PrefaceCapturingCarrier(rawClient);
    const [client, server] = await Promise.all([
      establishSessionV2(capturingClient, config("client")),
      establishSessionV2(serverCarrier, config("server")),
    ]);
    const opening = client.openStream("capture-preface");
    await server.acceptStream();
    await opening;
    expect(capturingClient.preface).toHaveLength(56);

    const duplicate = await rawClient.openStream();
    await duplicate.write(capturingClient.preface!);
    await eventually(() => expect(server.terminalError).toMatchObject({ code: "protocol" }));
    await expect(server.acceptStream()).rejects.toMatchObject({ code: "protocol" });
  });

  test("propagates the caller signal through FSS2 and OPEN writes and resets a canceled opening", async () => {
    const [rawClient, rawServer] = createMemoryCarrierPairV2({ kind: "webtransport", path: "direct", inboundBidirectionalStreamCapacity: 6 });
    const clientCarrier = new SignalCapturingCarrier(rawClient);
    const serverCarrier = new DelayedApplicationAcceptCarrier(rawServer);
    const [client] = await Promise.all([
      establishSessionV2(clientCarrier, config("client")),
      establishSessionV2(serverCarrier, config("server")),
    ]);
    const controller = new AbortController();
    const opening = client.openStream("cancel-open", { signal: controller.signal });
    await eventually(() => expect(clientCarrier.applicationWriteSignals.length).toBeGreaterThanOrEqual(3));
    expect(clientCarrier.applicationWriteSignals.every((signal) => signal === controller.signal)).toBe(true);
    controller.abort(new Error("cancel setup"));
    await expect(opening).rejects.toThrow("cancel setup");
    expect(clientCarrier.applicationReset).toBe(true);
    serverCarrier.release();
    await client.close();
  });

  test("does not advance the outbound frontier until ordered STREAM_RESET commit completes", async () => {
    const [rawClient, rawServer] = createMemoryCarrierPairV2({ kind: "webtransport", path: "direct", inboundBidirectionalStreamCapacity: 6 });
    const clientCarrier = new OrderedResetCarrier(rawClient);
    const serverCarrier = new DelayedApplicationAcceptCarrier(rawServer);
    const [client] = await Promise.all([
      establishSessionV2(clientCarrier, config("client")),
      establishSessionV2(serverCarrier, config("server")),
    ]);
    clientCarrier.blockNextControlWrite();
    const controller = new AbortController();
    const opening = client.openStream("ordered-reset", { signal: controller.signal });
    await eventually(() => expect(clientCarrier.applicationWrites).toBeGreaterThanOrEqual(3));
    controller.abort(new Error("cancel before ACK"));
    await eventually(() => expect(clientCarrier.controlWriteBlocked).toBe(true));
    expect(sessionInternals(client).outboundLedger.frontier).toBe(0n);
    clientCarrier.releaseControlWrite();
    await expect(opening).rejects.toThrow("cancel before ACK");
    expect(sessionInternals(client).outboundLedger.frontier).toBe(1n);
    serverCarrier.release();
    await client.close();
  });

  test("validates GOAWAY parity, high-watermark, reason, and independent boundaries", async () => {
    const [clientCarrier, serverCarrier] = createMemoryCarrierPairV2({ kind: "webtransport", path: "direct", inboundBidirectionalStreamCapacity: 6 });
    const [client, server] = await Promise.all([
      establishSessionV2(clientCarrier, config("client")),
      establishSessionV2(serverCarrier, config("server")),
    ]);
    const opening = client.openStream("before-goaway");
    const incoming = await server.acceptStream();
    const stream = await opening;
    const clientInternals = sessionInternals(client);
    const serverInternals = sessionInternals(server);

    await expect(clientInternals.receiveGoAway(idReason(2n, 2))).rejects.toThrow(/boundary/);
    await expect(clientInternals.receiveGoAway(idReason(3n, 2))).rejects.toThrow(/boundary/);
    await serverInternals.sendGoAway(2);
    await eventually(() => expect(clientInternals.receivedGoAway).toBe(true));
    expect(serverInternals.sentGoAwayLastAccepted).toBe(1n);
    expect(clientInternals.receivedGoAwayLastAccepted).toBe(1n);
    await clientInternals.receiveGoAway(idReason(1n, 2));
    await expect(clientInternals.receiveGoAway(idReason(1n, 3))).rejects.toThrow(/conflicting/);
    await expect(client.openStream("beyond-goaway")).rejects.toMatchObject({ code: "going_away" });

    await stream.write(Uint8Array.of(7));
    expect(await incoming.stream.read()).toEqual(Uint8Array.of(7));
    await client.close();
  });
});

type SessionInternals = Readonly<{
  receiveGoAway(payload: Uint8Array): Promise<void>;
  sendGoAway(reason: number): Promise<void>;
  receivedGoAway: boolean;
  receivedGoAwayLastAccepted: bigint;
  sentGoAwayLastAccepted: bigint;
  outboundLedger: Readonly<{ frontier: bigint }>;
}>;

function sessionInternals(session: SessionV2): SessionInternals {
  return session as unknown as SessionInternals;
}

class PrefaceCapturingCarrier implements CarrierSessionV2 {
  readonly kind;
  readonly path;
  readonly inboundBidirectionalStreamCapacity: number;
  preface: Uint8Array | undefined;
  private opens = 0;

  constructor(private readonly inner: CarrierSessionV2) {
    this.kind = inner.kind;
    this.path = inner.path;
    this.inboundBidirectionalStreamCapacity = inner.inboundBidirectionalStreamCapacity;
  }

  async openStream(options: OperationOptionsV2 = {}): Promise<CarrierStreamV2> {
    const stream = await this.inner.openStream(options);
    this.opens++;
    return this.opens === 1 ? stream : new WriteObservingStream(stream, (data) => {
      if (this.preface === undefined && data.length === 56) this.preface = data.slice();
    });
  }

  async acceptStream(options: OperationOptionsV2 = {}): Promise<CarrierStreamV2> {
    return await this.inner.acceptStream(options);
  }

  async close(error?: Readonly<{ code: number; reason: string }>): Promise<void> {
    await this.inner.close(error);
  }

  abort(error?: Readonly<{ code: number; reason: string }>): void {
    this.inner.abort(error);
  }
}

class SignalCapturingCarrier implements CarrierSessionV2 {
  readonly kind;
  readonly path;
  readonly inboundBidirectionalStreamCapacity: number;
  readonly applicationWriteSignals: Array<AbortSignal | undefined> = [];
  applicationReset = false;
  private opens = 0;

  constructor(private readonly inner: CarrierSessionV2) {
    this.kind = inner.kind;
    this.path = inner.path;
    this.inboundBidirectionalStreamCapacity = inner.inboundBidirectionalStreamCapacity;
  }

  async openStream(options: OperationOptionsV2 = {}): Promise<CarrierStreamV2> {
    const stream = await this.inner.openStream(options);
    this.opens++;
    if (this.opens === 1) return stream;
    return new WriteObservingStream(
      stream,
      (_data, writeOptions) => this.applicationWriteSignals.push(writeOptions.signal),
      () => { this.applicationReset = true; },
    );
  }

  async acceptStream(options: OperationOptionsV2 = {}): Promise<CarrierStreamV2> {
    return await this.inner.acceptStream(options);
  }

  async close(error?: Readonly<{ code: number; reason: string }>): Promise<void> {
    await this.inner.close(error);
  }

  abort(error?: Readonly<{ code: number; reason: string }>): void {
    this.inner.abort(error);
  }
}

class OrderedResetCarrier implements CarrierSessionV2 {
  readonly kind;
  readonly path;
  readonly inboundBidirectionalStreamCapacity: number;
  applicationWrites = 0;
  controlWriteBlocked = false;
  private opens = 0;
  private shouldBlockControl = false;
  private readonly controlGate = deferred<void>();

  constructor(private readonly inner: CarrierSessionV2) {
    this.kind = inner.kind;
    this.path = inner.path;
    this.inboundBidirectionalStreamCapacity = inner.inboundBidirectionalStreamCapacity;
  }

  async openStream(options: OperationOptionsV2 = {}): Promise<CarrierStreamV2> {
    const stream = await this.inner.openStream(options);
    this.opens++;
    if (this.opens === 1) {
      return new WriteObservingStream(stream, async (_data, _options) => {
        if (!this.shouldBlockControl) return;
        this.shouldBlockControl = false;
        this.controlWriteBlocked = true;
        await this.controlGate.promise;
      });
    }
    return new WriteObservingStream(stream, () => { this.applicationWrites++; });
  }

  async acceptStream(options: OperationOptionsV2 = {}): Promise<CarrierStreamV2> {
    return await this.inner.acceptStream(options);
  }

  async close(error?: Readonly<{ code: number; reason: string }>): Promise<void> {
    await this.inner.close(error);
  }

  abort(error?: Readonly<{ code: number; reason: string }>): void {
    this.controlGate.resolve();
    this.inner.abort(error);
  }

  blockNextControlWrite(): void { this.shouldBlockControl = true; }
  releaseControlWrite(): void { this.controlGate.resolve(); }
}

class WriteObservingStream implements CarrierStreamV2 {
  constructor(
    private readonly inner: CarrierStreamV2,
    private readonly onWrite: (data: Uint8Array, options: OperationOptionsV2) => void | Promise<void>,
    private readonly onReset: () => void = () => undefined,
  ) {}

  async read(options: OperationOptionsV2 = {}): Promise<Uint8Array | null> {
    return await this.inner.read(options);
  }

  async write(data: Uint8Array, options: OperationOptionsV2 = {}): Promise<number> {
    await this.onWrite(data, options);
    return await this.inner.write(data, options);
  }

  async closeWrite(): Promise<void> { await this.inner.closeWrite(); }
  async reset(): Promise<void> { this.onReset(); await this.inner.reset(); }
  abort(error?: Error): void { this.onReset(); this.inner.abort(error); }
}

class DelayedApplicationAcceptCarrier implements CarrierSessionV2 {
  readonly kind;
  readonly path;
  readonly inboundBidirectionalStreamCapacity: number;
  private accepts = 0;
  private readonly gate = deferred<void>();

  constructor(private readonly inner: CarrierSessionV2) {
    this.kind = inner.kind;
    this.path = inner.path;
    this.inboundBidirectionalStreamCapacity = inner.inboundBidirectionalStreamCapacity;
  }

  async openStream(options: OperationOptionsV2 = {}): Promise<CarrierStreamV2> {
    return await this.inner.openStream(options);
  }

  async acceptStream(options: OperationOptionsV2 = {}): Promise<CarrierStreamV2> {
    const stream = await this.inner.acceptStream(options);
    this.accepts++;
    if (this.accepts > 1) await this.gate.promise;
    return stream;
  }

  async close(error?: Readonly<{ code: number; reason: string }>): Promise<void> {
    await this.inner.close(error);
  }

  abort(error?: Readonly<{ code: number; reason: string }>): void {
    this.gate.resolve();
    this.inner.abort(error);
  }

  release(): void { this.gate.resolve(); }
}

function idReason(id: bigint, reason: number): Uint8Array {
  const payload = new Uint8Array(10);
  const view = new DataView(payload.buffer);
  view.setBigUint64(0, id, false);
  view.setUint16(8, reason, false);
  return payload;
}

function deferred<T = void>(): Readonly<{ promise: Promise<T>; resolve(value: T | PromiseLike<T>): void }> {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((resolvePromise) => { resolve = resolvePromise; });
  return { promise, resolve };
}

async function eventually(assertion: () => void): Promise<void> {
  for (let attempt = 0; attempt < 200; attempt++) {
    try { assertion(); return; } catch { await new Promise((resolve) => setTimeout(resolve, 0)); }
  }
  assertion();
}
