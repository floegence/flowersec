import { describe, expect, test, vi } from "vitest";

import { createMemoryCarrierPairV3, type CarrierSessionV3, type CarrierStreamV3 } from "./carrier.js";
import type { OperationOptionsV3 } from "./contract.js";
import { CipherSuiteV3, InnerTypeV3 } from "./protocol.js";
import { establishSessionV3, SessionV3Error, type SessionConfigV3, type SessionV3 } from "./session.js";
import { nodeSessionRuntimeV3 } from "./nodeSessionRuntime.js";

function config(role: "client" | "server"): SessionConfigV3 {
  return {
    role,
    path: "direct",
    channelID: "session-v3-control-terminal",
    sessionContractHash: new Uint8Array(32).fill(0x41),
    suite: CipherSuiteV3.ChaCha20Poly1305,
    psk: new Uint8Array(32).fill(0x42),
    maxInboundStreams: 1,
    localAdmissionBinding: new Uint8Array(32).fill(0x43),
    peerAdmissionBinding: new Uint8Array(32).fill(0x43),
    localEndpointInstanceID: "",
    expectedPeerEndpointInstanceID: "",
    runtime: nodeSessionRuntimeV3,
    idleTimeoutMs: 0,
    closeTimeoutMs: 500,
  };
}

describe("SessionV3 control terminal serialization", () => {
  test("requires native EOF after encrypted FIN before publishing EOF or releasing capacity", async () => {
    const fault = new ApplicationFINFault("block");
    const [rawClient, rawServer] = createMemoryCarrierPairV3({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const [client, server] = await Promise.all([
      establishSessionV3(new ApplicationFINFaultCarrier(rawClient, "client", fault), config("client")),
      establishSessionV3(new ApplicationFINFaultCarrier(rawServer, "server", fault), config("server")),
    ]);
    const opening = client.openStream("native-eof-gate");
    const incoming = await server.acceptStream();
    const outgoing = await opening;

    await incoming.stream.closeWrite();
    await expect(outgoing.read()).resolves.toBeNull();
    let readSettled = false;
    const reading = incoming.stream.read().finally(() => { readSettled = true; });
    const closing = outgoing.closeWrite();
    await testDeadline(fault.clientCloseEntered.promise, "client native FIN block");
    await testDeadline(fault.serverEOFReadEntered.promise, "server native EOF read");
    await Promise.resolve();
    expect(readSettled).toBe(false);
    let replacementSettled = false;
    const replacementOpening = client.openStream("after-native-eof").finally(() => {
      replacementSettled = true;
    });
    await Promise.resolve();
    expect(replacementSettled).toBe(false);

    fault.releaseNativeFIN.resolve();
    await expect(testDeadline(closing, "native FIN release")).resolves.toBeUndefined();
    await expect(testDeadline(reading, "clean application EOF")).resolves.toBeNull();
    const replacementIncoming = await testDeadline(server.acceptStream(), "replacement accept");
    const replacement = await testDeadline(replacementOpening, "replacement open");
    await Promise.all([
      replacement.reset().catch(() => undefined),
      replacementIncoming.stream.reset().catch(() => undefined),
    ]);
    await Promise.all([client.close().catch(() => undefined), server.close().catch(() => undefined)]);
  });

  test("rejects a trailing carrier byte after encrypted FIN", async () => {
    const fault = new ApplicationFINFault("trailing");
    const [rawClient, rawServer] = createMemoryCarrierPairV3({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const [client, server] = await Promise.all([
      establishSessionV3(new ApplicationFINFaultCarrier(rawClient, "client", fault), config("client")),
      establishSessionV3(rawServer, config("server")),
    ]);
    const opening = client.openStream("trailing-fin");
    const incoming = await server.acceptStream();
    const outgoing = await opening;

    await outgoing.closeWrite();
    await expect(incoming.stream.read()).rejects.toMatchObject({ code: "protocol" });
    await Promise.all([client.close().catch(() => undefined), server.close().catch(() => undefined)]);
  });

  test("seals queued responses and appends GOAWAY, SESSION_CLOSE, and FIN after owned cleanup", async () => {
    const [rawClient, serverCarrier] = createMemoryCarrierPairV3({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const clientCarrier = new TerminalOrderingCarrier(rawClient);
    const [client, server] = await Promise.all([
      establishSessionV3(clientCarrier, config("client")),
      establishSessionV3(serverCarrier, config("server")),
    ]);
    await client.openStream("terminal-reset");
    await server.acceptStream();
    const internals = sessionInternals(client);

    clientCarrier.blockNextControlWrite();
    const active = internals.sendControl(InnerTypeV3.Ping, new Uint8Array(8));
    await clientCarrier.blockedWriteEntered.promise;
    const cleanup = internals.sendControlCleanup(InnerTypeV3.StreamReset, idReason(1n, 6));
    const pong = internals.sendControlResponse(InnerTypeV3.Pong, new Uint8Array(8));
    const rekeyACK = internals.sendControlResponse(InnerTypeV3.SessionKeyUpdateACK, new Uint8Array(20));
    const closing = client.close();

    await expect(internals.sendControl(InnerTypeV3.Ping, new Uint8Array(8))).rejects.toThrow(/sealed|closed/);
    await expect(internals.sendControlCleanup(InnerTypeV3.StreamReset, idReason(3n, 6))).resolves.toBe(false);
    await expect(internals.sendControlResponse(InnerTypeV3.Pong, new Uint8Array(8))).resolves.toBe(false);
    clientCarrier.releaseBlockedWrite();

    await expect(active).resolves.toBeUndefined();
    await expect(cleanup).resolves.toBe(true);
    await expect(pong).resolves.toBe(false);
    await expect(rekeyACK).resolves.toBe(false);
    await expect(closing).resolves.toBeUndefined();
    expect(clientCarrier.controlEvents).toEqual(["write", "write", "write", "write", "fin"]);
    expect(clientCarrier.writesAfterFIN).toBe(0);
    expect(clientCarrier.aborts).toBe(0);
  });

  test("does not commit a receive rekey when its ACK is suppressed", async () => {
    const [clientCarrier, serverCarrier] = createMemoryCarrierPairV3({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const [client, server] = await Promise.all([
      establishSessionV3(clientCarrier, config("client")),
      establishSessionV3(serverCarrier, config("server")),
    ]);
    const internals = sessionInternals(client);
    const sendControlResponse = internals.sendControlResponse.bind(client);
    internals.sendControlResponse = async (type) => {
      expect(type).toBe(InnerTypeV3.SessionKeyUpdateACK);
      return false;
    };

    await internals.receiveSessionRekeyBeforeDeadline(sessionRekeyPayload(), new AbortController().signal);

    expect(internals.receiveEpoch).toBe(0);
    expect(internals.receiveTransition).toBe(0n);
    expect(internals.pendingReceiveEpoch).toBeUndefined();
    expect([...internals.receiveRoots.keys()]).toEqual([0]);
    internals.sendControlResponse = sendControlResponse;
    await client.close();
    await server.waitTermination();
  });

  test("does not consume a session rekey transition when prepare is cancelled", async () => {
    const [clientCarrier, serverCarrier] = createMemoryCarrierPairV3({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const [client, server] = await Promise.all([
      establishSessionV3(clientCarrier, config("client")),
      establishSessionV3(serverCarrier, config("server")),
    ]);
    const internals = sessionInternals(client);
    const entered = deferred<void>();
    const release = deferred<void>();
    const controller = new AbortController();
    const originalWait = internals.waitOutboundFrontier;
    internals.waitOutboundFrontier = async (_watermark, signal) => {
      entered.resolve();
      await abortableWait(release.promise, signal);
    };
    try {
      const operation = client.rekey({ signal: controller.signal });
      await entered.promise;
      controller.abort(new SessionV3Error("aborted", "test cancellation"));
      await expect(operation).rejects.toMatchObject({ code: "aborted" });
      expect(internals.nextTransition).toBe(1n);
    } finally {
      release.resolve();
      internals.waitOutboundFrontier = originalWait;
      await Promise.all([client.close().catch(() => undefined), server.close().catch(() => undefined)]);
    }
  });

  test("unfreezes inbound responders when rekey is cancelled during responder drain", async () => {
    const [clientCarrier, serverCarrier] = createMemoryCarrierPairV3({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const [client, server] = await Promise.all([
      establishSessionV3(clientCarrier, config("client")),
      establishSessionV3(serverCarrier, config("server")),
    ]);
    const internals = sessionInternals(client);
    const controller = new AbortController();
    internals.activeInboundResponders = 1;

    const operation = client.rekey({ signal: controller.signal });
    await waitFor(() => internals.localResponderFrozen);
    controller.abort(new SessionV3Error("aborted", "test cancellation"));
    await expect(operation).rejects.toMatchObject({ code: "aborted" });
    expect(internals.localResponderFrozen).toBe(false);
    await expect(internals.enterInboundResponder()).resolves.toBeUndefined();
    internals.activeInboundResponders = 0;
    internals.notifyResponderChanged();

    await Promise.all([client.close().catch(() => undefined), server.close().catch(() => undefined)]);
  });

  test("uses the maximum session transition once and then fails before wire wrap", async () => {
    const [clientCarrier, serverCarrier] = createMemoryCarrierPairV3({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const [client, server] = await Promise.all([
      establishSessionV3(clientCarrier, config("client")),
      establishSessionV3(serverCarrier, config("server")),
    ]);
    const maximum = (1n << 64n) - 1n;
    const clientInternals = sessionInternals(client);
    const serverInternals = sessionInternals(server);
    clientInternals.nextTransition = maximum;
    serverInternals.receiveTransition = maximum - 1n;

    await expect(client.rekey()).resolves.toBeUndefined();
    expect(clientInternals.nextTransition).toBe(0n);
    await expect(client.rekey()).rejects.toMatchObject({ code: "resource_exhausted" });
    expect(clientInternals.nextTransition).toBe(0n);
    await waitFor(() => serverInternals.receivedGoAway);
    await expect(server.openStream("after-transition-exhaustion")).rejects.toMatchObject({ code: "going_away" });

    await Promise.all([client.close().catch(() => undefined), server.close().catch(() => undefined)]);
  });

  test("caller cancellation after rekey commit does not terminate the session", async () => {
    const [clientCarrier, serverCarrier] = createMemoryCarrierPairV3({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const [client, server] = await Promise.all([
      establishSessionV3(clientCarrier, config("client")),
      establishSessionV3(serverCarrier, config("server")),
    ]);
    const serverInternals = sessionInternals(server);
    const entered = deferred<void>();
    const release = deferred<void>();
    const originalSendResponse = serverInternals.sendControlResponse.bind(server);
    serverInternals.sendControlResponse = async (type, payload) => {
      if (type === InnerTypeV3.SessionKeyUpdateACK) {
        entered.resolve();
        await release.promise;
      }
      return await originalSendResponse(type, payload);
    };
    const controller = new AbortController();
    const operation = client.rekey({ signal: controller.signal });
    await entered.promise;
    controller.abort(new SessionV3Error("aborted", "test cancellation"));
    await expect(operation).rejects.toMatchObject({ code: "aborted" });
    release.resolve();
    const internals = sessionInternals(client);
    await waitFor(() => internals.sendEpoch === 1 && internals.pendingSessionRekey === undefined);
    expect(client.terminalError).toBeUndefined();
    await Promise.all([client.close().catch(() => undefined), server.close().catch(() => undefined)]);
  });

  test("session failure rejects and clears a pending session rekey ACK immediately", async () => {
    const [clientCarrier, serverCarrier] = createMemoryCarrierPairV3({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const [client, server] = await Promise.all([
      establishSessionV3(clientCarrier, config("client")),
      establishSessionV3(serverCarrier, config("server")),
    ]);
    const serverInternals = sessionInternals(server);
    const entered = deferred<void>();
    const release = deferred<void>();
    const originalSendResponse = serverInternals.sendControlResponse.bind(server);
    serverInternals.sendControlResponse = async (type, payload) => {
      if (type === InnerTypeV3.SessionKeyUpdateACK) {
        entered.resolve();
        await release.promise;
      }
      return await originalSendResponse(type, payload);
    };
    const operation = client.rekey();
    await entered.promise;
    const clientInternals = sessionInternals(client);
    expect(clientInternals.pendingSessionRekey).toBeDefined();
    clientInternals.fail(new SessionV3Error("closed", "test failure"), false);
    await expect(operation).rejects.toMatchObject({ code: "closed" });
    expect(clientInternals.pendingSessionRekey).toBeUndefined();
    release.resolve();
    await Promise.all([client.close().catch(() => undefined), server.close().catch(() => undefined)]);
  });

  test("coalesces authenticated activity while preserving the signed idle deadline", async () => {
    const clock = { now: 0 };
    const [clientCarrier, serverCarrier] = createMemoryCarrierPairV3({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const [client, server] = await Promise.all([
      establishSessionV3(clientCarrier, {
        ...config("client"),
        runtime: { ...nodeSessionRuntimeV3, monotonicMilliseconds: () => clock.now },
      }),
      establishSessionV3(serverCarrier, config("server")),
    ]);
    const internals = sessionInternals(client);
    internals.config.idleTimeoutMs = 1_000;
    const callbacks: Array<() => void> = [];
    const schedule = ((callback: (...args: unknown[]) => void) => {
      callbacks.push(() => callback());
      return 1 as unknown as ReturnType<typeof setTimeout>;
    }) as typeof setTimeout;
    const performanceSpy = vi.spyOn(globalThis.performance, "now").mockImplementation(() => clock.now);
    const setTimeoutSpy = vi.spyOn(globalThis, "setTimeout").mockImplementation(schedule);
    try {
      sessionInternals(server).markAuthenticatedActivity();
      expect(callbacks).toHaveLength(0);

      internals.markAuthenticatedActivity();
      expect(callbacks).toHaveLength(1);
      clock.now = 900;
      internals.markAuthenticatedActivity();
      expect(callbacks).toHaveLength(1);

      clock.now = 1_000;
      callbacks[0]!();
      expect(client.terminalError).toBeUndefined();
      expect(callbacks).toHaveLength(2);

      clock.now = 1_900;
      callbacks[1]!();
      expect(client.terminalError).toMatchObject({ code: "timeout" });
      await expect(client.waitTermination()).resolves.toMatchObject({ error: { code: "timeout" } });
    } finally {
      setTimeoutSpy.mockRestore();
      performanceSpy.mockRestore();
      await Promise.all([client.close().catch(() => undefined), server.close().catch(() => undefined)]);
    }
  });

  test("transfers temporary inbound record material and wipes it at stream terminal", async () => {
    const [clientCarrier, serverCarrier] = createMemoryCarrierPairV3({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const [client, server] = await Promise.all([
      establishSessionV3(clientCarrier, config("client")),
      establishSessionV3(serverCarrier, config("server")),
    ]);
    const serverInternals = sessionInternals(server);
    const originalRead = serverInternals.readStreamRecord.bind(serverInternals);
    let temporary: StreamInternals | undefined;
    let transferred: RecordMaterialInternals | undefined;
    serverInternals.readStreamRecord = async (stream) => {
      const record = await originalRead(stream);
      if (!serverInternals.streams.has(stream.id) && stream.receiveMaterials.size !== 0) {
        temporary = stream;
        transferred = [...stream.receiveMaterials.values()][0];
      }
      return record;
    };

    const opening = client.openStream("record-material-transfer");
    const incoming = await server.acceptStream();
    const outgoing = await opening;
    const accepted = serverInternals.streams.get(incoming.id);
    expect(temporary).toBeDefined();
    expect(temporary!.receiveMaterials.size).toBe(0);
    expect(transferred).toBeDefined();
    expect(accepted?.receiveMaterials.get(0)).toBe(transferred);

    await outgoing.reset();
    await waitFor(() => materialIsZero(transferred!));
    await Promise.all([client.close().catch(() => undefined), server.close().catch(() => undefined)]);
  });

  test("releases and wipes an OPEN_REJECT stream before hanging carrier cleanup", async () => {
    const [rawClient, serverCarrier] = createMemoryCarrierPairV3({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const clientCarrier = new HangingApplicationCloseWriteCarrier(rawClient);
    const [client, server] = await Promise.all([
      establishSessionV3(clientCarrier, config("client")),
      establishSessionV3(serverCarrier, config("server")),
    ]);
    const internals = sessionInternals(client);
    const originalRelease = internals.releaseStream.bind(internals);
    let released: StreamInternals | undefined;
    let releasedMaterials: readonly RecordMaterialInternals[] = [];
    internals.releaseStream = (stream) => {
      released = stream;
      releasedMaterials = [...stream.sendMaterials.values(), ...stream.receiveMaterials.values()];
      originalRelease(stream);
    };

    const opening = internals.openLogicalStream("flowersec.rpc.v3", { metadata: { unexpected: true } }, true);
    await expect(opening).rejects.toMatchObject({ code: "open_rejected" });
    await clientCarrier.closeWriteEntered.promise;
    internals.fail(new SessionV3Error("closed", "test termination"), false);

    expect(released).toBeDefined();
    expect(internals.streams.size).toBe(0);
    expect(released!.sendMaterials.size).toBe(0);
    expect(released!.receiveMaterials.size).toBe(0);
    expect(releasedMaterials.length).toBeGreaterThan(0);
    expect(releasedMaterials.every(materialIsZero)).toBe(true);

    clientCarrier.releaseCloseWrite();
    await Promise.all([client.close().catch(() => undefined), server.close().catch(() => undefined)]);
  });
});

type RecordMaterialInternals = Readonly<{
  secret: Uint8Array;
  recordKey: Uint8Array;
  noncePrefix: Uint8Array;
}>;

type StreamInternals = {
  id: bigint;
  sendMaterials: Map<number, RecordMaterialInternals>;
  receiveMaterials: Map<number, RecordMaterialInternals>;
};

type SessionInternals = {
  config: { idleTimeoutMs?: number };
  markAuthenticatedActivity(): void;
  streams: Map<bigint, StreamInternals>;
  readStreamRecord(stream: StreamInternals): Promise<unknown>;
  openLogicalStream(kind: string, options: Readonly<{ metadata?: Readonly<Record<string, unknown>> }>, internal: boolean): Promise<unknown>;
  releaseStream(stream: StreamInternals): void;
  sendControl(type: InnerTypeV3, payload: Uint8Array): Promise<void>;
  sendControlResponse(type: InnerTypeV3, payload: Uint8Array): Promise<boolean>;
  sendControlCleanup(type: InnerTypeV3, payload: Uint8Array): Promise<boolean>;
  receiveSessionRekeyBeforeDeadline(payload: Uint8Array, signal: AbortSignal): Promise<void>;
  receiveEpoch: number;
  receiveTransition: bigint;
  receivedGoAway: boolean;
  pendingReceiveEpoch: number | undefined;
  receiveRoots: Map<number, unknown>;
  nextTransition: bigint;
  sendEpoch: number;
  pendingSessionRekey: unknown;
  waitOutboundFrontier(watermark: bigint, signal: AbortSignal): Promise<void>;
  activeInboundResponders: number;
  localResponderFrozen: boolean;
  enterInboundResponder(): Promise<void>;
  notifyResponderChanged(): void;
  fail(error: Error, abortCarrier?: boolean): void;
};

function sessionInternals(session: SessionV3): SessionInternals {
  return session as unknown as SessionInternals;
}

function materialIsZero(material: RecordMaterialInternals): boolean {
  return [material.secret, material.recordKey, material.noncePrefix]
    .every((value) => value.every((byte) => byte === 0));
}

async function abortableWait<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) throw signal.reason;
  return await new Promise<T>((resolve, reject) => {
    const abort = () => reject(signal.reason);
    signal.addEventListener("abort", abort, { once: true });
    void promise.then(
      (value) => { signal.removeEventListener("abort", abort); resolve(value); },
      (error) => { signal.removeEventListener("abort", abort); reject(error); },
    );
  });
}

async function waitFor(predicate: () => boolean): Promise<void> {
  const deadline = Date.now() + 2_000;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error("timed out waiting for session rekey");
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
  }
}

class TerminalOrderingCarrier implements CarrierSessionV3 {
  readonly kind: CarrierSessionV3["kind"];
  readonly path: CarrierSessionV3["path"];
  readonly inboundBidirectionalStreamCapacity: number;
  readonly unreliableDatagrams: CarrierSessionV3["unreliableDatagrams"];
  readonly blockedWriteEntered = deferred<void>();
  readonly controlEvents: string[] = [];
  writesAfterFIN = 0;
  aborts = 0;
  private opens = 0;
  private tracking = false;
  private blockNext = false;
  private fin = false;
  private readonly blockedWriteRelease = deferred<void>();

  constructor(private readonly inner: CarrierSessionV3) {
    this.kind = inner.kind;
    this.path = inner.path;
    this.inboundBidirectionalStreamCapacity = inner.inboundBidirectionalStreamCapacity;
    this.unreliableDatagrams = inner.unreliableDatagrams;
  }

  blockNextControlWrite(): void {
    this.tracking = true;
    this.blockNext = true;
  }

  releaseBlockedWrite(): void {
    this.blockedWriteRelease.resolve();
  }

  async openStream(options: OperationOptionsV3 = {}): Promise<CarrierStreamV3> {
    const stream = await this.inner.openStream(options);
    const control = this.opens++ === 0;
    return control ? this.wrapControl(stream) : stream;
  }

  async acceptStream(options: OperationOptionsV3 = {}): Promise<CarrierStreamV3> {
    return await this.inner.acceptStream(options);
  }

  async waitTermination(): Promise<void> { await this.inner.waitTermination(); }
  async close(error?: Readonly<{ code: number; reason: string }>): Promise<void> { await this.inner.close(error); }
  abort(error?: Readonly<{ code: number; reason: string }>): void { this.aborts++; this.inner.abort(error); }

  private wrapControl(stream: CarrierStreamV3): CarrierStreamV3 {
    return {
      read: async (options) => await stream.read(options),
      write: async (data, options) => {
        if (this.tracking) {
          if (this.fin) this.writesAfterFIN++;
          this.controlEvents.push("write");
          if (this.blockNext) {
            this.blockNext = false;
            this.blockedWriteEntered.resolve();
            await this.blockedWriteRelease.promise;
          }
        }
        return await stream.write(data, options);
      },
      closeWrite: async () => {
        if (this.tracking) {
          this.fin = true;
          this.controlEvents.push("fin");
        }
        await stream.closeWrite();
      },
      stopSending: async () => await stream.stopSending(),
      reset: async () => await stream.reset(),
      abort: (error) => stream.abort(error),
    };
  }
}

class HangingApplicationCloseWriteCarrier implements CarrierSessionV3 {
  readonly kind: CarrierSessionV3["kind"];
  readonly path: CarrierSessionV3["path"];
  readonly inboundBidirectionalStreamCapacity: number;
  readonly unreliableDatagrams: CarrierSessionV3["unreliableDatagrams"];
  readonly closeWriteEntered = deferred<void>();
  private readonly closeWriteRelease = deferred<void>();
  private opens = 0;

  constructor(private readonly inner: CarrierSessionV3) {
    this.kind = inner.kind;
    this.path = inner.path;
    this.inboundBidirectionalStreamCapacity = inner.inboundBidirectionalStreamCapacity;
    this.unreliableDatagrams = inner.unreliableDatagrams;
  }

  releaseCloseWrite(): void { this.closeWriteRelease.resolve(); }

  async openStream(options: OperationOptionsV3 = {}): Promise<CarrierStreamV3> {
    const stream = await this.inner.openStream(options);
    return this.opens++ === 0 ? stream : this.wrap(stream);
  }

  async acceptStream(options: OperationOptionsV3 = {}): Promise<CarrierStreamV3> {
    return await this.inner.acceptStream(options);
  }

  async waitTermination(): Promise<void> { await this.inner.waitTermination(); }
  async close(error?: Readonly<{ code: number; reason: string }>): Promise<void> { await this.inner.close(error); }
  abort(error?: Readonly<{ code: number; reason: string }>): void { this.closeWriteRelease.resolve(); this.inner.abort(error); }

  private wrap(stream: CarrierStreamV3): CarrierStreamV3 {
    return {
      read: async (options) => await stream.read(options),
      write: async (data, options) => await stream.write(data, options),
      closeWrite: async () => {
        this.closeWriteEntered.resolve();
        await this.closeWriteRelease.promise;
        await stream.closeWrite();
      },
      stopSending: async () => await stream.stopSending(),
      reset: async () => await stream.reset(),
      abort: (error) => stream.abort(error),
    };
  }
}

class ApplicationFINFault {
  readonly clientCloseEntered = deferred<void>();
  readonly serverEOFReadEntered = deferred<void>();
  readonly releaseNativeFIN = deferred<void>();
  blockingNativeFIN = false;

  constructor(readonly mode: "block" | "trailing") {}
}

class ApplicationFINFaultCarrier implements CarrierSessionV3 {
  readonly kind: CarrierSessionV3["kind"];
  readonly path: CarrierSessionV3["path"];
  readonly inboundBidirectionalStreamCapacity: number;
  readonly unreliableDatagrams: CarrierSessionV3["unreliableDatagrams"];
  private streams = 0;

  constructor(
    private readonly inner: CarrierSessionV3,
    private readonly side: "client" | "server",
    private readonly fault: ApplicationFINFault,
  ) {
    this.kind = inner.kind;
    this.path = inner.path;
    this.inboundBidirectionalStreamCapacity = inner.inboundBidirectionalStreamCapacity;
    this.unreliableDatagrams = inner.unreliableDatagrams;
  }

  async openStream(options: OperationOptionsV3 = {}): Promise<CarrierStreamV3> {
    return this.wrap(await this.inner.openStream(options));
  }

  async acceptStream(options: OperationOptionsV3 = {}): Promise<CarrierStreamV3> {
    return this.wrap(await this.inner.acceptStream(options));
  }

  async waitTermination(): Promise<void> { await this.inner.waitTermination(); }
  async close(error?: Readonly<{ code: number; reason: string }>): Promise<void> { await this.inner.close(error); }
  abort(error?: Readonly<{ code: number; reason: string }>): void { this.inner.abort(error); }

  private wrap(stream: CarrierStreamV3): CarrierStreamV3 {
    const application = this.streams++ === 1;
    if (!application) return stream;
    return {
      read: async (options) => {
        if (this.side === "server" && this.fault.blockingNativeFIN) {
          this.fault.serverEOFReadEntered.resolve();
        }
        return await stream.read(options);
      },
      write: async (data, options) => await stream.write(data, options),
      closeWrite: async () => {
        if (this.side !== "client") {
          await stream.closeWrite();
          return;
        }
        if (this.fault.mode === "trailing") {
          await stream.write(new Uint8Array([0xa5]));
        } else {
          this.fault.blockingNativeFIN = true;
          this.fault.clientCloseEntered.resolve();
          await this.fault.releaseNativeFIN.promise;
        }
        await stream.closeWrite();
      },
      stopSending: async () => await stream.stopSending(),
      reset: async () => await stream.reset(),
      abort: (error) => stream.abort(error),
    };
  }
}

function idReason(id: bigint, reason: number): Uint8Array {
  const output = new Uint8Array(10);
  const view = new DataView(output.buffer);
  view.setBigUint64(0, id);
  view.setUint16(8, reason);
  return output;
}

function sessionRekeyPayload(): Uint8Array {
  const output = new Uint8Array(20);
  const view = new DataView(output.buffer);
  view.setBigUint64(0, 1n);
  view.setUint32(8, 1);
  view.setBigUint64(12, 0n);
  return output;
}

function deferred<T = void>(): Readonly<{
  promise: Promise<T>;
  resolve(value: T | PromiseLike<T>): void;
}> {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((resolvePromise) => { resolve = resolvePromise; });
  return { promise, resolve };
}

async function testDeadline<T>(promise: Promise<T>, stage: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<T>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${stage} did not settle`)), 1_000);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}
