import { describe, expect, test } from "vitest";

import {
  createMemoryCarrierPairV2,
  type CarrierSessionV2,
  type CarrierStreamV2,
} from "./carrier.js";
import type { OperationOptionsV2 } from "./contract.js";
import { CipherSuiteV2, encodeStreamKeyUpdateACKV2 } from "./protocol.js";
import { establishSessionV2, type SessionConfigV2, type SessionV2 } from "./session.js";

const encode = (value: string) => new TextEncoder().encode(value);
const decode = (value: Uint8Array | null) => value === null ? null : new TextDecoder().decode(value);

function config(role: "client" | "server"): SessionConfigV2 {
  return {
    role,
    path: "direct",
    channelID: "session-v2-rekey",
    sessionContractHash: new Uint8Array(32).fill(0x11),
    suite: CipherSuiteV2.ChaCha20Poly1305,
    psk: new Uint8Array(32).fill(0x22),
    maxInboundStreams: 8,
    localAdmissionBinding: new Uint8Array(32).fill(0x33),
    peerAdmissionBinding: new Uint8Array(32).fill(0x33),
    localEndpointInstanceID: "",
    expectedPeerEndpointInstanceID: "",
  };
}

describe("SessionV2 active-stream rekey", () => {
  test("supports simultaneous and consecutive one-sided rekeys on the same bidirectional stream", async () => {
    const [clientCarrier, serverCarrier] = createMemoryCarrierPairV2({ kind: "webtransport", path: "direct", inboundBidirectionalStreamCapacity: 10 });
    const [client, server] = await Promise.all([
      establishSessionV2(clientCarrier, config("client")),
      establishSessionV2(serverCarrier, config("server")),
    ]);
    const opening = client.openStream("rekey-echo");
    const incoming = await server.acceptStream();
    const outgoing = await opening;

    await outgoing.write(encode("before"));
    expect(decode(await incoming.stream.read())).toBe("before");

    await Promise.all([client.rekey(), server.rekey()]);
    await outgoing.write(encode("after-simultaneous-c2s"));
    await incoming.stream.write(encode("after-simultaneous-s2c"));
    expect(decode(await incoming.stream.read())).toBe("after-simultaneous-c2s");
    expect(decode(await outgoing.read())).toBe("after-simultaneous-s2c");

    await client.rekey();
    await outgoing.write(encode("after-client-epoch2"));
    expect(decode(await incoming.stream.read())).toBe("after-client-epoch2");

    await server.rekey();
    await incoming.stream.write(encode("after-server-epoch2"));
    expect(decode(await outgoing.read())).toBe("after-server-epoch2");
    await client.close();
  }, 10_000);

  test("accepts identical duplicate ACKs and wipes epoch roots after cutover", async () => {
    const [clientCarrier, serverCarrier] = createMemoryCarrierPairV2({ kind: "webtransport", path: "direct", inboundBidirectionalStreamCapacity: 10 });
    const [client, server] = await Promise.all([
      establishSessionV2(clientCarrier, config("client")),
      establishSessionV2(serverCarrier, config("server")),
    ]);
    const opening = client.openStream("rekey-ack-idempotence");
    await server.acceptStream();
    const outgoing = await opening;
    await client.rekey();

    const streamACK = encodeStreamKeyUpdateACKV2({ logicalStreamID: outgoing.id, transition: 1n, epoch: 1 });
    const streamInternals = outgoing as unknown as Readonly<{
      receiveStreamKeyUpdateACK(payload: Uint8Array): void;
    }>;
    expect(() => streamInternals.receiveStreamKeyUpdateACK(streamACK)).not.toThrow();
    expect(() => streamInternals.receiveStreamKeyUpdateACK(streamACK)).not.toThrow();

    const clientInternals = sessionInternals(client);
    const lastSessionACK = clientInternals.lastSessionRekeyACK!;
    expect(() => clientInternals.receiveSessionRekeyACK(lastSessionACK)).not.toThrow();
    expect(() => clientInternals.receiveSessionRekeyACK(lastSessionACK)).not.toThrow();
    expect([...clientInternals.sendRoots.keys()]).toEqual([1]);

    await client.probeLiveness();
    expect([...sessionInternals(server).receiveRoots.keys()]).toEqual([1]);
    expect(client.terminalError).toBeUndefined();
    expect(server.terminalError).toBeUndefined();
    await client.close();
  });

  test("waits for an in-flight inbound OPEN responder before taking the rekey stream snapshot", async () => {
    const [clientInner, serverCarrier] = createMemoryCarrierPairV2({ kind: "webtransport", path: "direct", inboundBidirectionalStreamCapacity: 10 });
    const clientCarrier = new BlockingApplicationReadCarrier(clientInner);
    const [client, server] = await Promise.all([
      establishSessionV2(clientCarrier, config("client")),
      establishSessionV2(serverCarrier, config("server")),
    ]);
    clientCarrier.enable();
    const opening = server.openStream("concurrent-inbound-open");
    await clientCarrier.entered.promise;

    const rekeyed = deferred<void>();
    const rekeying = client.rekey().then(() => rekeyed.resolve());
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(rekeyed.settled).toBe(false);

    clientCarrier.release();
    const incoming = await within(client.acceptStream(), "inbound OPEN delivery");
    const outgoing = await within(opening, "outbound OPEN ACK");
    await within(rekeying, "rekey completion");
    await outgoing.write(encode("after-responder-barrier"));
    expect(decode(await incoming.stream.read())).toBe("after-responder-barrier");
    await client.close();
  });

  test("cancels a queued rekey without waiting for or starting behind the active rekey", async () => {
    const [clientInner, serverCarrier] = createMemoryCarrierPairV2({ kind: "webtransport", path: "direct", inboundBidirectionalStreamCapacity: 10 });
    const clientCarrier = new BlockingApplicationReadCarrier(clientInner);
    const [client, server] = await Promise.all([
      establishSessionV2(clientCarrier, config("client")),
      establishSessionV2(serverCarrier, config("server")),
    ]);
    clientCarrier.enable();
    const opening = server.openStream("block-first-rekey");
    await clientCarrier.entered.promise;

    const first = client.rekey();
    const controller = new AbortController();
    const queued = client.rekey({ signal: controller.signal });
    controller.abort(new Error("queued rekey canceled"));
    await expect(Promise.race([
      queued,
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("queued rekey ignored cancellation")), 100)),
    ])).rejects.toThrow("queued rekey canceled");
    let followingSettled = false;
    const following = client.rekey().then(() => { followingSettled = true; });
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(followingSettled).toBe(false);

    clientCarrier.release();
    await client.acceptStream();
    await opening;
    await first;
    await following;
    expect(sessionInternals(client).nextTransition).toBe(3n);
    await client.close();
  });
});

class BlockingApplicationReadCarrier implements CarrierSessionV2 {
  readonly kind;
  readonly path;
  readonly inboundBidirectionalStreamCapacity: number;
  readonly entered = deferred<void>();
  private readonly gate = deferred<void>();
  private accepts = 0;
  private enabled = false;

  constructor(private readonly inner: CarrierSessionV2) {
    this.kind = inner.kind;
    this.path = inner.path;
    this.inboundBidirectionalStreamCapacity = inner.inboundBidirectionalStreamCapacity;
  }

  enable(): void { this.enabled = true; }
  release(): void { this.gate.resolve(); }

  async openStream(options: OperationOptionsV2 = {}): Promise<CarrierStreamV2> {
    return await this.inner.openStream(options);
  }

  async acceptStream(options: OperationOptionsV2 = {}): Promise<CarrierStreamV2> {
    const stream = await this.inner.acceptStream(options);
    this.accepts++;
    if (!this.enabled || this.accepts !== 1) return stream;
    let firstRead = true;
    return {
      read: async (readOptions = {}) => {
        if (firstRead) {
          firstRead = false;
          this.entered.resolve();
          await this.gate.promise;
        }
        return await stream.read(readOptions);
      },
      write: async (data, writeOptions = {}) => await stream.write(data, writeOptions),
      closeWrite: async () => await stream.closeWrite(),
      reset: async () => await stream.reset(),
      abort: (error) => {
        this.gate.resolve();
        stream.abort(error);
      },
    };
  }

  async close(error?: Readonly<{ code: number; reason: string }>): Promise<void> {
    await this.inner.close(error);
  }

  abort(error?: Readonly<{ code: number; reason: string }>): void {
    this.gate.resolve();
    this.inner.abort(error);
  }
}

type SessionInternals = Readonly<{
  lastSessionRekeyACK: Uint8Array | undefined;
  receiveSessionRekeyACK(payload: Uint8Array): void;
  sendRoots: Map<number, unknown>;
  receiveRoots: Map<number, unknown>;
  nextTransition: bigint;
}>;

function sessionInternals(session: SessionV2): SessionInternals {
  return session as unknown as SessionInternals;
}

type Deferred<T> = Readonly<{
  promise: Promise<T>;
  resolve(value: T | PromiseLike<T>): void;
  readonly settled: boolean;
}>;

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let settled = false;
  const promise = new Promise<T>((resolvePromise) => {
    resolve = (value) => {
      settled = true;
      resolvePromise(value);
    };
  });
  return { promise, resolve, get settled() { return settled; } };
}

async function within<T>(operation: Promise<T>, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      operation,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error(`timed out waiting for ${label}`)), 1_000);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}
