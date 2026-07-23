import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";

import { base64urlDecode } from "../utils/base64url.js";
import {
  createMemoryCarrierPairV2,
  type CarrierSessionV2,
  type CarrierUnreliableDatagramsV2,
} from "./carrier.js";
import type { UnreliableMessageChannelV2 } from "./contract.js";
import {
  CipherSuiteV2,
  DirectionV2,
  deriveEpochRoots,
  deriveEpochZero,
  deriveNextEpoch,
} from "./protocol.js";
import { establishSessionV2, type SessionConfigV2 } from "./session.js";
import {
  UNRELIABLE_MESSAGE_WIRE_BYTES_V2,
  UnreliableMessageError,
  createInternalUnreliableMessageChannelV2,
  createUnreliableMessageV2,
  sealUnreliableMessageDatagramV2,
} from "./unreliableMessage.js";

const sharedVectors = JSON.parse(readFileSync(
  new URL("../../../testdata/transport_v2/datagram_vectors.json", import.meta.url),
  "utf8",
)) as Readonly<{
  schema_version: number;
  vectors: readonly Readonly<{
    name: string;
    suite: number;
    session_prk_b64u: string;
    h3_b64u: string;
    direction: number;
    epoch: number;
    sequence: number;
    expires_at_unix_ms: number;
    plaintext_b64u: string;
    epoch_secret_b64u: string;
    unreliable_root_b64u: string;
    material_secret_b64u: string;
    record_key_b64u: string;
    nonce_prefix_b64u: string;
    nonce_b64u: string;
    header_hex: string;
    aad_b64u: string;
    ciphertext_b64u: string;
    wire_b64u: string;
  }>[];
}>;

describe("FSD2 unreliable message channel", () => {
  test("consumes the shared FSD2 derivation and wire vectors field by field", () => {
    expect(sharedVectors.schema_version).toBe(1);
    expect(sharedVectors.vectors.length).toBeGreaterThan(0);
    for (const vector of sharedVectors.vectors) {
      const sessionPRK = base64urlDecode(vector.session_prk_b64u);
      const direction = vector.direction as DirectionV2;
      const h3 = base64urlDecode(vector.h3_b64u);
      const epochSecret = deriveVectorEpochSecret(sessionPRK, h3, direction, vector.epoch);
      expect(epochSecret, `${vector.name}: epoch secret`).toEqual(base64urlDecode(vector.epoch_secret_b64u));
      const sealed = sealUnreliableMessageDatagramV2({
        suite: vector.suite as CipherSuiteV2,
        epochSecret,
        h3,
        direction,
        epoch: vector.epoch,
        sequence: BigInt(vector.sequence),
        expiresAtUnixMs: BigInt(vector.expires_at_unix_ms),
        plaintext: base64urlDecode(vector.plaintext_b64u),
      });
      expect(sealed.material.unreliableRoot, `${vector.name}: unreliable root`).toEqual(
        base64urlDecode(vector.unreliable_root_b64u),
      );
      expect(sealed.material.materialSecret, `${vector.name}: material secret`).toEqual(
        base64urlDecode(vector.material_secret_b64u),
      );
      expect(sealed.material.recordKey, `${vector.name}: record key`).toEqual(
        base64urlDecode(vector.record_key_b64u),
      );
      expect(sealed.material.noncePrefix, `${vector.name}: nonce prefix`).toEqual(
        base64urlDecode(vector.nonce_prefix_b64u),
      );
      expect(sealed.nonce, `${vector.name}: nonce`).toEqual(base64urlDecode(vector.nonce_b64u));
      expect(hex(sealed.header), `${vector.name}: header`).toBe(vector.header_hex);
      expect(sealed.aad, `${vector.name}: AAD`).toEqual(base64urlDecode(vector.aad_b64u));
      expect(sealed.ciphertext, `${vector.name}: ciphertext`).toEqual(base64urlDecode(vector.ciphertext_b64u));
      expect(sealed.wire, `${vector.name}: wire`).toEqual(base64urlDecode(vector.wire_b64u));
    }
  });

  test("advertises the channel only after the FSH2 feature intersection completes", async () => {
    const [baseClient, baseServer] = createMemoryCarrierPairV2({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 10,
    });
    const [clientDatagrams, serverDatagrams] = pairedDatagrams();
    const clientCarrier = withDatagrams(baseClient, clientDatagrams);
    const serverCarrier = withDatagrams(baseServer, serverDatagrams);
    const [clientConfig, serverConfig] = sessionConfigs();
    const [client, server] = await Promise.all([
      establishSessionV2(clientCarrier, clientConfig),
      establishSessionV2(serverCarrier, serverConfig),
    ]);

    expect(client.unreliableMessages?.maxMessageSize).toBe(1_024);
    expect(server.unreliableMessages?.maxMessageSize).toBe(1_024);
    await client.unreliableMessages!.send(createUnreliableMessageV2(Uint8Array.of(7, 8)), {
      expiresAtUnixMs: Date.now() + 5_000,
    });
    await expect(server.unreliableMessages!.receive()).resolves.toEqual(
      expect.objectContaining({ data: Uint8Array.of(7, 8) }),
    );
    await client.close();

    const [baseUnsupportedClient, baseUnsupportedServer] = createMemoryCarrierPairV2({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 10,
    });
    const oneSided = pairedDatagrams()[0];
    const [unsupportedClient, unsupportedServer] = await Promise.all([
      establishSessionV2(withDatagrams(baseUnsupportedClient, oneSided), clientConfig),
      establishSessionV2(baseUnsupportedServer, serverConfig),
    ]);
    expect(unsupportedClient.unreliableMessages).toBeUndefined();
    expect(unsupportedServer.unreliableMessages).toBeUndefined();
    await unsupportedClient.close();
  });

  test("seals application messages into the frozen FSD2 wire format", async () => {
    const transport = new CapturingTransport();
    const channel = createChannel(transport, DirectionV2.ClientToServer, DirectionV2.ServerToClient);
    const plaintext = new TextEncoder().encode("private unreliable payload");

    await expect(channel.send(createUnreliableMessageV2(plaintext), {
      expiresAtUnixMs: 2_000,
    })).resolves.toBe("accepted");

    const wire = transport.sent[0]!;
    expect(wire.byteLength).toBe(32 + plaintext.byteLength + 16);
    expect(new TextDecoder().decode(wire.subarray(0, 4))).toBe("FSD2");
    expect(wire[4]).toBe(2);
    expect(wire[5]).toBe(0);
    const view = new DataView(wire.buffer, wire.byteOffset, wire.byteLength);
    expect(view.getUint16(6, false)).toBe(32);
    expect(view.getUint32(8, false)).toBe(0);
    expect(view.getBigUint64(12, false)).toBe(0n);
    expect(view.getBigUint64(20, false)).toBe(2_000n);
    expect(view.getUint32(28, false)).toBe(plaintext.byteLength + 16);
    expect(new TextDecoder().decode(wire)).not.toContain("private unreliable payload");
  });

  test("round trips authenticated messages while silently dropping replay, expiry, and tampering", async () => {
    let receiverNow = 1_000;
    const outbound = new CapturingTransport();
    const inbound = new CapturingTransport();
    const sender = createChannel(outbound, DirectionV2.ClientToServer, DirectionV2.ServerToClient);
    const receiver = createChannel(
      inbound,
      DirectionV2.ServerToClient,
      DirectionV2.ClientToServer,
      () => receiverNow,
    );

    await sender.send(createUnreliableMessageV2(Uint8Array.of(1, 2)), { expiresAtUnixMs: 2_000 });
    const first = outbound.sent[0]!;
    inbound.enqueue(first);
    await expect(receiver.receive()).resolves.toEqual(expect.objectContaining({ data: Uint8Array.of(1, 2) }));

    const tampered = first.slice();
    tampered[tampered.length - 1]! ^= 0xff;
    inbound.enqueue(first);
    inbound.enqueue(tampered);
    await sender.send(createUnreliableMessageV2(Uint8Array.of(3)), { expiresAtUnixMs: 2_500 });
    inbound.enqueue(outbound.sent[1]!);
    await expect(receiver.receive()).resolves.toEqual(expect.objectContaining({ data: Uint8Array.of(3) }));

    receiverNow = 3_000;
    await sender.send(createUnreliableMessageV2(Uint8Array.of(4)), { expiresAtUnixMs: 3_500 });
    const expiredAtReceiver = outbound.sent[2]!;
    receiverNow = 4_000;
    inbound.enqueue(expiredAtReceiver);
    const receivingAfterExpired = receiver.receive();
    await Promise.resolve();
    receiverNow = 3_000;
    await sender.send(createUnreliableMessageV2(Uint8Array.of(5)), { expiresAtUnixMs: 4_500 });
    inbound.enqueue(outbound.sent[3]!);
    await expect(receivingAfterExpired).resolves.toEqual(expect.objectContaining({ data: Uint8Array.of(5) }));
  });

  test("enforces payload, expiry, and the 64-send budget before native transport", async () => {
    const transport = new HangingTransport();
    const channel = createChannel(transport, DirectionV2.ClientToServer, DirectionV2.ServerToClient);
    expect(() => createUnreliableMessageV2(new Uint8Array())).toThrow(UnreliableMessageError);
    expect(() => createUnreliableMessageV2(new Uint8Array(1_025))).toThrow(UnreliableMessageError);
    await expect(channel.send(createUnreliableMessageV2(Uint8Array.of(1)), {
      expiresAtUnixMs: 999,
    })).resolves.toBe("dropped_expired");

    const pending = Array.from({ length: 64 }, (_, index) => channel.send(
      createUnreliableMessageV2(Uint8Array.of(index)),
      { expiresAtUnixMs: 2_000 },
    ));
    await Promise.resolve();
    await expect(channel.send(createUnreliableMessageV2(Uint8Array.of(65)), {
      expiresAtUnixMs: 2_000,
    })).resolves.toBe("dropped_budget");
    expect(transport.sendCount).toBe(64);
    transport.release();
    await expect(Promise.all(pending)).resolves.toEqual(new Array(64).fill("accepted"));
  });

  test("requires the nominal message type and never accepts protocol bytes directly", () => {
    const use = (channel: UnreliableMessageChannelV2) => {
      // @ts-expect-error raw handshake/control bytes are not application unreliable messages.
      void channel.send(Uint8Array.of(0x46, 0x53, 0x48, 0x32), { expiresAtUnixMs: 2_000 });
      // @ts-expect-error arbitrary artifact-like objects cannot enter the message channel.
      void channel.send({ artifact: "opaque" }, { expiresAtUnixMs: 2_000 });
    };
    expect(use).toBeTypeOf("function");
  });

  test("requires native capacity for the maximum encrypted FSD2 datagram", () => {
    expect(() => createChannel(
      new CapturingTransport(UNRELIABLE_MESSAGE_WIRE_BYTES_V2 - 1),
      DirectionV2.ClientToServer,
      DirectionV2.ServerToClient,
    )).toThrow(UnreliableMessageError);
  });
});

function createChannel(
  transport: CarrierUnreliableDatagramsV2,
  sendDirection: DirectionV2,
  receiveDirection: DirectionV2,
  now: () => number = () => 1_000,
): UnreliableMessageChannelV2 {
  const epochSecret = new Uint8Array(32).fill(0x22);
  return createInternalUnreliableMessageChannelV2({
    transport,
    suite: CipherSuiteV2.ChaCha20Poly1305,
    h3: new Uint8Array(32).fill(0x11),
    sendDirection,
    receiveDirection,
    currentSendEpoch: () => ({ epoch: 0, epochSecret }),
    receiveEpochSecret: (epoch) => epoch === 0 ? epochSecret : undefined,
    now,
  });
}

function sessionConfigs(): readonly [SessionConfigV2, SessionConfigV2] {
  const common = {
    path: "direct" as const,
    channelID: "unreliable-message-test",
    sessionContractHash: new Uint8Array(32).fill(1),
    suite: CipherSuiteV2.ChaCha20Poly1305,
    psk: new Uint8Array(32).fill(2),
    maxInboundStreams: 8,
    localAdmissionBinding: new Uint8Array(32).fill(3),
    peerAdmissionBinding: new Uint8Array(32).fill(3),
    localEndpointInstanceID: "",
    expectedPeerEndpointInstanceID: "",
    idleTimeoutMs: 0,
  };
  return [{ ...common, role: "client" }, { ...common, role: "server" }];
}

function withDatagrams(
  carrier: CarrierSessionV2,
  unreliableDatagrams: CarrierUnreliableDatagramsV2,
): CarrierSessionV2 {
  return {
    kind: carrier.kind,
    path: carrier.path,
    inboundBidirectionalStreamCapacity: carrier.inboundBidirectionalStreamCapacity,
    unreliableDatagrams,
    openStream: async (options) => await carrier.openStream(options),
    acceptStream: async (options) => await carrier.acceptStream(options),
    close: async (error) => await carrier.close(error),
    abort: (error) => carrier.abort(error),
  };
}

function pairedDatagrams(): readonly [CapturingTransport, CapturingTransport] {
  const left = new CapturingTransport();
  const right = new CapturingTransport();
  left.peer = right;
  right.peer = left;
  return [left, right];
}

class CapturingTransport implements CarrierUnreliableDatagramsV2 {
  readonly sent: Uint8Array[] = [];
  private readonly queued: Uint8Array[] = [];
  private readonly waiters: Array<(value: Uint8Array) => void> = [];
  peer: CapturingTransport | undefined;

  constructor(readonly maxDatagramSize: number = UNRELIABLE_MESSAGE_WIRE_BYTES_V2) {}

  async send(data: Uint8Array): Promise<"accepted"> {
    this.sent.push(data.slice());
    this.peer?.enqueue(data);
    return "accepted";
  }

  receive(options: Readonly<{ signal?: AbortSignal }> = {}): Promise<Uint8Array> {
    const queued = this.queued.shift();
    if (queued !== undefined) return Promise.resolve(queued);
    return new Promise((resolve, reject) => {
      const onAbort = () => reject(new DOMException("aborted", "AbortError"));
      options.signal?.addEventListener("abort", onAbort, { once: true });
      this.waiters.push((value) => {
        options.signal?.removeEventListener("abort", onAbort);
        resolve(value);
      });
    });
  }

  enqueue(value: Uint8Array): void {
    const waiter = this.waiters.shift();
    if (waiter === undefined) this.queued.push(value.slice());
    else waiter(value.slice());
  }
}

class HangingTransport extends CapturingTransport {
  sendCount = 0;
  private readonly gate = deferred<void>();

  override async send(): Promise<"accepted"> {
    this.sendCount++;
    await this.gate.promise;
    return "accepted";
  }

  release(): void {
    this.gate.resolve();
  }
}

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

function hex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function deriveVectorEpochSecret(
  sessionPRK: Uint8Array,
  h3: Uint8Array,
  direction: DirectionV2,
  epoch: number,
): Uint8Array {
  let secret = deriveEpochZero(sessionPRK, direction).epochSecret;
  for (let next = 1; next <= epoch; next++) {
    secret = deriveNextEpoch(deriveEpochRoots(secret).rekeyRoot, h3, direction, next);
  }
  return secret;
}
