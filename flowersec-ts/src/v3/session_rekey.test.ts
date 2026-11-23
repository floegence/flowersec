import { createHmac } from "node:crypto";
import { describe, expect, test } from "vitest";

import { createMemoryCarrierPairV3, type CarrierStreamV3 } from "./carrier.js";
import { nodeSessionRuntimeV3 } from "./nodeSessionRuntime.js";
import { projectSessionV3 } from "./publicSession.js";
import { CipherSuiteV3, type RecordKeyV3 } from "./protocol.js";
import { establishSessionV3, type SessionConfigV3, type SessionV3 } from "./session.js";

const encode = (value: string) => new TextEncoder().encode(value);
const decode = (value: Uint8Array | null) => value === null ? null : new TextDecoder().decode(value);

function config(role: "client" | "server"): SessionConfigV3 {
  return {
    role,
    path: "direct",
    channelID: "session-v3-rekey",
    sessionContractHash: new Uint8Array(32).fill(0x11),
    suite: CipherSuiteV3.ChaCha20Poly1305,
    psk: new Uint8Array(32).fill(0x22),
    maxInboundStreams: 8,
    localAdmissionBinding: new Uint8Array(32).fill(0x33),
    peerAdmissionBinding: new Uint8Array(32).fill(0x33),
    localEndpointInstanceID: "",
    expectedPeerEndpointInstanceID: "",
    runtime: nodeSessionRuntimeV3,
    idleTimeoutMs: 0,
    closeTimeoutMs: 500,
  };
}

describe("record stream ownership", () => {
  test("withdraws reset streams not yet delivered to accept", async () => {
    const [local, remote] = createMemoryCarrierPairV3({ kind: "websocket", path: "direct", inboundBidirectionalStreamCapacity: 10 });
    const [client, server] = await Promise.all([establishSessionV3(local, config("client")), establishSessionV3(remote, config("server"))]);
    try {
      for (let index = 0; index < 12; index++) {
        await (await client.openStream("withdrawn")).reset();
        await client.probeLiveness();
      }
      await client.openStream("current");
      expect((await server.acceptStream()).kind).toBe("current");
    } finally { await Promise.all([client.close(), server.close()]); }
  });

  test.each([CipherSuiteV3.ChaCha20Poly1305, CipherSuiteV3.AES256GCM])("snapshots raw Buffer writes and reads fragmented records with suite %i", async suite => {
    const [local, remote] = createMemoryCarrierPairV3({ kind: "websocket", path: "direct", inboundBidirectionalStreamCapacity: 10 });
    const [client, server] = await Promise.all([
      establishSessionV3(local, { ...config("client"), suite }),
      establishSessionV3(remote, { ...config("server"), suite }),
    ]);
    try {
      const [outgoing, incoming] = await Promise.all([projectSessionV3(client).openStream("owned"), projectSessionV3(server).acceptStream()]);
      const backing = Buffer.alloc(16_391, 0x47);
      const source = backing.subarray(1, -2);
      const sent = outgoing.write(source);
      backing.fill(0xff);
      expect(await sent).toBe(16_388);
      await outgoing.closeWrite();
      let bytes = 0;
      for (let part = await incoming.stream.read(); part !== null; part = await incoming.stream.read()) {
        expect(part.byteLength).toBe(part.buffer.byteLength);
        expect(part.every(value => value === 0x47)).toBe(true);
        bytes += part.length;
      }
      expect(bytes).toBe(16_388);
    } finally {
      await Promise.all([client.close(), server.close()]);
    }
  });
});

describe("SessionV3 active-stream rekey", () => {
  test("rejects an unauthenticated control cutover and erases the old receive key", async () => {
    const [clientCarrier, serverCarrier] = createMemoryCarrierPairV3({
      kind: "websocket", path: "direct", inboundBidirectionalStreamCapacity: 10,
    });
    const [client, server] = await Promise.all([
      establishSessionV3(clientCarrier, config("client")),
      establishSessionV3(serverCarrier, config("server")),
    ]);
    try {
      await client.probeLiveness();
      await client.rekey();
      const receiver = server as unknown as { controlReceiveEpoch: number; controlReceiveKey?: RecordKeyV3 };
      const old = receiver.controlReceiveKey!;
      const control = (client as unknown as { control: CarrierStreamV3 }).control;
      const write = control.write.bind(control);
      control.write = (data, options) => {
        const corrupt = data.slice();
        corrupt[corrupt.length - 1] = corrupt[corrupt.length - 1]! ^ 1;
        return write(corrupt, options);
      };
      const rejected = expect(client.probeLiveness()).rejects.toThrow();
      expect((await server.waitTermination()).error?.message).toMatch(/authentication failed/);
      expect(receiver.controlReceiveEpoch).toBe(0);
      expect(receiver.controlReceiveKey).toBeUndefined();
      expect(old.recordKey).toEqual(new Uint8Array(32));
      expect(old.noncePrefix).toEqual(new Uint8Array(4));
      await rejected;
    } finally {
      await Promise.all([client.close(), server.close()]);
    }
  });

  test("keeps control keys within one session, direction and authenticated epoch", async () => {
    const connect = () => {
      const [clientCarrier, serverCarrier] = createMemoryCarrierPairV3({
        kind: "websocket", path: "direct", inboundBidirectionalStreamCapacity: 10,
      });
      return Promise.all([
        establishSessionV3(clientCarrier, config("client")),
        establishSessionV3(serverCarrier, config("server")),
      ]);
    };
    const [[client, server], [otherClient, otherServer]] = await Promise.all([connect(), connect()]);
    const slots = (session: SessionV3) => session as unknown as {
      controlSendKey?: RecordKeyV3; controlReceiveKey?: RecordKeyV3;
    };
    const expectErased = (key: RecordKeyV3) => {
      expect(key.recordKey).toEqual(new Uint8Array(32));
      expect(key.noncePrefix).toEqual(new Uint8Array(4));
    };
    const expectEpochKey = (session: SessionV3, direction: 1 | 2, epoch: number) => {
      const epochBytes = Buffer.alloc(4);
      epochBytes.writeUInt32BE(epoch);
      const expand = (key: Uint8Array, label: string, ...context: Uint8Array[]) => {
        const hmac = createHmac("sha256", key).update(`flowersec v5 ${label}\0`);
        for (const part of context) hmac.update(part);
        return hmac.update(Buffer.from([1])).digest();
      };
      const secret = expand(session.rootForSend(epoch).controlRoot, "control", session.transcriptHash(),
        Buffer.alloc(8), Buffer.from([direction]), epochBytes);
      const stored = slots(session).controlSendKey!;
      expect(stored.recordKey).toEqual(Uint8Array.from(expand(secret, "record key")));
      expect(stored.noncePrefix).toEqual(Uint8Array.from(expand(secret, "nonce").subarray(0, 4)));
      return stored;
    };
    try {
      await Promise.all([client.probeLiveness(), otherClient.probeLiveness()]);
      const firstSend = expectEpochKey(client, 1, 0), firstReceive = slots(server).controlReceiveKey!;
      const reverse = expectEpochKey(server, 2, 0), independent = expectEpochKey(otherClient, 1, 0);
      expect(firstReceive).toEqual(firstSend);
      expect(firstReceive.recordKey.buffer).not.toBe(firstSend.recordKey.buffer);
      expect(reverse.recordKey).not.toEqual(firstSend.recordKey);
      expect(independent.recordKey).not.toEqual(firstSend.recordKey);
      await client.probeLiveness();
      expect(slots(client).controlSendKey).toBe(firstSend);
      expect(slots(server).controlReceiveKey).toBe(firstReceive);
      await client.rekey();
      expectErased(firstSend);
      expect(slots(server).controlReceiveKey).toBe(firstReceive);
      await client.probeLiveness();
      expectErased(firstReceive);
      const nextSend = expectEpochKey(client, 1, 1);
      const nextReceive = slots(server).controlReceiveKey!;
      expect(nextReceive).toEqual(nextSend);
      expect(slots(server).controlSendKey).toBe(reverse);
      await Promise.all([client.close(), server.close()]);
      for (const key of [nextSend, nextReceive, reverse]) expectErased(key);
      await otherClient.probeLiveness();
      expect(expectEpochKey(otherClient, 1, 0)).toBe(independent);
    } finally {
      await Promise.all([client, server, otherClient, otherServer].map(session => session.close()));
    }
  });

  test("supports simultaneous and consecutive one-sided rekeys on a cached bidirectional stream", async () => {
    const [clientCarrier, serverCarrier] = createMemoryCarrierPairV3({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 10,
    });
    const [client, server] = await Promise.all([
      establishSessionV3(clientCarrier, config("client")),
      establishSessionV3(serverCarrier, config("server")),
    ]);
    const opening = client.openStream("rekey-echo");
    const incoming = await server.acceptStream();
    const outgoing = await opening;

    await outgoing.write(encode("before-client"));
    await incoming.stream.write(encode("before-server"));
    expect(decode(await incoming.stream.read())).toBe("before-client");
    expect(decode(await outgoing.read())).toBe("before-server");

    await Promise.all([client.rekey(), server.rekey()]);
    await outgoing.write(encode("after-simultaneous-client"));
    await incoming.stream.write(encode("after-simultaneous-server"));
    expect(decode(await incoming.stream.read())).toBe("after-simultaneous-client");
    expect(decode(await outgoing.read())).toBe("after-simultaneous-server");

    await client.rekey();
    await outgoing.write(encode("after-client-rekey"));
    expect(decode(await incoming.stream.read())).toBe("after-client-rekey");

    await server.rekey();
    await incoming.stream.write(encode("after-server-rekey"));
    expect(decode(await outgoing.read())).toBe("after-server-rekey");

    await Promise.all([client.close().catch(() => undefined), server.close().catch(() => undefined)]);
  }, 10_000);
});
