import { describe, expect, test } from "vitest";

import { createMemoryCarrierPairV2, type CarrierSessionV2 } from "./carrier.js";
import { CipherSuiteV2 } from "./protocol.js";
import { SessionV2, establishSessionV2, type SessionConfigV2 } from "./session.js";

const bytes = (value: string): Uint8Array => new TextEncoder().encode(value);
const text = (value: Uint8Array): string => new TextDecoder().decode(value);

function configs(maxInboundStreams = 8): readonly [SessionConfigV2, SessionConfigV2] {
  const common = {
    path: "direct" as const,
    channelID: "session-v2-test",
    sessionContractHash: Uint8Array.from({ length: 32 }, (_, index) => index + 1),
    suite: CipherSuiteV2.ChaCha20Poly1305,
    psk: Uint8Array.from({ length: 32 }, (_, index) => 0xa0 + index),
    maxInboundStreams,
    localAdmissionBinding: Uint8Array.from({ length: 32 }, (_, index) => 0x40 + index),
    peerAdmissionBinding: Uint8Array.from({ length: 32 }, (_, index) => 0x40 + index),
    localEndpointInstanceID: "",
    expectedPeerEndpointInstanceID: "",
  };
  return [{ ...common, role: "client" }, { ...common, role: "server" }];
}

async function establishPair(maxInboundStreams = 8): Promise<readonly [SessionV2, SessionV2]> {
  const [clientCarrier, serverCarrier] = createMemoryCarrierPairV2({ kind: "webtransport", path: "direct", inboundBidirectionalStreamCapacity: maxInboundStreams + 2 });
  const [clientConfig, serverConfig] = configs(maxInboundStreams);
  return await Promise.all([
    establishSessionV2(clientCarrier, clientConfig),
    establishSessionV2(serverCarrier, serverConfig),
  ]);
}

describe("SessionV2", () => {
  test("rejects an N=1 physical-capacity mismatch before opening the control stream", async () => {
    const [inner] = createMemoryCarrierPairV2({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    let opens = 0;
    const mismatched: CarrierSessionV2 = {
      kind: inner.kind,
      path: inner.path,
      inboundBidirectionalStreamCapacity: 4,
      openStream: async (options) => {
        opens++;
        return await inner.openStream(options);
      },
      acceptStream: async (options) => await inner.acceptStream(options),
      close: async (error) => await inner.close(error),
      abort: (error) => inner.abort(error),
    };
    const [clientConfig] = configs(1);
    await expect(establishSessionV2(mismatched, clientConfig)).rejects.toThrow("capacity mismatch");
    expect(opens).toBe(0);
  });

  test("establishes through READY and carries bidirectional encrypted logical streams", async () => {
    const [client, server] = await establishPair();
    expect(client).toBeInstanceOf(SessionV2);
    expect(server.path).toBe("direct");

    const opened = client.openStream("echo", { metadata: { locale: "zh-CN", retry: 2 } });
    const incoming = await server.acceptStream();
    const clientStream = await opened;
    expect(incoming.id).toBe(1n);
    expect(incoming.kind).toBe("echo");
    expect(incoming.metadata).toEqual({ locale: "zh-CN", retry: 2 });

    await clientStream.write(bytes("request"));
    expect(text((await incoming.stream.read())!)).toBe("request");
    await clientStream.closeWrite();
    expect(await incoming.stream.read()).toBeNull();
    await incoming.stream.write(bytes("response"));
    expect(text((await clientStream.read())!)).toBe("response");
    await incoming.stream.closeWrite();
    expect(await clientStream.read()).toBeNull();
    expect(clientStream.terminalError).toBeUndefined();

    expect(await client.probeLiveness()).toBeGreaterThanOrEqual(0);
    await client.close();
    await expect(server.acceptStream()).rejects.toThrow("closed");
    expect(server.terminalError).toBeInstanceOf(Error);
  });

  test("isolates reset, enforces stream limits, and preserves canceled accepts", async () => {
    const [client, server] = await establishPair(2);
    const firstOpen = client.openStream("first");
    const firstIncoming = await server.acceptStream();
    const first = await firstOpen;
    const secondOpen = client.openStream("second");
    const secondIncoming = await server.acceptStream();
    const second = await secondOpen;

    const third = client.openStream("third");
    await expect(Promise.race([
      third.then(() => "opened"),
      new Promise<string>((resolve) => setTimeout(() => resolve("blocked"), 20)),
    ])).resolves.toBe("blocked");

    await first.reset();
    await expect(firstIncoming.stream.read()).rejects.toThrow("reset");
    const thirdIncoming = await server.acceptStream();
    const thirdStream = await third;
    expect(thirdIncoming.kind).toBe("third");
    await second.write(bytes("still-live"));
    expect(text((await secondIncoming.stream.read())!)).toBe("still-live");
    await thirdStream.reset();

    const controller = new AbortController();
    const canceled = server.acceptStream({ signal: controller.signal });
    controller.abort();
    await expect(canceled).rejects.toThrow("aborted");

    const afterCanceledOpen = client.openStream("after-canceled-accept");
    const afterCanceledIncoming = await Promise.race([
      server.acceptStream(),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("next accept was consumed")), 100)),
    ]);
    const afterCanceled = await afterCanceledOpen;
    expect(afterCanceledIncoming.kind).toBe("after-canceled-accept");
    await afterCanceled.reset();
    await client.close();
  });

  test("returns a queued outbound permit when the waiting open is canceled", async () => {
    const [client, server] = await establishPair(1);
    const firstOpen = client.openStream("permit-owner");
    const firstIncoming = await server.acceptStream();
    const first = await firstOpen;

    const controller = new AbortController();
    const canceled = client.openStream("canceled-waiter", { signal: controller.signal });
    controller.abort();
    await expect(canceled).rejects.toThrow("aborted");
    await first.reset();
    await expect(firstIncoming.stream.read()).rejects.toThrow("reset");

    const nextOpen = client.openStream("after-canceled-waiter");
    const nextIncoming = await server.acceptStream();
    const next = await Promise.race([
      nextOpen,
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("permit leaked to canceled waiter")), 100)),
    ]);
    expect(nextIncoming.kind).toBe("after-canceled-waiter");
    await next.reset();
    await client.close();
  });
});
