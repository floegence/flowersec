import { describe, expect, test } from "vitest";

import { createMemoryCarrierPairV3 } from "./carrier.js";
import { nodeSessionRuntimeV3 } from "./nodeSessionRuntime.js";
import { CipherSuiteV3 } from "./protocol.js";
import { establishSessionV3, type SessionConfigV3 } from "./session.js";

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

describe("SessionV3 active-stream rekey", () => {
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
