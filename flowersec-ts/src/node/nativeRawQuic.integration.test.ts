import { createRequire } from "node:module";

import { describe, expect, test } from "vitest";

import {
  createNativeRawQuicDriver,
  type NativeTransportAddonBinding,
} from "./nativeTransportAddon.js";

const CERTIFICATE_DER = Buffer.from("MIIBjzCCAUGgAwIBAgIUW8hQEpQsUJN9a6qqF2g6hsNpSm8wBQYDK2VwMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDAeFw0yNjA3MjAxOTAxMjFaFw0zNjA3MTcxOTAxMjFaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDAqMAUGAytlcAMhAAihki/Jec+1EaC6E6PsSxjMYFAazrgkNiUIlbj/+A/0o4GkMIGhMB0GA1UdDgQWBBQCuKxQmMQkAAy9KkfuD+WOmrrMbTAfBgNVHSMEGDAWgBQCuKxQmMQkAAy9KkfuD+WOmrrMbTAsBgNVHREEJTAjgglsb2NhbGhvc3SHBH8AAAGHEAAAAAAAAAAAAAAAAAAAAAEwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwBQYDK2VwA0EArZng3XitiH2E1pW/NTxQvEOBXJYpYE8coQmLV4yTjfI43CWHMG6lIrwk/so67oe6Z2R4iHGjUm3Tuy50Fl8hBw==", "base64");
const PRIVATE_KEY_DER = Buffer.from("MC4CAQAwBQYDK2VwBCIEICxYUWHqGoh0CBBohsaNg/NThm1n3UeWCzYuq6jS+Qi6", "base64");

describe("Node native raw QUIC driver", () => {
  test("runs stream, FIN, datagram, cancellation, and cleanup through N-API", async () => {
    const addonPath = process.env.FLOWERSEC_NATIVE_ADDON_PATH;
    if (addonPath === undefined) throw new Error("FLOWERSEC_NATIVE_ADDON_PATH is required");
    const addon = createRequire(import.meta.url)(addonPath) as NativeTransportAddonBinding;
    const driver = createNativeRawQuicDriver(addon);
    const listener = await driver.bindRawQuic({
      host: "127.0.0.1",
      port: 0,
      path: "direct",
      certificateChainDer: [CERTIFICATE_DER],
      privateKeyDer: PRIVATE_KEY_DER,
      inboundBidirectionalStreamCapacity: 10,
      handshakeTimeoutMs: 2_000,
    });
    const accepting = listener.accept();
    const address = listener.address();
    const client = await driver.connectRawQuic({
      host: address.host,
      port: address.port,
      serverName: "localhost",
      path: "direct",
      trustRootsDer: [CERTIFICATE_DER],
      inboundBidirectionalStreamCapacity: 10,
      handshakeTimeoutMs: 2_000,
    });
    const server = await accepting;

    const outbound = await client.openStream();
    expect(await outbound.write(new Uint8Array([1, 2, 3]))).toBe(3);
    const inbound = await server.acceptStream();
    await outbound.closeWrite();
    expect(Array.from((await inbound.read())!)).toEqual([1, 2, 3]);
    expect(await inbound.read()).toBeNull();

    const resetOutbound = await client.openStream();
    await resetOutbound.write(new Uint8Array([9]));
    const resetInbound = await server.acceptStream();
    expect(Array.from((await resetInbound.read())!)).toEqual([9]);
    await resetOutbound.reset();
    await expect(resetInbound.read()).rejects.toMatchObject({ code: "reset" });

    expect(client.unreliableDatagrams).toBeDefined();
    expect(server.unreliableDatagrams).toBeDefined();
    await expect(client.unreliableDatagrams!.send(new Uint8Array([4, 5]))).resolves.toBe("accepted");
    expect(Array.from(await server.unreliableDatagrams!.receive())).toEqual([4, 5]);

    const controller = new AbortController();
    const pendingAccept = listener.accept({ signal: controller.signal });
    controller.abort();
    await expect(pendingAccept).rejects.toMatchObject({ code: "aborted" });
    expect(listener.address().port).toBe(address.port);

    client.abort();
    await server.waitTermination();
    await listener.close();
  });
});
