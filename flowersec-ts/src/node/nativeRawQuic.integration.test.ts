import { createRequire } from "node:module";

import { describe, expect, test } from "vitest";

import {
  createNativeRawQuicDriver,
  type NativeRawQuicDriver,
  type NativeRawQuicListener,
  type NativeTransportAddonBinding,
} from "./nativeTransportAddon.js";
import type { NativeCarrierSessionV2 } from "../v2/carrier.js";

const CERTIFICATE_DER = Buffer.from("MIIBjzCCAUGgAwIBAgIUW8hQEpQsUJN9a6qqF2g6hsNpSm8wBQYDK2VwMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDAeFw0yNjA3MjAxOTAxMjFaFw0zNjA3MTcxOTAxMjFaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDAqMAUGAytlcAMhAAihki/Jec+1EaC6E6PsSxjMYFAazrgkNiUIlbj/+A/0o4GkMIGhMB0GA1UdDgQWBBQCuKxQmMQkAAy9KkfuD+WOmrrMbTAfBgNVHSMEGDAWgBQCuKxQmMQkAAy9KkfuD+WOmrrMbTAsBgNVHREEJTAjgglsb2NhbGhvc3SHBH8AAAGHEAAAAAAAAAAAAAAAAAAAAAEwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwBQYDK2VwA0EArZng3XitiH2E1pW/NTxQvEOBXJYpYE8coQmLV4yTjfI43CWHMG6lIrwk/so67oe6Z2R4iHGjUm3Tuy50Fl8hBw==", "base64");
const PRIVATE_KEY_DER = Buffer.from("MC4CAQAwBQYDK2VwBCIEICxYUWHqGoh0CBBohsaNg/NThm1n3UeWCzYuq6jS+Qi6", "base64");

describe("Node native raw QUIC driver", () => {
  test("runs stream, FIN, datagram, cancellation, and cleanup through N-API", async () => {
    const addonPath = process.env.FLOWERSEC_NATIVE_ADDON_PATH;
    if (addonPath === undefined) throw new Error("FLOWERSEC_NATIVE_ADDON_PATH is required");
    const addon = createRequire(import.meta.url)(addonPath) as NativeTransportAddonBinding;
    const driver = createNativeRawQuicDriver(addon);
    await expect(driver.bindRawQuic({
      host: "127.0.0.1",
      port: 0,
      path: "direct",
      certificateChainDer: [CERTIFICATE_DER],
      privateKeyDer: PRIVATE_KEY_DER,
      inboundBidirectionalStreamCapacity: 131,
      handshakeTimeoutMs: 2_000,
    })).rejects.toThrow(/invalid_limits/u);
    await expect(driver.bindRawQuic({
      host: "127.0.0.1",
      port: 0,
      path: "invalid" as "direct",
      certificateChainDer: [CERTIFICATE_DER],
      privateKeyDer: PRIVATE_KEY_DER,
      inboundBidirectionalStreamCapacity: 3,
      handshakeTimeoutMs: 2_000,
    })).rejects.toThrow(/invalid_path/u);

    const listener = await driver.bindRawQuic({
      host: "127.0.0.1",
      port: 0,
      path: "direct",
      certificateChainDer: [CERTIFICATE_DER],
      privateKeyDer: PRIVATE_KEY_DER,
      inboundBidirectionalStreamCapacity: 10,
      handshakeTimeoutMs: 2_000,
    });
    let client: Awaited<ReturnType<typeof driver.connectRawQuic>> | undefined;
    let server: Awaited<ReturnType<typeof listener.accept>> | undefined;
    try {
      const accepting = listener.accept();
      const address = listener.address();
      client = await driver.connectRawQuic({
        host: address.host,
        port: address.port,
        serverName: "localhost",
        path: "direct",
        trustRootsDer: [CERTIFICATE_DER],
        inboundBidirectionalStreamCapacity: 10,
        handshakeTimeoutMs: 2_000,
      });
      server = await accepting;

      const outbound = await client.openStream();
      expect(await outbound.write(new Uint8Array([1, 2, 3]))).toBe(3);
      const inbound = await server.acceptStream();
      await outbound.closeWrite();
      expect(Array.from((await inbound.read())!)).toEqual([1, 2, 3]);
      expect(await inbound.read()).toBeNull();
      await inbound.closeWrite();
      expect(await outbound.read()).toBeNull();

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
      await expect(client.unreliableDatagrams!.send(new Uint8Array(65_000)))
        .rejects.toMatchObject({ code: "datagram_unavailable" });

      const controller = new AbortController();
      const pendingAccept = listener.accept({ signal: controller.signal });
      controller.abort();
      await expect(pendingAccept).rejects.toMatchObject({ code: "aborted" });
      expect(listener.address().port).toBe(address.port);

      const receiveController = new AbortController();
      const pendingReceive = client.unreliableDatagrams!.receive({ signal: receiveController.signal });
      receiveController.abort();
      await expect(pendingReceive).rejects.toMatchObject({ code: "aborted" });

      client.abort();
      client.abort();
      await server.waitTermination();
    } finally {
      client?.abort();
      server?.abort();
      await listener.close();
      await listener.close();
    }
  });

  test("propagates STOP_SENDING to the peer send direction", async () => {
    const pair = await openPair(3);
    try {
      const outbound = await pair.client.openStream();
      await outbound.write(new Uint8Array([7]));
      const inbound = await pair.server.acceptStream();

      await inbound.stopSending();
      await pair.server.unreliableDatagrams!.send(new Uint8Array([8]));
      expect(Array.from(await pair.client.unreliableDatagrams!.receive())).toEqual([8]);
      await expect(outbound.write(new Uint8Array([9]))).rejects.toMatchObject({ code: "reset" });
    } finally {
      await pair.cleanup();
    }
  });

  test("enforces runtime stream capacity and cancels an in-flight open", async () => {
    const pair = await openPair(1);
    try {
      expect(pair.client.inboundBidirectionalStreamCapacity).toBe(1);
      expect(pair.server.inboundBidirectionalStreamCapacity).toBe(1);
      const heldOutbound = await pair.client.openStream();
      await heldOutbound.write(new Uint8Array([1]));
      const heldInbound = await pair.server.acceptStream();
      const controller = new AbortController();
      let settled = false;
      const pendingOpen = pair.client.openStream({ signal: controller.signal });
      void pendingOpen.then(
        () => { settled = true; },
        () => { settled = true; },
      );

      await new Promise<void>((resolve) => { setImmediate(resolve); });
      expect(settled).toBe(false);
      controller.abort();
      await expect(pendingOpen).rejects.toMatchObject({ code: "aborted" });
      await Promise.all([heldOutbound.reset(), heldInbound.reset()]);
    } finally {
      await pair.cleanup();
    }
  });

  test("maps peer abort into portable errors for pending operations", async () => {
    const pair = await openPair(3);
    try {
      const pendingAccept = pair.server.acceptStream();
      const pendingReceive = pair.server.unreliableDatagrams!.receive();
      const accepted = expect(pendingAccept).rejects.toMatchObject({ code: "closed" });
      const received = expect(pendingReceive).rejects.toMatchObject({ code: "closed" });

      pair.client.abort();

      await Promise.all([accepted, received]);
      await pair.server.waitTermination();
    } finally {
      await pair.cleanup();
    }
  });
});

type NativePair = Readonly<{
  client: NativeCarrierSessionV2;
  server: NativeCarrierSessionV2;
  listener: NativeRawQuicListener;
  cleanup(): Promise<void>;
}>;

async function openPair(capacity: number): Promise<NativePair> {
  const driver = loadDriver();
  const listener = await bindListener(driver, capacity);
  let client: NativeCarrierSessionV2 | undefined;
  let server: NativeCarrierSessionV2 | undefined;
  try {
    const accepting = listener.accept();
    const address = listener.address();
    client = await driver.connectRawQuic({
      host: address.host,
      port: address.port,
      serverName: "localhost",
      path: "direct",
      trustRootsDer: [CERTIFICATE_DER],
      inboundBidirectionalStreamCapacity: capacity,
      handshakeTimeoutMs: 2_000,
    });
    server = await accepting;
    const connectedClient = client;
    const connectedServer = server;
    return {
      client: connectedClient,
      server: connectedServer,
      listener,
      async cleanup() {
        connectedClient.abort();
        connectedServer.abort();
        await listener.close();
      },
    };
  } catch (error) {
    client?.abort();
    server?.abort();
    await listener.close();
    throw error;
  }
}

function loadDriver(): NativeRawQuicDriver {
  const addonPath = process.env.FLOWERSEC_NATIVE_ADDON_PATH;
  if (addonPath === undefined) throw new Error("FLOWERSEC_NATIVE_ADDON_PATH is required");
  const addon = createRequire(import.meta.url)(addonPath) as NativeTransportAddonBinding;
  return createNativeRawQuicDriver(addon);
}

async function bindListener(driver: NativeRawQuicDriver, capacity: number): Promise<NativeRawQuicListener> {
  return await driver.bindRawQuic({
    host: "127.0.0.1",
    port: 0,
    path: "direct",
    certificateChainDer: [CERTIFICATE_DER],
    privateKeyDer: PRIVATE_KEY_DER,
    inboundBidirectionalStreamCapacity: capacity,
    handshakeTimeoutMs: 2_000,
  });
}
