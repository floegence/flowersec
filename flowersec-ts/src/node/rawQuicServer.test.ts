import { describe, expect, test, vi } from "vitest";

import type { NativeRawQuicDriver } from "./nativeTransportAddon.js";
import { normalizeCertificateChain } from "./rawQuicAdapter.js";
import { startNodeRawQuicServer } from "./rawQuicServer.js";

describe("Node raw QUIC listener adapter", () => {
  test("requires explicit TLS material before binding", async () => {
    const driver = { bindRawQuic: vi.fn() } as unknown as NativeRawQuicDriver;
    await expect(startNodeRawQuicServer(driver, {
      host: "127.0.0.1",
      port: 0,
      path: "direct",
      inboundBidirectionalStreamCapacity: 66,
      tls: { certificate: "", privateKey: "" },
    })).rejects.toThrow("raw QUIC listener requires explicit TLS material");
    expect(driver.bindRawQuic).not.toHaveBeenCalled();
  });

  test("redacts certificate and key parser diagnostics", async () => {
    const driver = { bindRawQuic: vi.fn() } as unknown as NativeRawQuicDriver;
    await expect(startNodeRawQuicServer(driver, {
      host: "127.0.0.1",
      port: 0,
      path: "direct",
      inboundBidirectionalStreamCapacity: 66,
      tls: {
        certificate: "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----",
        privateKey: "-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----",
      },
    })).rejects.toThrowError(new TypeError("invalid raw QUIC certificate"));
    expect(driver.bindRawQuic).not.toHaveBeenCalled();
  });

  test("rejects an oversized PEM bundle before certificate parsing", () => {
    const oversized = `${TEST_CERTIFICATE}\n${" ".repeat(1024 * 1024)}`;
    expect(() => normalizeCertificateChain(oversized)).toThrowError(
      new TypeError("invalid raw QUIC certificate"),
    );
  });

  test("accepts a bounded concatenated PEM chain", () => {
    expect(normalizeCertificateChain(`${TEST_CERTIFICATE}\n${TEST_CERTIFICATE}`)).toHaveLength(2);
  });

  test("rejects a certificate array that exceeds the chain limit", () => {
    expect(() => normalizeCertificateChain(Array.from({ length: 33 }, () => TEST_CERTIFICATE))).toThrowError(
      new TypeError("invalid raw QUIC certificate"),
    );
  });

  test("redacts malformed certificate array entries", () => {
    expect(() => normalizeCertificateChain([null] as unknown as string[])).toThrowError(
      new TypeError("invalid raw QUIC certificate"),
    );
  });

  test("maps accepted sessions and waits for listener cleanup", async () => {
    const session = nativeSession();
    const listener = {
      address: () => ({ host: "127.0.0.1", port: 32101 }),
      accept: vi.fn(async () => session),
      close: vi.fn(async () => undefined),
    };
    const driver = {
      bindRawQuic: vi.fn(async () => listener),
    } as unknown as NativeRawQuicDriver;
    const running = await startNodeRawQuicServer(driver, {
      host: "127.0.0.1",
      port: 0,
      path: "tunnel",
      inboundBidirectionalStreamCapacity: 66,
      tls: { certificate: TEST_CERTIFICATE, privateKey: TEST_PRIVATE_KEY },
    });

    expect(driver.bindRawQuic).toHaveBeenCalledWith(expect.objectContaining({
      host: "127.0.0.1",
      port: 0,
      path: "tunnel",
      inboundBidirectionalStreamCapacity: 66,
      certificateChainDer: expect.any(Array),
      privateKeyDer: expect.any(Uint8Array),
    }));
    expect((await running.accept()).kind).toBe("raw_quic");
    expect(running.address()).toEqual({ host: "127.0.0.1", port: 32101 });
    await running.close();
    expect(listener.close).toHaveBeenCalledOnce();
  });
});

function nativeSession() {
  return {
    kind: "raw_quic" as const,
    path: "tunnel" as const,
    inboundBidirectionalStreamCapacity: 66,
    openStream: vi.fn(),
    acceptStream: vi.fn(),
    waitTermination: vi.fn(async () => undefined),
    close: vi.fn(async () => undefined),
    abort: vi.fn(),
  };
}

const TEST_CERTIFICATE = "-----BEGIN CERTIFICATE-----\nMIIBjzCCAUGgAwIBAgIUW8hQEpQsUJN9a6qqF2g6hsNpSm8wBQYDK2VwMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDAeFw0yNjA3MjAxOTAxMjFaFw0zNjA3MTcxOTAxMjFaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDAqMAUGAytlcAMhAAihki/Jec+1EaC6E6PsSxjMYFAazrgkNiUIlbj/+A/0o4GkMIGhMB0GA1UdDgQWBBQCuKxQmMQkAAy9KkfuD+WOmrrMbTAfBgNVHSMEGDAWgBQCuKxQmMQkAAy9KkfuD+WOmrrMbTAsBgNVHREEJTAjgglsb2NhbGhvc3SHBH8AAAGHEAAAAAAAAAAAAAAAAAAAAAEwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwBQYDK2VwA0EArZng3XitiH2E1pW/NTxQvEOBXJYpYE8coQmLV4yTjfI43CWHMG6lIrwk/so67oe6Z2R4iHGjUm3Tuy50Fl8hBw==\n-----END CERTIFICATE-----";
const TEST_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEICxYUWHqGoh0CBBohsaNg/NThm1n3UeWCzYuq6jS+Qi6\n-----END PRIVATE KEY-----";
