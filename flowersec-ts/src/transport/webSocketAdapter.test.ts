import { describe, expect, test, vi } from "vitest";

import {
  createWebSocketCarrierSessionV2,
  type WebSocketBinaryTransportV2,
} from "./webSocketAdapter.js";

describe("runtime-neutral WebSocket carrier adapter", () => {
  test("graceful close waits for the WebSocket sink barrier", async () => {
    let releaseFlush!: () => void;
    const flush = vi.fn(async () => await new Promise<void>((resolve) => { releaseFlush = resolve; }));
    const close = vi.fn();
    const transport = {
      readBinary: async () => await new Promise<Uint8Array>(() => undefined),
      writeBinary: async () => undefined,
      flush,
      close,
    };
    const carrier = createWebSocketCarrierSessionV2(transport, {
      path: "direct",
      client: true,
      inboundBidirectionalStreamCapacity: 3,
    });

    const closing = carrier.close();
    await Promise.resolve();
    expect(flush).toHaveBeenCalledOnce();
    expect(close).not.toHaveBeenCalled();
    releaseFlush();
    await closing;
    expect(close).toHaveBeenCalledOnce();
  });

  test("local close settles pending and future accepts", async () => {
    const close = vi.fn();
    const transport: WebSocketBinaryTransportV2 = {
      readBinary: async () => await new Promise<Uint8Array>(() => undefined),
      writeBinary: async () => undefined,
      flush: async () => undefined,
      close,
    };
    const carrier = createWebSocketCarrierSessionV2(transport, {
      path: "direct",
      client: true,
      inboundBidirectionalStreamCapacity: 3,
    });

    const accepting = carrier.acceptStream();
    await carrier.close();
    await expect(accepting).rejects.toMatchObject({ code: "closed" });
    await expect(carrier.acceptStream()).rejects.toMatchObject({ code: "closed" });
    await expect(carrier.waitTermination()).resolves.toBeUndefined();
    expect(close).toHaveBeenCalledOnce();
  });
});
