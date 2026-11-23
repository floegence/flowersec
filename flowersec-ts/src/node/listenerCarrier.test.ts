import { expect, test, vi } from "vitest";
import { createAcceptor, createTunnelRuntime } from "./index.js";

test.each(["unknown", "https"])("rejects an unknown listener carrier (%s) before raw QUIC bind", async (carrier) => {
  const listeners = [{ carrier, path: "direct", host: "127.0.0.1", port: 0 }] as never;
  const authorize = vi.fn(async () => { throw new Error("unexpected authorization"); });
  await expect(createAcceptor({ listeners, authorize, maxInboundStreams: 1 })).rejects.toThrow(TypeError);
  expect(() => createTunnelRuntime({ listeners, authorize, maxInboundStreams: 1 })).toThrow(TypeError);
  expect(authorize).not.toHaveBeenCalled();
});
