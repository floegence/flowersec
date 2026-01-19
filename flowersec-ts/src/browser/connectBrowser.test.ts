import { afterEach, describe, expect, test, vi } from "vitest";

import { FlowersecError } from "../utils/errors.js";

const mocks = vi.hoisted(() => {
  const connect = vi.fn();
  return { connect };
});

vi.mock("../facade.js", () => ({
  connect: (...args: unknown[]) => mocks.connect(...args),
}));

import { connectBrowser } from "./connect.js";

afterEach(() => {
  delete (globalThis as any).window;
  vi.clearAllMocks();
});

describe("connectBrowser", () => {
  test("throws missing_origin when window.location.origin is unavailable", async () => {
    const p = connectBrowser({ ws_url: "ws://example.invalid/ws" }, {});
    await expect(p).rejects.toBeInstanceOf(FlowersecError);
    await expect(p).rejects.toMatchObject({ stage: "validate", code: "missing_origin", path: "auto" });
    expect(mocks.connect).not.toHaveBeenCalled();
  });

  test("injects window.location.origin and delegates to connect", async () => {
    (globalThis as any).window = { location: { origin: "http://127.0.0.1:5173" } };
    mocks.connect.mockResolvedValueOnce({ ok: true });

    const input = { ws_url: "ws://example.invalid/ws" };
    const out = await connectBrowser(input, { connectTimeoutMs: 123 });
    expect(out).toEqual({ ok: true });

    expect(mocks.connect).toHaveBeenCalledWith(input, { connectTimeoutMs: 123, origin: "http://127.0.0.1:5173" });
  });
});
