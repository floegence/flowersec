import { afterEach, describe, expect, test, vi } from "vitest";

import { FlowersecError } from "../utils/errors.js";
import type { ConnectArtifact } from "../connect/artifact.js";

const mocks = vi.hoisted(() => {
  const connect = vi.fn();
  return { connect };
});

vi.mock("../facade.js", () => ({
  connect: (...args: unknown[]) => mocks.connect(...args),
}));

import { connectBrowser } from "./connect.js";

function makeDirectArtifact(): ConnectArtifact {
  return {
    v: 1,
    transport: "direct",
    direct_info: {
      ws_url: "ws://example.invalid/ws",
      channel_id: "chan_1",
      e2ee_psk_b64u: "Zm9vYmFyYmF6cXV4eHl6MDEyMzQ1Njc4OWFiY2RlZg",
      channel_init_expire_at_unix_s: 123,
      default_suite: 1,
    },
  };
}

afterEach(() => {
  delete (globalThis as any).window;
  vi.clearAllMocks();
});

describe("connectBrowser", () => {
  test("throws missing_origin when window.location.origin is unavailable", async () => {
    const p = connectBrowser(makeDirectArtifact(), {});
    await expect(p).rejects.toBeInstanceOf(FlowersecError);
    await expect(p).rejects.toMatchObject({ stage: "validate", code: "missing_origin", path: "auto" });
    expect(mocks.connect).not.toHaveBeenCalled();
  });

  test("injects window.location.origin and delegates to connect", async () => {
    (globalThis as any).window = { location: { origin: "http://127.0.0.1:5173" } };
    mocks.connect.mockResolvedValueOnce({ ok: true });

    const input = makeDirectArtifact();
    const out = await connectBrowser(input, { connectTimeoutMs: 123 });
    expect(out).toEqual({ ok: true });

    expect(mocks.connect).toHaveBeenCalledWith(input, { connectTimeoutMs: 123, origin: "http://127.0.0.1:5173" });
  });
});
