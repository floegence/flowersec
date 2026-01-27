import { describe, expect, test } from "vitest";
import { FlowersecError } from "../utils/errors.js";
import { connectCore } from "./connectCore.js";

describe("connectCore option validation", () => {
  const baseArgs = {
    path: "direct" as const,
    wsUrl: "ws://example.invalid",
    channelId: "ch_1",
    e2eePskB64u: "psk",
    defaultSuite: 1,
    opts: { origin: "https://app.example" }
  };

  test.each([
    ["connectTimeoutMs", { connectTimeoutMs: -1 }, "connectTimeoutMs"],
    ["handshakeTimeoutMs", { handshakeTimeoutMs: -1 }, "handshakeTimeoutMs"],
    ["keepaliveIntervalMs", { keepaliveIntervalMs: -1 }, "keepaliveIntervalMs"],
    ["clientFeatures", { clientFeatures: -1 }, "clientFeatures"],
    ["maxHandshakePayload", { maxHandshakePayload: -1 }, "maxHandshakePayload"],
    ["maxRecordBytes", { maxRecordBytes: -1 }, "maxRecordBytes"],
    ["maxBufferedBytes", { maxBufferedBytes: -1 }, "maxBufferedBytes"],
    ["maxWsQueuedBytes", { maxWsQueuedBytes: -1 }, "maxWsQueuedBytes"]
  ])("rejects invalid %s", async (_name, extra, needle) => {
    const p = connectCore({
      ...baseArgs,
      opts: { ...baseArgs.opts, ...(extra as any) }
    } as any);
    await expect(p).rejects.toBeInstanceOf(FlowersecError);
    await expect(p).rejects.toMatchObject({ path: "direct", stage: "validate", code: "invalid_option" });
    await expect(p).rejects.toMatchObject({ message: expect.stringContaining(String(needle)) });
  });

  test("rejects non-finite timeout values", async () => {
    const p = connectCore({
      ...baseArgs,
      opts: { ...baseArgs.opts, connectTimeoutMs: Number.NaN }
    } as any);
    await expect(p).rejects.toBeInstanceOf(FlowersecError);
    await expect(p).rejects.toMatchObject({ path: "direct", stage: "validate", code: "invalid_option" });
    await expect(p).rejects.toMatchObject({ message: expect.stringContaining("connectTimeoutMs") });
  });

  test("rejects clientFeatures outside uint32 range", async () => {
    const p = connectCore({
      ...baseArgs,
      opts: { ...baseArgs.opts, clientFeatures: 0x1_0000_0000 }
    } as any);
    await expect(p).rejects.toBeInstanceOf(FlowersecError);
    await expect(p).rejects.toMatchObject({ path: "direct", stage: "validate", code: "invalid_option" });
    await expect(p).rejects.toMatchObject({ message: expect.stringContaining("clientFeatures") });
  });

  test("rejects whitespace-only origin as missing_origin", async () => {
    const p = connectCore({
      ...baseArgs,
      opts: { ...baseArgs.opts, origin: " " }
    } as any);
    await expect(p).rejects.toBeInstanceOf(FlowersecError);
    await expect(p).rejects.toMatchObject({ path: "direct", stage: "validate", code: "missing_origin" });
  });

  test("trims origin before passing it to wsFactory", async () => {
    try {
      await connectCore({
        ...baseArgs,
        opts: {
          ...baseArgs.opts,
          origin: " https://app.example ",
          wsFactory: (_url: string, origin: string) => {
            if (origin !== "https://app.example") throw new Error("origin_not_trimmed");
            throw new Error("ok");
          }
        }
      } as any);
      throw new Error("expected connectCore to throw");
    } catch (e) {
      expect(e).toBeInstanceOf(FlowersecError);
      expect(e).toMatchObject({ path: "direct", stage: "connect", code: "dial_failed" });
      expect((e as any).cause).toBeInstanceOf(Error);
      expect(((e as any).cause as Error).message).toBe("ok");
    }
  });
});
