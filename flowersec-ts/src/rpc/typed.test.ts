import { describe, expect, test, vi } from "vitest";
import { RpcCallError } from "./callError.js";
import { callTyped } from "./typed.js";
import type { RpcCaller } from "./caller.js";

describe("rpc.callTyped", () => {
  test("returns typed payload on success", async () => {
    const rpc: RpcCaller = {
      call: vi.fn().mockResolvedValue({ payload: { ok: true } }),
      onNotify: vi.fn()
    };
    await expect(callTyped<{ ok: boolean }>(rpc, 1, {})).resolves.toEqual({ ok: true });
  });

  test("throws RpcCallError on rpc error", async () => {
    const rpc: RpcCaller = {
      call: vi.fn().mockResolvedValue({ payload: null, error: { code: 404, message: "not found" } }),
      onNotify: vi.fn()
    };
    await expect(callTyped(rpc, 123, {})).rejects.toBeInstanceOf(RpcCallError);
    await expect(callTyped(rpc, 123, {})).rejects.toMatchObject({ code: 404, typeId: 123 });
  });

  test("uses assert when provided", async () => {
    const rpc: RpcCaller = {
      call: vi.fn().mockResolvedValue({ payload: { ok: true } }),
      onNotify: vi.fn()
    };
    const assert = vi.fn((v: unknown) => {
      if (v == null || typeof v !== "object" || (v as any).ok !== true) throw new Error("bad payload");
      return v as { ok: true };
    });
    await expect(callTyped(rpc, 1, {}, { assert })).resolves.toEqual({ ok: true });
    expect(assert).toHaveBeenCalledTimes(1);
  });
});

