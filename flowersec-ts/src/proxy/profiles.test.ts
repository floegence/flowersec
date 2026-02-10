import { describe, expect, it } from "vitest";

import {
  PROXY_PROFILE_CODESERVER,
  PROXY_PROFILE_DEFAULT,
  resolveProxyProfile,
} from "./profiles.js";

describe("proxy profiles", () => {
  it("resolves named profiles", () => {
    expect(resolveProxyProfile()).toEqual(PROXY_PROFILE_DEFAULT);
    expect(resolveProxyProfile("default")).toEqual(PROXY_PROFILE_DEFAULT);
    expect(resolveProxyProfile("codeserver")).toEqual(PROXY_PROFILE_CODESERVER);
  });

  it("supports partial override", () => {
    const p = resolveProxyProfile({ maxWsFrameBytes: 4 * 1024 * 1024 });
    expect(p.maxWsFrameBytes).toBe(4 * 1024 * 1024);
    expect(p.maxChunkBytes).toBe(PROXY_PROFILE_DEFAULT.maxChunkBytes);
  });

  it("rejects invalid values", () => {
    expect(() => resolveProxyProfile({ maxBodyBytes: -1 })).toThrow(/maxBodyBytes/);
    expect(() => resolveProxyProfile({ timeoutMs: Number.POSITIVE_INFINITY })).toThrow(/timeoutMs/);
  });
});
