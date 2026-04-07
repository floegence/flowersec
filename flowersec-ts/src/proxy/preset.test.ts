import { describe, expect, it } from "vitest";

import {
  CODESERVER_PROXY_PRESET_MANIFEST,
  DEFAULT_PROXY_PRESET_MANIFEST,
  assertProxyPresetManifest,
  resolveNamedProxyPreset,
  resolveProxyPreset,
} from "./preset.js";

describe("proxy presets", () => {
  it("resolves named presets", () => {
    expect(resolveNamedProxyPreset("default")).toEqual(DEFAULT_PROXY_PRESET_MANIFEST);
    expect(resolveNamedProxyPreset("codeserver")).toEqual(CODESERVER_PROXY_PRESET_MANIFEST);
  });

  it("builds resolved concrete limits", () => {
    const preset = resolveProxyPreset({ max_ws_frame_bytes: 4 * 1024 * 1024 });
    expect(preset.preset_id).toBe("custom");
    expect(preset.limits.max_ws_frame_bytes).toBe(4 * 1024 * 1024);
    expect(preset.limits.max_chunk_bytes).toBe(DEFAULT_PROXY_PRESET_MANIFEST.limits.max_chunk_bytes);
  });

  it("rejects zero and unknown manifest fields", () => {
    expect(() =>
      assertProxyPresetManifest({
        v: 1,
        preset_id: "demo",
        limits: { timeout_ms: 0 },
      })
    ).toThrow(/timeout_ms/);
    expect(() =>
      assertProxyPresetManifest({
        v: 1,
        preset_id: "demo",
        owner_doc: "nope",
        limits: {},
      })
    ).toThrow(/owner_doc/);
  });
});
