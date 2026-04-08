import { describe, expect, it } from "vitest";

import { DEFAULT_PROXY_PRESET_MANIFEST } from "./preset.js";
import { assertProxyRuntimeScopeV1, extractProxyRuntimeScopeV1 } from "./runtimeScope.js";

function makeServiceWorkerScope() {
  return {
    mode: "service_worker",
    serviceWorker: {
      scriptUrl: "/proxy-sw.js",
      scope: "/",
    },
    preset: {
      presetId: "default",
    },
    limits: {
      maxBodyBytes: 4096,
    },
  } as const;
}

describe("proxy runtime scope", () => {
  it("validates service worker mode", () => {
    expect(assertProxyRuntimeScopeV1(makeServiceWorkerScope())).toMatchObject({
      mode: "service_worker",
      serviceWorker: { scriptUrl: "/proxy-sw.js", scope: "/" },
    });
  });

  it("rejects mode-specific field mixing", () => {
    expect(() =>
      assertProxyRuntimeScopeV1({
        ...makeServiceWorkerScope(),
        controllerBridge: { allowedOrigins: ["https://app.example.test"] },
      })
    ).toThrow("bad proxy.runtime.controllerBridge");
  });

  it("rejects missing mode-required fields", () => {
    expect(() =>
      assertProxyRuntimeScopeV1({
        mode: "service_worker",
        preset: { presetId: "default" },
      } as any)
    ).toThrow("bad proxy.runtime.serviceWorker");

    expect(() =>
      assertProxyRuntimeScopeV1({
        mode: "controller_bridge",
        preset: { presetId: "default" },
      } as any)
    ).toThrow("bad proxy.runtime.controllerBridge");
  });

  it("rejects unknown fields", () => {
    expect(() =>
      assertProxyRuntimeScopeV1({
        ...makeServiceWorkerScope(),
        extraField: true,
      } as any)
    ).toThrow("bad proxy.runtime.extraField");
  });

  it("rejects too many fields", () => {
    const payload: Record<string, unknown> = {
      mode: "service_worker",
      serviceWorker: { scriptUrl: "/proxy-sw.js", scope: "/" },
      preset: { presetId: "default" },
    };
    for (let i = 0; i < 70; i++) {
      payload[`field${i}`] = i;
    }
    expect(() => assertProxyRuntimeScopeV1(payload)).toThrow("bad proxy.runtime.payload");
  });

  it("rejects too-deep payloads", () => {
    expect(() =>
      assertProxyRuntimeScopeV1({
        mode: "service_worker",
        serviceWorker: { scriptUrl: "/proxy-sw.js", scope: "/" },
        preset: {
          presetId: "default",
          snapshot: {
            v: 1,
            preset_id: "default",
            limits: {
              max_json_frame_bytes: {
                too: { deep: { for: { proxy: { runtime: { test: true } } } } },
              } as any,
            },
          },
        },
      } as any)
    ).toThrow("bad proxy.runtime.payload");
  });

  it("rejects unsupported scope versions for stable helpers", () => {
    expect(() =>
      extractProxyRuntimeScopeV1({
        v: 1,
        transport: "tunnel",
        tunnel_grant: {
          tunnel_url: "wss://example.invalid/tunnel",
          channel_id: "chan_1",
          channel_init_expire_at_unix_s: 123,
          idle_timeout_seconds: 30,
          role: 1,
          token: "tok",
          e2ee_psk_b64u: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          allowed_suites: [1],
          default_suite: 1,
        },
        scoped: [
          {
            scope: "proxy.runtime",
            scope_version: 2,
            critical: false,
            payload: { mode: "service_worker" },
          },
        ],
      },
      "service_worker")
    ).toThrow("unsupported proxy.runtime scope_version: 2");
  });

  it("keeps the current preset snapshot schema comfortably below the runtime size cap", () => {
    expect(new TextEncoder().encode(JSON.stringify(DEFAULT_PROXY_PRESET_MANIFEST)).length).toBeLessThan(4 * 1024);
  });
});
