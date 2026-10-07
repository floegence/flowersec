import { afterEach, describe, expect, it, vi } from "vitest";
import { captureLocalBrowserBridge, type LocalBrowserBridgeOptions } from "./localBrowserBridge.js";

function configuration(host = "127.0.0.1"): LocalBrowserBridgeOptions {
  const origin = `http://${host}:19080`;
  vi.stubGlobal("location", { origin });
  return { deployment: { endpoint: `ws://${host}:19080/flowersec/v4/local`, applicationOrigin: origin,
    routeDigest: new Uint8Array(32).fill(1), notBeforeMS: 1n, notAfterMS: 1000n,
    applicationAuthAssurance: "application_origin", ambientCredentialScope: "trusted_local_services" },
    queueMessages: 4, sendBufferBytes: 65544, runtimeBytes: 1024n, providerRuntimeBytes: 131072n };
}
afterEach(() => vi.unstubAllGlobals());

describe("current LocalBrowserBridge deployment boundary", () => {
  it.each(["127.0.0.1", "127.17.0.2", "[::1]"])("captures exact same-origin numeric loopback %s", host => {
    const original = configuration(host), captured = captureLocalBrowserBridge(original);
    original.deployment.routeDigest.fill(9);
    expect(captured.deployment.routeDigest).toEqual(new Uint8Array(32).fill(1));
    expect(captured.deployment.applicationOrigin).toBe(globalThis.location.origin);
    expect(captured.deployment.endpoint.endsWith("/flowersec/v4/local")).toBe(true);
  });
  it.each(["localhost", "192.168.1.1", "127.000.0.1", "[::ffff:127.0.0.1]", "[::]", "0.0.0.0"])("rejects address aliases and non-loopback %s", host => {
    expect(() => captureLocalBrowserBridge(configuration(host))).toThrow();
  });
  it.each(["wss://127.0.0.1:19080/flowersec/v4/local", "ws://127.0.0.1:19080/flowersec/v4/direct", "ws://127.0.0.1:19080/flowersec/v3/direct",
    "ws://127.0.0.1:19080/flowersec/v4/local?token=secret", "ws://user@127.0.0.1:19080/flowersec/v4/local", "ws://127.0.0.1:19080/flowersec/v4/local#fragment"])("rejects a different deployment tuple %s", endpoint => {
    const config = configuration();
    expect(() => captureLocalBrowserBridge({ ...config, deployment: { ...config.deployment, endpoint } })).toThrow();
  });
  it("refuses a configured Origin different from the browser's actual document", () => {
    const config = configuration(); vi.stubGlobal("location", { origin: "http://127.0.0.1:19081" });
    expect(() => captureLocalBrowserBridge(config)).toThrow();
  });
  it("does not manufacture host-instance assurance from ordinary browser configuration", () => {
    const config = configuration();
    expect(() => captureLocalBrowserBridge({ ...config, deployment: { ...config.deployment, applicationAuthAssurance: "host_instance" as "application_origin" } })).toThrow();
  });
  it("does not start an asynchronous User-Agent capability probe that can outlive local bridge capture", async () => {
    let rejectProbe!: (error: Error) => void;
    const pending = new Promise<never>((_resolve, reject) => { rejectProbe = reject; });
    void pending.catch(() => undefined);
    const probe = vi.fn(() => pending);
    vi.stubGlobal("navigator", { userAgentData: { getHighEntropyValues: probe } });

    const captured = captureLocalBrowserBridge(configuration());
    expect(probe).not.toHaveBeenCalled();
    expect(captured.deployment.endpoint).toBe("ws://127.0.0.1:19080/flowersec/v4/local");

    rejectProbe(new Error("late provider failure"));
    await Promise.resolve();
    expect(probe).not.toHaveBeenCalled();
    expect(captured.deployment.applicationOrigin).toBe("http://127.0.0.1:19080");
  });
});
