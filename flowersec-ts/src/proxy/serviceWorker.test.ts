import { describe, expect, it } from "vitest";

import { createProxyServiceWorkerScript } from "./serviceWorker.js";

describe("proxy service worker generator", () => {
  it("emits a v2 registration and bounded response-credit bridge", () => {
    const script = createProxyServiceWorkerScript({
      passthrough: { paths: ["/proxy-sw.js"], prefixes: ["/assets/"] },
      runtimeRegistrationToken: "runtime-token",
      runtimeClientPathPrefix: "/boot/",
      injectHTML: { mode: "external_script", scriptUrl: "/inject.js", runtimeGlobal: "__runtime" },
    });
    expect(script).toContain("@floegence/flowersec-core/proxy v2");
    expect(script).toContain("chunk_credit_v2");
    expect(script).toContain("flowersec-proxy:register-runtime");
    expect(script).toContain("runtime-token");
    expect(script).not.toContain("proxy.runtime@1");
    expect(script).not.toContain("Yamux");
  });

  it("rejects unsafe or unbounded generator inputs", () => {
    expect(() => createProxyServiceWorkerScript({ maxRequestBodyBytes: 0 })).toThrow();
    expect(() => createProxyServiceWorkerScript({ runtimeRegistrationToken: " bad " })).toThrow();
    expect(() => createProxyServiceWorkerScript({ injectHTML: { mode: "inline_module" } })).toThrow();
    expect(() => createProxyServiceWorkerScript({ responseBodyInactivityTimeoutMs: -1 })).toThrow();
    expect(() => createProxyServiceWorkerScript({ responseBodyInactivityTimeoutMs: 300_001 })).toThrow();
  });

  it("aborts a request before response metadata and closes the remote stream", async () => {
    let remotePort: MessagePort | undefined;
    const remoteMessages: unknown[] = [];
    const target = {
      id: "client",
      postMessage(_message: unknown, transfers: Transferable[]) {
        remotePort = transfers[0] as MessagePort;
        remotePort.onmessage = (event) => remoteMessages.push(event.data);
        remotePort.start();
      },
    };
    const worker = generatedWorker(async () => target, { responseMetadataTimeoutMs: 1_000 });
    const controller = new AbortController();
    const response = worker.fetch(new Request("https://app.example/api", { signal: controller.signal }));
    await waitFor(() => remotePort !== undefined);
    controller.abort();
    await expect(within(response)).resolves.toMatchObject({ status: 499 });
    await waitFor(() => remoteMessages.some((message: any) => message?.type === "flowersec-proxy:abort"));
    remotePort?.close();
  });

  it("detects runtime disappearance while waiting for metadata", async () => {
    const target = { id: "client", postMessage() {} };
    let lookups = 0;
    const worker = generatedWorker(async () => ++lookups === 1 ? target : null, { responseMetadataTimeoutMs: 1_000 });
    const response = await within(worker.fetch(new Request("https://app.example/api")), 700);
    expect(response.status).toBe(503);
    expect(lookups).toBeGreaterThanOrEqual(2);
  });

  it("bounds the first response metadata wait and aborts the remote stream", async () => {
    const remoteMessages: unknown[] = [];
    let remotePort: MessagePort | undefined;
    const target = {
      id: "client",
      postMessage(_message: unknown, transfers: Transferable[]) {
        remotePort = transfers[0] as MessagePort;
        remotePort.onmessage = (event) => remoteMessages.push(event.data);
        remotePort.start();
      },
    };
    const worker = generatedWorker(async () => target, { responseMetadataTimeoutMs: 20 });
    const response = await within(worker.fetch(new Request("https://app.example/api")));
    expect(response.status).toBe(504);
    await waitFor(() => remoteMessages.some((message: any) => message?.type === "flowersec-proxy:abort"));
    remotePort?.close();
  });

  it("preserves normal streaming while liveness and metadata bounds are active", async () => {
    const target = {
      id: "client",
      postMessage(_message: unknown, transfers: Transferable[]) {
        const port = transfers[0] as MessagePort;
        port.onmessage = (event) => {
          if (event.data?.type !== "flowersec-proxy:response_credit") return;
          const data = new TextEncoder().encode("ok").buffer;
          port.postMessage({ type: "flowersec-proxy:response_chunk", data }, [data]);
          port.postMessage({ type: "flowersec-proxy:response_end" });
        };
        port.start();
        port.postMessage({ type: "flowersec-proxy:response_meta", status: 200, headers: [{ name: "content-type", value: "text/plain" }] });
      },
    };
    const worker = generatedWorker(async () => target, { responseMetadataTimeoutMs: 1_000 });
    const response = await within(worker.fetch(new Request("https://app.example/api")));
    expect(response.status).toBe(200);
    await expect(within(response.text())).resolves.toBe("ok");
  });

  it("bounds a stalled response body only when an inactivity timeout is configured", async () => {
    const remoteMessages: unknown[] = [];
    let remotePort: MessagePort | undefined;
    const target = {
      id: "client",
      postMessage(_message: unknown, transfers: Transferable[]) {
        remotePort = transfers[0] as MessagePort;
        remotePort.onmessage = (event) => remoteMessages.push(event.data);
        remotePort.start();
        remotePort.postMessage({ type: "flowersec-proxy:response_meta", status: 200, headers: [] });
      },
    };
    const worker = generatedWorker(async () => target, {
      responseMetadataTimeoutMs: 1_000,
      responseBodyInactivityTimeoutMs: 20,
    });
    const response = await within(worker.fetch(new Request("https://app.example/api")));
    await expect(within(response.text())).rejects.toThrow(/body timed out/);
    await waitFor(() => remoteMessages.some((message: any) => message?.type === "flowersec-proxy:abort"));
    remotePort?.close();
  });

  it("allows long idle streaming responses by default after metadata arrives", async () => {
    const target = {
      id: "client",
      postMessage(_message: unknown, transfers: Transferable[]) {
        const port = transfers[0] as MessagePort;
        port.start();
        port.postMessage({ type: "flowersec-proxy:response_meta", status: 200, headers: [] });
        setTimeout(() => {
          const data = new TextEncoder().encode("later").buffer;
          port.postMessage({ type: "flowersec-proxy:response_chunk", data }, [data]);
          port.postMessage({ type: "flowersec-proxy:response_end" });
        }, 60);
      },
    };
    const worker = generatedWorker(async () => target, { responseMetadataTimeoutMs: 20 });
    const response = await within(worker.fetch(new Request("https://app.example/api")));
    await expect(within(response.text(), 200)).resolves.toBe("later");
  });
});

function generatedWorker(
  getClient: (id: string) => Promise<unknown>,
  options: Parameters<typeof createProxyServiceWorkerScript>[0],
): Readonly<{ fetch(request: Request): Promise<Response> }> {
  let fetchHandler: ((event: any) => void) | undefined;
  const worker = {
    location: new URL("https://app.example/proxy-sw.js"),
    clients: { get: getClient, claim: async () => undefined },
    skipWaiting: async () => undefined,
    addEventListener(type: string, handler: (event: any) => void) {
      if (type === "fetch") fetchHandler = handler;
    },
  };
  const install = new Function("self", createProxyServiceWorkerScript({ ...options, windowTarget: "request_client" }));
  install(worker);
  return {
    fetch(request: Request): Promise<Response> {
      let response: Promise<Response> | undefined;
      fetchHandler?.({
        request,
        clientId: "client",
        respondWith(value: Promise<Response>) { response = value; },
      });
      if (response === undefined) throw new Error("service worker did not intercept fetch");
      return response;
    },
  };
}

async function waitFor(condition: () => boolean): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt++) {
    if (condition()) return;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  throw new Error("condition was not reached");
}

async function within<T>(operation: Promise<T>, timeoutMs = 200): Promise<T> {
  return await Promise.race([
    operation,
    new Promise<never>((_resolve, reject) => setTimeout(() => reject(new Error("operation remained pending")), timeoutMs)),
  ]);
}
