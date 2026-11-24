import { describe, expect, it } from "vitest";

import { createProxyServiceWorkerScript } from "./serviceWorker.js";

describe("proxy service worker generator", () => {
  it("forwards bounded non-streaming uploads and rejects oversized blobs", async () => {
    const bodies: string[] = [];
    const worker = generatedWorker(async id => ({ id, postMessage(message: { req: {body: ArrayBuffer} }, [port]: MessagePort[]) {
      bodies.push(new TextDecoder().decode(message.req.body));
      port!.postMessage({ type: "flowersec-proxy:response_meta", status: 204, headers: [] });
      port!.postMessage({ type: "flowersec-proxy:response_end" });
      port!.close();
    } }), { maxRequestBodyBytes: 3 });
    for (const [text, status] of [["one", 204], ["long", 413]] as const) {
      const request = new Request("https://app.example/upload", { method: "POST", body: text });
      Object.defineProperty(request, "body", { value: undefined });
      expect((await within(worker.fetch(request))).status).toBe(status);
    }
    expect(bodies).toEqual(["one"]);
  });

  it("routes interleaved requests only to the initiating client by default", async () => {
    const worker = generatedWorker(async id => ({ id, postMessage(_value: unknown, [port]: MessagePort[]) {
      port!.postMessage({ type: "flowersec-proxy:response_meta", status: 204, headers: [{ name: "x-runtime", value: id }] });
      port!.postMessage({ type: "flowersec-proxy:response_end" });
      port!.close();
    } }), {});
    const owners = ["first", "second", "first"];
    const responses = await Promise.all(owners.map(id => worker.fetch(new Request("https://app.example/api"), id)));
    expect(responses.map(response => response.headers.get("x-runtime"))).toEqual(owners);
  });

  it("requires the live shared owner to release before another window takes over", async () => {
    const worker = generatedWorker(async id => ({ id }), { windowTarget: "registered_runtime" });
    await expect(worker.register("one")).resolves.toBe(true);
    await expect(worker.register("two")).resolves.toBe(false);
    worker.release("two");
    await expect(worker.register("two")).resolves.toBe(false);
    worker.release("one");
    await expect(worker.register("two")).resolves.toBe(true);
  });

  it.each([204, 205, 304])("settles status %i without a response body", async (status) => {
    const target = { id: "client", postMessage(_message: unknown, [port]: MessagePort[]) {
      port!.postMessage({ type: "flowersec-proxy:response_meta", status, headers: [] });
      port!.postMessage({ type: "flowersec-proxy:response_end" });
      port!.close();
    } };
    const worker = generatedWorker(async () => target, {});
    const response = await within(worker.fetch(new Request("https://app.example/status")));
    expect(response.status).toBe(status);
    expect(response.body).toBeNull();
  });

  it.each(["registered_runtime", "request_client"] as const)("restores a live %s after worker suspension", async windowTarget => {
    const cache = new Map<string, string>();
    const target = { id: "owner", url: "https://app.example/boot/", postMessage(message: { type: string }, [port]: MessagePort[]) {
      if (message.type === "flowersec-proxy:confirm-registration") port!.postMessage({ registered: true });
      else {
        port!.postMessage({ type: "flowersec-proxy:response_meta", status: 204 });
        port!.postMessage({ type: "flowersec-proxy:response_end" });
      }
      port!.close();
    } };
    const start = () => generatedWorker(async id => id === target.id ? target : null, { windowTarget, runtimeClientPathPrefix: "/boot/" }, cache);
    expect(await start().register(target.id)).toBe(true);
    const response = await within(start().fetch(new Request("https://app.example/api"), target.id));
    expect(response.status).toBe(204);
  });

  it("stops reading an oversized streaming upload before dispatch", async () => {
    let canceled = false;
    const body = new ReadableStream<Uint8Array>({
      start(controller) { controller.enqueue(Uint8Array.of(1, 2)); },
      cancel() { canceled = true; },
    });
    const worker = generatedWorker(async () => ({ id: "client" }), { maxRequestBodyBytes: 1 });
    const init = { method: "POST", body, duplex: "half" };
    const response = await within(worker.fetch(new Request("https://app.example/upload", init)));
    expect(response.status).toBe(413);
    expect(canceled).toBe(true);
  });

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
    expect(script).not.toContain("runtime-token");
    expect(script).not.toContain("proxy.runtime@1");
    expect(script).not.toContain("Yamux");
  });

  it("verifies the registration token before accepting a shared owner", async () => {
    const worker = generatedWorker(async id => ({ id }), { windowTarget: "registered_runtime", runtimeRegistrationToken: "registered-owner" });
    expect(await worker.register("wrong", "different")).toBe(false);
    expect(await worker.register("owner", "registered-owner")).toBe(true);
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
    const worker = generatedWorker(async () => ++lookups === 1 ? target : undefined, { responseMetadataTimeoutMs: 1_000 });
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
  cache = new Map<string, string>(),
): Readonly<{ fetch(request: Request, clientId?: string): Promise<Response>; register(id: string, token?: string): Promise<boolean>; release(id: string): void }> {
  let fetchHandler: ((event: any) => void) | undefined;
  let messageHandler: ((event: any) => void) | undefined;
  const worker = {
    caches: { open: async () => ({
      match: async (key: string) => cache.has(key) ? new Response(cache.get(key)) : undefined,
      put: async (key: string, response: Response) => { cache.set(key, await response.text()); },
      delete: async (key: string) => cache.delete(key),
    }) },
    location: new URL("https://app.example/proxy-sw.js"),
    clients: { get: getClient, claim: async () => undefined },
    skipWaiting: async () => undefined,
    addEventListener(type: string, handler: (event: any) => void) {
      if (type === "fetch") fetchHandler = handler;
      if (type === "message") messageHandler = handler;
    },
  };
  const install = new Function("self", createProxyServiceWorkerScript(options));
  install(worker);
  return {
    register(id, token) {
      return new Promise<boolean>((resolve, reject) => messageHandler!({
        source: { id, url: "https://app.example/boot/" }, data: { type: "flowersec-proxy:register-runtime", version: 2, token },
        ports: [{ postMessage: (reply: { ok: boolean }) => resolve(reply.ok), close() {} }],
        waitUntil: (work: Promise<void>) => work.catch(reject),
      }));
    },
    release(id) { messageHandler!({ source: { id }, data: { type: "flowersec-proxy:release-runtime", version: 2 }, waitUntil() {} }); },
    fetch(request: Request, clientId = "client"): Promise<Response> {
      let response: Promise<Response> | undefined;
      fetchHandler?.({
        request,
        clientId,
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
