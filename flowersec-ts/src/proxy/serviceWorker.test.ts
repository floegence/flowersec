import { gzipSync, deflateSync, brotliCompressSync } from "node:zlib";
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

  it.each([["HEAD", 200], ["GET", 304]] as const)("preserves %s/%s representation metadata above the body limit", async (method, status) => {
    let remote: MessagePort | undefined;
    const target = { id: "client", postMessage(_message: unknown, transfers: Transferable[]) {
      remote = transfers[0] as MessagePort;
      remote.postMessage({ type: "flowersec-proxy:response_meta", status,
        headers: [{ name: "content-length", value: "1073741824" }, { name: "content-encoding", value: "gzip" }] });
    } };
    try {
      const worker = generatedWorker(async () => target, { maxEncodedBodyBytes: 8 });
      const response = await within(worker.fetch(new Request("https://app.example/large", { method })));
      expect(response.status).toBe(status);
      expect(response.body).toBeNull();
      expect(response.headers.get("content-length")).toBe("1073741824");
      expect(response.headers.get("content-encoding")).toBe("gzip");
    } finally { remote?.close(); }
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


describe("service worker content representation", () => {
  it.each(["gzip", "deflate", "br", "gzip, br"])("decodes %s once and retains origin metadata", async (coding) => {
    const plain = Buffer.from("decoded browser body");
    const coded = coding === "gzip" ? gzipSync(plain) : coding === "deflate" ? deflateSync(plain) : brotliCompressSync(coding === "br" ? plain : gzipSync(plain));
    let remote: MessagePort | undefined;
    const worker = generatedWorker(async () => ({ id: "client", postMessage(_message: unknown, transfers: Transferable[]) {
      remote = transfers[0] as MessagePort;
      let sent = false;
      remote.onmessage = event => {
        if (sent || event.data?.type !== "flowersec-proxy:response_credit") return;
        sent = true;
        const data = Uint8Array.from(coded).buffer;
        remote!.postMessage({ type: "flowersec-proxy:response_chunk", data }, [data]);
        remote!.postMessage({ type: "flowersec-proxy:response_end" });
      };
      remote.postMessage({ type: "flowersec-proxy:response_meta", status: 200, headers: [
        { name: "content-encoding", value: coding }, { name: "content-length", value: String(coded.length) }, { name: "etag", value: '"origin"' },
      ] });
    } }), {});
    try {
      const response = await within(worker.fetch(new Request("https://app.example/api")));
      expect(await within(response.text())).toBe(plain.toString());
      expect(response.headers.get("content-encoding")).toBe(coding);
      expect(response.headers.get("content-length")).toBe(String(coded.length));
      expect(response.headers.get("etag")).toBe('"origin"');
    } finally { remote?.close(); }
  });

  it("fails the body and cancels the original source when decoded bytes exceed the cap", async () => {
    const coded = gzipSync(Buffer.alloc(8192, 65));
    let remote: MessagePort | undefined;
    let aborted = false;
    const worker = generatedWorker(async () => ({ id: "client", postMessage(_message: unknown, transfers: Transferable[]) {
      remote = transfers[0] as MessagePort;
      let sent = false;
      remote.onmessage = event => {
        if (event.data?.type === "flowersec-proxy:abort") { aborted = true; return; }
        if (sent || event.data?.type !== "flowersec-proxy:response_credit") return;
        sent = true;
        const data = Uint8Array.from(coded).buffer;
        remote!.postMessage({ type: "flowersec-proxy:response_chunk", data }, [data]);
      };
      remote.postMessage({ type: "flowersec-proxy:response_meta", status: 200, headers: [{ name: "content-encoding", value: "gzip" }] });
    } }), { maxDecodedBodyBytes: 1024 });
    try {
      const response = await within(worker.fetch(new Request("https://app.example/api")));
      await expect(within(response.text())).rejects.toThrow(/decoded body exceeds limit/);
      await waitFor(() => aborted);
    } finally { remote?.close(); }
  });
});

describe("service worker original publication generation", () => {
  it("seals a body read across FENCE and INSTALL and reports cleanup until real reader cancellation ends", async () => {
    let startRead!: () => void, completeCancel!: () => void;
    const reading = new Promise<void>(resolve => { startRead = resolve; });
    const canceled = new Promise<void>(resolve => { completeCancel = resolve; });
    const forwarded: unknown[] = [], observations: { type?: string; ok?: boolean; sequence?: number; pending_callbacks?: number }[] = [];
    const ports: MessagePort[] = [];
    const worker = generatedWorker(async () => ({ id: "client", postMessage(message: unknown) { forwarded.push(message); } }), {
      runtimeRegistrationToken: "private-runtime-token",
    });
    let runtimeClaim = "";
    const command = async (data: Record<string, unknown>) => {
      const channel = new MessageChannel(); ports.push(channel.port1, channel.port2);
      const reply = new Promise<Record<string, unknown>>(resolve => {
        channel.port1.onmessage = event => { observations.push(event.data); if (event.data?.type?.endsWith("ack")) resolve(event.data); };
        channel.port1.start();
      });
      const message = { ...data, token: "private-runtime-token" };
      if (data.type === "flowersec-proxy:publication-control") Object.assign(message, {
        owner_id: data.owner_id ?? "owner-a", owner_epoch: data.owner_epoch ?? 1, owner_claim: data.owner_claim ?? runtimeClaim,
      });
      worker.message(message, channel.port2);
      const result = await within(reply);
      if (result.type === "flowersec-proxy:register-runtime-ack" && typeof result.owner_claim === "string") runtimeClaim = result.owner_claim;
      return result;
    };
    try {
      expect((await command({ type: "flowersec-proxy:register-runtime", version: 2 })).ok).toBe(true);
      expect((await command({ type: "flowersec-proxy:publication-control", action: "install", sequence: 1, context: "A".repeat(43) })).ok).toBe(true);
      const body = new ReadableStream<Uint8Array>({ pull() { startRead(); }, cancel() { return canceled; } });
      const request = new Request("https://app.example/api", { method: "POST", body, duplex: "half" } as RequestInit & { duplex: "half" });
      const response = worker.fetch(request);
      await within(reading); await waitFor(() => request.body?.locked === true);
      const fence = await command({ type: "flowersec-proxy:publication-control", action: "fence", sequence: 2, context: "A".repeat(43) });
      expect(fence.ok).toBe(true); expect(fence.pending_callbacks).toBeGreaterThan(0);
      const install = await command({ type: "flowersec-proxy:publication-control", action: "install", sequence: 3, context: "B".repeat(43) });
      expect(install.ok).toBe(true); expect(install.pending_callbacks).toBeGreaterThan(0);
      const failed = await within(response);
      expect(failed.status).toBe(499); expect(failed.headers.get("cache-control")).toBe("no-store, no-transform");
      expect(forwarded).toHaveLength(0);
      completeCancel();
      await waitFor(() => observations.some(value => value.type === "flowersec-proxy:publication-cleanup" && value.sequence === 3 && value.pending_callbacks === 0));
    } finally { completeCancel(); for (const port of ports) port.close(); }
  });

  it("permits repeated drained owner replacements and rejects delayed controls from prior claims", async () => {
    const ports: MessagePort[] = [];
    const worker = generatedWorker(async () => ({ id: "client", postMessage() {} }), {
      runtimeRegistrationToken: "private-runtime-token",
    });
    const register = async (owner_id: string, owner_epoch: number): Promise<string> => {
      const channel = new MessageChannel(); ports.push(channel.port1, channel.port2);
      const reply = new Promise<Record<string, unknown>>(resolve => {
        channel.port1.onmessage = event => resolve(event.data);
        channel.port1.start();
      });
      worker.message({ type: "flowersec-proxy:register-runtime", version: 2, token: "private-runtime-token", owner_id, owner_epoch }, channel.port2);
      const result = await within(reply);
      expect(result.ok).toBe(true); expect(typeof result.owner_claim).toBe("string");
      return result.owner_claim as string;
    };
    const command = async (owner_id: string, owner_epoch: number, owner_claim: string,
      action: "fence" | "install", sequence: number, context: string) => {
      const channel = new MessageChannel(); ports.push(channel.port1, channel.port2);
      const reply = new Promise<Record<string, unknown>>(resolve => {
        channel.port1.onmessage = event => { if (event.data?.type === "flowersec-proxy:publication-ack") resolve(event.data); };
        channel.port1.start();
      });
      worker.message({ type: "flowersec-proxy:publication-control", owner_id, owner_epoch, owner_claim, action, sequence, context,
        token: "private-runtime-token" }, channel.port2);
      return await within(reply);
    };
    try {
      const contextA = "A".repeat(43), contextB = "B".repeat(43), contextC = "C".repeat(43);
      const claimA = await register("owner-a", 1);
      expect((await command("owner-a", 1, claimA, "install", 1, contextA)).ok).toBe(true);
      expect((await command("owner-a", 1, claimA, "fence", 2, contextA)).ok).toBe(true);
      const claimB = await register("owner-b", 2);
      expect((await command("owner-b", 2, claimB, "install", 1, contextB)).ok).toBe(true);
      expect((await command("owner-b", 2, claimB, "fence", 2, contextB)).ok).toBe(true);
      const claimC = await register("owner-c", 3);
      expect((await command("owner-c", 3, claimC, "install", 1, contextC)).ok).toBe(true);
      expect((await command("owner-c", 3, claimC, "fence", 2, contextC)).ok).toBe(true);
      const claimD = await register("owner-d", 1);
      expect((await command("owner-d", 1, claimD, "install", 1, "D".repeat(43))).ok).toBe(true);
      expect((await command("owner-a", 1, claimA, "fence", 99, contextA)).ok).toBe(false);
      expect((await command("owner-b", 2, claimB, "fence", 99, contextB)).ok).toBe(false);
      expect((await command("owner-c", 3, claimC, "fence", 99, contextC)).ok).toBe(false);
      expect((await command("owner-d", 1, claimD, "fence", 2, "D".repeat(43))).ok).toBe(true);
    } finally { for (const port of ports) port.close(); }
  });

  it("captures the original generation before client lookup and never forwards it under a successor context", async () => {
    let releaseClient!: (value: unknown) => void, lookedUp!: () => void;
    const started = new Promise<void>(resolve => { lookedUp = resolve; });
    const lookup = new Promise<unknown>(resolve => { releaseClient = resolve; });
    const forwarded: unknown[] = [], ports: MessagePort[] = [];
    const worker = generatedWorker(async () => { lookedUp(); return await lookup; }, { runtimeRegistrationToken: "private-runtime-token" });
    let runtimeClaim = "";
    const command = async (data: Record<string, unknown>): Promise<Record<string, unknown>> => {
      const channel = new MessageChannel(); ports.push(channel.port1, channel.port2);
      const reply = new Promise<Record<string, unknown>>(resolve => {
        channel.port1.onmessage = event => { if (event.data?.type?.endsWith("ack")) resolve(event.data); };
        channel.port1.start();
      });
      const message = { ...data, token: "private-runtime-token" };
      if (data.type === "flowersec-proxy:publication-control") Object.assign(message, {
        owner_id: data.owner_id ?? "owner-a", owner_epoch: data.owner_epoch ?? 1, owner_claim: data.owner_claim ?? runtimeClaim,
      });
      worker.message(message, channel.port2);
      const result = await within(reply);
      if (result.type === "flowersec-proxy:register-runtime-ack" && typeof result.owner_claim === "string") runtimeClaim = result.owner_claim;
      return result;
    };
    try {
      await command({ type: "flowersec-proxy:register-runtime", version: 2 });
      await command({ type: "flowersec-proxy:publication-control", action: "install", sequence: 1, context: "A".repeat(43) });
      const response = worker.fetch(new Request("https://app.example/api")); await within(started);
      await command({ type: "flowersec-proxy:publication-control", action: "fence", sequence: 2, context: "A".repeat(43) });
      const unavailable = await within(worker.fetch(new Request("https://app.example/after-close")));
      expect(unavailable.status).toBe(503);
      expect(unavailable.headers.get("cache-control")).toBe("no-store, no-transform");
      expect(forwarded).toHaveLength(0);
      await command({ type: "flowersec-proxy:publication-control", action: "install", sequence: 3, context: "B".repeat(43) });
      releaseClient({ id: "client", postMessage(message: unknown) { forwarded.push(message); } });
      const failed = await within(response);
      expect(failed.status).toBe(502); expect(failed.headers.get("cache-control")).toBe("no-store, no-transform"); expect(forwarded).toHaveLength(0);
    } finally { releaseClient(null); for (const port of ports) port.close(); }
  });
});

function generatedWorker(
  getClient: (id: string) => Promise<unknown>,
  options: Parameters<typeof createProxyServiceWorkerScript>[0],
): Readonly<{ fetch(request: Request): Promise<Response>; message(data: unknown, port: MessagePort): void }> {
  let messageHandler: ((event: any) => void) | undefined;
  let fetchHandler: ((event: any) => void) | undefined;
  const worker = {
    location: new URL("https://app.example/proxy-sw.js"),
    clients: { get: getClient, claim: async () => undefined },
    skipWaiting: async () => undefined,
    addEventListener(type: string, handler: (event: any) => void) {
      if (type === "fetch") fetchHandler = handler;
      if (type === "message") messageHandler = handler;
    },
  };
  const install = new Function("self", createProxyServiceWorkerScript({ ...options, windowTarget: "request_client" }));
  install(worker);
  return {
    message(data: unknown, port: MessagePort): void {
      messageHandler?.({ data, ports: [port], source: { id: "client", url: "https://app.example/boot/" }, waitUntil() {} });
    },
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
