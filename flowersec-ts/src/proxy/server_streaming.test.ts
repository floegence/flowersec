import { describe, expect, test } from "vitest";

import type { Session } from "../endpoint/index.js";
import { readU32be, u32be } from "../utils/bin.js";
import type { YamuxStream } from "../yamux/stream.js";
import { PROXY_KIND_HTTP1 } from "./constants.js";
import { serveProxySession, serveProxyStream } from "./server.js";

describe("Node proxy HTTP streaming", () => {
  test("delivers the first request chunk upstream before the terminal frame", async () => {
    const stream = new PushStream();
    const firstChunk = new TextEncoder().encode("first");
    const upstreamChunk = deferred<Uint8Array>();
    let settled = false;

    const serving = serveProxyStream(PROXY_KIND_HTTP1, stream as unknown as YamuxStream, options({
      fetch: async (_input, init) => {
        const reader = (init?.body as ReadableStream<Uint8Array>).getReader();
        upstreamChunk.resolve((await reader.read()).value!);
        return new Response(null, { status: 204 });
      },
    })).finally(() => { settled = true; });

    stream.enqueue(requestMeta("stream-request"));
    stream.enqueue(u32be(firstChunk.length));
    stream.enqueue(firstChunk);

    expect(await upstreamChunk.promise).toEqual(firstChunk);
    await waitFor(() => stream.output.length > 0);
    expect(responseMeta(stream)).toMatchObject({ ok: true, status: 204 });
    expect(settled).toBe(false);
    expect(stream.closed).toBe(false);

    stream.enqueue(u32be(0));
    await serving;
    expect(stream.resetCalls).toHaveLength(0);
  });

  test("writes response metadata and the first chunk before upstream completion", async () => {
    const stream = requestStream("stream-response");
    let responseController!: ReadableStreamDefaultController<Uint8Array>;
    const serving = serveProxyStream(PROXY_KIND_HTTP1, stream as unknown as YamuxStream, options({
      fetch: async () => new Response(new ReadableStream<Uint8Array>({
        start(controller) { responseController = controller; },
      }), { status: 200 }),
    }));

    const firstChunk = new TextEncoder().encode("first response");
    await waitFor(() => responseController != null);
    responseController.enqueue(firstChunk);
    await waitFor(() => responseBodyChunks(stream).length === 1);

    expect(responseMeta(stream)).toMatchObject({ ok: true, status: 200 });
    expect(responseBodyChunks(stream)).toEqual([firstChunk]);
    expect(stream.closed).toBe(false);

    responseController.close();
    await serving;
  });

  test("rejects a known oversized request before calling fetch", async () => {
    const stream = requestStream("known-request-limit", new Uint8Array([1]), [
      { name: "content-length", value: "5" },
    ]);
    let fetchCalls = 0;

    await serveProxyStream(PROXY_KIND_HTTP1, stream as unknown as YamuxStream, options({
      maxBodyBytes: 4,
      extraRequestHeaders: ["content-length"],
      fetch: async () => {
        fetchCalls += 1;
        return new Response(null, { status: 204 });
      },
    }));

    expect(fetchCalls).toBe(0);
    expect(responseMeta(stream)).toMatchObject({ ok: false, error: { code: "request_body_too_large" } });
    expect(stream.resetCalls).toHaveLength(0);
  });

  test("returns a structured error when an unknown request body exceeds the limit before the response starts", async () => {
    const stream = requestStream("unknown-request-limit", new Uint8Array([1, 2, 3, 4, 5]));

    await serveProxyStream(PROXY_KIND_HTTP1, stream as unknown as YamuxStream, options({
      maxBodyBytes: 4,
      maxChunkBytes: 4,
      fetch: async (_input, init) => {
        const reader = (init?.body as ReadableStream<Uint8Array>).getReader();
        while (!(await reader.read()).done) { /* Consume the streaming upload. */ }
        return new Response(null, { status: 204 });
      },
    }));

    expect(responseMeta(stream)).toMatchObject({ ok: false, error: { code: "request_body_too_large" } });
    expect(stream.resetCalls).toHaveLength(0);
  });

  test("resets after an unknown response body exceeds the limit without writing a second metadata frame", async () => {
    const stream = requestStream("unknown-response-limit");
    await serveProxyStream(PROXY_KIND_HTTP1, stream as unknown as YamuxStream, options({
      maxBodyBytes: 4,
      fetch: async () => new Response(new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new Uint8Array([1, 2, 3, 4]));
          controller.enqueue(new Uint8Array([5]));
          controller.close();
        },
      }), { status: 200 }),
    }));

    expect(responseMeta(stream)).toMatchObject({ ok: true, status: 200 });
    expect(metadataFrameCount(stream)).toBe(1);
    expect(stream.resetCalls).toEqual([expect.stringContaining("response body too large")]);
  });

  test("returns a structured error for a known oversized response before success metadata", async () => {
    const stream = requestStream("known-response-limit");
    await serveProxyStream(PROXY_KIND_HTTP1, stream as unknown as YamuxStream, options({
      maxBodyBytes: 4,
      fetch: async () => new Response(new Uint8Array([1, 2, 3, 4, 5]), {
        status: 200,
        headers: { "content-length": "5" },
      }),
    }));

    expect(responseMeta(stream)).toMatchObject({ ok: false, error: { code: "response_body_too_large" } });
    expect(metadataFrameCount(stream)).toBe(1);
    expect(stream.resetCalls).toHaveLength(0);
  });

  test("resets an early response when the caller cancels before request framing completes", async () => {
    const stream = new PushStream();
    const stop = new AbortController();
    stream.enqueue(requestMeta("early-response-cancel"));
    stream.enqueue(u32be(1));
    stream.enqueue(new Uint8Array([1]));

    const serving = serveProxyStream(PROXY_KIND_HTTP1, stream as unknown as YamuxStream, options({
      fetch: async (_input, init) => {
        const reader = (init?.body as ReadableStream<Uint8Array>).getReader();
        await reader.read();
        return new Response(null, { status: 204 });
      },
    }), stop.signal);

    await waitFor(() => stream.output.length > 0);
    expect(responseMeta(stream)).toMatchObject({ ok: true, status: 204 });
    stop.abort();
    await serving;

    expect(metadataFrameCount(stream)).toBe(1);
    expect(stream.resetCalls).toEqual([expect.stringContaining("proxy request canceled")]);
  });

  test("cancels the upstream request when request framing fails", async () => {
    const stream = new PushStream();
    const fetchAborted = deferred<void>();
    stream.enqueue(requestMeta("framing-error"));
    stream.enqueue(u32be(4));
    stream.enqueueError(new Error("truncated request body"));

    await serveProxyStream(PROXY_KIND_HTTP1, stream as unknown as YamuxStream, options({
      fetch: async (_input, init) => {
        const reader = (init?.body as ReadableStream<Uint8Array>).getReader();
        init?.signal?.addEventListener("abort", () => fetchAborted.resolve(), { once: true });
        await expect(reader.read()).rejects.toThrow("truncated request body");
        throw new Error("upload failed");
      },
    }));

    await fetchAborted.promise;
    expect(responseMeta(stream)).toMatchObject({ ok: false, error: { code: "request_body_invalid" } });
  });

  test("rejects excess proxy streams immediately and releases permits", async () => {
    const session = new AcceptedSession();
    const stop = new AbortController();
    const responses = [deferred<Response>(), deferred<Response>(), deferred<Response>()];
    let fetchCalls = 0;
    const serving = serveProxySession(session as unknown as Session, options({
      maxConcurrentStreams: 2,
      fetch: async () => await responses[fetchCalls++]!.promise,
    }), stop.signal).catch(() => {});

    const first = requestStream("first");
    const second = requestStream("second");
    const rejected = requestStream("rejected");
    session.enqueue(first);
    session.enqueue(second);
    await waitFor(() => fetchCalls === 2);
    session.enqueue(rejected);
    await waitFor(() => rejected.resetCalls.length === 1);
    expect(fetchCalls).toBe(2);

    responses[0]!.resolve(new Response(null, { status: 204 }));
    await waitFor(() => first.closed);
    const afterRelease = requestStream("after-release");
    session.enqueue(afterRelease);
    await waitFor(() => fetchCalls === 3);

    responses[1]!.resolve(new Response(null, { status: 204 }));
    responses[2]!.resolve(new Response(null, { status: 204 }));
    await waitFor(() => second.closed && afterRelease.closed);
    stop.abort();
    await serving;
  });

  test("uses the shared default limit of 64 proxy streams", async () => {
    const session = new AcceptedSession();
    const stop = new AbortController();
    const responses = Array.from({ length: 64 }, () => deferred<Response>());
    let fetchCalls = 0;
    const serving = serveProxySession(session as unknown as Session, options({
      fetch: async () => await responses[fetchCalls++]!.promise,
    }), stop.signal).catch(() => {});

    for (let index = 0; index < 64; index++) session.enqueue(requestStream(`accepted-${index}`));
    await waitFor(() => fetchCalls === 64);

    const rejected = requestStream("rejected-65");
    session.enqueue(rejected);
    await waitFor(() => rejected.resetCalls.length === 1);
    expect(fetchCalls).toBe(64);

    for (const response of responses) response.resolve(new Response(null, { status: 204 }));
    await waitFor(() => responses.every((_response, index) => session.streamAt(index)?.closed === true));
    stop.abort();
    await serving;
  });
});

function options(overrides: Partial<Parameters<typeof serveProxyStream>[2]> = {}): Parameters<typeof serveProxyStream>[2] {
  return {
    upstream: "http://127.0.0.1",
    ...overrides,
  };
}

class AcceptedSession {
  private readonly queue: PushStream[] = [];
  private readonly waiters: Array<(stream: PushStream) => void> = [];
  private readonly accepted: PushStream[] = [];

  enqueue(stream: PushStream): void {
    const waiter = this.waiters.shift();
    if (waiter == null) this.queue.push(stream);
    else waiter(stream);
  }

  streamAt(index: number): PushStream | undefined { return this.accepted[index]; }

  async acceptStream(options: Readonly<{ signal?: AbortSignal }> = {}): Promise<Readonly<{
    kind: typeof PROXY_KIND_HTTP1;
    stream: YamuxStream;
  }>> {
    const queued = this.queue.shift();
    if (queued != null) {
      this.accepted.push(queued);
      return { kind: PROXY_KIND_HTTP1, stream: queued as unknown as YamuxStream };
    }
    const stream = await new Promise<PushStream>((resolve, reject) => {
      const onAbort = () => reject(options.signal?.reason ?? new Error("aborted"));
      options.signal?.addEventListener("abort", onAbort, { once: true });
      this.waiters.push((value) => {
        options.signal?.removeEventListener("abort", onAbort);
        resolve(value);
      });
    });
    this.accepted.push(stream);
    return { kind: PROXY_KIND_HTTP1, stream: stream as unknown as YamuxStream };
  }
}

class PushStream {
  readonly output: Uint8Array[] = [];
  readonly resetCalls: string[] = [];
  closed = false;
  private readonly input: Array<Uint8Array | Error> = [];
  private readonly waiters: Array<(value: Uint8Array | Error) => void> = [];

  enqueue(value: Uint8Array): void { this.push(value); }
  enqueueError(error: Error): void { this.push(error); }

  async read(): Promise<Uint8Array | null> {
    const next = this.input.shift() ?? await new Promise<Uint8Array | Error>((resolve) => this.waiters.push(resolve));
    if (next instanceof Error) throw next;
    return next;
  }

  async write(bytes: Uint8Array): Promise<void> { this.output.push(bytes.slice()); }
  async close(): Promise<void> { this.closed = true; }
  reset(error: Error): void { this.resetCalls.push(error.message); this.closed = true; }

  private push(value: Uint8Array | Error): void {
    const waiter = this.waiters.shift();
    if (waiter == null) this.input.push(value);
    else waiter(value);
  }
}

function requestStream(requestId: string, body = new Uint8Array(), headers: Array<{ name: string; value: string }> = []): PushStream {
  const stream = new PushStream();
  stream.enqueue(requestMeta(requestId, headers));
  if (body.length > 0) {
    stream.enqueue(u32be(body.length));
    stream.enqueue(body);
  }
  stream.enqueue(u32be(0));
  return stream;
}

function requestMeta(requestId: string, headers: Array<{ name: string; value: string }> = []): Uint8Array {
  const json = new TextEncoder().encode(JSON.stringify({
    v: 1,
    request_id: requestId,
    method: "POST",
    path: "/upload",
    headers,
  }));
  const framed = new Uint8Array(4 + json.length);
  framed.set(u32be(json.length), 0);
  framed.set(json, 4);
  return framed;
}

function responseMeta(stream: PushStream): Record<string, unknown> {
  const bytes = concat(stream.output);
  const length = readU32be(bytes, 0);
  return JSON.parse(new TextDecoder().decode(bytes.subarray(4, 4 + length))) as Record<string, unknown>;
}

function responseBodyChunks(stream: PushStream): Uint8Array[] {
  const bytes = concat(stream.output);
  if (bytes.length < 4) return [];
  const metaLength = readU32be(bytes, 0);
  let offset = 4 + metaLength;
  const chunks: Uint8Array[] = [];
  while (offset + 4 <= bytes.length) {
    const length = readU32be(bytes, offset);
    offset += 4;
    if (length === 0 || offset + length > bytes.length) break;
    chunks.push(bytes.slice(offset, offset + length));
    offset += length;
  }
  return chunks;
}

function metadataFrameCount(stream: PushStream): number {
  const bytes = concat(stream.output);
  if (bytes.length < 4) return 0;
  const firstLength = readU32be(bytes, 0);
  const bodyStart = 4 + firstLength;
  if (bodyStart + 4 > bytes.length) return 1;
  const firstBodyLength = readU32be(bytes, bodyStart);
  const afterFirstBody = bodyStart + 4 + firstBodyLength;
  if (afterFirstBody + 4 > bytes.length) return 1;
  const possibleMetaLength = readU32be(bytes, afterFirstBody);
  if (possibleMetaLength === 0 || afterFirstBody + 4 + possibleMetaLength > bytes.length) return 1;
  try {
    const value = JSON.parse(new TextDecoder().decode(bytes.subarray(afterFirstBody + 4, afterFirstBody + 4 + possibleMetaLength)));
    return typeof value === "object" && value != null && "request_id" in value ? 2 : 1;
  } catch {
    return 1;
  }
}

function concat(chunks: readonly Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const output = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }
  return output;
}

function deferred<T>(): Readonly<{ promise: Promise<T>; resolve: (value: T) => void }> {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((next) => { resolve = next; });
  return { promise, resolve };
}

async function waitFor(condition: () => boolean): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt++) {
    if (condition()) return;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  throw new Error("timed out waiting for proxy server state");
}
