import { describe, expect, test } from "vitest";

import type { Session } from "../endpoint/index.js";
import { readU32be, u32be } from "../utils/bin.js";
import type { YamuxStream } from "../yamux/stream.js";
import { PROXY_KIND_HTTP1 } from "./constants.js";
import { serveProxySession } from "./server.js";

describe("Node proxy request body budget", () => {
  test("bounds concurrent buffered request bodies and releases after fetch", async () => {
    const session = new AcceptedSession();
    const stop = new AbortController();
    const firstFetch = deferred<Response>();
    let fetchCalls = 0;
    const serving = serveProxySession(session as unknown as Session, {
      upstream: "http://127.0.0.1",
      maxBodyBytes: 8,
      maxBufferedRequestBodyBytes: 6,
      maxConcurrentStreams: 3,
      fetch: async () => {
        fetchCalls += 1;
        if (fetchCalls === 1) return await firstFetch.promise;
        return new Response(null, { status: 204 });
      },
    }, stop.signal).catch(() => {});

    const first = requestStream("first", new Uint8Array([1, 2, 3, 4]));
    session.enqueue(first);
    await waitFor(() => fetchCalls === 1);

    const overflow = requestStream("overflow", new Uint8Array([5, 6, 7, 8]));
    session.enqueue(overflow);
    await waitFor(() => overflow.closed);
    expect(responseMeta(overflow)).toMatchObject({
      ok: false,
      error: { code: "resource_exhausted" },
    });
    expect(fetchCalls).toBe(1);

    firstFetch.resolve(new Response(null, { status: 204 }));
    await waitFor(() => first.closed);

    const afterRelease = requestStream("after-release", new Uint8Array([9, 10, 11, 12]));
    session.enqueue(afterRelease);
    await waitFor(() => afterRelease.closed);
    expect(responseMeta(afterRelease)).toMatchObject({ ok: true, status: 204 });
    expect(fetchCalls).toBe(2);

    stop.abort();
    await serving;
  });

  test("releases a reservation when body reading fails", async () => {
    const session = new AcceptedSession();
    const stop = new AbortController();
    let fetchCalls = 0;
    const serving = serveProxySession(session as unknown as Session, {
      upstream: "http://127.0.0.1",
      maxBodyBytes: 4,
      maxBufferedRequestBodyBytes: 4,
      maxConcurrentStreams: 2,
      fetch: async () => {
        fetchCalls += 1;
        return new Response(null, { status: 204 });
      },
    }, stop.signal).catch(() => {});

    const failed = failingRequestStream("failed", 4);
    session.enqueue(failed);
    await waitFor(() => failed.closed);
    expect(fetchCalls).toBe(0);

    const retry = requestStream("retry", new Uint8Array([1, 2, 3, 4]));
    session.enqueue(retry);
    await waitFor(() => retry.closed);
    expect(responseMeta(retry)).toMatchObject({ ok: true, status: 204 });
    expect(fetchCalls).toBe(1);

    stop.abort();
    await serving;
  });

  test("releases a reservation after fetch failure and returns a sanitized error", async () => {
    const session = new AcceptedSession();
    const stop = new AbortController();
    const bodies: ArrayBuffer[] = [];
    let rejectFetch = true;
    const serving = serveProxySession(session as unknown as Session, {
      upstream: "http://127.0.0.1",
      maxBodyBytes: 4,
      maxBufferedRequestBodyBytes: 4,
      fetch: async (_input, init) => {
        expect(init?.body).toBeInstanceOf(ArrayBuffer);
        bodies.push(init?.body as ArrayBuffer);
        if (rejectFetch) {
          rejectFetch = false;
          throw new Error("secret.internal.example:8443 token=do-not-return");
        }
        return new Response(null, { status: 204 });
      },
    }, stop.signal).catch(() => {});

    const failed = requestStream("failed-fetch", new Uint8Array([1, 2, 3, 4]));
    session.enqueue(failed);
    await waitFor(() => failed.closed);
    expect(responseMeta(failed)).toMatchObject({
      ok: false,
      error: {
        code: "upstream_request_failed",
        message: "upstream request failed",
      },
    });
    expect(JSON.stringify(responseMeta(failed))).not.toContain("secret.internal.example");

    const retry = requestStream("retry-fetch", new Uint8Array([5, 6, 7, 8]));
    session.enqueue(retry);
    await waitFor(() => retry.closed);
    expect(responseMeta(retry)).toMatchObject({ ok: true, status: 204 });
    expect(bodies.map((body) => Array.from(new Uint8Array(body)))).toEqual([
      [1, 2, 3, 4],
      [5, 6, 7, 8],
    ]);

    stop.abort();
    await serving;
  });

  test("does not fetch after cancellation at the request-body boundary", async () => {
    const session = new AcceptedSession();
    const stop = new AbortController();
    let fetchCalls = 0;
    const serving = serveProxySession(session as unknown as Session, {
      upstream: "http://127.0.0.1",
      maxBodyBytes: 4,
      maxBufferedRequestBodyBytes: 4,
      fetch: async () => {
        fetchCalls += 1;
        return new Response(null, { status: 204 });
      },
    }, stop.signal).catch(() => {});

    const canceled = requestStream(
      "canceled-at-body-boundary",
      new Uint8Array([1, 2, 3, 4]),
      () => stop.abort(),
    );
    session.enqueue(canceled);
    await waitFor(() => canceled.output.length > 0);

    expect(responseMeta(canceled)).toMatchObject({
      ok: false,
      error: {
        code: "canceled",
        message: "proxy request canceled",
      },
    });
    expect(fetchCalls).toBe(0);
    await serving;
  });

  test("releases a request-body reservation before a response body finishes", async () => {
    const session = new AcceptedSession();
    const stop = new AbortController();
    let firstResponseController: ReadableStreamDefaultController<Uint8Array> | undefined;
    let fetchCalls = 0;
    const serving = serveProxySession(session as unknown as Session, {
      upstream: "http://127.0.0.1",
      maxBodyBytes: 4,
      maxBufferedRequestBodyBytes: 4,
      maxConcurrentStreams: 2,
      fetch: async () => {
        fetchCalls += 1;
        if (fetchCalls === 1) {
          return new Response(new ReadableStream<Uint8Array>({
            start(controller) {
              firstResponseController = controller;
            },
          }), { status: 200 });
        }
        return new Response(null, { status: 204 });
      },
    }, stop.signal).catch(() => {});

    const first = requestStream("streaming-response", new Uint8Array([1, 2, 3, 4]));
    session.enqueue(first);
    await waitFor(() => fetchCalls === 1 && firstResponseController != null);

    const second = requestStream("after-fetch-returned", new Uint8Array([5, 6, 7, 8]));
    session.enqueue(second);
    await waitFor(() => second.closed);
    expect(responseMeta(second)).toMatchObject({ ok: true, status: 204 });
    expect(fetchCalls).toBe(2);

    firstResponseController!.close();
    await waitFor(() => first.closed);
    stop.abort();
    await serving;
  });
});

class AcceptedSession {
  private readonly queue: MemoryStream[] = [];
  private readonly waiters: Array<(stream: MemoryStream) => void> = [];

  enqueue(stream: MemoryStream): void {
    const waiter = this.waiters.shift();
    if (waiter == null) this.queue.push(stream);
    else waiter(stream);
  }

  async acceptStream(options: Readonly<{ signal?: AbortSignal }> = {}): Promise<Readonly<{
    kind: typeof PROXY_KIND_HTTP1;
    stream: YamuxStream;
  }>> {
    const queued = this.queue.shift();
    if (queued != null) return { kind: PROXY_KIND_HTTP1, stream: queued as unknown as YamuxStream };
    const stream = await new Promise<MemoryStream>((resolve, reject) => {
      const onAbort = () => reject(options.signal?.reason ?? new Error("aborted"));
      options.signal?.addEventListener("abort", onAbort, { once: true });
      this.waiters.push((value) => {
        options.signal?.removeEventListener("abort", onAbort);
        resolve(value);
      });
    });
    return { kind: PROXY_KIND_HTTP1, stream: stream as unknown as YamuxStream };
  }
}

class MemoryStream {
  readonly output: Uint8Array[] = [];
  closed = false;
  private readonly input: Array<Uint8Array | Error>;

  constructor(
    input: Array<Uint8Array | Error>,
    private readonly onRead?: (value: Uint8Array | Error) => void,
  ) {
    this.input = input;
  }

  async read(): Promise<Uint8Array | null> {
    const next = this.input.shift();
    if (next == null) return null;
    this.onRead?.(next);
    if (next instanceof Error) throw next;
    return next;
  }

  async write(bytes: Uint8Array): Promise<void> {
    this.output.push(bytes.slice());
  }

  async close(): Promise<void> {
    this.closed = true;
  }

  reset(): void {
    this.closed = true;
  }
}

function requestStream(requestId: string, body: Uint8Array, onTerminalRead?: () => void): MemoryStream {
  const terminal = u32be(0);
  return new MemoryStream([
    requestMeta(requestId),
    u32be(body.length),
    body,
    terminal,
  ], (value) => {
    if (value === terminal) onTerminalRead?.();
  });
}

function failingRequestStream(requestId: string, bodyLength: number): MemoryStream {
  return new MemoryStream([
    requestMeta(requestId),
    u32be(bodyLength),
    new Error("body read failed"),
  ]);
}

function requestMeta(requestId: string): Uint8Array {
  const json = new TextEncoder().encode(JSON.stringify({
    v: 1,
    request_id: requestId,
    method: "POST",
    path: "/upload",
    headers: [],
  }));
  const framed = new Uint8Array(4 + json.length);
  framed.set(u32be(json.length), 0);
  framed.set(json, 4);
  return framed;
}

function responseMeta(stream: MemoryStream): Record<string, unknown> {
  const bytes = concat(stream.output);
  const length = readU32be(bytes, 0);
  return JSON.parse(new TextDecoder().decode(bytes.subarray(4, 4 + length))) as Record<string, unknown>;
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

function deferred<T>(): Readonly<{
  promise: Promise<T>;
  resolve: (value: T) => void;
}> {
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
