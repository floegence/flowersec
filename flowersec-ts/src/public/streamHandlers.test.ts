import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, test, vi } from "vitest";

import { createStreamMetadata } from "./streamMetadata.js";
import { SessionError, type IncomingStream, type Session } from "./contract.js";
import {
  StreamHandlers,
  type HandlerRegistrationError,
} from "./streamHandlers.js";

type StreamKindVectors = Readonly<{
  stream_kinds: readonly Readonly<{
    id: string;
    unit: string;
    repeat: number;
    suffix: string;
    valid: boolean;
  }>[];
}>;

const repositoryRoot = fileURLToPath(new URL("../../..", import.meta.url));
const vectors = JSON.parse(readFileSync(
  path.join(repositoryRoot, "testdata/transport_v2/session_handler_vectors.json"),
  "utf8",
)) as StreamKindVectors;

function scriptedSession(incoming: readonly IncomingStream[]): {
  session: Session;
  close: ReturnType<typeof vi.fn<() => Promise<void>>>;
} {
  let index = 0;
  const close = vi.fn(async () => undefined);
  return {
    close,
    session: {
      rpc: {} as Session["rpc"],
      async openStream() { throw new SessionError("operation_failed"); },
      async acceptStream() {
        if (index < incoming.length) return incoming[index++]!;
        throw new SessionError("closed");
      },
      async rekey() {},
      async probeLiveness() { return 0; },
      async waitTermination() { return { error: new SessionError("closed") }; },
      close,
    },
  };
}

function testIncoming(
  kind: string,
  closeWrite: () => Promise<void> = async () => undefined,
): {
  incoming: IncomingStream;
  closeWrite: ReturnType<typeof vi.fn<() => Promise<void>>>;
  reset: ReturnType<typeof vi.fn<() => Promise<void>>>;
} {
  const closeWriteSpy = vi.fn(closeWrite);
  const reset = vi.fn(async () => undefined);
  return {
    closeWrite: closeWriteSpy,
    reset,
    incoming: {
      kind,
      metadata: createStreamMetadata({}),
      stream: {
        kind,
        terminalError: undefined,
        async read() { return null; },
        async write(data) { return data.byteLength; },
        closeWrite: closeWriteSpy,
        reset,
        async close() {},
      },
    },
  };
}

function establishedSession(incoming: IncomingStream): Session {
  let delivered = false;
  return {
    rpc: {} as Session["rpc"],
    async openStream() { throw new SessionError("operation_failed"); },
    async acceptStream(options) {
      if (!delivered) {
        delivered = true;
        return incoming;
      }
      return await new Promise<IncomingStream>((_resolve, reject) => {
        options?.signal?.addEventListener(
          "abort",
          () => reject(new SessionError("canceled")),
          { once: true },
        );
      });
    },
    async rekey() {},
    async probeLiveness() { return 0; },
    async waitTermination() { return { error: new SessionError("closed") }; },
    async close() {},
  };
}

describe("StreamHandlers", () => {
  test("dispatches application streams on an established endpoint-client session", async () => {
    const closeWrite = vi.fn(async () => undefined);
    const reset = vi.fn(async () => undefined);
    const handled = vi.fn(async () => undefined);
    const incoming: IncomingStream = {
      kind: "files/read",
      metadata: createStreamMetadata({ request_id: "req-1" }),
      stream: {
        kind: "files/read",
        terminalError: undefined,
        async read() { return null; },
        async write(data) { return data.byteLength; },
        closeWrite,
        reset,
        async close() {},
      },
    };
    const handlers = new StreamHandlers({ maxConcurrentStreams: 2 });
    handlers.handleStream("files/read", handled);
    const controller = new AbortController();
    const serving = handlers.serve(establishedSession(incoming), {
      signal: controller.signal,
    });

    await vi.waitFor(() => expect(handled).toHaveBeenCalledOnce());
    expect(() => handlers.handleStream("late", async () => undefined)).toThrowError(
      expect.objectContaining<Partial<HandlerRegistrationError>>({ code: "frozen" }),
    );
    controller.abort();
    await expect(serving).rejects.toMatchObject({ code: "canceled" });
    expect(closeWrite).toHaveBeenCalledOnce();
    expect(reset).not.toHaveBeenCalled();
  });

  test("enforces bounded and duplicate registrations", () => {
    expect(() => new StreamHandlers({ maxConcurrentStreams: 129 })).toThrowError(
      expect.objectContaining<Partial<HandlerRegistrationError>>({ code: "invalid_handler" }),
    );
    const handlers = new StreamHandlers();
    handlers.handleStream("events", async () => undefined);
    expect(() => handlers.handleStream("events", async () => undefined)).toThrowError(
      expect.objectContaining<Partial<HandlerRegistrationError>>({ code: "already_registered" }),
    );
    expect(() => handlers.handleStream("flowersec.rpc.v2", async () => undefined)).toThrowError(
      expect.objectContaining<Partial<HandlerRegistrationError>>({ code: "invalid_handler" }),
    );
  });

  test("applies the shared OPEN kind contract", () => {
    for (const vector of vectors.stream_kinds) {
      const handlers = new StreamHandlers();
      const kind = vector.unit.repeat(vector.repeat) + vector.suffix;
      const registration = (): void => handlers.handleStream(kind, async () => undefined);
      if (vector.valid) expect(registration, vector.id).not.toThrow();
      else expect(registration, vector.id).toThrowError(
        expect.objectContaining<Partial<HandlerRegistrationError>>({ code: "invalid_handler" }),
      );
    }
  });

  test("resets unknown, failed, and failed-close streams while continuing dispatch", async () => {
    const success = testIncoming("success");
    const failure = testIncoming("failure");
    const closeFailure = testIncoming(
      "close-failure",
      async () => await Promise.reject(new Error("close failed")),
    );
    const unknown = testIncoming("unknown");
    const { session, close } = scriptedSession([
      success.incoming,
      failure.incoming,
      closeFailure.incoming,
      unknown.incoming,
    ]);
    const handlers = new StreamHandlers({ maxConcurrentStreams: 4 });
    handlers.handleStream("success", async () => undefined);
    handlers.handleStream("failure", async () => await Promise.reject(new Error("failed")));
    handlers.handleStream("close-failure", async () => undefined);

    await expect(handlers.serve(session)).rejects.toMatchObject({ code: "closed" });
    expect(success.closeWrite).toHaveBeenCalledOnce();
    expect(success.reset).not.toHaveBeenCalled();
    expect(failure.reset).toHaveBeenCalledOnce();
    expect(closeFailure.closeWrite).toHaveBeenCalledOnce();
    expect(closeFailure.reset).toHaveBeenCalledOnce();
    expect(unknown.reset).toHaveBeenCalledOnce();
    expect(close).toHaveBeenCalledOnce();
  });

  test("resets excess streams and waits for active handlers after aborting them", async () => {
    const active = testIncoming("held");
    const excess = testIncoming("held");
    const { session, close } = scriptedSession([active.incoming, excess.incoming]);
    const handlers = new StreamHandlers({ maxConcurrentStreams: 1 });
    let canceled = false;
    handlers.handleStream("held", async (_incoming, options) => {
      await new Promise<void>((resolve) => {
        if (options.signal?.aborted === true) resolve();
        else options.signal?.addEventListener("abort", () => resolve(), { once: true });
      });
      canceled = true;
    });

    await expect(handlers.serve(session)).rejects.toMatchObject({ code: "closed" });
    expect(canceled).toBe(true);
    expect(active.closeWrite).toHaveBeenCalledOnce();
    expect(excess.reset).toHaveBeenCalledOnce();
    expect(close).toHaveBeenCalledOnce();
  });

  test("aborts active handlers before waiting when the Session closes", async () => {
    const close = vi.fn(async () => undefined);
    const reset = vi.fn(async () => undefined);
    let accepted = false;
    const session: Session = {
      rpc: {} as Session["rpc"],
      async openStream() { throw new SessionError("operation_failed"); },
      async acceptStream() {
        if (accepted) throw new SessionError("closed");
        accepted = true;
        return {
          kind: "blocking",
          metadata: createStreamMetadata({}),
          stream: {
            kind: "blocking",
            terminalError: undefined,
            async read() { return null; },
            async write(data) { return data.byteLength; },
            async closeWrite() {},
            reset,
            async close() {},
          },
        };
      },
      async rekey() {},
      async probeLiveness() { return 0; },
      async waitTermination() { return { error: new SessionError("closed") }; },
      close,
    };
    const handlers = new StreamHandlers();
    handlers.handleStream("blocking", async (_incoming, options) => {
      await new Promise<void>((resolve) => {
        if (options.signal?.aborted === true) resolve();
        else options.signal?.addEventListener("abort", () => resolve(), { once: true });
      });
    });

    await expect(handlers.serve(session)).rejects.toMatchObject({ code: "closed" });
    expect(close).toHaveBeenCalledOnce();
    expect(reset).not.toHaveBeenCalled();
  });
});
