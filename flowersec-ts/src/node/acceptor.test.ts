import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, test } from "vitest";

import {
  createRPCRouter,
  freezeRPCHandlers,
  RPCHandlers,
  SessionHandlers,
  type HandlerRegistrationError,
} from "./acceptor.js";

type StreamKindVectors = Readonly<{
  stream_kinds: readonly Readonly<{
    id: string;
    unit: string;
    repeat: number;
    suffix: string;
    valid: boolean;
  }>[];
  duplicate_kind: string;
  rpc_type_ids: readonly Readonly<{ id: string; value: number; valid: boolean }>[];
  duplicate_type_id: number;
}>;

const repositoryRoot = fileURLToPath(new URL("../../..", import.meta.url));
const vectors = JSON.parse(readFileSync(
  path.join(repositoryRoot, "testdata/transport_v2/session_handler_vectors.json"),
  "utf8",
)) as StreamKindVectors;

describe("SessionHandlers", () => {
  test("enforces the shared UTF-8 stream-kind registration contract", () => {
    for (const vector of vectors.stream_kinds) {
      const handlers = new SessionHandlers();
      const kind = vector.unit.repeat(vector.repeat) + vector.suffix;
      if (vector.valid) {
        expect(() => handlers.handleStream(kind, async () => undefined), vector.id).not.toThrow();
      } else {
        expect(() => handlers.handleStream(kind, async () => undefined), vector.id).toThrowError(
          expect.objectContaining<Partial<HandlerRegistrationError>>({ code: "invalid_handler" }),
        );
      }
    }

    const handlers = new SessionHandlers();
    handlers.handleStream(vectors.duplicate_kind, async () => undefined);
    expect(() => handlers.handleStream(vectors.duplicate_kind, async () => undefined)).toThrowError(
      expect.objectContaining<Partial<HandlerRegistrationError>>({ code: "already_registered" }),
    );
  });

  test("keeps notification registrations isolated from request handlers and freezes them", () => {
    const handlers = new SessionHandlers();
    handlers.handleNotification(41, async () => undefined);
    expect(() => handlers.handleNotification(41, async () => undefined)).toThrowError(
      expect.objectContaining<Partial<HandlerRegistrationError>>({ code: "already_registered" }),
    );
    expect(() => handlers.handleRPC(41, async () => ({ payload: null }))).toThrowError(
      expect.objectContaining<Partial<HandlerRegistrationError>>({ code: "already_registered" }),
    );
  });
});

describe("RPCHandlers", () => {
  test("enforces the nonzero uint32 shared namespace without replacing the first handler", async () => {
    const handlers = new RPCHandlers();
    const original = async () => ({ payload: "original" as const });
    for (const vector of vectors.rpc_type_ids) {
      const vectorHandlers = new RPCHandlers();
      const registration = () => vectorHandlers.handleRPC(vector.value, original);
      if (vector.valid) expect(registration, vector.id).not.toThrow();
      else expect(registration, vector.id).toThrowError(
        expect.objectContaining<Partial<HandlerRegistrationError>>({ code: "invalid_handler" }),
      );
    }
    expect(() => handlers.handleRPC(1, undefined as never)).toThrowError(
      expect.objectContaining<Partial<HandlerRegistrationError>>({ code: "invalid_handler" }),
    );
    expect(() => handlers.handleRPC(0x1_0000_0000, original)).toThrowError(
      expect.objectContaining<Partial<HandlerRegistrationError>>({ code: "invalid_handler" }),
    );

    handlers.handleRPC(vectors.duplicate_type_id, original);
    handlers.handleNotification(0xffff_ffff, () => undefined);
    expect(() => handlers.handleRPC(vectors.duplicate_type_id, async () => ({ payload: "replacement" }))).toThrowError(
      expect.objectContaining<Partial<HandlerRegistrationError>>({ code: "already_registered" }),
    );
    expect(() => handlers.handleNotification(vectors.duplicate_type_id, () => undefined)).toThrowError(
      expect.objectContaining<Partial<HandlerRegistrationError>>({ code: "already_registered" }),
    );

    const snapshot = freezeRPCHandlers(handlers);
    expect(freezeRPCHandlers(handlers)).toBe(snapshot);
    const firstRouter = createRPCRouter(snapshot);
    const secondRouter = createRPCRouter(snapshot);
    expect(secondRouter).not.toBe(firstRouter);
    await expect(firstRouter.handler(vectors.duplicate_type_id)?.(null)).resolves.toMatchObject({ payload: "original" });
    expect(() => handlers.handleNotification(2, () => undefined)).toThrowError(
      expect.objectContaining<Partial<HandlerRegistrationError>>({ code: "frozen" }),
    );
  });

  test("keeps formatting and registration failures opaque", () => {
    const secret = "handler-secret-must-not-leak";
    const handlers = new RPCHandlers();
    handlers.handleRPC(7, async () => ({ payload: secret }));
    expect(JSON.stringify(handlers)).toBe("{}");
    expect(String(handlers)).not.toContain(secret);
    try {
      handlers.handleRPC(7, async () => ({ payload: null }));
    } catch (error) {
      expect(String(error)).not.toContain(secret);
    }
  });
});
