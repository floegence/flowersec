import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, test } from "vitest";

import { SessionHandlers, type SessionHandlersError } from "./acceptor.js";

type StreamKindVectors = Readonly<{
  stream_kinds: readonly Readonly<{
    id: string;
    unit: string;
    repeat: number;
    suffix: string;
    valid: boolean;
  }>[];
  duplicate_kind: string;
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
          expect.objectContaining<Partial<SessionHandlersError>>({ code: "invalid_handler" }),
        );
      }
    }

    const handlers = new SessionHandlers();
    handlers.handleStream(vectors.duplicate_kind, async () => undefined);
    expect(() => handlers.handleStream(vectors.duplicate_kind, async () => undefined)).toThrowError(
      expect.objectContaining<Partial<SessionHandlersError>>({ code: "already_registered" }),
    );
  });
});
