import { readFileSync } from "node:fs";

import { describe, expect, test, vi } from "vitest";

import { canonicalizeCandidatesV3, decodeArtifactV3JSON } from "./artifact.js";
import { readyWebSocketAdmissionV3, type WebSocketLikeV3 } from "./runtimeAdapters.js";

const fixture = JSON.parse(readFileSync(
  new URL("../../../testdata/transport_v3/artifact_vectors.json", import.meta.url),
  "utf8",
)) as Readonly<{ positive: readonly Readonly<{ artifact_json: string }>[] }>;
const artifact = decodeArtifactV3JSON(fixture.positive[0]!.artifact_json);
const candidate = canonicalizeCandidatesV3(artifact.path.kind, artifact.path.candidates).candidates[0]!;

describe("transport v3 WebSocket admission adapter", () => {
  test("closes an already-open socket when the negotiated protocol mismatches", async () => {
    const socket = fakeSocket(1, "wrong.v3");

    await expect(readyWebSocketAdmissionV3(
      candidate,
      artifact,
      socket,
      new AbortController().signal,
    )).rejects.toMatchObject({ code: "connection_failed" });
    expect(socket.close).toHaveBeenCalledOnce();
  });

  test("closes a socket when the open event negotiates the wrong protocol", async () => {
    const socket = fakeSocket(0, "wrong.v3");
    const opening = readyWebSocketAdmissionV3(
      candidate,
      artifact,
      socket,
      new AbortController().signal,
    );
    socket.emit("open");

    await expect(opening).rejects.toMatchObject({ code: "connection_failed" });
    expect(socket.close).toHaveBeenCalledOnce();
  });
});

function fakeSocket(readyState: number, protocol: string): WebSocketLikeV3 & Readonly<{
  emit(type: "open" | "error" | "close"): void;
}> {
  const listeners = new Map<string, Set<(event: unknown) => void>>();
  const socket = {
    binaryType: "",
    readyState,
    protocol,
    bufferedAmount: 0,
    send: vi.fn(),
    close: vi.fn(),
    addEventListener(type: string, listener: (event: unknown) => void) {
      const bucket = listeners.get(type) ?? new Set();
      bucket.add(listener);
      listeners.set(type, bucket);
    },
    removeEventListener(type: string, listener: (event: unknown) => void) {
      listeners.get(type)?.delete(listener);
    },
    emit(type: "open" | "error" | "close") {
      if (type === "open") socket.readyState = 1;
      for (const listener of listeners.get(type) ?? []) listener({});
    },
  } as unknown as WebSocketLikeV3 & Readonly<{
    emit(type: "open" | "error" | "close"): void;
  }>;
  return socket;
}
