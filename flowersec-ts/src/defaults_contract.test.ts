import { readFile } from "node:fs/promises";
import { describe, expect, test } from "vitest";
import { SDK_DEFAULTS } from "./defaults.js";

describe("SDK defaults contract", () => {
  test("matches the shared stability manifest", async () => {
    const path = new URL("../../stability/sdk_defaults.json", import.meta.url);
    const manifest = JSON.parse(await readFile(path, "utf8")) as Record<string, Record<string, number | null>>;

    expect(SDK_DEFAULTS.transport).toEqual({
      connectTimeoutMs: manifest.transport!.connect_timeout_ms,
      handshakeTimeoutMs: manifest.transport!.handshake_timeout_ms,
      handshakeClockSkewMs: manifest.transport!.handshake_clock_skew_ms,
    });
    expect(SDK_DEFAULTS.controlplane).toEqual({
      maxRequestBodyBytes: manifest.controlplane!.max_request_body_bytes,
      maxResponseBodyBytes: manifest.controlplane!.max_response_body_bytes,
    });
    expect(SDK_DEFAULTS.proxy).toEqual({
      maxMetadataBytes: manifest.proxy!.max_metadata_bytes,
      maxChunkBytes: manifest.proxy!.max_chunk_bytes,
      maxBodyBytes: manifest.proxy!.max_body_bytes,
      maxWsFrameBytes: manifest.proxy!.max_ws_frame_bytes,
      maxConcurrentStreams: manifest.proxy!.max_concurrent_streams,
      defaultTimeoutMs: manifest.proxy!.default_timeout_ms,
      maxTimeoutMs: manifest.proxy!.max_timeout_ms,
    });
    expect(SDK_DEFAULTS.connectionController).toEqual({
      initialDelayMs: manifest.connection_controller!.initial_delay_ms,
      maxDelayMs: manifest.connection_controller!.max_delay_ms,
      factor: manifest.connection_controller!.factor,
      jitterRatio: manifest.connection_controller!.jitter_ratio,
      defaultAttemptLimit: manifest.connection_controller!.default_attempt_limit,
    });
  });
});
