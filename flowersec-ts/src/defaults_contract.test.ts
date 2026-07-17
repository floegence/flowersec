import { readFile } from "node:fs/promises";
import { describe, expect, test } from "vitest";
import { SDK_DEFAULTS } from "./defaults.js";

describe("SDK defaults contract", () => {
  test("matches the shared stability manifest", async () => {
    const path = new URL("../../stability/sdk_defaults.json", import.meta.url);
    const manifest = JSON.parse(await readFile(path, "utf8")) as Record<string, Record<string, number>>;

    expect(SDK_DEFAULTS.transport).toEqual({
      connectTimeoutMs: manifest.transport!.connect_timeout_ms,
      handshakeTimeoutMs: manifest.transport!.handshake_timeout_ms,
      handshakeClockSkewMs: manifest.transport!.handshake_clock_skew_ms,
    });
    expect(SDK_DEFAULTS.e2ee).toEqual({
      maxHandshakePayloadBytes: manifest.e2ee!.max_handshake_payload_bytes,
      maxRecordBytes: manifest.e2ee!.max_record_bytes,
      outboundRecordChunkBytes: manifest.e2ee!.outbound_record_chunk_bytes,
      maxInboundBufferedBytes: manifest.e2ee!.max_inbound_buffered_bytes,
      maxOutboundBufferedBytes: manifest.e2ee!.max_outbound_buffered_bytes,
    });
    expect(SDK_DEFAULTS.yamux).toEqual({
      maxActiveStreams: manifest.yamux!.max_active_streams,
      maxInboundStreams: manifest.yamux!.max_inbound_streams,
      maxFrameBytes: manifest.yamux!.max_frame_bytes,
      preferredOutboundFrameBytes: manifest.yamux!.preferred_outbound_frame_bytes,
      maxStreamWriteQueueBytes: manifest.yamux!.max_stream_write_queue_bytes,
      maxStreamReceiveBytes: manifest.yamux!.max_stream_receive_bytes,
      maxSessionReceiveBytes: manifest.yamux!.max_session_receive_bytes,
    });
    expect(SDK_DEFAULTS.rpc).toEqual({
      maxJsonFrameBytes: manifest.rpc!.max_json_frame_bytes,
      maxConcurrentRequests: manifest.rpc!.max_concurrent_requests,
      maxQueuedRequests: manifest.rpc!.max_queued_requests,
      maxQueuedNotifications: manifest.rpc!.max_queued_notifications,
    });
    expect(SDK_DEFAULTS.controlplane).toEqual({
      maxRequestBodyBytes: manifest.controlplane!.max_request_body_bytes,
      maxResponseBodyBytes: manifest.controlplane!.max_response_body_bytes,
    });
    expect(SDK_DEFAULTS.proxy).toEqual({
      maxJsonFrameBytes: manifest.proxy!.max_json_frame_bytes,
      maxChunkBytes: manifest.proxy!.max_chunk_bytes,
      maxBodyBytes: manifest.proxy!.max_body_bytes,
      maxWsFrameBytes: manifest.proxy!.max_ws_frame_bytes,
      defaultTimeoutMs: manifest.proxy!.default_timeout_ms,
      maxTimeoutMs: manifest.proxy!.max_timeout_ms,
    });
    expect(SDK_DEFAULTS.reconnect).toEqual({
      maxAttempts: manifest.reconnect!.max_attempts,
      initialDelayMs: manifest.reconnect!.initial_delay_ms,
      maxDelayMs: manifest.reconnect!.max_delay_ms,
      factor: manifest.reconnect!.factor,
      jitterRatio: manifest.reconnect!.jitter_ratio,
    });
  });
});
