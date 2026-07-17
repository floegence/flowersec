import { describe, expect, it, vi } from "vitest";

import { createMessagePortBackedStream } from "./portStream.js";
import {
  PROXY_WINDOW_STREAM_CHUNK_MSG_TYPE,
  PROXY_WINDOW_STREAM_CLOSE_MSG_TYPE,
  PROXY_WINDOW_STREAM_RESET_MSG_TYPE,
  PROXY_WINDOW_STREAM_WRITE_ACK_MSG_TYPE,
} from "./windowBridgeProtocol.js";

async function waitFor(condition: () => boolean): Promise<void> {
  for (let index = 0; index < 50; index++) {
    if (condition()) return;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  throw new Error("timed out waiting for MessagePort traffic");
}

describe("createMessagePortBackedStream", () => {
  it("acknowledges an inbound chunk only when read consumes it", async () => {
    const channel = new MessageChannel();
    const messages: unknown[] = [];
    channel.port2.onmessage = (event) => messages.push(event.data);
    channel.port2.start();
    const stream = createMessagePortBackedStream(channel.port1);

    channel.port2.postMessage({
      type: PROXY_WINDOW_STREAM_CHUNK_MSG_TYPE,
      data: new Uint8Array([1, 2, 3]).buffer,
      writeId: 7,
    });
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(messages).toEqual([]);

    await expect(stream.read()).resolves.toEqual(new Uint8Array([1, 2, 3]));
    await waitFor(() => messages.length === 1);
    expect(messages).toEqual([{ type: PROXY_WINDOW_STREAM_WRITE_ACK_MSG_TYPE, writeId: 7 }]);

    channel.port2.close();
  });

  it("resets when more than one inbound chunk is unacknowledged", async () => {
    const channel = new MessageChannel();
    const messages: unknown[] = [];
    channel.port2.onmessage = (event) => messages.push(event.data);
    channel.port2.start();
    const stream = createMessagePortBackedStream(channel.port1);

    channel.port2.postMessage({
      type: PROXY_WINDOW_STREAM_CHUNK_MSG_TYPE,
      data: new Uint8Array([1]).buffer,
      writeId: 1,
    });
    channel.port2.postMessage({
      type: PROXY_WINDOW_STREAM_CHUNK_MSG_TYPE,
      data: new Uint8Array([2]).buffer,
      writeId: 2,
    });

    await waitFor(() => messages.some(
      (message) => (message as { type?: string }).type === PROXY_WINDOW_STREAM_RESET_MSG_TYPE,
    ));
    await expect(stream.read()).rejects.toThrow(/more than one unacknowledged chunk/);
    channel.port2.close();
  });

  it("allows only one outbound chunk to await acknowledgement", async () => {
    const channel = new MessageChannel();
    const chunks: Array<{ data: ArrayBuffer; writeId: number }> = [];
    channel.port2.onmessage = (event) => {
      const message = event.data as { type?: string; data?: ArrayBuffer; writeId?: number };
      if (message.type === PROXY_WINDOW_STREAM_CHUNK_MSG_TYPE
        && message.data instanceof ArrayBuffer
        && message.writeId != null) {
        chunks.push({ data: message.data, writeId: message.writeId });
      }
    };
    channel.port2.start();
    const stream = createMessagePortBackedStream(channel.port1);

    const first = stream.write(new Uint8Array([1]));
    const second = stream.write(new Uint8Array([2]));
    await waitFor(() => chunks.length === 1);
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(chunks).toHaveLength(1);

    channel.port2.postMessage({
      type: PROXY_WINDOW_STREAM_WRITE_ACK_MSG_TYPE,
      writeId: chunks[0]!.writeId,
    });
    await first;
    await waitFor(() => chunks.length === 2);
    channel.port2.postMessage({
      type: PROXY_WINDOW_STREAM_WRITE_ACK_MSG_TYPE,
      writeId: chunks[1]!.writeId,
    });
    await second;
    expect(chunks.map((chunk) => new Uint8Array(chunk.data)[0])).toEqual([1, 2]);

    channel.port2.close();
  });

  it("bounds writes waiting behind the acknowledged chunk", async () => {
    const channel = new MessageChannel();
    const messages: Array<{ type?: string; writeId?: number }> = [];
    channel.port2.onmessage = (event) => messages.push(event.data);
    channel.port2.start();
    const stream = createMessagePortBackedStream(channel.port1, { maxBufferedBytes: 1 });

    const first = stream.write(new Uint8Array([1]));
    await waitFor(() => messages.some((message) => message.type === PROXY_WINDOW_STREAM_CHUNK_MSG_TYPE));
    await expect(stream.write(new Uint8Array([2]))).rejects.toThrow("outbound buffer exceeded");

    const chunk = messages.find((message) => message.type === PROXY_WINDOW_STREAM_CHUNK_MSG_TYPE)!;
    channel.port2.postMessage({
      type: PROXY_WINDOW_STREAM_WRITE_ACK_MSG_TYPE,
      writeId: chunk.writeId,
    });
    await first;
    channel.port2.close();
  });

  it("waits for an accepted write before closing", async () => {
    const channel = new MessageChannel();
    const messages: Array<{ type?: string; writeId?: number }> = [];
    channel.port2.onmessage = (event) => messages.push(event.data);
    channel.port2.start();
    const stream = createMessagePortBackedStream(channel.port1);

    const write = stream.write(new Uint8Array([1]));
    const close = stream.close();
    await waitFor(() => messages.some((message) => message.type === PROXY_WINDOW_STREAM_CHUNK_MSG_TYPE));
    expect(messages.some((message) => message.type === PROXY_WINDOW_STREAM_CLOSE_MSG_TYPE)).toBe(false);
    const chunk = messages.find((message) => message.type === PROXY_WINDOW_STREAM_CHUNK_MSG_TYPE)!;
    channel.port2.postMessage({
      type: PROXY_WINDOW_STREAM_WRITE_ACK_MSG_TYPE,
      writeId: chunk.writeId,
    });

    await write;
    await close;
    await waitFor(() => messages.some((message) => message.type === PROXY_WINDOW_STREAM_CLOSE_MSG_TYPE));
    channel.port2.close();
  });

  it("rejects a pending write when the peer resets", async () => {
    const channel = new MessageChannel();
    const messages: Array<{ type?: string }> = [];
    channel.port2.onmessage = (event) => messages.push(event.data);
    channel.port2.start();
    const stream = createMessagePortBackedStream(channel.port1);

    const write = stream.write(new Uint8Array([1]));
    await waitFor(() => messages.some((message) => message.type === PROXY_WINDOW_STREAM_CHUNK_MSG_TYPE));
    channel.port2.postMessage({
      type: PROXY_WINDOW_STREAM_RESET_MSG_TYPE,
      message: "peer reset",
    });

    await expect(write).rejects.toThrow("peer reset");
    await expect(stream.read()).rejects.toThrow("peer reset");
    channel.port2.close();
  });

  it("notifies terminal lifecycle once when a pending write is reset", async () => {
    const channel = new MessageChannel();
    const messages: Array<{ type?: string }> = [];
    channel.port2.onmessage = (event) => messages.push(event.data);
    channel.port2.start();
    const onTerminal = vi.fn();
    const stream = createMessagePortBackedStream(channel.port1, { onTerminal });

    const write = stream.write(new Uint8Array([1]));
    await waitFor(() => messages.some((message) => message.type === PROXY_WINDOW_STREAM_CHUNK_MSG_TYPE));
    void stream.reset(new Error("disposed"));
    void stream.reset(new Error("duplicate"));

    await expect(write).rejects.toThrow("disposed");
    expect(onTerminal).toHaveBeenCalledTimes(1);
    channel.port2.close();
  });
});
