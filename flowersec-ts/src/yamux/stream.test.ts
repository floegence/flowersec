import { describe, expect, test } from "vitest";
import { YamuxStream } from "./stream.js";
import { decodeHeader } from "./header.js";
import { DEFAULT_MAX_STREAM_WINDOW, FLAG_FIN, FLAG_SYN, TYPE_DATA, TYPE_WINDOW_UPDATE } from "./constants.js";

class FakeSession {
  readonly writes: Uint8Array[] = [];
  readonly rst: number[] = [];
  established: number[] = [];

  async writeRaw(chunk: Uint8Array): Promise<void> {
    this.writes.push(chunk);
  }

  notifySendWindow(_streamId: number): void {}

  async waitForSendWindow(_streamId: number): Promise<void> {
    return;
  }

  async sendRst(id: number): Promise<void> {
    this.rst.push(id);
  }

  onStreamEstablished(id: number): void {
    this.established.push(id);
  }
}

async function tick(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 0));
}

describe("YamuxStream", () => {
  test("open emits SYN window update", async () => {
    const session = new FakeSession();
    const stream = new YamuxStream(session as any, 1, "init");

    await stream.open();
    expect(session.writes.length).toBe(1);
    const hdr = decodeHeader(session.writes[0]!, 0);
    expect(hdr.type).toBe(TYPE_WINDOW_UPDATE);
    expect(hdr.flags & FLAG_SYN).toBe(FLAG_SYN);
  });

  test("write emits SYN data on first send", async () => {
    const session = new FakeSession();
    const stream = new YamuxStream(session as any, 1, "init");

    await stream.write(new Uint8Array([1, 2]));
    expect(session.writes.length).toBe(1);
    const hdr = decodeHeader(session.writes[0]!, 0);
    expect(hdr.type).toBe(TYPE_DATA);
    expect(hdr.flags & FLAG_SYN).toBe(FLAG_SYN);
  });

  test("close emits FIN and prevents further writes", async () => {
    const session = new FakeSession();
    const stream = new YamuxStream(session as any, 1, "init");

    await stream.close();
    expect(session.writes.length).toBe(1);
    const hdr = decodeHeader(session.writes[0]!, 0);
    expect(hdr.type).toBe(TYPE_WINDOW_UPDATE);
    expect(hdr.flags & FLAG_FIN).toBe(FLAG_FIN);

    await expect(stream.write(new Uint8Array([1]))).rejects.toThrow(/stream closed/);
  });

  test("recv window overflow resets stream", async () => {
    const session = new FakeSession();
    const stream = new YamuxStream(session as any, 1, "established");
    (stream as any).recvWindow = 1;

    stream.onData(new Uint8Array([1, 2]), 0);
    await tick();

    expect(session.rst).toEqual([1]);
    await expect(stream.read()).rejects.toThrow(/recv window exceeded|rst/);
  });

  test("FIN transitions to remote close and read returns null", async () => {
    const session = new FakeSession();
    const stream = new YamuxStream(session as any, 1, "established");

    stream.onData(new Uint8Array(), FLAG_FIN);
    await expect(stream.read()).resolves.toBeNull();
  });

  test("reset marks stream as closed", async () => {
    const session = new FakeSession();
    const stream = new YamuxStream(session as any, 1, "established");

    stream.reset(new Error("boom"));
    await expect(stream.read()).rejects.toThrow(/boom/);
    await expect(stream.write(new Uint8Array([1]))).rejects.toThrow(/stream reset/);
  });

  test("sendWindowUpdate throttles small deltas", async () => {
    const session = new FakeSession();
    const stream = new YamuxStream(session as any, 1, "established");
    (stream as any).recvWindow = DEFAULT_MAX_STREAM_WINDOW - 1;
    (stream as any).recvQueueBytes = 0;

    await (stream as any).sendWindowUpdate();
    expect(session.writes.length).toBe(0);
  });
});
