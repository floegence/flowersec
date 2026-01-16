import { describe, expect, test } from "vitest";
import { YamuxSession } from "./session.js";
import { encodeHeader, decodeHeader } from "./header.js";
import { FLAG_ACK, FLAG_SYN, TYPE_DATA, TYPE_GO_AWAY, TYPE_PING, TYPE_WINDOW_UPDATE } from "./constants.js";

class QueueConn {
  private readonly reads: Uint8Array[] = [];
  private readonly waiters: Array<{ resolve: (b: Uint8Array) => void; reject: (e: unknown) => void }> = [];
  readonly writes: Uint8Array[] = [];
  closed = false;

  async read(): Promise<Uint8Array> {
    if (this.closed) throw new Error("closed");
    const next = this.reads.shift();
    if (next != null) return next;
    return await new Promise<Uint8Array>((resolve, reject) => {
      if (this.closed) {
        reject(new Error("closed"));
        return;
      }
      this.waiters.push({ resolve, reject });
    });
  }

  async write(chunk: Uint8Array): Promise<void> {
    this.writes.push(chunk);
  }

  close(): void {
    this.closed = true;
    const ws = this.waiters.splice(0, this.waiters.length);
    for (const w of ws) w.reject(new Error("closed"));
  }

  enqueue(chunk: Uint8Array): void {
    const w = this.waiters.shift();
    if (w != null) {
      w.resolve(chunk);
      return;
    }
    this.reads.push(chunk);
  }
}

async function tick(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 0));
}

describe("YamuxSession", () => {
  test("responds to SYN ping with ACK", async () => {
    const conn = new QueueConn();
    const session = new YamuxSession(conn, { client: true });

    const ping = encodeHeader({ type: TYPE_PING, flags: FLAG_SYN, streamId: 0, length: 7 });
    conn.enqueue(ping);

    await tick();
    expect(conn.writes.length).toBe(1);
    const resp = decodeHeader(conn.writes[0]!, 0);
    expect(resp.type).toBe(TYPE_PING);
    expect(resp.flags & FLAG_ACK).toBe(FLAG_ACK);
    expect(resp.length).toBe(7);

    session.close();
  });

  test("streamId 0 data closes session", async () => {
    const conn = new QueueConn();
    const session = new YamuxSession(conn, { client: true });

    const data = encodeHeader({ type: TYPE_DATA, flags: 0, streamId: 0, length: 0 });
    conn.enqueue(data);

    await tick();
    expect(conn.closed).toBe(true);
    session.close();
  });

  test("maxFrameBytes closes session", async () => {
    const conn = new QueueConn();
    const session = new YamuxSession(conn, { client: true, maxFrameBytes: 1 });

    const hdr = encodeHeader({ type: TYPE_DATA, flags: 0, streamId: 1, length: 2 });
    conn.enqueue(hdr);
    conn.enqueue(new Uint8Array([1, 2]));

    await tick();
    expect(conn.closed).toBe(true);
    session.close();
  });

  test("window update with SYN creates stream", async () => {
    const conn = new QueueConn();
    let incoming = 0;
    const session = new YamuxSession(conn, {
      client: true,
      onIncomingStream: () => {
        incoming += 1;
      }
    });

    const hdr = encodeHeader({ type: TYPE_WINDOW_UPDATE, flags: FLAG_SYN, streamId: 5, length: 128 });
    conn.enqueue(hdr);

    await tick();
    expect(incoming).toBe(1);
    expect(session.getStream(5)).toBeDefined();

    session.close();
  });

  test("go away closes session", async () => {
    const conn = new QueueConn();
    const session = new YamuxSession(conn, { client: true });

    const hdr = encodeHeader({ type: TYPE_GO_AWAY, flags: 0, streamId: 0, length: 0 });
    conn.enqueue(hdr);

    await tick();
    expect(conn.closed).toBe(true);
    session.close();
  });

  test("close wakes send window waiters", async () => {
    const conn = new QueueConn();
    const session = new YamuxSession(conn, { client: true });

    const wait = session.waitForSendWindow(1);
    session.close();

    await expect(wait).rejects.toThrow(/session closed/);
  });
});
