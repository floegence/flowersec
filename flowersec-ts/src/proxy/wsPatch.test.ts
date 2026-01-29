import { describe, expect, it } from "vitest";

import { installWebSocketPatch } from "./wsPatch.js";

class FakeYamuxStream {
  readonly writes: Uint8Array[] = [];

  async write(b: Uint8Array): Promise<void> {
    this.writes.push(b);
  }

  async read(): Promise<Uint8Array | null> {
    // Keep the read loop pending long enough so tests can trigger send().
    await new Promise((r) => setTimeout(r, 10));
    return null;
  }

  async close(): Promise<void> {}

  reset(_err: Error): void {}
}

describe("installWebSocketPatch", () => {
  it("proxies same host/port ws URLs by default (ws<->http scheme mapping)", async () => {
    const oldWS = (globalThis as any).WebSocket;
    const oldLoc = (globalThis as any).location;

    class OriginalWebSocket {
      readonly kind = "original";
      constructor(public readonly url: string, public readonly protocols?: string | string[]) {}
    }

    const calls: string[] = [];
    const runtime = {
      cookieJar: null as any,
      limits: { maxJsonFrameBytes: 1, maxChunkBytes: 1, maxBodyBytes: 1, maxWsFrameBytes: 1024 },
      dispose: () => {},
      openWebSocketStream: async (path: string) => {
        calls.push(path);
        return { stream: new FakeYamuxStream() as any, protocol: "" };
      }
    };

    (globalThis as any).WebSocket = OriginalWebSocket;
    (globalThis as any).location = {
      href: "http://127.0.0.1:5173/examples/ts/proxy-sandbox/app/",
      protocol: "http:",
      hostname: "127.0.0.1",
      port: "5173",
      origin: "http://127.0.0.1:5173"
    };

    try {
      const { uninstall } = installWebSocketPatch({ runtime });

      const a = new (globalThis as any).WebSocket("ws://example.com/ws");
      expect(a).toBeInstanceOf(OriginalWebSocket);
      expect((a as any).kind).toBe("original");
      expect(calls.length).toBe(0);

      const b = new (globalThis as any).WebSocket("ws://127.0.0.1:5173/ws");
      expect(b).not.toBeInstanceOf(OriginalWebSocket);

      const c = new (globalThis as any).WebSocket("/ws");
      expect(c).not.toBeInstanceOf(OriginalWebSocket);

      // Allow init() to run.
      await new Promise((r) => setTimeout(r, 0));
      expect(calls).toEqual(["/ws", "/ws"]);

      uninstall();
      const d = new (globalThis as any).WebSocket("ws://127.0.0.1:5173/ws");
      expect(d).toBeInstanceOf(OriginalWebSocket);
    } finally {
      (globalThis as any).WebSocket = oldWS;
      (globalThis as any).location = oldLoc;
    }
  });

  it("enforces maxWsFrameBytes (0 uses runtime limit; negative rejects)", async () => {
    const oldWS = (globalThis as any).WebSocket;
    const oldLoc = (globalThis as any).location;

    class OriginalWebSocket {
      constructor(_url: string, _protocols?: string | string[]) {}
    }

    const runtime = {
      cookieJar: null as any,
      limits: { maxJsonFrameBytes: 1, maxChunkBytes: 1, maxBodyBytes: 1, maxWsFrameBytes: 8 },
      dispose: () => {},
      openWebSocketStream: async (_path: string, _opts?: any) => ({ stream: new FakeYamuxStream() as any, protocol: "" })
    };

    (globalThis as any).WebSocket = OriginalWebSocket;
    (globalThis as any).location = {
      href: "http://127.0.0.1:5173/",
      protocol: "http:",
      hostname: "127.0.0.1",
      port: "5173",
      origin: "http://127.0.0.1:5173"
    };

    try {
      expect(() => installWebSocketPatch({ runtime, maxWsFrameBytes: -1 })).toThrow(/maxWsFrameBytes/);

      installWebSocketPatch({ runtime, maxWsFrameBytes: 0 });
      const ws = new (globalThis as any).WebSocket("/ws");

      let closedReason = "";
      (ws as any).onopen = () => {
        // 9 bytes > runtime max (8).
        (ws as any).send("123456789");
      };
      (ws as any).onclose = (ev: any) => {
        closedReason = String(ev?.reason ?? "");
      };

      for (let i = 0; i < 100 && closedReason === ""; i++) {
        await new Promise((r) => setTimeout(r, 1));
      }
      expect(closedReason).toContain("ws payload too large");
    } finally {
      (globalThis as any).WebSocket = oldWS;
      (globalThis as any).location = oldLoc;
    }
  });
});

