import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import { HANDSHAKE_TYPE_INIT, PROTOCOL_VERSION } from "../e2ee/constants.js";
import { encodeHandshakeFrame } from "../e2ee/framing.js";
import type { WebSocketLike } from "../ws-client/binaryTransport.js";

const mocks = vi.hoisted(() => ({
  serverHandshake: vi.fn(),
}));

vi.mock("../e2ee/handshake.js", async (importOriginal) => {
  const actual = await importOriginal();
  return {
    ...(actual as object),
    serverHandshake: mocks.serverHandshake,
  };
});

import { acceptDirect, acceptDirectResolved } from "./index.js";

type WebSocketEvent = "open" | "message" | "error" | "close";

class FakeWebSocket implements WebSocketLike {
  binaryType = "";
  readyState = 1;
  bufferedAmount = 0;
  readonly send = vi.fn();
  readonly close = vi.fn(() => { this.readyState = 3; });
  private readonly listeners = new Map<WebSocketEvent, Set<(event: unknown) => void>>();

  addEventListener(type: WebSocketEvent, listener: (event: unknown) => void): void {
    let listeners = this.listeners.get(type);
    if (listeners == null) {
      listeners = new Set();
      this.listeners.set(type, listeners);
    }
    listeners.add(listener);
  }

  removeEventListener(type: WebSocketEvent, listener: (event: unknown) => void): void {
    this.listeners.get(type)?.delete(listener);
  }

  emit(type: WebSocketEvent, event: unknown): void {
    for (const listener of this.listeners.get(type) ?? []) listener(event);
  }
}

const secure = {
  read: vi.fn(() => new Promise<Uint8Array>(() => {})),
  write: vi.fn(),
  close: vi.fn(),
  rekeyNow: vi.fn(),
};

describe("acceptDirectResolved handshake deadline", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(0));
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  test("times out while waiting for the first frame and closes the transport", async () => {
    const websocket = new FakeWebSocket();
    const pending = acceptDirectResolved(websocket, vi.fn(), {
      handshakeTimeoutMs: 100,
    });
    const rejection = expect(pending).rejects.toMatchObject({
      path: "direct",
      stage: "handshake",
      code: "timeout",
    });

    await vi.advanceTimersByTimeAsync(100);

    await rejection;
    expect(websocket.close).toHaveBeenCalledTimes(1);
  });

	test("reports cancellation while resolving credentials and closes the transport", async () => {
    const websocket = new FakeWebSocket();
    const controller = new AbortController();
    const resolver = vi.fn(() => new Promise<never>(() => {}));
    const pending = acceptDirectResolved(websocket, resolver, {
      signal: controller.signal,
      handshakeTimeoutMs: 1_000,
    });
    await emitInit(websocket);
    expect(resolver).toHaveBeenCalledTimes(1);

    controller.abort();

    await expect(pending).rejects.toMatchObject({
      path: "direct",
      stage: "handshake",
      code: "canceled",
    });
		expect(websocket.close).toHaveBeenCalledTimes(1);
	});

	test.each([
		["missing", "   ", "missing_channel_id"],
		["surrounding whitespace", " channel-id ", "invalid_input"],
		["too long", "x".repeat(257), "invalid_input"],
	])("rejects a %s channel ID before calling the resolver", async (_name, channelId, code) => {
		const websocket = new FakeWebSocket();
		const resolver = vi.fn();
		const pending = acceptDirectResolved(websocket, resolver, { handshakeTimeoutMs: 1_000 });
		const rejection = expect(pending).rejects.toMatchObject({
			path: "direct",
			stage: "validate",
			code,
		});
		await emitInit(websocket, channelId);

		await rejection;
		expect(resolver).not.toHaveBeenCalled();
		expect(websocket.close).toHaveBeenCalledTimes(1);
	});

  test("shares one timeout budget across resolver and server handshake", async () => {
    const websocket = new FakeWebSocket();
    const resolver = vi.fn(() => new Promise<ReturnType<typeof credential>>((resolve) => {
      setTimeout(() => resolve(credential()), 60);
    }));
    mocks.serverHandshake.mockImplementationOnce(() => new Promise(() => {}));
    const pending = acceptDirectResolved(websocket, resolver, {
      handshakeTimeoutMs: 100,
    });
    const rejection = expect(pending).rejects.toMatchObject({
      path: "direct",
      stage: "handshake",
      code: "timeout",
    });
    await emitInit(websocket);

    await vi.advanceTimersByTimeAsync(60);

    expect(mocks.serverHandshake).toHaveBeenCalledTimes(1);
    expect(mocks.serverHandshake.mock.calls[0]?.[2]).toMatchObject({ timeoutMs: 40 });

    await vi.advanceTimersByTimeAsync(40);

    await rejection;
    expect(websocket.close).toHaveBeenCalledTimes(1);
  });

  test("includes authenticated credential commit in the timeout budget", async () => {
    const websocket = new FakeWebSocket();
    const commitAuthenticated = vi.fn(() => new Promise<void>(() => {}));
    mocks.serverHandshake.mockResolvedValueOnce(secure);
    const pending = acceptDirectResolved(websocket, () => ({
      ...credential(),
      commitAuthenticated,
    }), {
      handshakeTimeoutMs: 100,
    });
    const rejection = expect(pending).rejects.toMatchObject({
      path: "direct",
      stage: "handshake",
      code: "timeout",
    });
    await emitInit(websocket);
    await vi.advanceTimersByTimeAsync(0);
    expect(commitAuthenticated).toHaveBeenCalledTimes(1);

    await vi.advanceTimersByTimeAsync(100);

    await rejection;
    expect(secure.close).toHaveBeenCalledTimes(1);
    expect(websocket.close).toHaveBeenCalledTimes(1);
  });

  test("applies the timeout budget to acceptDirect credential commit", async () => {
    const websocket = new FakeWebSocket();
    const commitAuthenticated = vi.fn(() => new Promise<void>(() => {}));
    mocks.serverHandshake.mockResolvedValueOnce(secure);
    const pending = acceptDirect(websocket, {
      channelId: "endpoint-direct-deadline",
      suite: 1,
      ...credential(),
      commitAuthenticated,
    }, {
      handshakeTimeoutMs: 100,
    });
    const rejection = expect(pending).rejects.toMatchObject({
      path: "direct",
      stage: "handshake",
      code: "timeout",
    });
    await vi.advanceTimersByTimeAsync(0);
    expect(commitAuthenticated).toHaveBeenCalledTimes(1);

    await vi.advanceTimersByTimeAsync(100);

    await rejection;
    expect(secure.close).toHaveBeenCalledTimes(1);
    expect(websocket.close).toHaveBeenCalledTimes(1);
  });

  test("rejects a synchronous credential commit that overruns the deadline", async () => {
    const websocket = new FakeWebSocket();
    const commitAuthenticated = vi.fn(() => {
      vi.setSystemTime(new Date(101));
    });
    mocks.serverHandshake.mockResolvedValueOnce(secure);

    await expect(acceptDirect(websocket, {
      channelId: "endpoint-direct-overrun",
      suite: 1,
      ...credential(),
      commitAuthenticated,
    }, {
      handshakeTimeoutMs: 100,
    })).rejects.toMatchObject({
      path: "direct",
      stage: "handshake",
      code: "timeout",
    });

    expect(commitAuthenticated).toHaveBeenCalledTimes(1);
    expect(secure.close).toHaveBeenCalledTimes(1);
    expect(websocket.close).toHaveBeenCalledTimes(1);
  });

  test("reports cancellation while committing authenticated credentials", async () => {
    const websocket = new FakeWebSocket();
    const controller = new AbortController();
    const commitAuthenticated = vi.fn(() => new Promise<void>(() => {}));
    mocks.serverHandshake.mockResolvedValueOnce(secure);
    const pending = acceptDirect(websocket, {
      channelId: "endpoint-direct-canceled",
      suite: 1,
      ...credential(),
      commitAuthenticated,
    }, {
      signal: controller.signal,
      handshakeTimeoutMs: 100,
    });
    await vi.advanceTimersByTimeAsync(0);
    expect(commitAuthenticated).toHaveBeenCalledTimes(1);

    controller.abort();

    await expect(pending).rejects.toMatchObject({
      path: "direct",
      stage: "handshake",
      code: "canceled",
    });
    expect(secure.close).toHaveBeenCalledTimes(1);
    expect(websocket.close).toHaveBeenCalledTimes(1);
  });
});

async function emitInit(websocket: FakeWebSocket, channelId = "endpoint-resolved-deadline"): Promise<void> {
	await vi.advanceTimersByTimeAsync(0);
	websocket.emit("message", { data: handshakeInitFrame(channelId) });
	await vi.advanceTimersByTimeAsync(0);
}

function handshakeInitFrame(channelId: string): Uint8Array {
	return encodeHandshakeFrame(HANDSHAKE_TYPE_INIT, new TextEncoder().encode(JSON.stringify({
		version: PROTOCOL_VERSION,
		role: 1,
		channel_id: channelId,
    suite: 1,
    client_features: 0,
  })));
}

function credential() {
  return {
    psk: new Uint8Array(32).fill(7),
    initExpireAtUnixS: 60,
  } as const;
}
