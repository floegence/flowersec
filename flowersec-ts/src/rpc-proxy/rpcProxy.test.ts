import { describe, expect, test, vi } from "vitest";

import { RpcProxy } from "./rpcProxy.js";

class FakeRpcClient {
  private readonly handlers = new Map<number, Set<(payload: unknown) => void>>();

  onNotify(typeId: number, handler: (payload: unknown) => void): () => void {
    const tid = typeId >>> 0;
    const set = this.handlers.get(tid) ?? new Set<(payload: unknown) => void>();
    set.add(handler);
    this.handlers.set(tid, set);
    return () => {
      set.delete(handler);
      if (set.size === 0) this.handlers.delete(tid);
    };
  }

  trigger(typeId: number, payload: unknown): void {
    const set = this.handlers.get(typeId >>> 0);
    if (set == null) return;
    for (const h of set) h(payload);
  }

  async call(): Promise<{ payload: unknown }> {
    return { payload: null };
  }
}

describe("RpcProxy", () => {
  test("unsubscribe stops notifications immediately", () => {
    const proxy = new RpcProxy();
    const client = new FakeRpcClient();
    proxy.attach(client as any);

    const handler = vi.fn();
    const unsub = proxy.onNotify(2, handler);
    client.trigger(2, { x: 1 });
    expect(handler).toHaveBeenCalledTimes(1);

    unsub();
    client.trigger(2, { x: 2 });
    expect(handler).toHaveBeenCalledTimes(1);
  });

  test("reattach migrates subscriptions", () => {
    const proxy = new RpcProxy();
    const c1 = new FakeRpcClient();
    const c2 = new FakeRpcClient();

    const handler = vi.fn();
    proxy.onNotify(2, handler);

    proxy.attach(c1 as any);
    c1.trigger(2, { a: 1 });
    expect(handler).toHaveBeenCalledTimes(1);

    proxy.attach(c2 as any);
    c1.trigger(2, { a: 2 });
    c2.trigger(2, { a: 3 });
    expect(handler).toHaveBeenCalledTimes(2);
  });
});

