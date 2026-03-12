import type { RpcClient } from "./client.js";

export class RpcProxyDetachedError extends Error {
  constructor() {
    super("rpc proxy is not attached");
    this.name = "RpcProxyDetachedError";
  }
}

// RpcProxy keeps notify subscriptions stable across client reattachment.
export class RpcProxy {
  private client: RpcClient | null = null;
  private readonly notifyHandlers = new Map<number, Map<(payload: unknown) => void, { unsub?: () => void }>>();

  attach(client: RpcClient): void {
    this.detach();
    this.client = client;
    for (const [typeId, handlers] of this.notifyHandlers) {
      for (const [handler, state] of handlers) {
        state.unsub = client.onNotify(typeId, handler);
      }
    }
  }

  detach(): void {
    for (const [, handlers] of this.notifyHandlers) {
      for (const [, state] of handlers) {
        state.unsub?.();
        delete state.unsub;
      }
    }
    this.client = null;
  }

  onNotify(typeId: number, handler: (payload: unknown) => void): () => void {
    const tid = typeId >>> 0;
    const handlers = this.notifyHandlers.get(tid) ?? new Map<(payload: unknown) => void, { unsub?: () => void }>();
    if (!this.notifyHandlers.has(tid)) this.notifyHandlers.set(tid, handlers);
    if (!handlers.has(handler)) {
      const state: { unsub?: () => void } = {};
      if (this.client != null) state.unsub = this.client.onNotify(tid, handler);
      handlers.set(handler, state);
    }
    return () => {
      const state = handlers.get(handler);
      state?.unsub?.();
      handlers.delete(handler);
      if (handlers.size === 0) this.notifyHandlers.delete(tid);
    };
  }

  async call(typeId: number, payload: unknown, signal?: AbortSignal) {
    if (this.client == null) throw new RpcProxyDetachedError();
    return await this.client.call(typeId, payload, signal);
  }

  async notify(typeId: number, payload: unknown): Promise<void> {
    if (this.client == null) throw new RpcProxyDetachedError();
    await this.client.notify(typeId, payload);
  }
}
