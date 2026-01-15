import type { RpcClient } from "../rpc/client.js";

// RpcProxy allows handlers to survive client reattachment.
export class RpcProxy {
  private client: RpcClient | null = null;
  private readonly notifyHandlers = new Map<number, Map<(payload: unknown) => void, { unsub?: () => void }>>();

  // attach wires existing notification handlers to a new client.
  attach(client: RpcClient): void {
    this.detach();
    this.client = client;
    for (const [typeId, handlers] of this.notifyHandlers) {
      for (const [h, state] of handlers) {
        state.unsub = client.onNotify(typeId, h);
      }
    }
  }

  // detach unwires handlers from the current client.
  detach(): void {
    for (const [, handlers] of this.notifyHandlers) {
      for (const [, state] of handlers) {
        state.unsub?.();
        delete state.unsub;
      }
    }
    this.client = null;
  }

  // onNotify registers handlers that will be rebound on reattach.
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

  // call forwards the RPC call to the attached client.
  async call(typeId: number, payload: unknown, signal?: AbortSignal) {
    if (this.client == null) throw new Error("rpc proxy is not attached");
    return await this.client.call(typeId, payload, signal);
  }
}
