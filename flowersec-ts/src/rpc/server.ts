import type { RpcEnvelope, RpcError } from "../gen/flowersec/rpc/v1.gen.js";
import { readJsonFrame, writeJsonFrame } from "./framing.js";
import { assertRpcEnvelope } from "./validate.js";

// RpcHandler processes a request and returns a payload or error.
export type RpcHandler = (payload: unknown) => Promise<{ payload: unknown; error?: RpcError }>;

// RpcServer dispatches request envelopes to registered handlers.
export class RpcServer {
  // Registered handlers keyed by type ID.
  private readonly handlers = new Map<number, RpcHandler>();
  // Closed flag to stop the serve loop.
  private closed = false;

  constructor(
    private readonly readExactly: (n: number) => Promise<Uint8Array>,
    private readonly write: (b: Uint8Array) => Promise<void>
  ) {}

  // register binds a handler to a type ID.
  register(typeId: number, h: RpcHandler): void {
    this.handlers.set(typeId >>> 0, h);
  }

  // serve handles request/response frames until closed or aborted.
  async serve(signal?: AbortSignal): Promise<void> {
    while (!this.closed) {
      if (signal?.aborted) throw signal.reason ?? new Error("aborted");
      const v = assertRpcEnvelope(await readJsonFrame(this.readExactly, 1 << 20));
      if (v.response_to !== 0) continue;
      if (v.request_id === 0) {
        const h = this.handlers.get(v.type_id >>> 0);
        if (h != null) {
          try {
            await h(v.payload);
          } catch {
            // Keep the serve loop alive on notification handler errors.
          }
        }
        continue;
      }
      const h = this.handlers.get(v.type_id >>> 0);
      let out: Awaited<ReturnType<RpcHandler>>;
      if (h == null) {
        out = { payload: null, error: { code: 404, message: "handler not found" } };
      } else {
        try {
          out = await h(v.payload);
        } catch {
          // Keep the serve loop alive on request handler errors.
          out = { payload: null, error: { code: 500, message: "internal error" } };
        }
      }
      const resp: RpcEnvelope = {
        type_id: v.type_id,
        request_id: 0,
        response_to: v.request_id,
        payload: out.payload,
        ...(out.error != null ? { error: out.error } : {})
      };
      await writeJsonFrame(this.write, resp);
    }
  }

  // close stops the serve loop.
  close(): void {
    this.closed = true;
  }
}
