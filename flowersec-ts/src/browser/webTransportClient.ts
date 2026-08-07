import {
  adaptWebTransportCarrierSessionV2,
  type WebTransportSessionLikeV2,
} from "../transport/webTransportAdapter.js";
import { RuntimeError } from "../runtime/errors.js";
import type { NativeCarrierSessionV2 } from "../v2/carrier.js";
import type { PathKind } from "../v2/contract.js";

export type BrowserWebTransportClientOptionsV2 = Readonly<{
  path: PathKind;
  inboundBidirectionalStreamCapacity: number;
  signal?: AbortSignal;
}>;

type BrowserWebTransportRuntimeV2 = WebTransportSessionLikeV2 & Readonly<{
  ready: Promise<void>;
}>;

export async function createBrowserWebTransportClientV2(
  url: string,
  options: BrowserWebTransportClientOptionsV2,
): Promise<NativeCarrierSessionV2> {
  const parsed = validateWebTransportURL(url, options.path);
  const Constructor = (globalThis as unknown as {
    WebTransport?: new (url: string) => BrowserWebTransportRuntimeV2;
  }).WebTransport;
  if (Constructor === undefined) {
    throw new RuntimeError("runtime_unsupported", "WebTransport is unavailable in this browser runtime");
  }
  if (options.signal?.aborted === true) throw options.signal.reason;

  // Chromium does not implement a WebTransport pooling constructor option.
  // Every carrier is one independent native WebTransport created from its URL.
  const transport = new Constructor(parsed.href);
  try {
    await raceAbort(transport.ready, options.signal);
    return adaptWebTransportCarrierSessionV2(transport, options);
  } catch (error) {
    transport.close({ closeCode: 6, reason: "WebTransport start failed" });
    const detail = error instanceof Error && error.message !== "" ? `: ${error.message}` : "";
    throw new RuntimeError("runtime_start_failed", `browser WebTransport failed to start${detail}`, error);
  }
}

function validateWebTransportURL(raw: string, path: PathKind): URL {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch (error) {
    throw new RuntimeError("runtime_start_failed", "invalid WebTransport URL", error);
  }
  const expectedPath = path === "direct"
    ? "/flowersec/webtransport/v2/direct"
    : "/flowersec/webtransport/v2/tunnel";
  if (
    parsed.protocol !== "https:" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.pathname !== expectedPath ||
    parsed.search !== "" ||
    parsed.hash !== ""
  ) {
    throw new RuntimeError("runtime_start_failed", `WebTransport URL must use ${expectedPath}`);
  }
  return parsed;
}

async function raceAbort<T>(promise: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (signal === undefined) return await promise;
  if (signal.aborted) throw signal.reason;
  return await new Promise<T>((resolve, reject) => {
    const abort = () => reject(signal.reason);
    signal.addEventListener("abort", abort, { once: true });
    void promise.then(resolve, reject).finally(() => signal.removeEventListener("abort", abort));
  });
}
