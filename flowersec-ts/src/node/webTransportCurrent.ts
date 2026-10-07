import type { V4TransportEnvironment } from "../v4/public.js";
import { configureNodeRawQUIC, type NodeRawQUICClientConfig, type NodeRawQUICClient } from "./clientV4.js";
import { createNodeRawQUICListener, type NodeRawQUICListener, type NodeRawQUICListenerOptions } from "./serveRawQUIC.js";
import type { NodeRawQUICOptions } from "./rawQUICCurrent.js";

/** Explicit trusted deployment binding for the built-in native H3 carrier.
 * Actual CONNECT/TLS/stream/receipt evidence comes only from the native owner. */
export interface NodeWebTransportOptions extends Omit<NodeRawQUICOptions, "nativeCarrier" | "webTransport"> {
  readonly headerBytes: number; readonly controlBytes: number;
  readonly tuples: readonly ("chromium_draft02" | "native_h3")[];
  readonly allowedOrigins: readonly string[]; readonly allowAbsentOrigin: boolean;
}
export function nativeWebTransportOptions(input: NodeWebTransportOptions): NodeRawQUICOptions {
  const { headerBytes, controlBytes, tuples, allowedOrigins, allowAbsentOrigin, ...resources } = input;
  return { ...resources, nativeCarrier: "webtransport", webTransport: { headerBytes, controlBytes, tuples, allowedOrigins, allowAbsentOrigin } };
}
export interface NodeWebTransportClientConfig extends Omit<NodeRawQUICClientConfig, "carrier"> { readonly carrier: NodeWebTransportOptions }
export type NodeWebTransportClient = NodeRawQUICClient;
export function configureNodeWebTransport(environment: V4TransportEnvironment, options: NodeWebTransportClientConfig): NodeWebTransportClient {
  return configureNodeRawQUIC(environment, { ...options, carrier: nativeWebTransportOptions(options.carrier) });
}
export interface NodeWebTransportListenerOptions extends Omit<NodeRawQUICListenerOptions, "carrier"> { readonly carrier: NodeWebTransportOptions }
export type NodeWebTransportListener = NodeRawQUICListener;
export function createNodeWebTransportListener(environment: V4TransportEnvironment, options: NodeWebTransportListenerOptions): NodeWebTransportListener {
  return createNodeRawQUICListener(environment, { ...options, carrier: nativeWebTransportOptions(options.carrier) });
}
