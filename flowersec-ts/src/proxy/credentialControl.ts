import type { ProxyRuntime } from "./types.js";
import { decodeProxyMetadata, encodeProxyMetadata, PROXY_WIRE_VERSION } from "./wire.js";

/** Private control carried by the existing flowersec.proxy.http application
 * Stream. The trusted dispatcher intercepts this path before upstream routing. */
export const PROXY_CREDENTIAL_CONTROL_PATH = "/.flowersec/upstream-credentials";
export type ProxyCredentialAction = 1 | 2 | 3;
export interface ProxyCredentialControlRequest {
  readonly v: number;
  readonly operation_id: string;
  readonly action: ProxyCredentialAction;
  readonly surface_owner: string;
  readonly credential_context?: string;
  readonly content_origin?: string;
}
export interface ProxyCredentialControlResponse {
  readonly v: number;
  readonly operation_id: string;
  readonly action: ProxyCredentialAction;
  readonly ok: boolean;
  readonly credential_context?: string;
  readonly server_invalidated?: boolean;
  readonly error?: Readonly<{ code: string; message: string }>;
}
const identity = /^[a-f0-9]{32}$/u;
const association = /^[A-Za-z0-9_-]{43}$/u;
const controls = new WeakMap<ProxyRuntime, (body: Uint8Array, signal?: AbortSignal) => Promise<Response>>();
/** @internal The original runtime owns this route; content has no access. */
export function registerProxyCredentialControl(runtime: ProxyRuntime,
  control: (body: Uint8Array, signal?: AbortSignal) => Promise<Response>): void {
  if (controls.has(runtime)) throw new Error("credential_control_already_registered");
  controls.set(runtime, control);
}
export function validateProxyCredentialControlRequest(request: ProxyCredentialControlRequest): void {
  if (request.v !== PROXY_WIRE_VERSION || !identity.test(request.operation_id) || !identity.test(request.surface_owner) ||
      ![1, 2, 3].includes(request.action)) throw new Error("credential_control_invalid");
  if (request.action === 1) {
    if (request.credential_context !== undefined || typeof request.content_origin !== "string") throw new Error("credential_control_invalid");
    const url = new URL(request.content_origin);
    if (url.origin !== request.content_origin || !["http:", "https:"].includes(url.protocol)) throw new Error("credential_control_invalid");
  } else if (typeof request.credential_context !== "string" || !association.test(request.credential_context) || request.content_origin !== undefined) {
    throw new Error("credential_control_invalid");
  }
}
export function decodeProxyCredentialControlRequest(bytes: Uint8Array): ProxyCredentialControlRequest {
  const request = decodeProxyMetadata("ProxyCredentialControlRequest", bytes, 8192) as unknown as ProxyCredentialControlRequest;
  validateProxyCredentialControlRequest(request); return request;
}
export function encodeProxyCredentialControlResponse(response: ProxyCredentialControlResponse): Uint8Array {
  validateProxyCredentialControlResponse(response);
  return encodeProxyMetadata("ProxyCredentialControlResponse", response, 8192);
}
export function validateProxyCredentialControlResponse(response: ProxyCredentialControlResponse): void {
  if (response.v !== PROXY_WIRE_VERSION || !identity.test(response.operation_id) || ![1, 2, 3].includes(response.action)) throw new Error("credential_control_invalid");
  if (response.ok !== true) {
    if (response.ok !== false || response.error === undefined || response.credential_context !== undefined ||
        response.server_invalidated !== undefined && (response.action !== 2 || response.server_invalidated !== true)) throw new Error("credential_control_invalid");
    return;
  }
  if (response.error !== undefined) throw new Error("credential_control_invalid");
  if (response.action === 1 && (response.server_invalidated !== undefined || typeof response.credential_context !== "string" || !association.test(response.credential_context)) ||
      response.action === 2 && (response.server_invalidated !== true || typeof response.credential_context !== "string" || !association.test(response.credential_context)) ||
      response.action === 3 && (response.server_invalidated !== true || response.credential_context !== undefined)) throw new Error("credential_control_invalid");
}
export async function proxyCredentialControl(runtime: ProxyRuntime, request: ProxyCredentialControlRequest,
  signal?: AbortSignal): Promise<ProxyCredentialControlResponse> {
  validateProxyCredentialControlRequest(request);
  const control = controls.get(runtime); if (control === undefined) throw new Error("credential_control_unavailable");
  const body = encodeProxyMetadata("ProxyCredentialControlRequest", request, 8192);
  const response = await control(body, signal);
  if (!response.ok || response.body === null) throw new Error("credential_control_failed");
  const reader = response.body.getReader(), bytes = new Uint8Array(8192);
  let size = 0;
  try {
    for (;;) {
      signal?.throwIfAborted(); const next = await reader.read();
      if (next.done) break;
      if (next.value.byteLength > bytes.length - size) throw new Error("credential_control_invalid");
      bytes.set(next.value, size); size += next.value.byteLength;
    }
  } finally { await reader.cancel().catch(() => undefined); reader.releaseLock(); }
  const ack = decodeProxyMetadata("ProxyCredentialControlResponse", bytes.subarray(0, size), 8192) as unknown as ProxyCredentialControlResponse;
  validateProxyCredentialControlResponse(ack);
  if (ack.operation_id !== request.operation_id || ack.action !== request.action) throw new Error("credential_control_invalid");
  return ack;
}
