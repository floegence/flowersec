import { assertConnectArtifact, type ConnectArtifact } from "../connect/artifact.js";
import { SDK_DEFAULTS } from "../defaults.js";

type FetchLike = typeof fetch;

export type ControlplaneBaseConfig = Readonly<{
  baseUrl?: string;
  path?: string;
  headers?: HeadersInit;
  credentials?: RequestCredentials;
  fetch?: FetchLike;
  signal?: AbortSignal;
  allowLoopbackHTTP?: boolean;
}>;

export type ArtifactRequestCorrelation = Readonly<{
  traceId?: string;
}>;

export type RequestConnectArtifactInput = ControlplaneBaseConfig &
  Readonly<{
    endpointId: string;
    payload?: Record<string, unknown>;
    correlation?: ArtifactRequestCorrelation;
  }>;

export type RequestEntryConnectArtifactInput = RequestConnectArtifactInput &
  Readonly<{
    entryTicket: string;
  }>;

export type ConnectArtifactEnvelope = Readonly<{
  connect_artifact: ConnectArtifact;
}>;

export type ControlplaneErrorEnvelope = Readonly<{
  error: Readonly<{
    code: string;
    message: string;
  }>;
}>;

export class ControlplaneRequestError extends Error {
  readonly status: number;
  readonly code: string;
  readonly responseBody: unknown;

  constructor(args: Readonly<{ status: number; message: string; code?: string; responseBody?: unknown }>) {
    super(args.message);
    this.name = "ControlplaneRequestError";
    this.status = args.status;
    this.code = String(args.code ?? "").trim();
    this.responseBody = args.responseBody;
  }
}

export const DEFAULT_CONNECT_ARTIFACT_PATH = "/v1/connect/artifact";
export const DEFAULT_ENTRY_CONNECT_ARTIFACT_PATH = "/v1/connect/artifact/entry";

const DEFAULT_MAX_CONTROLPLANE_RESPONSE_BYTES = SDK_DEFAULTS.controlplane.maxResponseBodyBytes;

class ControlplaneResponseTooLargeError extends Error {
  constructor(maxBytes: number) {
    super(`controlplane response exceeded ${maxBytes} bytes`);
    this.name = "ControlplaneResponseTooLargeError";
  }
}

function resolveFetch(fetchImpl: FetchLike | undefined): FetchLike {
  if (fetchImpl) return fetchImpl;
  if (typeof globalThis.fetch === "function") return globalThis.fetch.bind(globalThis);
  throw new Error("global fetch is not available");
}

export function buildControlplaneURL(baseUrl: string | undefined, path: string): string {
  const base = String(baseUrl ?? "").trim();
  if (base === "") return path;
  return `${base.replace(/\/+$/, "")}${path}`;
}

function transportPolicyDenied(): ControlplaneRequestError {
  return new ControlplaneRequestError({
    status: 0,
    code: "transport_policy_denied",
    message: "controlplane transport security policy denied URL",
  });
}

function validateArtifactURL(rawUrl: string, allowLoopbackHTTP: boolean | undefined): void {
  let target: URL;
  try {
    if (/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(rawUrl)) {
      target = new URL(rawUrl);
    } else {
      const base = globalThis.location?.href;
      if (!base) throw new Error("relative URL requires a browser location");
      target = new URL(rawUrl, base);
    }
  } catch {
    throw transportPolicyDenied();
  }
  if (target.username !== "" || target.password !== "" || target.hash !== "") {
    throw transportPolicyDenied();
  }
  if (target.protocol === "https:") return;
  if (
    target.protocol === "http:"
    && allowLoopbackHTTP === true
    && isLiteralLoopbackHost(sourceHostname(rawUrl, target))
  ) return;
  throw transportPolicyDenied();
}

function sourceHostname(rawUrl: string, target: URL): string {
  const authority = /^(?:[A-Za-z][A-Za-z0-9+.-]*:)?\/\/([^/?#]*)/.exec(rawUrl)?.[1];
  if (authority === undefined) return target.hostname;

  const hostPort = authority.slice(authority.lastIndexOf("@") + 1);
  if (hostPort.startsWith("[")) {
    const end = hostPort.indexOf("]");
    if (end < 0 || (hostPort.length > end + 1 && !/^:\d+$/.test(hostPort.slice(end + 1)))) {
      return hostPort;
    }
    return hostPort.slice(1, end);
  }

  const colon = hostPort.lastIndexOf(":");
  if (colon < 0) return hostPort;
  if (hostPort.indexOf(":") !== colon || !/^\d+$/.test(hostPort.slice(colon + 1))) return hostPort;
  return hostPort.slice(0, colon);
}

function isLiteralLoopbackHost(rawHost: string): boolean {
  const host = rawHost.startsWith("[") && rawHost.endsWith("]")
    ? rawHost.slice(1, -1).toLowerCase()
    : rawHost.toLowerCase();
  if (host === "localhost" || host === "::1") return true;
  const parts = host.split(".");
  if (parts.length !== 4) return false;
  const octets = parts.map((part) => {
    if (!/^(0|[1-9]\d{0,2})$/.test(part)) return -1;
    const value = Number(part);
    return value <= 255 ? value : -1;
  });
  return octets.every((value) => value >= 0) && octets[0] === 127;
}

function parseMaybeJSON(bodyText: string): unknown {
  const trimmed = String(bodyText ?? "").trim();
  if (trimmed === "") return "";
  try {
    return JSON.parse(trimmed) as unknown;
  } catch {
    return trimmed;
  }
}

function parseContentLength(headerValue: string | null): number | null {
  const raw = String(headerValue ?? "").trim();
  if (raw === "") return null;
  if (!/^[0-9]+$/.test(raw)) return null;
  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed) || parsed < 0) return null;
  return parsed;
}

async function readControlplaneText(response: Response, maxBytes: number): Promise<string> {
  const contentLength = parseContentLength(response.headers.get("Content-Length"));
  if (contentLength !== null && contentLength > maxBytes) {
    throw new ControlplaneResponseTooLargeError(maxBytes);
  }

  if (!response.body) {
    return "";
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let totalBytes = 0;
  let text = "";
  while (true) {
    const chunk = await reader.read();
    if (chunk.done) break;
    totalBytes += chunk.value.byteLength;
    if (totalBytes > maxBytes) {
      try {
        await reader.cancel();
      } catch {
        // The size violation is authoritative; cancellation is secondary cleanup.
      }
      throw new ControlplaneResponseTooLargeError(maxBytes);
    }
    text += decoder.decode(chunk.value, { stream: true });
  }
  text += decoder.decode();
  return text;
}

function decodeErrorMessage(status: number, responseBody: unknown): Readonly<{ code: string; message: string }> {
  let message = `controlplane request failed: ${status}`;
  let code = "";

  if (responseBody && typeof responseBody === "object") {
    const error = (responseBody as { error?: { code?: unknown; message?: unknown } }).error;
    if (error && typeof error === "object") {
      const nextMessage = String(error.message ?? "").trim();
      if (nextMessage !== "") {
        message = nextMessage;
      }
      code = String(error.code ?? "").trim();
    }
  } else if (typeof responseBody === "string" && responseBody !== "") {
    message = responseBody;
  }

  return { code, message };
}

export async function requestControlplaneJSON(
  url: string,
  init: RequestInit & Readonly<{ fetch?: FetchLike }>
): Promise<unknown> {
  const runFetch = resolveFetch(init.fetch);
  const response = await runFetch(url, {
    ...init,
    cache: "no-store",
    redirect: "error",
  });
  let rawBody = "";
  try {
    rawBody = await readControlplaneText(response, DEFAULT_MAX_CONTROLPLANE_RESPONSE_BYTES);
  } catch (err) {
    if (err instanceof ControlplaneResponseTooLargeError && !response.ok) {
      throw new ControlplaneRequestError({
        status: response.status,
        message: err.message,
      });
    }
    throw err;
  }
  const responseBody = parseMaybeJSON(rawBody);

  if (!response.ok) {
    const error = decodeErrorMessage(response.status, responseBody);
    throw new ControlplaneRequestError({
      status: response.status,
      message: error.message,
      code: error.code,
      responseBody,
    });
  }

  if (typeof responseBody === "string") {
    if (responseBody === "") {
      throw new Error("Invalid controlplane response: expected JSON body");
    }
    throw new Error("Invalid controlplane response: expected JSON body");
  }

  return responseBody;
}

function buildConnectArtifactPayload(config: RequestConnectArtifactInput): Record<string, unknown> {
  const body: Record<string, unknown> = {
    endpoint_id: String(config.endpointId ?? "").trim(),
  };
  if (body.endpoint_id === "") throw new Error("endpointId is required");
  if (config.payload !== undefined) body.payload = { ...config.payload };
  const traceId = String(config.correlation?.traceId ?? "").trim();
  if (traceId !== "") {
    body.correlation = { trace_id: traceId };
  }
  return body;
}

function createJSONHeaders(input: HeadersInit | undefined): Headers {
  const headers = new Headers(input);
  if (!headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  return headers;
}

export async function requestConnectArtifact(config: RequestConnectArtifactInput): Promise<ConnectArtifact> {
  const url = buildControlplaneURL(config.baseUrl, config.path ?? DEFAULT_CONNECT_ARTIFACT_PATH);
  validateArtifactURL(url, config.allowLoopbackHTTP);
  const data = (await requestControlplaneJSON(
    url,
    {
      ...(config.fetch === undefined ? {} : { fetch: config.fetch }),
      method: "POST",
      credentials: config.credentials ?? "omit",
      headers: createJSONHeaders(config.headers),
      body: JSON.stringify(buildConnectArtifactPayload(config)),
      ...(config.signal === undefined ? {} : { signal: config.signal }),
    }
  )) as { connect_artifact?: unknown };
  if (!data?.connect_artifact) {
    throw new Error("Invalid controlplane response: missing `connect_artifact`");
  }
  return assertConnectArtifact(data.connect_artifact);
}

export async function requestEntryConnectArtifact(config: RequestEntryConnectArtifactInput): Promise<ConnectArtifact> {
  const entryTicket = String(config.entryTicket ?? "").trim();
  if (entryTicket === "") throw new Error("entryTicket is required");
  const headers = createJSONHeaders(config.headers);
  headers.set("Authorization", `Bearer ${entryTicket}`);
  const url = buildControlplaneURL(config.baseUrl, config.path ?? DEFAULT_ENTRY_CONNECT_ARTIFACT_PATH);
  validateArtifactURL(url, config.allowLoopbackHTTP);
  const data = (await requestControlplaneJSON(
    url,
    {
      ...(config.fetch === undefined ? {} : { fetch: config.fetch }),
      method: "POST",
      credentials: config.credentials ?? "omit",
      headers,
      body: JSON.stringify(buildConnectArtifactPayload(config)),
      ...(config.signal === undefined ? {} : { signal: config.signal }),
    }
  )) as { connect_artifact?: unknown };
  if (!data?.connect_artifact) {
    throw new Error("Invalid controlplane response: missing `connect_artifact`");
  }
  return assertConnectArtifact(data.connect_artifact);
}
