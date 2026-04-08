import { assertConnectArtifact, type ConnectArtifact } from "../connect/artifact.js";

type FetchLike = typeof fetch;

export type ControlplaneBaseConfig = Readonly<{
  baseUrl?: string;
  path?: string;
  headers?: HeadersInit;
  credentials?: RequestCredentials;
  fetch?: FetchLike;
  signal?: AbortSignal;
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

function parseMaybeJSON(bodyText: string): unknown {
  const trimmed = String(bodyText ?? "").trim();
  if (trimmed === "") return "";
  try {
    return JSON.parse(trimmed) as unknown;
  } catch {
    return trimmed;
  }
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
  });
  const rawBody = await response.text();
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
  const data = (await requestControlplaneJSON(
    buildControlplaneURL(config.baseUrl, config.path ?? DEFAULT_CONNECT_ARTIFACT_PATH),
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
  const data = (await requestControlplaneJSON(
    buildControlplaneURL(config.baseUrl, config.path ?? DEFAULT_ENTRY_CONNECT_ARTIFACT_PATH),
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
