import { assertChannelInitGrant, type ChannelInitGrant } from "../facade.js";
import { assertConnectArtifact, type ConnectArtifact } from "../connect/artifact.js";

type FetchLike = typeof fetch;

type BaseControlplaneRequestConfig = Readonly<{
  baseUrl?: string;
  endpointId: string;
  payload?: Record<string, unknown>;
  headers?: HeadersInit;
  credentials?: RequestCredentials;
  fetch?: FetchLike;
}>;

export type ControlplaneConfig = BaseControlplaneRequestConfig;

export type EntryControlplaneConfig = BaseControlplaneRequestConfig & Readonly<{
  entryTicket: string;
}>;

export type ConnectArtifactRequestConfig = BaseControlplaneRequestConfig & Readonly<{
  path?: string;
  correlation?: Readonly<{
    traceId?: string;
  }>;
}>;

export type EntryConnectArtifactRequestConfig = ConnectArtifactRequestConfig &
  Readonly<{
    entryTicket: string;
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

function resolveFetch(fetchImpl: FetchLike | undefined): FetchLike {
  if (fetchImpl) return fetchImpl;
  if (typeof globalThis.fetch === "function") return globalThis.fetch.bind(globalThis);
  throw new Error("global fetch is not available");
}

function buildURL(baseUrl: string | undefined, path: string): string {
  const base = String(baseUrl ?? "").trim();
  if (base === "") return path;
  return `${base.replace(/\/+$/, "")}${path}`;
}

function buildPayload(endpointId: string, payload: Record<string, unknown> | undefined): Record<string, unknown> {
  const id = String(endpointId ?? "").trim();
  if (id === "") throw new Error("endpointId is required");

  const out = { ...(payload ?? {}) };
  const raw = out.endpoint_id;
  if (raw !== undefined && String(raw ?? "").trim() !== id) {
    throw new Error("payload.endpoint_id must match endpointId");
  }
  out.endpoint_id = id;
  return out;
}

async function requestGrant(
  url: string,
  init: RequestInit & Readonly<{ fetch?: FetchLike }>
): Promise<unknown> {
  const runFetch = resolveFetch(init.fetch);
  const response = await runFetch(url, {
    ...init,
    cache: "no-store",
  });

  if (!response.ok) {
    const rawBody = await response.text();
    const bodyText = String(rawBody ?? "").trim();
    let responseBody: unknown = bodyText;
    if (bodyText !== "") {
      try {
        responseBody = JSON.parse(bodyText) as unknown;
      } catch {
        responseBody = bodyText;
      }
    }

    let message = `Failed to get channel grant: ${response.status}`;
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

    throw new ControlplaneRequestError({
      status: response.status,
      message,
      code,
      responseBody,
    });
  }

  return await response.json();
}

export async function requestChannelGrant(config: ControlplaneConfig): Promise<ChannelInitGrant> {
  const headers = new Headers(config.headers);
  if (!headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const data = (await requestGrant(buildURL(config.baseUrl, "/v1/channel/init"), {
    ...(config.fetch === undefined ? {} : { fetch: config.fetch }),
    method: "POST",
    credentials: config.credentials ?? "omit",
    headers,
    body: JSON.stringify(buildPayload(config.endpointId, config.payload)),
  })) as { grant_client?: unknown };
  if (!data?.grant_client) {
    throw new Error("Invalid controlplane response: missing `grant_client`");
  }
  return assertChannelInitGrant(data.grant_client);
}

export async function requestEntryChannelGrant(config: EntryControlplaneConfig): Promise<ChannelInitGrant> {
  const entryTicket = String(config.entryTicket ?? "").trim();
  if (entryTicket === "") throw new Error("entryTicket is required");

  const endpointId = String(config.endpointId ?? "").trim();
  const headers = new Headers(config.headers);
  headers.set("Authorization", `Bearer ${entryTicket}`);
  if (!headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const data = (await requestGrant(
    buildURL(config.baseUrl, `/v1/channel/init/entry?endpoint_id=${encodeURIComponent(endpointId)}`),
    {
      ...(config.fetch === undefined ? {} : { fetch: config.fetch }),
      method: "POST",
      credentials: config.credentials ?? "omit",
      headers,
      body: JSON.stringify(buildPayload(endpointId, config.payload)),
    }
  )) as { grant_client?: unknown };
  if (!data?.grant_client) {
    throw new Error("Invalid controlplane response: missing `grant_client`");
  }
  return assertChannelInitGrant(data.grant_client);
}

function buildConnectArtifactPayload(config: ConnectArtifactRequestConfig): Record<string, unknown> {
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

export async function requestConnectArtifact(config: ConnectArtifactRequestConfig): Promise<ConnectArtifact> {
  const headers = new Headers(config.headers);
  if (!headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  const data = (await requestGrant(buildURL(config.baseUrl, config.path ?? "/v1/connect/artifact"), {
    ...(config.fetch === undefined ? {} : { fetch: config.fetch }),
    method: "POST",
    credentials: config.credentials ?? "omit",
    headers,
    body: JSON.stringify(buildConnectArtifactPayload(config)),
  })) as { connect_artifact?: unknown };
  if (!data?.connect_artifact) {
    throw new Error("Invalid controlplane response: missing `connect_artifact`");
  }
  return assertConnectArtifact(data.connect_artifact);
}

export async function requestEntryConnectArtifact(config: EntryConnectArtifactRequestConfig): Promise<ConnectArtifact> {
  const entryTicket = String(config.entryTicket ?? "").trim();
  if (entryTicket === "") throw new Error("entryTicket is required");
  const headers = new Headers(config.headers);
  headers.set("Authorization", `Bearer ${entryTicket}`);
  if (!headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  const data = (await requestGrant(buildURL(config.baseUrl, config.path ?? "/v1/connect/artifact/entry"), {
    ...(config.fetch === undefined ? {} : { fetch: config.fetch }),
    method: "POST",
    credentials: config.credentials ?? "omit",
    headers,
    body: JSON.stringify(buildConnectArtifactPayload(config)),
  })) as { connect_artifact?: unknown };
  if (!data?.connect_artifact) {
    throw new Error("Invalid controlplane response: missing `connect_artifact`");
  }
  return assertConnectArtifact(data.connect_artifact);
}
