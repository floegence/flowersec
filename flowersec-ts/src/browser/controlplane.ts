import { assertChannelInitGrant, type ChannelInitGrant } from "../facade.js";

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
): Promise<ChannelInitGrant> {
  const runFetch = resolveFetch(init.fetch);
  const response = await runFetch(url, {
    ...init,
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`Failed to get channel grant: ${response.status}`);
  }

  const data = (await response.json()) as { grant_client?: unknown };
  if (!data?.grant_client) {
    throw new Error("Invalid controlplane response: missing `grant_client`");
  }

  return assertChannelInitGrant(data.grant_client);
}

export async function requestChannelGrant(config: ControlplaneConfig): Promise<ChannelInitGrant> {
  const headers = new Headers(config.headers);
  if (!headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  return await requestGrant(buildURL(config.baseUrl, "/v1/channel/init"), {
    ...(config.fetch === undefined ? {} : { fetch: config.fetch }),
    method: "POST",
    credentials: config.credentials ?? "omit",
    headers,
    body: JSON.stringify(buildPayload(config.endpointId, config.payload)),
  });
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

  return await requestGrant(
    buildURL(config.baseUrl, `/v1/channel/init/entry?endpoint_id=${encodeURIComponent(endpointId)}`),
    {
      ...(config.fetch === undefined ? {} : { fetch: config.fetch }),
      method: "POST",
      credentials: config.credentials ?? "omit",
      headers,
      body: JSON.stringify(buildPayload(endpointId, config.payload)),
    }
  );
}
