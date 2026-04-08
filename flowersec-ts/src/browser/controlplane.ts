import { assertChannelInitGrant, type ChannelInitGrant } from "../facade.js";
import type {
  ControlplaneBaseConfig as SharedControlplaneBaseConfig,
  RequestConnectArtifactInput,
  RequestEntryConnectArtifactInput,
} from "../controlplane/request.js";
import {
  requestControlplaneJSON,
} from "../controlplane/request.js";
export {
  ControlplaneRequestError,
  requestConnectArtifact,
  requestEntryConnectArtifact,
} from "../controlplane/request.js";

type FetchLike = typeof fetch;

type BaseControlplaneRequestConfig = SharedControlplaneBaseConfig &
  Readonly<{
    endpointId: string;
    payload?: Record<string, unknown>;
  }>;

export type ControlplaneConfig = BaseControlplaneRequestConfig;

export type EntryControlplaneConfig = BaseControlplaneRequestConfig & Readonly<{
  entryTicket: string;
}>;

export type ConnectArtifactRequestConfig = RequestConnectArtifactInput;

export type EntryConnectArtifactRequestConfig = RequestEntryConnectArtifactInput;

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
  return await requestControlplaneJSON(url, init);
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
    ...(config.signal === undefined ? {} : { signal: config.signal }),
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
      ...(config.signal === undefined ? {} : { signal: config.signal }),
    }
  )) as { grant_client?: unknown };
  if (!data?.grant_client) {
    throw new Error("Invalid controlplane response: missing `grant_client`");
  }
  return assertChannelInitGrant(data.grant_client);
}
