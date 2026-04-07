import { assertChannelInitGrant, Role as ControlRole, type ChannelInitGrant } from "../gen/flowersec/controlplane/v1.gen.js";
import { assertDirectConnectInfo, type DirectConnectInfo } from "../gen/flowersec/direct/v1.gen.js";

const SCOPE_NAME_RE = /^[a-z][a-z0-9._-]{0,63}$/;
const TAG_KEY_RE = /^[a-z][a-z0-9._-]{0,31}$/;
const CORRELATION_ID_RE = /^[A-Za-z0-9._~-]{8,128}$/;
const encoder = new TextEncoder();

const TUNNEL_ARTIFACT_KEYS = new Set(["v", "transport", "tunnel_grant", "scoped", "correlation"]);
const DIRECT_ARTIFACT_KEYS = new Set(["v", "transport", "direct_info", "scoped", "correlation"]);
const ARTIFACT_ONLY_KEYS = new Set(["v", "transport", "tunnel_grant", "direct_info", "scoped", "correlation"]);

export type ConnectArtifactTransport = "tunnel" | "direct";

export type CorrelationKV = Readonly<{
  key: string;
  value: string;
}>;

export type CorrelationContext = Readonly<{
  v: 1;
  trace_id?: string;
  session_id?: string;
  tags: readonly CorrelationKV[];
}>;

export type ScopePayload = Record<string, unknown>;

export type ScopeMetadataEntry = Readonly<{
  scope: string;
  scope_version: number;
  critical: boolean;
  payload: ScopePayload;
}>;

export type TunnelClientConnectArtifact = Readonly<{
  v: 1;
  transport: "tunnel";
  tunnel_grant: ChannelInitGrant;
  scoped?: readonly ScopeMetadataEntry[];
  correlation?: CorrelationContext;
}>;

export type DirectClientConnectArtifact = Readonly<{
  v: 1;
  transport: "direct";
  direct_info: DirectConnectInfo;
  scoped?: readonly ScopeMetadataEntry[];
  correlation?: CorrelationContext;
}>;

export type ConnectArtifact = TunnelClientConnectArtifact | DirectClientConnectArtifact;

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v != null && !Array.isArray(v);
}

function hasOwn(o: Record<string, unknown>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(o, key);
}

function assertNoUnknownFields(kind: string, obj: Record<string, unknown>, allowed: ReadonlySet<string>): void {
  for (const key of Object.keys(obj)) {
    if (!allowed.has(key)) throw new Error(`bad ${kind}.${key}`);
  }
}

function assertPositiveInt(name: string, value: unknown, min: number, max: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) throw new Error(`bad ${name}`);
  if (value < min || value > max) throw new Error(`bad ${name}`);
  return value;
}

function utf8Len(value: string): number {
  return encoder.encode(value).length;
}

function normalizedJSONForSize(value: unknown): string {
  return serializeNormalizedJSON(normalizeJSONValue(value));
}

function normalizeJSONValue(value: unknown): unknown {
  if (value === null) return null;
  switch (typeof value) {
    case "string":
    case "boolean":
      return value;
    case "number":
      if (!Number.isFinite(value)) throw new Error("bad payload.number");
      return value;
    case "object": {
      if (Array.isArray(value)) {
        return value.map((entry) => normalizeJSONValue(entry));
      }
      if (!isRecord(value)) throw new Error("bad payload.object");
      const out: Record<string, unknown> = {};
      for (const key of Object.keys(value).sort()) {
        out[key] = normalizeJSONValue(value[key]);
      }
      return out;
    }
    default:
      throw new Error("bad payload.value");
  }
}

function serializeNormalizedJSON(value: unknown): string {
  return JSON.stringify(value);
}

function maxContainerDepth(value: unknown): number {
  if (Array.isArray(value)) {
    let best = 1;
    for (const entry of value) best = Math.max(best, 1 + maxContainerDepth(entry));
    return best;
  }
  if (isRecord(value)) {
    let best = 1;
    for (const entry of Object.values(value)) best = Math.max(best, 1 + maxContainerDepth(entry));
    return best;
  }
  return 0;
}

function sanitizeCorrelationID(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  if (!CORRELATION_ID_RE.test(trimmed)) return undefined;
  return trimmed;
}

function assertCorrelationKV(value: unknown): CorrelationKV {
  if (!isRecord(value)) throw new Error("bad CorrelationKV");
  assertNoUnknownFields("CorrelationKV", value, new Set(["key", "value"]));
  if (typeof value.key !== "string" || !TAG_KEY_RE.test(value.key)) throw new Error("bad CorrelationKV.key");
  if (typeof value.value !== "string") throw new Error("bad CorrelationKV.value");
  if (utf8Len(value.key) > 32) throw new Error("bad CorrelationKV.key");
  if (utf8Len(value.value) > 128) throw new Error("bad CorrelationKV.value");
  return Object.freeze({ key: value.key, value: value.value });
}

function assertCorrelationContext(value: unknown): CorrelationContext {
  if (!isRecord(value)) throw new Error("bad CorrelationContext");
  assertNoUnknownFields("CorrelationContext", value, new Set(["v", "trace_id", "session_id", "tags"]));
  if (value.v !== 1) throw new Error("bad CorrelationContext.v");
  const rawTags = value.tags;
  if (rawTags !== undefined && !Array.isArray(rawTags)) throw new Error("bad CorrelationContext.tags");
  const tags = (rawTags ?? []).map((entry) => assertCorrelationKV(entry));
  const seen = new Set<string>();
  for (const tag of tags) {
    if (seen.has(tag.key)) throw new Error("bad CorrelationContext.tags");
    seen.add(tag.key);
  }
  if (tags.length > 8) throw new Error("bad CorrelationContext.tags");
  const traceId = sanitizeCorrelationID(value.trace_id);
  const sessionId = sanitizeCorrelationID(value.session_id);
  return Object.freeze({
    v: 1,
    ...(traceId === undefined ? {} : { trace_id: traceId }),
    ...(sessionId === undefined ? {} : { session_id: sessionId }),
    tags: Object.freeze(tags),
  });
}

function assertPayloadObject(value: unknown): ScopePayload {
  if (!isRecord(value)) throw new Error("bad ScopeMetadataEntry.payload");
  const normalized = normalizedJSONForSize(value);
  if (utf8Len(normalized) > 8192) throw new Error("bad ScopeMetadataEntry.payload");
  if (maxContainerDepth(value) > 8) throw new Error("bad ScopeMetadataEntry.payload");
  return value;
}

function assertScopeMetadataEntry(value: unknown): ScopeMetadataEntry {
  if (!isRecord(value)) throw new Error("bad ScopeMetadataEntry");
  assertNoUnknownFields("ScopeMetadataEntry", value, new Set(["scope", "scope_version", "critical", "payload"]));
  if (typeof value.scope !== "string" || !SCOPE_NAME_RE.test(value.scope)) throw new Error("bad ScopeMetadataEntry.scope");
  if (typeof value.critical !== "boolean") throw new Error("bad ScopeMetadataEntry.critical");
  const scopeVersion = assertPositiveInt("ScopeMetadataEntry.scope_version", value.scope_version, 1, 65535);
  const payload = assertPayloadObject(value.payload);
  return Object.freeze({
    scope: value.scope,
    scope_version: scopeVersion,
    critical: value.critical,
    payload,
  });
}

function assertScopedEntries(value: unknown): readonly ScopeMetadataEntry[] {
  if (!Array.isArray(value)) throw new Error("bad ConnectArtifact.scoped");
  if (value.length > 8) throw new Error("bad ConnectArtifact.scoped");
  const out = value.map((entry) => assertScopeMetadataEntry(entry));
  const seen = new Set<string>();
  for (const entry of out) {
    if (seen.has(entry.scope)) throw new Error("bad ConnectArtifact.scoped");
    seen.add(entry.scope);
  }
  return Object.freeze(out);
}

function assertArtifactObject(value: unknown): Record<string, unknown> {
  if (!isRecord(value)) throw new Error("bad ConnectArtifact");
  return value;
}

function assertArtifactTransport(value: unknown): ConnectArtifactTransport {
  if (value !== "tunnel" && value !== "direct") throw new Error("bad ConnectArtifact.transport");
  return value;
}

export function hasArtifactOnlyFields(value: Record<string, unknown>): boolean {
  return Object.keys(value).some((key) => ARTIFACT_ONLY_KEYS.has(key));
}

export function assertConnectArtifact(value: unknown): ConnectArtifact {
  const record = assertArtifactObject(value);
  if (record.v !== 1) throw new Error("bad ConnectArtifact.v");
  const transport = assertArtifactTransport(record.transport);
  const scoped = record.scoped === undefined ? undefined : assertScopedEntries(record.scoped);
  const correlation = record.correlation === undefined ? undefined : assertCorrelationContext(record.correlation);
  if (transport === "tunnel") {
    assertNoUnknownFields("TunnelClientConnectArtifact", record, TUNNEL_ARTIFACT_KEYS);
    if (!hasOwn(record, "tunnel_grant")) throw new Error("bad TunnelClientConnectArtifact.tunnel_grant");
    const tunnelGrant = assertChannelInitGrant(record.tunnel_grant);
    if (tunnelGrant.role !== ControlRole.Role_client) {
      throw new Error("bad TunnelClientConnectArtifact.tunnel_grant.role");
    }
    return Object.freeze({
      v: 1,
      transport,
      tunnel_grant: tunnelGrant,
      ...(scoped === undefined ? {} : { scoped }),
      ...(correlation === undefined ? {} : { correlation }),
    });
  }
  assertNoUnknownFields("DirectClientConnectArtifact", record, DIRECT_ARTIFACT_KEYS);
  if (!hasOwn(record, "direct_info")) throw new Error("bad DirectClientConnectArtifact.direct_info");
  const directInfo = assertDirectConnectInfo(record.direct_info);
  return Object.freeze({
    v: 1,
    transport,
    direct_info: directInfo,
    ...(scoped === undefined ? {} : { scoped }),
    ...(correlation === undefined ? {} : { correlation }),
  });
}
