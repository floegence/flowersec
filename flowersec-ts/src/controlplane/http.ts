import { assertConnectArtifact, type ConnectArtifact } from "../connect/artifact.js";
import { SDK_DEFAULTS } from "../defaults.js";

export type ArtifactRequest = Readonly<{
  endpoint_id: string;
  payload?: Record<string, unknown>;
  correlation?: Readonly<{ trace_id?: string }>;
}>;

export class ControlplaneCodecError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) {
    super(message);
    this.name = "ControlplaneCodecError";
  }
}

export function decodeArtifactRequest(
  contentType: string,
  body: Uint8Array,
  maxBodyBytes = SDK_DEFAULTS.controlplane.maxRequestBodyBytes,
): ArtifactRequest {
  if (contentType.split(";", 1)[0]?.trim().toLowerCase() !== "application/json") {
    throw new ControlplaneCodecError(415, "unsupported_media_type", "content type must be application/json");
  }
  if (body.length > maxBodyBytes) throw new ControlplaneCodecError(413, "body_too_large", `request body exceeds ${maxBodyBytes} bytes`);
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder().decode(body));
  } catch {
    throw new ControlplaneCodecError(400, "invalid_json", "malformed JSON request body");
  }
  if (typeof value !== "object" || value == null || Array.isArray(value)) throw new ControlplaneCodecError(400, "invalid_json", "request body must be a JSON object");
  const input = value as Record<string, unknown>;
  const endpointId = typeof input["endpoint_id"] === "string" ? input["endpoint_id"].trim() : "";
  if (endpointId === "") throw new ControlplaneCodecError(400, "invalid_request", "bad endpoint_id");
  const payload = input["payload"];
  if (payload !== undefined && (typeof payload !== "object" || payload == null || Array.isArray(payload))) throw new ControlplaneCodecError(400, "invalid_request", "bad payload");
  const correlation = input["correlation"];
  if (correlation !== undefined && (typeof correlation !== "object" || correlation == null || Array.isArray(correlation))) throw new ControlplaneCodecError(400, "invalid_request", "bad correlation");
  const traceId = typeof (correlation as Record<string, unknown> | undefined)?.["trace_id"] === "string"
    ? String((correlation as Record<string, unknown>)["trace_id"]).trim()
    : "";
  return {
    endpoint_id: endpointId,
    ...(payload === undefined ? {} : { payload: payload as Record<string, unknown> }),
    ...(traceId === "" ? {} : { correlation: { trace_id: traceId } }),
  };
}

export function encodeArtifactEnvelope(artifact: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({ connect_artifact: assertConnectArtifact(artifact) satisfies ConnectArtifact }));
}

export function encodeControlplaneError(code: string, message: string): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({ error: { code, message } }));
}

export function bearerToken(authorization: string): string | undefined {
  const value = authorization.trim();
  if (!value.startsWith("Bearer ")) return undefined;
  const token = value.slice("Bearer ".length).trim();
  return token === "" ? undefined : token;
}
