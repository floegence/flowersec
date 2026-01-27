import type { ChannelInitGrant } from "../gen/flowersec/controlplane/v1.gen.js";
import { Role as TunnelRole, type Attach } from "../gen/flowersec/tunnel/v1.gen.js";
import { assertChannelInitGrant, Role as ControlRole } from "../gen/flowersec/controlplane/v1.gen.js";
import { base64urlDecode, base64urlEncode } from "../utils/base64url.js";
import { FlowersecError } from "../utils/errors.js";
import { randomBytes } from "../client-connect/common.js";
import { connectCore, type ConnectOptionsBase } from "../client-connect/connectCore.js";
import type { ClientInternal } from "../client.js";

// TunnelConnectOptions controls transport and handshake limits.
export type TunnelConnectOptions = ConnectOptionsBase &
  Readonly<{
    /** Optional caller-provided endpoint instance ID (base64url). */
    endpointInstanceId?: string;
  }>;

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v != null && !Array.isArray(v);
}

function hasOwn(o: Record<string, unknown>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(o, key);
}

function unwrapGrant(v: unknown): unknown {
  if (!isRecord(v)) return v;
  if (hasOwn(v, "grant_client")) return v["grant_client"];
  if (hasOwn(v, "grant_server")) return v["grant_server"];
  return v;
}

// connectTunnel attaches to a tunnel and returns an RPC-ready session.
export async function connectTunnel(grant: unknown, opts: TunnelConnectOptions): Promise<ClientInternal> {
  const input = unwrapGrant(grant);
  if (input == null) {
    throw new FlowersecError({ stage: "validate", code: "missing_grant", path: "tunnel", message: "missing grant" });
  }
  if (isRecord(input)) {
    // Align missing/invalid field codes with Go: missing fields map to specific stable codes.
    const okTypes =
      (!hasOwn(input, "role") || (typeof input["role"] === "number" && Number.isSafeInteger(input["role"]))) &&
      (!hasOwn(input, "tunnel_url") || typeof input["tunnel_url"] === "string") &&
      (!hasOwn(input, "channel_id") || typeof input["channel_id"] === "string") &&
      (!hasOwn(input, "token") || typeof input["token"] === "string") &&
      (!hasOwn(input, "channel_init_expire_at_unix_s") ||
        (typeof input["channel_init_expire_at_unix_s"] === "number" && Number.isSafeInteger(input["channel_init_expire_at_unix_s"]))) &&
      (!hasOwn(input, "e2ee_psk_b64u") || typeof input["e2ee_psk_b64u"] === "string") &&
      (!hasOwn(input, "default_suite") || (typeof input["default_suite"] === "number" && Number.isSafeInteger(input["default_suite"])));
    if (okTypes) {
      const role = input["role"] as number | undefined;
      if (role === undefined || role !== ControlRole.Role_client) {
        throw new FlowersecError({ stage: "validate", code: "role_mismatch", path: "tunnel", message: "expected role=client" });
      }
      if (!hasOwn(input, "tunnel_url")) {
        throw new FlowersecError({ stage: "validate", code: "missing_tunnel_url", path: "tunnel", message: "missing tunnel_url" });
      }
      if (!hasOwn(input, "channel_id")) {
        throw new FlowersecError({ stage: "validate", code: "missing_channel_id", path: "tunnel", message: "missing channel_id" });
      }
      if (!hasOwn(input, "token")) {
        throw new FlowersecError({ stage: "validate", code: "missing_token", path: "tunnel", message: "missing token" });
      }
      if (!hasOwn(input, "channel_init_expire_at_unix_s")) {
        throw new FlowersecError({ stage: "validate", code: "missing_init_exp", path: "tunnel", message: "missing channel_init_expire_at_unix_s" });
      }
      if (!hasOwn(input, "e2ee_psk_b64u")) {
        throw new FlowersecError({ stage: "validate", code: "invalid_psk", path: "tunnel", message: "missing e2ee_psk_b64u" });
      }
      if (!hasOwn(input, "default_suite")) {
        throw new FlowersecError({ stage: "validate", code: "invalid_suite", path: "tunnel", message: "missing default_suite" });
      }
    }

    const suite = input["default_suite"];
    // Keep "invalid_suite" as the stable error code even when the IDL validator rejects the enum value.
    if (typeof suite === "number" && Number.isSafeInteger(suite) && suite !== 1 && suite !== 2) {
      throw new FlowersecError({ stage: "validate", code: "invalid_suite", path: "tunnel", message: "invalid suite" });
    }
    const allowed = input["allowed_suites"];
    if (Array.isArray(allowed)) {
      for (const v of allowed) {
        if (typeof v === "number" && Number.isSafeInteger(v) && v !== 1 && v !== 2) {
          throw new FlowersecError({ stage: "validate", code: "invalid_suite", path: "tunnel", message: "invalid suite" });
        }
      }
    }
  }
  let checkedGrant: ChannelInitGrant;
  try {
    checkedGrant = assertChannelInitGrant(input);
  } catch (e) {
    throw new FlowersecError({ stage: "validate", code: "invalid_input", path: "tunnel", message: "invalid ChannelInitGrant", cause: e });
  }
  if (checkedGrant.tunnel_url === "") {
    throw new FlowersecError({ stage: "validate", code: "missing_tunnel_url", path: "tunnel", message: "missing tunnel_url" });
  }
  if (checkedGrant.channel_id === "") {
    throw new FlowersecError({ stage: "validate", code: "missing_channel_id", path: "tunnel", message: "missing channel_id" });
  }
  if (checkedGrant.token === "") {
    throw new FlowersecError({ stage: "validate", code: "missing_token", path: "tunnel", message: "missing token" });
  }
  if (checkedGrant.channel_init_expire_at_unix_s <= 0) {
    throw new FlowersecError({
      stage: "validate",
      code: "missing_init_exp",
      path: "tunnel",
      message: "missing channel_init_expire_at_unix_s",
    });
  }
  try {
    const psk = base64urlDecode(checkedGrant.e2ee_psk_b64u);
    if (psk.length !== 32) {
      throw new Error("psk must be 32 bytes");
    }
  } catch (e) {
    throw new FlowersecError({ stage: "validate", code: "invalid_psk", path: "tunnel", message: "invalid e2ee_psk_b64u", cause: e });
  }
  const idleTimeoutSeconds = checkedGrant.idle_timeout_seconds;
  if (checkedGrant.role !== ControlRole.Role_client) {
    throw new FlowersecError({ stage: "validate", code: "role_mismatch", path: "tunnel", message: "expected role=client" });
  }
  const endpointInstanceId = opts.endpointInstanceId ?? base64urlEncode(randomBytes(24));
  let eidBytes: Uint8Array;
  try {
    eidBytes = base64urlDecode(endpointInstanceId);
  } catch (e) {
    throw new FlowersecError({
      stage: "validate",
      code: "invalid_endpoint_instance_id",
      path: "tunnel",
      message: "invalid endpointInstanceId",
      cause: e
    });
  }
  if (eidBytes.length < 16 || eidBytes.length > 32) {
    throw new FlowersecError({
      stage: "validate",
      code: "invalid_endpoint_instance_id",
      path: "tunnel",
      message: "endpointInstanceId must decode to 16..32 bytes"
    });
  }
  const attach: Attach = {
    v: 1,
    channel_id: checkedGrant.channel_id,
    role: TunnelRole.Role_client,
    token: checkedGrant.token,
    endpoint_instance_id: endpointInstanceId
  };
  const attachJson = JSON.stringify(attach);
  const keepaliveIntervalMs = opts.keepaliveIntervalMs ?? defaultKeepaliveIntervalMs(idleTimeoutSeconds);
  return await connectCore({
    path: "tunnel",
    wsUrl: checkedGrant.tunnel_url,
    channelId: checkedGrant.channel_id,
    e2eePskB64u: checkedGrant.e2ee_psk_b64u,
    defaultSuite: checkedGrant.default_suite,
    opts: { ...opts, keepaliveIntervalMs },
    attach: { attachJson, endpointInstanceId }
  });
}

function defaultKeepaliveIntervalMs(idleTimeoutSeconds: number): number {
  if (!Number.isFinite(idleTimeoutSeconds) || idleTimeoutSeconds <= 0) return 0;
  const idleMs = Math.floor(idleTimeoutSeconds * 1000);
  if (idleMs <= 0) return 0;
  let interval = Math.floor(idleMs / 2);
  if (interval < 500) interval = 500;
  if (interval >= idleMs) interval = Math.floor(idleMs / 2);
  return interval;
}
