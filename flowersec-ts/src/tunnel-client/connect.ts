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

function unwrapGrantClient(v: unknown): unknown {
  if (v == null || typeof v !== "object") return v;
  const o = v as Record<string, unknown>;
  if (o["grant_client"] != null) return o["grant_client"];
  return v;
}

// connectTunnel attaches to a tunnel and returns an RPC-ready session.
export async function connectTunnel(grant: unknown, opts: TunnelConnectOptions): Promise<ClientInternal> {
  const input = unwrapGrantClient(grant);
  if (input == null) {
    throw new FlowersecError({ stage: "validate", code: "missing_grant", path: "tunnel", message: "missing grant" });
  }
  let checkedGrant: ChannelInitGrant;
  try {
    checkedGrant = assertChannelInitGrant(input);
  } catch (e) {
    throw new FlowersecError({ stage: "validate", code: "invalid_grant", path: "tunnel", message: "invalid ChannelInitGrant", cause: e });
  }
  if (checkedGrant.tunnel_url === "") {
    throw new FlowersecError({ stage: "validate", code: "missing_tunnel_url", path: "tunnel", message: "missing tunnel_url" });
  }
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
  return await connectCore({
    path: "tunnel",
    wsUrl: checkedGrant.tunnel_url,
    channelId: checkedGrant.channel_id,
    e2eePskB64u: checkedGrant.e2ee_psk_b64u,
    defaultSuite: checkedGrant.default_suite,
    opts,
    attach: { attachJson, endpointInstanceId }
  });
}
