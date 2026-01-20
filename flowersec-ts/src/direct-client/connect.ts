import type { DirectConnectInfo } from "../gen/flowersec/direct/v1.gen.js";
import { assertDirectConnectInfo } from "../gen/flowersec/direct/v1.gen.js";
import { base64urlDecode } from "../utils/base64url.js";
import { FlowersecError } from "../utils/errors.js";
import { connectCore, type ConnectOptionsBase } from "../client-connect/connectCore.js";
import type { ClientInternal } from "../client.js";

// DirectConnectOptions controls transport and handshake limits.
export type DirectConnectOptions = ConnectOptionsBase;

// connectDirect connects to a direct websocket endpoint and returns an RPC-ready session.
export async function connectDirect(info: unknown, opts: DirectConnectOptions): Promise<ClientInternal> {
  const endpointInstanceId = (opts as any)?.endpointInstanceId;
  if (endpointInstanceId != null) {
    throw new FlowersecError({
      stage: "validate",
      code: "invalid_option",
      path: "direct",
      message: "endpointInstanceId is only valid for tunnel connects",
    });
  }
  if (info == null) {
    throw new FlowersecError({ stage: "validate", code: "missing_connect_info", path: "direct", message: "missing connect info" });
  }
  let ready: DirectConnectInfo;
  try {
    ready = assertDirectConnectInfo(info);
  } catch (e) {
    throw new FlowersecError({ stage: "validate", code: "invalid_input", path: "direct", message: "invalid DirectConnectInfo", cause: e });
  }
  if (ready.ws_url === "") {
    throw new FlowersecError({ stage: "validate", code: "missing_ws_url", path: "direct", message: "missing ws_url" });
  }
  if (ready.channel_id === "") {
    throw new FlowersecError({ stage: "validate", code: "missing_channel_id", path: "direct", message: "missing channel_id" });
  }
  if (ready.channel_init_expire_at_unix_s <= 0) {
    throw new FlowersecError({
      stage: "validate",
      code: "missing_init_exp",
      path: "direct",
      message: "missing channel_init_expire_at_unix_s",
    });
  }
  try {
    const psk = base64urlDecode(ready.e2ee_psk_b64u);
    if (psk.length !== 32) {
      throw new Error("psk must be 32 bytes");
    }
  } catch (e) {
    throw new FlowersecError({ stage: "validate", code: "invalid_psk", path: "direct", message: "invalid e2ee_psk_b64u", cause: e });
  }
  return await connectCore({
    path: "direct",
    wsUrl: ready.ws_url,
    channelId: ready.channel_id,
    e2eePskB64u: ready.e2ee_psk_b64u,
    defaultSuite: ready.default_suite,
    opts,
  });
}
