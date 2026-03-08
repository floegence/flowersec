import type { ChannelInitGrant, Role as ControlRole, Suite as ControlSuite } from "../gen/flowersec/controlplane/v1.gen.js";
import type { DirectConnectInfo } from "../gen/flowersec/direct/v1.gen.js";

import { base64urlDecode } from "../utils/base64url.js";
import { FlowersecError, type FlowersecPath } from "../utils/errors.js";

const textEncoder = new TextEncoder();

export const CHANNEL_ID_MAX_BYTES = 256;

export function prepareChannelId(raw: string, path: Exclude<FlowersecPath, "auto">): string {
  const channelId = typeof raw === "string" ? raw.trim() : "";
  if (channelId === "") {
    throw new FlowersecError({ path, stage: "validate", code: "missing_channel_id", message: "missing channel_id" });
  }
  if (textEncoder.encode(channelId).length > CHANNEL_ID_MAX_BYTES) {
    throw new FlowersecError({ path, stage: "validate", code: "invalid_input", message: "channel_id too long" });
  }
  return channelId;
}

export function assertTunnelGrantContract(grant: ChannelInitGrant, expectedRole: ControlRole): void {
  if (grant.role !== expectedRole) {
    throw new FlowersecError({ stage: "validate", code: "role_mismatch", path: "tunnel", message: `expected role=${expectedRole === 1 ? "client" : "server"}` });
  }
  const allowedSuites = Array.isArray(grant.allowed_suites) ? grant.allowed_suites : [];
  if (allowedSuites.length === 0) {
    throw new FlowersecError({ stage: "validate", code: "invalid_suite", path: "tunnel", message: "allowed_suites must be non-empty" });
  }
  for (const suite of allowedSuites) {
    assertSupportedSuite(suite, "tunnel");
  }
  assertSupportedSuite(grant.default_suite, "tunnel");
  if (!allowedSuites.includes(grant.default_suite)) {
    throw new FlowersecError({ stage: "validate", code: "invalid_suite", path: "tunnel", message: "default_suite must be included in allowed_suites" });
  }
}

export function assertDirectConnectContract(info: DirectConnectInfo): void {
  assertSupportedSuite(info.default_suite, "direct");
}

export function assertValidPSK(raw: string, path: Exclude<FlowersecPath, "auto">): string {
  const pskB64u = typeof raw === "string" ? raw.trim() : "";
  try {
    const psk = base64urlDecode(pskB64u);
    if (psk.length !== 32) {
      throw new Error("psk must be 32 bytes");
    }
  } catch (e) {
    throw new FlowersecError({ stage: "validate", code: "invalid_psk", path, message: "invalid e2ee_psk_b64u", cause: e });
  }
  return pskB64u;
}

function assertSupportedSuite(suite: number, path: Exclude<FlowersecPath, "auto">): asserts suite is ControlSuite {
  if (suite !== 1 && suite !== 2) {
    throw new FlowersecError({ stage: "validate", code: "invalid_suite", path, message: "invalid suite" });
  }
}
