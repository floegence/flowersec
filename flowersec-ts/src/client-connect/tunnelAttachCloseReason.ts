import type { FlowersecErrorCode } from "../utils/errors.js";

export const tunnelAttachCloseReasons = [
  "too_many_connections",
  "expected_attach",
  "invalid_attach",
  "invalid_token",
  "channel_mismatch",
  "init_exp_mismatch",
  "idle_timeout_mismatch",
  "role_mismatch",
  "token_replay",
  "replace_rate_limited",
  "attach_failed",
  "timeout",
  "canceled"
] as const satisfies readonly FlowersecErrorCode[];

export type TunnelAttachCloseReason = (typeof tunnelAttachCloseReasons)[number];

export function isTunnelAttachCloseReason(v: string | undefined): v is TunnelAttachCloseReason {
  if (v == null) return false;
  return (tunnelAttachCloseReasons as readonly string[]).includes(v);
}
