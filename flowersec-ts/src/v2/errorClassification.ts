import type { SessionErrorCode } from "./contract.js";
import type { ConnectErrorCode } from "../utils/errors.js";

export type FlowersecRetryActionV2 = "retry" | "refresh_artifact" | "stop";

export type FlowersecErrorRetryClassificationV2 = Readonly<{
  action: FlowersecRetryActionV2;
  retryable: boolean;
  refreshArtifact: boolean;
  callerCanceled: boolean;
  sessionClosed: boolean;
}>;

export function classifyConnectErrorV2(error: Readonly<{ code: ConnectErrorCode }>): FlowersecErrorRetryClassificationV2 {
  if (error.code === "canceled") return classify("stop", { callerCanceled: true });
  if (error.code === "invalid_input" || error.code === "invalid_options") return classify("stop");
  return classify("refresh_artifact");
}

export function classifySessionErrorV2(error: Readonly<{ code: SessionErrorCode }>): FlowersecErrorRetryClassificationV2 {
  switch (error.code) {
    case "canceled":
      return classify("stop", { callerCanceled: true });
    case "closed":
    case "going_away":
      return classify("refresh_artifact", { sessionClosed: true });
    case "timeout":
    case "resource_exhausted":
    case "stream_reset":
    case "rekey_failed":
    case "liveness_failed":
      return classify("retry");
    case "stream_rejected":
    case "unreliable_unavailable":
    case "unreliable_too_large":
    case "unreliable_dropped":
    case "operation_failed":
      return classify("stop");
  }
}

function classify(
  action: FlowersecRetryActionV2,
  flags: Readonly<{ callerCanceled?: boolean; sessionClosed?: boolean }> = {},
): FlowersecErrorRetryClassificationV2 {
  return Object.freeze({
    action,
    retryable: action !== "stop",
    refreshArtifact: action === "refresh_artifact",
    callerCanceled: flags.callerCanceled === true,
    sessionClosed: flags.sessionClosed === true,
  });
}
