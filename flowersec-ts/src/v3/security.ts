import { base64urlDecode } from "../utils/base64url.js";
import type { CertificatePinV3, TransportSecurityPolicyV3 } from "./artifact.js";

export type TransportFailureCodeV3 =
  | "invalid_artifact"
  | "expired_artifact"
  | "tls_unsupported"
  | "tls_policy_expired"
  | "tls_failed"
  | "connection_failed";

export type TransportFailureDetailV3 =
  | "ca_untrusted"
  | "pin_mismatch"
  | "unknown"
  | "browser_pin_opaque";

export class TransportFailureV3 extends Error {
  constructor(
    readonly code: TransportFailureCodeV3,
    readonly detail?: TransportFailureDetailV3,
    cause?: unknown,
  ) {
    super("Flowersec v3 transport attempt failed", { cause });
    this.name = "TransportFailureV3";
  }
}

export type PublicConnectErrorCodeV3 =
  | "artifact_invalid"
  | "expired_artifact"
  | "transport_security_unsupported"
  | "transport_security_failed"
  | "connection_failed";

export type RetryDispositionV3 =
  | Readonly<{ kind: "terminal" }>
  | Readonly<{ kind: "retryable" }>
  | Readonly<{
      kind: "retry_after";
      notBeforeUnixMilliseconds: number;
    }>;

type RetryDispositionInputV3 = RetryDispositionV3;

export class ConnectErrorV3 extends Error {
  readonly retryDisposition: RetryDispositionV3;

  constructor(
    readonly code: PublicConnectErrorCodeV3,
    disposition: RetryDispositionInputV3,
  ) {
    super(`Flowersec connection failed (code=${code})`);
    this.name = "ConnectError";
    this.retryDisposition = validateRetryDispositionValueV3(disposition);
  }

}

export type TransportSecuritySnapshotV3 =
  | Readonly<{ mode: "ca" }>
  | Readonly<{
      mode: "pin";
      activePins: readonly CertificatePinV3[];
      activeLeafDerSHA256: readonly Uint8Array[];
    }>;

export function snapshotTransportSecurityPolicyV3(
  policy: TransportSecurityPolicyV3,
  attemptNowUnixSeconds: number,
  supportedModes: readonly ("ca" | "pin")[],
): TransportSecuritySnapshotV3 {
  if (!Number.isSafeInteger(attemptNowUnixSeconds) || attemptNowUnixSeconds < 0) {
    throw new TransportFailureV3("invalid_artifact");
  }
  if (!supportedModes.includes(policy.mode)) throw new TransportFailureV3("tls_unsupported");
  if (policy.mode === "ca") return Object.freeze({ mode: "ca" });
  const activePins = policy.pins.filter((pin) => attemptNowUnixSeconds < pin.not_after_unix_s);
  if (activePins.length === 0) throw new TransportFailureV3("tls_policy_expired");
  let decoded: Uint8Array[];
  try {
    decoded = activePins.map((pin) => {
      const bytes = base64urlDecode(pin.value_b64u);
      if (bytes.length !== 32) throw new Error("invalid pin length");
      return bytes;
    });
  } catch (error) {
    throw new TransportFailureV3("invalid_artifact", undefined, error);
  }
  return Object.freeze({
    mode: "pin",
    activePins: Object.freeze([...activePins]),
    activeLeafDerSHA256: Object.freeze(decoded),
  });
}

export function projectTransportFailureV3(
  failure: TransportFailureV3,
  _policyMode: "ca" | "pin",
): ConnectErrorV3 {
  switch (failure.code) {
    case "invalid_artifact":
      return new ConnectErrorV3("artifact_invalid", terminal());
    case "expired_artifact":
      return new ConnectErrorV3("expired_artifact", retryable());
    case "tls_unsupported":
      return new ConnectErrorV3("transport_security_unsupported", terminal());
    case "tls_policy_expired":
    case "tls_failed":
      return new ConnectErrorV3("transport_security_failed", terminal());
    case "connection_failed":
      return new ConnectErrorV3("connection_failed", retryable());
  }
}

export function validateRetryDispositionV3(value: RetryDispositionInputV3): RetryDispositionV3 {
  try {
    return validateRetryDispositionValueV3(value);
  } catch {
    throw new ConnectErrorV3("artifact_invalid", terminal());
  }
}

export function aggregateRetryDispositionsV3(values: readonly RetryDispositionInputV3[]): RetryDispositionV3 {
  let latest: number | undefined;
  let canRetry = false;
  for (const input of values) {
    const value = validateRetryDispositionV3(input);
    if (value.kind === "retry_after") {
      latest = Math.max(latest ?? 0, value.notBeforeUnixMilliseconds);
    }
    else if (value.kind === "retryable") canRetry = true;
  }
  if (latest !== undefined) return retryAfter(latest);
  return canRetry ? retryable() : terminal();
}

export function controllerBackoffMillisecondsV3(consecutiveFailure: number): number {
  if (!Number.isSafeInteger(consecutiveFailure) || consecutiveFailure < 1) {
    throw new RangeError("consecutive failure ordinal must be positive");
  }
  if (consecutiveFailure >= 8) return 30_000;
  return Math.min(250 * 2 ** (consecutiveFailure - 1), 30_000);
}

const terminal = (): RetryDispositionV3 => Object.freeze({ kind: "terminal" });
const retryable = (): RetryDispositionV3 => Object.freeze({ kind: "retryable" });

const retryAfter = (notBeforeUnixMilliseconds: number): RetryDispositionV3 => Object.freeze({
  kind: "retry_after",
  notBeforeUnixMilliseconds,
});

function validateRetryDispositionValueV3(value: RetryDispositionInputV3): RetryDispositionV3 {
  if (value.kind === "terminal") return terminal();
  if (value.kind === "retryable") return retryable();
  const deadline = value.notBeforeUnixMilliseconds;
  if (!Number.isSafeInteger(deadline) || deadline < 0 || deadline > 253_402_300_799_999) {
    throw new TypeError("invalid Flowersec retry-after deadline");
  }
  return retryAfter(deadline);
}
