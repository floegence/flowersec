import type { V4ConnectionRequirements, V4SessionInfo } from "../generated/transportV4APIResults.js";

/** Capture optional local requirements without choosing the material's profile. */
export function captureConnectionRequirements(input: Partial<V4ConnectionRequirements> = {}): V4ConnectionRequirements {
  if (input === null || typeof input !== "object") throw new Error("invalid_argument");
  const boolean = (value: unknown): boolean => {
    if (value === undefined) return false;
    if (typeof value !== "boolean") throw new Error("invalid_argument");
    return value;
  };
  const applicationProfile = input.application_profile;
  if (applicationProfile !== undefined && applicationProfile !== "transport" && applicationProfile !== "services" && applicationProfile !== "execution") {
    throw new Error("invalid_argument");
  }
  return Object.freeze({
    independent_reliable_read_progress: boolean(input.independent_reliable_read_progress),
    bound_stream_input_isolation: boolean(input.bound_stream_input_isolation),
    datagram: boolean(input.datagram),
    local_consumer_tls13_verification: boolean(input.local_consumer_tls13_verification),
    ...(applicationProfile === undefined ? {} : { application_profile: applicationProfile }),
  });
}

/** Check original caller requirements against the actual assembled path. */
export function requireConnectionGuarantees(request: V4ConnectionRequirements, info: V4SessionInfo): void {
  const guarantees = info.guarantees;
  if (request.application_profile !== undefined && request.application_profile !== info.application_profile ||
      request.independent_reliable_read_progress && guarantees.reliable_progress !== "independent_within_profile" ||
      request.bound_stream_input_isolation && guarantees.bound_stream_input_isolation !== "bound_stream_within_profile" ||
      request.datagram && !guarantees.datagram ||
      request.local_consumer_tls13_verification && guarantees.local_consumer_tls13_verification !== "consumer_enforced") {
    throw new Error("connection_requirement_unavailable");
  }
}
