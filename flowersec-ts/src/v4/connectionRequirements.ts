import type { V4ConnectionRequirements } from "../generated/transportV4APIResults.js";

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
