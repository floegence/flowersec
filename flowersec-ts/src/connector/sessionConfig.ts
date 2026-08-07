import { admissionBindingV2, type ArtifactV2 } from "../v2/artifact.js";
import { base64urlDecode } from "../utils/base64url.js";
import type { SessionConfigV2, SessionDeadlineFactoryV2, SessionProtocolRuntimeV2 } from "../v2/session.js";

const SESSION_CLOSE_TIMEOUT_MS = 5_000;

export function sessionConfigFromArtifactV2(
  artifact: ArtifactV2,
  rawFSB2: Uint8Array,
  runtime: SessionProtocolRuntimeV2,
  deadlineFactory?: SessionDeadlineFactoryV2,
  role?: SessionConfigV2["role"],
): SessionConfigV2 {
  const localBinding = admissionBindingV2(rawFSB2);
  const tunnel = artifact.path.kind === "tunnel" ? artifact.path : undefined;
  return {
    role: role ?? (tunnel?.role === 2 ? "server" : "client"),
    path: artifact.path.kind,
    channelID: artifact.session.channel_id,
    sessionContractHash: base64urlDecode(artifact.session.contract_hash_b64u),
    suite: artifact.session.default_suite,
    psk: base64urlDecode(artifact.session.e2ee_psk_b64u),
    maxInboundStreams: artifact.session.max_inbound_streams,
    sessionContract: artifact.session,
    idleTimeoutMs: artifact.session.idle_timeout_seconds * 1_000,
    closeTimeoutMs: SESSION_CLOSE_TIMEOUT_MS,
    runtime,
    localAdmissionBinding: localBinding,
    peerAdmissionBinding: tunnel === undefined ? localBinding : new Uint8Array(32),
    localEndpointInstanceID: tunnel?.local_endpoint_instance_id ?? "",
    expectedPeerEndpointInstanceID: tunnel?.expected_peer_endpoint_instance_id ?? "",
    deadlines: {
      establishTimeoutMs: artifact.session.establish_timeout_seconds * 1_000,
      rekeyPrepareTimeoutMs: artifact.session.rekey_prepare_timeout_seconds * 1_000,
      rekeyCompletionTimeoutMs: artifact.session.rekey_completion_timeout_seconds * 1_000,
      ...(deadlineFactory === undefined ? {} : { factory: deadlineFactory }),
    },
  };
}
