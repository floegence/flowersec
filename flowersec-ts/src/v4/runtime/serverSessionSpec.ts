import { reliableClientSpec, type ReliableClientLimits } from "./clientSessionSpec.js";
import { captureStreamSendQueueBytes } from "./sendBudget.js";
import type { ClientPreparationFields } from "./credentialVerifier.js";
import type { ReadyIdentitySigner } from "./noiseHandshake.js";
import type { V4AuthenticatedTransport } from "./session.js";
import type { V4EnvironmentSessionSpec } from "./environment.js";
import type { RPCApplicationConfig } from "./rpcApplication.js";
/** Both reliable roles share the same resource/feature negotiation rules. Only
 * local identity, direction and local send defaults depend on the role. */
export function reliableServerSpec(fields: ClientPreparationFields, transport: V4AuthenticatedTransport, signer: ReadyIdentitySigner,
  privateKey: Uint8Array, limits: ReliableClientLimits, runtimeBytes: bigint, application?: RPCApplicationConfig,
  applicationProfile: "services" | "execution" = "services"): V4EnvironmentSessionSpec {
  const spec = reliableClientSpec(fields, transport, signer, privateKey, limits, runtimeBytes, "not_applicable", application, applicationProfile);
  return { ...spec,
    noise: { ...spec.noise, role: "server", localStaticPublic: fields.noiseKeys[1]!, peerStaticPublic: fields.noiseKeys[0]! },
    peerReadyPublicKey: fields.identityKeys[0]!,
    ready: { ...spec.ready, localCertificateDigest: fields.identities[1]!, peerCertificateDigest: fields.identities[0]! },
    streams: { ...spec.streams, limits: { ...spec.streams.limits, direction: 1 }, streamSendQueueBytes: captureStreamSendQueueBytes(limits.streamSendQueueBytes, "server") } };
}
