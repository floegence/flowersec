import type { OperationOptions } from "../../public/contract.js";
import type { V4AuthenticatedTransport } from "./session.js";
import type { VerifiedRelayCredentials } from "./relayCredentials.js";
import type { ReadyIdentitySigner } from "./noiseHandshake.js";
import type { RandomFill } from "./random.js";
import type { TrustedDeadline } from "./deadline.js";
import type { ResourceReference } from "./resources.js";
import { credentialOwner, requireCredential, type CredentialResources } from "./credentialSupport.js";
import { HopAuthentication, HopAuthenticationPreparation, hopAuthenticationCharge } from "./hopAuthentication.js";

/** Original browser maintenance transport; no deployment statement, source
 * response or relay HELLO can replace its actual four-flight possession proof. */
export async function authenticateEndpointHop(transport: V4AuthenticatedTransport, credentials: VerifiedRelayCredentials, signer: ReadyIdentitySigner, random: RandomFill,
  resources: CredentialResources, reference: ResourceReference, deadline: TrustedDeadline, options?: OperationOptions, acceptedHello?: Uint8Array, prepared?: HopAuthenticationPreparation): Promise<void> {
  let reservation: ResourceReference | HopAuthenticationPreparation | undefined = prepared, hop: HopAuthentication | undefined; const incarnation = new Uint8Array(16);
  try {
    transport.checkPreparation?.(); deadline.check(); requireCredential(transport.role === (credentials.role === 0 ? "client" : "server"));
    reservation ??= resources.root.reserve({ owner: credentialOwner(resources, "endpoint_hop"), accounts: resources.accounts, charge: hopAuthenticationCharge(resources.runtimeBytes) }); random(incarnation);
    hop = new HopAuthentication({ resources, transport, credentials, localRole: credentials.role, localIncarnation: incarnation, random, signer, deadline,
      guard: () => transport.checkPreparation?.(), ...(acceptedHello === undefined ? {} : { acceptedHello }) }, reservation, reference); await hop.authenticateEndpoint(options);
  } finally { hop?.close(); incarnation.fill(0); if (reservation instanceof HopAuthenticationPreparation) reservation.close(); else reservation?.release(); }
}
