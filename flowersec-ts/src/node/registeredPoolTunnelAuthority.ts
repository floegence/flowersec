import { prepareTunnelEndpointDialer, type TunnelEndpointDialerPreparation } from "./endpointDialer.js";
import { NodePoolServerAllowReceiver, type NodePoolServerAllowReceiverOptions, type PoolServerAllowBinding } from "./poolServerAllow.js";
import { observeTask } from "../v4/runtime/taskObservation.js";
import { createPublicKey } from "node:crypto";
import type { V4TransportEnvironment } from "../v4/public.js";
import { originalEnvironment, type EnvironmentDependency, type V4CredentialBuffers, type V4CredentialLengths, type V4CredentialPolicy, type V4EnvironmentMaterial } from "../v4/runtime/environment.js";
import { CredentialWork, credentialWorkCharge, equalCredential, requireCredential } from "../v4/runtime/credentialSupport.js";
import { ResourceVector, type ResourceReference } from "../v4/runtime/resources.js";
import { TrustedDeadline, timerChunk } from "../v4/runtime/deadline.js";
import { createGrantIssuer, type GrantIssuer, type GrantIssuerOptions, type GrantIssuanceInput } from "./grantIssuerCurrent.js";
import { createAcceptor, type Acceptor, type AcceptorOptions } from "./acceptorCurrent.js";

type PoolListener = AcceptorOptions["listeners"][number];
type WithoutCredentials<Listener> = Listener extends PoolListener ? Omit<Listener, "credentials" | "preparation"> : never;
export interface RegisteredPoolTunnelAuthorityOptions {
  readonly issuer: GrantIssuerOptions;
  /** Original signed registration installed by the pool authority. */
  readonly material: GrantIssuanceInput;
  /** Endpoint B shares this Environment and the issuer's actual ParentWinner
   * store. Its service store must register that exact original authority. */
  readonly server: Omit<AcceptorOptions, "environment" | "listeners"> & Readonly<{
    listener: WithoutCredentials<PoolListener>;
    policy: V4CredentialPolicy;
  }>;
  readonly publicationMS: bigint;
  readonly serverAllow: NodePoolServerAllowReceiverOptions;
}
export interface RegisteredPoolTunnelMaterial extends GrantIssuanceInput {
  readonly clientGrant: Uint8Array;
  readonly serverGrant: Uint8Array;
}
const capability = Symbol("original registered pool tunnel authority");
/** A shared registered authority keeps the native server listener, original
 * pool registration, Grant signing, ParentWinner and server-local publication
 * in one Environment. It does not import publication or COMMIT receipts. */
export class RegisteredPoolTunnelAuthority {
  readonly #runtime: ReturnType<typeof originalEnvironment>;
  readonly #environment: V4TransportEnvironment;
  readonly #dependency: EnvironmentDependency;
  readonly #material: GrantIssuanceInput;
  readonly #issuer: GrantIssuer;
  #dialer: TunnelEndpointDialerPreparation | undefined;
  readonly #allowReceiver: NodePoolServerAllowReceiver;
  readonly #publicationReady: Promise<void>; #resolvePublication!: () => void; #rejectPublication!: (error: unknown) => void;
  readonly #serverOptions: RegisteredPoolTunnelAuthorityOptions["server"];
  readonly #publicationMS: bigint;
  readonly #serverGrant = new Uint8Array(65536);
  readonly #done: Promise<void>; #resolve!: () => void;
  #acceptor: Acceptor | undefined;
  #prepared: V4EnvironmentMaterial | undefined;
  #publication: ResourceReference | undefined;
  #credentialPreparation: ReturnType<ReturnType<typeof originalEnvironment>["prepareTunnelCredentials"]> | undefined;
  #deadline: TrustedDeadline | undefined;
  #timer: ReturnType<typeof setTimeout> | undefined;
  #grantLength = 0; #issued = false; #published = false; #consumed = false; #started = false;
  #busy = false; #closed = false; #released = false; #closing: Promise<void> | undefined;
  constructor(token: symbol, options: RegisteredPoolTunnelAuthorityOptions) {
    requireCredential(token === capability && options.material.source === "preauthorized_pool" && options.server.policy.tunnel?.role === 1 &&
      options.server.listener.path === "tunnel" && typeof options.publicationMS === "bigint" && options.publicationMS > 0n && options.publicationMS <= 60000n, "configuration_capacity");
    this.#environment = options.issuer.environment; this.#runtime = originalEnvironment(this.#environment);
    const input = options.material;
    requireCredential(Number.isSafeInteger(input.candidateIndex) && input.candidateIndex >= 0 && input.candidateIndex < 16 &&
      input.artifact.length > 0 && input.artifact.length <= 65536 && input.activation.length > 0 && input.activation.length <= 4096 &&
      [input.clientCertificate, input.serverCertificate, input.relayCertificate].every(bytes => bytes instanceof Uint8Array && bytes.length > 0 && bytes.length <= 8192), "configuration_capacity");
    this.#dependency = this.#runtime.admitDependency("registered_pool_tunnel_authority", new ResourceVector([BigInt(input.artifact.length + input.activation.length + input.clientCertificate.length + input.serverCertificate.length + input.relayCertificate.length) + 131072n + this.#runtime.resources.runtimeBytes, 0n, 0n, 16n, 1n, 1n, 0n, 0n, 0n, 0n, 0n]));
    this.#publicationReady = new Promise((resolve, reject) => { this.#resolvePublication = resolve; this.#rejectPublication = reject; }); void this.#publicationReady.catch(() => undefined);
    let issuer: GrantIssuer | undefined, material: GrantIssuanceInput | undefined;
    try {
      requireCredential(options.server.listener.admissionStore.hasOriginalParentWinner(options.issuer.activationStore, this.#dependency.reference), "credential_binding");
      this.#material = material = Object.freeze({ source: "preauthorized_pool", candidateIndex: input.candidateIndex, artifact: new Uint8Array(input.artifact), activation: new Uint8Array(input.activation),
        clientCertificate: new Uint8Array(input.clientCertificate), serverCertificate: new Uint8Array(input.serverCertificate), relayCertificate: new Uint8Array(input.relayCertificate) });
      issuer = createGrantIssuer(options.issuer); this.#issuer = issuer;
      // Listener adapters capture TLS, keys, carrier configuration and policy
      // before binding. Callback ownership remains with this original owner.
      const policy = options.server.policy;
      this.#serverOptions = Object.freeze({ ...options.server, policy: Object.freeze({ ...policy, authorities: Object.freeze([...policy.authorities]), cryptoProfiles: Object.freeze([...policy.cryptoProfiles]),
        ...(policy.tunnel === undefined ? {} : { tunnel: Object.freeze({ ...policy.tunnel }) }) }), listener: Object.freeze({ ...options.server.listener }) });
      this.#publicationMS = options.publicationMS;
      this.#done = new Promise(resolve => { this.#resolve = resolve; });
      this.#allowReceiver = new NodePoolServerAllowReceiver(this.#environment, options.serverAllow, (request, grant) => {
        this.#check(); requireCredential(this.#issued && !this.#published && !this.#consumed && this.#prepared !== undefined && this.#publication !== undefined, "credential_binding");
        this.#deadline!.check(); this.#runtime.acceptOriginalPoolServerAllow(this.#prepared, request, grant, this.#publication);
        this.#published = true; this.#resolvePublication();
      });
      this.#dependency.onClose(() => { void this.close(); }); Object.freeze(this);
    } catch (error) { issuer?.close(); for (const bytes of Object.values(material ?? {})) if (bytes instanceof Uint8Array) bytes.fill(0); this.#dependency.release(); throw error; }
  }
  #check(): void { requireCredential(!this.#closed, "credential_closed"); this.#dependency.check(); }
  /** The physical listener and fixed server transfer backing exist before
   * entering the original Grant issuance transaction. */
  async prepare(token: symbol): Promise<void> {
    this.#check(); requireCredential(token === capability && !this.#started); this.#started = true; this.#busy = true;
    let work: CredentialWork | undefined, reference: ResourceReference | undefined;
    try {
      reference = this.#runtime.reserveConnectionWork("registered_pool_server_route", credentialWorkCharge(131072, this.#runtime.resources.runtimeBytes));
      work = new CredentialWork(this.#runtime.resources, 131072, reference);
      const artifact = work.parse(this.#material.artifact, "Artifact", 65536, 16384), certificate = work.parse(this.#material.serverCertificate, "IdentityCertificate", 8192);
      try {
        const candidate = [...artifact.items("candidates")][this.#material.candidateIndex]!;
        const leg = artifact.field("server_leg", candidate, "Candidate"), listener = this.#serverOptions.listener;
        const carrier = "carrierKind" in listener ? listener.carrierKind ?? "wss" : "wss";
        const dialer = "physicalDirection" in listener;
        requireCredential(artifact.uint("path_kind", candidate, "Candidate") === 1n && artifact.uint("endpoint_role", leg, "Leg") === 1n &&
          artifact.uint("dialer_role", leg, "Leg") === (dialer ? 1n : 2n) && artifact.uint("listener_role", leg, "Leg") === (dialer ? 2n : 1n) &&
          artifact.text("host", leg, "Leg") === listener.serverName && artifact.uint("port", leg, "Leg") === BigInt(listener.port) &&
          artifact.uint("carrier", leg, "Leg") === (carrier === "wss" ? 1n : carrier === "webtransport" ? 2n : 0n), "credential_binding");
        const publicKey = createPublicKey(listener.identityKey).export({ format: "jwk" }), expected = certificate.bytes("ed25519_public_key"); let actualKey: Uint8Array | undefined;
        try { requireCredential(publicKey.crv === "Ed25519" && typeof publicKey.x === "string", "credential_binding"); actualKey = new Uint8Array(Buffer.from(publicKey.x, "base64url")); requireCredential(equalCredential(actualKey, expected), "credential_binding"); }
        finally { expected.fill(0); actualKey?.fill(0); }
      } finally { artifact.close(); certificate.close(); }
      const endpoint = this.#serverOptions.listener;
      if ("physicalDirection" in endpoint) this.#dialer = await prepareTunnelEndpointDialer({ environment: this.#environment, policy: this.#serverOptions.policy, material: { ...this.#material, tunnel: { relayCertificate: this.#material.relayCertificate } }, workMS: this.#publicationMS, carrierKind: endpoint.carrierKind, carrier: endpoint.carrier } as Parameters<typeof prepareTunnelEndpointDialer>[0]);
      const resolve = (request: Readonly<{ signal: AbortSignal; hello: Uint8Array }>, buffers: V4CredentialBuffers): Promise<V4CredentialLengths> => this.#resolveServer(request, buffers);
      this.#acceptor = await createAcceptor({ ...this.#serverOptions, environment: this.#environment, listeners: [{ ...this.#serverOptions.listener, ...(this.#dialer === undefined ? {} : { preparation: this.#dialer }),
        credentials: { source: "preauthorized_pool", policy: this.#serverOptions.policy, resolve, resolveHop: resolve, takePreparedHop: request => this.#takeServer(request) } } as PoolListener] });
      this.#check(); const actual = this.#acceptor.addresses();
      requireCredential(actual.length === 1 && actual[0]!.port === this.#serverOptions.listener.port, "credential_binding");
      await this.#allowReceiver.listen();
    } finally { work?.close(); reference?.release(); this.#busy = false; if (this.#closed) void this.close(); }
  }
  acceptor(): Acceptor { this.#check(); requireCredential(this.#acceptor !== undefined); return this.#acceptor; }
  poolServerAllowBinding(): PoolServerAllowBinding { this.#check(); return this.#allowReceiver.binding(); }
  /** Returning completes issuance and verified installation. B's activation
   * remains closed until A publishes after its own original TxA-P success. */
  async issue(): Promise<RegisteredPoolTunnelMaterial> {
    this.#check(); requireCredential(this.#acceptor !== undefined && !this.#busy && !this.#issued && !this.#consumed, "credential_binding"); this.#busy = true; this.#issued = true;
    let grants: Awaited<ReturnType<GrantIssuer["issue"]>> | undefined;
    try {
      this.#publication = this.#runtime.reserveConnectionWork("registered_pool_server_publication", new ResourceVector([65536n + this.#runtime.resources.runtimeBytes, 0n, 0n, 8n, 1n, 0n, 0n, 0n, 0n, 0n, 0n]));
      this.#deadline = TrustedDeadline.ageAt(this.#runtime.clock, this.#runtime.clock.sample(), this.#publicationMS, 0xffffffffffffffffn);
      this.#credentialPreparation = this.#runtime.prepareTunnelCredentials(this.#serverOptions.policy);
      grants = await this.#issuer.issue(this.#material); this.#check(); this.#deadline.check();
      this.#prepared = this.#runtime.verify(this.#serverOptions.policy, { ...this.#material, tunnel: { grant: grants.serverGrant, relayCertificate: this.#material.relayCertificate } }, this.#credentialPreparation);
      this.#credentialPreparation.close(); this.#credentialPreparation = undefined;
      this.#runtime.checkOriginalServerPublication(this.#prepared, this.#publication);
      requireCredential(grants.serverGrant.length <= this.#serverGrant.length, "configuration_capacity"); this.#serverGrant.set(grants.serverGrant); this.#grantLength = grants.serverGrant.length;
      const tick = (): void => {
        try { this.#check(); this.#deadline!.check(); this.#runtime.checkOriginalServerPublication(this.#prepared!, this.#publication!); this.#timer = setTimeout(tick, timerChunk(this.#deadline!.remainingMS())); }
        catch { this.#clearPublication(); }
      }; tick(); this.#check(); requireCredential(this.#prepared !== undefined, "credential_closed");
      return Object.freeze({ ...this.#material, artifact: new Uint8Array(this.#material.artifact), activation: new Uint8Array(this.#material.activation),
        clientCertificate: new Uint8Array(this.#material.clientCertificate), serverCertificate: new Uint8Array(this.#material.serverCertificate), relayCertificate: new Uint8Array(this.#material.relayCertificate),
        clientGrant: new Uint8Array(grants.clientGrant), serverGrant: new Uint8Array(grants.serverGrant) });
    } catch (error) { this.#clearPublication(); throw error; }
    finally { grants?.clientGrant.fill(0); grants?.serverGrant.fill(0); this.#busy = false; if (this.#closed) void this.close(); }
  }
  async #takeServer(request: Readonly<{ signal: AbortSignal; hello: Uint8Array }>): Promise<V4EnvironmentMaterial> {
    this.#check(); await observeTask(this.#publicationReady, request.signal); this.#check(); requireCredential(!request.signal.aborted && this.#published && !this.#consumed && this.#prepared !== undefined && this.#publication !== undefined, "credential_binding");
    this.#deadline!.check(); this.#runtime.checkOriginalServerPublication(this.#prepared, this.#publication);
    const reference = this.#runtime.reserveConnectionWork("registered_pool_server_hello", credentialWorkCharge(65536, this.#runtime.resources.runtimeBytes)); let work: CredentialWork | undefined;
    try {
      if ("physicalDirection" in this.#serverOptions.listener) requireCredential(request.hello.length === 0, "credential_binding");
      else { work = new CredentialWork(this.#runtime.resources, 65536, reference);
      const hello = work.parse(request.hello, "HOP_AUTH_HELLO", 65536, 16384, { selectors: { hop_sender_role: "relay" } });
      try { const certificate = hello.bytes("identity_certificate"); try { requireCredential(equalCredential(certificate, this.#material.relayCertificate), "credential_binding"); } finally { certificate.fill(0); } } finally { hello.close(); } }
      this.#check(); requireCredential(!request.signal.aborted); this.#runtime.checkOriginalServerPublication(this.#prepared, this.#publication);
      const prepared = this.#prepared; this.#prepared = undefined; this.#consumed = true;
      this.#clearPublication(); return prepared;
    } finally { work?.close(); reference.release(); }
  }
  async #resolveServer(_request: Readonly<{ signal: AbortSignal; hello: Uint8Array }>, _buffers: V4CredentialBuffers): Promise<V4CredentialLengths> {
    throw new Error("original_prepared_server_material_required");
  }
  #clearPublication(): void {
    if (!this.#published) this.#rejectPublication(new Error("credential_closed"));
    if (this.#timer !== undefined) clearTimeout(this.#timer); this.#timer = undefined;
    this.#credentialPreparation?.close(); this.#credentialPreparation = undefined;
    void this.#prepared?.closeMaterial(); this.#prepared = undefined; this.#publication?.release(); this.#publication = undefined; this.#serverGrant.fill(0); this.#grantLength = 0;
  }
  close(): Promise<void> {
    this.#closed = true; this.#rejectPublication(new Error("credential_closed")); this.#issuer.close(); this.#clearPublication();
    if (this.#busy) return this.#done;
    return this.#closing ??= (async () => {
      await this.#allowReceiver.close(); await this.#acceptor?.close(); await this.#dialer?.close(); if (this.#released) return;
      this.#released = true; for (const bytes of Object.values(this.#material)) if (bytes instanceof Uint8Array) bytes.fill(0); this.#dependency.release(); this.#resolve();
    })();
  }
}
export async function createRegisteredPoolTunnelAuthority(options: RegisteredPoolTunnelAuthorityOptions): Promise<RegisteredPoolTunnelAuthority> {
  const owner = new RegisteredPoolTunnelAuthority(capability, options);
  try { await owner.prepare(capability); return owner; } catch (error) { await owner.close(); throw error; }
}
Object.freeze(RegisteredPoolTunnelAuthority.prototype); Object.freeze(RegisteredPoolTunnelAuthority);
