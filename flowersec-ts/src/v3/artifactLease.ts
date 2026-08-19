import type { ArtifactV3 } from "./artifact.js";

export class ArtifactLeaseV3Error extends Error {
  readonly code = "already_consumed";

  constructor() {
    super("Flowersec artifact lease is no longer available");
    this.name = "ArtifactLeaseError";
  }
}

type LeaseState = {
  readonly artifact: ArtifactV3;
  status: "idle" | "claimed" | "spending" | "consumed" | "retired";
  readonly commit: (signal?: AbortSignal) => Promise<void>;
  readonly cleanup?: (() => Promise<void>) | undefined;
  cleanupStarted: boolean;
};

const leaseStates = new WeakMap<ArtifactLeaseV3, LeaseState>();
const claimStates = new WeakMap<ClaimedArtifactLeaseV3, LeaseState>();

export class ArtifactLeaseV3 {
  declare private readonly leaseBrand: void;
  private constructor() {}
}

export class ClaimedArtifactLeaseV3 {
  declare private readonly claimBrand: void;
  private constructor() {}
}

/** @internal Artifact sources construct idle one-shot leases through this boundary. */
export function createArtifactLeaseV3Internal(
  artifact: ArtifactV3,
  commitSpend: (signal?: AbortSignal) => Promise<void>,
  retireCleanup?: () => Promise<void>,
): ArtifactLeaseV3 {
  if (typeof commitSpend !== "function" || (retireCleanup !== undefined && typeof retireCleanup !== "function")) {
    throw new TypeError("invalid Flowersec v3 artifact lease callbacks");
  }
  const lease = new (ArtifactLeaseV3 as unknown as { new(): ArtifactLeaseV3 })();
  leaseStates.set(lease, {
    artifact,
    status: "idle",
    commit: commitSpend,
    cleanup: retireCleanup,
    cleanupStarted: false,
  });
  return Object.freeze(lease) as ArtifactLeaseV3;
}

/** @internal Creates another handle over the same atomic state for race tests and wrappers. */
export function duplicateArtifactLeaseHandleV3(lease: ArtifactLeaseV3): ArtifactLeaseV3 {
  const state = leaseStates.get(lease);
  if (state === undefined) throw new ArtifactLeaseV3Error();
  const copy = new (ArtifactLeaseV3 as unknown as { new(): ArtifactLeaseV3 })();
  leaseStates.set(copy, state);
  return Object.freeze(copy) as ArtifactLeaseV3;
}

export function claimArtifactLeaseV3(lease: ArtifactLeaseV3): ClaimedArtifactLeaseV3 {
  const state = leaseStates.get(lease);
  if (state === undefined || state.status !== "idle") throw new ArtifactLeaseV3Error();
  state.status = "claimed";
  const claim = new (ClaimedArtifactLeaseV3 as unknown as { new(): ClaimedArtifactLeaseV3 })();
  claimStates.set(claim, state);
  return Object.freeze(claim) as ClaimedArtifactLeaseV3;
}

export function claimedArtifactV3(claim: ClaimedArtifactLeaseV3): ArtifactV3 {
  const state = claimStates.get(claim);
  if (state === undefined || (state.status !== "claimed" && state.status !== "spending")) {
    throw new ArtifactLeaseV3Error();
  }
  return state.artifact;
}

export async function commitArtifactLeaseSpendV3(
  claim: ClaimedArtifactLeaseV3,
  signal?: AbortSignal,
): Promise<void> {
  const state = claimStates.get(claim);
  if (state === undefined || state.status !== "claimed") throw new ArtifactLeaseV3Error();
  state.status = "spending";
  const callback = Promise.resolve().then(() => state.commit(signal));
  let abort: (() => void) | undefined;
  try {
    if (signal === undefined) {
      await callback;
    } else {
      const canceled = new Promise<never>((_, reject) => {
        abort = () => reject(signal.reason ?? new Error("artifact spend canceled"));
        if (signal.aborted) abort();
        else signal.addEventListener("abort", abort, { once: true });
      });
      await Promise.race([callback, canceled]);
    }
  } finally {
    if (signal !== undefined && abort !== undefined) signal.removeEventListener("abort", abort);
    state.status = "consumed";
    // A cancellation result is authoritative for the lease even when an
    // application callback ignores the signal and settles later.
    void callback.catch(() => undefined);
  }
}

export async function retireArtifactLeaseV3(claim: ClaimedArtifactLeaseV3): Promise<void> {
  const state = claimStates.get(claim);
  if (state === undefined || state.status !== "claimed") throw new ArtifactLeaseV3Error();
  state.status = "retired";
  if (state.cleanup === undefined || state.cleanupStarted) return;
  state.cleanupStarted = true;
  try {
    await state.cleanup();
  } catch {
    // Retirement is final. Cleanup failures are deliberately not allowed to
    // restore or leak ownership of a one-shot credential.
  }
}

/** @internal */
export function artifactLeaseStateV3(
  lease: ArtifactLeaseV3 | ClaimedArtifactLeaseV3,
): "idle" | "claimed" | "spending" | "consumed" | "retired" {
  const state = lease instanceof ArtifactLeaseV3 ? leaseStates.get(lease) : claimStates.get(lease);
  if (state === undefined) throw new ArtifactLeaseV3Error();
  return state.status;
}
