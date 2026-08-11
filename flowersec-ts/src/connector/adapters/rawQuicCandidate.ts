import type { ArtifactV2, CanonicalArtifactCandidateV2 } from "../../v2/artifact.js";
import {
  adaptNativeCarrierSessionV2,
  type NativeCarrierSessionV2,
} from "../../v2/carrier.js";
import type { ReadyAdmissionTransportV2 } from "../admissionCommit.js";
import type {
  CandidateAttemptFactoryV2,
  CandidateAttemptV2,
} from "../sessionConnector.js";

export type RawQuicClientFactoryV2 = (
  candidate: CanonicalArtifactCandidateV2,
  artifact: ArtifactV2,
  signal: AbortSignal,
) => Promise<NativeCarrierSessionV2>;

export function createRawQuicCandidateFactoryV2(
  factory: RawQuicClientFactoryV2,
): CandidateAttemptFactoryV2 {
  return {
    create(candidate, artifact) {
      if (candidate.carrier !== "raw_quic") {
        throw new Error(`unsupported raw QUIC carrier ${candidate.carrier}`);
      }
      return new RawQuicCandidateAttempt(candidate, artifact, factory);
    },
  };
}

class RawQuicCandidateAttempt implements CandidateAttemptV2 {
  private readonly controller = new AbortController();
  private carrier: NativeCarrierSessionV2 | undefined;
  private finalized = false;

  constructor(
    readonly candidate: CanonicalArtifactCandidateV2,
    private readonly artifact: ArtifactV2,
    private readonly factory: RawQuicClientFactoryV2,
  ) {}

  async ready(signal?: AbortSignal): Promise<ReadyAdmissionTransportV2> {
    const unlink = linkAbort(signal, this.controller);
    try {
      const carrier = await this.factory(this.candidate, this.artifact, this.controller.signal);
      this.carrier = carrier;
      return {
        candidate: this.candidate,
        kind: carrier.kind,
        path: carrier.path,
        inboundBidirectionalStreamCapacity: carrier.inboundBidirectionalStreamCapacity,
        openAdmissionChannel: async (channelSignal) => {
          const options = channelSignal === undefined ? {} : { signal: channelSignal };
          const stream = await carrier.openStream(options);
          return {
            framing: "stream",
            stream,
            abort: (error) => stream.abort(error),
          };
        },
        finalize: () => {
          if (this.finalized) throw new Error("raw QUIC candidate already finalized");
          this.finalized = true;
          return adaptNativeCarrierSessionV2(carrier);
        },
        close: async () => await carrier.close(),
        abort: () => carrier.abort({ code: 6, reason: "candidate aborted" }),
      };
    } finally {
      unlink();
    }
  }

  abort(): void {
    this.controller.abort(new Error("raw QUIC candidate aborted"));
    this.carrier?.abort({ code: 6, reason: "candidate aborted" });
  }
}

function linkAbort(parent: AbortSignal | undefined, child: AbortController): () => void {
  if (parent === undefined) return () => undefined;
  const abort = () => child.abort(parent.reason);
  if (parent.aborted) abort();
  else parent.addEventListener("abort", abort, { once: true });
  return () => parent.removeEventListener("abort", abort);
}
