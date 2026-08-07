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

export type WebTransportClientFactoryV2 = (
  candidate: CanonicalArtifactCandidateV2,
  artifact: ArtifactV2,
  signal: AbortSignal,
) => Promise<NativeCarrierSessionV2>;

export function createWebTransportCandidateFactoryV2(
  factory: WebTransportClientFactoryV2,
): CandidateAttemptFactoryV2 {
  return {
    create(candidate, artifact) {
      if (candidate.carrier !== "webtransport") {
        throw new Error(`unsupported WebTransport carrier ${candidate.carrier}`);
      }
      return new WebTransportCandidateAttempt(candidate, artifact, factory);
    },
  };
}

class WebTransportCandidateAttempt implements CandidateAttemptV2 {
  private readonly controller = new AbortController();
  private carrier: NativeCarrierSessionV2 | undefined;
  private finalized = false;

  constructor(
    readonly candidate: CanonicalArtifactCandidateV2,
    private readonly artifact: ArtifactV2,
    private readonly factory: WebTransportClientFactoryV2,
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
          const stream = carrier.kind === "webtransport"
            ? await carrier.acceptStream(options)
            : await carrier.openStream(options);
          return {
            framing: "stream",
            stream,
            abort: (error) => stream.abort(error),
          };
        },
        finalize: () => {
          if (this.finalized) throw new Error("WebTransport candidate already finalized");
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
    this.controller.abort(new Error("WebTransport candidate aborted"));
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
