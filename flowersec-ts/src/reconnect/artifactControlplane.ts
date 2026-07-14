import type { ConnectArtifact } from "../connect/artifact.js";
import {
  requestConnectArtifact,
  requestEntryConnectArtifact,
  type RequestConnectArtifactInput,
  type RequestEntryConnectArtifactInput,
} from "../controlplane/index.js";

export type ArtifactAcquireContext = Readonly<{
  traceId?: string;
  signal?: AbortSignal;
}>;

export type ArtifactSource =
  | Readonly<{ kind: "once"; artifact: ConnectArtifact }>
  | Readonly<{ kind: "refreshable"; acquire: (context: ArtifactAcquireContext) => Promise<ConnectArtifact> }>;

export function createControlplaneArtifactSource(
  input: RequestConnectArtifactInput | RequestEntryConnectArtifactInput,
): ArtifactSource {
  return {
    kind: "refreshable",
    acquire: async ({ traceId, signal }) => {
      const correlation = traceId === undefined ? input.correlation : { traceId };
      if ("entryTicket" in input) {
        return await requestEntryConnectArtifact({
          ...input,
          ...(correlation === undefined ? {} : { correlation }),
          ...(signal === undefined ? {} : { signal }),
        });
      }
      return await requestConnectArtifact({
        ...input,
        ...(correlation === undefined ? {} : { correlation }),
        ...(signal === undefined ? {} : { signal }),
      });
    },
  };
}

export function createArtifactResolver(source: ArtifactSource): (context: ArtifactAcquireContext) => Promise<ConnectArtifact> {
  let consumed = false;
  return async (context) => {
    if (source.kind === "refreshable") return await source.acquire(context);
    if (consumed) throw new Error("one-time artifact source has already been consumed");
    consumed = true;
    return source.artifact;
  };
}

export function updateTraceId(current: string | undefined, artifact: ConnectArtifact): string | undefined {
  return artifact.correlation?.trace_id ?? current;
}
