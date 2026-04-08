import type { ConnectArtifact } from "../connect/artifact.js";
import {
  requestConnectArtifact,
  requestEntryConnectArtifact,
  type RequestConnectArtifactInput,
  type RequestEntryConnectArtifactInput,
} from "../controlplane/index.js";

export type ArtifactFactoryArgs = Readonly<{
  traceId?: string;
  signal?: AbortSignal;
}>;

export type ArtifactAwareReconnectConfig = Readonly<{
  artifact?: ConnectArtifact;
  getArtifact?: (args: ArtifactFactoryArgs) => Promise<ConnectArtifact>;
  artifactControlplane?: RequestConnectArtifactInput | RequestEntryConnectArtifactInput;
}>;

export async function resolveConnectArtifact(
  config: ArtifactAwareReconnectConfig,
  traceId?: string,
  signal?: AbortSignal
): Promise<ConnectArtifact> {
  if (config.getArtifact) {
    return await config.getArtifact({
      ...(traceId === undefined ? {} : { traceId }),
      ...(signal === undefined ? {} : { signal }),
    });
  }
  if (config.artifact) return config.artifact;
  if (config.artifactControlplane) {
    const correlation =
      traceId === undefined
        ? config.artifactControlplane.correlation
        : ({ traceId } satisfies Readonly<{ traceId?: string }>);
    if ("entryTicket" in config.artifactControlplane) {
      const input: RequestEntryConnectArtifactInput = {
        ...config.artifactControlplane,
        ...(correlation === undefined ? {} : { correlation }),
        ...(signal === undefined ? {} : { signal }),
      };
      return await requestEntryConnectArtifact(input);
    }
    const input: RequestConnectArtifactInput = {
      ...config.artifactControlplane,
      ...(correlation === undefined ? {} : { correlation }),
      ...(signal === undefined ? {} : { signal }),
    };
    return await requestConnectArtifact(input);
  }
  throw new Error("Artifact reconnect config requires `getArtifact`, `artifact`, or `artifactControlplane`");
}

export function updateTraceId(current: string | undefined, artifact: ConnectArtifact): string | undefined {
  return artifact.correlation?.trace_id ?? current;
}
