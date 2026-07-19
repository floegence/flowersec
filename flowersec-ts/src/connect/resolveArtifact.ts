import type { ChannelInitGrant } from "../gen/flowersec/controlplane/v1.gen.js";
import type { DirectConnectInfo } from "../gen/flowersec/direct/v1.gen.js";
import { emitObserverDiagnostic, normalizeObserver, withObserverContext, type ClientObserverLike } from "../observability/observer.js";
import { FlowersecError, type FlowersecPath } from "../utils/errors.js";

import {
  assertConnectArtifact,
  type ConnectArtifact,
  type ScopeMetadataEntry,
} from "./artifact.js";

export type ConnectScopeResolver = (entry: ScopeMetadataEntry) => void | Promise<void>;

export type ConnectScopeResolverMap = Readonly<Record<string, ConnectScopeResolver>>;

type ResolveOptions = Readonly<{
  observer?: ClientObserverLike;
  scopeResolvers?: ConnectScopeResolverMap;
  relaxedOptionalScopeValidation?: boolean;
}>;

export type ResolvedConnectArtifact =
  | Readonly<{ kind: "tunnel"; input: ChannelInitGrant; observer?: ClientObserverLike }>
  | Readonly<{ kind: "direct"; input: DirectConnectInfo; observer?: ClientObserverLike }>;

async function validateArtifactScopes(
  artifact: ConnectArtifact,
  opts: ResolveOptions,
  observer: ClientObserverLike | undefined
): Promise<void> {
  const scoped = artifact.scoped ?? [];
  if (scoped.length === 0) return;
  const path: FlowersecPath = artifact.transport;
  for (const entry of scoped) {
    const resolver = opts.scopeResolvers?.[entry.scope];
    if (resolver == null) {
      if (entry.critical) {
        throw new FlowersecError({
          path,
          stage: "validate",
          code: "resolve_failed",
          message: `missing scope resolver for ${entry.scope}@${entry.scope_version}`,
        });
      }
      emitObserverDiagnostic(observer, {
        path,
        stage: "scope",
        code_domain: "event",
        code: "scope_ignored_missing_resolver",
        result: "skip",
      });
      continue;
    }
    try {
      await resolver(entry);
    } catch (error) {
      if (!entry.critical && opts.relaxedOptionalScopeValidation === true) {
        emitObserverDiagnostic(observer, {
          path,
          stage: "scope",
          code_domain: "event",
          code: "scope_ignored_relaxed_validation",
          result: "skip",
        });
        continue;
      }
      throw new FlowersecError({
        path,
        stage: "validate",
        code: "resolve_failed",
        message: `scope validation failed for ${entry.scope}@${entry.scope_version}`,
        cause: error,
      });
    }
  }
}

export async function resolveConnectArtifact(
  input: ConnectArtifact,
  opts: ResolveOptions = {}
): Promise<ResolvedConnectArtifact> {
  let artifact: ConnectArtifact;
  try {
    artifact = assertConnectArtifact(input);
  } catch (error) {
    throw new FlowersecError({
      path: "auto",
      stage: "validate",
      code: "invalid_input",
      message: "invalid ConnectArtifact",
      cause: error,
    });
  }

  const observer =
    opts.observer == null
      ? undefined
      : normalizeObserver(
          withObserverContext(opts.observer, {
            path: artifact.transport,
            ...(artifact.correlation?.trace_id === undefined ? {} : { traceId: artifact.correlation.trace_id }),
            ...(artifact.correlation?.session_id === undefined ? {} : { sessionId: artifact.correlation.session_id }),
          }),
          { path: artifact.transport }
        );
  await validateArtifactScopes(artifact, opts, observer);

  if (artifact.transport === "direct") {
    return {
      kind: "direct",
      input: artifact.direct_info,
      ...(observer === undefined ? {} : { observer }),
    };
  }
  return {
    kind: "tunnel",
    input: artifact.tunnel_grant,
    ...(observer === undefined ? {} : { observer }),
  };
}
