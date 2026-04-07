import { Role as ControlRole } from "../gen/flowersec/controlplane/v1.gen.js";
import { emitObserverDiagnostic, normalizeObserver, withObserverContext, type ClientObserverLike } from "../observability/observer.js";
import { FlowersecError, type FlowersecPath } from "../utils/errors.js";

import {
  assertConnectArtifact,
  hasArtifactOnlyFields,
  type ConnectArtifact,
  type CorrelationContext,
  type ScopeMetadataEntry,
} from "./artifact.js";

export type ConnectScopeResolver = (entry: ScopeMetadataEntry) => void | Promise<void>;

export type ConnectScopeResolverMap = Readonly<Record<string, ConnectScopeResolver>>;

type NormalizeOptions = Readonly<{
  observer?: ClientObserverLike;
  scopeResolvers?: ConnectScopeResolverMap;
  relaxedOptionalScopeValidation?: boolean;
}>;

export type NormalizedConnectInput =
  | Readonly<{ kind: "tunnel"; input: unknown; correlation?: CorrelationContext; observer?: ClientObserverLike }>
  | Readonly<{ kind: "direct"; input: unknown; correlation?: CorrelationContext; observer?: ClientObserverLike }>;

function maybeParseJSON(input: unknown): unknown {
  if (typeof input !== "string") return input;
  const s = input.trim();
  if (s === "") return input;
  if (s[0] !== "{" && s[0] !== "[") return input;
  try {
    return JSON.parse(s);
  } catch (e) {
    throw new FlowersecError({
      path: "auto",
      stage: "validate",
      code: "invalid_input",
      message: "invalid JSON string",
      cause: e,
    });
  }
}

async function validateArtifactScopes(
  artifact: ConnectArtifact,
  opts: NormalizeOptions,
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
    } catch (e) {
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
        cause: e,
      });
    }
  }
}

export async function normalizeConnectInput(input: unknown, opts: NormalizeOptions = {}): Promise<NormalizedConnectInput> {
  const v = maybeParseJSON(input);
  if (v == null || typeof v !== "object") {
    throw new FlowersecError({
      path: "auto",
      stage: "validate",
      code: "invalid_input",
      message: "invalid input: expected an object or a JSON string",
    });
  }

  const o = v as Record<string, unknown>;
  const hasWsUrl = Object.prototype.hasOwnProperty.call(o, "ws_url");
  const hasTunnelUrl = Object.prototype.hasOwnProperty.call(o, "tunnel_url");
  const hasGrantClient = Object.prototype.hasOwnProperty.call(o, "grant_client");
  const hasGrantServer = Object.prototype.hasOwnProperty.call(o, "grant_server");
  const isArtifactCandidate = hasArtifactOnlyFields(o);

  if ((hasWsUrl && (hasTunnelUrl || hasGrantClient || hasGrantServer)) || (hasTunnelUrl && (hasGrantClient || hasGrantServer))) {
    throw new FlowersecError({
      path: "auto",
      stage: "validate",
      code: "invalid_input",
      message: "hybrid connect input is not allowed",
    });
  }
  if (isArtifactCandidate && (hasWsUrl || hasTunnelUrl || hasGrantClient || hasGrantServer)) {
    throw new FlowersecError({
      path: "auto",
      stage: "validate",
      code: "invalid_input",
      message: "artifact fields cannot be mixed with legacy connect inputs",
    });
  }
  if (hasGrantServer) {
    throw new FlowersecError({
      path: "tunnel",
      stage: "validate",
      code: "role_mismatch",
      message: "expected role=client",
    });
  }
  if (hasGrantClient) return { kind: "tunnel", input: v };
  if (hasWsUrl) return { kind: "direct", input: v };
  if (hasTunnelUrl) {
    if (typeof o.role === "number" && Number.isSafeInteger(o.role) && o.role === ControlRole.Role_server) {
      throw new FlowersecError({
        path: "tunnel",
        stage: "validate",
        code: "role_mismatch",
        message: "expected role=client",
      });
    }
    return { kind: "tunnel", input: v };
  }
  if (isArtifactCandidate) {
    let artifact: ConnectArtifact;
    try {
      artifact = assertConnectArtifact(v);
    } catch (e) {
      throw new FlowersecError({
        path: "auto",
        stage: "validate",
        code: "invalid_input",
        message: "invalid ConnectArtifact",
        cause: e,
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
        ...(artifact.correlation === undefined ? {} : { correlation: artifact.correlation }),
        ...(observer === undefined ? {} : { observer }),
      };
    }
    return {
      kind: "tunnel",
      input: artifact.tunnel_grant,
      ...(artifact.correlation === undefined ? {} : { correlation: artifact.correlation }),
      ...(observer === undefined ? {} : { observer }),
    };
  }
  throw new FlowersecError({
    path: "auto",
    stage: "validate",
    code: "invalid_input",
    message: "invalid input: expected DirectConnectInfo, ChannelInitGrant, wrapper, or ConnectArtifact",
  });
}
