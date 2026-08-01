import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";

import {
  classifyConnectError,
  classifySessionError,
  ConnectError,
  SessionError,
} from "../facade.js";

type ContractDecision = Readonly<{
  action: "retry" | "refresh_artifact" | "stop";
  retryable: boolean;
  refresh_artifact: boolean;
  caller_canceled: boolean;
  session_closed: boolean;
}>;

type ContractCase = Readonly<{
  decision: string;
  codes: Readonly<Record<string, readonly string[]>>;
}>;

type ClassificationContract = Readonly<{
  decisions: Readonly<Record<string, ContractDecision>>;
  connect: readonly ContractCase[];
  session: readonly ContractCase[];
}>;

const sharedContract = JSON.parse(
  readFileSync(new URL("../../../stability/public_error_classification.json", import.meta.url), "utf8"),
) as ClassificationContract;

describe("public error retry classification", () => {
  test("matches the shared cross-language contract", () => {
    for (const testCase of sharedContract.connect) {
      const expected = sharedContract.decisions[testCase.decision];
      expect(expected).toBeDefined();
      if (expected === undefined) throw new Error(`missing decision ${testCase.decision}`);
      for (const code of testCase.codes.typescript ?? []) {
        expect(classifyConnectError(new ConnectError(code as ConstructorParameters<typeof ConnectError>[0]))).toEqual({
          action: expected.action,
          retryable: expected.retryable,
          refreshArtifact: expected.refresh_artifact,
          callerCanceled: expected.caller_canceled,
          sessionClosed: expected.session_closed,
        });
      }
    }

    for (const testCase of sharedContract.session) {
      const expected = sharedContract.decisions[testCase.decision];
      expect(expected).toBeDefined();
      if (expected === undefined) throw new Error(`missing decision ${testCase.decision}`);
      for (const code of testCase.codes.typescript ?? []) {
        expect(classifySessionError(new SessionError(code as ConstructorParameters<typeof SessionError>[0]))).toEqual({
          action: expected.action,
          retryable: expected.retryable,
          refreshArtifact: expected.refresh_artifact,
          callerCanceled: expected.caller_canceled,
          sessionClosed: expected.session_closed,
        });
      }
    }
  });

  test("classifies connection failures without exposing internal diagnostics", () => {
    expect(classifyConnectError(new ConnectError("timeout"))).toEqual({
      action: "refresh_artifact",
      retryable: true,
      refreshArtifact: true,
      callerCanceled: false,
      sessionClosed: false,
    });
    expect(classifyConnectError(new ConnectError("expired_artifact"))).toEqual({
      action: "refresh_artifact",
      retryable: true,
      refreshArtifact: true,
      callerCanceled: false,
      sessionClosed: false,
    });
    expect(classifyConnectError(new ConnectError("canceled"))).toEqual({
      action: "stop",
      retryable: false,
      refreshArtifact: false,
      callerCanceled: true,
      sessionClosed: false,
    });
    expect(classifyConnectError(new ConnectError("invalid_options"))).toEqual({
      action: "stop",
      retryable: false,
      refreshArtifact: false,
      callerCanceled: false,
      sessionClosed: false,
    });
    expect(Object.keys(classifyConnectError(new ConnectError("connection_failed"))).sort()).toEqual([
      "action",
      "callerCanceled",
      "refreshArtifact",
      "retryable",
      "sessionClosed",
    ]);
  });

  test("classifies session failures for operation retry or fresh session acquisition", () => {
    expect(classifySessionError(new SessionError("timeout"))).toEqual({
      action: "retry",
      retryable: true,
      refreshArtifact: false,
      callerCanceled: false,
      sessionClosed: false,
    });
    expect(classifySessionError(new SessionError("closed"))).toEqual({
      action: "refresh_artifact",
      retryable: true,
      refreshArtifact: true,
      callerCanceled: false,
      sessionClosed: true,
    });
    expect(classifySessionError(new SessionError("canceled"))).toEqual({
      action: "stop",
      retryable: false,
      refreshArtifact: false,
      callerCanceled: true,
      sessionClosed: false,
    });
    expect(classifySessionError(new SessionError("stream_rejected"))).toEqual({
      action: "stop",
      retryable: false,
      refreshArtifact: false,
      callerCanceled: false,
      sessionClosed: false,
    });
    expect(classifySessionError(new SessionError("unreliable_unavailable"))).toEqual({
      action: "stop",
      retryable: false,
      refreshArtifact: false,
      callerCanceled: false,
      sessionClosed: false,
    });
    expect(classifySessionError(new SessionError("unreliable_too_large"))).toEqual({
      action: "stop",
      retryable: false,
      refreshArtifact: false,
      callerCanceled: false,
      sessionClosed: false,
    });
    expect(classifySessionError(new SessionError("unreliable_dropped"))).toEqual({
      action: "stop",
      retryable: false,
      refreshArtifact: false,
      callerCanceled: false,
      sessionClosed: false,
    });
  });
});
