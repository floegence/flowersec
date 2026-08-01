import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";

import {
  classifyConnectErrorV2,
  classifySessionErrorV2,
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
      for (const code of testCase.codes.typescript ?? []) {
        expect(classifyConnectErrorV2(new ConnectError(code as ConstructorParameters<typeof ConnectError>[0]))).toEqual({
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
      for (const code of testCase.codes.typescript ?? []) {
        expect(classifySessionErrorV2(new SessionError(code as ConstructorParameters<typeof SessionError>[0]))).toEqual({
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
    expect(classifyConnectErrorV2(new ConnectError("timeout"))).toEqual({
      action: "refresh_artifact",
      retryable: true,
      refreshArtifact: true,
      callerCanceled: false,
      sessionClosed: false,
    });
    expect(classifyConnectErrorV2(new ConnectError("expired_artifact"))).toEqual({
      action: "refresh_artifact",
      retryable: true,
      refreshArtifact: true,
      callerCanceled: false,
      sessionClosed: false,
    });
    expect(classifyConnectErrorV2(new ConnectError("canceled"))).toEqual({
      action: "stop",
      retryable: false,
      refreshArtifact: false,
      callerCanceled: true,
      sessionClosed: false,
    });
    expect(classifyConnectErrorV2(new ConnectError("invalid_options"))).toEqual({
      action: "stop",
      retryable: false,
      refreshArtifact: false,
      callerCanceled: false,
      sessionClosed: false,
    });
    expect(Object.keys(classifyConnectErrorV2(new ConnectError("connection_failed"))).sort()).toEqual([
      "action",
      "callerCanceled",
      "refreshArtifact",
      "retryable",
      "sessionClosed",
    ]);
  });

  test("classifies session failures for operation retry or fresh session acquisition", () => {
    expect(classifySessionErrorV2(new SessionError("timeout"))).toEqual({
      action: "retry",
      retryable: true,
      refreshArtifact: false,
      callerCanceled: false,
      sessionClosed: false,
    });
    expect(classifySessionErrorV2(new SessionError("closed"))).toEqual({
      action: "refresh_artifact",
      retryable: true,
      refreshArtifact: true,
      callerCanceled: false,
      sessionClosed: true,
    });
    expect(classifySessionErrorV2(new SessionError("canceled"))).toEqual({
      action: "stop",
      retryable: false,
      refreshArtifact: false,
      callerCanceled: true,
      sessionClosed: false,
    });
    expect(classifySessionErrorV2(new SessionError("stream_rejected"))).toEqual({
      action: "stop",
      retryable: false,
      refreshArtifact: false,
      callerCanceled: false,
      sessionClosed: false,
    });
  });
});
