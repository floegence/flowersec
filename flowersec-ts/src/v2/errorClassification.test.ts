import { describe, expect, test } from "vitest";

import {
  classifyConnectErrorV2,
  classifySessionErrorV2,
  ConnectError,
  SessionError,
} from "../facade.js";

describe("public error retry classification", () => {
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

