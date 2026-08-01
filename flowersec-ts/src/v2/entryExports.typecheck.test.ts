import type {
  BrowserSessionOptions,
  ErrorRetryClassification as BrowserErrorRetryClassification,
  JsonPrimitive as BrowserJsonPrimitive,
  JsonValue as BrowserJsonValue,
  OperationOptions as BrowserOperationOptions,
  RetryAction as BrowserRetryAction,
  SessionError as BrowserSessionError,
} from "../browser/index.js";
// @ts-expect-error runtime capability descriptors are package-internal.
import type { RuntimeCapabilityDescriptorV2 as BrowserRuntimeCapabilityDescriptorV2 } from "../browser/index.js";
// @ts-expect-error candidate selection diagnostics are package-internal.
import type { FlowersecCandidateDiagnostic as BrowserFlowersecCandidateDiagnostic } from "../browser/index.js";
import {
  classifyConnectError as classifyBrowserConnectError,
  classifySessionError as classifyBrowserSessionError,
  ConnectError as BrowserConnectError,
} from "../browser/index.js";
import type {
  ErrorRetryClassification as NodeErrorRetryClassification,
  JsonPrimitive as NodeJsonPrimitive,
  JsonValue as NodeJsonValue,
  NodeSessionOptions,
  OperationOptions as NodeOperationOptions,
  RetryAction as NodeRetryAction,
  SessionError as NodeSessionError,
} from "../node/index.js";
// @ts-expect-error acquisition orchestration is available only from the reconnect subpath.
import type { ArtifactAcquireContextOptions as RootArtifactAcquireContextOptions } from "../facade.js";
// @ts-expect-error reconnect orchestration is available only from the reconnect subpath.
import type { SessionReconnectConfig as RootSessionReconnectConfig } from "../facade.js";
// @ts-expect-error a v2-only SDK does not expose a single-value version policy.
import type { ArtifactVersionPolicy as RootArtifactVersionPolicy } from "../facade.js";
// @ts-expect-error acquisition orchestration is available only from the reconnect subpath.
import type { ArtifactAcquireContextOptions as BrowserArtifactAcquireContextOptions } from "../browser/index.js";
// @ts-expect-error a v2-only SDK does not expose a single-value version policy.
import type { ArtifactVersionPolicy as BrowserArtifactVersionPolicy } from "../browser/index.js";
// @ts-expect-error acquisition orchestration is available only from the reconnect subpath.
import type { ArtifactAcquireContextOptions as NodeArtifactAcquireContextOptions } from "../node/index.js";
// @ts-expect-error a v2-only SDK does not expose a single-value version policy.
import type { ArtifactVersionPolicy as NodeArtifactVersionPolicy } from "../node/index.js";
// @ts-expect-error runtime capability descriptors are package-internal.
import type { RuntimeCapabilityDescriptorV2 as NodeRuntimeCapabilityDescriptorV2 } from "../node/index.js";
// @ts-expect-error candidate selection diagnostics are package-internal.
import type { FlowersecCandidateDiagnostic as NodeFlowersecCandidateDiagnostic } from "../node/index.js";
import {
  classifyConnectError as classifyNodeConnectError,
  classifySessionError as classifyNodeSessionError,
  ConnectError as NodeConnectError,
} from "../node/index.js";
// @ts-expect-error Application-level v2 names are not exported by the browser entry.
import type { BrowserSessionConnectorV2Options } from "../browser/index.js";
// @ts-expect-error Application-level v2 names are not exported by the Node entry.
import type { NodeSessionConnectorV2Options } from "../node/index.js";
// @ts-expect-error Application-level v2 functions are not exported by the browser entry.
import { classifyConnectErrorV2 } from "../browser/index.js";
// @ts-expect-error Application-level v2 functions are not exported by the Node entry.
import { classifySessionErrorV2 } from "../node/index.js";
// @ts-expect-error Internal carrier stages must not be exported by the browser entry.
import { createBrowserWebTransportCarrierInternalStage } from "../browser/index.js";
import { expect, test } from "vitest";

type BrowserTypes = readonly [
  BrowserErrorRetryClassification,
  BrowserRetryAction,
  BrowserJsonPrimitive,
  BrowserJsonValue,
  BrowserOperationOptions,
  BrowserSessionError,
  BrowserRuntimeCapabilityDescriptorV2,
  BrowserFlowersecCandidateDiagnostic,
  BrowserSessionConnectorV2Options,
  BrowserArtifactAcquireContextOptions,
  BrowserArtifactVersionPolicy,
];
type NodeTypes = readonly [
  NodeErrorRetryClassification,
  NodeRetryAction,
  NodeJsonPrimitive,
  NodeJsonValue,
  NodeOperationOptions,
  NodeSessionError,
  NodeRuntimeCapabilityDescriptorV2,
  NodeFlowersecCandidateDiagnostic,
  NodeSessionConnectorV2Options,
  NodeArtifactAcquireContextOptions,
  NodeArtifactVersionPolicy,
];
type RootRemovedTypes = readonly [
  RootArtifactAcquireContextOptions,
  RootSessionReconnectConfig,
  RootArtifactVersionPolicy,
];

test("keeps shared Transport v2 types importable from browser and Node entries", () => {
  expect(true).toBe(true);
  expect(BrowserConnectError).toBe(NodeConnectError);
  expect(classifyBrowserConnectError).toBe(classifyNodeConnectError);
  expect(classifyBrowserSessionError).toBe(classifyNodeSessionError);
  void classifyConnectErrorV2;
  void classifySessionErrorV2;
  void createBrowserWebTransportCarrierInternalStage;
  void (undefined as unknown as BrowserTypes);
  void (undefined as unknown as NodeTypes);
  void (undefined as unknown as RootRemovedTypes);
});

function typecheckOpaqueConnectorOptions(
  browserOptions: BrowserSessionOptions,
  nodeOptions: NodeSessionOptions,
  browserError: BrowserConnectError,
): void {
  void browserOptions;
  void nodeOptions;
  const leakedAdmissionReasons: BrowserSessionOptions = {
    // @ts-expect-error admission policy is runtime-owned.
    admissionReasons: new Set(),
  };
  const leakedNodeCarrier: NodeSessionOptions = {
    origin: "https://app.example",
    // @ts-expect-error Node carrier tuning is package-internal.
    webSocket: {},
  };
  const leakedBrowserClock: BrowserSessionOptions = {
    // @ts-expect-error clock injection is package-internal.
    now: () => 0,
  };
  const leakedBrowserCleanup: BrowserSessionOptions = {
    // @ts-expect-error candidate cleanup tuning is package-internal.
    loserCloseTimeoutMs: 1,
  };
  const leakedNodeClock: NodeSessionOptions = {
    origin: "https://app.example",
    // @ts-expect-error clock injection is package-internal.
    now: () => 0,
  };
  const leakedNodeCleanup: NodeSessionOptions = {
    origin: "https://app.example",
    // @ts-expect-error candidate cleanup tuning is package-internal.
    loserCloseTimeoutMs: 1,
  };
  // @ts-expect-error public connection errors expose only their closed code.
  void browserError.path;
  // @ts-expect-error public connection errors expose only their closed code.
  void browserError.stage;
  void leakedAdmissionReasons;
  void leakedNodeCarrier;
  void leakedBrowserClock;
  void leakedBrowserCleanup;
  void leakedNodeClock;
  void leakedNodeCleanup;
}

test("keeps connector policy and diagnostics package-internal", () => {
  expect(typecheckOpaqueConnectorOptions).toBeTypeOf("function");
});
