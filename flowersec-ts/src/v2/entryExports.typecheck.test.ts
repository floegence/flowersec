import type {
  ArtifactAcquireContextOptions as BrowserArtifactAcquireContextOptions,
  ArtifactVersionPolicy as BrowserArtifactVersionPolicy,
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
  ArtifactAcquireContextOptions as NodeArtifactAcquireContextOptions,
  ArtifactVersionPolicy as NodeArtifactVersionPolicy,
  ErrorRetryClassification as NodeErrorRetryClassification,
  JsonPrimitive as NodeJsonPrimitive,
  JsonValue as NodeJsonValue,
  NodeSessionOptions,
  OperationOptions as NodeOperationOptions,
  RetryAction as NodeRetryAction,
  SessionError as NodeSessionError,
} from "../node/index.js";
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
  BrowserArtifactAcquireContextOptions,
  BrowserArtifactVersionPolicy,
  BrowserErrorRetryClassification,
  BrowserRetryAction,
  BrowserJsonPrimitive,
  BrowserJsonValue,
  BrowserOperationOptions,
  BrowserSessionError,
  BrowserRuntimeCapabilityDescriptorV2,
  BrowserFlowersecCandidateDiagnostic,
  BrowserSessionConnectorV2Options,
];
type NodeTypes = readonly [
  NodeArtifactAcquireContextOptions,
  NodeArtifactVersionPolicy,
  NodeErrorRetryClassification,
  NodeRetryAction,
  NodeJsonPrimitive,
  NodeJsonValue,
  NodeOperationOptions,
  NodeSessionError,
  NodeRuntimeCapabilityDescriptorV2,
  NodeFlowersecCandidateDiagnostic,
  NodeSessionConnectorV2Options,
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
  // @ts-expect-error public connection errors expose only their closed code.
  void browserError.path;
  // @ts-expect-error public connection errors expose only their closed code.
  void browserError.stage;
  void leakedAdmissionReasons;
  void leakedNodeCarrier;
}

test("keeps connector policy and diagnostics package-internal", () => {
  expect(typecheckOpaqueConnectorOptions).toBeTypeOf("function");
});
