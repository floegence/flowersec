import type {
  ArtifactAcquireContextOptionsV2 as BrowserArtifactAcquireContextOptionsV2,
  ArtifactVersionPolicyV2 as BrowserArtifactVersionPolicyV2,
  BrowserSessionConnectorV2Options,
  JsonPrimitiveV2 as BrowserJsonPrimitiveV2,
  JsonValueV2 as BrowserJsonValueV2,
  OperationOptionsV2 as BrowserOperationOptionsV2,
  SessionError as BrowserSessionError,
} from "../browser/index.js";
// @ts-expect-error runtime capability descriptors are package-internal.
import type { RuntimeCapabilityDescriptorV2 as BrowserRuntimeCapabilityDescriptorV2 } from "../browser/index.js";
// @ts-expect-error candidate selection diagnostics are package-internal.
import type { FlowersecCandidateDiagnostic as BrowserFlowersecCandidateDiagnostic } from "../browser/index.js";
import { ConnectError as BrowserConnectError } from "../browser/index.js";
import type {
  ArtifactAcquireContextOptionsV2 as NodeArtifactAcquireContextOptionsV2,
  ArtifactVersionPolicyV2 as NodeArtifactVersionPolicyV2,
  JsonPrimitiveV2 as NodeJsonPrimitiveV2,
  JsonValueV2 as NodeJsonValueV2,
  OperationOptionsV2 as NodeOperationOptionsV2,
  NodeSessionConnectorV2Options,
  SessionError as NodeSessionError,
} from "../node/index.js";
// @ts-expect-error runtime capability descriptors are package-internal.
import type { RuntimeCapabilityDescriptorV2 as NodeRuntimeCapabilityDescriptorV2 } from "../node/index.js";
// @ts-expect-error candidate selection diagnostics are package-internal.
import type { FlowersecCandidateDiagnostic as NodeFlowersecCandidateDiagnostic } from "../node/index.js";
import { ConnectError as NodeConnectError } from "../node/index.js";
// @ts-expect-error Internal carrier stages must not be exported by the browser entry.
import { createBrowserWebTransportCarrierInternalStage } from "../browser/index.js";
import { expect, test } from "vitest";

type BrowserTypes = readonly [
  BrowserArtifactAcquireContextOptionsV2,
  BrowserArtifactVersionPolicyV2,
  BrowserJsonPrimitiveV2,
  BrowserJsonValueV2,
  BrowserOperationOptionsV2,
  BrowserSessionError,
  BrowserRuntimeCapabilityDescriptorV2,
  BrowserFlowersecCandidateDiagnostic,
];
type NodeTypes = readonly [
  NodeArtifactAcquireContextOptionsV2,
  NodeArtifactVersionPolicyV2,
  NodeJsonPrimitiveV2,
  NodeJsonValueV2,
  NodeOperationOptionsV2,
  NodeSessionError,
  NodeRuntimeCapabilityDescriptorV2,
  NodeFlowersecCandidateDiagnostic,
];

test("keeps shared Transport v2 types importable from browser and Node entries", () => {
  expect(true).toBe(true);
  expect(BrowserConnectError).toBe(NodeConnectError);
  void createBrowserWebTransportCarrierInternalStage;
  void (undefined as unknown as BrowserTypes);
  void (undefined as unknown as NodeTypes);
});

function typecheckOpaqueConnectorOptions(
  browserOptions: BrowserSessionConnectorV2Options,
  nodeOptions: NodeSessionConnectorV2Options,
  browserError: BrowserConnectError,
): void {
  void browserOptions;
  void nodeOptions;
  const leakedAdmissionReasons: BrowserSessionConnectorV2Options = {
    // @ts-expect-error admission policy is runtime-owned.
    admissionReasons: new Set(),
  };
  const leakedNodeCarrier: NodeSessionConnectorV2Options = {
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
