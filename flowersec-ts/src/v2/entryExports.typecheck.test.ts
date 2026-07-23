import type {
  ArtifactAcquireContextOptionsV2 as BrowserArtifactAcquireContextOptionsV2,
  ArtifactVersionPolicyV2 as BrowserArtifactVersionPolicyV2,
  JsonPrimitiveV2 as BrowserJsonPrimitiveV2,
  JsonValueV2 as BrowserJsonValueV2,
  NetworkModeV2 as BrowserNetworkModeV2,
  OperationOptionsV2 as BrowserOperationOptionsV2,
  RuntimeCapabilityTupleV2 as BrowserRuntimeCapabilityTupleV2,
  SessionRoleV2 as BrowserSessionRoleV2,
  UnsupportedRuntimeCarrierV2 as BrowserUnsupportedRuntimeCarrierV2,
} from "../browser/index.js";
// @ts-expect-error candidate selection diagnostics are package-internal.
import type { FlowersecCandidateDiagnostic as BrowserFlowersecCandidateDiagnostic } from "../browser/index.js";
import { FlowersecError as BrowserFlowersecError } from "../browser/index.js";
import type {
  ArtifactAcquireContextOptionsV2 as NodeArtifactAcquireContextOptionsV2,
  ArtifactVersionPolicyV2 as NodeArtifactVersionPolicyV2,
  JsonPrimitiveV2 as NodeJsonPrimitiveV2,
  JsonValueV2 as NodeJsonValueV2,
  NetworkModeV2 as NodeNetworkModeV2,
  OperationOptionsV2 as NodeOperationOptionsV2,
  RuntimeCapabilityTupleV2 as NodeRuntimeCapabilityTupleV2,
  SessionRoleV2 as NodeSessionRoleV2,
  UnsupportedRuntimeCarrierV2 as NodeUnsupportedRuntimeCarrierV2,
} from "../node/index.js";
// @ts-expect-error candidate selection diagnostics are package-internal.
import type { FlowersecCandidateDiagnostic as NodeFlowersecCandidateDiagnostic } from "../node/index.js";
import { FlowersecError as NodeFlowersecError } from "../node/index.js";
// @ts-expect-error Internal carrier stages must not be exported by the browser entry.
import { createBrowserWebTransportCarrierInternalStage } from "../browser/index.js";
import { expect, test } from "vitest";

type BrowserTypes = readonly [
  BrowserArtifactAcquireContextOptionsV2,
  BrowserArtifactVersionPolicyV2,
  BrowserJsonPrimitiveV2,
  BrowserJsonValueV2,
  BrowserNetworkModeV2,
  BrowserOperationOptionsV2,
  BrowserRuntimeCapabilityTupleV2,
  BrowserSessionRoleV2,
  BrowserUnsupportedRuntimeCarrierV2,
  BrowserFlowersecCandidateDiagnostic,
];
type NodeTypes = readonly [
  NodeArtifactAcquireContextOptionsV2,
  NodeArtifactVersionPolicyV2,
  NodeJsonPrimitiveV2,
  NodeJsonValueV2,
  NodeNetworkModeV2,
  NodeOperationOptionsV2,
  NodeRuntimeCapabilityTupleV2,
  NodeSessionRoleV2,
  NodeUnsupportedRuntimeCarrierV2,
  NodeFlowersecCandidateDiagnostic,
];

test("keeps shared Transport v2 types importable from browser and Node entries", () => {
  expect(true).toBe(true);
  expect(BrowserFlowersecError).toBe(NodeFlowersecError);
  void createBrowserWebTransportCarrierInternalStage;
  void (undefined as unknown as BrowserTypes);
  void (undefined as unknown as NodeTypes);
});
