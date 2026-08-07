import { expect, test } from "vitest";

import {
  ConnectError,
  createBrowserConnectionController,
  type ArtifactSource as BrowserArtifactSource,
  type BrowserConnectionControllerOptions,
  type ConnectionController as BrowserConnectionController,
} from "../browser/index.js";
import {
  createNodeConnectionController,
  type ArtifactSource as NodeArtifactSource,
  type ConnectionController as NodeConnectionController,
  type NodeConnectionControllerOptions,
} from "../node/index.js";
// @ts-expect-error runtime capability descriptors are package-internal.
import type { RuntimeCapabilityDescriptorV2 } from "../browser/index.js";
// @ts-expect-error candidate factories are package-internal.
import type { CandidateAttemptFactoryV2 } from "../node/index.js";

test("exports the final controller API from browser and Node entries", () => {
  expect(createBrowserConnectionController).toBeTypeOf("function");
  expect(createNodeConnectionController).toBeTypeOf("function");
  expect(ConnectError).toBeTypeOf("function");
  void (undefined as unknown as BrowserArtifactSource);
  void (undefined as unknown as NodeArtifactSource);
  void (undefined as unknown as BrowserConnectionController);
  void (undefined as unknown as NodeConnectionController);
  void (undefined as unknown as BrowserConnectionControllerOptions);
  void (undefined as unknown as NodeConnectionControllerOptions);
  void (undefined as unknown as RuntimeCapabilityDescriptorV2);
  void (undefined as unknown as CandidateAttemptFactoryV2);
});
