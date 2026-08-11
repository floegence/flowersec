import { expect, test } from "vitest";

import {
  ConnectError,
  createConnectionController as createBrowserConnectionController,
  type ArtifactSource as BrowserArtifactSource,
  type ConnectionControllerOptions as BrowserConnectionControllerOptions,
  type ConnectionController as BrowserConnectionController,
  type ConnectionSnapshot as BrowserConnectionSnapshot,
  type RetryDisposition as BrowserRetryDisposition,
} from "../browser/index.js";
import {
  createConnectionController as createNodeConnectionController,
  type ArtifactSource as NodeArtifactSource,
  type ConnectionController as NodeConnectionController,
  type ConnectionSnapshot as NodeConnectionSnapshot,
  type ConnectionControllerOptions as NodeConnectionControllerOptions,
  type RetryDisposition as NodeRetryDisposition,
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
  const browserDisposition = (snapshot: BrowserConnectionSnapshot): BrowserRetryDisposition | undefined => snapshot.retryDisposition;
  const nodeDisposition = (snapshot: NodeConnectionSnapshot): NodeRetryDisposition | undefined => snapshot.retryDisposition;
  void browserDisposition;
  void nodeDisposition;
  void (undefined as unknown as RuntimeCapabilityDescriptorV2);
  void (undefined as unknown as CandidateAttemptFactoryV2);
});
