import { expect, test } from "vitest";

import {
  ConnectError,
  StreamHandlers as BrowserStreamHandlers,
  createConnectionController as createBrowserConnectionController,
  v2 as BrowserV2,
  type ArtifactSource as BrowserArtifactSource,
  type ConnectionControllerOptions as BrowserConnectionControllerOptions,
  type ConnectionController as BrowserConnectionController,
  type ConnectionSnapshot as BrowserConnectionSnapshot,
  type RetryDisposition as BrowserRetryDisposition,
} from "../browser/index.js";
import {
  createConnectionController as createNodeConnectionController,
  StreamHandlers as NodeStreamHandlers,
  v2 as NodeV2,
  type ArtifactSource as NodeArtifactSource,
  type ConnectionController as NodeConnectionController,
  type ConnectionSnapshot as NodeConnectionSnapshot,
  type ConnectionControllerOptions as NodeConnectionControllerOptions,
  type RetryDisposition as NodeRetryDisposition,
} from "../node/index.js";
import type { StreamHandlerRegistrar as NodeStreamHandlerRegistrar } from "../node/v2.js";
// @ts-expect-error runtime capability descriptors are package-internal.
import type { RuntimeCapabilityDescriptorV2 } from "../browser/index.js";
// @ts-expect-error candidate factories are package-internal.
import type { CandidateAttemptFactoryV2 } from "../node/index.js";
// @ts-expect-error the sealed ProxyServer registrar is Node-only.
import type { StreamHandlerRegistrar as BrowserStreamHandlerRegistrar } from "../browser/index.js";
// @ts-expect-error the portable root does not expose the server registrar.
import type { StreamHandlerRegistrar as RootStreamHandlerRegistrar } from "../facade.js";

// @ts-expect-error only SDK-owned registries satisfy the nominal registrar.
const forgedStreamHandlerRegistrar: NodeStreamHandlerRegistrar = {
  handleStream() {},
  async serve() {},
};

test("exports the final controller API from browser and Node entries", () => {
  expect(createBrowserConnectionController).toBeTypeOf("function");
  expect(createNodeConnectionController).toBeTypeOf("function");
  expect(ConnectError).toBeTypeOf("function");
  expect(BrowserStreamHandlers).toBe(NodeStreamHandlers);
  expect(BrowserV2.StreamHandlers).toBe(NodeV2.StreamHandlers);
  expect(BrowserV2.StreamHandlers).not.toBe(BrowserStreamHandlers);
  const v3Handlers = new BrowserStreamHandlers();
  expect(() => v3Handlers.handleStream("flowersec.rpc.v3", async () => undefined)).toThrow();
  expect(() => v3Handlers.handleStream("flowersec.rpc.v2", async () => undefined)).not.toThrow();
  const v2Handlers = new BrowserV2.StreamHandlers();
  expect(() => v2Handlers.handleStream("flowersec.rpc.v2", async () => undefined)).toThrow();
  expect(() => v2Handlers.handleStream("flowersec.rpc.v3", async () => undefined)).not.toThrow();
  expect(BrowserV2.connect).toBeTypeOf("function");
  expect(NodeV2.connect).toBeTypeOf("function");
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
  void (undefined as unknown as BrowserStreamHandlerRegistrar);
  void (undefined as unknown as RootStreamHandlerRegistrar);
  void forgedStreamHandlerRegistrar;
});
