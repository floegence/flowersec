import {
  createArtifactLease,
  createSessionReconnectManager,
  type ArtifactSource,
  type SessionReconnectConfig,
} from "../reconnect/index.js";
import { expect, test } from "vitest";

test("exposes reconnect orchestration from its dedicated subpath", () => {
  expect(createArtifactLease).toBeTypeOf("function");
  expect(createSessionReconnectManager).toBeTypeOf("function");
  void (undefined as unknown as ArtifactSource);
  void (undefined as unknown as SessionReconnectConfig);
});
