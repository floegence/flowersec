import { expectTypeOf, test } from "vitest";

import {
  createTunnelRuntime,
  type TunnelRuntime,
  type TunnelAuthorizationDecision,
  type TunnelRuntimeOptions,
} from "./index.js";

test("exports an opaque tunnel runtime without application Session ownership", () => {
  expectTypeOf(createTunnelRuntime).returns.toEqualTypeOf<TunnelRuntime>();
  expectTypeOf<TunnelRuntimeOptions["authorize"]>().returns.resolves.toEqualTypeOf<TunnelAuthorizationDecision>();
  expectTypeOf<TunnelRuntimeOptions>().not.toHaveProperty("handlers");
  expectTypeOf<TunnelRuntimeOptions>().not.toHaveProperty("onSession");
  expectTypeOf<TunnelAuthorizationDecision>().not.toHaveProperty("session");
});
