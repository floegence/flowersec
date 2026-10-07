import { expectTypeOf, test } from "vitest";
import type { NodeRawQUICOptions } from "./rawQUICCurrent.js";
import { createTunnelRuntime, type TunnelRuntime, type TunnelRuntimeOptions, type TunnelRuntimeListenerOptions } from "./tunnelRuntime.js";

test("the current relay owns only physical hops and logical-side claims", () => {
  expectTypeOf(createTunnelRuntime).returns.toEqualTypeOf<TunnelRuntime>();
  expectTypeOf<TunnelRuntimeOptions["ingressRole"]>().toEqualTypeOf<0 | 1 | undefined>();
  expectTypeOf<TunnelRuntimeOptions["carrierAlternatives"]>().toEqualTypeOf<readonly NodeRawQUICOptions[] | undefined>();
  expectTypeOf<TunnelRuntimeOptions["serverCarrierAlternatives"]>().toEqualTypeOf<readonly NodeRawQUICOptions[] | undefined>();
  expectTypeOf<TunnelRuntimeOptions["oppositeListener"]>().toEqualTypeOf<TunnelRuntimeListenerOptions | undefined>();
  expectTypeOf<TunnelRuntimeOptions>().not.toHaveProperty("handlers");
  expectTypeOf<TunnelRuntimeOptions>().not.toHaveProperty("onSession");
  expectTypeOf<TunnelRuntimeOptions>().not.toHaveProperty("psk");
});
