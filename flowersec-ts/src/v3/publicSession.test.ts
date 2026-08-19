import { readFileSync } from "node:fs";
import { describe, expect, test, vi } from "vitest";

import type { InternalSessionV3, JsonValueV3 } from "./contract.js";
import { projectSessionV3 } from "./publicSession.js";

type NotificationFixture = Readonly<{
  transport_contract_version: 3;
  type_id: number;
  payloads: readonly Readonly<{
    id: string;
    json: string;
    decoder: "state_object" | "string_array" | "string";
    expected_value?: string;
    outcome: "success" | "decode_failure";
  }>[];
  subscription_scenarios: readonly string[];
}>;

const fixture = JSON.parse(readFileSync(
  new URL("../../../testdata/transport_v3/rpc_notification_vectors.json", import.meta.url),
  "utf8",
)) as NotificationFixture;

describe("opaque public SessionV3 projection", () => {
  test("executes every shared v3 notification payload vector", () => {
    expect(fixture.transport_contract_version).toBe(3);
    expect(fixture.subscription_scenarios).toEqual([
      "duplicate_subscriptions_receive_independently",
      "cancel_is_idempotent",
      "handler_failure_is_isolated",
      "session_close_terminates_subscriptions",
    ]);

    for (const vector of fixture.payloads) {
      let dispatch: ((payload: unknown) => void) | undefined;
      const unsubscribeInternal = vi.fn();
      const session = projectSessionV3(fakeSession((handler) => {
        dispatch = handler;
        return unsubscribeInternal;
      }));
      const observed: unknown[] = [];
      const unsubscribe = session.rpc.onNotify(
        fixture.type_id,
        (payload) => decodeFixturePayload(vector.decoder, payload),
        (payload) => { observed.push(payload); },
      );

      dispatch?.(JSON.parse(vector.json));

      if (vector.outcome === "decode_failure") {
        expect(observed, vector.id).toEqual([]);
      } else if (vector.decoder === "string_array") {
        expect(observed, vector.id).toEqual([JSON.parse(vector.json)]);
      } else {
        expect(observed, vector.id).toEqual([vector.expected_value]);
      }
      unsubscribe();
      unsubscribe();
      expect(unsubscribeInternal, vector.id).toHaveBeenCalledTimes(1);
    }
  });
});

function fakeSession(
  onNotify: (handler: (payload: unknown) => void) => () => void,
): InternalSessionV3 {
  return {
    path: "direct",
    endpointInstanceId: undefined,
    rpc: {
      async call() { return { payload: null }; },
      async notify() {},
      onNotify(_typeId, handler) { return onNotify(handler); },
      close() {},
    },
    termination: new Promise(() => undefined),
    async openStream() { throw new Error("unused"); },
    async acceptStream() { throw new Error("unused"); },
    async rekey() {},
    async probeLiveness() { return 0; },
    async waitTermination() { return await new Promise(() => undefined); },
    async close() {},
  };
}

function decodeFixturePayload(
  decoder: "state_object" | "string_array" | "string",
  payload: JsonValueV3,
): unknown {
  if (decoder === "state_object") {
    if (typeof payload !== "object" || payload === null) {
      throw new TypeError("expected notification state");
    }
    const state = (payload as Readonly<Record<string, JsonValueV3>>).state;
    if (typeof state !== "string") throw new TypeError("expected notification state");
    return state;
  }
  if (decoder === "string_array") {
    if (!Array.isArray(payload) || payload.some((value) => typeof value !== "string")) {
      throw new TypeError("expected notification string array");
    }
    return payload;
  }
  if (typeof payload !== "string") throw new TypeError("expected notification string");
  return payload;
}
