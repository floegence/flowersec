import { describe, expect, test } from "vitest";

import { preflightJSONV3 } from "./jsonPreflight.js";

const artifactEnvelope = (payload: string): string => `{"scoped":[{"payload":${payload}}]}`;

function nestedPayload(objectDepth: number): string {
  let value = "0";
  for (let depth = 0; depth < objectDepth; depth += 1) value = `{"a":${value}}`;
  return value;
}

function nodeBoundaryPayload(scalarNodes: number): string {
  const lengths = [63, 63, 63, scalarNodes - 189];
  const arrays = lengths.map((length) => `[${Array.from({ length }, () => "0").join(",")}]`);
  return `{"a":${arrays[0]},"b":${arrays[1]},"c":${arrays[2]},"d":${arrays[3]}}`;
}

describe("v3 JSON lexical preflight", () => {
  test("rejects duplicate keys at arbitrary nesting before object parsing", () => {
    expect(() => preflightJSONV3('{"tuples":[{"carrier":"raw_quic","carrier":"websocket"}]}'))
      .toThrowError(/duplicate JSON field "carrier"/);
    expect(() => preflightJSONV3(artifactEnvelope('{"outer":{"value":1,"value":2}}'), true))
      .toThrowError(/duplicate JSON field "value"/);
  });

  test("counts the scoped payload root as depth one", () => {
    expect(() => preflightJSONV3(artifactEnvelope(nestedPayload(15)), true)).not.toThrow();
    expect(() => preflightJSONV3(artifactEnvelope(nestedPayload(16)), true))
      .toThrowError(/depth exceeds 16/);
    expect(() => preflightJSONV3(`{"outside":${nestedPayload(16)}}`, true)).not.toThrow();
  });

  test("enforces the 256-node boundary while counting every scalar", () => {
    expect(() => preflightJSONV3(artifactEnvelope(nodeBoundaryPayload(251)), true)).not.toThrow();
    expect(() => preflightJSONV3(artifactEnvelope(nodeBoundaryPayload(252)), true))
      .toThrowError(/node count exceeds 256/);
  });

  test("enforces scoped collection and UTF-8 scalar limits", () => {
    const members = Array.from({ length: 65 }, (_, index) => `"k${index}":0`).join(",");
    expect(() => preflightJSONV3(artifactEnvelope(`{${members}}`), true)).toThrowError(/object exceeds 64 members/);
    expect(() => preflightJSONV3(artifactEnvelope(`{"a":[${Array.from({ length: 65 }, () => "0").join(",")}]}`), true))
      .toThrowError(/array exceeds 64 elements/);
    expect(() => preflightJSONV3(artifactEnvelope(`{"${"k".repeat(129)}":0}`), true))
      .toThrowError(/key exceeds 128 bytes/);
    expect(() => preflightJSONV3(artifactEnvelope(`{"a":"${"v".repeat(1_025)}"}`), true))
      .toThrowError(/string exceeds 1024 bytes/);
  });
});
