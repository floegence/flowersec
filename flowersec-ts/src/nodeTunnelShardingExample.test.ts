import { describe, expect, test } from "vitest";

import { pickTunnelURL } from "../../examples/ts/node-tunnel-sharding.mjs";

describe("examples/ts/node-tunnel-sharding.mjs", () => {
  test("pickTunnelURL is deterministic for the same channel and URL set", () => {
    const urls = ["wss://a.example/ws", "wss://b.example/ws", "wss://c.example/ws"];

    const first = pickTunnelURL("channel-demo-1", urls);
    const second = pickTunnelURL("channel-demo-1", urls);

    expect(urls).toContain(first);
    expect(second).toBe(first);
  });

  test("pickTunnelURL always returns one of the provided URLs", () => {
    const urls = ["wss://a.example/ws", "wss://b.example/ws"];

    expect(urls).toContain(pickTunnelURL("channel-demo-2", urls));
    expect(urls).toContain(pickTunnelURL("channel-demo-3", urls));
  });
});
