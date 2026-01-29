import { describe, expect, it } from "vitest";

import { filterRequestHeaders, filterResponseHeaders, filterWsOpenHeaders } from "./headerPolicy.js";

describe("proxy header policy", () => {
  it("filters request headers by allowlist and drops Host/Authorization/Cookie", () => {
    const out = filterRequestHeaders([
      { name: "Accept", value: "text/plain" },
      { name: "Host", value: "evil" },
      { name: "Authorization", value: "Bearer secret" },
      { name: "Cookie", value: "a=1" },
      { name: "X-Not-Allowed", value: "x" }
    ]);
    expect(out).toEqual([{ name: "accept", value: "text/plain" }]);
  });

  it("splits response set-cookie for runtime CookieJar handling", () => {
    const out = filterResponseHeaders([
      { name: "content-type", value: "text/plain" },
      { name: "set-cookie", value: "a=1; Path=/" }
    ]);
    expect(out.passthrough).toEqual([{ name: "content-type", value: "text/plain" }]);
    expect(out.setCookie).toEqual(["a=1; Path=/"]);
  });

  it("allows ws open headers: sec-websocket-protocol and cookie", () => {
    const out = filterWsOpenHeaders([
      { name: "sec-websocket-protocol", value: "demo" },
      { name: "cookie", value: "a=1" },
      { name: "x-not-allowed", value: "x" }
    ]);
    expect(out).toEqual([
      { name: "sec-websocket-protocol", value: "demo" },
      { name: "cookie", value: "a=1" }
    ]);
  });
});

