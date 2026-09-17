import { describe, expect, it } from "vitest";

import { assertProxyRuntimeScope } from "./scope.js";

const base = {
  version: 2,
  mode: "service_worker",
  appBasePath: "/app/",
  serviceWorker: { scriptUrl: "/proxy-sw.js", scope: "/" },
};

describe("authorized HTTP scope additions", () => {
  it("normalizes and freezes explicit HTTP additions independently of the app base", () => {
    const input = {
      additionalPathPrefixes: ["/platform//api/", "/platform/api/"],
      extraRequestHeaders: ["X-Platform-CSRF", "x-platform-csrf"],
    };
    const scope = assertProxyRuntimeScope({ ...base, http: input });
    expect(scope).toMatchObject({
      appBasePath: "/app/",
      http: {
        additionalPathPrefixes: ["/platform/api/"],
        extraRequestHeaders: ["x-platform-csrf"],
      },
    });
    const http = Object.getOwnPropertyDescriptor(scope, "http")!.value;
    expect(Object.isFrozen(http)).toBe(true);
    expect(Object.isFrozen(http.additionalPathPrefixes)).toBe(true);
    expect(Object.isFrozen(http.extraRequestHeaders)).toBe(true);
    input.additionalPathPrefixes.push("/private/");
    input.extraRequestHeaders.push("authorization");
    expect(http.additionalPathPrefixes).toEqual(["/platform/api/"]);
    expect(http.extraRequestHeaders).toEqual(["x-platform-csrf"]);
  });

  it("keeps omitted HTTP additions absent", () => {
    expect(assertProxyRuntimeScope(base)).not.toHaveProperty("http");
  });

  it.each([
    null, [], { unknown: true },
    { additionalPathPrefixes: "/*" },
    { additionalPathPrefixes: [1] },
    { additionalPathPrefixes: ["https://other.example/"] },
    { additionalPathPrefixes: ["//other.example/"] },
    { additionalPathPrefixes: ["/api/?q=1"] },
    { additionalPathPrefixes: ["/api/#fragment"] },
    { additionalPathPrefixes: ["/api/%2fprivate/"] },
    { additionalPathPrefixes: Array.from({ length: 33 }, (_, i) => `/api/${i}/`) },
    { extraRequestHeaders: "x-platform-csrf" },
    { extraRequestHeaders: [null] },
    { extraRequestHeaders: [" authorization "] },
    { extraRequestHeaders: ["Cookie"] },
    { extraRequestHeaders: ["host"] },
    { extraRequestHeaders: ["Set-Cookie"] },
    { extraRequestHeaders: ["x-injected\r\nheader"] },
    { extraRequestHeaders: Array.from({ length: 33 }, (_, i) => `x-header-${i}`) },
  ])("rejects invalid HTTP additions %#", (http) => {
    expect(() => assertProxyRuntimeScope({ ...base, http })).toThrow();
  });

  it("requires an explicit app base when declaring extra HTTP paths", () => {
    expect(() => assertProxyRuntimeScope({
      ...base, appBasePath: undefined, http: { additionalPathPrefixes: ["/platform/"] },
    })).toThrow();
  });
});
