import { describe, expect, it } from "vitest";

import { CookieJar } from "./cookieJar.js";

describe("CookieJar", () => {
  it("stores cookies from Set-Cookie and returns a Cookie header", () => {
    const jar = new CookieJar();
    jar.setCookie("a=1; Path=/");
    jar.setCookie("b=2; Path=/sub");

    expect(jar.getCookieHeader("/")).toBe("a=1");
    expect(jar.getCookieHeader("/sub/x")).toContain("a=1");
    expect(jar.getCookieHeader("/sub/x")).toContain("b=2");
  });
});

