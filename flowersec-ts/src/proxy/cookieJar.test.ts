import { describe, expect, it } from "vitest";

import { CookieJar } from "./cookieJar.js";

describe("CookieJar", () => {
  it("stores cookies from Set-Cookie and returns a Cookie header", () => {
    const jar = new CookieJar();
    jar.setCookie("a=1; Path=/");
    jar.setCookie("b=2; Path=/sub");

    expect(jar.getCookieHeader("/")).toBe("a=1");
    expect(jar.getCookieHeader("/sub/x")).toBe("b=2; a=1");
  });

  it("does not over-send path-scoped cookies to sibling paths", () => {
    const jar = new CookieJar();
    jar.setCookie("sid=admin; Path=/admin");
    jar.setCookie("root=1; Path=/");

    expect(jar.getCookieHeader("/admin")).toBe("sid=admin; root=1");
    expect(jar.getCookieHeader("/admin/panel")).toBe("sid=admin; root=1");
    expect(jar.getCookieHeader("/administrator")).toBe("root=1");
    expect(jar.getCookieHeader("/admin-api")).toBe("root=1");
  });

  it("keeps same-name cookies scoped by path and deletes only the targeted path", () => {
    const jar = new CookieJar();
    jar.setCookie("sid=root; Path=/");
    jar.setCookie("sid=admin; Path=/admin");

    expect(jar.getCookieHeader("/admin/panel")).toBe("sid=admin; sid=root");

    jar.setCookie("sid=; Max-Age=0; Path=/admin");

    expect(jar.getCookieHeader("/admin/panel")).toBe("sid=root");
    expect(jar.getCookieHeader("/")).toBe("sid=root");
  });

  it("derives the default cookie path from the request path", () => {
    const jar = new CookieJar();
    jar.setCookie("sid=1", "/admin/panel?tab=security");

    expect(jar.getCookieHeader("/admin/panel")).toBe("sid=1");
    expect(jar.getCookieHeader("/admin/next")).toBe("sid=1");
    expect(jar.getCookieHeader("/")).toBe("");
    expect(jar.getCookieHeader("/administrator")).toBe("");
  });
});
