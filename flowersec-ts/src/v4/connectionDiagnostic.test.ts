import { describe, expect, test } from "vitest";
import { controllerFailureCode } from "./connectionDiagnostic.js";

describe("Controller diagnostic disclosure", () => {
  test("source and host failures cannot publish credentials or retain raw objects", () => {
    const secret = "wss://user:credential@example.test/private?token=secret";
    expect(controllerFailureCode(new Error(secret))).toBe("controller_failed");
    expect(controllerFailureCode({ message: secret, carrier: {}, session: {} })).toBe("controller_failed");
    expect(controllerFailureCode(new Error("resource_exhausted", { cause: new Error(secret) }))).toBe("resource_exhausted");
  });
  test("throwing host error accessors produce only the finite fallback", () => {
    const hostError = new Error();
    Object.defineProperty(hostError, "message", { get: () => { throw new Error("secret"); } });
    expect(controllerFailureCode(hostError)).toBe("controller_failed");
  });
});
