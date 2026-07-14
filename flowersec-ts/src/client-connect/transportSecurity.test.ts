import { describe, expect, test, vi } from "vitest";
import type { FlowersecError } from "../utils/errors.js";
import {
  AllowPlaintext,
  AllowPlaintextForLoopback,
  RequireTLS,
  enforceTransportSecurity,
} from "./transportSecurity.js";

describe("transport security policy", () => {
  test.each([
    [RequireTLS, "wss://example.com/ws", true],
    [RequireTLS, "ws://127.0.0.1/ws", false],
    [AllowPlaintextForLoopback, "ws://localhost/ws", true],
    [AllowPlaintextForLoopback, "ws://127.42.0.9/ws", true],
    [AllowPlaintextForLoopback, "ws://[::1]/ws", true],
    [AllowPlaintextForLoopback, "ws://localhost.example/ws", false],
    [AllowPlaintextForLoopback, "ws://127.1/ws", false],
    [AllowPlaintextForLoopback, "ws://127.0.00.1/ws", false],
    [AllowPlaintextForLoopback, "ws://2130706433/ws", false],
    [AllowPlaintextForLoopback, "ws://loopback.example/ws", false],
    [AllowPlaintext, "ws://example.com/ws", true],
    [AllowPlaintext, "http://example.com/ws", false],
  ] as const)("evaluates %s for %s", async (policy, rawUrl, allowed) => {
    const run = enforceTransportSecurity({ rawUrl, path: "direct", policy });
    if (allowed) {
      await expect(run).resolves.toBeUndefined();
    } else {
      await expect(run).rejects.toMatchObject({ code: "transport_policy_denied", stage: "validate" });
    }
  });

  test("custom policy receives sanitized input", async () => {
    const policy = vi.fn(() => true);
    await enforceTransportSecurity({
      rawUrl: "wss://example.com/private?token=secret",
      path: "tunnel",
      policy,
    });
    expect(policy).toHaveBeenCalledWith({
      path: "tunnel",
      scheme: "wss",
      host: "example.com",
      runtime: "node",
    });
    expect(JSON.stringify(policy.mock.calls)).not.toContain("secret");
  });

  test("missing policy requires TLS", async () => {
    const run = enforceTransportSecurity({
      rawUrl: "ws://example.com/ws",
      path: "direct",
    });
    await expect(run).rejects.toMatchObject({ code: "transport_policy_denied" });
  });

  test("malformed URLs use the caller path and never invoke a policy", async () => {
    const policy = vi.fn(() => true);
    const run = enforceTransportSecurity({ rawUrl: "ws://user@example.com/ws", path: "tunnel", policy });
    await expect(run).rejects.toEqual(expect.objectContaining<Partial<FlowersecError>>({
      code: "transport_policy_denied",
      path: "tunnel",
    }));
    expect(policy).not.toHaveBeenCalled();
  });
});
