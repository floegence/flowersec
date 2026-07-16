import { describe, expect, test, vi } from "vitest";
import type { FlowersecError } from "../utils/errors.js";
import {
  AllowPlaintext,
  AllowPlaintextForLoopback,
  createNetworkPlaintextPolicy,
  PlaintextRiskAcceptance,
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

  test("network plaintext policy allows only explicit canonical IP hosts", async () => {
    const policy = createNetworkPlaintextPolicy({
      allowedHosts: ["192.168.1.20", "2001:db8::20"],
      riskAcceptance: PlaintextRiskAcceptance.acceptPreE2ECredentialExposure,
    });
    await expect(enforceTransportSecurity({ rawUrl: "wss://service.example/ws", path: "direct", policy })).resolves.toBeUndefined();
    await expect(enforceTransportSecurity({ rawUrl: "ws://192.168.1.20/ws", path: "direct", policy })).resolves.toBeUndefined();
    await expect(enforceTransportSecurity({ rawUrl: "ws://[2001:db8::20]/ws", path: "direct", policy })).resolves.toBeUndefined();
    await expect(enforceTransportSecurity({ rawUrl: "ws://192.168.1.21/ws", path: "direct", policy })).rejects.toMatchObject({ code: "transport_policy_denied" });
    await expect(enforceTransportSecurity({ rawUrl: "ws://127.0.0.1/ws", path: "direct", policy })).rejects.toMatchObject({ code: "transport_policy_denied" });
  });

  test.each([
    { allowedHosts: ["192.168.1.20"], riskAcceptance: "" },
    { allowedHosts: [], riskAcceptance: PlaintextRiskAcceptance.acceptPreE2ECredentialExposure },
    { allowedHosts: ["localhost"], riskAcceptance: PlaintextRiskAcceptance.acceptPreE2ECredentialExposure },
    { allowedHosts: ["127.0.0.1"], riskAcceptance: PlaintextRiskAcceptance.acceptPreE2ECredentialExposure },
    { allowedHosts: ["0.0.0.0"], riskAcceptance: PlaintextRiskAcceptance.acceptPreE2ECredentialExposure },
    { allowedHosts: ["example.com"], riskAcceptance: PlaintextRiskAcceptance.acceptPreE2ECredentialExposure },
    { allowedHosts: ["192.168.001.20"], riskAcceptance: PlaintextRiskAcceptance.acceptPreE2ECredentialExposure },
    { allowedHosts: ["[2001:db8::20]"], riskAcceptance: PlaintextRiskAcceptance.acceptPreE2ECredentialExposure },
    { allowedHosts: ["fe80::1"], riskAcceptance: PlaintextRiskAcceptance.acceptPreE2ECredentialExposure },
    { allowedHosts: ["::ffff:c0a8:114"], riskAcceptance: PlaintextRiskAcceptance.acceptPreE2ECredentialExposure },
  ])("rejects unsafe network plaintext options: $allowedHosts", (options) => {
    expect(() => createNetworkPlaintextPolicy(options as never)).toThrow();
  });
});
