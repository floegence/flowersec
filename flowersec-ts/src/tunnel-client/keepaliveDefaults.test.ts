import { beforeEach, describe, expect, test, vi } from "vitest";
import { base64urlEncode } from "../utils/base64url.js";

const mocks = vi.hoisted(() => {
  return {
    connectCore: vi.fn()
  };
});

vi.mock("../client-connect/connectCore.js", () => ({
  connectCore: (args: unknown) => mocks.connectCore(args)
}));

import type { ClientInternal } from "../client.js";
import type { ChannelInitGrant } from "../gen/flowersec/controlplane/v1.gen.js";
import { Role, Suite } from "../gen/flowersec/controlplane/v1.gen.js";
import { connectTunnel } from "./connect.js";

function makeGrant(idleTimeoutSeconds: number): ChannelInitGrant {
  const psk = base64urlEncode(new Uint8Array(32).fill(1));
  return {
    tunnel_url: "ws://example.invalid",
    channel_id: "ch_1",
    channel_init_expire_at_unix_s: Math.floor(Date.now() / 1000) + 120,
    idle_timeout_seconds: idleTimeoutSeconds,
    role: Role.Role_client,
    token: "tok",
    e2ee_psk_b64u: psk,
    allowed_suites: [Suite.Suite_X25519_HKDF_SHA256_AES_256_GCM],
    default_suite: 1
  };
}

function makeClient(): ClientInternal {
  return {
    path: "tunnel",
    endpointInstanceId: "eid",
    rpc: {} as any,
    openStream: async () => ({} as any),
    ping: async () => {},
    close: () => {},
    secure: {} as any,
    mux: {} as any
  };
}

describe("connectTunnel keepalive defaults", () => {
  beforeEach(() => {
    mocks.connectCore.mockReset();
  });

  test("defaults to idle_timeout_seconds/2", async () => {
    mocks.connectCore.mockResolvedValueOnce(makeClient());
    await connectTunnel(makeGrant(60), { origin: "https://app.example" });
    expect(mocks.connectCore).toHaveBeenCalledTimes(1);
    const args: any = mocks.connectCore.mock.calls[0]?.[0];
    expect(args.opts.keepaliveIntervalMs).toBe(30_000);
  });

  test("default interval is always strictly less than idle", async () => {
    mocks.connectCore.mockResolvedValueOnce(makeClient());
    await connectTunnel(makeGrant(1), { origin: "https://app.example" });
    expect(mocks.connectCore).toHaveBeenCalledTimes(1);
    const args: any = mocks.connectCore.mock.calls[0]?.[0];
    expect(args.opts.keepaliveIntervalMs).toBe(500);
    expect(args.opts.keepaliveIntervalMs).toBeLessThan(1_000);
  });
});
