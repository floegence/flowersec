import { afterEach, describe, expect, test, vi } from "vitest";

import {
  ControlplaneRequestError,
  requestChannelGrant,
  requestEntryChannelGrant,
} from "./controlplane.js";

function makeGrant(channelID: string) {
  return {
    tunnel_url: "wss://example.invalid/tunnel",
    channel_id: channelID,
    channel_init_expire_at_unix_s: 123,
    idle_timeout_seconds: 30,
    role: 1,
    token: "tok",
    e2ee_psk_b64u: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    allowed_suites: [1],
    default_suite: 1,
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("browser controlplane helpers", () => {
  test("requestChannelGrant posts endpoint_id and returns grant_client", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ grant_client: makeGrant("chan_1") }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      })
    );

    const out = await requestChannelGrant({
      baseUrl: "https://cp.example.com/",
      endpointId: "env_1",
      fetch: fetchMock as typeof fetch,
    });

    expect(out.channel_id).toBe("chan_1");
    expect(fetchMock).toHaveBeenCalledWith(
      "https://cp.example.com/v1/channel/init",
      expect.objectContaining({
        method: "POST",
        credentials: "omit",
        body: JSON.stringify({ endpoint_id: "env_1" }),
      })
    );
  });

  test("requestEntryChannelGrant sends bearer token and merged payload", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ grant_client: makeGrant("chan_2") }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      })
    );

    const out = await requestEntryChannelGrant({
      endpointId: "env_2",
      entryTicket: "ticket_1",
      payload: { floe_app: "demo.app" },
      fetch: fetchMock as typeof fetch,
    });

    expect(out.channel_id).toBe("chan_2");
    const [url, init] = fetchMock.mock.calls[0] ?? [];
    expect(url).toBe("/v1/channel/init/entry?endpoint_id=env_2");
    expect(init).toEqual(
      expect.objectContaining({
        method: "POST",
        credentials: "omit",
        headers: expect.any(Headers),
      })
    );

    const headers = init?.headers as Headers;
    expect(headers.get("Authorization")).toBe("Bearer ticket_1");
    expect(JSON.parse(String(init?.body ?? "{}"))).toEqual({ endpoint_id: "env_2", floe_app: "demo.app" });
  });

  test("rejects mismatched endpoint_id in payload", async () => {
    await expect(
      requestEntryChannelGrant({
        endpointId: "env_2",
        entryTicket: "ticket_1",
        payload: { endpoint_id: "env_other" },
        fetch: vi.fn() as typeof fetch,
      })
    ).rejects.toThrow("payload.endpoint_id must match endpointId");
  });

  test("preserves structured controlplane errors for callers", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          success: false,
          error: {
            code: "AGENT_OFFLINE",
            message: "No agent connected",
          },
        }),
        {
          status: 503,
          headers: { "Content-Type": "application/json" },
        }
      )
    );

    let error: unknown = null;
    try {
      await requestChannelGrant({
        endpointId: "env_3",
        fetch: fetchMock as typeof fetch,
      });
    } catch (nextError) {
      error = nextError;
    }

    expect(error).toBeInstanceOf(ControlplaneRequestError);
    expect(error).toMatchObject({
      name: "ControlplaneRequestError",
      message: "No agent connected",
      status: 503,
      code: "AGENT_OFFLINE",
      responseBody: {
        success: false,
        error: {
          code: "AGENT_OFFLINE",
          message: "No agent connected",
        },
      },
    } satisfies Partial<ControlplaneRequestError>);
  });

  test("re-exports the stable artifact helper aliases from the shared controlplane module", async () => {
    const browser = await import("./controlplane.js");
    const controlplane = await import("../controlplane/index.js");

    expect(browser.requestConnectArtifact).toBe(controlplane.requestConnectArtifact);
    expect(browser.requestEntryConnectArtifact).toBe(controlplane.requestEntryConnectArtifact);
    expect(browser.ControlplaneRequestError).toBe(controlplane.ControlplaneRequestError);
  });
});
