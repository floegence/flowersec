import { afterEach, describe, expect, test, vi } from "vitest";

import type { ControlplaneRequestError } from "./index.js";
import {
  requestConnectArtifact,
  requestEntryConnectArtifact,
} from "./index.js";

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

function makeArtifact(channelID: string) {
  return {
    v: 1,
    transport: "tunnel",
    tunnel_grant: makeGrant(channelID),
    correlation: {
      v: 1,
      trace_id: "trace-0001",
      session_id: "session-0001",
      tags: [{ key: "flow", value: "demo" }],
    },
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("controlplane artifact helpers", () => {
  test("requestConnectArtifact posts the stable artifact envelope", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ connect_artifact: makeArtifact("chan_art_1") }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      })
    );

    const out = await requestConnectArtifact({
      baseUrl: "https://cp.example.com/",
      endpointId: "env_art_1",
      payload: { floe_app: "demo.app" },
      correlation: { traceId: "trace-0001" },
      fetch: fetchMock as typeof fetch,
    });

    expect(out.transport).toBe("tunnel");
    expect(fetchMock).toHaveBeenCalledWith(
      "https://cp.example.com/v1/connect/artifact",
      expect.objectContaining({
        method: "POST",
        credentials: "omit",
        body: JSON.stringify({
          endpoint_id: "env_art_1",
          payload: { floe_app: "demo.app" },
          correlation: { trace_id: "trace-0001" },
        }),
      })
    );
  });

  test("requestEntryConnectArtifact sends bearer token", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ connect_artifact: makeArtifact("chan_art_2") }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      })
    );

    const out = await requestEntryConnectArtifact({
      endpointId: "env_art_2",
      entryTicket: "ticket_2",
      fetch: fetchMock as typeof fetch,
    });

    expect(out.transport).toBe("tunnel");
    const [url, init] = fetchMock.mock.calls[0] ?? [];
    expect(url).toBe("/v1/connect/artifact/entry");
    const headers = init?.headers as Headers;
    expect(headers.get("Authorization")).toBe("Bearer ticket_2");
    expect(JSON.parse(String(init?.body ?? "{}"))).toEqual({ endpoint_id: "env_art_2" });
  });

  test("preserves structured non-2xx JSON errors for callers", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
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

    await expect(
      requestConnectArtifact({
        endpointId: "env_art_3",
        fetch: fetchMock as typeof fetch,
      })
    ).rejects.toMatchObject({
      name: "ControlplaneRequestError",
      message: "No agent connected",
      status: 503,
      code: "AGENT_OFFLINE",
    } satisfies Partial<ControlplaneRequestError>);
  });

  test("falls back to raw non-JSON error body", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response("gateway down", {
        status: 502,
        headers: { "Content-Type": "text/plain" },
      })
    );

    await expect(
      requestConnectArtifact({
        endpointId: "env_art_4",
        fetch: fetchMock as typeof fetch,
      })
    ).rejects.toMatchObject({
      message: "gateway down",
      status: 502,
      code: "",
    } satisfies Partial<ControlplaneRequestError>);
  });

  test("rejects malformed success envelopes that omit connect_artifact", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      })
    );

    await expect(
      requestConnectArtifact({
        endpointId: "env_art_missing",
        fetch: fetchMock as typeof fetch,
      })
    ).rejects.toThrow("Invalid controlplane response: missing `connect_artifact`");
  });

  test("passes AbortSignal through to fetch", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ connect_artifact: makeArtifact("chan_art_signal") }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      })
    );
    const ac = new AbortController();

    await requestConnectArtifact({
      endpointId: "env_art_signal",
      signal: ac.signal,
      fetch: fetchMock as typeof fetch,
    });

    expect(fetchMock).toHaveBeenCalledWith(
      "/v1/connect/artifact",
      expect.objectContaining({
        signal: ac.signal,
      })
    );
  });

  test("keeps the default stable endpoints", async () => {
    const fetchMock = vi.fn().mockImplementation(() =>
      Promise.resolve(new Response(JSON.stringify({ connect_artifact: makeArtifact("chan_art_default") }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }))
    );

    await requestConnectArtifact({
      endpointId: "env_art_default",
      fetch: fetchMock as typeof fetch,
    });
    await requestEntryConnectArtifact({
      endpointId: "env_art_default_entry",
      entryTicket: "ticket-default",
      fetch: fetchMock as typeof fetch,
    });

    expect(fetchMock).toHaveBeenNthCalledWith(1, "/v1/connect/artifact", expect.anything());
    expect(fetchMock).toHaveBeenNthCalledWith(2, "/v1/connect/artifact/entry", expect.anything());
  });

  test("keeps path override working for advanced callers", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ connect_artifact: makeArtifact("chan_art_override") }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      })
    );

    await requestConnectArtifact({
      endpointId: "env_art_override",
      path: "/custom/artifact",
      fetch: fetchMock as typeof fetch,
    });

    expect(fetchMock).toHaveBeenCalledWith("/custom/artifact", expect.anything());
  });

  test("keeps transport errors observable to callers", async () => {
    const failure = new Error("network down");
    const fetchMock = vi.fn().mockRejectedValue(failure);

    await expect(
      requestConnectArtifact({
        endpointId: "env_art_neterr",
        fetch: fetchMock as typeof fetch,
      })
    ).rejects.toBe(failure);
  });
});
