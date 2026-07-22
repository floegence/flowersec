import { readFileSync } from "node:fs";
import { afterEach, describe, expect, test, vi } from "vitest";

import { createArtifactLeaseV2, type ArtifactSourceV2 } from "./artifactLease.js";
import { BROWSER_RUNTIME_CAPABILITY_V2 } from "./capability.js";
import type { SessionTerminationV2, SessionV2 } from "./contract.js";
import { FlowersecError, type FlowersecErrorCode } from "../utils/errors.js";
import {
  createSessionReconnectManagerV2,
  type SessionReconnectConfigV2,
} from "./reconnect.js";

const fixture = JSON.parse(
  readFileSync(new URL("../../../testdata/transport_v2/artifact_vectors.json", import.meta.url), "utf8"),
) as Readonly<{ positive: readonly Readonly<{ artifact_json: string }>[] }>;
const rawArtifact = fixture.positive[0]!.artifact_json;

afterEach(() => vi.useRealTimers());

describe("SessionV2 reconnect lifecycle", () => {
  test("acquires a fresh lease for every retry and exposes the connected session", async () => {
    const events: string[] = [];
    let acquisitions = 0;
    const connected = fakeSession();
    const source: ArtifactSourceV2 = {
      kind: "refreshable",
      acquire: async () => {
        acquisitions++;
        events.push(`acquire:${acquisitions}`);
        return createArtifactLeaseV2(rawArtifact, async () => events.push(`spend:${acquisitions}`));
      },
    };
    const config: SessionReconnectConfigV2 = {
      source,
      capability: BROWSER_RUNTIME_CAPABILITY_V2,
      connect: async (lease) => {
        events.push(`connect:${acquisitions}`);
        await lease.commitSpend();
        if (acquisitions === 1) throw new Error("first attempt failed");
        return connected.session;
      },
      autoReconnect: { enabled: true, maxAttempts: 2, initialDelayMs: 0, maxDelayMs: 0, jitterRatio: 0 },
    };
    const manager = createSessionReconnectManagerV2();

    await manager.connect(config);

    expect(events).toEqual([
      "acquire:1", "connect:1", "spend:1",
      "acquire:2", "connect:2", "spend:2",
    ]);
    expect(manager.state()).toMatchObject({ status: "connected", session: connected.session, error: null });
    await manager.disconnect();
  });

  test("reconnects after observable session termination and closes the old session", async () => {
    const first = fakeSession();
    const second = fakeSession();
    let acquisitions = 0;
    const source: ArtifactSourceV2 = {
      kind: "refreshable",
      acquire: async () => {
        acquisitions++;
        return createArtifactLeaseV2(rawArtifact, async () => undefined);
      },
    };
    const manager = createSessionReconnectManagerV2();
    await manager.connect({
      source,
      capability: BROWSER_RUNTIME_CAPABILITY_V2,
      connect: async () => acquisitions === 1 ? first.session : second.session,
      autoReconnect: { enabled: true, maxAttempts: 2, initialDelayMs: 0, maxDelayMs: 0, jitterRatio: 0 },
    });

    first.terminate(new Error("peer closed"));
    await eventually(() => {
      expect(manager.state()).toMatchObject({ status: "connected", session: second.session });
    });
    expect(first.closeCount()).toBe(1);
    await manager.disconnect();
  });

  test("rejects auto reconnect for one-time artifact sources", async () => {
    const manager = createSessionReconnectManagerV2();
    await expect(manager.connect({
      source: { kind: "once", artifact: rawArtifact, commitSpend: async () => undefined },
      capability: BROWSER_RUNTIME_CAPABILITY_V2,
      connect: async () => fakeSession().session,
      autoReconnect: { enabled: true },
    })).rejects.toThrow("refreshable");
    expect(manager.state().status).toBe("error");
  });

  test("rejects an invalid replacement without closing the active session", async () => {
    const active = fakeSession();
    const manager = createSessionReconnectManagerV2();
    const validConfig: SessionReconnectConfigV2 = {
      source: { kind: "once", artifact: rawArtifact, commitSpend: async () => undefined },
      capability: BROWSER_RUNTIME_CAPABILITY_V2,
      connect: async () => active.session,
    };
    await manager.connect(validConfig);

    await expect(manager.connect({
      ...validConfig,
      autoReconnect: { enabled: true },
    })).rejects.toMatchObject({
      name: "FlowersecError",
      path: "auto",
      stage: "validate",
      code: "invalid_option",
    });

    expect(active.closeCount()).toBe(0);
    expect(manager.state()).toMatchObject({ status: "connected", error: null, session: active.session });
    await manager.disconnect();
  });

  test("normalizes a malformed runtime source before changing lifecycle state", async () => {
    const manager = createSessionReconnectManagerV2();
    const malformed = {
      source: null,
      capability: BROWSER_RUNTIME_CAPABILITY_V2,
      connect: async () => fakeSession().session,
    } as unknown as SessionReconnectConfigV2;

    await expect(manager.connect(malformed)).rejects.toMatchObject({
      name: "FlowersecError",
      path: "auto",
      stage: "validate",
      code: "invalid_option",
    });
    expect(manager.state()).toMatchObject({ status: "error", session: null });
    expect(manager.state().error).toBeInstanceOf(FlowersecError);
  });

  test("does not retry FlowersecError codes classified as terminal by the shared registry", async () => {
    const registry = JSON.parse(
      readFileSync(new URL("../../../stability/connect_error_code_registry.json", import.meta.url), "utf8"),
    ) as Readonly<{ reconnect_terminal_codes: readonly FlowersecErrorCode[] }>;

    for (const code of registry.reconnect_terminal_codes) {
      const failure = new FlowersecError({ path: "direct", stage: "validate", code });
      let attempts = 0;
      const manager = createSessionReconnectManagerV2();
      const config: SessionReconnectConfigV2 = {
        source: {
          kind: "refreshable",
          acquire: async () => createArtifactLeaseV2(rawArtifact, async () => undefined),
        },
        capability: BROWSER_RUNTIME_CAPABILITY_V2,
        connect: async () => {
          attempts++;
          throw failure;
        },
        autoReconnect: { enabled: true, maxAttempts: 3, initialDelayMs: 0, maxDelayMs: 0, jitterRatio: 0 },
      };

      await expect(manager.connect(config), code).rejects.toBe(failure);
      expect(attempts, code).toBe(1);
      expect(manager.state(), code).toMatchObject({ status: "error", error: failure, session: null });
    }
  });

  test("does not reconnect sessions terminated by a registry terminal FlowersecError", async () => {
    const registry = JSON.parse(
      readFileSync(new URL("../../../stability/connect_error_code_registry.json", import.meta.url), "utf8"),
    ) as Readonly<{ reconnect_terminal_codes: readonly FlowersecErrorCode[] }>;

    for (const code of registry.reconnect_terminal_codes) {
      const active = fakeSession();
      let attempts = 0;
      const manager = createSessionReconnectManagerV2();
      await manager.connect({
        source: {
          kind: "refreshable",
          acquire: async () => createArtifactLeaseV2(rawArtifact, async () => undefined),
        },
        capability: BROWSER_RUNTIME_CAPABILITY_V2,
        connect: async () => {
          attempts++;
          if (attempts > 1) throw new Error("terminal session was retried");
          return active.session;
        },
        autoReconnect: { enabled: true, maxAttempts: 2, initialDelayMs: 0, maxDelayMs: 0, jitterRatio: 0 },
      });
      const failure = new FlowersecError({ path: "direct", stage: "validate", code });

      active.terminate(failure);
      await eventually(() => {
        expect(manager.state(), code).toMatchObject({ status: "error", error: failure, session: null });
      });
      expect(attempts, code).toBe(1);
      expect(active.closeCount(), code).toBe(1);
      await manager.disconnect();
    }
  });

  test("disconnect immediately cancels an active reconnect backoff", async () => {
    vi.useFakeTimers();
    let attempts = 0;
    const manager = createSessionReconnectManagerV2();
    const connecting = manager.connect({
      source: {
        kind: "refreshable",
        acquire: async () => createArtifactLeaseV2(rawArtifact, async () => undefined),
      },
      capability: BROWSER_RUNTIME_CAPABILITY_V2,
      connect: async () => {
        attempts++;
        throw new Error("dial failed");
      },
      autoReconnect: { enabled: true, maxAttempts: 2, initialDelayMs: 60_000, maxDelayMs: 60_000, jitterRatio: 0 },
    });
    const settled = vi.fn();
    void connecting.then(settled, settled);
    await flushMicrotasks();

    expect(attempts).toBe(1);
    expect(vi.getTimerCount()).toBe(1);
    await manager.disconnect();
    await flushMicrotasks();

    expect(settled).toHaveBeenCalledOnce();
    expect(vi.getTimerCount()).toBe(0);
    expect(manager.state()).toMatchObject({ status: "disconnected", error: null, session: null });
  });

  test("disconnect waits for an abort-ignoring connect attempt and closes its late session", async () => {
	const late = fakeSession();
	let releaseConnect!: () => void;
	const connectGate = new Promise<void>((resolve) => { releaseConnect = resolve; });
	const manager = createSessionReconnectManagerV2();
	const connecting = manager.connect({
	  source: { kind: "once", artifact: rawArtifact, commitSpend: async () => undefined },
	  capability: BROWSER_RUNTIME_CAPABILITY_V2,
	  connect: async () => {
		await connectGate;
		return late.session;
	  },
	});
	await flushMicrotasks();

	const disconnecting = manager.disconnect();
	const settled = vi.fn();
	void disconnecting.then(settled, settled);
	await flushMicrotasks();
	expect(settled).not.toHaveBeenCalled();

	releaseConnect();
	await disconnecting;
	await connecting;
	expect(late.closeCount()).toBe(1);
	expect(manager.state()).toMatchObject({ status: "disconnected", session: null, error: null });
  });

  test("hard replacement waits for the superseded attempt cleanup before acquiring again", async () => {
	const late = fakeSession();
	let releaseFirst!: () => void;
	const firstGate = new Promise<void>((resolve) => { releaseFirst = resolve; });
	const events: string[] = [];
	const manager = createSessionReconnectManagerV2();
	const first = manager.connect({
	  source: { kind: "once", artifact: rawArtifact, commitSpend: async () => undefined },
	  capability: BROWSER_RUNTIME_CAPABILITY_V2,
	  connect: async () => {
		events.push("first-connect");
		await firstGate;
		return late.session;
	  },
	});
	await flushMicrotasks();

	const replacement = manager.connect({
	  source: {
		kind: "refreshable",
		acquire: async () => {
		  events.push("replacement-acquire");
		  return createArtifactLeaseV2(rawArtifact, async () => undefined);
		},
	  },
	  capability: BROWSER_RUNTIME_CAPABILITY_V2,
	  connect: async () => fakeSession().session,
	});
	await flushMicrotasks();
	expect(events).toEqual(["first-connect"]);

	releaseFirst();
	await first;
	await replacement;
	expect(late.closeCount()).toBe(1);
	expect(events).toEqual(["first-connect", "replacement-acquire"]);
	await manager.disconnect();
  });

  test("waits the first backoff interval after an established session terminates", async () => {
	vi.useFakeTimers();
	const first = fakeSession();
	const second = fakeSession();
	let acquisitions = 0;
	const manager = createSessionReconnectManagerV2();
	await manager.connect({
	  source: {
		kind: "refreshable",
		acquire: async () => {
		  acquisitions++;
		  return createArtifactLeaseV2(rawArtifact, async () => undefined);
		},
	  },
	  capability: BROWSER_RUNTIME_CAPABILITY_V2,
	  connect: async () => acquisitions === 1 ? first.session : second.session,
	  autoReconnect: { enabled: true, maxAttempts: 2, initialDelayMs: 1_000, maxDelayMs: 1_000, jitterRatio: 0 },
	});

	first.terminate(new Error("peer closed"));
	await flushMicrotasks();
	expect(acquisitions).toBe(1);
	expect(manager.state().status).toBe("connecting");
	await vi.advanceTimersByTimeAsync(999);
	expect(acquisitions).toBe(1);
	await vi.advanceTimersByTimeAsync(1);
	await flushMicrotasks();
	expect(acquisitions).toBe(2);
	expect(manager.state()).toMatchObject({ status: "connected", session: second.session });
	await manager.disconnect();
  });

  test("normalizes public reconnect failures to FlowersecError", async () => {
	const invalidConfig = createSessionReconnectManagerV2();
	await expect(invalidConfig.connect({
	  source: { kind: "once", artifact: rawArtifact, commitSpend: async () => undefined },
	  capability: BROWSER_RUNTIME_CAPABILITY_V2,
	  connect: async () => fakeSession().session,
	  autoReconnect: { enabled: true },
	})).rejects.toMatchObject({ name: "FlowersecError", path: "auto", stage: "validate", code: "invalid_option" });

	const acquireFailure = createSessionReconnectManagerV2();
	await expect(acquireFailure.connect({
	  source: { kind: "refreshable", acquire: async () => { throw new Error("registry unavailable"); } },
	  capability: BROWSER_RUNTIME_CAPABILITY_V2,
	  connect: async () => fakeSession().session,
	})).rejects.toMatchObject({ name: "FlowersecError", path: "auto", stage: "validate", code: "resolve_failed" });

	const connectFailure = createSessionReconnectManagerV2();
	await expect(connectFailure.connect({
	  source: { kind: "once", artifact: rawArtifact, commitSpend: async () => undefined },
	  capability: BROWSER_RUNTIME_CAPABILITY_V2,
	  connect: async () => { throw new Error("dial failed"); },
	})).rejects.toMatchObject({ name: "FlowersecError", path: "direct", stage: "connect", code: "dial_failed" });

	for (const manager of [invalidConfig, acquireFailure, connectFailure]) {
	  expect(manager.state().error).toBeInstanceOf(FlowersecError);
	}
  });

  test("awaits bounded asynchronous close before reporting disconnected", async () => {
    const active = fakeSession(20);
    const manager = createSessionReconnectManagerV2();
    await manager.connect({
      source: { kind: "once", artifact: rawArtifact, commitSpend: async () => undefined },
      capability: BROWSER_RUNTIME_CAPABILITY_V2,
      connect: async () => active.session,
    });

    const disconnecting = manager.disconnect();
    expect(manager.state().status).toBe("connecting");
    await disconnecting;
    expect(active.closeCount()).toBe(1);
    expect(manager.state()).toMatchObject({ status: "disconnected", session: null, error: null });
  });

  test("does not let a stale disconnect overwrite a newer connection", async () => {
    const first = fakeSession(20);
    const second = fakeSession();
    const manager = createSessionReconnectManagerV2();
    await manager.connect({
      source: { kind: "once", artifact: rawArtifact, commitSpend: async () => undefined },
      capability: BROWSER_RUNTIME_CAPABILITY_V2,
      connect: async () => first.session,
    });

    const disconnecting = manager.disconnect();
    await manager.connect({
      source: { kind: "once", artifact: rawArtifact, commitSpend: async () => undefined },
      capability: BROWSER_RUNTIME_CAPABILITY_V2,
      connect: async () => second.session,
    });
    await disconnecting;

    expect(manager.state()).toMatchObject({ status: "connected", session: second.session, error: null });
    await manager.disconnect();
  });
});

function fakeSession(closeDelayMs = 0): Readonly<{
  session: SessionV2;
  terminate(error: Error): void;
  closeCount(): number;
}> {
  let closeCount = 0;
  let resolveTermination!: (value: SessionTerminationV2) => void;
  const termination = new Promise<SessionTerminationV2>((resolve) => { resolveTermination = resolve; });
  let terminal = false;
  const terminate = (error: Error) => {
    if (terminal) return;
    terminal = true;
    resolveTermination({ error });
  };
  const session = {
    termination,
    waitClosed: async () => await termination,
    close: async () => {
      closeCount++;
      if (closeDelayMs > 0) await new Promise((resolve) => setTimeout(resolve, closeDelayMs));
      terminate(new Error("closed"));
    },
  } as unknown as SessionV2;
  return { session, terminate, closeCount: () => closeCount };
}

async function eventually(assertion: () => void): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt++) {
    try { assertion(); return; } catch { await new Promise((resolve) => setTimeout(resolve, 1)); }
  }
  assertion();
}

async function flushMicrotasks(): Promise<void> {
  for (let index = 0; index < 8; index++) await Promise.resolve();
}
