import { describe, expect, test, vi } from "vitest";

import { Supervisor } from "./interop-supervisor.mjs";

describe("interop Supervisor", () => {
  test("surfaces a task failure immediately and at join", async () => {
    const controller = new AbortController();
    const failure = new Error("task failed");
    const onTaskError = vi.fn();
    const supervisor = new Supervisor(controller, onTaskError);

    supervisor.run(Promise.reject(failure));

    await expect(supervisor.waitForFailure()).rejects.toBe(failure);
    await expect(supervisor.finish()).rejects.toBe(failure);
    expect(controller.signal.reason).toBe(failure);
    expect(onTaskError).toHaveBeenCalledWith(failure);
  });

  test("retains independent failures that arrive after cancellation", async () => {
    const controller = new AbortController();
    const first = new Error("first failure");
    const second = new Error("second failure");
    const supervisor = new Supervisor(controller);
    let rejectSecond;

    supervisor.run(new Promise((_, reject) => { rejectSecond = reject; }));
    supervisor.run(Promise.reject(first));
    await expect(supervisor.waitForFailure()).rejects.toBe(first);
    rejectSecond(second);

    await expect(supervisor.finish()).rejects.toMatchObject({
      errors: [first, second],
    });
  });

  test("does not convert intentional cancellation into a task failure", async () => {
    const controller = new AbortController();
    const supervisor = new Supervisor(controller);
    const stopped = new Error("stopped");

    supervisor.run(new Promise((_, reject) => {
      controller.signal.addEventListener("abort", () => reject(controller.signal.reason), { once: true });
    }));
    supervisor.stop(stopped);

    await expect(supervisor.finish()).resolves.toBeUndefined();
  });
});
