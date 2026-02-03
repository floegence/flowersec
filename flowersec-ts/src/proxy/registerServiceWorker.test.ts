import { describe, expect, it } from "vitest";

import { __testOnly } from "./registerServiceWorker.js";

describe("registerServiceWorkerAndEnsureControl (helpers)", () => {
  it("parses repair attempt from URL query", () => {
    const { parseRepairAttemptFromHref } = __testOnly;
    expect(parseRepairAttemptFromHref("https://example.test/a", "_k")).toBe(0);
    expect(parseRepairAttemptFromHref("https://example.test/a?_k=1", "_k")).toBe(1);
    expect(parseRepairAttemptFromHref("https://example.test/a?_k=2.9", "_k")).toBe(2);
    expect(parseRepairAttemptFromHref("https://example.test/a?_k=-1", "_k")).toBe(0);
    expect(parseRepairAttemptFromHref("https://example.test/a?_k=NaN", "_k")).toBe(0);
    expect(parseRepairAttemptFromHref("https://example.test/a?_k=999", "_k")).toBe(9);
  });

  it("builds a new href with updated attempt", () => {
    const { buildHrefWithRepairAttempt } = __testOnly;
    expect(buildHrefWithRepairAttempt("https://example.test/a", "_k", 1)).toBe("https://example.test/a?_k=1");
    expect(buildHrefWithRepairAttempt("https://example.test/a?x=1", "_k", 2)).toBe("https://example.test/a?x=1&_k=2");
  });

  it("removes repair query param without changing path/hash", () => {
    const { buildHrefWithoutRepairQueryParam } = __testOnly;
    expect(buildHrefWithoutRepairQueryParam("https://example.test/a?_k=1#h", "_k")).toBe("/a#h");
    expect(buildHrefWithoutRepairQueryParam("https://example.test/a?x=1&_k=2#h", "_k")).toBe("/a?x=1#h");
  });
});

