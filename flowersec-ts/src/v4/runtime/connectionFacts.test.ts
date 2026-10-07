import { describe, expect, test } from "vitest";
import { ConnectionFacts } from "./connectionFacts.js";

describe("original connection fact ownership", () => {
  test("retains spent evidence across an unconfirmed admission and READY", () => {
    const facts = new ConnectionFacts();
    facts.source("preauthorized_pool");
    facts.spendDispatched();
    expect(facts.snapshot()).toMatchObject({ phase: "unknown", spendState: "unknown", admissionState: "not_started" });
    facts.spent();
    facts.admissionDispatched();
    facts.failed();
    expect(facts.snapshot()).toMatchObject({ phase: "unknown", spendState: "spent", admissionState: "unknown" });
    facts.admitted(); facts.ready(); facts.publicationFailed(); facts.unavailable();
    expect(facts.snapshot()).toMatchObject({ phase: "ready", spent: true, spendState: "spent", admissionState: "admitted",
      networkReady: "ready", applicationPublish: "failed" });
  });
  test("only a confirmed pre-commit abort may restore unspent", () => {
    const facts = new ConnectionFacts();
    facts.spendDispatched(); facts.unspent();
    expect(facts.snapshot()).toMatchObject({ phase: "not_started", spent: false, spendState: "unspent" });
    facts.spent(); facts.unspent();
    expect(facts.snapshot()).toMatchObject({ phase: "spent_not_admitted", spent: true, spendState: "spent" });
  });
  test("notifies passive observers at fact transitions", () => {
    let changes = 0;
    const facts = new ConnectionFacts(() => { changes++; });
    facts.spendDispatched(); facts.spent(); facts.admissionDispatched(); facts.admitted(); facts.ready(); facts.published();
    expect(changes).toBe(6);
  });
});
