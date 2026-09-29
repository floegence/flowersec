import { expect, it } from "vitest";
import { OpenAdmission, openAdmissionCharge, openDecoderCharge, type OpenAdmissionConfig } from "./runtime/openAdmission.js";
import { ResourceRoot, ResourceVector } from "./runtime/resources.js";

it("keeps the unique terminal token charged after logical retirement until the original proof is released", () => {
  const limit = new ResourceVector(Array<bigint>(11).fill(128n << 20n));
  const root = new ResourceRoot({ profileRevision: "1".repeat(64), limit, accounts: 2, reservations: 8, references: 16,
    rootRuntimeBytes: 128n, accountRuntimeBytes: 128n, reservationRuntimeBytes: 128n, referenceRuntimeBytes: 128n });
  const tenant = "1".repeat(32), environment = "2".repeat(32);
  const accounts = [root.account("tenant", tenant, limit), root.account("environment", environment, limit)];
  // Exactly one positive proof plus the protected rejection position.
  const config: OpenAdmissionConfig = { direction: 0, maxActive: 1, maxPending: 1, ingressItems: 1, ingressBytes: 8192,
    terminalCapacity: 2, rejectionReserve: 1, runtimeBytes: 1024n,
    perClass: [1, 1, 0], perOpener: [[1, 1, 0], [1, 1, 0]], protected: [[0, 0, 0], [0, 0, 0]] };
  const references = [openAdmissionCharge(config), openDecoderCharge(config.runtimeBytes)].map((charge, index) =>
    root.reserve({ accounts, owner: { tenant, environment, kind: "retired_proof", backing: String(index + 3).repeat(32) }, charge }));
  const admission = new OpenAdmission(config, references[0]!, references[1]!);
  for (const reference of references) reference.release();
  try {
    const original = admission.prepareBootstrap("services"); admission.completeBootstrap(original);
    admission.terminal(original); admission.retire(original, true);
    expect(admission.isStable(1n)).toBe(true);
    expect(admission.snapshot(original).phase).toBe("stable");
    expect(admission.counts()).toMatchObject({ active: 0, positiveProofs: 1 });
    expect(() => admission.prepareLocal(0, 0, "example/next", new Uint8Array(), 256n)).toThrow("open_capacity");
    admission.completeRekey(1);
    expect(admission.counts().positiveProofs).toBe(1);
    admission.releaseRetired(original);
    expect(admission.counts().positiveProofs).toBe(0);
    expect(admission.isStable(1n)).toBe(true);
    const next = admission.prepareLocal(1, 0, "example/next", new Uint8Array(), 256n);
    expect(admission.snapshot(next).scope).toBe(3n);
    // A stale proof owner cannot release a token after its slot is reused.
    expect(() => admission.releaseRetired(original)).toThrow("open_association");
    expect(admission.counts().positiveProofs).toBe(1);
    admission.cancelUnsubmitted(next);
  } finally {
    admission.close(); for (const account of accounts) account.close(); root.close();
    expect(root.snapshot().cleanupComplete).toBe(true);
  }
});
