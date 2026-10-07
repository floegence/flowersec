import { describe, expect, it } from "vitest";
import type { AdmissionOffer as CoreAdmissionOffer, ServiceContract } from "./facade.js";
import type { AdmissionOffer as NodeAdmissionOffer } from "./node/index.js";
import type { AdmissionOffer as BrowserAdmissionOffer } from "./browser/index.js";
import type { AdmissionOffer as ProxyAdmissionOffer } from "./proxy/index.js";

// All ordinary entrypoints describe the same detached application value.
function ordinaryOfferTypes(offer: CoreAdmissionOffer): readonly [NodeAdmissionOffer, BrowserAdmissionOffer, ProxyAdmissionOffer] {
  return [offer, offer, offer];
}
function installedOffer(contract: ServiceContract): CoreAdmissionOffer | undefined { return contract.offer; }

describe("public AdmissionOffer contract", () => {
  it("shares only immutable contract identity and UTC window fields across entrypoints", () => {
    const offer: CoreAdmissionOffer = Object.freeze({ serviceContractDigest: "a".repeat(64), notBeforeMS: 900n, notAfterMS: 10000n });
    const contract: ServiceContract = Object.freeze({ availability: "available", installed: true, acceptance: "exact",
      digest: offer.serviceContractDigest, refresh: "installed", offer });
    for (const entry of ordinaryOfferTypes(installedOffer(contract)!)) {
      expect(entry).toBe(offer);
      expect(Object.keys(entry).sort()).toEqual(["notAfterMS", "notBeforeMS", "serviceContractDigest"]);
    }
  });
});
