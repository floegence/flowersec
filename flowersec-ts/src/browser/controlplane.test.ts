import { describe, expect, test } from "vitest";

import * as browser from "./index.js";
import { requestConnectArtifact, requestEntryConnectArtifact } from "../controlplane/request.js";

describe("browser controlplane exports", () => {
  test("exposes the shared artifact helpers without legacy grant helpers", () => {
    expect(browser.requestConnectArtifact).toBe(requestConnectArtifact);
    expect(browser.requestEntryConnectArtifact).toBe(requestEntryConnectArtifact);
    expect(browser).not.toHaveProperty("requestChannelGrant");
    expect(browser).not.toHaveProperty("requestEntryChannelGrant");
  });
});
