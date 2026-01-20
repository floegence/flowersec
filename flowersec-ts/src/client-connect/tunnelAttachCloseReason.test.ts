import { describe, expect, test } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { tunnelAttachCloseReasons } from "./tunnelAttachCloseReason.js";

describe("tunnelAttachCloseReason", () => {
  test("docs/PROTOCOL.md includes all tunnel attach close reasons", () => {
    const docPath = fileURLToPath(new URL("../../../docs/PROTOCOL.md", import.meta.url));
    const doc = readFileSync(docPath, "utf8");
    for (const reason of tunnelAttachCloseReasons) {
      expect(doc).toContain(`\`${reason}\``);
    }
  });
});

