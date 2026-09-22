import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { repositoryRoot } from "./transport-v4-files.mjs";

test("binding verification remains independent of SDK and vector-generator dependencies", () => {
  const result = spawnSync(process.execPath, ["--input-type=module", "-e", `
    import { registerHooks } from "node:module";
    registerHooks({ resolve(specifier, context, next) {
      if (specifier.includes("@noble/") || specifier.includes("generate-transport-v4-vectors")) {
        throw new Error("binding must not load fixture generation: " + specifier);
      }
      return next(specifier, context);
    }});
    const { verifyBinding } = await import("./scripts/check-transport-v4-binding.mjs");
    const result = verifyBinding();
    if (result.references !== "verified") throw new Error("binding not verified");
  `], { cwd: repositoryRoot, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr || result.stdout);
});
