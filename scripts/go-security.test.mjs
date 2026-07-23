import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";

const sourceRoot = path.resolve(import.meta.dirname, "..");
const checkerPath = path.join(sourceRoot, "scripts/check-go-security.mjs");

async function loadChecker() {
  assert.ok(fs.existsSync(checkerPath), "scripts/check-go-security.mjs must exist");
  return import(pathToFileURL(checkerPath));
}

test("workspace, manifest, and maintained-tree Go module inventories are identical", async (t) => {
  const { collectGoModuleDirectories } = await loadChecker();
  const repoRoot = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-go-inventory-"));
  t.after(() => fs.rmSync(repoRoot, { recursive: true, force: true }));
  for (const module of ["flowersec-go", "tools/transportcheck"]) {
    fs.mkdirSync(path.join(repoRoot, module), { recursive: true });
    fs.writeFileSync(path.join(repoRoot, module, "go.mod"), `module example.com/${module}\n`);
  }
  const workspace = {
    Use: [
      { DiskPath: "./flowersec-go" },
      { DiskPath: "./tools/transportcheck" },
      { DiskPath: "./flowersec-go" },
    ],
  };
  const manifest = { modules: ["flowersec-go", "tools/transportcheck"] };
  const modules = collectGoModuleDirectories(repoRoot, workspace, manifest);
  assert.deepEqual(modules, [
    path.join(repoRoot, "flowersec-go"),
    path.join(repoRoot, "tools/transportcheck"),
  ]);
  assert.throws(
    () => collectGoModuleDirectories(repoRoot, { Use: [] }, manifest),
    /no Go modules/,
  );
  assert.throws(
    () => collectGoModuleDirectories(repoRoot, { Use: [{ DiskPath: "../outside" }] }, manifest),
    /outside the repository/,
  );

  fs.mkdirSync(path.join(repoRoot, "tools/unregistered"), { recursive: true });
  fs.writeFileSync(path.join(repoRoot, "tools/unregistered/go.mod"), "module example.com/unregistered\n");
  assert.throws(
    () => collectGoModuleDirectories(repoRoot, workspace, manifest),
    /maintained tree.*tools\/unregistered.*security manifest/i,
  );
});

test("every Go module is verified, resolved, and scanned with workspace mode disabled", async () => {
  const { runGoSecurityChecks } = await loadChecker();
  const calls = [];
  const run = (command, args, options) => {
    calls.push({ command, args, options });
    if (args.join(" ") === "work edit -json") {
      return JSON.stringify({
        Use: [
          { DiskPath: "./flowersec-go" },
          { DiskPath: "./tools/transportcheck" },
        ],
      });
    }
    return "";
  };

  const modules = runGoSecurityChecks({
    repoRoot: sourceRoot,
    govulncheckVersion: "v1.1.4",
    goToolchain: "go1.26.5",
    moduleManifest: { modules: ["flowersec-go", "tools/transportcheck"] },
    discoverModules: () => [
      path.join(sourceRoot, "flowersec-go"),
      path.join(sourceRoot, "tools/transportcheck"),
    ],
    run,
  });

  assert.deepEqual(modules, [
    path.join(sourceRoot, "flowersec-go"),
    path.join(sourceRoot, "tools/transportcheck"),
  ]);
  assert.equal(calls.length, 7);
  assert.deepEqual(calls[0].args, ["work", "edit", "-json"]);
  for (const moduleDir of modules) {
    const moduleCalls = calls.filter((call) => call.options.cwd === moduleDir);
    assert.deepEqual(moduleCalls.map((call) => call.args), [
      ["mod", "verify"],
      ["list", "-m", "-json", "all"],
      ["run", "golang.org/x/vuln/cmd/govulncheck@v1.1.4", "./..."],
    ]);
    for (const call of moduleCalls) {
      assert.equal(call.options.env.GOWORK, "off");
      assert.equal(call.options.env.GOTOOLCHAIN, "go1.26.5");
    }
  }
});

test("the repository gate delegates Go vulnerability checks to the complete scanner", async () => {
  await loadChecker();
  const makefile = fs.readFileSync(path.join(sourceRoot, "Makefile"), "utf8");
  assert.match(
    makefile,
    /^go-vulncheck:\n\tnode scripts\/check-go-security\.mjs$/m,
  );
});

test("Go security tool versions are fixed and environment overrides fail closed", async () => {
  const { goSecurityToolVersions } = await loadChecker();
  assert.deepEqual(goSecurityToolVersions({}), {
    govulncheckVersion: "v1.1.4",
    goToolchain: "go1.26.5",
  });
  assert.throws(
    () => goSecurityToolVersions({ GOVULNCHECK_VERSION: "not-a-version" }),
    /GOVULNCHECK_VERSION.*must not override/i,
  );
  assert.throws(
    () => goSecurityToolVersions({ GOVULNCHECK_GOTOOLCHAIN: "local" }),
    /GOVULNCHECK_GOTOOLCHAIN.*must not override/i,
  );
});
