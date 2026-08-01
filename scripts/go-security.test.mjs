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

test("manifest and maintained-tree Go module inventories are identical", async (t) => {
  const { collectGoModuleDirectories } = await loadChecker();
  const repoRoot = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-go-inventory-"));
  t.after(() => fs.rmSync(repoRoot, { recursive: true, force: true }));
  for (const module of ["flowersec-go", "tools/transportcheck"]) {
    fs.mkdirSync(path.join(repoRoot, module), { recursive: true });
    fs.writeFileSync(path.join(repoRoot, module, "go.mod"), `module example.com/${module}\n`);
  }
  const manifest = { modules: ["flowersec-go", "tools/transportcheck"] };
  const modules = collectGoModuleDirectories(repoRoot, manifest);
  assert.deepEqual(modules, [
    path.join(repoRoot, "flowersec-go"),
    path.join(repoRoot, "tools/transportcheck"),
  ]);
  fs.mkdirSync(path.join(repoRoot, "tools/unregistered"), { recursive: true });
  fs.writeFileSync(path.join(repoRoot, "tools/unregistered/go.mod"), "module example.com/unregistered\n");
  assert.throws(
    () => collectGoModuleDirectories(repoRoot, manifest),
    /maintained tree.*tools\/unregistered.*security manifest/i,
  );
});

test("every Go module is verified, resolved, and scanned with workspace mode disabled", async () => {
  const { runGoSecurityChecks } = await loadChecker();
  const calls = [];
  const run = (command, args, options) => {
    calls.push({ command, args, options });
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
  assert.equal(calls.length, 6);
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

test("offline stages bind the exact prefetched Go toolchain to the source HEAD", async (t) => {
  const { prepareOfflineGoToolchain } = await loadChecker();
  const repoRoot = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-go-toolchain-"));
  t.after(() => fs.rmSync(repoRoot, { recursive: true, force: true }));
  const toolchainRoot = path.join(repoRoot, "toolchain");
  const binary = path.join(toolchainRoot, "bin", "go");
  const statePath = path.join(repoRoot, "state.json");
  fs.mkdirSync(path.dirname(binary), { recursive: true });
  fs.writeFileSync(binary, "fake-go-toolchain");
  const realBinary = fs.realpathSync(binary);
  const calls = [];
  const sourceHead = "a".repeat(40);
  const run = (command, args, options) => {
    calls.push({ command, args, options });
    if (command === "go") return `${toolchainRoot}\ngo1.26.5\n`;
    if (command === realBinary) return "go version go1.26.5 test/arch\n";
    if (command === "git") return `${sourceHead}\n`;
    throw new Error(`unexpected command: ${command}`);
  };
  const state = prepareOfflineGoToolchain({
    repoRoot,
    goToolchain: "go1.26.5",
    run,
    statePath,
  });
  assert.deepEqual(JSON.parse(fs.readFileSync(statePath, "utf8")), state);
  assert.equal(state.sourceHead, sourceHead);
  assert.equal(state.binary, realBinary);
  assert.match(state.sha256, /^[0-9a-f]{64}$/);
  assert.deepEqual(calls[0].options.env, { GOTOOLCHAIN: "go1.26.5", GOWORK: "off" });
  assert.deepEqual(calls[1].options.env, { GOTOOLCHAIN: "local", GOWORK: "off" });
});
