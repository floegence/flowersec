import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const sourceRoot = path.resolve(import.meta.dirname, "..");
const checker = path.join(sourceRoot, "scripts/check-security-makefile.mjs");
const canonical = fs.readFileSync(path.join(sourceRoot, "Makefile"), "utf8");
const gmake = (process.env.PATH ?? "")
  .split(path.delimiter)
  .map((directory) => path.join(directory, "gmake"))
  .find((candidate) => fs.existsSync(candidate));

function check(makefile, extraEnv = {}, makeBinary) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-make-security-"));
  fs.writeFileSync(path.join(root, "Makefile"), makefile);
  fs.mkdirSync(path.join(root, "scripts"));
  fs.copyFileSync(
    path.join(sourceRoot, "scripts/run-final-stage.mjs"),
    path.join(root, "scripts/run-final-stage.mjs"),
  );
  fs.copyFileSync(
    path.join(sourceRoot, "scripts/run-final-lanes.mjs"),
    path.join(root, "scripts/run-final-lanes.mjs"),
  );
  fs.copyFileSync(
    path.join(sourceRoot, "scripts/run-precommit-wave.mjs"),
    path.join(root, "scripts/run-precommit-wave.mjs"),
  );
  const env = { ...process.env, ...extraEnv };
  if (makeBinary !== undefined) {
    fs.symlinkSync(makeBinary, path.join(root, "make"));
    env.PATH = `${root}${path.delimiter}${env.PATH ?? ""}`;
  }
  const result = spawnSync("node", [checker, path.join(root, "Makefile")], {
    cwd: sourceRoot,
    encoding: "utf8",
    env,
  });
  fs.rmSync(root, { recursive: true, force: true });
  return result;
}

function dryRun(target) {
  return spawnSync("make", ["--no-print-directory", "-n", target], {
    cwd: sourceRoot,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
  });
}

function replaceTargetRecipeLine(makefile, target, line, replacement) {
  const expression = new RegExp(`^${target}:[^\\n]*\\n(?:\\t.*\\n)*`, "m");
  const match = expression.exec(makefile);
  assert.ok(match, `${target} recipe must exist`);
  const mutatedBlock = match[0].replace(line, replacement);
  assert.notEqual(mutatedBlock, match[0], `${target} must contain ${line}`);
  return `${makefile.slice(0, match.index)}${mutatedBlock}${makefile.slice(match.index + match[0].length)}`;
}

test("effective Make graph keeps the security gate complete and reachable", () => {
  assert.equal(fs.existsSync(checker), true, "security Make graph checker must exist");
  const result = check(canonical);
  assert.equal(result.status, 0, result.stderr);
});

test("precommit stays source-only while final integration retains heavy validation", () => {
  const precommit = dryRun("precommit");
  assert.equal(precommit.status, 0, precommit.stderr);
  const finalIntegration = dryRun("check");
  assert.equal(finalIntegration.status, 0, finalIntegration.stderr);

  const heavyCommands = [
    "cd flowersec-go && go test -timeout=5m ./...",
    "npm run test:coverage",
    "npm run verify:package",
    "swift build",
    "--enable-code-coverage",
    "go run . verify-swift",
    "go run . verify-rust",
    "cargo package --allow-dirty",
    "cargo publish --dry-run --allow-dirty",
  ];
  for (const command of heavyCommands) {
    assert.doesNotMatch(
      precommit.stdout,
      new RegExp(command.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")),
      `precommit must not reach final-only command: ${command}`,
    );
    assert.match(
      finalIntegration.stdout,
      new RegExp(command.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")),
      `final integration must retain command: ${command}`,
    );
  }
});

test("precommit phases prepare dependencies before bounded static and language waves", () => {
  const precommit = canonical.match(/^precommit:[^\n]*\n((?:\t.*\n)+)/m)?.[1] ?? "";
  const lines = precommit.trim().split("\n").map((line) => line.trim());
  assert.deepEqual(lines, [
    "node scripts/run-precommit-wave.mjs generate $(MAKE) gen-check",
    "node scripts/run-precommit-wave.mjs dependencies $(MAKE) ts-ensure-deps",
    "node scripts/run-precommit-wave.mjs static $(MAKE) security-makefile-check security-dependency-check release-policy-check readme-localization-check stability-source-check example-source-check",
    "node scripts/run-precommit-wave.mjs languages $(MAKE) precommit-go precommit-ts precommit-swift precommit-rust",
  ]);
});

test("precommit uses the short Go group while final integration retains the complete Go suite", () => {
  const precommitGo = dryRun("precommit-go");
  assert.equal(precommitGo.status, 0, precommitGo.stderr);
  const finalIntegration = dryRun("check");
  assert.equal(finalIntegration.status, 0, finalIntegration.stderr);

  assert.match(precommitGo.stdout, /go test -short -timeout=5m/);
  assert.doesNotMatch(precommitGo.stdout, /cd flowersec-go && go test -timeout=5m \.\/\.\.\./);
  assert.match(finalIntegration.stdout, /cd flowersec-go && go test -timeout=5m \.\/\.\.\./);
});

test("final integration isolates race from the bounded language build lanes", () => {
  const laneCall = [
    "\tCARGO_NET_OFFLINE=true GOPROXY=off GOSUMDB=off npm_config_offline=true node scripts/run-final-stage.mjs 595 race $(MAKE) final-race-check",
    "\tCARGO_NET_OFFLINE=true GOPROXY=off GOSUMDB=off npm_config_offline=true node scripts/run-final-stage.mjs 595 languages node scripts/run-final-lanes.mjs $(MAKE) final-go-check final-ts-check final-swift-check final-rust-check",
  ].join("\n");
  const laneTarget = canonical.match(/^final-integration-lanes:\n((?:\t.*\n)+)/m)?.[1] ?? "";
  const checkTarget = canonical.match(/^check: security-makefile-check\n((?:\t.*\n)+)/m)?.[1] ?? "";
  assert.equal(laneTarget.trim(), laneCall.trim());
  assert.match(checkTarget, /^\t\$\(MAKE\) final-integration-lanes$/m);

  for (const target of ["final-go-check", "final-race-check", "final-ts-check", "final-swift-check", "final-rust-check"]) {
    assert.match(canonical, new RegExp("^" + target + ":", "m"), target + " must remain an explicit final lane");
  }

  const weakened = canonical.replace(laneCall, "\tCARGO_NET_OFFLINE=true GOPROXY=off GOSUMDB=off npm_config_offline=true node scripts/run-final-stage.mjs 595 race $(MAKE) final-race-check\n\tCARGO_NET_OFFLINE=true GOPROXY=off GOSUMDB=off npm_config_offline=true node scripts/run-final-stage.mjs 595 languages node scripts/run-final-lanes.mjs $(MAKE) final-go-check final-ts-check final-swift-check");
  assert.notEqual(weakened, canonical);
  const result = check(weakened);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /final-integration-lanes|final-rust-check|exact/i);
});

test("network preflight completes before expensive stages and final lanes stay offline", () => {
  const checkTarget = canonical.match(/^check: security-makefile-check\n((?:\t.*\n)+)/m)?.[1] ?? "";
  const preflightIndex = checkTarget.indexOf("run-final-stage.mjs 595 preflight $(MAKE) final-network-preflight");
  const packagesIndex = checkTarget.indexOf("run-final-stage.mjs 300 packages $(MAKE) final-package-validation");
  const lanesIndex = checkTarget.indexOf("$(MAKE) final-integration-lanes");
  assert.ok(preflightIndex >= 0, "check must run the bounded network preflight");
  assert.ok(packagesIndex > preflightIndex, "package validation must follow the network preflight");
  assert.ok(lanesIndex > packagesIndex, "package validation must fail before expensive final lanes");

  const preflight = canonical.match(/^final-network-preflight:\n((?:\t.*\n)+)/m)?.[1] ?? "";
  assert.match(preflight, /run-final-lanes\.mjs.*final-go-preflight.*final-ts-preflight.*final-swift-preflight.*final-rust-preflight/);
  assert.match(
    canonical,
    /^final-go-preflight:\n\t\$\(MAKE\) go-vulncheck\n\tnode scripts\/check-go-security\.mjs --prepare-offline-toolchain$/m,
  );

  const lanes = canonical.match(/^final-integration-lanes:\n((?:\t.*\n)+)/m)?.[1] ?? "";
  for (const recipe of checkTarget.split("\n").filter((line) => line.includes("run-final-stage.mjs") && !line.includes(" preflight "))) {
    assert.match(recipe, /GOSUMDB=off/, "every post-preflight stage must disable the Go checksum database");
  }
  for (const recipe of lanes.trim().split("\n")) {
    assert.match(recipe, /GOSUMDB=off/, "every final integration lane must disable the Go checksum database");
  }
  assert.match(lanes, /GOPROXY=off.*npm_config_offline=true.*run-final-lanes\.mjs \$\(MAKE\) final-go-check final-ts-check final-swift-check final-rust-check/);
  assert.match(lanes, /CARGO_NET_OFFLINE=true.*GOPROXY=off.*npm_config_offline=true.*run-final-stage\.mjs 595 race/);
  const packages = canonical.match(/^final-package-validation:\n((?:\t.*\n)+)/m)?.[1] ?? "";
  for (const target of ["security-package-check", "ts-package-check", "swift-package-check", "rust-package-offline-check"]) {
    assert.match(packages, new RegExp(`^\\t\\$\\(MAKE\\) ${target}$`, "m"));
  }
  assert.doesNotMatch(canonical.match(/^final-go-check:\n((?:\t.*\n)+)/m)?.[1] ?? "", /go-vulncheck/);
  assert.doesNotMatch(canonical.match(/^final-ts-check:\n((?:\t.*\n)+)/m)?.[1] ?? "", /ts-audit|ts-browser-ensure|ts-package-check/);
  assert.match(canonical.match(/^final-swift-check:\n((?:\t.*\n)+)/m)?.[1] ?? "", /swift-final-check/);
  assert.match(canonical.match(/^final-rust-check:\n((?:\t.*\n)+)/m)?.[1] ?? "", /CARGO_NET_OFFLINE=true.*rust-final-check/);
  assert.doesNotMatch(canonical.match(/^rust-final-check:.*$/m)?.[0] ?? "", /rust-package|rust-audit/);
});

test("exact-main gate keeps network work before deterministic offline phases", () => {
  assert.match(canonical, /^security-dependency-check:\n/m);
  assert.doesNotMatch(canonical, /^security-dependency-check:.*ts-ensure-deps/m);
  assert.match(canonical, /^check: security-makefile-check\n/m);

  const checkTarget = canonical.match(/^check: security-makefile-check\n((?:\t.*\n)+)/m)?.[1] ?? "";
  const releaseIndex = checkTarget.indexOf("$(MAKE) release-policy-check");
  const readmeIndex = checkTarget.indexOf("$(MAKE) readme-localization-check");
  const exampleSourceIndex = checkTarget.indexOf("$(MAKE) example-source-check");
  const preflightIndex = checkTarget.indexOf("run-final-stage.mjs 595 preflight $(MAKE) final-network-preflight");
  const contractsIndex = checkTarget.indexOf("run-final-stage.mjs 300 contracts $(MAKE) final-offline-contracts");
  const packagesIndex = checkTarget.indexOf("run-final-stage.mjs 300 packages $(MAKE) final-package-validation");
  const lanesIndex = checkTarget.indexOf("$(MAKE) final-integration-lanes");
  const postIndex = checkTarget.indexOf("run-final-stage.mjs 595 post $(MAKE) final-post-validation");
  assert.ok(
    releaseIndex >= 0 && readmeIndex > releaseIndex && exampleSourceIndex > readmeIndex,
    "dependency-free source contracts must run first",
  );
  assert.doesNotMatch(
    checkTarget.slice(0, preflightIndex),
    /npm ci|npm audit|cargo (?:fetch|package|publish)|go-vulncheck|swift-security-check|ts-browser-ensure/,
    "the source-contract phase must not reach network-sensitive dependency work",
  );
  assert.ok(preflightIndex > exampleSourceIndex, "network preflight must follow source contracts");
  assert.ok(contractsIndex > preflightIndex, "deterministic contracts must follow dependency preparation");
  assert.ok(packagesIndex > contractsIndex, "offline package validation must follow deterministic contracts");
  assert.ok(lanesIndex > packagesIndex, "race and language lanes must follow package validation");
  assert.ok(postIndex > lanesIndex, "offline examples and interoperability must run last");

  const preflight = canonical.match(/^final-network-preflight:\n((?:\t.*\n)+)/m)?.[1] ?? "";
  for (const target of ["final-go-preflight", "final-ts-preflight", "final-swift-preflight", "final-rust-preflight"]) {
    assert.match(preflight, new RegExp(target));
  }
  const offlineContracts = canonical.match(/^final-offline-contracts:\n((?:\t.*\n)+)/m)?.[1] ?? "";
  for (const target of ["security-dependency-check", "gen-check", "stability-source-check"]) {
    assert.match(offlineContracts, new RegExp(`^\\t\\$\\(MAKE\\) ${target}$`, "m"));
  }
  const packages = canonical.match(/^final-package-validation:\n((?:\t.*\n)+)/m)?.[1] ?? "";
  assert.match(packages, /rust-package-offline-check/);
  assert.doesNotMatch(packages, /rust-package-check/);
  const rustPreflight = canonical.match(/^final-rust-preflight:\n((?:\t.*\n)+)/m)?.[1] ?? "";
  assert.match(rustPreflight, /\$\(MAKE\) rust-fetch/);
  assert.match(rustPreflight, /\$\(MAKE\) rust-audit/);
  assert.match(rustPreflight, /\$\(MAKE\) rust-publish-preflight/);
  assert.doesNotMatch(rustPreflight, /rust-package/, "network preflight must not perform Rust package validation");
  const rustPublishPreflight = canonical.match(/^rust-publish-preflight:\n((?:\t.*\n)+)/m)?.[1] ?? "";
  assert.match(rustPublishPreflight, /cargo publish --dry-run --allow-dirty --no-verify/);
  const rustPackageOffline = canonical.match(/^rust-package-offline-check:\n((?:\t.*\n)+)/m)?.[1] ?? "";
  assert.match(rustPackageOffline, /cargo package --allow-dirty --offline/);
  assert.doesNotMatch(rustPackageOffline, /cargo publish/);

  const laneTarget = canonical.match(/^final-integration-lanes:\n((?:\t.*\n)+)/m)?.[1] ?? "";
  assert.match(laneTarget, /^\tCARGO_NET_OFFLINE=true GOPROXY=off GOSUMDB=off npm_config_offline=true node scripts\/run-final-stage\.mjs 595 race/m);
  assert.match(laneTarget, /CARGO_NET_OFFLINE=true GOPROXY=off GOSUMDB=off npm_config_offline=true.*595 languages/);
  const post = canonical.match(/^final-post-validation:\n((?:\t.*\n)+)/m)?.[1] ?? "";
  assert.match(post, /\$\(MAKE\) example-check/);
  assert.match(post, /\$\(MAKE\) transport-interop-smoke/);

  const finalSwift = canonical.match(/^final-swift-check:\n((?:\t.*\n)+)/m)?.[1] ?? "";
  const finalRust = canonical.match(/^final-rust-check:\n((?:\t.*\n)+)/m)?.[1] ?? "";
  assert.match(finalSwift, /stability-swift-check/);
  assert.match(finalRust, /stability-rust-check/);
  assert.doesNotMatch(canonical.match(/^rust-final-check:.*$/m)?.[0] ?? "", /rust-audit/);
  assert.equal((canonical.match(/\$\(MAKE\) rust-audit$/gm) ?? []).length, 1, "Rust audit must run once in preflight");
  assert.equal((canonical.match(/\$\(MAKE\) rust-package-check$/gm) ?? []).length, 0, "online package validation must not run in preflight");
  assert.equal((canonical.match(/\$\(MAKE\) rust-publish-preflight$/gm) ?? []).length, 1, "publish dry-run must run once in network preflight");
  assert.equal((canonical.match(/\$\(MAKE\) rust-package-offline-check$/gm) ?? []).length, 1, "offline package validation must run once after preflight");

  assert.match(canonical, /^SWIFTPM_CACHE_PATH := \$\(CURDIR\)\/\.flowersec\/swiftpm-cache$/m);
  const swiftCache = '\"$(SWIFTPM_CACHE_PATH)\"';
  for (const target of ["swift-package-check", "swift-final-check", "example-check"]) {
    const recipe = canonical.match(new RegExp(`^${target}:.*\\n((?:\\t.*\\n)+)`, "m"))?.[1] ?? "";
    assert.ok(recipe.includes(swiftCache), `${target} must use the shared SwiftPM cache`);
    assert.match(recipe, /--skip-update/);
    assert.match(recipe, /--only-use-versions-from-resolved-file/);
  }
  const exampleSource = canonical.match(/^example-source-check:\n((?:\t.*\n)+)/m)?.[1] ?? "";
  assert.match(exampleSource, /node --test scripts\/sdk-examples\.test\.mjs/);
  assert.match(exampleSource, /find examples\/ts .*node --check/);
  const examples = canonical.match(/^example-check: example-source-check\n((?:\t.*\n)+)/m)?.[1] ?? "";
  assert.match(examples, /cd flowersec-go && go test -run/);
  assert.match(examples, /cargo check --locked --offline --manifest-path examples\/rust\/Cargo\.toml/);
  assert.match(examples, /swift test --package-path examples\/swift/);
});

test("final Go race gate runs all shards with an explicit CPU budget", () => {
  const raceTarget = canonical.match(/^go-test-race:\n((?:\t.*\n)+)/m)?.[1] ?? "";
  assert.match(
    raceTarget,
    /run-go-test-race-shards\.sh tools\/transportcheck auto 5m auto race 1/,
    "exclusive race must use one shard per test, host-adaptive worker slots, and one Go scheduler slot per worker",
  );
  const discovered = spawnSync("go", ["test", "-list", "^Test", "."], {
    cwd: path.join(sourceRoot, "tools/transportcheck"),
    encoding: "utf8",
    timeout: 30_000,
  });
  assert.equal(discovered.status, 0, discovered.stderr);
  const discoveredTests = discovered.stdout
    .split("\n")
    .filter((line) => /^Test[A-Za-z0-9_]+$/.test(line)).length;
  assert.ok(discoveredTests > 0, "the transport checker must expose top-level tests");
});

test("measured fixture-heavy race cases stay in the high-cost wave", () => {
  const source = fs.readFileSync(path.join(sourceRoot, "tools/transportcheck/main_test.go"), "utf8");
  for (const name of [
    "TestEvidenceAcceptsCompleteSyntheticUnitEvidence",
    "TestMigrationMetricRequiresSharedQlogRPCTimestamp",
  ]) {
    assert.match(
      source,
      new RegExp(`// flowersec:race-cost=high\\nfunc ${name}\\(`),
      `${name} must start before short race shards`,
    );
  }
});

test("race shard runner derives bounded auto parallelism from online CPUs", () => {
  for (const { online, want } of [{ online: 3, want: 3 }, { online: 32, want: 12 }]) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-race-auto-"));
    try {
      const packageDirectory = path.join(root, "package");
      const binDirectory = path.join(root, "bin");
      fs.mkdirSync(packageDirectory);
      fs.mkdirSync(binDirectory);
      fs.writeFileSync(path.join(binDirectory, "getconf"), `#!/bin/sh\nprintf '${online}\\n'\n`, { mode: 0o755 });
      fs.writeFileSync(path.join(binDirectory, "go"), `#!/bin/sh
output=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then output="$2"; shift; fi
  shift
done
cat > "$output" <<'EOF'
#!/bin/sh
if [ "$1" = "-test.list" ]; then
  printf 'TestOne\\nTestTwo\\nTestThree\\n'
fi
EOF
chmod +x "$output"
`, { mode: 0o755 });

      const result = spawnSync(
        path.join(sourceRoot, "scripts/run-go-test-race-shards.sh"),
        [packageDirectory, "3", "1m", "auto", "normal", "1"],
        {
          cwd: sourceRoot,
          encoding: "utf8",
          env: { ...process.env, PATH: `${binDirectory}${path.delimiter}${process.env.PATH ?? ""}` },
        },
      );
      assert.equal(result.status, 0, result.stderr);
      assert.match(result.stdout, new RegExp(`parallelism ${want}\\b`));
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  }
});

test("race shard runner applies the CPU budget to every worker", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-race-budget-"));
  try {
    const packageDirectory = path.join(root, "package");
    const binDirectory = path.join(root, "bin");
    fs.mkdirSync(packageDirectory);
    fs.mkdirSync(binDirectory);
    const fakeGo = path.join(binDirectory, "go");
    fs.writeFileSync(fakeGo, `#!/bin/sh
output=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then output="$2"; shift; fi
  shift
done
cat > "$output" <<'EOF'
#!/bin/sh
if [ "$1" = "-test.list" ]; then
  printf 'TestOne\\nTestTwo\\nTestThree\\n'
  exit 0
fi
printf 'worker GOMAXPROCS=%s\\n' "\${GOMAXPROCS:-unset}"
EOF
chmod +x "$output"
`);
    fs.chmodSync(fakeGo, 0o755);

    const result = spawnSync(
      path.join(sourceRoot, "scripts/run-go-test-race-shards.sh"),
      [packageDirectory, "3", "1m", "2", "race", "1"],
      {
        cwd: sourceRoot,
        encoding: "utf8",
        env: { ...process.env, PATH: `${binDirectory}${path.delimiter}${process.env.PATH ?? ""}` },
      },
    );
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout.match(/worker GOMAXPROCS=1/g)?.length, 3, result.stdout);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("race shard runner starts full shards before sparse tail shards", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-race-order-"));
  try {
    const packageDirectory = path.join(root, "package");
    const binDirectory = path.join(root, "bin");
    fs.mkdirSync(packageDirectory);
    fs.mkdirSync(binDirectory);
    const fakeGo = path.join(binDirectory, "go");
    fs.writeFileSync(fakeGo, `#!/bin/sh
output=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then output="$2"; shift; fi
  shift
done
cat > "$output" <<'EOF'
#!/bin/sh
if [ "$1" = "-test.list" ]; then
  i=1
  while [ "$i" -le 10 ]; do
    printf 'Test%s\n' "$i"
    i=$((i + 1))
  done
fi
EOF
chmod +x "$output"
`);
    fs.chmodSync(fakeGo, 0o755);

    const result = spawnSync(
      path.join(sourceRoot, "scripts/run-go-test-race-shards.sh"),
      [packageDirectory, "4", "1m", "1", "normal"],
      {
        cwd: sourceRoot,
        encoding: "utf8",
        env: { ...process.env, PATH: `${binDirectory}${path.delimiter}${process.env.PATH ?? ""}` },
      },
    );
    assert.equal(result.status, 0, result.stderr);
    const starts = [...result.stdout.matchAll(/running normal shard (\d+)\/4/g)]
      .map((match) => Number(match[1]));
    assert.deepEqual(starts, [1, 2, 3, 4]);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("race shard runner retains diagnostics after SIGTERM", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-race-signal-"));
  const packageDirectory = path.join(root, "package");
  const binDirectory = path.join(root, "bin");
  const tempDirectory = path.join(root, "tmp");
  fs.mkdirSync(packageDirectory);
  fs.mkdirSync(binDirectory);
  fs.mkdirSync(tempDirectory);
  const fakeGo = path.join(binDirectory, "go");
  fs.writeFileSync(fakeGo, `#!/bin/sh
output=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then output="$2"; shift; fi
  shift
done
cat > "$output" <<'EOF'
#!/bin/sh
if [ "$1" = "-test.list" ]; then
  printf 'TestOne\n'
  exit 0
fi
exec sleep 30
EOF
chmod +x "$output"
`);
  fs.chmodSync(fakeGo, 0o755);

  const child = spawn(
    path.join(sourceRoot, "scripts/run-go-test-race-shards.sh"),
    [packageDirectory, "1", "1m", "1", "normal"],
    {
      cwd: sourceRoot,
      env: {
        ...process.env,
        PATH: `${binDirectory}${path.delimiter}${process.env.PATH ?? ""}`,
        TMPDIR: tempDirectory,
      },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  try {
    await new Promise((resolve, reject) => {
      const deadline = Date.now() + 5_000;
      const inspect = () => {
        const directories = fs.readdirSync(tempDirectory)
          .filter((entry) => entry.startsWith("flowersec-race-shards."));
        const started = directories.some((entry) =>
          fs.existsSync(path.join(tempDirectory, entry, "shard-0.log")));
        if (started) {
          resolve();
        } else if (Date.now() >= deadline) {
          reject(new Error(`runner did not start a shard: ${stdout}${stderr}`));
        } else {
          setTimeout(inspect, 20);
        }
      };
      inspect();
    });
    assert.equal(child.kill("SIGTERM"), true);
    const result = await new Promise((resolve) => {
      child.once("exit", (code, signal) => resolve({ code, signal }));
    });
    assert.notEqual(result.code, 0);
    const retained = /race shard logs retained at (.+)/.exec(stderr)?.[1]?.trim();
    assert.ok(retained, stderr);
    assert.equal(fs.existsSync(retained), true, retained);
    assert.equal(fs.existsSync(path.join(retained, "tests")), true);
    assert.equal(fs.existsSync(path.join(retained, "shard-0.log")), true);
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("final race validation completes before bounded language build lanes start", () => {
  const laneTarget = canonical.match(/^final-integration-lanes:\n((?:\t.*\n)+)/m)?.[1] ?? "";
  const goTarget = canonical.match(/^final-go-check:\n((?:\t.*\n)+)/m)?.[1] ?? "";
  const raceTarget = canonical.match(/^final-race-check:\n((?:\t.*\n)+)/m)?.[1] ?? "";
  assert.match(laneTarget, /^\tCARGO_NET_OFFLINE=true GOPROXY=off GOSUMDB=off npm_config_offline=true node scripts\/run-final-stage\.mjs 595 race \$\(MAKE\) final-race-check\n\tCARGO_NET_OFFLINE=true GOPROXY=off GOSUMDB=off npm_config_offline=true node scripts\/run-final-stage\.mjs 595 languages node scripts\/run-final-lanes\.mjs \$\(MAKE\) final-go-check final-ts-check final-swift-check final-rust-check\n$/);
  assert.doesNotMatch(goTarget, /go-test-race/);
  assert.match(raceTarget, /^\t\$\(MAKE\) go-test-race$/m);
});

test("Swift final checks stay serial without globally serializing Make", () => {
  const recipe = [
    "swift-check:",
    "\t$(MAKE) swift-package-check",
    "\t$(MAKE) swift-security-check",
    "\t$(MAKE) swift-source-guard",
    "\t$(MAKE) swift-build",
    "\t$(MAKE) swift-test",
    "\t$(MAKE) swift-cover-check",
  ].join("\n");
  assert.match(canonical, new RegExp(`^${recipe.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`, "m"));
  assert.doesNotMatch(canonical, /^\.NOTPARALLEL(?::|\s)/m);

  for (const weakened of [
    recipe.replace("\n\t$(MAKE) swift-security-check", ""),
    recipe.replace("\t$(MAKE) swift-test", "\t-$(MAKE) swift-test"),
    recipe.replace(
      "\t$(MAKE) swift-test\n\t$(MAKE) swift-cover-check",
      "\t$(MAKE) swift-cover-check\n\t$(MAKE) swift-test",
    ),
  ]) {
    const result = check(canonical.replace(recipe, weakened));
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /swift-check.*recipe|exact/i);
  }
});

test("effective Make recipe parsing supports GNU Make 4.4", { skip: gmake === undefined }, () => {
  const result = check(canonical, {}, gmake);
  assert.equal(result.status, 0, result.stderr);
});

test("effective Make database ignores marker text in variable definitions", () => {
  const markerText = [
    "define HARMLESS_DATABASE_MARKERS",
    "# Files",
    "forged-target:",
    "# files hash-table stats:",
    "endef",
    "",
  ].join("\n");
  const result = check(`${markerText}${canonical}`);
  assert.equal(result.status, 0, result.stderr);
});

test("Make control variables cannot neutralize recursive security gates", () => {
  for (const assignment of [
    "MAKE := true",
    "MAKE_COMMAND := true",
    "SHELL := /usr/bin/true",
    ".SHELLFLAGS := -c true",
  ]) {
    const result = check(`${canonical}\n${assignment}\n`);
    assert.notEqual(result.status, 0, `${assignment} must be rejected`);
    assert.match(result.stderr, /control variable|MAKE|SHELL/i);
  }
});

test("protected targets cannot carry target-specific Make controls", () => {
  for (const mutation of [
    "release-check: MAKE := true",
    "dummy release-check: MAKE := true",
    "release-%: MAKE := true",
    "release-%: private MAKE := true",
    "release-%: export MAKE := true",
    "swift-%: SWIFT_SOURCE_GUARD_PATTERN := a^",
    "swift-source-guard: SWIFT_SOURCE_GUARD_PATTERN := a^",
    "TARGET := swift-check\n$(TARGET): SWIFT_SOURCE_GUARD_PATTERN := a^",
    "%: SHELL := /usr/bin/true",
    "%: MAKE \\\n:= true",
    "%: SHELL \\\n:= /usr/bin/true",
    "%: MAKEFLAGS \\\n:= -i",
    "%: MAKE \\\r\n:= true",
    "%: SHELL \\\r\n:= /usr/bin/true",
    "%: MAKEFLAGS \\\r\n:= -i",
  ]) {
    const mutated = mutation.startsWith("release-check:")
      ? canonical.replace(/^release-check:$/m, mutation)
      : `${canonical}\n${mutation}\n`;
    assert.notEqual(mutated, canonical);
    const result = check(mutated);
    assert.notEqual(result.status, 0, `${mutation} must be rejected`);
    assert.match(result.stderr, /release-check|target-specific|control variable|continuation|dynamic/i);
  }
});

test("audited targets cannot be generated dynamically", () => {
  for (const mutated of [
    canonical.replace(/^release-check:$/m, "RELEASE_TARGET := release-check\n$(RELEASE_TARGET):"),
    `${canonical}\n$(eval GENERATED_TARGET := release-check)\n`,
    `${canonical}\nINJECTED_RULE = swift-%: SWIFT_SOURCE_GUARD_PATTERN := a^\n$(call eval,$(INJECTED_RULE))\n`,
    `${canonical}\nUNTRUSTED := $(shell exit 0)\n`,
  ]) {
    assert.notEqual(mutated, canonical);
    const result = check(mutated);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /dynamic|generate|rewrite/i);
  }
});

test("security gate configuration cannot be overridden by source or environment", () => {
  for (const mutation of [
    "CHECK_INTEROP := 0",
    "CHECK_INTEROP := 1 ",
    "YAMUX_INTEROP := 0",
    "SWIFT_SOURCE_GUARD_PATTERN := a^",
  ]) {
    const result = check(`${canonical}\n${mutation}\n`);
    assert.notEqual(result.status, 0, `${mutation} must be rejected`);
    assert.match(result.stderr, /configuration|effective|variable|expected/i);
  }

  for (const [name, value] of [
    ["CHECK_INTEROP", "0"],
    ["CHECK_INTEROP", " 1"],
    ["YAMUX_INTEROP", "0"],
  ]) {
    const result = check(canonical, { [name]: value });
    assert.notEqual(result.status, 0, `${name}=${value} must be rejected`);
    assert.match(result.stderr, /configuration|effective|variable|expected/i);
  }
});

test("shell assignment is rejected before GNU Make evaluates it", { skip: gmake === undefined }, () => {
  const marker = path.join(os.tmpdir(), `flowersec-make-shell-${process.pid}-${Date.now()}`);
  fs.rmSync(marker, { force: true });
  const result = check(`${canonical}\nUNTRUSTED != printf executed > ${marker}\n`, {}, gmake);
  assert.notEqual(result.status, 0);
  assert.equal(fs.existsSync(marker), false, "Make shell assignment executed before validation");
  fs.rmSync(marker, { force: true });
});

test("Swift source guard recipe cannot be replaced with a no-op", () => {
  const mutated = canonical.replace(
    /^swift-source-guard:\n(?:\t.*\n)+/m,
    "swift-source-guard:\n\t@:\n",
  );
  assert.notEqual(mutated, canonical);
  const result = check(mutated);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /swift-source-guard.*recipe|exact audited command/i);
});

test("security source checks stay fast while package closure keeps a fresh npm build", () => {
  assert.match(canonical, /^ts-build: ts-ensure-deps$/m);
  assert.match(canonical, /^security-dependency-check:$/m);
  assert.match(canonical, /^security-package-check: ts-build$/m);
  const reconnected = canonical.replace(
    /^security-dependency-check:$/m,
    "security-dependency-check: ts-ensure-deps",
  );
  const result = check(reconnected);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /security-dependency-check.*dependency installation|before final-network-preflight/i);

  const packageDisconnected = canonical.replace(
    /^security-package-check: ts-build$/m,
    "security-package-check:",
  );
  const packageResult = check(packageDisconnected);
  assert.notEqual(packageResult.status, 0);
  assert.match(packageResult.stderr, /security-package-check.*ts-build/i);

  const dependenciesDisconnected = canonical.replace(/^ts-build: ts-ensure-deps$/m, "ts-build:");
  const dependenciesResult = check(dependenciesDisconnected);
  assert.notEqual(dependenciesResult.status, 0);
  assert.match(dependenciesResult.stderr, /ts-build.*ts-ensure-deps/i);
});

test("effective Make graph rejects recipe override and missing inventory freshness", () => {
  const overridden = `${canonical}\nsecurity-dependency-check:\n\t@:\n`;
  const overrideResult = check(overridden);
  assert.notEqual(overrideResult.status, 0);
  assert.match(overrideResult.stderr, /duplicate|overrid/i);

  const staleAllowed = canonical.replace("generate-source-inventory.mjs --check", "generate-source-inventory.mjs");
  const staleResult = check(staleAllowed);
  assert.notEqual(staleResult.status, 0);
  assert.match(staleResult.stderr, /--check|fresh|exact|recipe/i);

  const checkerNoOp = canonical.replace(
    "security-makefile-check:\n\tnode scripts/check-security-makefile.mjs Makefile",
    "security-makefile-check:\n\t@:",
  );
  assert.notEqual(checkerNoOp, canonical);
  const checkerResult = check(checkerNoOp);
  assert.notEqual(checkerResult.status, 0);
  assert.match(checkerResult.stderr, /security-makefile-check.*recipe/i);

  const ignoredFailure = canonical.replace(
    "\tnode --test scripts/security-dependencies.test.mjs",
    "\t-node --test scripts/security-dependencies.test.mjs",
  );
  assert.notEqual(ignoredFailure, canonical);
  const ignoredResult = check(ignoredFailure);
  assert.notEqual(ignoredResult.status, 0);
  assert.match(ignoredResult.stderr, /exact|ignore|recipe/i);

  const swallowedFailure = canonical.replace(
    "scripts/security-makefile.test.mjs scripts/run-final-stage.test.mjs scripts/run-final-lanes.test.mjs scripts/run-precommit-wave.test.mjs\n\tnode scripts/generate-source-inventory.mjs --check",
    "scripts/security-makefile.test.mjs scripts/run-final-stage.test.mjs scripts/run-final-lanes.test.mjs scripts/run-precommit-wave.test.mjs || true\n\tnode scripts/generate-source-inventory.mjs --check",
  );
  assert.notEqual(swallowedFailure, canonical);
  const swallowedResult = check(swallowedFailure);
  assert.notEqual(swallowedResult.status, 0);
  assert.match(swallowedResult.stderr, /exact|shell|recipe/i);
});

test("npm package freshness cannot bypass the exact clean build", () => {
  const exactLine = "\tcd flowersec-ts && rm -rf dist && npm run build";
  for (const replacement of [
    "\t@:",
    `\t-${exactLine.slice(1)}`,
    `${exactLine} || true`,
    "\tcd flowersec-ts && npm run build",
    "\tcd flowersec-ts && rm -rf dist",
  ]) {
    const mutated = replaceTargetRecipeLine(canonical, "ts-build", exactLine, replacement);
    const result = check(mutated);
    assert.notEqual(result.status, 0, `${replacement} must not bypass a clean npm build`);
    assert.match(result.stderr, /ts-build.*recipe|exact audited command/i);
  }
});

test("npm audit cannot omit dependencies or downgrade the severity threshold", () => {
  const exactLine = "\tcd flowersec-ts && npm audit --audit-level=info --include=prod --include=dev --include=optional --include=peer";
  for (const replacement of [
    "\tcd flowersec-ts && npm audit",
    "\tcd flowersec-ts && npm audit --audit-level=high",
    "\tcd flowersec-ts && npm audit --omit=dev",
    `${exactLine} || true`,
    `\t-${exactLine.slice(1)}`,
  ]) {
    const mutated = replaceTargetRecipeLine(canonical, "ts-audit", exactLine, replacement);
    const result = check(mutated);
    assert.notEqual(result.status, 0, `${replacement} must not weaken npm audit`);
    assert.match(result.stderr, /ts-audit.*recipe|exact audited command/i);
  }
});

test("effective Make graph rejects security gate removal from precommit and check", () => {
  const staticWave = "\tnode scripts/run-precommit-wave.mjs static $(MAKE) security-makefile-check security-dependency-check release-policy-check readme-localization-check stability-source-check";
  for (const securityTarget of ["security-makefile-check", "security-dependency-check"]) {
    const disconnected = replaceTargetRecipeLine(
      canonical,
      "precommit",
      staticWave,
      staticWave.replace(` ${securityTarget}`, ""),
    );
    const result = check(disconnected);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /precommit.*bounded phase recipe|bounded phase recipe.*precommit/i);
  }

  const disconnectedCheck = canonical.replace(/^check: security-makefile-check$/m, "check:");
  assert.notEqual(disconnectedCheck, canonical, "check must declare its dependency-free security prerequisite");
  const checkResult = check(disconnectedCheck);
  assert.notEqual(checkResult.status, 0);
  assert.match(checkResult.stderr, /check.*security-makefile-check/i);
});

test("check cannot suppress or disconnect final integration lanes", () => {
  for (const scanner of ["final-integration-lanes"]) {
    const exactLine = `\t$(MAKE) ${scanner}`;
    for (const replacement of ["", `\t-$(MAKE) ${scanner}`, `${exactLine} || true`]) {
      const mutated = replaceTargetRecipeLine(canonical, "check", exactLine, replacement);
      const result = check(mutated);
      assert.notEqual(result.status, 0, `${scanner} mutation must fail`);
      assert.match(result.stderr, /check must call|exact, unsuppressed/i);
    }
  }
  const packageCall = "\tCARGO_NET_OFFLINE=true GOPROXY=off GOSUMDB=off npm_config_offline=true node scripts/run-final-stage.mjs 300 packages $(MAKE) final-package-validation";
  for (const replacement of ["", `\t-${packageCall.slice(1)}`, `${packageCall} || true`]) {
    const mutated = replaceTargetRecipeLine(canonical, "check", packageCall, replacement);
    const result = check(mutated);
    assert.notEqual(result.status, 0, "package validation mutation must fail");
    assert.match(result.stderr, /packages|phase|order|validation/i);
  }
});

test("precommit cannot disconnect language security wrappers", () => {
  const languageWave = "\tnode scripts/run-precommit-wave.mjs languages $(MAKE) precommit-go precommit-ts precommit-swift precommit-rust";
  for (const wrapper of ["precommit-go", "precommit-ts", "precommit-swift", "precommit-rust"]) {
    const mutated = replaceTargetRecipeLine(
      canonical,
      "precommit",
      languageWave,
      languageWave.replace(` ${wrapper}`, ""),
    );
    const result = check(mutated);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /precommit.*bounded phase recipe|bounded phase recipe.*precommit/i);
  }
});

test("release-check cannot suppress or disconnect the complete check gate", () => {
  const exactLine = "\t$(MAKE) check";
  for (const replacement of ["", "\t-$(MAKE) check", `${exactLine} || true`]) {
    const mutated = replaceTargetRecipeLine(canonical, "release-check", exactLine, replacement);
    const result = check(mutated);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /release-check.*check|exact, unsuppressed/i);
  }
  const ignored = check(`${canonical}\n.IGNORE: release-check\n`);
  assert.notEqual(ignored.status, 0);
  assert.match(ignored.stderr, /IGNORE.*release-check|release-check.*IGNORE/i);
});

test("effective Make graph rejects non-phony security targets", () => {
  const nonPhony = canonical.replace(
    /^\.PHONY: (.*)security-dependency-check /m,
    ".PHONY: $1",
  );
  assert.notEqual(nonPhony, canonical);
  const result = check(nonPhony);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /security-dependency-check.*phony/i);
});

test("Make special targets cannot suppress security failures", () => {
  for (const specialTarget of [
    ".IGNORE:",
    ".IGNORE: go-vulncheck",
    ".IGNORE: check security-makefile-check precommit-swift",
    ".ONESHELL:",
  ]) {
    const result = check(`${canonical}\n${specialTarget}\n`);
    assert.notEqual(result.status, 0, `${specialTarget} must be rejected`);
    assert.match(result.stderr, /IGNORE|ONESHELL|suppress/i);
  }
});
