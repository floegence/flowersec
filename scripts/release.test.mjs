import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const sourceRoot = path.resolve(import.meta.dirname, "..");
const releaseMutationConcurrency = 4;
const mainGateGraphFiles = [
  "Makefile",
  ".githooks/pre-push",
  "scripts/check-security-makefile.mjs",
  "scripts/push-main.sh",
  "scripts/release.sh",
  "scripts/run-final-lanes.mjs",
  "scripts/run-final-stage.mjs",
];
const releasePolicyFixtureFiles = [
  "Makefile",
  ".github/dependabot.yml",
  ".githooks/pre-push",
  ".github/workflows/ci.yml",
  ".github/workflows/codeql.yml",
  ".github/workflows/release.yml",
  ".github/workflows/rust-release.yml",
  ".github/workflows/scorecard.yml",
  "docker/flowersec-runtime/Dockerfile",
  "scripts/check-release-version-consistency.mjs",
  "scripts/check-release-version-consistency.test.mjs",
  "scripts/check-container-release-policy.mjs",
  "scripts/check-release-workflows.rb",
  "scripts/check-release-workflow-policy.sh",
  "scripts/check-security-makefile.mjs",
  "scripts/run-final-lanes.mjs",
  "scripts/run-final-stage.mjs",
  "scripts/run-final-stage.test.mjs",
  "scripts/run-precommit-wave.mjs",
  "scripts/run-precommit-wave.test.mjs",
  "scripts/release.sh",
  "scripts/push-main.sh",
  "scripts/release.test.mjs",
];
const repositoryLocalEnvironmentVariables = [
  "GIT_ALTERNATE_OBJECT_DIRECTORIES",
  "GIT_COMMON_DIR",
  "GIT_CONFIG",
  "GIT_CONFIG_COUNT",
  "GIT_CONFIG_PARAMETERS",
  "GIT_DIR",
  "GIT_GRAFT_FILE",
  "GIT_IMPLICIT_WORK_TREE",
  "GIT_INDEX_FILE",
  "GIT_INTERNAL_SUPER_PREFIX",
  "GIT_NO_REPLACE_OBJECTS",
  "GIT_OBJECT_DIRECTORY",
  "GIT_PREFIX",
  "GIT_QUARANTINE_PATH",
  "GIT_REPLACE_REF_BASE",
  "GIT_SHALLOW_FILE",
  "GIT_WORK_TREE",
];

function isolatedEnvironment(overrides = {}) {
  const env = { ...process.env, ...overrides };
  for (const variable of repositoryLocalEnvironmentVariables) {
    delete env[variable];
  }
  return env;
}

test("release test helpers use literal executables", () => {
  const source = fs.readFileSync(import.meta.filename, "utf8");
  assert.doesNotMatch(source, /spawnSync\(\s*command\s*,/);
});

test("release policy assertions use anchored mirror URL matching", () => {
  const source = fs.readFileSync(import.meta.filename, "utf8");
  const unsafeMirrorAssertion = [
    "assert.match(containerfile, /https:",
    String.raw`\/\/mirrors\.aliyun\.com\/ubuntu-ports\//);`,
  ].join("");
  const unsafeMirrorSubstringAssertion = [
    "assert.ok(containerfile.",
    'includes("https://mirrors.aliyun.com/ubuntu-ports/"));',
  ].join("");
  assert.equal(
    source.includes(unsafeMirrorAssertion),
    false,
  );
  assert.equal(
    source.includes(unsafeMirrorSubstringAssertion),
    false,
  );
});

test("release policy mutations use bounded isolated concurrency", () => {
  const source = fs.readFileSync(import.meta.filename, "utf8");
  assert.match(source, /const releaseMutationConcurrency = 4;/);
  assert.match(
    source,
    /test\("release policy rejects disconnected or commented-out gates", \{ concurrency: releaseMutationConcurrency \}/,
  );
  assert.match(source, /await Promise\.all\(policyMutations\);/);
});

function runGit(args, options = {}) {
  const { env, ...spawnOptions } = options;
  const result = spawnSync("git", args, {
    encoding: "utf8",
    ...spawnOptions,
    env: isolatedEnvironment(env),
  });
  if (result.status !== 0) {
    throw new Error(
      `git ${args.join(" ")} failed:\n${result.stdout}${result.stderr}`,
    );
  }
  return result.stdout.trim();
}

function executablePath(name) {
  const result = spawnSync("which", [name], {
    encoding: "utf8",
    env: isolatedEnvironment(),
  });
  if (result.status !== 0) {
    throw new Error(`could not locate ${name}:\n${result.stdout}${result.stderr}`);
  }
  return result.stdout.trim();
}

function createReleaseScriptFixture(t, makeScript = "#!/bin/sh\nexit 0\n") {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-release-script-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const repo = path.join(root, "repo");
  const origin = path.join(root, "origin.git");
  const bin = path.join(root, "bin");
  const gitLog = path.join(root, "git.log");
  const goLog = path.join(root, "go.log");
  const realGit = executablePath("git");
  const realMake = executablePath("make");
  fs.mkdirSync(path.join(repo, "scripts"), { recursive: true });
  fs.mkdirSync(path.join(repo, "flowersec-ts"), { recursive: true });
  fs.mkdirSync(path.join(repo, "flowersec-rust/fuzz"), { recursive: true });
  fs.mkdirSync(path.join(repo, "examples/rust"), { recursive: true });
  fs.mkdirSync(bin, { recursive: true });

  for (const file of mainGateGraphFiles) {
    const destination = path.join(repo, file);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.copyFileSync(path.join(sourceRoot, file), destination);
  }
  fs.copyFileSync(
    path.join(sourceRoot, "scripts/check-release-version-consistency.mjs"),
    path.join(repo, "scripts/check-release-version-consistency.mjs"),
  );
  fs.chmodSync(path.join(repo, "scripts/release.sh"), 0o755);
  fs.writeFileSync(
    path.join(repo, "flowersec-ts/package.json"),
    JSON.stringify({ version: "0.26.0" }),
  );
  fs.writeFileSync(
    path.join(repo, "flowersec-ts/package-lock.json"),
    JSON.stringify({ version: "0.26.0", packages: { "": { version: "0.26.0" } } }),
  );
  fs.writeFileSync(
    path.join(repo, "flowersec-rust/Cargo.toml"),
    "[package]\nname = \"flowersec\"\nversion = \"0.26.0\"\n",
  );
  fs.writeFileSync(path.join(repo, "flowersec-rust/fuzz/Cargo.toml"), "[package]\nname = \"fuzz\"\n");
  fs.writeFileSync(path.join(repo, "examples/rust/Cargo.toml"), "[package]\nname = \"example\"\n");
  fs.writeFileSync(path.join(repo, "tracked.txt"), "clean\n");

  fs.writeFileSync(
    path.join(bin, "cargo"),
    "#!/bin/sh\nprintf '%s\\n' '{\"packages\":[{\"name\":\"flowersec\",\"version\":\"0.26.0\",\"source\":null}]}'\n",
  );
  fs.chmodSync(path.join(bin, "cargo"), 0o755);
  fs.writeFileSync(path.join(bin, "make"), makeScript);
  fs.chmodSync(path.join(bin, "make"), 0o755);
  fs.writeFileSync(
    path.join(bin, "go"),
    [
      "#!/bin/sh",
      "printf '%s\\n' \"$*\" >> \"$FLOWERSEC_TEST_GO_LOG\"",
      "if [ \"${FLOWERSEC_TEST_FAIL_NOTES:-0}\" = 1 ]; then exit 88; fi",
      "output=''",
      "previous=''",
      "for argument in \"$@\"; do",
      "  if [ \"$previous\" = --output ]; then output=\"$argument\"; fi",
      "  previous=\"$argument\"",
      "done",
      "[ -n \"$output\" ] && printf '%s\\n' '# release notes' > \"$output\"",
      "",
    ].join("\n"),
  );
  fs.chmodSync(path.join(bin, "go"), 0o755);
  fs.writeFileSync(
    path.join(bin, "git"),
    [
      "#!/bin/sh",
      "printf '%s\\n' \"$*\" >> \"$FLOWERSEC_TEST_GIT_LOG\"",
      "if [ \"$1\" = tag ] && [ \"${FLOWERSEC_TEST_FAIL_TAG:-}\" = \"${2:-}\" ]; then",
      "  exit 86",
      "fi",
      "if [ \"$1\" = push ] && [ \"${FLOWERSEC_TEST_FAIL_PUSH:-0}\" = 1 ]; then",
      "  exit 87",
      "fi",
      "exec \"$FLOWERSEC_TEST_REAL_GIT\" \"$@\"",
      "",
    ].join("\n"),
  );
  fs.chmodSync(path.join(bin, "git"), 0o755);

  runGit(["init", "--bare", origin]);
  runGit(["init", "-b", "main", repo]);
  runGit(["-C", repo, "config", "user.name", "Release Test"]);
  runGit(["-C", repo, "config", "user.email", "release-test@example.com"]);
  runGit(["-C", repo, "add", "."]);
  runGit(["-C", repo, "commit", "-m", "test: release fixture"]);
  runGit(["-C", repo, "remote", "add", "origin", origin]);
  runGit(["-C", repo, "push", "-u", "origin", "main"]);

  return { bin, gitLog, goLog, origin, realGit, realMake, repo };
}

function runReleaseScript(fixture, env = {}) {
  return spawnSync("bash", ["scripts/release.sh", "0.26.0"], {
    cwd: fixture.repo,
    encoding: "utf8",
    env: isolatedEnvironment({
      FLOWERSEC_TEST_GIT_LOG: fixture.gitLog,
      FLOWERSEC_TEST_GO_LOG: fixture.goLog,
      FLOWERSEC_TEST_REAL_GIT: fixture.realGit,
      PATH: `${fixture.bin}:${process.env.PATH}`,
      ...env,
    }),
  });
}

function gitCommands(fixture) {
  const contents = fs.readFileSync(fixture.gitLog, "utf8").trim();
  return contents === "" ? [] : contents.split("\n");
}

function assertNoReleaseTags(fixture) {
  assert.equal(runGit(["-C", fixture.repo, "tag", "--list"]), "");
  assert.equal(runGit(["--git-dir", fixture.origin, "tag", "--list"]), "");
}

function assertReleaseDidNotStartPublication(fixture) {
  assertNoReleaseTags(fixture);
  const commands = gitCommands(fixture);
  assert.equal(
    commands.some((command) => /^tag (?:flowersec-go\/v0\.26\.0|0\.26\.0|flowersec-rust\/v0\.26\.0) [0-9a-f]+$/.test(command)),
    false,
    commands.join("\n"),
  );
  assert.equal(commands.some((command) => command.startsWith("push ")), false, commands.join("\n"));
}

function createReleasePolicyFixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-release-policy-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const file of releasePolicyFixtureFiles) {
    const destination = path.join(root, file);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.copyFileSync(path.join(sourceRoot, file), destination);
  }
  return root;
}

function workflowSnapshot(root) {
  const workflowRoot = path.join(root, ".github/workflows");
  return Object.fromEntries(
    fs.readdirSync(workflowRoot)
      .filter((file) => file.endsWith(".yml") || file.endsWith(".yaml"))
      .sort()
      .map((file) => [file, fs.readFileSync(path.join(workflowRoot, file), "utf8")]),
  );
}

function runReleasePolicy(root) {
  const sourceWorkflows = workflowSnapshot(sourceRoot);
  const fixtureWorkflows = workflowSnapshot(root);
  const sourceWorkflowNames = Object.keys(sourceWorkflows);
  const fixtureWorkflowNames = Object.keys(fixtureWorkflows);
  const workflowSetMatches = JSON.stringify(sourceWorkflowNames) === JSON.stringify(fixtureWorkflowNames);
  const workflowsChanged = JSON.stringify(sourceWorkflows) !== JSON.stringify(fixtureWorkflows);
  const changedNonWorkflowFiles = releasePolicyFixtureFiles.filter((file) => {
    if (file.startsWith(".github/workflows/")) return false;
    return fs.readFileSync(path.join(root, file), "utf8") !== fs.readFileSync(path.join(sourceRoot, file), "utf8");
  });
  if (workflowSetMatches && workflowsChanged && changedNonWorkflowFiles.length === 0) {
    return spawnSync("ruby", ["-W0", "scripts/check-release-workflows.rb"], {
      cwd: root,
      encoding: "utf8",
      env: isolatedEnvironment(),
    });
  }
  if (!workflowsChanged && changedNonWorkflowFiles.length === 1 && changedNonWorkflowFiles[0] === "Makefile") {
    return spawnSync("node", ["scripts/check-security-makefile.mjs", "Makefile"], {
      cwd: root,
      encoding: "utf8",
      env: isolatedEnvironment(),
    });
  }
  return spawnSync("bash", ["scripts/check-release-workflow-policy.sh"], {
    cwd: root,
    encoding: "utf8",
    env: isolatedEnvironment(),
  });
}

test("release fixtures cannot modify an inherited hook repository", (t) => {
  const sentinel = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-release-sentinel-"));
  t.after(() => fs.rmSync(sentinel, { recursive: true, force: true }));
  runGit(["init", "-b", "main", sentinel]);
  const sentinelConfig = path.join(sentinel, ".git/config");
  const before = fs.readFileSync(sentinelConfig, "utf8");
  const canonical = spawnSync("git", ["rev-parse", "--local-env-vars"], {
    encoding: "utf8",
    env: { PATH: process.env.PATH },
  });
  assert.equal(canonical.status, 0, canonical.stderr);
  for (const variable of canonical.stdout.trim().split("\n")) {
    assert.ok(repositoryLocalEnvironmentVariables.includes(variable), `missing Git local environment variable ${variable}`);
  }
  const original = Object.fromEntries(
    repositoryLocalEnvironmentVariables.map((variable) => [variable, process.env[variable]]),
  );

  try {
    for (const variable of repositoryLocalEnvironmentVariables) {
      process.env[variable] = "inherited";
    }
    process.env.GIT_DIR = path.join(sentinel, ".git");
    process.env.GIT_WORK_TREE = sentinel;
    process.env.GIT_INDEX_FILE = path.join(sentinel, ".git/index");
    const fixture = createReleaseScriptFixture(t);
    assert.equal(runGit(["-C", fixture.repo, "status", "--short"]), "");
  } finally {
    for (const variable of repositoryLocalEnvironmentVariables) {
      if (original[variable] === undefined) {
        delete process.env[variable];
      } else {
        process.env[variable] = original[variable];
      }
    }
  }

  assert.equal(fs.readFileSync(sentinelConfig, "utf8"), before);
});

test("release script rejects non-canonical versions before repository access", () => {
  for (const version of ["02.0.0", "2.00.0", "2.0.00"]) {
    const result = spawnSync("bash", ["scripts/release.sh", version], {
      cwd: sourceRoot,
      encoding: "utf8",
      env: isolatedEnvironment(),
    });
    assert.equal(result.status, 2, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /major\.minor\.patch/);
  }
});

test("release gates stay wired into local checks and publication workflows", () => {
  const makefile = fs.readFileSync(path.join(sourceRoot, "Makefile"), "utf8");
  const releaseWorkflow = fs.readFileSync(
    path.join(sourceRoot, ".github/workflows/release.yml"),
    "utf8",
  );
  const rustWorkflow = fs.readFileSync(
    path.join(sourceRoot, ".github/workflows/rust-release.yml"),
    "utf8",
  );
  const ciWorkflow = fs.readFileSync(
    path.join(sourceRoot, ".github/workflows/ci.yml"),
    "utf8",
  );
  const policyScript = fs.readFileSync(
    path.join(sourceRoot, "scripts/check-release-workflow-policy.sh"),
    "utf8",
  );

  assert.match(makefile, /^release-version-check:\n\tnode scripts\/check-release-version-consistency\.mjs$/m);
  assert.match(
    makefile,
    /^release-test:\n\tnode --test scripts\/check-release-version-consistency\.test\.mjs scripts\/release\.test\.mjs$/m,
  );
  assert.match(makefile, /^release-policy-check:\n(?:\t.*\n)*\t\$\(MAKE\) release-version-check$/m);
  assert.match(makefile, /^release-policy-check:\n(?:\t.*\n)*\t\$\(MAKE\) release-test$/m);
  assert.match(
    makefile,
    /^check: security-makefile-check\n\t\$\(MAKE\) release-policy-check$/m,
  );
  assert.match(makefile, /^check: security-makefile-check\n(?:\t.*\n)*\t\$\(MAKE\) final-integration-lanes$/m);
  assert.match(makefile, /^final-integration-lanes:\n\tCARGO_NET_OFFLINE=true GOPROXY=off GOSUMDB=off npm_config_offline=true node scripts\/run-final-stage\.mjs 595 race \$\(MAKE\) final-race-check\n\tCARGO_NET_OFFLINE=true GOPROXY=off GOSUMDB=off npm_config_offline=true node scripts\/run-final-stage\.mjs 595 languages node scripts\/run-final-lanes\.mjs \$\(MAKE\) final-go-check final-ts-check final-swift-check final-rust-check\n\tnode scripts\/run-final-stage\.mjs 595 browser \$\(MAKE\) browser-smoke$/m);
  assert.match(makefile, /^release-check:\n\tnode scripts\/check-release-version-consistency\.mjs$/m);
  assert.doesNotMatch(makefile, /^release-check:\n(?:\t.*\n)*\t\$\(MAKE\) /m);
  assert.match(
    releaseWorkflow,
    /^\s+RELEASE_VERSION: \$\{\{ steps\.vars\.outputs\.version \}\}\n\s+run: node scripts\/check-release-version-consistency\.mjs "\$RELEASE_VERSION"$/m,
  );
  assert.match(
    rustWorkflow,
    /^\s+RELEASE_VERSION: \$\{\{ steps\.version\.outputs\.version \}\}\n\s+run: node scripts\/check-release-version-consistency\.mjs "\$RELEASE_VERSION"$/m,
  );
  for (const workflow of [releaseWorkflow, rustWorkflow]) {
    const rustSetup = workflow.indexOf("uses: dtolnay/rust-toolchain@4cda84d5c5c54efe2404f9d843567869ab1699d4");
    const versionCheck = workflow.indexOf("run: node scripts/check-release-version-consistency.mjs");
    assert.ok(rustSetup >= 0 && rustSetup < versionCheck, "Rust must be set up before Cargo metadata validation");
  }
  const releaseScript = fs.readFileSync(
    path.join(sourceRoot, "scripts/release.sh"),
    "utf8",
  );
  assert.match(
    releaseWorkflow,
    /go -C tools\/releasenotes run \. \\[\r\n]+\s*--repo \.\.\/\.\./,
    "release workflow must run release notes from its Go module",
  );
  assert.doesNotMatch(
    releaseWorkflow,
    /go run \.\/tools\/releasenotes/,
    "release workflow must not assume a root Go module",
  );
  for (const required of [releaseScript, releaseWorkflow, rustWorkflow]) {
    assert.match(required, /check-release-version-consistency\.mjs/);
  }
  assert.match(policyScript, /check-release-version-consistency\.mjs/);
  assert.match(ciWorkflow, /^\s+run: scripts\/check-release-workflow-policy\.sh$/m);
  assert.match(ciWorkflow, /^\s+run: make precommit$/m);
  assert.match(ciWorkflow, /actions\/dependency-review-action@[0-9a-f]{40} # v5\.0\.0/);
});

test("default and final Go gates use the maintained source and test runner", () => {
  const makefile = fs.readFileSync(path.join(sourceRoot, "Makefile"), "utf8");
  const goTest = makefile.match(/^go-test:\n((?:\t.*\n)+)/m)?.[1] ?? "";
  assert.match(goTest, /\.\.\/scripts\/list-default-go-test-packages\.sh/);
  assert.doesNotMatch(goTest, /transport-test-runner|transportcheck/);
  assert.doesNotMatch(makefile, /tools\/transportcheck|transportcheck-diagnostic-contract|transport-v2-unit/);
  assert.match(makefile, /^test:\n\tgo -C flowersec-go run \.\/internal\/cmd\/flowersec-test run --suite acceptance$/m);
  assert.match(makefile, /^test-resume:\n\tgo -C flowersec-go run \.\/internal\/cmd\/flowersec-test resume --suite acceptance$/m);
  assert.match(makefile, /^browser-smoke:\n\tgo -C flowersec-go run \.\/internal\/cmd\/flowersec-test run --suite browser-smoke$/m);
  assert.match(makefile, /^diagnostic:\n\t\$\(FLOWERSEC_TEST_HOST\) run --suite diagnostic$/m);
  assert.match(makefile, /^performance:\n\t\$\(FLOWERSEC_TEST_HOST\) run --suite performance$/m);
});

test("release stays publication-only while main push owns fast acceptance", () => {
  const makefile = fs.readFileSync(path.join(sourceRoot, "Makefile"), "utf8");
  const releaseRecipe = makefile.match(/^release-check:\n((?:\t.*\n)+)/m)?.[1] ?? "";
  const releaseScript = fs.readFileSync(path.join(sourceRoot, "scripts/release.sh"), "utf8");
  const pushScript = fs.readFileSync(path.join(sourceRoot, "scripts/push-main.sh"), "utf8");
  const prePush = fs.readFileSync(path.join(sourceRoot, ".githooks/pre-push"), "utf8");

  assert.doesNotMatch(releaseRecipe, /\$\(MAKE\) check/);
  assert.match(releaseRecipe, /check-release-version-consistency\.mjs/);
  assert.doesNotMatch(releaseRecipe, /transport-v2|receipt|evidence|\$\(MAKE\)/);
  assert.doesNotMatch(releaseScript, /\bmake\b/);
  assert.doesNotMatch(
    releaseScript,
    /\b(?:go run|go test|npm|cargo|swift (?:build|test)|transport-v2-(?:release|signed|result))\b/,
  );
  assert.match(releaseScript, /go -C tools\/releasenotes run \. \\[\r\n]+\s*--repo \.\.\/\.\./);
  assert.doesNotMatch(releaseScript, /go run \.\/tools\/releasenotes/);
  assert.doesNotMatch(prePush, /make(?: -C \"\$repo_root\")? check/);
  assert.match(prePush, /use \.\/scripts\/push-main\.sh/);

  const gate = pushScript.indexOf("make test");
  const push = pushScript.indexOf("git push origin");
  assert.ok(gate >= 0 && gate < push, "fast acceptance must precede push");
  assert.doesNotMatch(pushScript, /make (?:precommit|check)/);
  assert.doesNotMatch(pushScript, /evidence|receipt/);
});

test("release workflows pin actions and pass expressions through fields, not shell source", () => {
  const workflows = [
    ".github/workflows/ci.yml",
    ".github/workflows/codeql.yml",
    ".github/workflows/release.yml",
    ".github/workflows/rust-release.yml",
    ".github/workflows/scorecard.yml",
  ].map((file) => ({ file, source: fs.readFileSync(path.join(sourceRoot, file), "utf8") }));
  for (const { file, source } of workflows) {
    for (const match of source.matchAll(/^\s*uses:\s+(\S+)(?:\s+#\s*(\S+))?$/gm)) {
      if (match[1].startsWith("./")) continue;
      assert.match(match[1], /@[0-9a-f]{40}$/, `${file} must pin ${match[1]} to a commit`);
      assert.ok(match[2], `${file} must retain a readable version comment for ${match[1]}`);
    }
  }
  const ruby = [
    'require "psych"',
    'ARGV.each do |file|',
    '  workflow = Psych.safe_load(File.read(file), aliases: false)',
    '  workflow.fetch("jobs").each_value do |job|',
    '    Array(job["steps"]).each do |step|',
    '      abort("#{file}: #{step["name"] || step["uses"]} interpolates an expression into run") if step["run"]&.include?("${{")',
    '    end',
    '  end',
    'end',
  ].join("\n");
  const result = spawnSync("ruby", ["-W0", "-rpsych", "-e", ruby, ...workflows.map(({ file }) => file)], {
    cwd: sourceRoot,
    encoding: "utf8",
  });
  assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
  const dependabot = fs.readFileSync(path.join(sourceRoot, ".github/dependabot.yml"), "utf8");
  for (const [ecosystem, directory] of [
    ["github-actions", "/"],
    ["npm", "/flowersec-ts"],
    ["gomod", "/flowersec-go"],
    ["gomod", "/tools/idlgen"],
    ["gomod", "/tools/releasenotes"],
    ["gomod", "/tools/stabilitycheck"],
    ["cargo", "/flowersec-rust"],
    ["cargo", "/flowersec-rust/fuzz"],
    ["cargo", "/examples/rust"],
    ["swift", "/"],
    ["swift", "/examples/swift"],
  ]) {
    const escapedDirectory = directory.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    assert.match(
      dependabot,
      new RegExp(`  - package-ecosystem: ${ecosystem}\\n    directory: ${escapedDirectory}\\n    schedule:\\n      interval: weekly`),
    );
  }
  assert.doesNotMatch(dependabot, /open-pull-requests-limit:/);
  assert.match(
    dependabot,
    /^    groups:\n      codeql-action:\n        patterns:\n          - github\/codeql-action$/m,
  );
  assert.match(
    dependabot,
    /  - package-ecosystem: gomod\n    directory: \/flowersec-go\n    schedule:\n      interval: weekly\n    groups:\n      quic-stack:\n        patterns:\n          - github\.com\/quic-go\/quic-go\n          - github\.com\/quic-go\/webtransport-go/m,
  );
  assert.match(
    dependabot,
    /  - package-ecosystem: cargo\n    directory: \/flowersec-rust\n    schedule:\n      interval: weekly\n    ignore:\n      # Flowersec v2 freezes IDNA behavior to Unicode 15\.1; 1\.1\.0 moves to Unicode 16\.0\.\n      - dependency-name: idna_mapping\n        versions:\n          - ">= 1\.1\.0"/m,
  );
  assert.match(
    dependabot,
    /  - package-ecosystem: npm\n    directory: \/flowersec-ts\n    schedule:\n      interval: weekly\n    ignore:\n      # Flowersec v2 freezes IDNA behavior to Unicode 15\.1; tr46 6 uses newer data\.\n      - dependency-name: tr46\n        versions:\n          - ">= 6\.0\.0"/m,
  );
  assert.match(
    dependabot,
    /      # idna_adapter 1\.2 uses newer ICU data that accepts post-15\.1 code points\.\n      - dependency-name: idna_adapter\n        versions:\n          - ">= 1\.2\.0"/m,
  );
});

test("CodeQL scans every language on changes and does not hide Swift failures", () => {
  const workflowPath = path.join(sourceRoot, ".github/workflows/codeql.yml");
  assert.equal(fs.existsSync(workflowPath), true, "the bounded CodeQL workflow must exist");
  const workflow = fs.readFileSync(workflowPath, "utf8");
  assert.match(workflow, /^name: codeql$/m);
  assert.match(workflow, /^on:\n  workflow_dispatch: \{\}\n  push:\n    branches:\n      - main\n  pull_request:\n    branches:\n      - main\n  schedule:\n    - cron: "17 3 \* \* \*"$/m);
  assert.match(workflow, /^  plan:\n    name: Plan scheduled analysis$/m);
  assert.match(workflow, /actions\/workflows\/codeql\.yml\/runs\?branch=main&event=schedule&status=success&per_page=1/);
  assert.match(workflow, /previous_sha=.*workflow_runs\[0\]\.head_sha/);
  assert.match(workflow, /Could not inspect previous CodeQL runs; scanning fail-safe\./);
  assert.match(workflow, /"\$previous_sha" == "\$HEAD_SHA"/);
  assert.match(workflow, /^    needs: plan\n    if: needs\.plan\.outputs\.should_scan == 'true'$/m);
  assert.doesNotMatch(workflow, /continue-on-error:/);
  assert.match(workflow, /^    timeout-minutes: 45$/m);
  for (const language of ["actions", "c-cpp", "go", "javascript-typescript", "ruby", "rust", "swift"]) {
    assert.match(workflow, new RegExp("^          - language: " + language + "$", "m"));
  }
  assert.match(workflow, /^          - language: c-cpp\n            build-mode: none$/m);
  assert.match(workflow, /^          - language: rust\n            build-mode: none$/m);
  assert.match(workflow, /^          - language: swift\n            build-mode: manual\n            runner: macos-26$/m);
  assert.match(workflow, /^        uses: github\/codeql-action\/init@[0-9a-f]{40} # v4(?:\.[0-9]+)*$/m);
  assert.match(workflow, /^          languages: \$\{\{ matrix\.language \}\}\n          build-mode: \$\{\{ matrix\.build-mode \}\}\n          queries: security-extended$/m);
  assert.match(workflow, /^      - name: Resolve Swift cache key\n        if: matrix\.language == 'swift'\n        id: swift-cache-key\n        run: \|\n          swift --version \| shasum -a 256 \| awk '\{ print "toolchain=" \$1 \}' >> "\$GITHUB_OUTPUT"$/m);
  assert.match(workflow, /^      - name: Restore Swift build cache\n        if: matrix\.language == 'swift'\n        uses: actions\/cache@[0-9a-f]{40} # v4(?:\.[0-9]+)*\n        with:\n          path: \.build\n          key: swift-codeql-\$\{\{ runner\.os \}\}-\$\{\{ steps\.swift-cache-key\.outputs\.toolchain \}\}-\$\{\{ hashFiles\('Package\.swift', 'Package\.resolved'\) \}\}$/m);
  const prepareSwift = workflow.indexOf("      - name: Prepare Swift build cache");
  const restoreSwift = workflow.indexOf("      - name: Restore Swift build cache");
  const initializeCodeQL = workflow.indexOf("      - name: Initialize CodeQL");
  assert.notEqual(restoreSwift, -1, "Swift dependency artifacts must be restored across runs");
  assert.notEqual(prepareSwift, -1, "Swift dependencies must be built outside CodeQL tracing");
  assert.ok(restoreSwift < prepareSwift, "the Swift build cache must be restored before dependency preparation");
  assert.ok(prepareSwift < initializeCodeQL, "Swift dependencies must be built before CodeQL initialization");
  assert.match(workflow, /^        run: \|\n          swift package --skip-update --only-use-versions-from-resolved-file resolve\n          swift build --skip-update --only-use-versions-from-resolved-file --target Flowersec -j 8$/m);
  assert.match(workflow, /^      - name: Build Swift library\n        if: matrix\.language == 'swift'\n        run: \|\n          find flowersec-swift\/Sources\/Flowersec -type f -name '\*\.swift' -exec touch \{\} \+\n          swift build --skip-update --only-use-versions-from-resolved-file --target Flowersec -j 8$/m);
  assert.match(workflow, /^        if: matrix\.language == 'go'\n        uses: github\/codeql-action\/autobuild@[0-9a-f]{40} # v4(?:\.[0-9]+)*$/m);
  assert.match(workflow, /^        uses: github\/codeql-action\/analyze@[0-9a-f]{40} # v4(?:\.[0-9]+)*$/m);
});

test("release workflow parser passes filenames compatibly across Psych versions", () => {
  const checker = fs.readFileSync(path.join(sourceRoot, "scripts/check-release-workflows.rb"), "utf8");
  assert.match(checker, /Psych\.parse_stream\(source, filename: path\)/);
  assert.doesNotMatch(checker, /Psych\.parse_stream\(source, path\)/);
});

test("Rust recovery rejects non-canonical versions before invoking git", (t) => {
  const ruby = [
    'require "psych"',
    'workflow = Psych.safe_load(File.read(ARGV.fetch(0)), aliases: false)',
    'step = workflow.fetch("jobs").fetch("publish").fetch("steps").find { |entry| entry["name"] == "Checkout release commit" }',
    'print step.fetch("run")',
  ].join("\n");
  const extracted = spawnSync("ruby", ["-W0", "-rpsych", "-e", ruby, ".github/workflows/rust-release.yml"], {
    cwd: sourceRoot,
    encoding: "utf8",
  });
  assert.equal(extracted.status, 0, `${extracted.stdout}${extracted.stderr}`);

  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-rust-release-input-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const bin = path.join(root, "bin");
  const gitLog = path.join(root, "git.log");
  fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin, "git"), `#!/bin/sh\nprintf '%s\\n' "$*" >> ${JSON.stringify(gitLog)}\nexit 99\n`);
  fs.chmodSync(path.join(bin, "git"), 0o755);

  for (const version of [
    "02.0.0",
    '2.0.0"; echo unexpected; #',
    "2.0.0$(echo unexpected)",
    "2.0.0;printf${IFS}unexpected",
  ]) {
    const output = path.join(root, `output-${Math.random()}`);
    const result = spawnSync("bash", ["-c", extracted.stdout], {
      cwd: sourceRoot,
      encoding: "utf8",
      env: isolatedEnvironment({
        GITHUB_OUTPUT: output,
        PATH: `${bin}:${process.env.PATH}`,
        RELEASE_VERSION_INPUT: version,
      }),
    });
    assert.equal(result.status, 2, `${result.stdout}${result.stderr}`);
  }
  assert.equal(fs.existsSync(gitLog), false, "invalid versions must fail before git");
});

test("release policy rejects disconnected or commented-out gates", { concurrency: releaseMutationConcurrency }, async (t) => {
  const policyMutations = [];
  const schedulePolicyTest = (name, fn) => {
    policyMutations.push(t.test(name, { concurrency: true }, fn));
  };
  schedulePolicyTest("current policy passes", () => {
    const root = createReleasePolicyFixture(t);
    const result = runReleasePolicy(root);
    assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
  });

  for (const bypass of [
    { name: "npm publication before the release gate", run: "npm publish" },
    { name: "GitHub release publication before the release gate", run: "gh release create bypass" },
  ]) {
    schedulePolicyTest(`rejects ${bypass.name}`, () => {
      const root = createReleasePolicyFixture(t);
      const workflowPath = path.join(root, ".github/workflows/release.yml");
      const workflow = fs.readFileSync(workflowPath, "utf8");
      const marker = "  release:\n    needs: prepare\n    runs-on: ubuntu-latest\n    permissions:\n      contents: write\n      packages: write\n      id-token: write\n    steps:\n";
      assert.ok(workflow.includes(marker));
      fs.writeFileSync(workflowPath, workflow.replace(marker, `${marker}      - name: Unreviewed command\n        run: ${bypass.run}\n\n`));
      const result = runReleasePolicy(root);
      assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
      assert.match(result.stderr, /step sequence|publication|unreviewed/i);
    });
  }

  schedulePolicyTest("rejects cargo publication before the Rust gate", () => {
    const root = createReleasePolicyFixture(t);
    const workflowPath = path.join(root, ".github/workflows/rust-release.yml");
    const workflow = fs.readFileSync(workflowPath, "utf8");
    const marker = "  publish:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: read\n      id-token: write\n    steps:\n";
    assert.ok(workflow.includes(marker));
    fs.writeFileSync(workflowPath, workflow.replace(marker, `${marker}      - name: Unreviewed cargo publication\n        run: cargo publish\n\n`));
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /step sequence|publication|unreviewed/i);
  });

  schedulePolicyTest("rejects an unreviewed publication action", () => {
    const root = createReleasePolicyFixture(t);
    const workflowPath = path.join(root, ".github/workflows/release.yml");
    const workflow = fs.readFileSync(workflowPath, "utf8");
    const marker = "  release:\n    needs: prepare\n    runs-on: ubuntu-latest\n    permissions:\n      contents: write\n      packages: write\n      id-token: write\n    steps:\n";
    assert.ok(workflow.includes(marker));
    fs.writeFileSync(workflowPath, workflow.replace(marker, `${marker}      - name: Unreviewed publisher\n        uses: example/publish-action@v1\n\n`));
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /step sequence|publication|unreviewed/i);
  });

  for (const mutation of [
    { name: "workflow", file: ".github/workflows/bypass.yaml", contents: "name: bypass\non: push\njobs: {}\n" },
    {
      name: "job",
      file: ".github/workflows/release.yml",
      marker: "jobs:\n",
      replacement: "jobs:\n  bypass:\n    runs-on: ubuntu-latest\n    steps: []\n",
    },
    {
      name: "harmless-looking step",
      file: ".github/workflows/ci.yml",
      marker: "    steps:\n",
      replacement: "    steps:\n      - name: Unreviewed step\n        run: echo bypass\n\n",
    },
  ]) {
    schedulePolicyTest(`rejects an unreviewed ${mutation.name}`, () => {
      const root = createReleasePolicyFixture(t);
      const target = path.join(root, mutation.file);
      if (mutation.contents) {
        fs.writeFileSync(target, mutation.contents);
      } else {
        const source = fs.readFileSync(target, "utf8");
        assert.ok(source.includes(mutation.marker));
        fs.writeFileSync(target, source.replace(mutation.marker, mutation.replacement));
      }
      const result = runReleasePolicy(root);
      assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
      assert.match(result.stderr, /workflow|job|step sequence|unreviewed/i);
    });
  }

  schedulePolicyTest("release validation rejects injected environment controls", () => {
    const root = createReleasePolicyFixture(t);
    const workflowPath = path.join(root, ".github/workflows/release.yml");
    const workflow = fs.readFileSync(workflowPath, "utf8");
    const marker = "          RELEASE_VERSION: ${{ steps.vars.outputs.version }}\n";
    assert.ok(workflow.includes(marker));
    fs.writeFileSync(workflowPath, workflow.replace(marker, `${marker}          NODE_OPTIONS: --require ./bypass.cjs\n`));
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /environment|reviewed value|version facts/i);
  });

  for (const mutation of [
    "        shell: bash --noprofile --norc -c 'true; exit 0; #' {0}\n",
    "        working-directory: flowersec-ts\n",
  ]) {
    schedulePolicyTest(`release validation rejects semantic override ${mutation.trim()}`, () => {
      const root = createReleasePolicyFixture(t);
      const workflowPath = path.join(root, ".github/workflows/release.yml");
      const workflow = fs.readFileSync(workflowPath, "utf8");
      const marker = "      - name: Validate release version facts\n";
      assert.ok(workflow.includes(marker));
      fs.writeFileSync(workflowPath, workflow.replace(marker, `${marker}${mutation}`));
      const result = runReleasePolicy(root);
      assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
      assert.match(result.stderr, /fields|validation|version facts/i);
    });
  }

  for (const mutation of [
    ["working-directory: flowersec-rust", "working-directory: ."],
    ["CARGO_REGISTRY_TOKEN: ${{ steps.auth.outputs.token }}", "CARGO_REGISTRY_TOKEN: attacker-token"],
    ["run: cargo publish --no-verify", "run: cargo publish --allow-dirty"],
    ["uses: rust-lang/crates-io-auth-action@c6f97d42243bad5fab37ca0427f495c86d5b1a18", "uses: example/auth-action@v1"],
  ]) {
    schedulePolicyTest(`Rust publication rejects changed contract ${mutation[0]}`, () => {
      const root = createReleasePolicyFixture(t);
      const workflowPath = path.join(root, ".github/workflows/rust-release.yml");
      const workflow = fs.readFileSync(workflowPath, "utf8");
      assert.ok(workflow.includes(mutation[0]));
      fs.writeFileSync(workflowPath, workflow.replace(mutation[0], mutation[1]));
      const result = runReleasePolicy(root);
      assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
      assert.match(result.stderr, /Rust|crate|publish|action|token|directory/i);
    });
  }

  schedulePolicyTest("release tests disconnected from release-policy-check", () => {
    const root = createReleasePolicyFixture(t);
    const makefilePath = path.join(root, "Makefile");
    const makefile = fs.readFileSync(makefilePath, "utf8");
    fs.writeFileSync(makefilePath, makefile.replace("\t$(MAKE) release-test\n", ""));
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /release-test/);
  });

  schedulePolicyTest("Dependabot action updates cannot be replaced by block-scalar decoys", () => {
    const root = createReleasePolicyFixture(t);
    const configPath = path.join(root, ".github/dependabot.yml");
    const config = fs.readFileSync(configPath, "utf8");
    fs.writeFileSync(configPath, `${config
      .replace("package-ecosystem: github-actions", "package-ecosystem: npm")
      .replace("interval: weekly", "interval: daily")}decoy: |2\n  - package-ecosystem: github-actions\n      interval: weekly\n`);
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /Dependabot|reviewed value|fields/i);
  });

  schedulePolicyTest("release version check disconnected from release-check", () => {
    const root = createReleasePolicyFixture(t);
    const makefilePath = path.join(root, "Makefile");
    const makefile = fs.readFileSync(makefilePath, "utf8");
    const versionCheck = "\tnode scripts/check-release-version-consistency.mjs\n";
    assert.ok(makefile.includes(versionCheck));
    fs.writeFileSync(
      makefilePath,
      makefile.replace(versionCheck, ""),
    );
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /release-check|version/i);
  });

  schedulePolicyTest("complete tests cannot enter release-check", () => {
    const root = createReleasePolicyFixture(t);
    const makefilePath = path.join(root, "Makefile");
    const makefile = fs.readFileSync(makefilePath, "utf8");
    const versionCheck = "\tnode scripts/check-release-version-consistency.mjs\n";
    assert.ok(makefile.includes(versionCheck));
    fs.writeFileSync(
      makefilePath,
      makefile.replace(
        versionCheck,
        `\t$(MAKE) check\n${versionCheck}`,
      ),
    );
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /release-check|exact recipe|check/i);
  });

  schedulePolicyTest("commented unified workflow version check", () => {
    const root = createReleasePolicyFixture(t);
    const workflowPath = path.join(root, ".github/workflows/release.yml");
    const workflow = fs.readFileSync(workflowPath, "utf8");
    fs.writeFileSync(
      workflowPath,
      workflow.replace(
        '        run: node scripts/check-release-version-consistency.mjs "$RELEASE_VERSION"',
        '        # run: node scripts/check-release-version-consistency.mjs "$RELEASE_VERSION"',
      ),
    );
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /unified release workflow/);
  });

  for (const mutation of [
    "        if: ${{ false }}\n",
    "        continue-on-error: true\n",
  ]) {
    schedulePolicyTest(`disabled unified workflow version check: ${mutation.trim()}`, () => {
      const root = createReleasePolicyFixture(t);
      const workflowPath = path.join(root, ".github/workflows/release.yml");
      const workflow = fs.readFileSync(workflowPath, "utf8");
      fs.writeFileSync(
        workflowPath,
        workflow.replace(
          "      - name: Validate release version facts\n",
          `      - name: Validate release version facts\n${mutation}`,
        ),
      );
      const result = runReleasePolicy(root);
      assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
      assert.match(result.stderr, /unified release workflow/);
    });
  }

  const equivalentControlKeyMutations = [
    "        if : ${{ false }}\n",
    "        \"if\": ${{ false }}\n",
    "        'if' : ${{ false }}\n",
    "        \"\\u0069f\": ${{ false }}\n",
    "        continue-on-error : true\n",
    "        \"continue-on-error\": true\n",
    "        \"continue-on-\\u0065rror\": true\n",
  ];
  for (const step of [
    { file: ".github/workflows/release.yml", name: "Validate release version facts" },
    { file: ".github/workflows/release.yml", name: "Publish GitHub Release" },
    { file: ".github/workflows/rust-release.yml", name: "Publish crate" },
  ]) {
    for (const mutation of equivalentControlKeyMutations) {
      schedulePolicyTest(`${step.name} rejects equivalent YAML key ${mutation.trim()}`, () => {
        const root = createReleasePolicyFixture(t);
        const workflowPath = path.join(root, step.file);
        const workflow = fs.readFileSync(workflowPath, "utf8");
        const marker = `      - name: ${step.name}\n`;
        assert.ok(workflow.includes(marker), `${step.file} is missing ${step.name}`);
        fs.writeFileSync(workflowPath, workflow.replace(marker, `${marker}${mutation}`));
        const result = runReleasePolicy(root);
        assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
      });
    }
  }

  const criticalSteps = [
    { file: ".github/workflows/release.yml", name: "Build release artifacts" },
    { file: ".github/workflows/release.yml", name: "Generate release notes" },
    { file: ".github/workflows/release.yml", name: "Publish GitHub Release" },
    { file: ".github/workflows/release.yml", name: "Build and push runtime image" },
    { file: ".github/workflows/release.yml", name: "Publish npm package" },
    { file: ".github/workflows/rust-release.yml", name: "Check whether version is already published" },
    { file: ".github/workflows/rust-release.yml", name: "Authenticate to crates.io" },
    { file: ".github/workflows/rust-release.yml", name: "Publish crate" },
  ];
  for (const step of criticalSteps) {
    for (const mutation of [
      "        if: ${{ always() }}\n",
      "        continue-on-error: true\n",
    ]) {
      schedulePolicyTest(`${step.name} rejects ${mutation.trim()}`, () => {
        const root = createReleasePolicyFixture(t);
        const workflowPath = path.join(root, step.file);
        const workflow = fs.readFileSync(workflowPath, "utf8");
        const marker = `      - name: ${step.name}\n`;
        assert.ok(workflow.includes(marker), `${step.file} is missing ${step.name}`);
        fs.writeFileSync(workflowPath, workflow.replace(marker, `${marker}${mutation}`));
        const result = runReleasePolicy(root);
        assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
        assert.match(result.stderr, /publication step|Rust publication step|duplicate YAML key|fields/);
      });
    }
  }

  schedulePolicyTest("unified workflow version failure is swallowed", () => {
    const root = createReleasePolicyFixture(t);
    const workflowPath = path.join(root, ".github/workflows/release.yml");
    const workflow = fs.readFileSync(workflowPath, "utf8");
    fs.writeFileSync(
      workflowPath,
      workflow.replace(
        'run: node scripts/check-release-version-consistency.mjs "$RELEASE_VERSION"',
        'run: node scripts/check-release-version-consistency.mjs "$RELEASE_VERSION" || true',
      ),
    );
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /unified release workflow/);
  });

  schedulePolicyTest("indented fake targets cannot hide no-op real gates", () => {
    const root = createReleasePolicyFixture(t);
    const makefilePath = path.join(root, "Makefile");
    const replaceTarget = (source, target, replacement) => {
      const lines = source.split("\n");
      const start = lines.findIndex((line) => line.startsWith(`${target}:`));
      assert.ok(start >= 0, `missing Make target ${target}`);
      let end = start + 1;
      while (end < lines.length && (lines[end].startsWith("\t") || lines[end].trim() === "")) end += 1;
      lines.splice(start, end - start, ...replacement.split("\n"));
      return lines.join("\n");
    };
    let makefile = fs.readFileSync(makefilePath, "utf8");
    makefile = replaceTarget(makefile, "check", [
      "check :",
      "\t@:",
      "",
      "policy-decoy-check:",
      "\tcheck:",
      "\t$(MAKE) release-policy-check",
      "\t$(MAKE) transport-tool-contract",
      "\t$(MAKE) weaknet-smoke",
      "\t$(MAKE) quic-native-smoke",
    ].join("\n"));
    makefile = replaceTarget(makefile, "release-check", [
      "release-check :",
      "\t@:",
      "",
      "policy-decoy-release-check:",
      "\trelease-check:",
      "\t$(MAKE) check",
      "\t$(MAKE) interop-stress-full",
      "\t$(MAKE) transport-v2-result-check",
    ].join("\n"));
    fs.writeFileSync(makefilePath, makefile);
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /Makefile target (?:check|release-check)/);
  });

  schedulePolicyTest("Make definitions cannot hide no-op effective release gates", () => {
    const root = createReleasePolicyFixture(t);
    const makefilePath = path.join(root, "Makefile");
    const makefile = fs.readFileSync(makefilePath, "utf8");
    const replaceTarget = (source, target, replacement) => {
      const lines = source.split("\n");
      const start = lines.findIndex((line) => line.startsWith(`${target}:`));
      assert.ok(start >= 0, `missing Make target ${target}`);
      let end = start + 1;
      while (end < lines.length && (lines[end].startsWith("\t") || lines[end].trim() === "")) end += 1;
      lines.splice(start, end - start, ...replacement.split("\n"));
      return lines.join("\n");
    };
    let mutated = replaceTarget(makefile, "check", [
      "define policy_decoy_check",
      "check:",
      "\t$(MAKE) release-policy-check",
      "\t$(MAKE) transport-tool-contract",
      "\t$(MAKE) weaknet-smoke",
      "\t$(MAKE) quic-native-smoke",
      "endef",
      "check::",
      "\t@:",
    ].join("\n"));
    mutated = replaceTarget(mutated, "release-check", [
      "define policy_decoy_release_check",
      "release-check:",
      "\t$(MAKE) check",
      "\t$(MAKE) interop-stress-full",
      "\t$(MAKE) transport-v2-result-check",
      "endef",
      "release-check::",
      "\t@:",
    ].join("\n"));
    fs.writeFileSync(makefilePath, mutated);
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /effective|Makefile target|release gate/i);
  });

  schedulePolicyTest("validation run must be a direct step field", () => {
    const root = createReleasePolicyFixture(t);
    const workflowPath = path.join(root, ".github/workflows/release.yml");
    const workflow = fs.readFileSync(workflowPath, "utf8");
    const expected = [
      "      - name: Validate release version facts",
      "        env:",
      "          RELEASE_VERSION: ${{ steps.vars.outputs.version }}",
      '        run: node scripts/check-release-version-consistency.mjs "$RELEASE_VERSION"',
    ].join("\n");
    const replacement = [
      "      - name: Validate release version facts",
      "        env:",
      "          RELEASE_VERSION: ${{ steps.vars.outputs.version }}",
      '          run: node scripts/check-release-version-consistency.mjs "$RELEASE_VERSION"',
      "        run: echo bypassed",
    ].join("\n");
    assert.ok(workflow.includes(expected));
    fs.writeFileSync(workflowPath, workflow.replace(expected, replacement));
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /version facts|direct step field|unified release workflow/i);
  });

  schedulePolicyTest("Rust setup uses must be a direct step field", () => {
    const root = createReleasePolicyFixture(t);
    const workflowPath = path.join(root, ".github/workflows/release.yml");
    const workflow = fs.readFileSync(workflowPath, "utf8");
    const expected = [
      "      - name: Setup Rust",
      "        uses: dtolnay/rust-toolchain@4cda84d5c5c54efe2404f9d843567869ab1699d4 # stable",
    ].join("\n");
    const replacement = [
      "      - name: Setup Rust",
      "        env:",
      "          uses: dtolnay/rust-toolchain@4cda84d5c5c54efe2404f9d843567869ab1699d4",
      "        run: echo bypassed",
    ].join("\n");
    assert.ok(workflow.includes(expected));
    fs.writeFileSync(workflowPath, workflow.replace(expected, replacement));
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /Setup Rust|direct step field|set up Rust/i);
  });

  schedulePolicyTest("Rust publish condition must be a direct step field", () => {
    const root = createReleasePolicyFixture(t);
    const workflowPath = path.join(root, ".github/workflows/rust-release.yml");
    const workflow = fs.readFileSync(workflowPath, "utf8");
    const expected = [
      "      - name: Publish crate",
      "        if: steps.published.outputs.exists != 'true'",
      "        working-directory: flowersec-rust",
      "        env:",
      "          CARGO_REGISTRY_TOKEN: ${{ steps.auth.outputs.token }}",
    ].join("\n");
    const replacement = [
      "      - name: Publish crate",
      "        working-directory: flowersec-rust",
      "        env:",
      "          if: steps.published.outputs.exists != 'true'",
      "          CARGO_REGISTRY_TOKEN: ${{ steps.auth.outputs.token }}",
    ].join("\n");
    assert.ok(workflow.includes(expected));
    fs.writeFileSync(workflowPath, workflow.replace(expected, replacement));
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /approved condition|direct step field|Rust publication step|fields/i);
  });

  schedulePolicyTest("workflow aliases and merge keys are rejected", () => {
    const root = createReleasePolicyFixture(t);
    const workflowPath = path.join(root, ".github/workflows/release.yml");
    const workflow = fs.readFileSync(workflowPath, "utf8");
    const marker = "jobs:\n";
    assert.ok(workflow.includes(marker));
    fs.writeFileSync(
      workflowPath,
      workflow.replace(marker, "guard: &guard\n  if: ${{ false }}\n\njobs:\n")
        .replace("  release:\n", "  release:\n    <<: *guard\n"),
    );
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /alias|anchor|merge|unconditional/i);
  });

  for (const implicitKey of ["yes", "true", "ON"]) {
    schedulePolicyTest(`implicit YAML scalar key ${implicitKey} cannot shadow the Actions on key`, () => {
      const root = createReleasePolicyFixture(t);
      const workflowPath = path.join(root, ".github/workflows/release.yml");
      const workflow = fs.readFileSync(workflowPath, "utf8");
      const reviewedTrigger = [
        "on:",
        "  push:",
        "    tags:",
        "      - \"flowersec-go/v*\"",
      ].join("\n");
      assert.ok(workflow.includes(reviewedTrigger));
      fs.writeFileSync(workflowPath, workflow.replace(reviewedTrigger, [
        "on: {}",
        `${implicitKey}:`,
        "  push:",
        "    tags:",
        "      - \"flowersec-go/v*\"",
      ].join("\n")));
      const result = runReleasePolicy(root);
      assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
      assert.match(result.stderr, /implicit|mapping key|ambiguous|on key/i);
    });
  }

  for (const mutation of [
    ["push: true", "push: yes"],
    ["fetch-depth: 0", "fetch-depth: 00"],
    ["fetch-depth: 0", "fetch-depth: +0"],
  ]) {
    schedulePolicyTest(`non-canonical YAML scalar ${mutation[1]} is rejected`, () => {
      const root = createReleasePolicyFixture(t);
      const workflowPath = path.join(root, ".github/workflows/release.yml");
      const workflow = fs.readFileSync(workflowPath, "utf8");
      assert.ok(workflow.includes(mutation[0]));
      fs.writeFileSync(workflowPath, workflow.replace(mutation[0], mutation[1]));
      const result = runReleasePolicy(root);
      assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
      assert.match(result.stderr, /canonical|implicit|scalar|reviewed value/i);
    });
  }

  schedulePolicyTest("hosted CI invokes the full local release gate", () => {
    const root = createReleasePolicyFixture(t);
    const workflowPath = path.join(root, ".github/workflows/ci.yml");
    const workflow = fs.readFileSync(workflowPath, "utf8");
    fs.writeFileSync(
      workflowPath,
      workflow.replace(
        "run: scripts/check-release-workflow-policy.sh",
        "run: make release-policy-check",
      ),
    );
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /hosted CI/);
  });

  schedulePolicyTest("release validation steps moved into the prepare job", () => {
    const root = createReleasePolicyFixture(t);
    const workflowPath = path.join(root, ".github/workflows/release.yml");
    const workflow = fs.readFileSync(workflowPath, "utf8");
    const guardedSteps = [
      "      - name: Setup Rust",
      "        uses: dtolnay/rust-toolchain@4cda84d5c5c54efe2404f9d843567869ab1699d4 # stable",
      "",
      "      - name: Validate release version facts",
      "        env:",
      "          RELEASE_VERSION: ${{ steps.vars.outputs.version }}",
      '        run: node scripts/check-release-version-consistency.mjs "$RELEASE_VERSION"',
      "",
    ].join("\n");
    assert.ok(workflow.includes(guardedSteps));
    fs.writeFileSync(
      workflowPath,
      workflow.replace(guardedSteps, "").replace(
        "\n  rust-publish:",
        `\n${guardedSteps}\n  rust-publish:`,
      ),
    );
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /unified release workflow/);
  });

  schedulePolicyTest("release version validation moved after publication", () => {
    const root = createReleasePolicyFixture(t);
    const workflowPath = path.join(root, ".github/workflows/release.yml");
    const workflow = fs.readFileSync(workflowPath, "utf8");
    const validationStep = [
      "      - name: Validate release version facts",
      "        env:",
      "          RELEASE_VERSION: ${{ steps.vars.outputs.version }}",
      '        run: node scripts/check-release-version-consistency.mjs "$RELEASE_VERSION"',
      "",
    ].join("\n");
    assert.ok(workflow.includes(validationStep));
    fs.writeFileSync(
      workflowPath,
      `${workflow.replace(validationStep, "")}\n${validationStep}`,
    );
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /in order|before every publication step|step sequence/);
  });

  schedulePolicyTest("release tag verification moved after publication", () => {
    const root = createReleasePolicyFixture(t);
    const workflowPath = path.join(root, ".github/workflows/release.yml");
    const workflow = fs.readFileSync(workflowPath, "utf8");
    const verificationStep = [
      "      - name: Verify all language tags point to this commit",
      "        env:",
      "          RELEASE_VERSION: ${{ steps.vars.outputs.version }}",
      "          RELEASE_SHA: ${{ steps.vars.outputs.sha }}",
      '        run: scripts/verify-release-tags.sh "$RELEASE_VERSION" "$RELEASE_SHA"',
      "",
    ].join("\n");
    assert.ok(workflow.includes(verificationStep));
    fs.writeFileSync(
      workflowPath,
      `${workflow.replace(verificationStep, "")}\n${verificationStep}`,
    );
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /before every publication step|step sequence/);
  });

  for (const tt of [
    { file: ".github/workflows/release.yml", job: "release" },
    { file: ".github/workflows/release.yml", job: "rust-publish" },
    { file: ".github/workflows/rust-release.yml", job: "publish" },
  ]) {
    for (const mutation of [
      "    if: ${{ false }}\n",
      "    if : ${{ false }}\n",
      "    \"if\": ${{ false }}\n",
      "    'if' : ${{ false }}\n",
      "    \"\\x69f\": ${{ false }}\n",
      "    \"\\u0069f\": ${{ false }}\n",
    ]) {
      schedulePolicyTest(`${tt.job} job rejects ${mutation.trim()}`, () => {
        const root = createReleasePolicyFixture(t);
        const workflowPath = path.join(root, tt.file);
        const workflow = fs.readFileSync(workflowPath, "utf8");
        fs.writeFileSync(
          workflowPath,
          workflow.replace(`  ${tt.job}:\n`, `  ${tt.job}:\n${mutation}`),
        );
        const result = runReleasePolicy(root);
        assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
        assert.match(result.stderr, /must remain unconditional|fields/);
      });
    }
  }
  await Promise.all(policyMutations);
});

test("release validates maintained versions before publication", (t) => {
  const fixture = createReleaseScriptFixture(t);
  fs.writeFileSync(
    path.join(fixture.repo, "flowersec-ts/package.json"),
    JSON.stringify({ version: "0.25.0" }),
  );
  runGit(["-C", fixture.repo, "add", "flowersec-ts/package.json"]);
  runGit(["-C", fixture.repo, "commit", "-m", "test: stale release version"]);
  runGit(["-C", fixture.repo, "push", "origin", "main"]);

  const result = runReleaseScript(fixture);
  assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
  assert.match(result.stderr, /release versions are inconsistent/);
  assertReleaseDidNotStartPublication(fixture);
});

test("release removes all local tags when tag creation fails partway", (t) => {
  const fixture = createReleaseScriptFixture(t);
  const result = runReleaseScript(fixture, { FLOWERSEC_TEST_FAIL_TAG: "0.26.0" });

  assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
  assertNoReleaseTags(fixture);
  const commands = gitCommands(fixture);
  assert.ok(commands.includes("tag flowersec-go/v0.26.0 " + runGit(["-C", fixture.repo, "rev-parse", "HEAD"])), commands.join("\n"));
  assert.equal(commands.some((command) => command.startsWith("push ")), false, commands.join("\n"));
});

test("release removes all local tags when atomic push fails", (t) => {
  const fixture = createReleaseScriptFixture(t);
  const result = runReleaseScript(fixture, { FLOWERSEC_TEST_FAIL_PUSH: "1" });

  assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
  assertNoReleaseTags(fixture);
  const commands = gitCommands(fixture);
  assert.ok(commands.some((command) => command.startsWith("push --atomic origin ")), commands.join("\n"));
});

test("release notes preflight rejects generator failure and removes local tags", (t) => {
  const fixture = createReleaseScriptFixture(t);
  const result = runReleaseScript(fixture, { FLOWERSEC_TEST_FAIL_NOTES: "1" });

  assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
  assert.match(result.stderr, /release notes preflight failed/);
  assertNoReleaseTags(fixture);
  const commands = gitCommands(fixture);
  assert.equal(commands.some((command) => command.startsWith("push ")), false, commands.join("\n"));
  assert.match(fs.readFileSync(fixture.goLog, "utf8"), /-C tools\/releasenotes run \. --repo \.\.\/\./);
});

test("release can retry after an atomic push failure without moving tags", (t) => {
  const fixture = createReleaseScriptFixture(t);
  const failed = runReleaseScript(fixture, { FLOWERSEC_TEST_FAIL_PUSH: "1" });
  assert.notEqual(failed.status, 0, `${failed.stdout}${failed.stderr}`);
  assertNoReleaseTags(fixture);

  const retried = runReleaseScript(fixture);
  assert.equal(retried.status, 0, `${retried.stdout}${retried.stderr}`);
  assert.deepEqual(runGit(["--git-dir", fixture.origin, "tag", "--list"]).split("\n"), [
    "0.26.0",
    "flowersec-go/v0.26.0",
    "flowersec-rust/v0.26.0",
  ]);
});

test("release publishes main and all ecosystem tags atomically", (t) => {
  const fixture = createReleaseScriptFixture(t);
  const result = runReleaseScript(fixture);

  assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
  const expectedTags = ["0.26.0", "flowersec-go/v0.26.0", "flowersec-rust/v0.26.0"];
  assert.deepEqual(runGit(["-C", fixture.repo, "tag", "--list"]).split("\n"), expectedTags);
  assert.deepEqual(runGit(["--git-dir", fixture.origin, "tag", "--list"]).split("\n"), expectedTags);
  assert.equal(
    runGit(["-C", fixture.repo, "rev-parse", "HEAD"]),
    runGit(["--git-dir", fixture.origin, "rev-parse", "refs/heads/main"]),
  );
  const commands = gitCommands(fixture);
  assert.ok(commands.some((command) => command.startsWith("push --atomic origin ")), commands.join("\n"));
});

test("pre-push accepts only the complete release tag set for the synchronized commit", async (t) => {
  const hook = path.join(sourceRoot, ".githooks/pre-push");
  const verified = "1".repeat(40);
  const other = "2".repeat(40);
  const deleted = "0".repeat(40);
  const tagLine = (ref, sha = verified) => `${ref} ${sha} ${ref} ${deleted}`;
  const allTags = [
    tagLine("refs/tags/flowersec-go/v0.26.0"),
    tagLine("refs/tags/0.26.0"),
    tagLine("refs/tags/flowersec-rust/v0.26.0"),
  ];
  const releaseEnv = {
    ...process.env,
    FLOWERSEC_RELEASE_PUSH_SHA: verified,
    FLOWERSEC_RELEASE_VERSION: "0.26.0",
  };
  const cases = [
    {
      name: "missing release entrypoint marker",
      lines: allTags,
      env: process.env,
      status: 1,
      error: /must be pushed with scripts\/release\.sh/,
    },
    {
      name: "missing one ecosystem tag",
      lines: allTags.slice(0, 2),
      env: releaseEnv,
      status: 1,
      error: /must be pushed together/,
    },
    {
      name: "tag points to another commit",
      lines: [...allTags.slice(0, 2), tagLine("refs/tags/flowersec-rust/v0.26.0", other)],
      env: releaseEnv,
      status: 1,
      error: /must point to the synchronized release commit/,
    },
    {
      name: "complete synchronized release",
      lines: allTags,
      env: releaseEnv,
      status: 0,
    },
  ];

  for (const tt of cases) {
    await t.test(tt.name, () => {
      const result = spawnSync("sh", [hook], {
        encoding: "utf8",
        env: isolatedEnvironment(tt.env),
        input: `${tt.lines.join("\n")}\n`,
      });
      assert.equal(result.status, tt.status, `${result.stdout}${result.stderr}`);
      if (tt.error) {
        assert.match(result.stderr, tt.error);
      }
    });
  }
});

test("pre-push permits push-main and rejects direct main pushes without running tests", (t) => {
  const marker = path.join(os.tmpdir(), `flowersec-pre-push-make-${process.pid}-${Date.now()}`);
  t.after(() => fs.rmSync(marker, { force: true }));
  const fixture = createReleaseScriptFixture(
    t,
    `#!/bin/sh\nprintf invoked > ${JSON.stringify(marker)}\nexit 99\n`,
  );
  const hook = path.join(fixture.repo, ".githooks/pre-push");
  const head = runGit(["-C", fixture.repo, "rev-parse", "HEAD"]);
  const input = `refs/heads/main ${head} refs/heads/main ${head}\n`;
  const env = isolatedEnvironment({
    FLOWERSEC_TEST_GIT_LOG: fixture.gitLog,
    FLOWERSEC_TEST_REAL_GIT: fixture.realGit,
    PATH: `${fixture.bin}${path.delimiter}${process.env.PATH}`,
    FLOWERSEC_PUSH_MAIN_SHA: head,
  });

  const verified = spawnSync("sh", [hook], {
    cwd: fixture.repo,
    encoding: "utf8",
    env,
    input,
  });
  assert.equal(verified.status, 0, `${verified.stdout}${verified.stderr}`);
  assert.equal(fs.existsSync(marker), false, "pre-push must not invoke make");

  const direct = spawnSync("sh", [hook], {
    cwd: fixture.repo,
    encoding: "utf8",
    env: isolatedEnvironment({
      FLOWERSEC_TEST_GIT_LOG: fixture.gitLog,
      FLOWERSEC_TEST_REAL_GIT: fixture.realGit,
      PATH: `${fixture.bin}${path.delimiter}${process.env.PATH}`,
    }),
    input,
  });
  assert.notEqual(direct.status, 0, `${direct.stdout}${direct.stderr}`);
  assert.match(direct.stderr, /use \.\/scripts\/push-main\.sh/);
  assert.equal(fs.existsSync(marker), false, "direct push rejection must not invoke make");
});

test("main push gates the exact SHA with fast acceptance before opening the remote transport", () => {
  const script = path.join(sourceRoot, "scripts/push-main.sh");
  assert.equal(fs.existsSync(script), true, "scripts/push-main.sh is missing");
  const source = fs.readFileSync(script, "utf8");
  const gate = source.indexOf("make test");
  const push = source.indexOf("git push origin");
  assert.notEqual(gate, -1, "main push must run fast acceptance");
  assert.notEqual(push, -1, "main push must use normal git push");
  assert.ok(gate < push, "the gate must finish before git opens the push transport");
  assert.match(source, /FLOWERSEC_PUSH_MAIN_SHA="\$head" git push/);
  assert.doesNotMatch(source, /make (?:precommit|check)/);
  assert.doesNotMatch(source, /receipt|TRANSPORT_V2_EVIDENCE/);
  assert.doesNotMatch(source, /--no-verify/);
});

test("main push passes only the checked HEAD after the gate completes", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-main-push-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const bin = path.join(root, "bin");
  const log = path.join(root, "commands.log");
  const head = "a".repeat(40);
  const origin = "b".repeat(40);
  fs.mkdirSync(bin);
  fs.writeFileSync(
    path.join(bin, "git"),
    [
      "#!/bin/sh",
      "printf 'git %s\\n' \"$*\" >> \"$FLOWERSEC_TEST_COMMAND_LOG\"",
      "case \"$*\" in",
      "  'status --short') exit 0 ;;",
      "  'symbolic-ref --short -q HEAD') printf 'main\\n' ; exit 0 ;;",
      `  'rev-parse HEAD') printf '${head}\\n' ; exit 0 ;;`,
      `  'rev-parse origin/main') printf '${origin}\\n' ; exit 0 ;;`,
      "  'fetch origin main') exit 0 ;;",
      "  'merge-base --is-ancestor '*) exit 0 ;;",
      `  'push origin refs/heads/main:refs/heads/main') [ "${"$"}{FLOWERSEC_PUSH_MAIN_SHA:-}" = '${head}' ] ; exit ;;`,
      "esac",
      "exit 90",
      "",
    ].join("\n"),
    { mode: 0o755 },
  );
  fs.writeFileSync(
    path.join(bin, "make"),
    "#!/bin/sh\nprintf 'make %s\\n' \"$*\" >> \"$FLOWERSEC_TEST_COMMAND_LOG\"\n",
    { mode: 0o755 },
  );
  const result = spawnSync("bash", [path.join(sourceRoot, "scripts/push-main.sh")], {
    cwd: sourceRoot,
    encoding: "utf8",
    env: isolatedEnvironment({
      ...process.env,
      FLOWERSEC_TEST_COMMAND_LOG: log,
      PATH: `${bin}${path.delimiter}${process.env.PATH}`,
    }),
  });
  assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
  const commands = fs.readFileSync(log, "utf8").trim().split("\n");
  const gate = commands.indexOf("make test");
  const push = commands.findIndex((command) => command.startsWith("git push origin "));
  assert.ok(gate >= 0 && push > gate, commands.join("\n"));
  assert.equal(commands.filter((command) => command === "make test").length, 1, commands.join("\n"));
});

test("browser compatibility remains explicit and separate from Chromium smoke", () => {
  const registry = fs.readFileSync(path.join(sourceRoot, "flowersec-go/internal/cmd/flowersec-test/registry.go"), "utf8");
  assert.match(registry, /browserCompatibilityEntry\("browser\/firefox\/webtransport-capability"/);
  assert.match(registry, /browserCompatibilityEntry\("browser\/webkit\/webtransport-capability"/);
  assert.doesNotMatch(registry, /"diagnostic\/browser"/);
  const packageManifest = fs.readFileSync(path.join(sourceRoot, "flowersec-ts/package.json"), "utf8");
  assert.match(packageManifest, /"test:browser": "npm run test:browser:chromium"/);
  assert.match(packageManifest, /"test:browser:chromium": "npm run ensure:browser && npm run build && playwright test --project=chromium"/);
  assert.match(packageManifest, /"test:browser:firefox": "npm run ensure:browser:firefox && npm run build && playwright test --project=firefox-compat"/);
  assert.match(packageManifest, /"test:browser:webkit": "npm run ensure:browser:webkit && npm run build && playwright test --project=webkit-smoke"/);
});
