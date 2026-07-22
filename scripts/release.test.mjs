import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const sourceRoot = path.resolve(import.meta.dirname, "..");
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

function run(command, args, options = {}) {
  const { env, ...spawnOptions } = options;
  const result = spawnSync(command, args, {
    encoding: "utf8",
    ...spawnOptions,
    env: isolatedEnvironment(env),
  });
  if (result.status !== 0) {
    throw new Error(
      `${command} ${args.join(" ")} failed:\n${result.stdout}${result.stderr}`,
    );
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
  const realGit = run("sh", ["-c", "command -v git"]);
  fs.mkdirSync(path.join(repo, "scripts"), { recursive: true });
  fs.mkdirSync(path.join(repo, "flowersec-ts"), { recursive: true });
  fs.mkdirSync(path.join(repo, "flowersec-rust/fuzz"), { recursive: true });
  fs.mkdirSync(path.join(repo, "examples/rust"), { recursive: true });
  fs.mkdirSync(path.join(repo, "docs/releases"), { recursive: true });
  fs.mkdirSync(bin, { recursive: true });

  for (const script of ["release.sh", "check-release-version-consistency.mjs"]) {
    fs.copyFileSync(path.join(sourceRoot, "scripts", script), path.join(repo, "scripts", script));
  }
  fs.chmodSync(path.join(repo, "scripts/release.sh"), 0o755);
  fs.cpSync(
    path.join(sourceRoot, "tools/releasenotes"),
    path.join(repo, "tools/releasenotes"),
    {
      recursive: true,
      filter(source) {
        return !source.endsWith("_test.go");
      },
    },
  );
  fs.copyFileSync(
    path.join(sourceRoot, "docs/releases/0.26.0.md"),
    path.join(repo, "docs/releases/0.26.0.md"),
  );
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

  run("git", ["init", "--bare", origin]);
  run("git", ["init", "-b", "main", repo]);
  run("git", ["-C", repo, "config", "user.name", "Release Test"]);
  run("git", ["-C", repo, "config", "user.email", "release-test@example.com"]);
  run("git", ["-C", repo, "add", "."]);
  run("git", ["-C", repo, "commit", "-m", "test: release fixture"]);
  run("git", ["-C", repo, "remote", "add", "origin", origin]);
  run("git", ["-C", repo, "push", "-u", "origin", "main"]);

  return { bin, gitLog, origin, realGit, repo };
}

function runReleaseScript(fixture, env = {}) {
  return spawnSync("bash", ["scripts/release.sh", "0.26.0"], {
    cwd: fixture.repo,
    encoding: "utf8",
    env: isolatedEnvironment({
      FLOWERSEC_TEST_GIT_LOG: fixture.gitLog,
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
  assert.equal(run("git", ["-C", fixture.repo, "tag", "--list"]), "");
  assert.equal(run("git", ["--git-dir", fixture.origin, "tag", "--list"]), "");
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
  const files = [
    "Makefile",
    ".githooks/pre-push",
    ".github/workflows/ci.yml",
    ".github/workflows/release.yml",
    ".github/workflows/rust-release.yml",
    "scripts/check-release-version-consistency.mjs",
    "scripts/check-release-version-consistency.test.mjs",
    "scripts/check-release-workflow-policy.sh",
    "scripts/check-transport-v2-evidence.sh",
    "scripts/release.sh",
    "scripts/release.test.mjs",
  ];
  for (const file of files) {
    const destination = path.join(root, file);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.copyFileSync(path.join(sourceRoot, file), destination);
  }
  return root;
}

function runReleasePolicy(root) {
  return spawnSync("bash", ["scripts/check-release-workflow-policy.sh"], {
    cwd: root,
    encoding: "utf8",
    env: isolatedEnvironment(),
  });
}

test("release fixtures cannot modify an inherited hook repository", (t) => {
  const sentinel = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-release-sentinel-"));
  t.after(() => fs.rmSync(sentinel, { recursive: true, force: true }));
  run("git", ["init", "-b", "main", sentinel]);
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
    assert.equal(run("git", ["-C", fixture.repo, "status", "--short"]), "");
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
  assert.match(makefile, /^check:\n\t\$\(MAKE\) release-policy-check$/m);
  for (const target of ["transport-v2-unit", "weaknet-smoke", "quic-native-smoke"]) {
    assert.match(makefile, new RegExp(`^check:\\n(?:\\t.*\\n)*\\t\\$\\(MAKE\\) ${target}$`, "m"));
  }
  for (const target of ["transport-v2-release-evidence", "transport-v2-signed-evidence-check"]) {
    assert.match(makefile, new RegExp(`^release-check:\\n(?:\\t.*\\n)*\\t\\$\\(MAKE\\) ${target}$`, "m"));
  }
  assert.match(
    releaseWorkflow,
    /^\s+run: node scripts\/check-release-version-consistency\.mjs "\$\{\{ steps\.vars\.outputs\.version \}\}"$/m,
  );
  assert.match(
    rustWorkflow,
    /^\s+run: node scripts\/check-release-version-consistency\.mjs "\$\{\{ steps\.version\.outputs\.version \}\}"$/m,
  );
  for (const workflow of [releaseWorkflow, rustWorkflow]) {
    const rustSetup = workflow.indexOf("uses: dtolnay/rust-toolchain@stable");
    const versionCheck = workflow.indexOf("run: node scripts/check-release-version-consistency.mjs");
    assert.ok(rustSetup >= 0 && rustSetup < versionCheck, "Rust must be set up before Cargo metadata validation");
  }
  const releaseScript = fs.readFileSync(
    path.join(sourceRoot, "scripts/release.sh"),
    "utf8",
  );
  for (const required of [releaseScript, releaseWorkflow, rustWorkflow]) {
    assert.match(required, /check-release-version-consistency\.mjs/);
  }
  assert.match(policyScript, /check-release-version-consistency\.mjs/);
  assert.match(ciWorkflow, /^\s+run: scripts\/check-release-workflow-policy\.sh$/m);
});

test("release policy rejects disconnected or commented-out gates", async (t) => {
  await t.test("current policy passes", () => {
    const root = createReleasePolicyFixture(t);
    const result = runReleasePolicy(root);
    assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
  });

  await t.test("release tests disconnected from release-policy-check", () => {
    const root = createReleasePolicyFixture(t);
    const makefilePath = path.join(root, "Makefile");
    const makefile = fs.readFileSync(makefilePath, "utf8");
    fs.writeFileSync(makefilePath, makefile.replace("\t$(MAKE) release-test\n", ""));
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /release-test/);
  });

  await t.test("signed Transport v2 evidence disconnected from release-check", () => {
    const root = createReleasePolicyFixture(t);
    const makefilePath = path.join(root, "Makefile");
    const makefile = fs.readFileSync(makefilePath, "utf8");
    fs.writeFileSync(
      makefilePath,
      makefile.replace("\t$(MAKE) transport-v2-signed-evidence-check\n", ""),
    );
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /transport-v2-signed-evidence-check/);
  });

  await t.test("Transport v2 evidence generation disconnected from release-check", () => {
    const root = createReleasePolicyFixture(t);
    const makefilePath = path.join(root, "Makefile");
    const makefile = fs.readFileSync(makefilePath, "utf8");
    fs.writeFileSync(
      makefilePath,
      makefile.replace("\t$(MAKE) transport-v2-release-evidence\n", ""),
    );
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /transport-v2-release-evidence/);
  });

  await t.test("commented unified workflow version check", () => {
    const root = createReleasePolicyFixture(t);
    const workflowPath = path.join(root, ".github/workflows/release.yml");
    const workflow = fs.readFileSync(workflowPath, "utf8");
    fs.writeFileSync(
      workflowPath,
      workflow.replace(
        '        run: node scripts/check-release-version-consistency.mjs "${{ steps.vars.outputs.version }}"',
        '        # run: node scripts/check-release-version-consistency.mjs "${{ steps.vars.outputs.version }}"',
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
    await t.test(`disabled unified workflow version check: ${mutation.trim()}`, () => {
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

  await t.test("unified workflow version failure is swallowed", () => {
    const root = createReleasePolicyFixture(t);
    const workflowPath = path.join(root, ".github/workflows/release.yml");
    const workflow = fs.readFileSync(workflowPath, "utf8");
    fs.writeFileSync(
      workflowPath,
      workflow.replace(
        'run: node scripts/check-release-version-consistency.mjs "${{ steps.vars.outputs.version }}"',
        'run: node scripts/check-release-version-consistency.mjs "${{ steps.vars.outputs.version }}" || true',
      ),
    );
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /unified release workflow/);
  });

  await t.test("hosted CI invokes the full local release gate", () => {
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

  await t.test("release validation steps moved into the prepare job", () => {
    const root = createReleasePolicyFixture(t);
    const workflowPath = path.join(root, ".github/workflows/release.yml");
    const workflow = fs.readFileSync(workflowPath, "utf8");
    const guardedSteps = [
      "      - name: Setup Rust",
      "        uses: dtolnay/rust-toolchain@stable",
      "",
      "      - name: Validate release version facts",
      '        run: node scripts/check-release-version-consistency.mjs "${{ steps.vars.outputs.version }}"',
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

  await t.test("release version validation moved after publication", () => {
    const root = createReleasePolicyFixture(t);
    const workflowPath = path.join(root, ".github/workflows/release.yml");
    const workflow = fs.readFileSync(workflowPath, "utf8");
    const validationStep = [
      "      - name: Validate release version facts",
      '        run: node scripts/check-release-version-consistency.mjs "${{ steps.vars.outputs.version }}"',
      "",
    ].join("\n");
    assert.ok(workflow.includes(validationStep));
    fs.writeFileSync(
      workflowPath,
      `${workflow.replace(validationStep, "")}\n${validationStep}`,
    );
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /in order|before every publication step/);
  });

  await t.test("release tag verification moved after publication", () => {
    const root = createReleasePolicyFixture(t);
    const workflowPath = path.join(root, ".github/workflows/release.yml");
    const workflow = fs.readFileSync(workflowPath, "utf8");
    const verificationStep = [
      "      - name: Verify all language tags point to this commit",
      '        run: scripts/verify-release-tags.sh "${{ steps.vars.outputs.version }}" "${GITHUB_SHA}"',
      "",
    ].join("\n");
    assert.ok(workflow.includes(verificationStep));
    fs.writeFileSync(
      workflowPath,
      `${workflow.replace(verificationStep, "")}\n${verificationStep}`,
    );
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /before every publication step/);
  });

  for (const tt of [
    { file: ".github/workflows/release.yml", job: "release" },
    { file: ".github/workflows/release.yml", job: "rust-publish" },
    { file: ".github/workflows/rust-release.yml", job: "publish" },
  ]) {
    await t.test(`${tt.job} job is disabled`, () => {
      const root = createReleasePolicyFixture(t);
      const workflowPath = path.join(root, tt.file);
      const workflow = fs.readFileSync(workflowPath, "utf8");
      fs.writeFileSync(
        workflowPath,
        workflow.replace(`  ${tt.job}:\n`, `  ${tt.job}:\n    if: \${{ false }}\n`),
      );
      const result = runReleasePolicy(root);
      assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
      assert.match(result.stderr, /must remain unconditional/);
    });
  }
});

test("release validates maintained versions before publication", (t) => {
  const fixture = createReleaseScriptFixture(t);
  fs.writeFileSync(
    path.join(fixture.repo, "flowersec-ts/package.json"),
    JSON.stringify({ version: "0.25.0" }),
  );
  run("git", ["-C", fixture.repo, "add", "flowersec-ts/package.json"]);
  run("git", ["-C", fixture.repo, "commit", "-m", "test: stale release version"]);
  run("git", ["-C", fixture.repo, "push", "origin", "main"]);

  const result = runReleaseScript(fixture);
  assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
  assert.match(result.stderr, /release versions are inconsistent/);
  assertReleaseDidNotStartPublication(fixture);
});

for (const tt of [
  {
    name: "missing",
    write(repo) {
      fs.rmSync(path.join(repo, "docs/releases/0.26.0.md"));
    },
    error: /docs\/releases\/0\.26\.0\.md/,
  },
  {
    name: "wrong heading",
    write(repo) {
      fs.writeFileSync(path.join(repo, "docs/releases/0.26.0.md"), "# Flowersec 0.25.0\n\nDetails.\n");
    },
    error: /must start with/,
  },
  {
    name: "heading only",
    write(repo) {
      fs.writeFileSync(path.join(repo, "docs/releases/0.26.0.md"), "# Flowersec 0.26.0\n");
    },
    error: /must include content after/,
  },
]) {
  test(`release rejects ${tt.name} curated notes before publication`, (t) => {
    const fixture = createReleaseScriptFixture(t);
    tt.write(fixture.repo);
    run("git", ["-C", fixture.repo, "add", "-A"]);
    run("git", ["-C", fixture.repo, "commit", "-m", `test: ${tt.name} release notes`]);
    run("git", ["-C", fixture.repo, "push", "origin", "main"]);

    const result = runReleaseScript(fixture);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, tt.error);
    assertReleaseDidNotStartPublication(fixture);
  });
}

test("release stops before git tag or push when release-check dirties the worktree", (t) => {
  const fixture = createReleaseScriptFixture(
    t,
    "#!/bin/sh\nprintf '%s\\n' dirty >> tracked.txt\n",
  );
  const result = runReleaseScript(fixture);

  assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
  assert.match(result.stderr, /release-check modified the worktree/);
  assertReleaseDidNotStartPublication(fixture);
});

test("release stops before git tag or push when release-check changes HEAD", (t) => {
  const fixture = createReleaseScriptFixture(
    t,
    "#!/bin/sh\nprintf '%s\\n' generated > release-generated.txt\ngit add release-generated.txt\ngit commit -m 'test: release-check commit' >/dev/null\n",
  );
  const result = runReleaseScript(fixture);

  assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
  assert.match(result.stderr, /release-check changed HEAD/);
  assertReleaseDidNotStartPublication(fixture);
});

test("release removes all local tags when tag creation fails partway", (t) => {
  const fixture = createReleaseScriptFixture(t);
  const result = runReleaseScript(fixture, { FLOWERSEC_TEST_FAIL_TAG: "0.26.0" });

  assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
  assertNoReleaseTags(fixture);
  const commands = gitCommands(fixture);
  assert.ok(commands.includes("tag flowersec-go/v0.26.0 " + run("git", ["-C", fixture.repo, "rev-parse", "HEAD"])), commands.join("\n"));
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

test("release publishes main and all ecosystem tags atomically", (t) => {
  const fixture = createReleaseScriptFixture(t);
  const result = runReleaseScript(fixture);

  assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
  const expectedTags = ["0.26.0", "flowersec-go/v0.26.0", "flowersec-rust/v0.26.0"];
  assert.deepEqual(run("git", ["-C", fixture.repo, "tag", "--list"]).split("\n"), expectedTags);
  assert.deepEqual(run("git", ["--git-dir", fixture.origin, "tag", "--list"]).split("\n"), expectedTags);
  assert.equal(
    run("git", ["-C", fixture.repo, "rev-parse", "HEAD"]),
    run("git", ["--git-dir", fixture.origin, "rev-parse", "refs/heads/main"]),
  );
  const commands = gitCommands(fixture);
  assert.ok(commands.some((command) => command.startsWith("push --atomic origin ")), commands.join("\n"));
});

test("pre-push accepts only the complete release tag set for the gated commit", async (t) => {
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
  const gatedEnv = {
    ...process.env,
    FLOWERSEC_RELEASE_GATE_COMMIT: verified,
    FLOWERSEC_RELEASE_VERSION: "0.26.0",
  };
  const cases = [
    {
      name: "missing release gate",
      lines: allTags,
      env: process.env,
      status: 1,
      error: /must be pushed with scripts\/release\.sh/,
    },
    {
      name: "missing one ecosystem tag",
      lines: allTags.slice(0, 2),
      env: gatedEnv,
      status: 1,
      error: /must be pushed together/,
    },
    {
      name: "tag points to another commit",
      lines: [...allTags.slice(0, 2), tagLine("refs/tags/flowersec-rust/v0.26.0", other)],
      env: gatedEnv,
      status: 1,
      error: /must point to the locally verified commit/,
    },
    {
      name: "complete verified release",
      lines: allTags,
      env: gatedEnv,
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
