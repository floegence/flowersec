import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmod, copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const repository = path.resolve(import.meta.dirname, "..");
const controllerPath = path.join(repository, "scripts", "transport-v2-runner.sh");
const agentPath = path.join(repository, "scripts", "transport-v2-runner-agent.sh");
const hostHelperPath = path.join(repository, "scripts", "transport-v2-runner-host.py");

test("three-tier runner uses fixed agents and closed stdin", async () => {
  const controller = await readFile(controllerPath, "utf8");
  const agent = await readFile(agentPath, "utf8");
  const proxy = await readFile(path.join(repository, "scripts", "transport-v2-runner-proxy.py"), "utf8");
  const hostHelper = await readFile(hostHelperPath, "utf8");
  const service = await readFile(path.join(repository, "scripts", "flowersec-formal@.service"), "utf8");
  const formalRunner = await readFile(path.join(repository, "scripts", "transport-v2-release-runner.sh"), "utf8");

  for (const action of ["doctor", "provision", "deploy", "run-formal", "collect", "cleanup"]) {
    assert.match(controller, new RegExp(`\\b${action}\\b`));
    assert.match(agent, new RegExp(`\\b${action}\\b`));
  }
  assert.doesNotMatch(controller, /ssh[^\n]*(?:bash|sh)\s+-[cs]/);
  assert.doesNotMatch(agent, /ssh[^\n]*(?:bash|sh)\s+-[cs]/);
  for (const line of agent.split("\n").filter((line) => line.includes("lxc exec"))) {
    assert.match(line, /<\s*\/dev\/null/, `lxc exec must close stdin: ${line}`);
  }
  assert.match(controller, /"\$ssh_executable"\s+-n\b/);
  assert.match(agent, /"\$ssh_executable"\s+-n\b/);
  assert.match(controller, /write_state_atomically/);
  assert.match(agent, /write_status_atomically/);
  assert.match(agent, /"\$prepared_transportcheck" runner-preflight/);
  assert.ok(agent.indexOf("transport-v2-runner-host.py") < agent.indexOf("jq -e"));
  assert.match(hostHelper, /stdin=subprocess\.DEVNULL/);
  assert.match(agent, /archive_sha256/);
  assert.match(agent, /artifact_ownership/);
  assert.doesNotMatch(proxy, /10\.191\.|goproxy\.cn|registry\.npmjs\.org|crates\.io/);
  assert.match(proxy, /--listen-host/);
  assert.match(proxy, /--allow-host/);
  assert.match(service, /\/usr\/local\/libexec\/flowersec-transport-v2-runner-agent/);
  assert.match(formalRunner, /FLOWERSEC_RELEASE_PREPARED_ROOT/);
});

test("provision waits for the dependency proxy socket after systemd reports active", async () => {
  const proxyPath = path.join(repository, "scripts", "transport-v2-runner-proxy.py");
  const probe = spawnSync("python3", ["-c", String.raw`
import hashlib
import importlib.util
import os
import sys

helper_path, proxy_path = sys.argv[1:]
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("flowersec_runner_host", helper_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

socket_probes = 0

class Result:
    def __init__(self, stdout="", returncode=0):
        self.stdout = stdout
        self.stderr = ""
        self.returncode = returncode

def fake_command(argv, timeout, check=True):
    global socket_probes
    if argv[:3] == ["systemctl", "--user", "is-active"]:
        return Result("active\n")
    if argv == ["ss", "-ltn"]:
        socket_probes += 1
        if socket_probes >= 3:
            return Result("LISTEN 0 128 10.0.0.1:3128 0.0.0.0:*\n")
    return Result()

module.command = fake_command
module.time.sleep = lambda _: None
with open(proxy_path, "rb") as source:
    proxy_sha256 = hashlib.sha256(source.read()).hexdigest()
module.start_proxy(
    {"proxy_url": "http://10.0.0.1:3128", "dependency_urls": ["https://example.invalid"]},
    {"proxy_sha256": proxy_sha256},
    os.path.dirname(proxy_path),
)
assert socket_probes == 3, socket_probes
`, hostHelperPath, proxyPath], { encoding: "utf8" });
  assert.equal(probe.status, 0, `${probe.stderr}\n${probe.stdout}`);
});

test("provision fills the locked Cargo cache through the proxy and verifies it offline", async () => {
  const agent = await readFile(agentPath, "utf8");
  const provisionStart = agent.indexOf("run_guest_provision() {");
  const provisionEnd = agent.indexOf("\nrun_guest_formal() {", provisionStart);
  const provision = agent.slice(provisionStart, provisionEnd);
  const cacheStart = agent.indexOf("locked_cargo_cache_ready() {");
  const cache = agent.slice(cacheStart, provisionStart);

  assert.notEqual(provisionStart, -1);
  assert.notEqual(provisionEnd, -1);
  assert.match(agent, /provision_locked_cargo_cache\(\)/);
  assert.match(agent, /cargo fetch --locked/);
  assert.match(agent, /HTTP_PROXY="\$proxy_url" HTTPS_PROXY="\$proxy_url"/);
  assert.match(agent, /RUSTUP_HOME=\/usr\/local\/rustup CARGO_HOME=\/usr\/local\/cargo/);
  assert.match(agent, /CARGO_NET_OFFLINE=true/);
  assert.match(agent, /rustup run 1\.88\.0 cargo metadata --locked --offline/);
  assert.match(agent, /agent_fail provision_cargo_cache/);
  assert.match(cache, /sudo -n timeout --signal=TERM --kill-after=5s 8m env/);
  assert.match(cache, /HOME=\/root/);
  assert.doesNotMatch(cache, /HOME="\$guest_home"/);
  assert.match(provision, /provision_locked_cargo_cache/);
  assert.ok(agent.indexOf("cargo fetch --locked") < agent.lastIndexOf("locked_cargo_cache_ready"));
});

test("controller does not expand parameters or commit partial GREEN state", async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "flowersec-runner-contract-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const calls = path.join(root, "calls.jsonl");
  const fakeSCP = path.join(root, "scp");
  const fakeSSH = path.join(root, "ssh");
  const state = path.join(root, "state with spaces.json");
  const config = path.join(root, "runner config.json");
  const sourceSHA = spawnSync("git", ["rev-parse", "HEAD"], { cwd: repository, encoding: "utf8" }).stdout.trim();
  const baseSHA = "b".repeat(40);

  await writeFile(fakeSCP, `#!/bin/sh\nprintf '%s\\n' 'scp' >>"${calls}"\nexit 0\n`);
  await writeFile(fakeSSH, `#!/bin/sh\nset -eu\nif IFS= read -r unexpected; then exit 91; fi\nprintf '%s\\n' "$*" >>"${calls}"\nif [ "${"$"}{FLOWERSEC_FAKE_SSH_FAIL:-0}" = 1 ]; then exit 23; fi\nprintf '%s\\n' '{"schema":"flowersec-remote-runner-result-v1","status":"GREEN","action":"doctor","source_sha":"${sourceSHA}","base_sha":"${baseSHA}","classification":"none","check_id":"","message":"literal $() value"}'\n`);
  await chmod(fakeSCP, 0o700);
  await chmod(fakeSSH, 0o700);
  const configText = `${JSON.stringify({
    schema: "flowersec-remote-runner-config-v1",
    runner_id: "runner-contract",
    ssh_target: "runner-host",
    ssh_executable: fakeSSH,
    scp_executable: fakeSCP,
    host_agent_path: "/home/runner/.flowersec-remote-agent",
    host_config_path: "/home/runner/.flowersec-remote-config.json",
    host_request_path: "/home/runner/.flowersec-remote-request.json",
    state_path: state,
    lxc_name: "flowersec-release-ubuntu24",
    lxc_root: "/workspace/flowersec-remote",
    guest_target: "runner@127.0.0.1",
    guest_port: 2222,
    guest_identity_file: "/workspace/runner/id_ed25519",
    guest_known_hosts_file: "/workspace/runner/known_hosts",
    guest_root: "/home/runner/.flowersec-remote",
    guest_repo: "/workspace/flowersec",
    artifact_root: "/evidence",
    proxy_url: "http://10.0.0.1:3128",
    dependency_urls: ["https://example.invalid/$()"],
  }, null, 2)}\n`;
  await writeFile(config, configText);
  await chmod(config, 0o600);
  await writeFile(state, `${JSON.stringify({
    schema: "flowersec-remote-runner-state-v1",
    config_sha256: createHash("sha256").update(configText).digest("hex"),
    actions: {
      provision: { status: "GREEN", source_sha: sourceSHA },
      deploy: { status: "GREEN", source_sha: sourceSHA },
    },
  })}\n`);
  await chmod(state, 0o600);

  const success = spawnSync(controllerPath, ["doctor", "--config", config, "--sha", sourceSHA, "--base-sha", baseSHA], {
    cwd: repository,
    encoding: "utf8",
  });
  assert.equal(success.status, 0, success.stderr);
  const written = JSON.parse(await readFile(state, "utf8"));
  assert.deepEqual(Object.keys(written).sort(), ["actions", "config_sha256", "schema", "updated_at"]);
  assert.equal(written.actions.doctor.status, "GREEN");
  assert.equal(written.actions.doctor.message, "literal $() value");
  const callsAfterSuccess = await readFile(calls, "utf8");

  const resumed = spawnSync(controllerPath, ["doctor", "--config", config, "--sha", sourceSHA, "--base-sha", baseSHA], {
    cwd: repository,
    encoding: "utf8",
    env: { ...process.env, FLOWERSEC_FAKE_SSH_FAIL: "1" },
  });
  assert.equal(resumed.status, 0, resumed.stderr);
  assert.deepEqual(JSON.parse(resumed.stdout), written.actions.doctor);
  assert.equal(await readFile(calls, "utf8"), callsAfterSuccess);

  const baseDrift = spawnSync(controllerPath, ["doctor", "--config", config, "--sha", sourceSHA, "--base-sha", "c".repeat(40)], {
    cwd: repository,
    encoding: "utf8",
    env: { ...process.env, FLOWERSEC_FAKE_SSH_FAIL: "1" },
  });
  assert.equal(baseDrift.status, 20);
  assert.notEqual(await readFile(calls, "utf8"), callsAfterSuccess);

  const failed = spawnSync(controllerPath, ["cleanup", "--config", config, "--sha", sourceSHA], {
    cwd: repository,
    encoding: "utf8",
    env: { ...process.env, FLOWERSEC_FAKE_SSH_FAIL: "1" },
  });
  assert.equal(failed.status, 20);
  const failedState = JSON.parse(await readFile(state, "utf8"));
  assert.deepEqual(failedState.actions, written.actions);
  assert.equal(failedState.last_failure.check_id, "runner_reachability");
  assert.equal(failedState.last_failure.classification, "unreachable");
});

test("a later failed action invalidates an earlier cleanup receipt", async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "flowersec-cleanup-resume-contract-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const calls = path.join(root, "calls.log");
  const fakeSCP = path.join(root, "scp");
  const fakeSSH = path.join(root, "ssh");
  const state = path.join(root, "state.json");
  const config = path.join(root, "config.json");
  const sourceSHA = spawnSync("git", ["rev-parse", "HEAD"], { cwd: repository, encoding: "utf8" }).stdout.trim();

  await writeFile(fakeSCP, "#!/bin/sh\nexit 0\n");
  await writeFile(fakeSSH, `#!/bin/sh
set -eu
if IFS= read -r unexpected; then exit 91; fi
printf '%s\n' "$*" >>"${calls}"
if [ "${"$"}{FLOWERSEC_FAKE_SSH_FAIL:-0}" = 1 ]; then exit 23; fi
printf '%s\n' '{"schema":"flowersec-remote-runner-result-v1","status":"GREEN","action":"cleanup","source_sha":"${sourceSHA}","base_sha":"","classification":"none","check_id":"","message":"remote cleanup executed"}'
`);
  await chmod(fakeSCP, 0o700);
  await chmod(fakeSSH, 0o700);
  const configText = `${JSON.stringify({
    schema: "flowersec-remote-runner-config-v1",
    runner_id: "cleanup-resume-contract",
    ssh_target: "runner-host",
    ssh_executable: fakeSSH,
    scp_executable: fakeSCP,
    host_agent_path: "/home/runner/.flowersec-remote/agent",
    host_config_path: "/home/runner/.flowersec-remote/config.json",
    host_request_path: "/home/runner/.flowersec-remote/request.json",
    state_path: state,
    lxc_name: "flowersec-release-ubuntu24",
    lxc_root: "/workspace/flowersec-remote",
    guest_target: "runner@127.0.0.1",
    guest_port: 2222,
    guest_identity_file: "/workspace/runner/id_ed25519",
    guest_known_hosts_file: "/workspace/runner/known_hosts",
    guest_root: "/home/runner/.flowersec-remote",
    guest_repo: "/workspace/flowersec",
    artifact_root: "/evidence",
    proxy_url: "http://10.0.0.1:3128",
    dependency_urls: ["https://example.invalid"],
  }, null, 2)}\n`;
  await writeFile(config, configText);
  await chmod(config, 0o600);

  const firstCleanup = spawnSync(controllerPath, ["cleanup", "--config", config, "--sha", sourceSHA], {
    cwd: repository,
    encoding: "utf8",
  });
  assert.equal(firstCleanup.status, 0, firstCleanup.stderr);

  const failedProvision = spawnSync(controllerPath, ["provision", "--config", config, "--sha", sourceSHA], {
    cwd: repository,
    encoding: "utf8",
    env: { ...process.env, FLOWERSEC_FAKE_SSH_FAIL: "1" },
  });
  assert.equal(failedProvision.status, 20);
  const callsAfterFailure = await readFile(calls, "utf8");

  const secondCleanup = spawnSync(controllerPath, ["cleanup", "--config", config, "--sha", sourceSHA], {
    cwd: repository,
    encoding: "utf8",
  });
  assert.equal(secondCleanup.status, 0, secondCleanup.stderr);
  assert.notEqual(await readFile(calls, "utf8"), callsAfterFailure);
  assert.equal(JSON.parse(secondCleanup.stdout).message, "remote cleanup executed");
});

test("host agent needs no jq and closes every LXC stdin before state transitions", async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "flowersec-lxc-stdin-contract-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const fakeLXC = path.join(root, "lxc");
  const fakeSystemctl = path.join(root, "systemctl");
  const fakeSS = path.join(root, "ss");
  const fakeTimeout = path.join(root, "timeout");
  const calls = path.join(root, "calls.log");
  const agent = path.join(root, "transport-v2-runner-agent.sh");
  const config = path.join(root, "config.json");
  const request = path.join(root, "request.json");
  const sourceSHA = "a".repeat(40);
  await copyFile(agentPath, agent);
  await chmod(agent, 0o700);
  const hostHelper = path.join(root, "transport-v2-runner-host.py");
  await copyFile(hostHelperPath, hostHelper);
  await chmod(hostHelper, 0o700);
  await writeFile(fakeLXC, `#!/bin/sh\nset -eu\nif IFS= read -r unexpected; then exit 91; fi\nprintf 'stdin=eof %s\\n' "$*" >>"${calls}"\ncase "$*" in\n  *'-- sha256sum '*'transport-v2-runner-agent.sh'*) sha256sum "${agent}" ;;\n  *'-- sha256sum '*'runner-config.json'*) sha256sum "${config}" ;;\n  *'--role lxd doctor'*) printf '%s\\n' '{"schema":"flowersec-remote-runner-result-v1","status":"GREEN","action":"doctor","source_sha":"${sourceSHA}","base_sha":"","classification":"none","message":"lxc stdin closed","check_id":""}' ;;\n  *'--role lxd cleanup'*) printf '%s\\n' '{"schema":"flowersec-remote-runner-result-v1","status":"RED","action":"cleanup","source_sha":"${sourceSHA}","base_sha":"","classification":"residual","message":"bounded cleanup failed","check_id":"residual_process"}'; exit 20 ;;\nesac\n`);
  await chmod(fakeLXC, 0o700);
  await writeFile(fakeSystemctl, "#!/bin/sh\ncase \"$*\" in *'is-active'*) echo active;; esac\n");
  await writeFile(fakeSS, "#!/bin/sh\nprintf '%s\\n' 'LISTEN 0 128 10.0.0.1:3128 0.0.0.0:*'\n");
  await writeFile(fakeTimeout, "#!/bin/sh\nset -eu\nwhile [ \"${1#--}\" != \"$1\" ]; do shift; done\nshift\nexec \"$@\"\n");
  await chmod(fakeSystemctl, 0o700);
  await chmod(fakeSS, 0o700);
  await chmod(fakeTimeout, 0o700);
  const configText = `${JSON.stringify({
    schema: "flowersec-remote-runner-config-v1",
    runner_id: "runner-contract",
    ssh_target: "runner-host",
    ssh_executable: "/usr/bin/ssh",
    scp_executable: "/usr/bin/scp",
    host_agent_path: agent,
    host_config_path: config,
    host_request_path: request,
    state_path: path.join(root, "state.json"),
    lxc_name: "flowersec-release-ubuntu24",
    lxc_root: "/workspace/flowersec-remote",
    guest_target: "runner@127.0.0.1",
    guest_port: 2222,
    guest_identity_file: "/workspace/runner/id_ed25519",
    guest_known_hosts_file: "/workspace/runner/known_hosts",
    guest_root: "/home/runner/.flowersec-remote",
    guest_repo: "/workspace/flowersec",
    artifact_root: "/evidence",
    proxy_url: "http://10.0.0.1:3128",
    dependency_urls: ["https://goproxy.cn"],
  }, null, 2)}\n`;
  const configSHA = createHash("sha256").update(configText).digest("hex");
  const agentSHA = createHash("sha256").update(await readFile(agent, "utf8")).digest("hex");
  const hostHelperSHA = createHash("sha256").update(await readFile(hostHelper, "utf8")).digest("hex");
  await writeFile(config, configText);
  await chmod(config, 0o600);
  await writeFile(request, `${JSON.stringify({
    schema: "flowersec-remote-runner-request-v1",
    action: "doctor",
    source_sha: sourceSHA,
    base_sha: "",
    output_path: "",
    config_sha256: configSHA,
    bundle_sha256: "",
    archive_sha256: "",
    agent_sha256: agentSHA,
    host_helper_sha256: hostHelperSHA,
    proxy_sha256: "c".repeat(64),
    template_sha256: "d".repeat(64),
    host_bundle_path: path.join(root, "unused.bundle"),
  })}\n`);
  await chmod(request, 0o600);

  const run = spawnSync(agent, ["--role", "host", "doctor", config, request, "flowersec-remote-runner-v1"], {
    encoding: "utf8",
    env: { ...process.env, PATH: `${root}:${process.env.PATH}` },
  });
  assert.equal(run.status, 0, `${run.stderr}\n${run.stdout}`);
  const lines = (await readFile(calls, "utf8")).trim().split("\n");
  assert.ok(lines.some((line) => line.includes("exec flowersec-release-ubuntu24")));
  assert.ok(lines.every((line) => line.startsWith("stdin=eof ")));
  assert.equal(JSON.parse(run.stdout).message, "lxc stdin closed");

  await writeFile(request, `${JSON.stringify({
    schema: "flowersec-remote-runner-request-v1",
    action: "cleanup",
    source_sha: sourceSHA,
    base_sha: "",
    output_path: "",
    config_sha256: configSHA,
    bundle_sha256: "",
    archive_sha256: "",
    agent_sha256: agentSHA,
    host_helper_sha256: hostHelperSHA,
    proxy_sha256: "c".repeat(64),
    template_sha256: "d".repeat(64),
    host_bundle_path: path.join(root, "unused.bundle"),
  })}\n`);
  await chmod(request, 0o600);
  const failed = spawnSync(agent, ["--role", "host", "cleanup", config, request, "flowersec-remote-runner-v1"], {
    encoding: "utf8",
    env: { ...process.env, PATH: `${root}:${process.env.PATH}` },
  });
  assert.equal(failed.status, 20, failed.stderr);
  assert.equal(JSON.parse(failed.stdout).check_id, "residual_process");
  assert.equal(JSON.parse(await readFile(`${request}.status`, "utf8")).status, "RED");
});

test("guest cleanup fails closed on archive drift and removes only verified exact-SHA artifacts", async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "flowersec-cleanup-contract-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const bin = path.join(root, "bin");
  const guestRoot = path.join(root, "guest");
  const guestRepo = path.join(root, "repository");
  const artifactRoot = path.join(root, "evidence");
  await Promise.all([mkdir(bin), mkdir(guestRoot), mkdir(guestRepo), mkdir(artifactRoot)]);
  const fakeSudo = path.join(bin, "sudo");
  const agent = path.join(guestRoot, "transport-v2-runner-agent.sh");
  const config = path.join(guestRoot, "runner-config.json");
  const request = path.join(guestRoot, "request.json");
  const sourceSHA = "a".repeat(40);
  const runnerID = "cleanup-contract";
  const artifact = path.join(artifactRoot, `formal-${sourceSHA}-${runnerID}`);
  const archive = path.join(artifactRoot, `${sourceSHA}-${runnerID}-formal-closure.tar.gz`);
  await mkdir(artifact);
  await writeFile(path.join(artifact, "report.unsigned.json"), "evidence\n");
  await writeFile(archive, "checksummed closure\n");
  await copyFile(agentPath, agent);
  await chmod(agent, 0o700);
  await writeFile(fakeSudo, "#!/bin/sh\nset -eu\n[ \"${1:-}\" != -n ] || shift\ncase \"$*\" in *'/run/flowersec/transport-v2-runner-request.json'*) exit 0;; esac\nexec \"$@\"\n");
  for (const [name, body] of [
    ["systemctl", "#!/bin/sh\nexit 0\n"],
    ["pgrep", "#!/bin/sh\nexit 1\n"],
    ["ip", "#!/bin/sh\nexit 0\n"],
    ["find", "#!/bin/sh\nexit 0\n"],
  ]) {
    await writeFile(path.join(bin, name), body);
    await chmod(path.join(bin, name), 0o700);
  }
  await chmod(fakeSudo, 0o700);
  const configText = `${JSON.stringify({
    schema: "flowersec-remote-runner-config-v1",
    runner_id: runnerID,
    ssh_target: "runner-host",
    ssh_executable: "/usr/bin/ssh",
    scp_executable: "/usr/bin/scp",
    host_agent_path: path.join(root, "host-agent"),
    host_config_path: path.join(root, "host-config.json"),
    host_request_path: path.join(root, "host-request.json"),
    state_path: path.join(root, "state.json"),
    lxc_name: "flowersec-release-ubuntu24",
    lxc_root: path.join(root, "lxd"),
    guest_target: "runner@127.0.0.1",
    guest_port: 2222,
    guest_identity_file: path.join(root, "id_ed25519"),
    guest_known_hosts_file: path.join(root, "known_hosts"),
    guest_root: guestRoot,
    guest_repo: guestRepo,
    artifact_root: artifactRoot,
    proxy_url: "http://10.0.0.1:3128",
    dependency_urls: ["https://goproxy.cn"],
  }, null, 2)}\n`;
  await writeFile(config, configText);
  await chmod(config, 0o600);
  const configSHA = createHash("sha256").update(configText).digest("hex");
  const agentSHA = createHash("sha256").update(await readFile(agent, "utf8")).digest("hex");
  const hostHelperSHA = createHash("sha256").update(await readFile(hostHelperPath, "utf8")).digest("hex");
  const archiveSHA = createHash("sha256").update(await readFile(archive)).digest("hex");
  const requestFor = (digest) => `${JSON.stringify({
    schema: "flowersec-remote-runner-request-v1",
    action: "cleanup",
    source_sha: sourceSHA,
    base_sha: "",
    output_path: "",
    config_sha256: configSHA,
    bundle_sha256: "",
    archive_sha256: digest,
    agent_sha256: agentSHA,
    host_helper_sha256: hostHelperSHA,
    proxy_sha256: "c".repeat(64),
    template_sha256: "d".repeat(64),
    host_bundle_path: path.join(root, "unused.bundle"),
  })}\n`;
  await writeFile(request, requestFor("e".repeat(64)));
  await chmod(request, 0o600);
  const drifted = spawnSync(agent, ["--role", "guest", "cleanup", config, request, "flowersec-remote-runner-v1"], {
    encoding: "utf8",
    env: { ...process.env, PATH: `${bin}:${process.env.PATH}` },
  });
  assert.equal(drifted.status, 40, drifted.stderr);
  assert.equal(JSON.parse(drifted.stdout).check_id, "artifact_digest");
  assert.equal(await readFile(archive, "utf8"), "checksummed closure\n");
  assert.equal(await readFile(path.join(artifact, "report.unsigned.json"), "utf8"), "evidence\n");

  await writeFile(request, requestFor(archiveSHA));
  await chmod(request, 0o600);
  const cleaned = spawnSync(agent, ["--role", "guest", "cleanup", config, request, "flowersec-remote-runner-v1"], {
    encoding: "utf8",
    env: { ...process.env, PATH: `${bin}:${process.env.PATH}` },
  });
  assert.equal(cleaned.status, 0, cleaned.stderr);
  assert.equal(JSON.parse(cleaned.stdout).status, "GREEN");
  await assert.rejects(readFile(archive));
  await assert.rejects(readFile(path.join(artifact, "report.unsigned.json")));
});
