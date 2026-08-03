import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmod, copyFile, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const repository = path.resolve(import.meta.dirname, "..");
const controllerPath = path.join(repository, "scripts", "transport-v2-runner.sh");
const agentPath = path.join(repository, "scripts", "transport-v2-runner-agent.sh");
const hostHelperPath = path.join(repository, "scripts", "transport-v2-runner-host.py");
const kvmHelperPath = path.join(repository, "scripts", "transport-v2-runner-kvm.py");

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
  const cleanupStart = hostHelper.indexOf("def cleanup_host(");
  const cleanupEnd = hostHelper.indexOf("\n\ndef main()", cleanupStart);
  assert.doesNotMatch(hostHelper.slice(cleanupStart, cleanupEnd), /flowersec-transport-v2-proxy\.service/);
});

test("KVM provisioning is checked-in, structured, and bound to the eight-CPU guest context", async () => {
  const controller = await readFile(controllerPath, "utf8");
  const agent = await readFile(agentPath, "utf8");
  const helper = await readFile(kvmHelperPath, "utf8");
  const service = await readFile(path.join(repository, "scripts", "flowersec-kvm-guest@.service"), "utf8");

  for (const field of [
    "guest_architecture",
    "guest_effective_cpus",
    "guest_launcher_argv",
    "guest_launcher_executable",
    "guest_legacy_pid_file",
    "guest_vm_name",
  ]) {
    assert.match(controller, new RegExp(`\\b${field}\\b`));
  }
  assert.match(controller, /kvm_helper_sha256/);
  assert.match(controller, /kvm_template_sha256/);
  assert.match(agent, /transport-v2-runner-kvm\.py/);
  assert.match(agent, /flowersec-kvm-guest@\.service/);
  assert.match(agent, /"\$lxd_kvm_helper" (?:provision|doctor) "\$lxd_config"/);
  assert.match(helper, /subprocess\.run\(/);
  assert.match(helper, /shell=False/);
  assert.match(helper, /stdin=subprocess\.DEVNULL/);
  assert.match(helper, /config\["guest_effective_cpus"\] != 8/);
  assert.match(service, /ExecStart=\/usr\/local\/libexec\/flowersec-transport-v2-runner-kvm run/);
});

test("KVM provisioning preserves argv, resumes idempotently, and rejects foreign legacy ownership", async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "flowersec-kvm-provision-contract-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const probe = spawnSync("python3", ["-c", String.raw`
import importlib.util
import json
import os
import pathlib
import sys

helper_path, root = sys.argv[1:]
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("flowersec_runner_kvm", helper_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.STABLE_HELPER = os.path.join(root, "stable", "runner-kvm")
module.STABLE_CONFIG_ROOT = os.path.join(root, "config")
module.STABLE_TEMPLATE = os.path.join(root, "systemd", "flowersec-kvm-guest@.service")
qemu = os.path.join(root, "qemu-system-aarch64")
pathlib.Path(qemu).write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
os.chmod(qemu, 0o755)
template = os.path.join(root, "template.service")
pathlib.Path(template).write_text("unit\n", encoding="utf-8")
special = "literal $() 'quoted value'"
argv = ["-name", "runner-contract", "-smp", "8", "-netdev", "user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22", "-D", special]
config = {
    "schema": "flowersec-remote-runner-config-v1",
    "runner_id": "runner-contract",
    "guest_architecture": "arm64",
    "guest_effective_cpus": 8,
    "guest_launcher_executable": qemu,
    "guest_launcher_argv": argv,
    "guest_legacy_pid_file": os.path.join(root, "legacy.pid"),
    "guest_vm_name": "runner-contract",
    "guest_port": 2222,
}
calls = []
active = False
class Result:
    def __init__(self, stdout="", returncode=0):
        self.stdout = stdout
        self.stderr = ""
        self.returncode = returncode
def command(arguments, timeout=30, check=True):
    global active
    calls.append(arguments)
    if arguments[1] == "enable":
        active = True
    if arguments[1] == "is-active":
        return Result("active\n" if active else "inactive\n", 0 if active else 3)
    if arguments[1] == "show":
        return Result("42\n")
    return Result()
module.command = command
module.process_argv = lambda pid: [qemu, *argv]
module.process_executable = lambda pid: os.path.realpath(qemu)
module.provision(config, template)
first = list(calls)
calls.clear()
module.provision(config, template)
second = list(calls)
assert any(call[1:3] == ["enable", "--now"] for call in first), first
assert not any(call[1] in {"enable", "start", "stop", "daemon-reload"} for call in second), second
assert module.process_argv(42)[-1] == special

executables = iter(["/usr/bin/python3", os.path.realpath(qemu)])
module.process_executable = lambda pid: next(executables, os.path.realpath(qemu))
module.verify_service(config)

module.PROCESS_READY_ATTEMPTS = 2
module.PROCESS_READY_DELAY = 0
module.process_executable = lambda pid: "/usr/bin/python3"
try:
    module.verify_service(config)
except module.KVMFailure as error:
    assert error.check_id == "kvm_process_identity"
else:
    raise AssertionError("persistent KVM executable drift was accepted")

seven_cpu = dict(config)
seven_cpu["guest_effective_cpus"] = 7
seven_cpu["guest_launcher_argv"] = ["-name", "runner-contract", "-smp", "7", "-netdev", "user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22"]
try:
    module.validate_config(seven_cpu)
except module.KVMFailure as error:
    assert error.check_id == "kvm_cpu"
else:
    raise AssertionError("seven-CPU formal guest was accepted")

legacy = pathlib.Path(config["guest_legacy_pid_file"])
legacy.write_text("99\n", encoding="ascii")
os.chmod(legacy, 0o600)
module.process_argv = lambda pid: [qemu, "-name", "another-task"]
module.process_executable = lambda pid: os.path.realpath(qemu)
try:
    module.stop_owned_legacy(config)
except module.KVMFailure as error:
    assert error.check_id == "kvm_legacy_ownership"
else:
    raise AssertionError("foreign legacy process was accepted")
assert legacy.read_text(encoding="ascii") == "99\n"
print(json.dumps({"first": first, "second": second, "special": special}))
`, kvmHelperPath, root], { encoding: "utf8" });
  assert.equal(probe.status, 0, `${probe.stderr}\n${probe.stdout}`);
  assert.equal(JSON.parse(probe.stdout).special, "literal $() 'quoted value'");
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
  assert.match(cache, /\/usr\/local\/cargo\/bin\/rustup run 1\.88\.0/);
  assert.doesNotMatch(cache, /HOME="\$guest_home"/);
  assert.match(provision, /provision_locked_cargo_cache/);
  assert.ok(agent.indexOf("cargo fetch --locked") < agent.lastIndexOf("locked_cargo_cache_ready"));
});

test("provision repairs generated build ownership and deploy reserves stdout for strict JSON", async () => {
  const agent = await readFile(agentPath, "utf8");
  const provisionStart = agent.indexOf("run_guest_provision() {");
  const provisionEnd = agent.indexOf("\nrun_guest_formal() {", provisionStart);
  const provision = agent.slice(provisionStart, provisionEnd);
  const deployStart = agent.indexOf("run_guest_deploy() {");
  const deployEnd = agent.indexOf("\ndoctor_fail() {", deployStart);
  const deploy = agent.slice(deployStart, deployEnd);

  assert.match(provision, /chown -R --reference="\$guest_repo"/);
  assert.match(provision, /agent_fail provision_build_permissions/);
  assert.match(deploy, /agent_fail deploy_ts_build/);
  assert.match(deploy, /agent_fail deploy_go_runner_build/);
  assert.match(deploy, /agent_fail deploy_transportcheck_build/);
  assert.match(deploy, /agent_fail deploy_rust_runner_build/);
  assert.match(deploy, /agent_fail deploy_identity_generation/);
  assert.match(deploy, /npm run build >&2/);
  assert.match(deploy, /cargo build --locked --release --example transport_release_runner/);
  assert.match(deploy, /rust_runner_sha256/);
  assert.match(deploy, /transport-release-runner-rust/);
  assert.match(deploy, /make -C "\$guest_repo" transport-runner-config >&2/);
});

test("deploy preserves bounded Rust diagnostics and classifies source build failures as product failures", async () => {
  const agent = await readFile(agentPath, "utf8");
  const deployStart = agent.indexOf("run_guest_deploy() {");
  const deployEnd = agent.indexOf("\ndoctor_fail() {", deployStart);
  const deploy = agent.slice(deployStart, deployEnd);

  assert.match(deploy, /rust-build\.stderr/);
  assert.match(deploy, /tail -c 16384/);
  assert.match(deploy, /deploy_rust_runner_build[\s\S]+product 50/);
});

test("host failures forward only bounded nested stderr and cleanup retains the first failure", async () => {
  const controller = await readFile(controllerPath, "utf8");
  const hostHelper = await readFile(hostHelperPath, "utf8");

  assert.match(hostHelper, /MAX_NESTED_STDERR_BYTES = 16384/);
  assert.match(hostHelper, /emit_nested_stderr\(nested\.stderr\)/);
  assert.match(hostHelper, /encoded\[-MAX_NESTED_STDERR_BYTES:\]/);
  assert.match(controller, /if \$existing \| has\("last_failure"\) then \.last_failure=\$existing\.last_failure else \. end/);
});

test("doctor mirrors the formal build and browser identity context", async () => {
  const agent = await readFile(agentPath, "utf8");
  const preflight = await readFile(path.join(repository, "tools", "transportcheck", "runner_preflight.go"), "utf8");
  const deployStart = agent.indexOf("run_guest_deploy() {");
  const deployEnd = agent.indexOf("\ndoctor_fail() {", deployStart);
  const deploy = agent.slice(deployStart, deployEnd);
  const doctorStart = agent.indexOf("run_guest_doctor() {");
  const doctorEnd = agent.indexOf("\nlocked_cargo_cache_ready() {", doctorStart);
  const doctor = agent.slice(doctorStart, doctorEnd);
  const formalStart = agent.indexOf("run_guest_formal_root() {");
  const formalEnd = agent.indexOf("\nrun_guest_collect() {", formalStart);
  const formal = agent.slice(formalStart, formalEnd);

  assert.match(deploy, /"\$\(node --version\)"/);
  for (const assignment of [
    "--setenv=GOOS=linux",
    '--setenv=GOARCH="$actual_go_architecture"',
    "--setenv=CGO_ENABLED=0",
    "--setenv=CARGO_NET_OFFLINE=true",
    "--setenv=GOWORK=off",
    "--setenv=GOFLAGS=-mod=readonly",
    "--setenv=GOPROXY=off",
    '--setenv=GOMODCACHE="$guest_home/go/pkg/mod"',
    '--setenv=PLAYWRIGHT_BROWSERS_PATH="$guest_home/.cache/ms-playwright"',
  ]) {
    assert.ok(doctor.includes(assignment), `doctor is missing ${assignment}`);
  }
  assert.match(agent, /guest_go_architecture\(\)[\s\S]*x86_64\) printf '%s\\n' amd64[\s\S]*aarch64\) printf '%s\\n' arm64/);
  assert.match(deploy, /export GOOS=linux GOARCH="\$actual_go_architecture" CGO_ENABLED=0/);
  assert.match(formal, /export GOOS=linux GOARCH="\$actual_go_architecture" CGO_ENABLED=0/);
  assert.match(agent, /git config --global --add safe\.directory "\$guest_repo\/\.git"/);
  assert.match(preflight, /BaseCheckoutReady/);
  assert.match(preflight, /runnerPreflightBaseCheckout/);
  assert.match(preflight, /add\("base_checkout"/);
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
    lxc_executable: "/usr/bin/lxc",
    guest_architecture: "arm64",
    guest_effective_cpus: 8,
    guest_launcher_executable: "/usr/bin/qemu-system-aarch64",
    guest_launcher_argv: ["-name", "runner-contract", "-smp", "8", "-netdev", "user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22"],
    guest_legacy_pid_file: "/run/runner-contract.pid",
    guest_vm_name: "runner-contract",
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

  await writeFile(fakeSSH, `#!/bin/sh\nset -eu\nif IFS= read -r unexpected; then exit 91; fi\nprintf '%s\\n' '{"schema":"flowersec-remote-runner-result-v1","status":"GREEN","action":"cleanup","source_sha":"${sourceSHA}","base_sha":"","classification":"none","check_id":"","message":"remote cleanup executed"}'\n`);
  const cleanup = spawnSync(controllerPath, ["cleanup", "--config", config, "--sha", sourceSHA], {
    cwd: repository,
    encoding: "utf8",
  });
  assert.equal(cleanup.status, 0, cleanup.stderr);
  const cleanedState = JSON.parse(await readFile(state, "utf8"));
  assert.equal(cleanedState.actions.cleanup.status, "GREEN");
  assert.deepEqual(cleanedState.last_failure, failedState.last_failure);
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
    lxc_executable: "/usr/bin/lxc",
    guest_architecture: "arm64",
    guest_effective_cpus: 8,
    guest_launcher_executable: "/usr/bin/qemu-system-aarch64",
    guest_launcher_argv: ["-name", "cleanup-resume-contract", "-smp", "8", "-netdev", "user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22"],
    guest_legacy_pid_file: "/run/cleanup-resume-contract.pid",
    guest_vm_name: "cleanup-resume-contract",
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

test("legacy config can recover an exact-state collection but cannot start another action", async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "flowersec-legacy-recovery-contract-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const fakeSCP = path.join(root, "scp");
  const fakeSSH = path.join(root, "ssh");
  const state = path.join(root, "state.json");
  const config = path.join(root, "config.json");
  const output = path.join(root, "closure.tar.gz");
  const sourceSHA = "a".repeat(40);
  const baseSHA = "b".repeat(40);
  await writeFile(fakeSCP, "#!/bin/sh\nexit 0\n");
  await writeFile(fakeSSH, `#!/bin/sh
set -eu
if IFS= read -r unexpected; then exit 91; fi
printf '%s\n' '{"schema":"flowersec-remote-runner-result-v1","status":"RUNNING","action":"collect","source_sha":"${sourceSHA}","base_sha":"${baseSHA}","classification":"none","check_id":"","message":"legacy exact-state recovery"}'
`);
  await chmod(fakeSCP, 0o700);
  await chmod(fakeSSH, 0o700);
  const configText = `${JSON.stringify({
    schema: "flowersec-remote-runner-config-v1",
    runner_id: "legacy-recovery-contract",
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
  await writeFile(state, `${JSON.stringify({
    schema: "flowersec-remote-runner-state-v1",
    config_sha256: createHash("sha256").update(configText).digest("hex"),
    actions: {
      "run-formal": { status: "RUNNING", source_sha: sourceSHA, base_sha: baseSHA },
    },
  })}\n`);
  await chmod(state, 0o600);

  const collect = spawnSync(controllerPath, ["collect", "--config", config, "--sha", sourceSHA, "--base-sha", baseSHA, "--output", output], {
    cwd: repository,
    encoding: "utf8",
  });
  assert.equal(collect.status, 0, collect.stderr);
  assert.equal(JSON.parse(collect.stdout).message, "legacy exact-state recovery");

  const doctor = spawnSync(controllerPath, ["doctor", "--config", config, "--sha", sourceSHA, "--base-sha", baseSHA], {
    cwd: repository,
    encoding: "utf8",
  });
  assert.equal(doctor.status, 2);
  assert.match(doctor.stderr, /runner config is invalid/);
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
  const kvmHelper = path.join(root, "transport-v2-runner-kvm.py");
  await copyFile(hostHelperPath, hostHelper);
  await copyFile(kvmHelperPath, kvmHelper);
  await chmod(hostHelper, 0o700);
  await chmod(kvmHelper, 0o700);
  await writeFile(fakeLXC, `#!/bin/sh\nset -eu\nif IFS= read -r unexpected; then exit 91; fi\nprintf 'stdin=eof %s\\n' "$*" >>"${calls}"\ncase "$*" in\n  *'-- sha256sum '*'transport-v2-runner-agent.sh'*) sha256sum "${agent}" ;;\n  *'-- sha256sum '*'runner-config.json'*) sha256sum "${config}" ;;\n  *'-- sha256sum '*'transport-v2-runner-kvm.py'*) sha256sum "${kvmHelper}" ;;\n  *'--role lxd doctor'*) printf '%s\\n' '{"schema":"flowersec-remote-runner-result-v1","status":"GREEN","action":"doctor","source_sha":"${sourceSHA}","base_sha":"","classification":"none","message":"lxc stdin closed","check_id":""}' ;;\n  *'--role lxd cleanup'*) printf '%s\\n' '{"schema":"flowersec-remote-runner-result-v1","status":"RED","action":"cleanup","source_sha":"${sourceSHA}","base_sha":"","classification":"residual","message":"bounded cleanup failed","check_id":"residual_process"}'; exit 20 ;;\nesac\n`);
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
    lxc_executable: fakeLXC,
    guest_architecture: "arm64",
    guest_effective_cpus: 8,
    guest_launcher_executable: "/usr/bin/qemu-system-aarch64",
    guest_launcher_argv: ["-name", "runner-contract", "-smp", "8", "-netdev", "user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22"],
    guest_legacy_pid_file: "/run/runner-contract.pid",
    guest_vm_name: "runner-contract",
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
  const kvmHelperSHA = createHash("sha256").update(await readFile(kvmHelper, "utf8")).digest("hex");
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
    kvm_helper_sha256: kvmHelperSHA,
    kvm_template_sha256: "e".repeat(64),
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
    kvm_helper_sha256: kvmHelperSHA,
    kvm_template_sha256: "e".repeat(64),
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

test("host helper uses the private absolute LXC executable without ambient PATH", async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "flowersec-lxc-path-contract-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const fakeLXC = path.join(root, "lxc-private");
  const linkedLXC = path.join(root, "lxc-linked");
  await writeFile(fakeLXC, "#!/bin/sh\nset -eu\nif IFS= read -r unexpected; then exit 91; fi\nprintf '%s\\n' \"$*\"\n");
  await chmod(fakeLXC, 0o700);
  await symlink(fakeLXC, linkedLXC);
  const probe = spawnSync("python3", ["-c", String.raw`
import importlib.util
import sys

helper_path, lxc_path = sys.argv[1:]
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("flowersec_runner_host", helper_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
completed = module.lxc({"lxc_executable": lxc_path}, "info", "runner")
print(completed.stdout, end="")
`, hostHelperPath, fakeLXC], {
    encoding: "utf8",
    env: { ...process.env, PATH: "/usr/bin:/bin" },
  });
  assert.equal(probe.status, 0, `${probe.stderr}\n${probe.stdout}`);
  assert.equal(probe.stdout, "info runner\n");

  const linked = spawnSync("python3", ["-c", String.raw`
import importlib.util
import sys

helper_path, lxc_path = sys.argv[1:]
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("flowersec_runner_host", helper_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
completed = module.lxc({"lxc_executable": lxc_path}, "info", "linked-runner")
print(completed.stdout, end="")
`, hostHelperPath, linkedLXC], {
    encoding: "utf8",
    env: { ...process.env, PATH: "/usr/bin:/bin" },
  });
  assert.equal(linked.status, 0, `${linked.stderr}\n${linked.stdout}`);
  assert.equal(linked.stdout, "info linked-runner\n");

  const legacy = spawnSync("python3", ["-c", String.raw`
import importlib.util
import sys

helper_path, lxc_path = sys.argv[1:]
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("flowersec_runner_host", helper_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.LEGACY_LXC_EXECUTABLE = lxc_path
completed = module.lxc({}, "info", "legacy-runner")
print(completed.stdout, end="")
`, hostHelperPath, fakeLXC], {
    encoding: "utf8",
    env: { ...process.env, PATH: "/usr/bin:/bin" },
  });
  assert.equal(legacy.status, 0, `${legacy.stderr}\n${legacy.stdout}`);
  assert.equal(legacy.stdout, "info legacy-runner\n");

  const missing = spawnSync("python3", ["-c", String.raw`
import importlib.util
import sys

helper_path, lxc_path = sys.argv[1:]
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("flowersec_runner_host", helper_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
try:
    module.lxc({"lxc_executable": lxc_path}, "info", "runner")
except module.RunnerFailure as error:
    print(error.check_id)
    raise SystemExit(23)
`, hostHelperPath, path.join(root, "missing-lxc")], {
    encoding: "utf8",
    env: { ...process.env, PATH: "/usr/bin:/bin" },
  });
  assert.equal(missing.status, 23, missing.stderr);
  assert.equal(missing.stdout, "host_lxc\n");
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
  const preflightRoot = path.join(guestRoot, "preflight");
  const preflightReport = path.join(preflightRoot, `${sourceSHA}-formal.json`);
  await mkdir(artifact);
  await mkdir(preflightRoot);
  await writeFile(path.join(artifact, "report.unsigned.json"), "evidence\n");
  await writeFile(archive, "checksummed closure\n");
  await writeFile(preflightReport, "preflight\n");
  await copyFile(agentPath, agent);
  await chmod(agent, 0o700);
  await writeFile(fakeSudo, "#!/bin/sh\nset -eu\n[ \"${1:-}\" != -n ] || shift\ncase \"$*\" in *'/run/flowersec/transport-v2-runner-request.json'*) exit 0;; esac\nFLOWERSEC_TEST_SUDO=1 exec \"$@\"\n");
  await writeFile(path.join(bin, "rm"), `#!/bin/sh
set -eu
for argument in "$@"; do
  case "$argument" in
    "${archive}"|"${preflightReport}") [ "${"$"}{FLOWERSEC_TEST_SUDO:-}" = 1 ] || exit 73 ;;
  esac
done
exec /bin/rm "$@"
`);
  for (const [name, body] of [
    ["systemctl", "#!/bin/sh\nexit 0\n"],
    ["pgrep", "#!/bin/sh\nexit 1\n"],
    ["ip", "#!/bin/sh\nexit 0\n"],
    ["find", "#!/bin/sh\nexit 0\n"],
  ]) {
    await writeFile(path.join(bin, name), body);
    await chmod(path.join(bin, name), 0o700);
  }
  await chmod(path.join(bin, "rm"), 0o700);
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
    lxc_executable: "/usr/bin/lxc",
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
    kvm_helper_sha256: "f".repeat(64),
    kvm_template_sha256: "1".repeat(64),
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
  await assert.rejects(readFile(preflightReport));
});
