#!/usr/bin/env python3

import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse


CONFIG_KEYS = {
    "artifact_root", "dependency_urls", "guest_identity_file", "guest_known_hosts_file", "guest_port",
    "guest_architecture", "guest_effective_cpus", "guest_launcher_argv", "guest_launcher_executable", "guest_legacy_pid_file",
    "guest_repo", "guest_root", "guest_target", "guest_vm_name", "host_agent_path", "host_config_path", "host_request_path",
    "lxc_executable", "lxc_name", "lxc_root", "proxy_url", "runner_id", "schema", "scp_executable", "ssh_executable",
    "ssh_target", "state_path",
}
RECOVERY_CONFIG_KEYS = CONFIG_KEYS - {
    "guest_architecture", "guest_effective_cpus", "guest_launcher_argv", "guest_launcher_executable",
    "guest_legacy_pid_file", "guest_vm_name",
}
LEGACY_CONFIG_KEYS = RECOVERY_CONFIG_KEYS - {"lxc_executable"}
LEGACY_LXC_EXECUTABLE = "/snap/bin/lxc"
REQUEST_KEYS = {
    "action", "agent_sha256", "archive_sha256", "base_sha", "bundle_sha256", "config_sha256",
    "host_bundle_path", "host_helper_sha256", "output_path", "proxy_sha256", "schema", "source_sha",
    "template_sha256", "kvm_helper_sha256", "kvm_template_sha256",
}
BASE_RESULT_KEYS = {
    "action", "base_sha", "check_id", "classification", "message", "schema", "source_sha", "status",
}
SAFE_TOKEN = re.compile(r"^[A-Za-z0-9_@./:-]+$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAX_NESTED_STDERR_BYTES = 16384


class RunnerFailure(Exception):
    def __init__(self, check_id, message, classification="environment", code=20):
        super().__init__(message)
        self.check_id = check_id
        self.classification = classification
        self.code = code


def digest(path):
    value = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def load_json(path):
    info = os.lstat(path)
    if not pathlib.Path(path).is_file() or pathlib.Path(path).is_symlink() or info.st_mode & 0o077:
        raise RunnerFailure("host_input", "host runner input is not a private regular file", "input", 10)
    with open(path, "r", encoding="utf-8") as source:
        return json.load(source)


def result_json(request, status, message, check_id="", classification="none"):
    return {
        "schema": "flowersec-remote-runner-result-v1",
        "status": status,
        "action": request["action"],
        "source_sha": request["source_sha"],
        "base_sha": request["base_sha"],
        "classification": classification,
        "message": message,
        "check_id": check_id,
    }


def write_status(path, payload):
    parent = os.path.dirname(path)
    os.makedirs(parent, mode=0o700, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".remote-runner-status.", dir=parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as target:
            json.dump(payload, target, separators=(",", ":"))
            target.write("\n")
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def command(argv, timeout, check=True):
    completed = subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        check=False,
    )
    if check and completed.returncode != 0:
        message = completed.stderr.strip() or completed.stdout.strip() or f"command exited {completed.returncode}"
        raise RunnerFailure("host_command", message)
    return completed


def emit_nested_stderr(value):
    encoded = value.encode("utf-8", errors="replace")
    diagnostic = encoded[-MAX_NESTED_STDERR_BYTES:].decode("utf-8", errors="replace").strip()
    if diagnostic:
        print(f"nested runner stderr (bounded tail):\n{diagnostic}", file=sys.stderr, flush=True)


def require_digest(path, expected, check_id):
    if not os.path.isfile(path) or os.path.islink(path) or digest(path) != expected:
        raise RunnerFailure(check_id, f"digest drifted: {path}", "identity", 30)


def require_executable(path, check_id):
    resolved = os.path.realpath(path)
    if (not os.path.isabs(path) or not os.path.isabs(resolved) or not os.path.isfile(resolved)
            or os.path.islink(resolved) or not os.access(path, os.X_OK)):
        raise RunnerFailure(check_id, f"configured executable is unavailable: {path}")


def validate_inputs(agent_path, helper_path, config, request, action):
    config_keys = set(config)
    legacy_recovery = action in {"collect", "cleanup"} and frozenset(config_keys) in {frozenset(RECOVERY_CONFIG_KEYS), frozenset(LEGACY_CONFIG_KEYS)}
    if (config_keys != CONFIG_KEYS and not legacy_recovery) or config.get("schema") != "flowersec-remote-runner-config-v1":
        raise RunnerFailure("host_config_schema", "host runner config schema is invalid", "input", 10)
    if set(request) != REQUEST_KEYS or request.get("schema") != "flowersec-remote-runner-request-v1":
        raise RunnerFailure("host_request_schema", "host runner request schema is invalid", "input", 10)
    if request["action"] not in {"doctor", "provision", "deploy", "run-formal", "collect", "cleanup"}:
        raise RunnerFailure("host_action", "host runner action is invalid", "input", 10)
    if request["action"] != action:
        raise RunnerFailure("host_action", "host runner argv and request actions differ", "input", 10)
    if not re.fullmatch(r"[0-9a-f]{40}", request["source_sha"]):
        raise RunnerFailure("host_source_sha", "host runner SHA is invalid", "input", 10)
    for name in ("agent_sha256", "host_helper_sha256", "proxy_sha256", "template_sha256", "kvm_helper_sha256", "kvm_template_sha256"):
        if not SHA256.fullmatch(request[name]):
            raise RunnerFailure("host_request_digest", f"invalid request digest: {name}", "input", 10)
    for name in (
        "runner_id", "lxc_name", "lxc_root", "guest_target", "guest_identity_file", "guest_known_hosts_file",
        "guest_root", "guest_repo", "artifact_root", "host_agent_path", "host_config_path", "host_request_path",
    ):
        if not isinstance(config[name], str) or not SAFE_TOKEN.fullmatch(config[name]):
            raise RunnerFailure("host_config_token", f"unsafe host runner token: {name}", "input", 10)
    if config_keys == CONFIG_KEYS:
        for name in ("guest_architecture", "guest_launcher_executable", "guest_legacy_pid_file", "guest_vm_name"):
            if not isinstance(config[name], str) or not SAFE_TOKEN.fullmatch(config[name]):
                raise RunnerFailure("host_config_token", f"unsafe KVM runner token: {name}", "input", 10)
        if config["guest_architecture"] not in {"amd64", "arm64"} or config["guest_effective_cpus"] != 8:
            raise RunnerFailure("host_kvm_cpu", "formal KVM guest must use the supported eight-CPU architecture", "input", 10)
        if not isinstance(config["guest_launcher_argv"], list) or not config["guest_launcher_argv"] or not all(isinstance(value, str) for value in config["guest_launcher_argv"]):
            raise RunnerFailure("host_kvm_argv", "KVM launcher argv must be a non-empty string array", "input", 10)
    require_digest(agent_path, request["agent_sha256"], "host_agent_digest")
    require_digest(helper_path, request["host_helper_sha256"], "host_helper_digest")
    require_executable(config.get("lxc_executable", LEGACY_LXC_EXECUTABLE), "host_lxc")


def validate_nested(payload, request):
    if not isinstance(payload, dict) or not BASE_RESULT_KEYS.issubset(payload):
        raise RunnerFailure("lxd_result_schema", "LXD agent returned an invalid result", "identity", 30)
    if payload["schema"] != "flowersec-remote-runner-result-v1" or payload["action"] != request["action"]:
        raise RunnerFailure("lxd_result_schema", "LXD agent result identity drifted", "identity", 30)
    if payload["source_sha"] != request["source_sha"] or payload["base_sha"] != request["base_sha"]:
        raise RunnerFailure("lxd_result_schema", "LXD agent result SHA drifted", "identity", 30)
    if payload["status"] not in {"GREEN", "RUNNING", "RED"}:
        raise RunnerFailure("lxd_result_schema", "LXD agent result status is invalid", "identity", 30)


def parse_result(output, request):
    try:
        payload = json.loads(output.strip())
    except json.JSONDecodeError as error:
        raise RunnerFailure("lxd_result_schema", f"LXD agent did not return strict JSON: {error}", "identity", 30)
    validate_nested(payload, request)
    return payload


def lxc(config, *arguments, timeout=30, check=True):
    executable = config.get("lxc_executable", LEGACY_LXC_EXECUTABLE)
    require_executable(executable, "host_lxc")
    return command([executable, *arguments], timeout, check)


def proxy_listening(config):
    parsed = urllib.parse.urlparse(config["proxy_url"])
    sockets = command(["ss", "-ltn"], 10, False)
    return sockets.returncode == 0 and f"{parsed.hostname}:{parsed.port}" in sockets.stdout


def start_proxy(config, request, helper_directory):
    proxy_path = os.path.join(helper_directory, "transport-v2-runner-proxy.py")
    require_digest(proxy_path, request["proxy_sha256"], "proxy_digest")
    parsed = urllib.parse.urlparse(config["proxy_url"])
    if parsed.scheme != "http" or not parsed.hostname or not parsed.port:
        raise RunnerFailure("proxy_config", "proxy URL is invalid", "input", 10)
    allowed = []
    for endpoint in config["dependency_urls"]:
        host = urllib.parse.urlparse(endpoint).hostname
        if not host or not re.fullmatch(r"[A-Za-z0-9.-]+", host):
            raise RunnerFailure("proxy_config", "dependency URL host is invalid", "input", 10)
        allowed.extend(["--allow-host", host])
    unit = "flowersec-transport-v2-proxy.service"
    command(["systemctl", "--user", "stop", unit], 15, False)
    command(["systemctl", "--user", "reset-failed", unit], 15, False)
    command([
        "systemd-run", "--user", f"--unit={unit}", "--property=Type=simple", "--property=Restart=on-failure",
        "--property=RestartSec=2s", "--property=RuntimeMaxSec=24h", "--property=TimeoutStopSec=5s",
        "/usr/bin/python3", proxy_path, "--listen-host", parsed.hostname, "--listen-port", str(parsed.port), *allowed,
    ], 30)
    active_seen = False
    for _ in range(50):
        active = command(["systemctl", "--user", "is-active", unit], 5, False)
        if active.stdout.strip() == "active":
            active_seen = True
            if proxy_listening(config):
                return
        time.sleep(0.1)
    if active_seen:
        raise RunnerFailure("proxy_socket", "host dependency proxy did not open the configured endpoint")
    raise RunnerFailure("proxy_service", "host dependency proxy did not become active")


def verify_proxy(config):
    unit = "flowersec-transport-v2-proxy.service"
    active = command(["systemctl", "--user", "is-active", unit], 5, False)
    if active.stdout.strip() != "active":
        raise RunnerFailure("proxy_service", "host dependency proxy is not active")
    if not proxy_listening(config):
        raise RunnerFailure("proxy_socket", "host dependency proxy is not listening on the configured endpoint")


def transfer_to_lxd(config, request, agent_path, helper_directory):
    lxc_name = config["lxc_name"]
    lxc_root = config["lxc_root"]
    lxd_agent = f"{lxc_root}/transport-v2-runner-agent.sh"
    lxd_config = f"{lxc_root}/runner-config.json"
    lxd_request = f"{lxc_root}/request.json"
    lxc(config, "info", lxc_name)
    lxc(config, "exec", lxc_name, "--", "install", "-d", "-m", "0700", lxc_root)
    for source, mode, destination in (
        (agent_path, "0700", lxd_agent),
        (config["host_config_path"], "0600", lxd_config),
        (config["host_request_path"], "0600", lxd_request),
    ):
        lxc(config, "file", "push", f"--mode={mode}", source, f"{lxc_name}{destination}")
    remote_agent = lxc(config, "exec", lxc_name, "--", "sha256sum", lxd_agent).stdout.split()[0]
    remote_config = lxc(config, "exec", lxc_name, "--", "sha256sum", lxd_config).stdout.split()[0]
    if remote_agent != request["agent_sha256"] or remote_config != request["config_sha256"]:
        raise RunnerFailure("lxd_transfer_digest", "LXD agent or config transfer digest drifted", "identity", 30)
    if request["action"] == "provision":
        template = os.path.join(helper_directory, "flowersec-formal@.service")
        require_digest(template, request["template_sha256"], "template_digest")
        lxd_template = f"{lxc_root}/flowersec-formal@.service"
        lxc(config, "file", "push", "--mode=0644", template, f"{lxc_name}{lxd_template}")
        remote_template = lxc(config, "exec", lxc_name, "--", "sha256sum", lxd_template).stdout.split()[0]
        if remote_template != request["template_sha256"]:
            raise RunnerFailure("lxd_template_digest", "LXD template transfer digest drifted", "identity", 30)
    if request["action"] in {"provision", "doctor"}:
        kvm_helper = os.path.join(helper_directory, "transport-v2-runner-kvm.py")
        require_digest(kvm_helper, request["kvm_helper_sha256"], "kvm_helper_digest")
        lxd_kvm_helper = f"{lxc_root}/transport-v2-runner-kvm.py"
        lxc(config, "file", "push", "--mode=0700", kvm_helper, f"{lxc_name}{lxd_kvm_helper}")
        remote_kvm_helper = lxc(config, "exec", lxc_name, "--", "sha256sum", lxd_kvm_helper).stdout.split()[0]
        if remote_kvm_helper != request["kvm_helper_sha256"]:
            raise RunnerFailure("lxd_kvm_helper_digest", "LXD KVM helper transfer digest drifted", "identity", 30)
    if request["action"] == "provision":
        kvm_template = os.path.join(helper_directory, "flowersec-kvm-guest@.service")
        require_digest(kvm_template, request["kvm_template_sha256"], "kvm_template_digest")
        lxd_kvm_template = f"{lxc_root}/flowersec-kvm-guest@.service"
        lxc(config, "file", "push", "--mode=0644", kvm_template, f"{lxc_name}{lxd_kvm_template}")
        remote_kvm_template = lxc(config, "exec", lxc_name, "--", "sha256sum", lxd_kvm_template).stdout.split()[0]
        if remote_kvm_template != request["kvm_template_sha256"]:
            raise RunnerFailure("lxd_kvm_template_digest", "LXD KVM template transfer digest drifted", "identity", 30)
    if request["action"] == "deploy":
        bundle = request["host_bundle_path"]
        require_digest(bundle, request["bundle_sha256"], "host_bundle_digest")
        lxd_bundle = f"{lxc_root}/{request['source_sha']}.bundle"
        lxc(config, "file", "push", "--mode=0600", bundle, f"{lxc_name}{lxd_bundle}", timeout=300)
    return lxd_agent, lxd_config, lxd_request


def action_timeout(action):
    return {"doctor": 35, "provision": 600, "deploy": 1200, "run-formal": 60, "collect": 540, "cleanup": 180}[action]


def pull_collection(config, request, payload):
    if request["action"] != "collect" or payload["status"] not in {"GREEN", "RED"} or "lxd_archive_path" not in payload:
        return payload
    lxd_archive = payload["lxd_archive_path"]
    archive_sha = payload.get("archive_sha256", "")
    if not SHA256.fullmatch(archive_sha):
        raise RunnerFailure("host_archive_digest", "LXD collection archive receipt is invalid", "identity", 30)
    host_directory = os.path.dirname(config["host_agent_path"])
    host_archive = os.path.join(host_directory, os.path.basename(lxd_archive))
    if not os.path.exists(host_archive):
        temporary_directory = tempfile.mkdtemp(prefix=f".collect-{request['source_sha']}.", dir=host_directory)
        temporary_archive = os.path.join(temporary_directory, "archive")
        try:
            lxc(config, "file", "pull", f"{config['lxc_name']}{lxd_archive}", temporary_archive, timeout=300)
            require_digest(temporary_archive, archive_sha, "host_archive_digest")
            os.replace(temporary_archive, host_archive)
        finally:
            shutil.rmtree(temporary_directory, ignore_errors=True)
    require_digest(host_archive, archive_sha, "host_archive_digest")
    return {**payload, "host_archive_path": host_archive}


def recover_lxd_collection(config, request, lxd_request):
    if request["action"] != "collect":
        return None
    host_directory = os.path.dirname(config["host_agent_path"])
    temporary_directory = tempfile.mkdtemp(prefix=f".status-{request['source_sha']}.", dir=host_directory)
    temporary_status = os.path.join(temporary_directory, "status.json")
    try:
        completed = lxc(
            config, "file", "pull", f"{config['lxc_name']}{lxd_request}.status", temporary_status,
            timeout=30, check=False,
        )
        if completed.returncode != 0:
            return None
        os.chmod(temporary_status, 0o600)
        with open(temporary_status, "r", encoding="utf-8") as source:
            raw_status = source.read()
        try:
            previous = json.loads(raw_status.strip())
        except json.JSONDecodeError:
            previous = None
        if isinstance(previous, dict) and previous.get("action") == "run-formal":
            if (set(previous) == BASE_RESULT_KEYS and previous.get("schema") == "flowersec-remote-runner-result-v1"
                    and previous.get("status") == "RUNNING" and previous.get("source_sha") == request["source_sha"]
                    and previous.get("base_sha") == request["base_sha"]):
                return None
            raise RunnerFailure("lxd_result_schema", "prior LXD formal receipt identity drifted", "identity", 30)
        payload = parse_result(raw_status, request)
        if payload["status"] not in {"GREEN", "RED"} or payload.get("lxd_archive_ready") is not True:
            return None
        archive_sha = payload.get("archive_sha256", "")
        archive_path = payload.get("lxd_archive_path", "")
        expected_names = {
            f"{request['source_sha']}-{config['runner_id']}-formal-closure.tar.gz",
            f"{request['source_sha']}-{config['runner_id']}-formal-failure.tar.gz",
        }
        if not SHA256.fullmatch(archive_sha) or os.path.dirname(archive_path) != config["lxc_root"] or os.path.basename(archive_path) not in expected_names:
            raise RunnerFailure("lxd_result_schema", "LXD collection status has an invalid archive receipt", "identity", 30)
        del payload["lxd_archive_ready"]
        return payload
    finally:
        shutil.rmtree(temporary_directory, ignore_errors=True)


def cleanup_host(config, request, helper_directory):
    expected = request["archive_sha256"]
    host_directory = os.path.dirname(config["host_agent_path"])
    bundle = os.path.join(host_directory, f"{request['source_sha']}.bundle")
    if os.path.lexists(bundle):
        if not os.path.isfile(bundle) or os.path.islink(bundle):
            raise RunnerFailure("host_cleanup_bundle", "host deploy bundle is not a regular task file", "cleanup", 40)
        os.unlink(bundle)
    if expected:
        for suffix in ("closure", "failure"):
            candidate = os.path.join(host_directory, f"{request['source_sha']}-{config['runner_id']}-formal-{suffix}.tar.gz")
            if os.path.lexists(candidate):
                require_digest(candidate, expected, "host_cleanup_digest")
                os.unlink(candidate)
    for candidate in pathlib.Path(host_directory).glob(f".collect-{request['source_sha']}.*"):
        if candidate.is_dir() and not candidate.is_symlink():
            shutil.rmtree(candidate)


def main():
    if len(sys.argv) != 7 or sys.argv[1:3] != ["--role", "host"] or sys.argv[6] != "flowersec-remote-runner-v1":
        return 2
    action, config_path, request_path = sys.argv[3:6]
    helper_path = os.path.realpath(__file__)
    helper_directory = os.path.dirname(helper_path)
    agent_path = os.path.join(helper_directory, "transport-v2-runner-agent.sh")
    request = {"action": action, "source_sha": "", "base_sha": ""}
    status_path = f"{request_path}.status"
    try:
        config = load_json(config_path)
        request = load_json(request_path)
        validate_inputs(agent_path, helper_path, config, request, action)
        require_digest(config_path, request["config_sha256"], "host_config_digest")
        os.chmod(agent_path, 0o700)
        os.chmod(config_path, 0o600)
        os.chmod(request_path, 0o600)
        if action == "provision":
            start_proxy(config, request, helper_directory)
        if action in {"provision", "doctor"}:
            verify_proxy(config)
        lxd_agent, lxd_config, lxd_request = transfer_to_lxd(config, request, agent_path, helper_directory)
        payload = recover_lxd_collection(config, request, lxd_request)
        if payload is None:
            nested = lxc(
                config, "exec", config["lxc_name"], "--", lxd_agent, "--role", "lxd", action, lxd_config,
                lxd_request, "flowersec-remote-runner-v1", timeout=action_timeout(action), check=False,
            )
            if nested.returncode != 0:
                emit_nested_stderr(nested.stderr)
            payload = parse_result(nested.stdout, request)
            nested_returncode = nested.returncode
        else:
            nested_returncode = 0 if payload["status"] == "GREEN" else 20
        payload = pull_collection(config, request, payload)
        if action == "deploy" and nested_returncode == 0:
            os.unlink(request["host_bundle_path"])
            lxd_bundle = f"{config['lxc_root']}/{request['source_sha']}.bundle"
            lxc(config, "exec", config["lxc_name"], "--", "rm", "-f", "--", lxd_bundle)
        if action == "cleanup" and nested_returncode == 0:
            cleanup_host(config, request, helper_directory)
        write_status(status_path, payload)
        print(json.dumps(payload, separators=(",", ":")), flush=True)
        if action == "cleanup" and nested_returncode == 0:
            for path in (
                config["host_agent_path"], config["host_config_path"], config["host_request_path"], status_path,
                helper_path, os.path.join(helper_directory, "transport-v2-runner-proxy.py"),
                os.path.join(helper_directory, "flowersec-formal@.service"),
                os.path.join(helper_directory, "transport-v2-runner-kvm.py"),
                os.path.join(helper_directory, "flowersec-kvm-guest@.service"),
            ):
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass
        return nested_returncode
    except RunnerFailure as error:
        payload = result_json(request, "RED", str(error), error.check_id, error.classification)
        try:
            write_status(status_path, payload)
        except OSError:
            pass
        print(json.dumps(payload, separators=(",", ":")), flush=True)
        return error.code
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, IndexError, json.JSONDecodeError) as error:
        payload = result_json(request, "RED", str(error), "host_orchestration", "environment")
        try:
            write_status(status_path, payload)
        except OSError:
            pass
        print(json.dumps(payload, separators=(",", ":")), flush=True)
        return 20


if __name__ == "__main__":
    sys.exit(main())
