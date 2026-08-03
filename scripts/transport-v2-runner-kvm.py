#!/usr/bin/env python3

import json
import os
import pathlib
import re
import signal
import subprocess
import sys
import tempfile
import time


CONFIG_KEYS = {
    "guest_architecture",
    "guest_effective_cpus",
    "guest_launcher_argv",
    "guest_launcher_executable",
    "guest_legacy_pid_file",
    "guest_port",
    "guest_vm_name",
    "runner_id",
    "schema",
}
SAFE_ID = re.compile(r"^[A-Za-z0-9_.-]+$")
STABLE_SCHEMA = "flowersec-kvm-guest-config-v1"
RESULT_SCHEMA = "flowersec-kvm-guest-result-v1"
STABLE_HELPER = "/usr/local/libexec/flowersec-transport-v2-runner-kvm"
STABLE_CONFIG_ROOT = "/etc/flowersec"
STABLE_TEMPLATE = "/etc/systemd/system/flowersec-kvm-guest@.service"


class KVMFailure(Exception):
    def __init__(self, check_id, message):
        super().__init__(message)
        self.check_id = check_id


def command(argv, timeout=30, check=True):
    completed = subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        check=False,
        shell=False,
    )
    if check and completed.returncode != 0:
        message = completed.stderr.strip() or completed.stdout.strip() or f"command exited {completed.returncode}"
        raise KVMFailure("kvm_command", message)
    return completed


def load_json(path, private):
    info = os.lstat(path)
    if not pathlib.Path(path).is_file() or pathlib.Path(path).is_symlink():
        raise KVMFailure("kvm_config", "KVM config is not a regular file")
    if private and info.st_mode & 0o077:
        raise KVMFailure("kvm_config", "KVM config is not mode 0600")
    with open(path, "r", encoding="utf-8") as source:
        return json.load(source)


def stable_config_path(runner_id):
    return os.path.join(STABLE_CONFIG_ROOT, f"transport-v2-kvm-{runner_id}.json")


def unit_name(runner_id):
    return f"flowersec-kvm-guest@{runner_id}.service"


def config_subset(config):
    return {
        "schema": STABLE_SCHEMA,
        "runner_id": config["runner_id"],
        "guest_architecture": config["guest_architecture"],
        "guest_effective_cpus": config["guest_effective_cpus"],
        "guest_launcher_executable": config["guest_launcher_executable"],
        "guest_launcher_argv": config["guest_launcher_argv"],
        "guest_legacy_pid_file": config["guest_legacy_pid_file"],
        "guest_vm_name": config["guest_vm_name"],
        "guest_port": config["guest_port"],
    }


def validate_config(config, stable=False):
    expected_schema = STABLE_SCHEMA if stable else "flowersec-remote-runner-config-v1"
    if config.get("schema") != expected_schema or not CONFIG_KEYS.issubset(config):
        raise KVMFailure("kvm_config_schema", "KVM config schema is invalid")
    if stable and set(config) != CONFIG_KEYS:
        raise KVMFailure("kvm_config_schema", "stable KVM config schema is not closed")
    if not SAFE_ID.fullmatch(config["runner_id"]) or not SAFE_ID.fullmatch(config["guest_vm_name"]):
        raise KVMFailure("kvm_identity", "KVM runner or VM identity is unsafe")
    if config["guest_architecture"] not in {"amd64", "arm64"}:
        raise KVMFailure("kvm_architecture", "KVM guest architecture is unsupported")
    if config["guest_effective_cpus"] != 8:
        raise KVMFailure("kvm_cpu", "formal KVM guest must use exactly eight effective CPUs")
    executable = config["guest_launcher_executable"]
    if not isinstance(executable, str) or not os.path.isabs(executable):
        raise KVMFailure("kvm_executable", "KVM executable must be absolute")
    resolved = os.path.realpath(executable)
    if not os.path.isfile(resolved) or not os.access(executable, os.X_OK):
        raise KVMFailure("kvm_executable", "KVM executable is unavailable")
    architecture_token = "qemu-system-aarch64" if config["guest_architecture"] == "arm64" else "qemu-system-x86_64"
    if architecture_token not in os.path.basename(resolved):
        raise KVMFailure("kvm_architecture", "KVM executable architecture differs from the guest identity")
    argv = config["guest_launcher_argv"]
    if not isinstance(argv, list) or not argv or any(not isinstance(item, str) or "\x00" in item for item in argv):
        raise KVMFailure("kvm_argv", "KVM argv must be a non-empty string array")
    if "-daemonize" in argv or "-pidfile" in argv:
        raise KVMFailure("kvm_argv", "systemd KVM argv cannot daemonize or own a pidfile")
    require_pair(argv, "-name", config["guest_vm_name"], "kvm_identity")
    require_pair(argv, "-smp", str(config["guest_effective_cpus"]), "kvm_cpu")
    expected_forward = f"hostfwd=tcp:127.0.0.1:{config['guest_port']}-:22"
    if not any(expected_forward in item.split(",") for item in argv):
        raise KVMFailure("kvm_port", "KVM argv does not bind the configured guest SSH port")
    legacy_pid = config["guest_legacy_pid_file"]
    if not isinstance(legacy_pid, str) or not os.path.isabs(legacy_pid):
        raise KVMFailure("kvm_legacy_pid", "legacy KVM pidfile must be absolute")


def require_pair(argv, flag, value, check_id):
    matches = [index for index, item in enumerate(argv) if item == flag]
    if len(matches) != 1 or matches[0] + 1 >= len(argv) or argv[matches[0] + 1] != value:
        raise KVMFailure(check_id, f"KVM argv must contain exactly one {flag} {value} pair")


def atomic_install_bytes(data, path, mode):
    os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{os.path.basename(path)}.", dir=os.path.dirname(path))
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as target:
            target.write(data)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def same_bytes(path, data, mode):
    try:
        info = os.lstat(path)
        return pathlib.Path(path).is_file() and not pathlib.Path(path).is_symlink() and info.st_mode & 0o777 == mode and pathlib.Path(path).read_bytes() == data
    except FileNotFoundError:
        return False


def process_argv(pid):
    try:
        data = pathlib.Path(f"/proc/{pid}/cmdline").read_bytes()
    except FileNotFoundError:
        return []
    return [item.decode("utf-8") for item in data.rstrip(b"\x00").split(b"\x00") if item]


def process_executable(pid):
    try:
        return os.path.realpath(os.readlink(f"/proc/{pid}/exe"))
    except FileNotFoundError:
        return ""


def normalized_legacy_argv(argv, effective_cpus):
    normalized = []
    index = 0
    while index < len(argv):
        argument = argv[index]
        if argument == "-daemonize":
            index += 1
            continue
        if argument == "-pidfile":
            if index + 1 >= len(argv):
                return []
            index += 2
            continue
        if argument == "-smp":
            if index + 1 >= len(argv):
                return []
            normalized.extend([argument, str(effective_cpus)])
            index += 2
            continue
        normalized.append(argument)
        index += 1
    return normalized


def stop_owned_legacy(config):
    path = config["guest_legacy_pid_file"]
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    if not pathlib.Path(path).is_file() or pathlib.Path(path).is_symlink() or info.st_mode & 0o022:
        raise KVMFailure("kvm_legacy_pid", "legacy KVM pidfile is not an owned regular file")
    try:
        pid = int(pathlib.Path(path).read_text(encoding="ascii").strip())
    except (ValueError, UnicodeError):
        raise KVMFailure("kvm_legacy_pid", "legacy KVM pidfile is invalid")
    argv = process_argv(pid)
    if not argv:
        os.unlink(path)
        return
    expected_executable = os.path.realpath(config["guest_launcher_executable"])
    normalized = normalized_legacy_argv(argv[1:], config["guest_effective_cpus"])
    if process_executable(pid) != expected_executable or normalized != config["guest_launcher_argv"]:
        raise KVMFailure("kvm_legacy_ownership", "legacy KVM process does not match the configured VM identity")
    os.kill(pid, signal.SIGTERM)
    for _ in range(100):
        if not process_argv(pid):
            break
        time.sleep(0.1)
    else:
        os.kill(pid, signal.SIGKILL)
        for _ in range(50):
            if not process_argv(pid):
                break
            time.sleep(0.1)
        else:
            raise KVMFailure("kvm_legacy_drain", "legacy KVM process did not stop")
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def service_pid(runner_id):
    completed = command(["systemctl", "show", unit_name(runner_id), "--property=MainPID", "--value"], 10)
    try:
        pid = int(completed.stdout.strip())
    except ValueError:
        raise KVMFailure("kvm_service_pid", "KVM service did not report a numeric main PID")
    if pid <= 0:
        raise KVMFailure("kvm_service_pid", "KVM service has no live main PID")
    return pid


def verify_service(config):
    stable_path = stable_config_path(config["runner_id"])
    stable = load_json(stable_path, True)
    validate_config(stable, True)
    if stable != config_subset(config):
        raise KVMFailure("kvm_config_drift", "installed KVM config differs from the private runner config")
    if command(["systemctl", "is-active", unit_name(config["runner_id"])], 10, False).stdout.strip() != "active":
        raise KVMFailure("kvm_service", "KVM guest service is not active")
    expected = [config["guest_launcher_executable"], *config["guest_launcher_argv"]]
    pid = service_pid(config["runner_id"])
    argv = process_argv(pid)
    if not argv or process_executable(pid) != os.path.realpath(expected[0]) or argv[1:] != expected[1:]:
        raise KVMFailure("kvm_process_identity", "KVM service argv differs from the private runner config")


def provision(config, template_path):
    validate_config(config)
    template = pathlib.Path(template_path).read_bytes()
    helper = pathlib.Path(os.path.realpath(__file__)).read_bytes()
    stable = json.dumps(config_subset(config), sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    stable_path = stable_config_path(config["runner_id"])
    changed = not same_bytes(STABLE_HELPER, helper, 0o755) or not same_bytes(STABLE_TEMPLATE, template, 0o644) or not same_bytes(stable_path, stable, 0o600)
    if changed:
        command(["systemctl", "stop", unit_name(config["runner_id"])], 30, False)
        stop_owned_legacy(config)
        atomic_install_bytes(helper, STABLE_HELPER, 0o755)
        atomic_install_bytes(template, STABLE_TEMPLATE, 0o644)
        atomic_install_bytes(stable, stable_path, 0o600)
        command(["systemctl", "daemon-reload"], 30)
        command(["systemctl", "enable", "--now", unit_name(config["runner_id"])], 60)
    elif command(["systemctl", "is-active", unit_name(config["runner_id"])], 10, False).stdout.strip() != "active":
        stop_owned_legacy(config)
        command(["systemctl", "start", unit_name(config["runner_id"])], 60)
    verify_service(config)


def result(config, status, check_id, message):
    return {
        "schema": RESULT_SCHEMA,
        "status": status,
        "check_id": check_id,
        "message": message,
        "runner_id": config.get("runner_id", ""),
        "architecture": config.get("guest_architecture", ""),
        "effective_cpus": config.get("guest_effective_cpus", 0),
    }


def main():
    if len(sys.argv) not in {3, 4} or sys.argv[1] not in {"doctor", "provision", "run"}:
        return 2
    action, config_path = sys.argv[1:3]
    config = {}
    try:
        config = load_json(config_path, action != "run")
        if action == "run":
            validate_config(config, True)
            os.execv(config["guest_launcher_executable"], [config["guest_launcher_executable"], *config["guest_launcher_argv"]])
        if action == "provision":
            if len(sys.argv) != 4:
                return 2
            provision(config, sys.argv[3])
        else:
            if len(sys.argv) != 3:
                return 2
            validate_config(config)
            verify_service(config)
        print(json.dumps(result(config, "GREEN", "", f"KVM guest {action} is stable"), separators=(",", ":")))
        return 0
    except (KVMFailure, OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
        check_id = error.check_id if isinstance(error, KVMFailure) else "kvm_internal"
        print(json.dumps(result(config, "RED", check_id, str(error)), separators=(",", ":")))
        return 20


if __name__ == "__main__":
    raise SystemExit(main())
