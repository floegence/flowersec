import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODELS = ROOT / "testdata" / "security_v5"
ADMISSION = {
    "direct_completes": "exists-trace",
    "tunnel_completes": "exists-trace",
    "disjoint_ingresses_pair": "exists-trace",
    "pair_authority_and_identity": "all-traces",
    "admission_provenance": "all-traces",
}
ACTIVE = {
    **ADMISSION,
    "admission_once": "all-traces",
    "direct_requires_admission": "all-traces",
    "unique_server_completion": "all-traces",
    "client_authenticates_server": "all-traces",
    "server_authenticates_client": "all-traces",
    "session_key_secrecy": "all-traces",
    "record_round_trip": "exists-trace",
    "authenticated_record_context": "all-traces",
    "confidential_payload": "all-traces",
}
ROUTED = {**ADMISSION, "routed_tunnel_requires_both_admissions": "all-traces"}


def run(command, directory, expected=0):
    result = subprocess.run(command, cwd=directory, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, timeout=180, check=False)
    if result.returncode != expected:
        raise RuntimeError(f"{command[0]} exited {result.returncode}, expected {expected}\n{result.stdout[-4000:]}")
    return result.stdout


def check_tlc(directory, jar, model, fault, properties, violation=None):
    config = directory / f"{model}.cfg"
    config.write_text(f'SPECIFICATION Spec\nCONSTANT Fault = "{fault}"\nINVARIANT {properties}\n')
    output = run(["java", "-Xmx512m", "-XX:+UseParallelGC", f"-Djava.io.tmpdir={directory}", "-cp", jar,
                  "tlc2.TLC", "-workers", "1", "-deadlock", "-cleanup", "-metadir", "states",
                  "-config", config.name, model], directory, 12 if violation else 0)
    marker = f"Invariant {violation} is violated" if violation else "Model checking completed. No error has been found."
    if marker not in output:
        raise RuntimeError(f"missing TLC result for {properties}\n{output[-4000:]}")
    counts = re.search(r"[\d,]+ states generated, [\d,]+ distinct states found", output)
    if not counts:
        raise RuntimeError("missing TLC exploration counts")
    outcome = "expected witness found" if violation else "invariants verified"
    print(f"TLC {model} / {fault} / {properties}: {outcome} ({counts[0]})", flush=True)


def check_tamarin(directory, model, expected, *flags):
    output = run(["tamarin-prover", "--prove", "--quit-on-warning", "--derivcheck-timeout=60", *flags, str(MODELS / model),
                  "+RTS", "-N2", "-M2G", "-RTS"], directory)
    summary = output.rpartition("summary of summaries:")[2]
    results = re.findall(r"^\s*(\w+) \((exists-trace|all-traces)\): (\w+)", summary, re.MULTILINE)
    if (len(results) != len(expected) or {name: kind for name, kind, _ in results} != expected
            or any(status != "verified" for _, _, status in results)):
        raise RuntimeError(f"incomplete Tamarin proof\n{output[-4000:]}")
    print(model, *flags, summary.strip(), flush=True)


def check_replay(directory, version):
    if run(["z3", "-version"], directory).split()[:3] != ["Z3", "version", version]:
        raise RuntimeError(f"expected Z3 {version}")
    template = (MODELS / "Replay.smt2.in").read_text()
    expected = ["first_delivery_blocks_replay", "unsat", "exact_acceptance_update", "unsat",
                "forward_jump_reachable", "sat", "forget_history_control", "sat"]
    for width in (64, 128):
        model = directory / f"Replay{width}.smt2"
        model.write_text(template.replace("WIDTH", str(width)).replace("EXTRA", str(width - 64)))
        results = run(["z3", "-T:150", model.name], directory).splitlines()
        if results != expected:
            raise RuntimeError(f"incomplete replay proof for width {width}: {results}")
        print(f"Z3 Replay{width}: {' '.join(results)}", flush=True)


def main():
    pins = json.loads((ROOT / "toolchains.json").read_text())["securityModels"]
    if not os.environ.get("TLA2TOOLS_JAR"):
        raise RuntimeError(f"set TLA2TOOLS_JAR to the TLA+ {pins['tlaTools']} release jar")
    jar = Path(os.environ["TLA2TOOLS_JAR"]).resolve()
    if hashlib.sha256(jar.read_bytes()).hexdigest() != pins["tlaSha256"]:
        raise RuntimeError("TLA+ release jar checksum mismatch")
    with tempfile.TemporaryDirectory(prefix="flowersec-v5-models-") as scratch:
        directory = Path(scratch)
        check_replay(directory, pins["z3"])
        print(run([sys.executable, ROOT / "scripts/check-v5-epoch-guards.py"], directory), end="", flush=True)
        versions = run(["tamarin-prover", "--version"], directory)
        for tool, prefix in [("tamarin", "Tamarin"), ("maude", "Maude")]:
            if f"{prefix} version {pins[tool]}" not in versions.splitlines():
                raise RuntimeError(f"expected {prefix} {pins[tool]}\n{versions}")
        suites = {
            "Credential": ("ConfirmedBeforeWrite SingleUse", "NoCompletedSession",
                           {"earlyWrite": "ConfirmedBeforeWrite", "staleAdmission": "SingleUse"}),
            "Policy": ("NoDowngrade EligibleWrite", "NoSuccessfulRotation",
                       {"downgrade": "NoDowngrade", "staleTime": "EligibleWrite"}),
            "Profile": ("Isolated Authorized LocalOnly", "NoHTTP",
                        {"mixedHandles": "Isolated", "wrongAuthority": "Isolated",
                         "originOnly": "Authorized", "remoteLoopback": "LocalOnly"}),
            "Stream": ("UniqueNonce UniqueDelivery OrderedEpochs AuthenticatedEOF", "NoRekeyedClose",
                       {"staleAck": "UniqueNonce", "earlyEOF": "AuthenticatedEOF"}),
            "ConcurrentRekey": ("AllStreamsReady LiveRoots", "NoCrossedUpdates",
                                {"earlyCommit": "AllStreamsReady", "ignorePrior": "LiveRoots"}),
            "Datagram": ("WindowSafe", "NoOutOfOrder", {"forgetWindow": "WindowSafe", "unchecked": "WindowSafe"}),
            "EpochWindow": ("AtMostOnce EligibleEpoch", "NoLatePrevious", {"retainedRoot": "AtMostOnce"}),
            "TunnelClose": ("AuthenticatedClose ClientWaitsForRelay", "NoCoordinatedClose",
                            {"carrierOnly": "AuthenticatedClose", "skipRelayClose": "ClientWaitsForRelay"}),
            "Lifecycle": ("TrafficAuthorized SafeRecords SafeLease", "NoCompletedLifecycle",
                          {"bypassBinding": "TrafficAuthorized"}),
        }
        for model, (properties, witness, controls) in suites.items():
            shutil.copyfile(MODELS / f"{model}.tla", directory / f"{model}.tla")
            check_tlc(directory, jar, model, "none", properties)
            check_tlc(directory, jar, model, "none", witness, witness)
            for fault, violation in controls.items():
                check_tlc(directory, jar, model, fault, violation, violation)
        check_tlc(directory, jar, "ConcurrentRekey", "none", "NoReclamation", "NoReclamation")
        check_tlc(directory, jar, "Profile", "none", "NoLoopback", "NoLoopback")
        check_tamarin(directory, "Handshake.spthy", ROUTED)
        check_tamarin(directory, "Handshake.spthy", ACTIVE, "-DACTIVE_RELAY")
        check_tamarin(directory, "KeyExposure.spthy", {"past_session_secret": "all-traces",
                      "opposite_direction_secret": "all-traces", "exposure_boundary": "exists-trace"})
        check_tamarin(directory, "Enrollment.spthy", {"descriptor_reachable": "exists-trace",
                      "confirm_before_describe": "all-traces", "one_description_per_exchange": "all-traces",
                      "descriptor_origin": "all-traces", "descriptor_secrecy": "all-traces"})


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        sys.exit(str(error))
