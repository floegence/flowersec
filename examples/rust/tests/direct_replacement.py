"""Check a single raw QUIC position using the capacity worker and independent issuer."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import tempfile


def send(process, frame):
    process.stdin.write(json.dumps(frame) + "\n")
    process.stdin.flush()


def receive(process):
    line = process.stdout.readline()
    assert line, "unexpected subprocess EOF"
    return json.loads(line)


def private_file(path):
    metadata = path.lstat()
    assert stat.S_ISREG(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) == 0o600
    return path.read_bytes()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def check(args, root):
    for role in ("records", "approvals", "invitations", "stores"):
        (root / role).mkdir(mode=0o700)
    env = dict(os.environ, FLOWERSEC_V5_APPROVAL_DIR=str(root / "approvals"),
               FLOWERSEC_V5_INVITATION_DIR=str(root / "invitations"),
               FLOWERSEC_V5_CERT_DER=str(args.cert), FLOWERSEC_V5_CA_DER=str(args.cert),
               FLOWERSEC_V5_KEY_DER=str(args.key))
    processes = []

    def start(*command):
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   text=True, env=env)
        processes.append(process)
        return process

    def observe(label, value):
        print(json.dumps({"observation": label, "value": value}), flush=True)

    events = []
    sequence = 0

    def call(op, *, reject=False, **fields):
        nonlocal sequence
        sequence += 1
        send(worker, dict(id=sequence, op=op, timeoutMS=5000, **fields))
        while True:
            row = receive(worker)
            if "event" not in row:
                break
            assert row["event"] == "terminated" and row["session"] not in events
            events.append(row["session"])
            observe("worker event", row)
        assert row["id"] == sequence
        if reject:
            assert row.get("error") == "configuration", row
        else:
            assert "error" not in row and isinstance(row.get("result"), dict), row
        observe(op, dict(request=fields, reply=row))
        return row.get("result")

    def issue(channel):
        send(issuer, {"channel_id": channel})
        receipt = receive(issuer)
        key = receipt["lookup_key"]
        assert receipt == dict(channel_id=channel, lookup_key=key, record_ref=key + ".json",
                               approval_ref=channel + ".json", invitation_ref=channel + ".json")
        invitation = private_file(root / "invitations" / receipt["invitation_ref"])
        artifact = json.loads(invitation)
        assert artifact["profile"] == "flowersec/5" and artifact["session"]["channel_id"] == channel
        assert artifact["path"]["kind"] == "direct"
        token_hash = hashlib.sha256(artifact["path"]["routing_token"].encode()).digest()
        assert key == base64.urlsafe_b64encode(token_hash).decode().rstrip("=")
        approval = private_file(root / "approvals" / receipt["approval_ref"])
        record = private_file(root / "records" / receipt["record_ref"])
        assert json.loads(record)["artifact_base64url"] == base64.urlsafe_b64encode(invitation).decode().rstrip("=")
        assert approval == invitation
        for role in ("stores", "approvals"):
            assert not (root / role / (channel + ".spent")).exists()
        observe("issuer publication", dict(receipt=receipt, artifactSHA256=digest(invitation),
                                           recordSHA256=digest(record)))
        return key

    def admitted(result, channel, generation, key):
        assert (result["id"], result["generation"], result["lookupKey"]) == (channel, generation, key)
        assert result["admissionProfile"] == "flowersec/5" and result["verifiedContractsPerEndpoint"] == 4
        binding = base64.b64decode(result["clientAdmission"], validate=True)
        assert len(binding) == 32 and any(binding) and result["clientAdmission"] == result["serverAdmission"]
        client = private_file(root / "stores" / (channel + ".spent"))
        assert client == b"flowersec-v5-artifact-spent\n"
        server = root / "approvals" / (channel + ".spent")
        assert server.samefile(root / "approvals" / (channel + ".json"))
        observe("durable consumption", dict(channel=channel, clientSpendSHA256=digest(client),
                                            linkedApprovalSHA256=digest(private_file(server))))

    def retirement(channel, generation):
        receipt = call("close_session", session=channel)
        assert receipt == dict(id=channel, generation=generation, closed=True)
        assert events[-1:] == [channel]

    try:
        worker = start(args.worker, "capacity-v5")
        bound = call("initialize", options=dict(nativeSDK="rust", carrier="raw-quic", sessions=1000,
                     streamsPerSession=0, directReplacement=True, operationTimeoutMS=5000,
                     storeDirectory=str(root / "stores")))
        issuer = start(args.issuer, "-url", "quic://" + bound["endpointAddress"], "-tls", "ca",
                       "-ttl", "180s", "-max-inbound", "32", "-record-dir", root / "records",
                       "-approval-dir", root / "approvals", "-invitation-dir", root / "invitations")
        call("prepare", count=1000)
        first = issue("p0")
        old = call("connect", index=0)
        admitted(old, "p0", 1, first)
        replace = dict(index=0, generation=2, session="p0", expectedSession="p0-g2")
        call("replace_direct", reject=True, **replace)
        assert not events
        retirement("p0", 1)
        retired = call("snapshot")
        assert retired["liveEnds"] == [0, 0] and retired["bound"] == 0 and retired["terminated"] == 1
        call("replace_direct", reject=True, **(replace | dict(generation=3, expectedSession="p0-g3")))
        call("replace_direct", reject=True, **(replace | dict(index=1)))
        second = issue("p0-g2")
        assert second != first
        new = call("replace_direct", **replace)
        admitted(new, "p0-g2", 2, second)
        assert new["clientAdmission"] != old["clientAdmission"]
        call("replace_direct", reject=True, **replace)
        for operation in ("check_live", "probe", "close_session"):
            call(operation, session="p0", reject=True)
        assert call("check_live", session="p0-g2")["liveEnds"] == [1, 1]
        current = call("check_live", count=1)
        assert current["acquired"] == current["bound"] == current["activeSessions"] == 1
        assert call("probe", session="p0-g2") == dict(id="p0-g2", generation=2, complete=True, outcome="Responsive", responsiveEnds=2)
        retirement("p0-g2", 2)
        final = call("snapshot")
        assert final["liveEnds"] == [0, 0] and final["terminated"] == 2
        assert final["acquired"] == 1 and final["bound"] == final["activeStreams"] == final["residualStreams"] == 0
        call("close")
        for process in processes:
            process.stdin.close()
            assert process.wait(timeout=5) == 0
            assert not process.stdout.read()
        assert events == ["p0", "p0-g2"]
        observe("PASS", "one Direct QUIC position, two independently issued and consumed generations")
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
            process.wait()


def deadline(*_):
    raise TimeoutError("Direct replacement smoke exceeded deadline")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("worker", "issuer", "cert", "key", "scratch"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(45)
    with tempfile.TemporaryDirectory(dir=args.scratch) as directory:
        check(args, Path(directory))
