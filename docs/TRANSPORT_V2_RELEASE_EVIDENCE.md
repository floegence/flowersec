# Transport v2 Release Evidence

Transport v2 release evidence is a fail-closed external system gate. Local unit, browser smoke, weak-network smoke, and benchmark commands validate deterministic behavior but cannot produce or impersonate the signed Linux evidence required by `make release-check`.

## Required inputs

A collection operator must provide all of the following for the exact clean final commit:

- an executable audited Linux runner through `TRANSPORT_V2_RELEASE_RUNNER`;
- an absolute fresh output path through `TRANSPORT_V2_UNSIGNED_EVIDENCE_REPORT`;
- a full ancestor Git SHA through `TRANSPORT_V2_BASE_SHA`;
- an independent clean checkout at that base SHA and a separately built, clean-VCS-stamped base runner; the audited wrapper creates both in its private temporary build directory;
- a private local runner identity file at `.flowersec/transport-runner.json`, or an absolute path selected by `FLOWERSEC_TRANSPORT_RUNNER_CONFIG`. The file records schema version, runner ID, OS, architecture, kernel release, executable SHA-256, source-graph SHA-256, and canonical argv SHA-256. It must be mode `0600`, non-symlink, untracked, and Git-ignored when it is inside the checkout;
- repository policy matching the portable capabilities in `evidence_trust_policy.json`: Linux, the supported architecture set, namespace, tc/eBPF effective config, workload, thresholds, and signer. Host-specific kernel and build identities belong only to the local file and the produced evidence.

Changing from one supported runner host or architecture to another changes only the local identity file. It must not cause a repository commit. The wrapper checks the local OS, architecture, and kernel before building; the collector deterministically rebuilds and compares executable bytes, source graph, and canonical argv, freezes the local file as an input digest, and records the complete actual identity in every raw collection index. Capacity parts must share that exact identity. Offline signing and release verification recompute the repository-derived source and argv digests and reject drift. These ownership changes do not relax any network, workload, certificate, resource, threshold, artifact, or zero-residual requirement.

The offline signing host requires the complete unsigned artifact directory, the clean exact-final-SHA repository, the production Ed25519 PKCS#8 private key, and the public key pinned by `testdata/transport_v2/evidence_trust_store.json`. The private key must never enter the Linux runner, its privileged container, Git, or chat.

The runner owns real measurements. It must execute every owner in `case_registry.json`, every 15-run cell in `performance_manifest.json`, real-browser WebTransport, qlog/pcap semantics, common-kernel weak-network cases, migration/rebinding, PMTUD, capacity, soak, resource cleanup, and race. For `clean-01`, the base variant must run the base executable from the base checkout and the candidate variant must run the final executable from the final checkout; both manifests must be byte-identical. The raw index binds each variant's source SHA, executable digest, command digest, and report digest. It must not synthesize artifacts, run both variants from the final executable, or convert local smoke output into signed evidence.

Forced browser WebTransport keeps each cold operation in the open-loop inflight
set until its session cleanup finishes. The clean profile freezes 100 operations
with at most 32 inflight, so cleanup necessarily spans four waves. An exact-SHA
Chromium 151 run started the first 32 qlog connections between
21:51:39.305Z and 21:51:39.617Z; the next 32 did not start until
21:51:44.333Z through 21:51:44.641Z. The former 6-second phase failed after
6.994 seconds with 64 artifacts spent and 36 unspent. The execution plan
therefore gives every cleanup wave the production 5-second WebTransport drain
plus its 1-second scheduler allowance, then adds one final second so the phase
strictly exceeds the cleanup-only lower bound. For clean-v1 this is
`ceil(100 / 32) * 6s + 1s = 25s`. The mapping applies only to forced browser
WebTransport direct and tunnel collection; the signed operation count,
inflight limit, start rate, network, payloads, certificate, thresholds,
zero-residual checks, and five-minute cell watchdog remain unchanged. Mobile
and edge forced profiles already exceed their one-wave lower bound, while the
adaptive browser cell retains its independently frozen signed envelope.

The `edge-v1` cold operation deadline is fifty-three seconds. Under the frozen
outage and burst-loss schedule, release qlog captured 1-RTT recovery probes at
2.156, 5.398, 11.882, and 24.847 seconds without an acknowledgement. Doubling
the last 12.966-second PTO interval places the next recovery probe at
approximately 50.779 seconds. Fifty-three seconds covers that probe, the
measured 0.583-second recovery round trip, and one second of application and
scheduler margin. The cold phase is fifty-five seconds so all ten operations
retain that allowance across the unchanged five-per-second open-loop schedule.
An exact-main QQ tunnel sample then exposed a lower carrier timeout inside that
unchanged budget. Burst loss delivered only the first fragment of a split QUIC
ClientHello. The client received its first Initial acknowledgement at about
3.349 seconds, but the server still lacked the second crypto fragment and
closed at the former ten-second handshake-idle limit. The artifact already
authorizes a thirty-second establishment interval, while both endpoints
advertise the independent sixty-second session-idle interval. Raw QUIC and
WebTransport therefore use the fixed artifact establishment interval for the
client handshake limit, and their shared production default gives a server
that same thirty-second allowance before admission can reveal the artifact.
This corrects the lower-layer timeout mismatch without changing the frozen
network, operation schedule, retries, payload, phase deadline, certificate,
threshold, or zero-residual contract.
An exact-main QW tunnel sample exposed the corresponding TCP recovery boundary.
The TLS ClientHello crossed the 1,280-byte link as 1,228-byte and 227-byte TCP
segments. The tail segment was lost, and the Linux exponential retransmission
schedule still had not closed the gap about sixteen seconds after the SYN; its
next interval fell beyond the artifact's fixed thirty-second establishment
limit. Linux WSS connections therefore enable `TCP_THIN_LINEAR_TIMEOUTS` on
each sending socket only while the TLS and WebSocket upgrade is in flight,
then restore ordinary TCP backoff before admission begins. This covers both a
fragmented ClientHello from a dialer and a fragmented server handshake from an
accepted connection. Unsupported platforms retain their native TCP policy.
This adds recovery opportunities inside the existing establishment contract;
it does not extend that contract or change the frozen network, workload,
certificate, threshold, resource, or zero-residual semantics.
The edge RPC operation deadline is twenty-four seconds and its phase deadline is
forty-seven seconds. A frozen 30-stream Ubuntu 24 release run at the former
sixteen-second boundary matched 169 client-to-server and 166 server-to-client
qlog packets with a 0.168-second median clock-adjusted one-way delay. The last
1,153-byte client request was sent at approximately 18.109 seconds on the
client qlog clock. Its earliest delivery and complete response place the lower
bound at approximately 18.444 seconds, after the client ended at 18.185
seconds. Relative to the approximately 2.185-second RPC operation start, the
measured completion lower bound is approximately 16.26 seconds. A later
clean-SHA run at the eighteen-second boundary had a 12.973-second server/client
clock offset and 0.175-second median one-way delay. The client sent the last
1,153-byte request packet at approximately 19.557 seconds, and the server sent
the matching 1,157-byte response at an aligned 19.735 seconds. Its earliest
return was approximately 19.910 seconds, after the client canceled at 19.826
seconds; a lost response would require the observed approximately 0.75-second
PTO. That evidence supported the former twenty-one-second bound. A later exact
clean-SHA run at that boundary matched 728 packets in each direction with a
12,400.9-millisecond server/client clock offset and 187.6-millisecond median
one-way delay. Persistent RPC traffic began at approximately 0.924 seconds,
but the last response tail did not reach the client until approximately
21.893 seconds. The resulting approximately 20.969-second completion lower
bound left only about 31 milliseconds for decrypt, scheduling, and future
completion. The server's final 0.408-second smoothed RTT and 0.153-second RTT
variance put one further PTO at approximately 1.02 seconds. Twenty-four
seconds covers the measured lower bound, that PTO, and approximately two
seconds of application and scheduler margin. The former two additional phase
seconds covered only the previously observed short persistent-connection
establishment path. A later exact-main QW tunnel run proved that bound could
preempt the unchanged operation budget. The persistent raw QUIC connection
started at zero, but its WSS peer lost the 276-byte tail of the fragmented TLS
ClientHello. The session OPEN acknowledgement reached the raw QUIC client at
approximately 19.522 seconds and its persistent RPC stream started at
approximately 20.779 seconds. At the former 26-second phase boundary the client
had received only about 31.8 KiB of RPC response stream data and the phase
closed at approximately 26.355 seconds. Composing the observed 20.779-second
establishment tail, the unchanged 24-second operation deadline, and the
existing two-second application and scheduler margin produces a 46.779-second
lower bound. The forty-seven-second phase is the smallest whole-second budget
that covers that evidence. It changes no network, operation count, payload,
certificate, threshold, resource, or zero-residual contract. The former edge
bulk phase deadline was fifty seconds. A clean-SHA Ubuntu
24 Chromium 151 browser WebTransport run completed RPC before approximately
4.15 seconds on its persistent connection. Its 64 KiB bidirectional warmup
then ran from approximately 4.908 through 11.206 seconds before both
directions reached FIN, consuming about 6.30 seconds. During the next 2.44
seconds, the scored server-to-browser stream delivered only about 27 KiB and
still lacked about 104.5 KiB when the former nine-second phase deadline
aborted it. Even serialization at the unchanged ideal 1 Mbps rate required at
least another 0.84 seconds before RTT, FIN, and application scheduling, which
made the old deadline physically unreachable. Extrapolating the measured
scored-stream delivery rate put the complete phase near 18.2 seconds. The
former twenty-one-second bound covered that measured duration, the latest
approximately 0.54-second PTO, and about two seconds of application and FIN
margin without changing the 64 KiB warmup, 128 KiB scored payload,
bidirectional stream, network, certificate, resource, zero-residual, or
evidence contracts. A later exact-SHA Chromium 151 run completed six
independent browser WebTransport workloads, then reached the score-stream tail
of run seven with only 130,538 of the successful 131,584 wire bytes sent and
without FIN. The client's deadline-driven STOP_SENDING arrived with the ACK
that released the final congestion window, so at least 1,046 bytes and FIN
still had to cross the unchanged network. Its minimum 115-millisecond one-way
delay alone put completion beyond twenty-one seconds. The tail smoothed RTT
was approximately 0.322 seconds, RTT variance approximately 0.062 seconds,
and the recorded PTO approximately 0.597 seconds. A later clean-SHA run proved
that twenty-three seconds still ended inside the score-stream tail: the server
received the request at approximately 4.476 seconds and did not emit all
131,584 response bytes plus FIN until approximately 26.842 seconds. The
browser's deadline-driven STOP_SENDING reached the server at approximately
27.079 seconds, leaving only 0.237 seconds after the final send. That was less
than the approximately 0.336-second smoothed RTT and could not cover the
recorded 0.434-to-0.486-second PTO. A later clean-SHA browser WebTransport to
raw QUIC tunnel run proved that twenty-five seconds still ended inside the
two-leg completion tail. Both 128 KiB directions and FIN crossed the raw QUIC
leg by approximately 23.142 and 24.083 seconds and the WebTransport leg by
approximately 13.827 and 23.977 seconds. The last WebTransport score
retransmission was emitted at approximately 24.692 seconds, but the phase
deadline reset the logical stream at approximately 25.293 seconds. Relative to
the inferred phase start, the last retransmission had already consumed about
24.399 seconds. With a 0.319-second smoothed RTT and 0.018-second RTT variance,
the base PTO was approximately 0.418 seconds. One backed-off PTO, one delivery
RTT, and one base-PTO safety interval place the completion bound near 25.97
seconds. A later exact-SHA WebSocket-to-raw-QUIC tunnel run showed that the
mixed carrier has a longer recovery tail. The slower 64 KiB warmup direction
used approximately 17.4 seconds before FIN. Its 128 KiB score direction then
advanced only about 40 KiB during the next 9.1 seconds before the former
twenty-seven-second phase boundary reset both streams. At the same observed
delivery slope, the score required approximately 29.7 seconds and the complete
bulk phase had a measured lower bound near 47.1 seconds. The tail smoothed RTT
was approximately 0.311 seconds and RTT variance approximately 0.035 seconds,
placing the base PTO near 0.478 seconds. Fifty seconds covers that measured
lower bound, one PTO, one RTT, and approximately one second of application and
scheduler margin without changing workload or evidence semantics.
An exact-clean-SHA Ubuntu 24 focused Linux shard then validated that adjusted
WQ budget without changing the frozen network or workload. Its three
independent runs delivered the complete 128 KiB scored payload in both
directions in approximately 18.19, 15.46, and 19.32 seconds. Each run retained
its qlog, pcap, kernel fault counters, and resource records, and the runner
exited with no Flowersec network namespace, BPF pin, browser, or build-directory
residual. This focused result validates the budget correction but does not
replace the complete signed final-SHA collection required below.
A later exact-main full collector exposed a rarer WQ tail at that boundary. The
raw QUIC server emitted the final scored-stream bytes and FIN approximately
49.15 seconds after the inferred phase start, then made the first PTO
retransmission approximately 0.339 seconds before the fifty-second deadline.
The client reset at the deadline before receiving the remaining 1,348 wire
bytes. The next observed PTO interval was approximately 1.020 seconds, and the
frozen jitter schedule permits a 195-millisecond one-way delay. Composing the
first-PTO position, the next PTO, maximum one-way delay, and two seconds of
application and scheduler margin gives a 52.876-second lower bound. The edge
former bulk phase deadline was therefore fifty-three seconds. A later
exact-main collection exposed a longer WQ acknowledgment-loss tail. The raw
QUIC receiver had received stream data through offset 119,397 and emitted
three acknowledgment waves, but the sender received no acknowledgment after
approximately 47.789 seconds. Its fourth PTO probes were sent at approximately
54.264 seconds and the next PTO was scheduled for approximately 61.167
seconds, after the fifty-three-second phase reset at approximately 60.540
seconds. Relative to the inferred phase start, the next probe alone required
approximately 53.627 seconds. Three frozen maximum one-way delays cover the
probe, acknowledgment, and remaining data path; serializing the remaining
12,308 wire bytes at the unchanged 1 Mbps rate requires another 98.464
milliseconds. Adding the existing two-second application and scheduler margin
produces a 56.310-second lower bound, so the edge bulk phase deadline is
fifty-seven seconds. This changes only the phase budget; the network, payloads,
operation count, certificate, thresholds, resource accounting, and
zero-residual requirements remain unchanged.
The edge outer cleanup deadline is twelve seconds. A frozen Ubuntu 24 run
measured a 13,138.9-millisecond server/client clock offset and
180.15-millisecond median one-way delay. Its final bulk payload reached the
client at approximately 22.238 seconds. After the initial completion response
was lost, two PTOs put
the earliest retransmitted response arrival at approximately 26.109 seconds,
so completion alone required approximately 3.872 seconds. A successful run's
worst measured orderly-close tail after its final bulk payload was another
1.809 seconds. A later clean-SHA run then failed during a cold public-session
close: its client sent the close/control packet at approximately 6.314 seconds
and was still sending at the former four-second internal boundary near 10.315
seconds, while the server remained active near 10.094 seconds. The Rust public
session therefore uses a seven-second close-flush upper bound.

Another clean-SHA run proved that the outer cleanup cannot share that same
seven-second bound. The outer phase first performs the release-complete
exchange and then awaits the independently bounded session close. Its failed
persistent connection had a 14,467.263-millisecond server/client clock offset
and 183.290-millisecond median one-way delay. The final server bulk packet
reached the client at approximately 20.956 seconds; after 21.428 seconds the
client received no more packets, but three PTOs kept close/control traffic
active through approximately 25.703 seconds before the outer seven-second
timeout fired. Twelve seconds composes the measured completion allowance,
rounded up to four seconds, the seven-second internal close bound, and one
second of scheduler margin. One run's total phase limit is 150
seconds, below the unchanged five-minute cell watchdog. This changes no
completion handshake, internal close bound, network, workload, certificate,
retry, zero-residual, or evidence semantics.

Each forced performance report preserves all fifteen independent runs as five
sequential three-run shards. Every shard is a separate fail-fast runner
invocation and collection stage with a fresh five-minute wall-clock context;
runs inside a shard remain sequential because they share the privileged
network runner. An exact clean-SHA Ubuntu 24 Chromium 151 run proved that five
child contexts inside one process are insufficient: the first thirteen runs
completed, but the enclosing 575-second workload timeout interrupted run 14
and the 595-second launcher contract rejected the incomplete report. No parent
workload context may therefore wrap all five shards. The 595-second hard stop
applies independently to each shard stage, so no single test can run longer
than ten minutes.

Every shard report binds its one-based shard index, the fixed shard count,
source, manifest, profile, topology, runner, BPF object, and exactly three
canonical run numbers. A separate workload-free merge stage strictly decodes
all five reports, re-hashes every referenced artifact from one pinned report
root, rejects metadata drift, duplicate or missing runs, unsafe paths,
symlinks, and size or digest changes, and atomically writes the final report
only when runs 1 through 15 are present exactly once. Static validation still
requires one complete run's phase limits to fit the five-minute shard context.
Release orchestration preserves partial artifacts on failure and rejects every
partial or unmerged report. Sharding changes only watchdog ownership: it does
not reduce the run count, operations, payload, network faults, thresholds, or
evidence.
Launch rates, operation counts, payloads, and the zero-retry contract remain
frozen; these phase budgets do not change the network, certificate, resource,
zero-residual, or evidence contracts.

The three `CAP-STREAM-WT-*-100X128` cases freeze a 32,768 aggregate
Go-runner-plus-Chromium process-tree file-descriptor ceiling and a 240
CPU-second aggregate ceiling. The audited Ubuntu 24 calibration observed
26,554 descriptors and 165.25 CPU-seconds while all 12,800 native
bidirectional streams remained simultaneously live through the hold. Their producer resource
attachment must also bind the effective `RLIMIT_NOFILE` and kernel
`fs.file-max` preflight; both must exceed the frozen case ceiling. This
stream-specific ceiling does not change the 12,288 browser-session ceiling or
the 8,192 Go-only ceiling.

Production collection requires delegated cgroup v2 controllers. Each bounded
lane is a process-free controller cgroup with a `workload` leaf for the Go
runner and a private sibling cgroup for the Node/Chromium process tree. The
browser worker enters only the selected network namespace so the cgroup mount
remains available for cumulative CPU, memory, and task accounting. A missing
controller, mismatched lane membership, unavailable private cgroup, or process
outside these descendants fails the case instead of falling back to unbounded
collection.

## Trust bootstrap

The checked-in `flowersec-release-linux-2026-01` production public key is enabled for this release evidence authority. Repository policy authorizes only reviewed portable runner capabilities; each concrete host remains unauthorized until its private local identity file matches the actual platform and deterministic executable/source/argv digests. Never commit that host identity file, the private key, evidence credentials, or unredacted infrastructure secrets.

After provisioning a clean checkout on the concrete Linux runner, generate the default private identity without starting a workload:

```bash
make transport-runner-config
```

`scripts/provision-transport-release-runner.sh` performs this step inside its pinned Ubuntu 24 container. For a manually provisioned runner, set `TRANSPORT_RUNNER_CONFIG` to an absolute repository-external output path when the default ignored file is unsuitable. Regenerate it after changing host, architecture, kernel, exact source, toolchain, or canonical collection plan; never change tracked policy merely to follow an instance change.

The signer and runner changes must be reviewed independently from the feature under test. Verify the trust-store and policy digests with the transportcheck tests before collecting final-SHA evidence.

## Release sequence

1. Merge the complete feature and security/documentation changes into `main`, push the full local `main` tip, and keep the worktree clean.
2. On the audited Linux system, check out that exact `main` SHA and collect `report.unsigned.json` plus its referenced artifacts into a fresh directory. The wrapper creates an independent detached base checkout, verifies the base and final manifests are byte-identical, and builds separate VCS-stamped runners before collecting the paired `clean-01` variants. The collector never receives a private key and never emits a signed report.
3. Stop the privileged collector, transfer the complete directory without changing bytes, and use `transportcheck sign` in a read-only, `--network none` signing container with the repository-external private key mounted read-only. The signer verifies the report, every artifact digest, runner policy, clean final SHA, base SHA, and ancestry before atomically creating `report.json` in the same directory.
4. Transfer the immutable signed directory back without changing bytes. From the synchronized clean `main` worktree, run:

```bash
TRANSPORT_V2_EVIDENCE_REPORT=/absolute/path/to/evidence/report.json \
TRANSPORT_V2_BASE_SHA=<40-character-ancestor-sha> \
scripts/release.sh <version>
```

5. `scripts/release.sh` records the signed report digest, reruns the full local release gate without invoking the collector, verifies the signature, runner policy, repository state, final/base SHA relationship, registered cases, performance cells, and referenced artifacts, then confirms the signed report bytes did not change before creating any tag.
6. Only after the atomic tag push succeeds may hosted publication jobs publish ecosystem artifacts. Confirm all publication jobs and registry artifacts before upgrading downstream repositories.

If any input is absent, the local runner identity does not match the actual host or deterministic build, the report final SHA differs, the repository is dirty, or one case is incomplete, stop. Do not bypass, downgrade, or relabel the evidence gate.
