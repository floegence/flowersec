# Transport v2 Release Evidence

Transport v2 release evidence is a fail-closed external system gate. Local unit, browser smoke, weak-network smoke, and benchmark commands validate deterministic behavior but cannot produce or impersonate the signed Linux evidence required by `make release-check`.

## Required inputs

A collection operator must provide all of the following for the exact clean final commit:

- an executable audited Linux runner through `TRANSPORT_V2_RELEASE_RUNNER`;
- an absolute fresh output path through `TRANSPORT_V2_UNSIGNED_EVIDENCE_REPORT`;
- a full ancestor Git SHA through `TRANSPORT_V2_BASE_SHA`;
- an independent clean checkout at that base SHA and a separately built, clean-VCS-stamped base runner; the audited wrapper creates both in its private temporary build directory;
- runner identity and exact kernel, architecture, namespace, tc/eBPF effective config, executable, source, and argv hashes matching `evidence_trust_policy.json`.

The offline signing host requires the complete unsigned artifact directory, the clean exact-final-SHA repository, the production Ed25519 PKCS#8 private key, and the public key pinned by `testdata/transport_v2/evidence_trust_store.json`. The private key must never enter the Linux runner, its privileged container, Git, or chat.

The runner owns real measurements. It must execute every owner in `case_registry.json`, every 15-run cell in `performance_manifest.json`, real-browser WebTransport, qlog/pcap semantics, common-kernel weak-network cases, migration/rebinding, PMTUD, capacity, soak, resource cleanup, and race. For `clean-01`, the base variant must run the base executable from the base checkout and the candidate variant must run the final executable from the final checkout; both manifests must be byte-identical. The raw index binds each variant's source SHA, executable digest, command digest, and report digest. It must not synthesize artifacts, run both variants from the final executable, or convert local smoke output into signed evidence.

The `edge-v1` cold operation deadline is fifty-three seconds. Under the frozen
outage and burst-loss schedule, release qlog captured 1-RTT recovery probes at
2.156, 5.398, 11.882, and 24.847 seconds without an acknowledgement. Doubling
the last 12.966-second PTO interval places the next recovery probe at
approximately 50.779 seconds. Fifty-three seconds covers that probe, the
measured 0.583-second recovery round trip, and one second of application and
scheduler margin. The cold phase is fifty-five seconds so all ten operations
retain that allowance across the unchanged five-per-second open-loop schedule.
The edge RPC operation deadline is twenty-one seconds and its phase deadline is
twenty-three seconds. A frozen 30-stream Ubuntu 24 release run at the former
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
PTO. Twenty-one seconds covers that recovery with scheduler margin. The two
additional phase seconds cover the persistent connection establishment and
the unchanged one-millisecond open-loop schedule without changing payload or
operation count. The edge bulk phase deadline is nine seconds. At the former
four-second boundary, the frozen Ubuntu 24 qlog still recorded 21,626 bytes in
flight with an approximately 0.480-second smoothed RTT. That first lower bound
required six seconds. A later clean-SHA Ubuntu 24 run reached the six-second
boundary with 34,320 client bytes and 7,200 server bytes still in flight and
recent 1.52-to-1.57-second PTO intervals. Serializing the remaining 41,520
bytes at the unchanged 1 Mbps rate, then allowing one further PTO and the
observed recovery RTT, requires about 2.3 seconds beyond that boundary. Nine
seconds preserves roughly 0.7 seconds of scheduler margin without changing
the 64 KiB warmup, 128 KiB scored payload, bidirectional stream, network,
certificate, resource, zero-residual, or evidence contracts.
The edge cleanup deadline is seven seconds. A frozen Ubuntu 24 run measured a
13,138.9-millisecond server/client clock offset and 180.15-millisecond median
one-way delay. Its final bulk payload reached the client at approximately
22.238 seconds. After the initial completion response was lost, two PTOs put
the earliest retransmitted response arrival at approximately 26.109 seconds,
so completion alone required approximately 3.872 seconds. A successful run's
worst measured orderly-close tail after its final bulk payload was another
1.809 seconds. Seven seconds covers that approximately 5.681-second lower
bound with about 1.319 seconds of recovery and scheduler margin. The Rust
public session keeps its independent four-second internal close-flush bound;
the outer cleanup deadline covers both completion reconciliation and that
bounded orderly close. This changes no completion handshake, network,
workload, certificate, retry, zero-residual, or evidence semantics.

Each forced performance report preserves all fifteen independent runs and
executes them as five sequential three-run shards. Every shard is fail-fast and
has a fresh five-minute wall-clock context; runs inside a shard remain
sequential because they share the privileged network runner. Static validation
requires one complete run's phase limits to fit that context. Release
orchestration must also apply the 595-second stage hard stop, preserve partial
artifacts on failure, and reject a report that does not contain runs 1 through
15 exactly once. Sharding changes only watchdog ownership: it does not reduce
the run count, operations, payload, network faults, thresholds, or evidence.
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

The checked-in `flowersec-release-linux-2026-01` production public key is enabled for this release evidence authority, while the placeholder runner hashes deliberately continue to authorize no release. A reviewed final-runner change must install the exact executable, source, and argv hashes before collection. Never commit the private key, evidence credentials, or unredacted infrastructure secrets.

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

If any input is absent, the runner policy still contains placeholder hashes, the report final SHA differs, the repository is dirty, or one case is incomplete, stop. Do not bypass, downgrade, or relabel the evidence gate.
