# Transport v2 Release Evidence

Transport v2 release evidence is a fail-closed external system gate. Local unit, browser smoke, weak-network smoke, and benchmark commands validate deterministic behavior but cannot produce or impersonate the signed Linux evidence required by `make release-check`.

## Required inputs

A collection operator must provide all of the following for the exact clean final commit:

- an executable audited Linux runner through `TRANSPORT_V2_RELEASE_RUNNER`;
- an absolute fresh output path through `TRANSPORT_V2_UNSIGNED_EVIDENCE_REPORT`;
- a full ancestor Git SHA through `TRANSPORT_V2_BASE_SHA`;
- runner identity and exact kernel, architecture, namespace, tc/eBPF effective config, executable, source, and argv hashes matching `evidence_trust_policy.json`.

The offline signing host requires the complete unsigned artifact directory, the clean exact-final-SHA repository, the production Ed25519 PKCS#8 private key, and the public key pinned by `testdata/transport_v2/evidence_trust_store.json`. The private key must never enter the Linux runner, its privileged container, Git, or chat.

The runner owns real measurements. It must execute every owner in `case_registry.json`, every 15-run cell in `performance_manifest.json`, real-browser WebTransport, qlog/pcap semantics, common-kernel weak-network cases, migration/rebinding, PMTUD, capacity, soak, resource cleanup, and race. It must not synthesize artifacts or convert local smoke output into signed evidence.

## Trust bootstrap

The checked-in `flowersec-release-linux-bootstrap-disabled` key and placeholder runner hashes deliberately authorize no release. Enabling a production signer requires a reviewed repository change that installs only the public key and exact runner policy. Never commit the private key, evidence credentials, or unredacted infrastructure secrets.

The signer and runner changes must be reviewed independently from the feature under test. Verify the trust-store and policy digests with the transportcheck tests before collecting final-SHA evidence.

## Release sequence

1. Merge the complete feature and security/documentation changes into `main`, push the full local `main` tip, and keep the worktree clean.
2. On the audited Linux system, check out that exact `main` SHA and collect `report.unsigned.json` plus its referenced artifacts into a fresh directory. The collector never receives a private key and never emits a signed report.
3. Stop the privileged collector, transfer the complete directory without changing bytes, and use `transportcheck sign` on the offline signing host. The signer verifies the report, every artifact digest, runner policy, clean final SHA, base SHA, and ancestry before atomically creating `report.json` in the same directory.
4. Transfer the immutable signed directory back without changing bytes. From the synchronized clean `main` worktree, run:

```bash
TRANSPORT_V2_EVIDENCE_REPORT=/absolute/path/to/evidence/report.json \
TRANSPORT_V2_BASE_SHA=<40-character-ancestor-sha> \
scripts/release.sh <version>
```

5. `scripts/release.sh` records the signed report digest, reruns the full local release gate without invoking the collector, verifies the signature, runner policy, repository state, final/base SHA relationship, registered cases, performance cells, and referenced artifacts, then confirms the signed report bytes did not change before creating any tag.
6. Only after the atomic tag push succeeds may hosted publication jobs publish ecosystem artifacts. Confirm all publication jobs and registry artifacts before upgrading downstream repositories.

If any input is absent, the signer/policy is still bootstrap-disabled, the report final SHA differs, the repository is dirty, or one case is incomplete, stop. Do not bypass, downgrade, or relabel the evidence gate.
