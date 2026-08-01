.PHONY: gen gen-core gen-examples gen-check test go-test go-test-short go-test-race go-vet go-vulncheck ts-ci ts-ensure-deps ts-audit ts-test ts-test-short ts-browser-ensure ts-browser-e2e ts-cover-check ts-lint ts-build ts-package-check swift-package-check swift-security-check swift-source-guard swift-build swift-test swift-cover-check swift-check swift-final-check rust-fmt-check rust-clippy rust-test rust-test-short rust-doc rust-msrv-check rust-fetch rust-package-check rust-package-offline-check rust-audit rust-audit-offline rust-deny rust-cover-check rust-fuzz-build rust-fuzz-check rust-semver-check rust-check rust-release-check rust-final-check release-check release-policy-check release-version-check release-test security-makefile-check security-dependency-check security-package-check source-inventory readme-localization-check example-check example-install-check fmt fmt-check lint lint-check install-hooks precommit precommit-go precommit-ts precommit-swift precommit-rust check final-network-preflight final-go-preflight final-ts-preflight final-swift-preflight final-rust-preflight final-offline-contracts final-package-validation final-integration-lanes final-post-validation final-go-check final-race-check final-ts-check final-swift-check final-rust-check stability-source-check stability-swift-check stability-rust-check stability-check transportcheck-fast transport-runner-config transport-v2-unit transport-conformance-smoke transport-browser-smoke transport-interop-smoke transport-conformance-full weaknet-smoke weaknet-full weaknet-system quic-native-smoke quic-native-proof quic-native-race quic-native-race-smoke bench-transport-capacity bench-transport-soak bench-transport-ab transport-v2-release-collect-conformance-smoke transport-v2-release-evidence transport-v2-signed-evidence-check go-cover-check compat-check nightly-check

CHECK_INTEROP ?= 1
TRANSPORT_RUNNER_CONFIG ?= $(CURDIR)/.flowersec/transport-runner.json
SWIFTPM_CACHE_PATH := $(CURDIR)/.flowersec/swiftpm-cache

YAMUX_INTEROP ?= 1
YAMUX_INTEROP_STRESS ?= 0
YAMUX_INTEROP_CLIENT_RST ?= 0
YAMUX_INTEROP_DEBUG ?= 0
SWIFT_SOURCE_GUARD_PATTERN := Redeven|redeven|RedevenFlowersec|RedevenRPCClient|FlowersecDirectClient|FlowersecDirectSession|FlowersecDirectError|RuntimeFS|RuntimeGit|RuntimeTerminal|RuntimeFlower|RuntimeTypedRPC|RuntimeJSONValue|RuntimeRPCPayload|FlowerMessage|TerminalSession|MonitorSnapshot|direct runtime
SWIFT_SOURCE_GUARD_PATHS := flowersec-swift/Sources Package.swift README.md flowersec-swift/README.md docs examples .github
SWIFT_SOURCE_GUARD_PRUNE := .build .git .swiftpm dist node_modules
SWIFT_SOURCE_GUARD_FILE_GLOBS := -name '*.go' -o -name '*.json' -o -name '*.md' -o -name '*.mjs' -o -name '*.swift' -o -name '*.ts' -o -name '*.tsx' -o -name '*.txt' -o -name '*.yaml' -o -name '*.yml'

gen: gen-core gen-examples

gen-check: gen
	@# Fail if any tracked generated outputs changed (prevents forgetting to commit codegen results).
	@git diff --exit-code -- \
		flowersec-go/gen \
		flowersec-ts/src/gen \
		flowersec-rust/src/gen \
		flowersec-swift/Sources/Flowersec/Generated \
		flowersec-swift/Tests/FlowersecTests/Generated \
		examples/gen \
		flowersec-go/internal/testgen \
		flowersec-ts/src/_examples

gen-core:
	cd tools/idlgen && go run . -in ../../idl -manifest ../../idl/manifest.core.txt -go-out ../../flowersec-go/gen -ts-out ../../flowersec-ts/src/gen
	cd flowersec-go && gofmt -w gen
	cd flowersec-rust && rustup run 1.88.0 cargo fmt --all

gen-examples:
	# Demo IDL is for examples/integration tests only; do not ship it as a public API surface.
	cd tools/idlgen && go run . -in ../../idl -manifest ../../idl/manifest.examples.txt -go-out ../../examples/gen -ts-out ../../flowersec-ts/src/_examples
	cd tools/idlgen && go run . -in ../../idl -manifest ../../idl/manifest.examples.txt -go-out ../../flowersec-go/internal/testgen -ts-out ../../flowersec-ts/src/_examples
	gofmt -w examples/gen
	cd flowersec-go && gofmt -w internal/testgen

test: go-test ts-test

go-test:
	cd flowersec-go && go test -timeout=5m ./...
	cd tools/idlgen && go test -timeout=5m ./...
	cd tools/releasenotes && go test -timeout=5m ./...
	cd tools/stabilitycheck && go test -timeout=5m ./...
	$(MAKE) transportcheck-fast

go-test-short:
	cd flowersec-go && go test -short -timeout=5m ./...
	cd tools/idlgen && go test -short -timeout=5m ./...
	cd tools/releasenotes && go test -short -timeout=5m ./...
	cd tools/stabilitycheck && go test -short -timeout=5m ./...
	$(MAKE) transportcheck-fast

go-test-race:
	cd flowersec-go && go test -race -timeout=5m ./...
	cd tools/idlgen && go test -race -timeout=5m ./...
	cd tools/releasenotes && go test -race -timeout=5m ./...
	cd tools/stabilitycheck && go test -race -timeout=5m ./...
	./scripts/run-go-test-race-shards.sh tools/transportcheck 45 5m auto race 1

go-vet:
	cd flowersec-go && go vet ./...
	cd tools/idlgen && go vet ./...
	cd tools/releasenotes && go vet ./...
	cd tools/stabilitycheck && go vet ./...
	cd tools/transportcheck && go vet ./...

transport-runner-config:
	cd tools/transportcheck && go run . runner-config -repo "$(CURDIR)" -output "$(TRANSPORT_RUNNER_CONFIG)"

go-vulncheck:
	node scripts/check-go-security.mjs

ts-test:
	cd flowersec-ts && \
		YAMUX_INTEROP=$(YAMUX_INTEROP) \
		YAMUX_INTEROP_STRESS=$(YAMUX_INTEROP_STRESS) \
		YAMUX_INTEROP_CLIENT_RST=$(YAMUX_INTEROP_CLIENT_RST) \
		YAMUX_INTEROP_DEBUG=$(YAMUX_INTEROP_DEBUG) \
		npm test

ts-test-short: ts-ensure-deps
	cd flowersec-ts && npx vitest run --exclude 'src/**/*.integration.test.ts' --exclude 'src/v2/session_go_interop.test.ts' --exclude 'src/v2/browserBundle.test.ts'

ts-browser-ensure:
	cd flowersec-ts && npm run ensure:browser

ts-browser-e2e:
	cd flowersec-ts && npm run test:browser

ts-cover-check:
	cd flowersec-ts && npm run test:coverage

ts-ci:
	cd flowersec-ts && npm ci --audit=false

ts-ensure-deps:
	@if [ ! -x flowersec-ts/node_modules/.bin/eslint ] || [ ! -x flowersec-ts/node_modules/.bin/vitest ] || [ ! -x flowersec-ts/node_modules/.bin/tsc ] || [ ! -f flowersec-ts/node_modules/@vitest/coverage-v8/package.json ] || [ ! -f flowersec-ts/node_modules/ajv/package.json ] || [ ! -f flowersec-ts/node_modules/ajv-formats/package.json ] || [ ! -f flowersec-ts/node_modules/ajv-formats-draft2019/package.json ]; then \
		echo "flowersec-ts dependencies missing or incomplete; running npm ci --audit=false"; \
		cd flowersec-ts && npm ci --audit=false; \
	fi

ts-audit:
	cd flowersec-ts && npm audit --audit-level=info --include=prod --include=dev --include=optional --include=peer

ts-lint:
	cd flowersec-ts && npm run lint

ts-build: ts-ensure-deps
	cd flowersec-ts && rm -rf dist && npm run build

ts-package-check:
	cd flowersec-ts && npm run verify:package

swift-package-check:
	swift package --cache-path "$(SWIFTPM_CACHE_PATH)" --skip-update --only-use-versions-from-resolved-file describe >/dev/null

swift-security-check:
	node scripts/check-swift-security.mjs

swift-source-guard:
	@status=1; \
	if command -v rg >/dev/null 2>&1; then \
		if rg -n --glob '!.build/**' --glob '!.git/**' --glob '!.swiftpm/**' --glob '!dist/**' --glob '!node_modules/**' '$(SWIFT_SOURCE_GUARD_PATTERN)' $(SWIFT_SOURCE_GUARD_PATHS); then \
			status=0; \
		else \
			status=$$?; \
		fi; \
	else \
		matches=$$(find $(SWIFT_SOURCE_GUARD_PATHS) $$(printf ' -name %s -o' $(SWIFT_SOURCE_GUARD_PRUNE) | sed 's/ -o$$//') -prune -o -type f \( $(SWIFT_SOURCE_GUARD_FILE_GLOBS) \) -exec grep -InE '$(SWIFT_SOURCE_GUARD_PATTERN)' {} +); \
		if [ -n "$$matches" ]; then \
			printf "%s\n" "$$matches"; \
			status=0; \
		else \
			status=1; \
		fi; \
	fi; \
	if [ "$$status" = "0" ]; then \
		echo "Swift SDK contains downstream product semantics"; \
		exit 1; \
	fi; \
	if [ "$$status" != "1" ]; then \
		echo "Swift source guard scan failed"; \
		exit "$$status"; \
	fi

swift-build:
	swift build --cache-path "$(SWIFTPM_CACHE_PATH)" --skip-update --only-use-versions-from-resolved-file

swift-test:
	# Xcode 26.4 can retain a stale test-bundle resource seal after swift-build.
	@if [ "$$(uname -s)" = "Darwin" ]; then swift package --cache-path "$(SWIFTPM_CACHE_PATH)" --skip-update --only-use-versions-from-resolved-file clean; fi
	swift test --cache-path "$(SWIFTPM_CACHE_PATH)" --skip-update --only-use-versions-from-resolved-file --enable-code-coverage

swift-cover-check:
	@coverage_path=$$(swift test --cache-path "$(SWIFTPM_CACHE_PATH)" --skip-update --only-use-versions-from-resolved-file --show-codecov-path); \
		node scripts/check-swift-coverage.mjs "$$coverage_path" 79 80

swift-check:
	$(MAKE) swift-package-check
	$(MAKE) swift-security-check
	$(MAKE) swift-source-guard
	$(MAKE) swift-build
	$(MAKE) swift-test
	$(MAKE) swift-cover-check

swift-final-check:
	$(MAKE) swift-source-guard
	swift build --cache-path "$(SWIFTPM_CACHE_PATH)" --skip-update --only-use-versions-from-resolved-file
	@# Xcode 26.4 can retain a stale test-bundle resource seal after swift-build.
	@if [ "$$(uname -s)" = "Darwin" ]; then swift package --cache-path "$(SWIFTPM_CACHE_PATH)" --skip-update --only-use-versions-from-resolved-file clean; fi
	swift test --cache-path "$(SWIFTPM_CACHE_PATH)" --skip-update --only-use-versions-from-resolved-file --enable-code-coverage
	@coverage_path=$$(swift test --cache-path "$(SWIFTPM_CACHE_PATH)" --skip-update --only-use-versions-from-resolved-file --show-codecov-path); \
		node scripts/check-swift-coverage.mjs "$$coverage_path" 79 80

rust-fmt-check:
	cd flowersec-rust && rustup run 1.88.0 cargo fmt --all --check
	cd flowersec-rust && rustup run 1.88.0 cargo fmt --manifest-path fuzz/Cargo.toml --check

rust-clippy:
	cd flowersec-rust && rustup run 1.88.0 cargo clippy --all-targets --all-features -- -D warnings

rust-test:
	cd flowersec-rust && rustup run 1.88.0 cargo test --all-features

rust-test-short:
	cd flowersec-rust && rustup run 1.88.0 cargo test --all-features --lib

rust-doc:
	cd flowersec-rust && RUSTDOCFLAGS="-D warnings" rustup run 1.88.0 cargo doc --all-features --no-deps

rust-msrv-check:
	cd flowersec-rust && rustup run 1.88.0 cargo check --all-targets --all-features

rust-fetch:
	cd flowersec-rust && rustup run 1.88.0 cargo fetch --locked
	cd flowersec-rust && rustup run 1.88.0 cargo fetch --locked --manifest-path fuzz/Cargo.toml
	rustup run 1.88.0 cargo fetch --locked --manifest-path examples/rust/Cargo.toml

rust-package-check:
	cd flowersec-rust && rustup run 1.88.0 cargo package --allow-dirty
	cd flowersec-rust && rustup run 1.88.0 cargo publish --dry-run --allow-dirty

rust-package-offline-check:
	cd flowersec-rust && rustup run 1.88.0 cargo package --allow-dirty --offline

rust-audit:
	node scripts/check-rust-security.mjs

rust-audit-offline:
	node scripts/check-rust-security.mjs --offline

rust-deny: rust-audit

rust-cover-check:
	cd flowersec-rust && rustup run 1.88.0 cargo llvm-cov --all-features --fail-under-lines 85

rust-fuzz-build:
	cd flowersec-rust && rustup run 1.88.0 cargo check --manifest-path fuzz/Cargo.toml --bins

rust-fuzz-check:
	cd flowersec-rust && cargo +nightly fuzz run artifact -- -max_total_time=10

rust-semver-check:
	@version=$$(sed -n 's/^version = "\([^"]*\)"/\1/p' flowersec-rust/Cargo.toml | head -1); \
	current="flowersec-rust/v$$version"; \
	previous=$$(git tag --list 'flowersec-rust/v*' --sort=-v:refname | grep -Fvx "$$current" | head -1); \
	if [ -z "$$previous" ]; then \
		echo "Rust semver check skipped: no previous flowersec-rust tag"; \
	else \
		cd flowersec-rust && cargo +stable semver-checks check-release --manifest-path Cargo.toml --baseline-rev "$$previous"; \
	fi

rust-check: rust-fmt-check rust-clippy rust-test rust-doc rust-msrv-check rust-package-check rust-fuzz-build

rust-release-check: rust-check rust-audit rust-deny rust-cover-check rust-semver-check

rust-final-check: rust-fmt-check rust-clippy rust-test rust-doc rust-msrv-check rust-cover-check rust-fuzz-build rust-semver-check

release-check:
	$(MAKE) check
	$(MAKE) transport-v2-signed-evidence-check

example-check:
	node --test scripts/sdk-examples.test.mjs
	find examples/ts -type f -name '*.mjs' -print0 | xargs -0 -n1 node --check
	cd flowersec-go && go test -run '^$$' .
	rustup run 1.88.0 cargo check --locked --offline --manifest-path examples/rust/Cargo.toml
	swift test --package-path examples/swift --cache-path "$(SWIFTPM_CACHE_PATH)" --skip-update --only-use-versions-from-resolved-file

example-install-check: example-check

fmt:
	gofmt -w flowersec-go examples/gen

fmt-check:
	@if [ -n "$$(gofmt -l flowersec-go examples/gen)" ]; then \
		echo "gofmt needed; run 'make fmt'"; \
		gofmt -l flowersec-go examples/gen; \
		exit 1; \
	fi

lint: fmt go-vet ts-lint

lint-check: fmt-check go-vet ts-lint

install-hooks:
	./scripts/install-git-hooks.sh

release-policy-check:
	./scripts/check-release-workflow-policy.sh
	$(MAKE) release-version-check
	$(MAKE) release-test

release-version-check:
	node scripts/check-release-version-consistency.mjs

release-test:
	node --test scripts/check-release-version-consistency.test.mjs scripts/release.test.mjs

security-makefile-check:
	node scripts/check-security-makefile.mjs Makefile

security-dependency-check:
	node --test scripts/security-dependencies.test.mjs scripts/go-security.test.mjs scripts/rust-security.test.mjs scripts/swift-security.test.mjs scripts/security-makefile.test.mjs scripts/run-final-stage.test.mjs scripts/run-final-lanes.test.mjs
	node scripts/generate-source-inventory.mjs --check

security-package-check: ts-build
	node --test scripts/source-inventory.test.mjs

source-inventory:
	node scripts/generate-source-inventory.mjs

readme-localization-check:
	node --test scripts/check-readme-localizations.test.mjs
	node ./scripts/check-readme-localizations.mjs

precommit-go:
	$(MAKE) fmt-check
	$(MAKE) go-vet
	$(MAKE) go-test-short
	$(MAKE) go-cover-check

precommit-ts:
	$(MAKE) ts-ensure-deps
	$(MAKE) ts-lint
	$(MAKE) ts-test-short

precommit-swift:
	$(MAKE) swift-package-check
	$(MAKE) swift-security-check
	$(MAKE) swift-source-guard

precommit-rust:
	$(MAKE) rust-fmt-check
	$(MAKE) rust-clippy
	$(MAKE) rust-test-short

precommit: security-makefile-check security-dependency-check
	$(MAKE) release-policy-check
	$(MAKE) readme-localization-check
	$(MAKE) gen-check
	$(MAKE) stability-source-check
	$(MAKE) precommit-go
	$(MAKE) precommit-ts
	$(MAKE) precommit-swift
	$(MAKE) precommit-rust

stability-source-check:
	cd tools/stabilitycheck && go run . verify-manifest
	cd tools/stabilitycheck && go run . verify-defaults
	cd tools/stabilitycheck && go run . verify-parity
	cd tools/stabilitycheck && go run . verify-docs
	cd tools/stabilitycheck && go run . verify-go
	cd tools/stabilitycheck && go run . verify-ts
	cd tools/stabilitycheck && go run . report

stability-swift-check:
	cd tools/stabilitycheck && go run . verify-swift

stability-rust-check:
	cd tools/stabilitycheck && go run . verify-rust

stability-check: stability-source-check stability-swift-check stability-rust-check

transportcheck-fast:
	cd tools/transportcheck && go test -timeout=5m -count=1 -run '^(TestCheckedInManifestAndRegistryAreValid|TestFrozenSingleTestTargetsDoNotExceedFiveMinutes|TestCheckedInRegistryOwnersHaveMakeRecipes|TestCheckedInEvidenceTrustPolicyPinsExactRunner|TestManifestRejectsInvalidFrozenContract|TestManifestDigestIsCanonicalAndTamperEvident|TestManifestAcceptsMeasuredEdgeRecoveryBudgetWithinFiveMinuteCell|TestCaseRegistryRejectsInvalidOwnership|TestStrictJSONRejectsUnknownFields|TestEvidenceMetaSchemaAndGateClassifications|TestMakeTargetsUseEvidenceClassificationGate)$$' .

transport-v2-unit:
	./scripts/run-go-test-race-shards.sh tools/transportcheck 6 5m 3 normal
	cd tools/transportcheck && go run . manifest -manifest ../../testdata/transport_v2/performance_manifest.json -registry ../../testdata/transport_v2/case_registry.json -makefile ../../Makefile
	cd tools/transportcheck && go run . gate -meta ../../testdata/transport_v2/evidence_meta_schema.json -target transport-v2-unit -classification contract_only

transport-conformance-smoke:
	cd tools/transportcheck && go run . gate -meta ../../testdata/transport_v2/evidence_meta_schema.json -target transport-conformance-smoke -classification local_smoke
	cd flowersec-go && go test -timeout=5m -count=1 ./internal/protocolv2 ./internal/artifactv2 ./internal/admissionv2 ./internal/session
	cd flowersec-ts && npx vitest run src/v2
	cd flowersec-rust && rustup run 1.88.0 cargo test --all-features --lib --test transport_v2_contract
	swift test --filter 'TransportV2|IDNAHostV2'
	@echo "classification=local_smoke; no signed release evidence is claimed"

transport-browser-smoke:
	cd tools/transportcheck && go run . gate -meta ../../testdata/transport_v2/evidence_meta_schema.json -target transport-browser-smoke -classification local_smoke
	cd flowersec-ts && npm run build
	cd flowersec-ts && npx vitest run src/browser/connectV2.test.ts src/browser/webTransportCarrierInternalStage.test.ts src/v2/browserBundle.test.ts
	cd flowersec-ts && npx playwright test --project=chromium
	@echo "classification=local_smoke; Chromium WebTransport interoperability evidence is not claimed"

transport-interop-smoke:
	cd tools/transportcheck && go run . gate -meta ../../testdata/transport_v2/evidence_meta_schema.json -target transport-interop-smoke -classification local_smoke
	cd flowersec-ts && npx vitest run src/v2/session_go_interop.test.ts
	cd flowersec-rust && rustup run 1.88.0 cargo test --all-features --lib rust_and_go_run_full_session_v2_over_raw_quic_direct_and_tunnel
	@echo "classification=local_smoke; the full cross-language release matrix is not claimed"

WEAKNET_SMOKE_REPORT ?= /tmp/flowersec-weaknet-smoke.json
WEAKNET_SMOKE_REPORT_ABS = $(abspath $(WEAKNET_SMOKE_REPORT))

weaknet-smoke:
	cd flowersec-go && FLOWERSEC_RUN_WEAKNET_SMOKE=1 WEAKNET_SMOKE_REPORT="$(WEAKNET_SMOKE_REPORT_ABS)" go test -timeout=5m -count=1 -run '^TestWeaknetSmoke$$' ./internal/weaknetsmoke
	cd tools/transportcheck && go run . gate -meta ../../testdata/transport_v2/evidence_meta_schema.json -target weaknet-smoke -classification local_smoke -report "$(WEAKNET_SMOKE_REPORT_ABS)"

quic-native-smoke:
	@if [ "$(QUIC_NATIVE_REQUIRE_SIGNED_EVIDENCE)" = "1" ]; then \
		echo "signed qlog-backed native QUIC evidence is unavailable; local_smoke cannot satisfy NS-N1/NS-N2"; \
		exit 1; \
	fi
	cd tools/transportcheck && go run . gate -meta ../../testdata/transport_v2/evidence_meta_schema.json -target quic-native-smoke -classification local_smoke
	cd flowersec-go && go test -timeout=5m -count=1 -run '^(TestEightCarrierStreamsUseEightDistinctNativeBidiStreamIDs|TestNativeResetIsIsolatedFromSiblingStream|TestNativeStreamFlowControlStallDoesNotBlockSibling|TestClientMigrationValidatesAndSwitchesExclusivelyToNewPacketConn)$$' ./internal/carrier/rawquic
	cd flowersec-go && go test -timeout=5m -count=1 -run '^TestBrokerBridgesControlAndBidirectionalStreamsAcrossMixedCarriers$$' ./internal/tunnelv2
	@echo "classification=local_smoke; qlog/system performance evidence is not claimed"

quic-native-race-smoke:
	cd tools/transportcheck && go run . gate -meta ../../testdata/transport_v2/evidence_meta_schema.json -target quic-native-race-smoke -classification local_smoke
	cd flowersec-go && go test -race -timeout=5m -count=1 -run '^(TestEightCarrierStreamsUseEightDistinctNativeBidiStreamIDs|TestNativeResetIsIsolatedFromSiblingStream|TestNativeStreamFlowControlStallDoesNotBlockSibling|TestClientMigrationValidatesAndSwitchesExclusivelyToNewPacketConn)$$' ./internal/carrier/rawquic
	cd flowersec-go && go test -race -timeout=5m -count=1 -run '^TestBrokerBridgesControlAndBidirectionalStreamsAcrossMixedCarriers$$' ./internal/tunnelv2
	@echo "classification=local_smoke; qlog-backed race evidence is not claimed"

TRANSPORT_V2_EVIDENCE_REPORT ?=
TRANSPORT_V2_UNSIGNED_EVIDENCE_REPORT ?=
TRANSPORT_V2_BASE_SHA ?=
TRANSPORT_V2_RELEASE_RUNNER ?=
override TRANSPORT_V2_TRUST_STORE := $(CURDIR)/testdata/transport_v2/evidence_trust_store.json
override TRANSPORT_V2_TRUST_POLICY := $(CURDIR)/testdata/transport_v2/evidence_trust_policy.json

define run_transport_v2_release_target
	@if [ -z "$(TRANSPORT_V2_RELEASE_RUNNER)" ] || [ -z "$(TRANSPORT_V2_UNSIGNED_EVIDENCE_REPORT)" ] || [ -z "$(TRANSPORT_V2_BASE_SHA)" ]; then \
		echo "$@: requires TRANSPORT_V2_RELEASE_RUNNER, TRANSPORT_V2_UNSIGNED_EVIDENCE_REPORT, and TRANSPORT_V2_BASE_SHA" >&2; \
		exit 2; \
	fi
	@if [ ! -x "$(TRANSPORT_V2_RELEASE_RUNNER)" ]; then \
		echo "$@: release runner is not executable: $(TRANSPORT_V2_RELEASE_RUNNER)" >&2; \
		exit 2; \
	fi
	"$(TRANSPORT_V2_RELEASE_RUNNER)" --target "$@" --report "$(TRANSPORT_V2_UNSIGNED_EVIDENCE_REPORT)"
endef

transport-conformance-full weaknet-full weaknet-system quic-native-proof quic-native-race bench-transport-capacity bench-transport-soak bench-transport-ab:
	$(run_transport_v2_release_target)

transport-v2-release-collect-conformance-smoke:
	@if [ -z "$(TRANSPORT_V2_RELEASE_RUNNER)" ] || [ -z "$(TRANSPORT_V2_UNSIGNED_EVIDENCE_REPORT)" ] || [ -z "$(TRANSPORT_V2_BASE_SHA)" ]; then \
		echo "$@: requires TRANSPORT_V2_RELEASE_RUNNER, TRANSPORT_V2_UNSIGNED_EVIDENCE_REPORT, and TRANSPORT_V2_BASE_SHA" >&2; \
		exit 2; \
	fi
	@if [ ! -x "$(TRANSPORT_V2_RELEASE_RUNNER)" ]; then \
		echo "$@: release runner is not executable: $(TRANSPORT_V2_RELEASE_RUNNER)" >&2; \
		exit 2; \
	fi
	"$(TRANSPORT_V2_RELEASE_RUNNER)" --target "transport-conformance-smoke" --report "$(TRANSPORT_V2_UNSIGNED_EVIDENCE_REPORT)"

transport-v2-release-evidence:
	@if [ -z "$(TRANSPORT_V2_RELEASE_RUNNER)" ] || [ -z "$(TRANSPORT_V2_UNSIGNED_EVIDENCE_REPORT)" ] || [ -z "$(TRANSPORT_V2_BASE_SHA)" ]; then \
		echo "$@: requires TRANSPORT_V2_RELEASE_RUNNER, TRANSPORT_V2_UNSIGNED_EVIDENCE_REPORT, and TRANSPORT_V2_BASE_SHA" >&2; \
		exit 2; \
	fi
	@if [ ! -x "$(TRANSPORT_V2_RELEASE_RUNNER)" ]; then \
		echo "$@: release runner is not executable: $(TRANSPORT_V2_RELEASE_RUNNER)" >&2; \
		exit 2; \
	fi
	"$(TRANSPORT_V2_RELEASE_RUNNER)" --target all --report "$(TRANSPORT_V2_UNSIGNED_EVIDENCE_REPORT)"

transport-v2-signed-evidence-check:
	./scripts/check-transport-v2-evidence.sh "$(TRANSPORT_V2_EVIDENCE_REPORT)" "$(TRANSPORT_V2_BASE_SHA)"

go-cover-check:
	cd tools/stabilitycheck && go run . verify-go-coverage

compat-check:
	$(MAKE) transport-conformance-smoke

nightly-check:
	$(MAKE) ts-ci
	$(MAKE) stability-check
	$(MAKE) rust-release-check
	$(MAKE) rust-fuzz-check
	@if [ "$(CHECK_INTEROP)" = "1" ]; then $(MAKE) transport-interop-smoke; fi

check: security-makefile-check
	$(MAKE) release-policy-check
	$(MAKE) readme-localization-check
	node scripts/run-final-stage.mjs 595 preflight $(MAKE) final-network-preflight
	CARGO_NET_OFFLINE=true GOPROXY=off npm_config_offline=true node scripts/run-final-stage.mjs 300 contracts $(MAKE) final-offline-contracts
	CARGO_NET_OFFLINE=true GOPROXY=off npm_config_offline=true node scripts/run-final-stage.mjs 300 packages $(MAKE) final-package-validation
	$(MAKE) final-integration-lanes
	CARGO_NET_OFFLINE=true GOPROXY=off npm_config_offline=true node scripts/run-final-stage.mjs 595 post $(MAKE) final-post-validation

final-network-preflight:
	node scripts/run-final-lanes.mjs $(MAKE) final-go-preflight final-ts-preflight final-swift-preflight final-rust-preflight

final-go-preflight:
	$(MAKE) go-vulncheck

final-ts-preflight:
	$(MAKE) ts-ci
	$(MAKE) ts-audit
	$(MAKE) ts-browser-ensure

final-swift-preflight:
	$(MAKE) swift-security-check

final-rust-preflight:
	$(MAKE) rust-fetch
	$(MAKE) rust-audit
	$(MAKE) rust-package-check

final-offline-contracts:
	$(MAKE) security-dependency-check
	$(MAKE) gen-check
	$(MAKE) stability-source-check

final-package-validation:
	$(MAKE) security-package-check
	$(MAKE) ts-package-check
	$(MAKE) swift-package-check
	$(MAKE) rust-package-offline-check

final-integration-lanes:
	CARGO_NET_OFFLINE=true GOPROXY=off npm_config_offline=true node scripts/run-final-stage.mjs 595 race $(MAKE) final-race-check
	CARGO_NET_OFFLINE=true GOPROXY=off npm_config_offline=true node scripts/run-final-stage.mjs 595 languages node scripts/run-final-lanes.mjs $(MAKE) final-go-check final-ts-check final-swift-check final-rust-check

final-post-validation:
	$(MAKE) example-check
	@if [ "$(CHECK_INTEROP)" = "1" ]; then $(MAKE) transport-interop-smoke; fi

final-go-check:
	$(MAKE) transport-v2-unit
	$(MAKE) weaknet-smoke
	$(MAKE) quic-native-smoke
	$(MAKE) go-vet
	$(MAKE) go-test
	$(MAKE) go-cover-check

final-race-check:
	$(MAKE) go-test-race

final-ts-check:
	$(MAKE) ts-lint
	$(MAKE) ts-build
	$(MAKE) ts-browser-e2e
	$(MAKE) ts-test
	$(MAKE) ts-cover-check

final-swift-check:
	$(MAKE) swift-final-check
	$(MAKE) stability-swift-check

final-rust-check:
	CARGO_NET_OFFLINE=true $(MAKE) rust-final-check
	CARGO_NET_OFFLINE=true $(MAKE) stability-rust-check
