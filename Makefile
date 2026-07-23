.PHONY: gen gen-core gen-examples gen-check test go-test go-test-race go-vet go-vulncheck ts-ci ts-ensure-deps ts-audit ts-test ts-browser-ensure ts-browser-e2e ts-cover-check ts-lint ts-build ts-package-check swift-package-check swift-security-check swift-source-guard swift-build swift-test swift-cover-check swift-check rust-fmt-check rust-clippy rust-test rust-doc rust-msrv-check rust-package-check rust-audit rust-deny rust-cover-check rust-fuzz-build rust-fuzz-check rust-semver-check rust-check rust-release-check release-check release-policy-check release-version-check release-test security-makefile-check security-dependency-check source-inventory readme-localization-check example-check example-install-check interop-smoke interop-smoke-linux interop-smoke-swift interop-stress interop-stress-full fmt fmt-check lint lint-check install-hooks precommit precommit-go precommit-ts precommit-swift precommit-rust bench bench-test check stability-check transport-v2-unit transport-conformance-smoke transport-browser-smoke transport-interop-smoke transport-conformance-full weaknet-smoke weaknet-full weaknet-system quic-native-smoke quic-native-proof quic-native-race quic-native-race-smoke bench-transport-capacity bench-transport-ab transport-v2-release-evidence transport-v2-signed-evidence-check go-cover-check compat-check nightly-check

INTEROP_CELLS ?= go_to_go,typescript_to_go,swift_to_go,rust_to_go,go_to_typescript,go_to_swift,go_to_rust
INTEROP_REPORT_DIR ?= $(or $(TMPDIR),/tmp)
INTEROP_DEADLINE_MS ?= 0
CHECK_INTEROP ?= 1

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
	cd tools/idlgen && go run . -in ../../idl -manifest ../../idl/manifest.core.txt -go-out ../../flowersec-go/gen -ts-out ../../flowersec-ts/src/gen -rust-out ../../flowersec-rust/src/gen -swift-out ../../flowersec-swift/Sources/Flowersec
	cd flowersec-go && gofmt -w gen
	cd flowersec-rust && cargo fmt --all

gen-examples:
	# Demo IDL is for examples/integration tests only; do not ship it as a public API surface.
	cd tools/idlgen && go run . -in ../../idl -manifest ../../idl/manifest.examples.txt -go-out ../../examples/gen -ts-out ../../flowersec-ts/src/_examples
	cd tools/idlgen && go run . -in ../../idl -manifest ../../idl/manifest.examples.txt -go-out ../../flowersec-go/internal/testgen -ts-out ../../flowersec-ts/src/_examples
	cd tools/idlgen && go run . -in ../../idl -manifest ../../idl/manifest.examples.txt -swift-out ../../flowersec-swift/Tests/FlowersecTests -swift-import Flowersec
	gofmt -w examples/gen
	cd flowersec-go && gofmt -w internal/testgen

test: go-test ts-test

go-test:
	cd flowersec-go && go test ./...
	cd examples && go test ./...
	cd tools/idlgen && go test ./...
	cd tools/manifestgen && go test ./...
	cd tools/releasenotes && go test ./...
	cd tools/stabilitycheck && go test ./...
	cd tools/transportcheck && go test ./...

go-test-race:
	cd flowersec-go && go test -race ./...
	cd examples && go test -race ./...
	cd tools/idlgen && go test -race ./...
	cd tools/manifestgen && go test -race ./...
	cd tools/releasenotes && go test -race ./...
	cd tools/stabilitycheck && go test -race ./...
	./scripts/run-go-test-race-shards.sh tools/transportcheck 4 10m

go-vet:
	cd flowersec-go && go vet ./...
	cd examples && go vet ./...
	cd tools/idlgen && go vet ./...
	cd tools/manifestgen && go vet ./...
	cd tools/releasenotes && go vet ./...
	cd tools/stabilitycheck && go vet ./...
	cd tools/transportcheck && go vet ./...

go-vulncheck:
	node scripts/check-go-security.mjs

ts-test:
	cd flowersec-ts && \
		YAMUX_INTEROP=$(YAMUX_INTEROP) \
		YAMUX_INTEROP_STRESS=$(YAMUX_INTEROP_STRESS) \
		YAMUX_INTEROP_CLIENT_RST=$(YAMUX_INTEROP_CLIENT_RST) \
		YAMUX_INTEROP_DEBUG=$(YAMUX_INTEROP_DEBUG) \
		npm test

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
	swift package describe >/dev/null

swift-security-check:
	node scripts/check-swift-security.mjs

swift-source-guard:
	@status=1; \
	if command -v rg >/dev/null 2>&1; then \
		if rg -n --glob '!.build/**' --glob '!.git/**' --glob '!.swiftpm/**' --glob '!dist/**' --glob '!node_modules/**' --glob '!docs/MIGRATION_TRANSPORT_V2.md' '$(SWIFT_SOURCE_GUARD_PATTERN)' $(SWIFT_SOURCE_GUARD_PATHS); then \
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
	swift build

swift-test:
	swift test --enable-code-coverage

swift-cover-check:
	@coverage_path=$$(swift test --show-codecov-path); \
		node scripts/check-swift-coverage.mjs "$$coverage_path" 79 80

swift-check: swift-package-check swift-security-check swift-source-guard swift-build swift-test swift-cover-check

rust-fmt-check:
	cd flowersec-rust && cargo fmt --all --check
	cd flowersec-rust && cargo fmt --manifest-path fuzz/Cargo.toml --check

rust-clippy:
	cd flowersec-rust && cargo clippy --all-targets --all-features -- -D warnings

rust-test:
	cd flowersec-rust && cargo test --all-features

rust-doc:
	cd flowersec-rust && RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps

rust-msrv-check:
	cd flowersec-rust && rustup run 1.85.0 cargo check --all-targets --all-features

rust-package-check:
	cd flowersec-rust && cargo package --allow-dirty
	cd flowersec-rust && cargo publish --dry-run --allow-dirty

rust-audit:
	node scripts/check-rust-security.mjs

rust-deny: rust-audit

rust-cover-check:
	cd flowersec-rust && cargo llvm-cov --all-features --fail-under-lines 85

rust-fuzz-build:
	cd flowersec-rust && cargo check --manifest-path fuzz/Cargo.toml --bins

rust-fuzz-check:
	cd flowersec-rust && for target in artifact handshake token yamux proxy; do cargo +nightly fuzz run "$$target" -- -max_total_time=10; done

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

release-check:
	$(MAKE) check
	$(MAKE) interop-stress-full
	$(MAKE) transport-v2-release-evidence
	$(MAKE) transport-v2-signed-evidence-check

example-check:
	cd examples && go test ./...
	find examples/ts -type f -name '*.mjs' -print0 | xargs -0 -n1 node --check
	cargo check --locked --manifest-path examples/rust/Cargo.toml
	swift build --package-path examples/swift

example-install-check: example-check

interop-smoke:
	go run ./flowersec-go/internal/cmd/flowersec-interop -profile smoke -cells "$(INTEROP_CELLS)" -deadline-ms "$(INTEROP_DEADLINE_MS)" -report "$(INTEROP_REPORT_DIR)/flowersec-interop-smoke.json"

interop-smoke-linux:
	$(MAKE) interop-smoke INTEROP_CELLS=go_to_go,typescript_to_go,rust_to_go,go_to_typescript,go_to_rust INTEROP_DEADLINE_MS=120000

interop-smoke-swift:
	$(MAKE) interop-smoke INTEROP_CELLS=go_to_go,swift_to_go,go_to_swift INTEROP_DEADLINE_MS=90000

interop-stress:
	@for tool in go node npm cargo rustc swift; do \
		command -v "$$tool" >/dev/null 2>&1 || { echo "missing required interop toolchain: $$tool"; exit 1; }; \
	done
	go run ./flowersec-go/internal/cmd/flowersec-interop -profile stress -cells "$(INTEROP_CELLS)" -report "$(INTEROP_REPORT_DIR)/flowersec-interop-stress.json"

interop-stress-full:
	$(MAKE) interop-stress INTEROP_CELLS="go_to_go,typescript_to_go,swift_to_go,rust_to_go,go_to_typescript,go_to_swift,go_to_rust"

fmt:
	gofmt -w flowersec-go examples/go examples/gen

fmt-check:
	@if [ -n "$$(gofmt -l flowersec-go examples/go examples/gen)" ]; then \
		echo "gofmt needed; run 'make fmt'"; \
		gofmt -l flowersec-go examples/go examples/gen; \
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

security-dependency-check: ts-build
	node --test scripts/security-dependencies.test.mjs scripts/go-security.test.mjs scripts/rust-security.test.mjs scripts/swift-security.test.mjs scripts/source-inventory.test.mjs scripts/security-makefile.test.mjs
	node scripts/generate-source-inventory.mjs --check

source-inventory:
	node scripts/generate-source-inventory.mjs

readme-localization-check:
	node ./scripts/check-readme-localizations.mjs

precommit-go:
	$(MAKE) fmt-check
	$(MAKE) go-vet
	$(MAKE) go-test
	$(MAKE) go-cover-check

precommit-ts:
	$(MAKE) ts-ensure-deps
	$(MAKE) ts-lint
	$(MAKE) ts-build
	$(MAKE) ts-test
	$(MAKE) ts-cover-check
	$(MAKE) ts-package-check

precommit-swift:
	$(MAKE) swift-check

precommit-rust:
	$(MAKE) rust-check

precommit: security-makefile-check security-dependency-check
	$(MAKE) release-policy-check
	$(MAKE) readme-localization-check
	$(MAKE) gen-check
	$(MAKE) stability-check
	$(MAKE) precommit-go
	$(MAKE) precommit-ts
	$(MAKE) precommit-swift
	$(MAKE) precommit-rust

stability-check:
	cd tools/manifestgen && go run .
	cd tools/stabilitycheck && go run . verify-manifest
	cd tools/stabilitycheck && go run . verify-defaults
	cd tools/stabilitycheck && go run . verify-parity
	cd tools/stabilitycheck && go run . verify-docs
	cd tools/stabilitycheck && go run . verify-go
	cd tools/stabilitycheck && go run . verify-ts
	cd tools/stabilitycheck && go run . verify-swift
	cd tools/stabilitycheck && go run . verify-rust
	cd tools/stabilitycheck && go run . report

transport-v2-unit:
	cd tools/transportcheck && go test ./...
	cd tools/transportcheck && go run . manifest -manifest ../../testdata/transport_v2/performance_manifest.json -registry ../../testdata/transport_v2/case_registry.json
	cd tools/transportcheck && go run . gate -meta ../../testdata/transport_v2/evidence_meta_schema.json -target transport-v2-unit -classification contract_only

transport-conformance-smoke:
	cd tools/transportcheck && go run . gate -meta ../../testdata/transport_v2/evidence_meta_schema.json -target transport-conformance-smoke -classification local_smoke
	cd flowersec-go && go test -count=1 ./protocolv2 ./artifactv2 ./admissionv2 ./session
	cd flowersec-ts && npx vitest run src/v2
	cd flowersec-rust && cargo test --all-features --test transport_v2_contract --test transport_v2_crypto_vectors --test open_v2_vectors --test session_v2
	swift test --filter 'TransportV2|IDNAHostV2'
	@echo "classification=local_smoke; no signed release evidence is claimed"

transport-browser-smoke:
	cd tools/transportcheck && go run . gate -meta ../../testdata/transport_v2/evidence_meta_schema.json -target transport-browser-smoke -classification local_smoke
	cd flowersec-ts && npx vitest run src/browser/connectV2.test.ts src/browser/webTransportCarrierInternalStage.test.ts src/v2/browserBundle.test.ts
	cd flowersec-ts && npm run test:browser:chromium
	@echo "classification=local_smoke; Chromium WebTransport interoperability evidence is not claimed"

transport-interop-smoke:
	cd tools/transportcheck && go run . gate -meta ../../testdata/transport_v2/evidence_meta_schema.json -target transport-interop-smoke -classification local_smoke
	cd flowersec-ts && npx vitest run src/v2/session_go_interop.test.ts
	cd flowersec-rust && cargo test --all-features --test raw_quic_v2 rust_and_go_run_full_session_v2_over_raw_quic_direct_and_tunnel
	@echo "classification=local_smoke; the full cross-language release matrix is not claimed"

WEAKNET_SMOKE_REPORT ?= /tmp/flowersec-weaknet-smoke.json
WEAKNET_SMOKE_REPORT_ABS = $(abspath $(WEAKNET_SMOKE_REPORT))

weaknet-smoke:
	cd flowersec-go && FLOWERSEC_RUN_WEAKNET_SMOKE=1 WEAKNET_SMOKE_REPORT="$(WEAKNET_SMOKE_REPORT_ABS)" go test -count=1 -run '^TestWeaknetSmoke$$' ./internal/weaknetsmoke
	cd tools/transportcheck && go run . gate -meta ../../testdata/transport_v2/evidence_meta_schema.json -target weaknet-smoke -classification local_smoke -report "$(WEAKNET_SMOKE_REPORT_ABS)"

quic-native-smoke:
	@if [ "$(QUIC_NATIVE_REQUIRE_SIGNED_EVIDENCE)" = "1" ]; then \
		echo "signed qlog-backed native QUIC evidence is unavailable; local_smoke cannot satisfy NS-N1/NS-N2"; \
		exit 1; \
	fi
	cd tools/transportcheck && go run . gate -meta ../../testdata/transport_v2/evidence_meta_schema.json -target quic-native-smoke -classification local_smoke
	cd flowersec-go && go test -count=1 -run '^(TestEightCarrierStreamsUseEightDistinctNativeBidiStreamIDs|TestNativeResetIsIsolatedFromSiblingStream|TestNativeStreamFlowControlStallDoesNotBlockSibling|TestClientMigrationValidatesAndSwitchesToNewPacketConn)$$' ./carrier/rawquic
	cd flowersec-go && go test -count=1 -run '^TestBrokerBridgesControlAndBidirectionalStreamsAcrossMixedCarriers$$' ./tunnelv2
	@echo "classification=local_smoke; qlog/system performance evidence is not claimed"

quic-native-race-smoke:
	cd tools/transportcheck && go run . gate -meta ../../testdata/transport_v2/evidence_meta_schema.json -target quic-native-race-smoke -classification local_smoke
	cd flowersec-go && go test -race -count=1 -run '^(TestEightCarrierStreamsUseEightDistinctNativeBidiStreamIDs|TestNativeResetIsIsolatedFromSiblingStream|TestNativeStreamFlowControlStallDoesNotBlockSibling|TestClientMigrationValidatesAndSwitchesToNewPacketConn)$$' ./carrier/rawquic
	cd flowersec-go && go test -race -count=1 -run '^TestBrokerBridgesControlAndBidirectionalStreamsAcrossMixedCarriers$$' ./tunnelv2
	@echo "classification=local_smoke; qlog-backed race evidence is not claimed"

TRANSPORT_V2_EVIDENCE_REPORT ?=
TRANSPORT_V2_BASE_SHA ?=
TRANSPORT_V2_RELEASE_RUNNER ?=
override TRANSPORT_V2_TRUST_STORE := $(CURDIR)/testdata/transport_v2/evidence_trust_store.json
override TRANSPORT_V2_TRUST_POLICY := $(CURDIR)/testdata/transport_v2/evidence_trust_policy.json

define run_transport_v2_release_target
	@if [ -z "$(TRANSPORT_V2_RELEASE_RUNNER)" ] || [ -z "$(TRANSPORT_V2_EVIDENCE_REPORT)" ] || [ -z "$(TRANSPORT_V2_BASE_SHA)" ]; then \
		echo "$@: requires TRANSPORT_V2_RELEASE_RUNNER, TRANSPORT_V2_EVIDENCE_REPORT, and TRANSPORT_V2_BASE_SHA" >&2; \
		exit 2; \
	fi
	@if [ ! -x "$(TRANSPORT_V2_RELEASE_RUNNER)" ]; then \
		echo "$@: release runner is not executable: $(TRANSPORT_V2_RELEASE_RUNNER)" >&2; \
		exit 2; \
	fi
	"$(TRANSPORT_V2_RELEASE_RUNNER)" --target "$@" --report "$(TRANSPORT_V2_EVIDENCE_REPORT)"
	$(MAKE) transport-v2-signed-evidence-check
endef

transport-conformance-full weaknet-full weaknet-system quic-native-proof quic-native-race bench-transport-capacity bench-transport-ab:
	$(run_transport_v2_release_target)

transport-v2-release-evidence:
	@if [ -z "$(TRANSPORT_V2_RELEASE_RUNNER)" ] || [ -z "$(TRANSPORT_V2_EVIDENCE_REPORT)" ] || [ -z "$(TRANSPORT_V2_BASE_SHA)" ]; then \
		echo "$@: requires TRANSPORT_V2_RELEASE_RUNNER, TRANSPORT_V2_EVIDENCE_REPORT, and TRANSPORT_V2_BASE_SHA" >&2; \
		exit 2; \
	fi
	@if [ ! -x "$(TRANSPORT_V2_RELEASE_RUNNER)" ]; then \
		echo "$@: release runner is not executable: $(TRANSPORT_V2_RELEASE_RUNNER)" >&2; \
		exit 2; \
	fi
	"$(TRANSPORT_V2_RELEASE_RUNNER)" --target all --report "$(TRANSPORT_V2_EVIDENCE_REPORT)"

transport-v2-signed-evidence-check:
	./scripts/check-transport-v2-evidence.sh "$(TRANSPORT_V2_EVIDENCE_REPORT)" "$(TRANSPORT_V2_BASE_SHA)"

go-cover-check:
	cd tools/stabilitycheck && go run . verify-go-coverage

compat-check:
	$(MAKE) interop-smoke-linux

nightly-check:
	$(MAKE) ts-ci
	$(MAKE) stability-check
	$(MAKE) rust-release-check
	$(MAKE) rust-fuzz-check
	@if [ "$(CHECK_INTEROP)" = "1" ]; then $(MAKE) interop-smoke-linux; fi
	cd flowersec-go && go test -run '^$$' -fuzz=FuzzDecodeHandshakeFrame -fuzztime=5s ./crypto/e2ee
	cd flowersec-go && go test -run '^$$' -fuzz=FuzzParseAndVerify -fuzztime=5s ./controlplane/token
	cd flowersec-go && go test -run '^$$' -fuzz=FuzzParseAttachWithConstraints -fuzztime=5s ./tunnel/protocol

check: security-makefile-check security-dependency-check
	$(MAKE) release-policy-check
	$(MAKE) ts-ci
	$(MAKE) readme-localization-check
	$(MAKE) gen-check
	$(MAKE) stability-check
	$(MAKE) transport-v2-unit
	$(MAKE) weaknet-smoke
	$(MAKE) quic-native-smoke
	$(MAKE) bench-test
	$(MAKE) lint-check
	$(MAKE) ts-build
	$(MAKE) ts-browser-ensure
	$(MAKE) ts-browser-e2e
	$(MAKE) swift-check
	$(MAKE) rust-release-check
	$(MAKE) example-check
	$(MAKE) test
	$(MAKE) go-cover-check
	$(MAKE) ts-cover-check
	$(MAKE) go-test-race
	$(MAKE) go-vulncheck
	$(MAKE) ts-audit
	@if [ "$(CHECK_INTEROP)" = "1" ]; then $(MAKE) interop-smoke; fi

bench:
	bash tools/bench/bench.sh

bench-test:
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tools/bench/bench_check_test.py
