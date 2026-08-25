.PHONY: test test-resume coverage-race browser-smoke browser-compat precommit diagnostic performance go-test go-test-short go-test-race go-vet go-vulncheck ts-ci ts-ensure-deps ts-audit ts-package-cache-preflight ts-test ts-test-short ts-browser-ensure ts-browser-e2e ts-cover-check ts-lint ts-build ts-package-check native-addon-test swift-package-check swift-security-check swift-source-guard swift-public-api-check swift-build swift-test swift-cover-check swift-check swift-final-check rust-fmt-check rust-clippy rust-test rust-test-short rust-doc rust-msrv-check rust-fetch rust-package-check rust-publish-preflight rust-package-offline-check rust-audit rust-audit-offline rust-deny rust-cover-check rust-fuzz-build rust-fuzz-check rust-semver-check rust-check rust-release-check release-check release-policy-check release-version-check release-test security-makefile-check security-dependency-check security-package-check source-inventory readme-localization-check example-source-check example-check example-install-check fmt fmt-check lint lint-check install-hooks precommit precommit-source precommit-go precommit-ts precommit-swift precommit-rust check final-network-preflight final-public-ca-preflight final-go-preflight final-ts-preflight final-swift-preflight final-rust-preflight final-offline-contracts final-package-validation final-integration-lanes final-post-validation final-go-check final-race-check final-ts-check final-swift-check final-rust-check stability-source-check stability-swift-check stability-rust-check stability-check flowersec-test-contract go-cover-check-short go-cover-check nightly-check

FLOWERSEC_TEST_HOST ?= ./scripts/test-host.sh
PERFORMANCE_BUDGET ?= 10m
SWIFTPM_CACHE_PATH := $(CURDIR)/.flowersec/swiftpm-cache

SWIFT_SOURCE_GUARD_PATTERN := Redeven|redeven|RedevenFlowersec|RedevenRPCClient|FlowersecDirectClient|FlowersecDirectSession|FlowersecDirectError|RuntimeFS|RuntimeGit|RuntimeTerminal|RuntimeFlower|RuntimeTypedRPC|RuntimeJSONValue|RuntimeRPCPayload|FlowerMessage|TerminalSession|MonitorSnapshot|direct runtime
SWIFT_SOURCE_GUARD_PATHS := flowersec-swift/Sources Package.swift README.md flowersec-swift/README.md docs examples .github
SWIFT_SOURCE_GUARD_PRUNE := .build .git .swiftpm dist node_modules
SWIFT_SOURCE_GUARD_FILE_GLOBS := -name '*.go' -o -name '*.json' -o -name '*.md' -o -name '*.mjs' -o -name '*.swift' -o -name '*.ts' -o -name '*.tsx' -o -name '*.txt' -o -name '*.yaml' -o -name '*.yml'

test:
	go -C flowersec-go run ./internal/cmd/flowersec-test run --suite acceptance

test-resume:
	go -C flowersec-go run ./internal/cmd/flowersec-test resume --suite acceptance

coverage-race:
	go -C flowersec-go run ./internal/cmd/flowersec-test run --suite coverage-race

browser-smoke:
	go -C flowersec-go run ./internal/cmd/flowersec-test run --suite browser-smoke

browser-compat:
	go -C flowersec-go run ./internal/cmd/flowersec-test run --suite browser-compat

diagnostic:
	$(FLOWERSEC_TEST_HOST) run --suite diagnostic

performance:
	@test -n "$(REPORT)" || { echo "REPORT=/absolute/path/performance-report.md is required" >&2; exit 2; }
	$(FLOWERSEC_TEST_HOST) run --suite performance --report "$(REPORT)" --budget "$(PERFORMANCE_BUDGET)"

go-test:
	cd flowersec-go && go test -timeout=5m $$(../scripts/list-default-go-test-packages.sh)
	cd tools/releasenotes && go test -timeout=5m ./...
	cd tools/stabilitycheck && go test -timeout=5m ./...

go-test-short:
	cd flowersec-go && go test -short -timeout=5m $$(../scripts/list-default-go-test-packages.sh)
	cd tools/releasenotes && go test -short -timeout=5m ./...
	cd tools/stabilitycheck && go test -short -timeout=5m ./...

go-test-race:
	cd flowersec-go && go test -race -timeout=5m $$(../scripts/list-default-go-test-packages.sh)
	cd tools/releasenotes && go test -race -timeout=5m ./...
	cd tools/stabilitycheck && go test -race -timeout=5m ./...

go-vet:
	cd flowersec-go && go vet ./...
	cd tools/releasenotes && go vet ./...
	cd tools/stabilitycheck && go vet ./...

go-vulncheck:
	node scripts/check-go-security.mjs

ts-test:
	cd flowersec-ts && npm test

ts-test-short: ts-ensure-deps
	cd flowersec-ts && npx vitest run --exclude 'src/**/*.integration.test.ts' --exclude 'src/v2/browserBundle.test.ts'

ts-browser-ensure:
	cd flowersec-ts && npm run ensure:browser

ts-browser-e2e:
	cd flowersec-ts && npm run test:browser:chromium

native-addon-test:
	node --test flowersec-node-native/index.test.cjs
	node scripts/server-parity-native-addon.mjs --test-native-integration

ts-cover-check:
	cd flowersec-ts && npm run test:coverage

ts-ci:
	cd flowersec-ts && npm ci --audit=false

ts-ensure-deps:
	@if [ ! -x flowersec-ts/node_modules/.bin/eslint ] || [ ! -x flowersec-ts/node_modules/.bin/vitest ] || [ ! -x flowersec-ts/node_modules/.bin/tsc ] || [ ! -x flowersec-ts/node_modules/.bin/tsx ] || [ ! -f flowersec-ts/node_modules/@vitest/coverage-v8/package.json ] || [ ! -f flowersec-ts/node_modules/ajv/package.json ] || [ ! -f flowersec-ts/node_modules/ajv-formats/package.json ] || [ ! -f flowersec-ts/node_modules/ajv-formats-draft2019/package.json ]; then \
		echo "flowersec-ts dependencies missing or incomplete; running npm ci --audit=false"; \
		cd flowersec-ts && npm ci --audit=false; \
	fi

ts-audit:
	cd flowersec-ts && npm audit --audit-level=info --include=prod --include=dev --include=optional --include=peer

ts-package-cache-preflight:
	node scripts/prepare-ts-package-cache.mjs

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

swift-public-api-check:
	node scripts/test-swift-public-api-surface.mjs

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
	rustup run 1.88.0 cargo test --manifest-path flowersec-native-transport/Cargo.toml --locked --all-features

rust-test-short:
	cd flowersec-rust && rustup run 1.88.0 cargo test --all-features --lib
	rustup run 1.88.0 cargo test --manifest-path flowersec-native-transport/Cargo.toml --locked --all-features --lib

rust-doc:
	cd flowersec-rust && RUSTDOCFLAGS="-D warnings" rustup run 1.88.0 cargo doc --all-features --no-deps

rust-msrv-check:
	cd flowersec-rust && rustup run 1.88.0 cargo check --all-targets --all-features

rust-fetch:
	cd flowersec-rust && rustup run 1.88.0 cargo fetch --locked
	cd flowersec-rust && rustup run 1.88.0 cargo fetch --locked --manifest-path fuzz/Cargo.toml
	rustup run 1.88.0 cargo fetch --locked --manifest-path examples/rust/Cargo.toml

rust-package-check:
	rustup run 1.88.0 cargo package --manifest-path flowersec-native-transport/Cargo.toml --locked --allow-dirty
	rustup run 1.88.0 cargo publish --manifest-path flowersec-native-transport/Cargo.toml --locked --dry-run --allow-dirty
	rustup run 1.88.0 cargo package --manifest-path flowersec-rust/Cargo.toml --locked --allow-dirty --list

rust-publish-preflight:
	rustup run 1.88.0 cargo publish --manifest-path flowersec-native-transport/Cargo.toml --locked --dry-run --allow-dirty
	rustup run 1.88.0 cargo package --manifest-path flowersec-rust/Cargo.toml --locked --allow-dirty --list

rust-package-offline-check:
	rustup run 1.88.0 cargo package --allow-dirty --offline --manifest-path flowersec-native-transport/Cargo.toml --locked
	rustup run 1.88.0 cargo package --allow-dirty --offline --manifest-path flowersec-rust/Cargo.toml --locked --list

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
	node scripts/check-release-version-consistency.mjs

example-source-check:
	node --test scripts/sdk-examples.test.mjs
	find examples/ts -type f -name '*.mjs' -print0 | xargs -0 -n1 node --check

example-check: example-source-check
	cd flowersec-go && go test -run '^$$' .
	flowersec-ts/node_modules/.bin/tsc --project examples/ts/tsconfig.json
	rustup run 1.88.0 cargo check --locked --offline --manifest-path examples/rust/Cargo.toml
	swift test --package-path examples/swift --cache-path "$(SWIFTPM_CACHE_PATH)" --skip-update --only-use-versions-from-resolved-file

example-install-check: example-check

fmt:
	gofmt -w flowersec-go

fmt-check:
	@if [ -n "$$(gofmt -l flowersec-go)" ]; then \
		echo "gofmt needed; run 'make fmt'"; \
		gofmt -l flowersec-go; \
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
	node --test scripts/security-dependencies.test.mjs scripts/check-dependency-contracts.test.mjs scripts/go-security.test.mjs scripts/go-toolchain-policy.test.mjs scripts/rust-security.test.mjs scripts/swift-security.test.mjs scripts/prepare-ts-package-cache.test.mjs scripts/security-makefile.test.mjs scripts/run-final-stage.test.mjs scripts/run-final-lanes.test.mjs scripts/run-precommit-wave.test.mjs scripts/test-architecture-contract.mjs
	node scripts/check-go-toolchain-policy.mjs
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
	$(MAKE) go-cover-check-short

precommit-ts:
	$(MAKE) ts-ensure-deps
	$(MAKE) ts-lint
	$(MAKE) ts-build
	$(MAKE) ts-test-short

precommit-swift:
	$(MAKE) swift-package-check
	$(MAKE) swift-security-check
	$(MAKE) swift-source-guard

precommit-rust:
	$(MAKE) rust-fmt-check
	$(MAKE) rust-clippy
	$(MAKE) rust-test-short
	$(MAKE) stability-rust-check

precommit:
	$(MAKE) precommit-source

precommit-source:
	node scripts/run-precommit-wave.mjs dependencies $(MAKE) ts-ensure-deps
	node scripts/run-precommit-wave.mjs static $(MAKE) flowersec-test-contract security-makefile-check
	node scripts/run-precommit-wave.mjs static $(MAKE) security-makefile-check security-dependency-check release-policy-check readme-localization-check stability-source-check example-source-check
	node scripts/run-precommit-wave.mjs languages $(MAKE) precommit-go precommit-ts precommit-swift precommit-rust

stability-source-check:
	cd tools/stabilitycheck && go run . verify-source

stability-swift-check:
	cd tools/stabilitycheck && go run . verify-swift
	node scripts/test-swift-public-api-surface.mjs --reuse-verified-graph

stability-rust-check:
	cd tools/stabilitycheck && go run . verify-rust

stability-check: stability-source-check stability-swift-check stability-rust-check

flowersec-test-contract:
	cd flowersec-go && go test -timeout=5m ./internal/cmd/flowersec-test ./internal/transporttest/linuxnetlab
	cd flowersec-go && go test -timeout=5m -run '^(TestCapacityCoordinatorConfigHoldsExactReleaseSessionCount|TestStreamCapacityWebSocketResourcesCoverAllPhysicalStreams|TestStreamCapacityUsesTightBridgeCopyBufferOnly)$$' ./internal/transporttest/tunnelworkload

go-cover-check-short:
	cd tools/stabilitycheck && go run . verify-go-coverage-short

go-cover-check:
	cd tools/stabilitycheck && go run . verify-go-coverage

nightly-check:
	$(MAKE) ts-ci
	$(MAKE) stability-check
	$(MAKE) rust-release-check
	$(MAKE) rust-fuzz-check
	$(MAKE) diagnostic

check: security-makefile-check
	$(MAKE) release-policy-check
	$(MAKE) readme-localization-check
	$(MAKE) example-source-check
	node scripts/run-final-stage.mjs 595 preflight $(MAKE) final-network-preflight
	CARGO_NET_OFFLINE=true GOPROXY=off GOSUMDB=off npm_config_offline=true node scripts/run-final-stage.mjs 300 contracts $(MAKE) final-offline-contracts
	CARGO_NET_OFFLINE=true GOPROXY=off GOSUMDB=off npm_config_offline=true node scripts/run-final-stage.mjs 300 packages $(MAKE) final-package-validation
	$(MAKE) final-integration-lanes
	CARGO_NET_OFFLINE=true GOPROXY=off GOSUMDB=off npm_config_offline=true node scripts/run-final-stage.mjs 595 post $(MAKE) final-post-validation

final-network-preflight: final-public-ca-preflight
	node scripts/run-final-lanes.mjs $(MAKE) final-go-preflight final-ts-preflight final-swift-preflight final-rust-preflight

final-public-ca-preflight:
	go -C flowersec-go run ./internal/cmd/flowersec-test preflight-public-ca

final-go-preflight:
	$(MAKE) go-vulncheck
	node scripts/check-go-security.mjs --prepare-offline-toolchain

final-ts-preflight:
	$(MAKE) ts-ci
	$(MAKE) ts-audit
	$(MAKE) ts-package-cache-preflight
	$(MAKE) ts-browser-ensure

final-swift-preflight:
	$(MAKE) swift-security-check
	node --test scripts/run-ios-simulator-test.test.mjs
	node scripts/run-ios-simulator-test.mjs --preflight

final-rust-preflight:
	$(MAKE) rust-fetch
	$(MAKE) rust-audit
	$(MAKE) rust-publish-preflight

final-offline-contracts:
	$(MAKE) security-dependency-check
	$(MAKE) stability-source-check

final-package-validation:
	$(MAKE) security-package-check
	$(MAKE) ts-package-check
	$(MAKE) swift-package-check
	$(MAKE) rust-package-offline-check

final-integration-lanes:
	CARGO_NET_OFFLINE=true GOPROXY=off GOSUMDB=off npm_config_offline=true node scripts/run-final-stage.mjs 595 race $(MAKE) final-race-check
	CARGO_NET_OFFLINE=true GOPROXY=off GOSUMDB=off npm_config_offline=true node scripts/run-final-stage.mjs 595 languages node scripts/run-final-lanes.mjs $(MAKE) final-go-check final-ts-check final-swift-check final-rust-check
	node scripts/run-final-stage.mjs 595 browser $(MAKE) browser-smoke

final-post-validation:
	$(MAKE) example-check

final-go-check:
	$(MAKE) flowersec-test-contract
	$(MAKE) go-vet
	$(MAKE) go-test
	$(MAKE) go-cover-check

final-race-check:
	$(MAKE) go-test-race

final-ts-check:
	$(MAKE) ts-lint
	$(MAKE) ts-build
	$(MAKE) ts-test
	$(MAKE) ts-cover-check

final-swift-check:
	$(MAKE) swift-final-check
	$(MAKE) stability-swift-check

final-rust-check:
	CARGO_NET_OFFLINE=true $(MAKE) rust-final-check
	CARGO_NET_OFFLINE=true $(MAKE) stability-rust-check
