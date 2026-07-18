.PHONY: gen gen-core gen-examples gen-check test go-test go-test-race go-vet go-vulncheck ts-ci ts-ensure-deps ts-audit ts-test ts-browser-ensure ts-browser-e2e ts-cover-check ts-lint ts-build ts-package-check swift-package-check swift-source-guard swift-build swift-test swift-cover-check swift-check rust-fmt-check rust-clippy rust-test rust-doc rust-msrv-check rust-package-check rust-audit rust-deny rust-cover-check rust-fuzz-build rust-fuzz-check rust-semver-check rust-check rust-release-check release-check release-policy-check release-version-check release-test readme-localization-check example-check example-install-check interop-smoke interop-smoke-linux interop-smoke-swift interop-stress interop-stress-full fmt fmt-check lint lint-check install-hooks precommit precommit-go precommit-ts precommit-swift precommit-rust bench bench-test check stability-check go-cover-check compat-check nightly-check

INTEROP_CELLS ?= go_to_go,typescript_to_go,swift_to_go,rust_to_go,go_to_typescript,go_to_swift,go_to_rust
INTEROP_REPORT_DIR ?= $(or $(TMPDIR),/tmp)
INTEROP_DEADLINE_MS ?= 0
CHECK_INTEROP ?= 1

GOVULNCHECK_VERSION ?= v1.1.4
GOVULNCHECK_GOTOOLCHAIN ?= go1.26.5

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

go-test-race:
	cd flowersec-go && go test -race ./...
	cd examples && go test -race ./...
	cd tools/idlgen && go test -race ./...
	cd tools/manifestgen && go test -race ./...
	cd tools/releasenotes && go test -race ./...
	cd tools/stabilitycheck && go test -race ./...

go-vet:
	cd flowersec-go && go vet ./...
	cd examples && go vet ./...
	cd tools/idlgen && go vet ./...
	cd tools/manifestgen && go vet ./...
	cd tools/releasenotes && go vet ./...
	cd tools/stabilitycheck && go vet ./...

go-vulncheck:
	cd flowersec-go && GOTOOLCHAIN=$(GOVULNCHECK_GOTOOLCHAIN) go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

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
	@if [ ! -x flowersec-ts/node_modules/.bin/eslint ] || [ ! -x flowersec-ts/node_modules/.bin/vitest ] || [ ! -x flowersec-ts/node_modules/.bin/tsc ] || [ ! -f flowersec-ts/node_modules/@vitest/coverage-v8/package.json ]; then \
		echo "flowersec-ts dependencies missing or incomplete; running npm ci --audit=false"; \
		cd flowersec-ts && npm ci --audit=false; \
	fi

ts-audit:
	cd flowersec-ts && npm audit --audit-level=high --omit=dev

ts-lint:
	cd flowersec-ts && npm run lint

ts-build:
	cd flowersec-ts && rm -rf dist && npm run build

ts-package-check:
	cd flowersec-ts && npm run verify:package

swift-package-check:
	swift package describe >/dev/null

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
	swift build

swift-test:
	swift test --enable-code-coverage

swift-cover-check:
	@coverage_path=$$(swift test --show-codecov-path); \
		node scripts/check-swift-coverage.mjs "$$coverage_path" 79 80

swift-check: swift-package-check swift-source-guard swift-build swift-test swift-cover-check

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
	cd flowersec-rust && cargo audit

rust-deny:
	cd flowersec-rust && cargo deny check

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

precommit:
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
	cd tools/stabilitycheck && go run . verify-swift
	cd tools/stabilitycheck && go run . verify-rust
	cd tools/stabilitycheck && go run . report

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

check:
	$(MAKE) release-policy-check
	$(MAKE) ts-ci
	$(MAKE) readme-localization-check
	$(MAKE) gen-check
	$(MAKE) stability-check
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
