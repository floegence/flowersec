.PHONY: gen gen-core gen-examples gen-check test go-test go-test-race go-vet go-vulncheck ts-ci ts-ensure-deps ts-audit ts-test ts-cover-check ts-lint ts-build ts-package-check fmt fmt-check lint lint-check install-hooks precommit precommit-go precommit-ts bench check stability-check go-cover-check compat-check nightly-check

GOVULNCHECK_VERSION ?= v1.1.4
GOVULNCHECK_GOTOOLCHAIN ?= go1.25.9

YAMUX_INTEROP ?= 1
YAMUX_INTEROP_STRESS ?= 0
YAMUX_INTEROP_CLIENT_RST ?= 0
YAMUX_INTEROP_DEBUG ?= 0

gen: gen-core gen-examples

gen-check: gen
	@# Fail if any tracked generated outputs changed (prevents forgetting to commit codegen results).
	@git diff --exit-code -- \
		flowersec-go/gen \
		flowersec-ts/src/gen \
		examples/gen \
		flowersec-go/internal/testgen \
		flowersec-ts/src/_examples

gen-core:
	cd tools/idlgen && go run . -in ../../idl -manifest ../../idl/manifest.core.txt -go-out ../../flowersec-go/gen -ts-out ../../flowersec-ts/src/gen
	cd flowersec-go && gofmt -w gen

gen-examples:
	# Demo IDL is for examples/integration tests only; do not ship it as a public API surface.
	cd tools/idlgen && go run . -in ../../idl -manifest ../../idl/manifest.examples.txt -go-out ../../examples/gen -ts-out ../../flowersec-ts/src/_examples
	cd tools/idlgen && go run . -in ../../idl -manifest ../../idl/manifest.examples.txt -go-out ../../flowersec-go/internal/testgen -ts-out ../../flowersec-ts/src/_examples
	gofmt -w examples/gen
	cd flowersec-go && gofmt -w internal/testgen

test: go-test ts-test

go-test:
	cd flowersec-go && go test ./...
	cd examples && go test ./...
	cd tools/idlgen && go test ./...
	cd tools/releasenotes && go test ./...
	cd tools/stabilitycheck && go test ./...

go-test-race:
	cd flowersec-go && go test -race ./...
	cd examples && go test -race ./...
	cd tools/idlgen && go test -race ./...
	cd tools/releasenotes && go test -race ./...
	cd tools/stabilitycheck && go test -race ./...

go-vet:
	cd flowersec-go && go vet ./...
	cd examples && go vet ./...
	cd tools/idlgen && go vet ./...
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

ts-cover-check:
	cd flowersec-ts && npm run test:coverage

ts-ci:
	cd flowersec-ts && npm ci --audit=false

ts-ensure-deps:
	@if [ ! -x flowersec-ts/node_modules/.bin/eslint ] || [ ! -x flowersec-ts/node_modules/.bin/vitest ] || [ ! -x flowersec-ts/node_modules/.bin/tsc ]; then \
		echo "flowersec-ts dependencies missing; running npm ci --audit=false"; \
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

precommit-go:
	$(MAKE) fmt-check
	$(MAKE) go-vet
	$(MAKE) go-test

precommit-ts:
	$(MAKE) ts-ensure-deps
	$(MAKE) ts-lint
	$(MAKE) ts-build
	$(MAKE) ts-test
	$(MAKE) ts-package-check

precommit:
	$(MAKE) gen-check
	$(MAKE) stability-check
	$(MAKE) precommit-go
	$(MAKE) precommit-ts

stability-check:
	cd tools/stabilitycheck && go run . verify-manifest
	cd tools/stabilitycheck && go run . verify-docs
	cd tools/stabilitycheck && go run . verify-go
	cd tools/stabilitycheck && go run . report

go-cover-check:
	cd tools/stabilitycheck && go run . verify-go-coverage

compat-check:
	cd flowersec-ts && \
		YAMUX_INTEROP=1 \
		YAMUX_INTEROP_STRESS=1 \
		YAMUX_INTEROP_CLIENT_RST=1 \
		YAMUX_INTEROP_DEBUG=0 \
		npm test

nightly-check:
	$(MAKE) ts-ci
	$(MAKE) stability-check
	$(MAKE) compat-check
	cd flowersec-go && go test -run '^$$' -fuzz=FuzzDecodeHandshakeFrame -fuzztime=5s ./crypto/e2ee
	cd flowersec-go && go test -run '^$$' -fuzz=FuzzParseAndVerify -fuzztime=5s ./controlplane/token
	cd flowersec-go && go test -run '^$$' -fuzz=FuzzParseAttachWithConstraints -fuzztime=5s ./tunnel/protocol

check:
	$(MAKE) ts-ci
	$(MAKE) gen-check
	$(MAKE) stability-check
	$(MAKE) lint-check
	$(MAKE) ts-build
	$(MAKE) test
	$(MAKE) go-cover-check
	$(MAKE) ts-cover-check
	$(MAKE) go-test-race
	$(MAKE) go-vulncheck
	$(MAKE) ts-audit

bench:
	bash tools/bench/bench.sh
