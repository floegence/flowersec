.PHONY: gen test go-test go-test-race go-vulncheck ts-ci ts-audit ts-test ts-lint ts-build fmt fmt-check lint lint-check bench check

GOVULNCHECK_VERSION ?= v1.1.4

YAMUX_INTEROP ?= 1
YAMUX_INTEROP_STRESS ?= 0
YAMUX_INTEROP_CLIENT_RST ?= 0
YAMUX_INTEROP_DEBUG ?= 0

gen:
	cd tools/idlgen && go run . -in ../../idl -go-out ../../go/gen -ts-out ../../ts/src/gen
	cd go && gofmt -w gen

test: go-test ts-test

go-test:
	cd go && go test ./...
	cd examples && go test ./...

go-test-race:
	cd go && go test -race ./...
	cd examples && go test -race ./...

go-vulncheck:
	cd go && go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

ts-test:
	cd ts && \
		YAMUX_INTEROP=$(YAMUX_INTEROP) \
		YAMUX_INTEROP_STRESS=$(YAMUX_INTEROP_STRESS) \
		YAMUX_INTEROP_CLIENT_RST=$(YAMUX_INTEROP_CLIENT_RST) \
		YAMUX_INTEROP_DEBUG=$(YAMUX_INTEROP_DEBUG) \
		npm test

ts-ci:
	cd ts && npm ci --audit=false

ts-audit:
	cd ts && npm audit --audit-level=high --omit=dev

ts-lint:
	cd ts && npm run lint

ts-build:
	cd ts && rm -rf dist && npm run build

fmt:
	gofmt -w go examples/go

fmt-check:
	@if [ -n "$$(gofmt -l go examples/go)" ]; then \
		echo "gofmt needed; run 'make fmt'"; \
		gofmt -l go examples/go; \
		exit 1; \
	fi

lint: fmt ts-lint

lint-check: fmt-check ts-lint

check:
	$(MAKE) ts-ci
	$(MAKE) lint-check
	$(MAKE) ts-build
	$(MAKE) test
	$(MAKE) go-test-race
	$(MAKE) go-vulncheck
	$(MAKE) ts-audit

bench:
	bash tools/bench/bench.sh
