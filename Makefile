.PHONY: gen test go-test go-test-race go-vulncheck ts-ci ts-audit ts-test ts-lint ts-build fmt fmt-check lint lint-check bench check

GOVULNCHECK_VERSION ?= v1.1.4

YAMUX_INTEROP ?= 1
YAMUX_INTEROP_STRESS ?= 0
YAMUX_INTEROP_CLIENT_RST ?= 0
YAMUX_INTEROP_DEBUG ?= 0

gen:
	cd tools/idlgen && go run . -in ../../idl -go-out ../../flowersec-go/gen -ts-out ../../flowersec-ts/src/gen
	cd flowersec-go && gofmt -w gen

test: go-test ts-test

go-test:
	cd flowersec-go && go test ./...
	cd examples && go test ./...

go-test-race:
	cd flowersec-go && go test -race ./...
	cd examples && go test -race ./...

go-vulncheck:
	cd flowersec-go && go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

ts-test:
	cd flowersec-ts && \
		YAMUX_INTEROP=$(YAMUX_INTEROP) \
		YAMUX_INTEROP_STRESS=$(YAMUX_INTEROP_STRESS) \
		YAMUX_INTEROP_CLIENT_RST=$(YAMUX_INTEROP_CLIENT_RST) \
		YAMUX_INTEROP_DEBUG=$(YAMUX_INTEROP_DEBUG) \
		npm test

ts-ci:
	cd flowersec-ts && npm ci --audit=false

ts-audit:
	cd flowersec-ts && npm audit --audit-level=high --omit=dev

ts-lint:
	cd flowersec-ts && npm run lint

ts-build:
	cd flowersec-ts && rm -rf dist && npm run build

fmt:
	gofmt -w flowersec-go examples/go

fmt-check:
	@if [ -n "$$(gofmt -l flowersec-go examples/go)" ]; then \
		echo "gofmt needed; run 'make fmt'"; \
		gofmt -l flowersec-go examples/go; \
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
