.PHONY: gen test go-test ts-test lint

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

ts-test:
	cd ts && \
		YAMUX_INTEROP=$(YAMUX_INTEROP) \
		YAMUX_INTEROP_STRESS=$(YAMUX_INTEROP_STRESS) \
		YAMUX_INTEROP_CLIENT_RST=$(YAMUX_INTEROP_CLIENT_RST) \
		YAMUX_INTEROP_DEBUG=$(YAMUX_INTEROP_DEBUG) \
		npm test

lint:
	gofmt -w go examples/go
	cd ts && npm run lint
