.PHONY: gen test go-test ts-test lint

gen:
	cd tools/idlgen && go run . -in ../../idl -go-out ../../go/gen -ts-out ../../ts/src/gen
	cd go && gofmt -w gen

test: go-test ts-test

go-test:
	cd go && go test ./...

ts-test:
	cd ts && npm test

lint:
	cd go && gofmt -w .
	cd ts && npm run lint
