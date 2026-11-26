module github.com/floegence/flowersec/flowersec-go/v7

go 1.27.1

// These internal engineering packages use the SQLite adapter's module graph.
ignore (
	./internal/carrierv4/websocket
	./internal/connectv4
	./internal/ledgerv4
	./internal/rpcv4
	./internal/sessionv4
)

require (
	github.com/dunglas/httpsfv v1.1.1 // indirect
	github.com/libp2p/go-buffer-pool v0.0.2 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
)

require (
	filippo.io/edwards25519 v1.2.0
	github.com/flynn/noise v1.1.0
	github.com/gorilla/websocket v1.5.3
	github.com/libp2p/go-yamux/v5 v5.1.0
	github.com/quic-go/quic-go v0.64.1
	github.com/quic-go/webtransport-go v0.13.0
	golang.org/x/crypto v0.59.0
	golang.org/x/net v0.62.0
	golang.org/x/sys v0.50.0
	golang.org/x/text v0.44.0
)
