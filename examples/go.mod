module github.com/floegence/flowersec-examples

go 1.26.5

require (
	github.com/floegence/flowersec/flowersec-go v0.0.0
	github.com/gorilla/websocket v1.5.3
	github.com/hashicorp/yamux v0.1.2
)

require (
	github.com/libp2p/go-buffer-pool v0.0.2 // indirect
	github.com/libp2p/go-yamux/v5 v5.1.0 // indirect
)

replace github.com/floegence/flowersec/flowersec-go => ../flowersec-go
