module github.com/floegence/flowersec-examples

go 1.25.6

require (
	github.com/floegence/flowersec/flowersec-go v0.0.0
	github.com/gorilla/websocket v1.5.3
	github.com/hashicorp/yamux v0.1.2
)

replace github.com/floegence/flowersec/flowersec-go => ../flowersec-go
