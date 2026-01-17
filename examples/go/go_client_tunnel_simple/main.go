package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/floegence/flowersec/connect"
	controlv1 "github.com/floegence/flowersec/gen/flowersec/controlplane/v1"
	"github.com/floegence/flowersec/rpc"
)

func main() {
	var grantPath string
	var origin string
	flag.StringVar(&grantPath, "grant", "", "path to JSON-encoded ChannelInitGrant for role=client (default: stdin)")
	flag.StringVar(&origin, "origin", "", "explicit Origin header value (required)")
	flag.Parse()

	if origin == "" {
		log.Fatal("missing --origin")
	}

	grant, err := readGrantClient(grantPath)
	if err != nil {
		log.Fatal(err)
	}

	client, err := connect.ConnectTunnelClientRPC(context.Background(), grant, connect.TunnelClientOptions{
		ConnectTimeout:   10 * time.Second,
		HandshakeTimeout: 10 * time.Second,
		MaxRecordBytes:   1 << 20,
		Origin:           origin,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	notified := make(chan json.RawMessage, 1)
	unsub := client.RPC.OnNotify(2, func(payload json.RawMessage) {
		select {
		case notified <- payload:
		default:
		}
	})
	defer unsub()

	callCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	payload, rpcErr, err := client.RPC.Call(callCtx, 1, json.RawMessage(`{}`))
	if err != nil {
		log.Fatal(err)
	}
	if rpcErr != nil {
		log.Fatalf("rpc error: %+v", rpcErr)
	}
	fmt.Printf("rpc response: %s\n", string(payload))

	select {
	case p := <-notified:
		fmt.Printf("rpc notify: %s\n", string(p))
	case <-time.After(2 * time.Second):
		fmt.Println("rpc notify: timeout")
	}

	echoStream, err := client.Mux.OpenStream()
	if err != nil {
		log.Fatal(err)
	}
	defer echoStream.Close()
	if err := rpc.WriteStreamHello(echoStream, "echo"); err != nil {
		log.Fatal(err)
	}

	msg := []byte("hello over yamux stream: echo")
	if _, err := echoStream.Write(msg); err != nil {
		log.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(echoStream, buf); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("echo response: %q\n", string(buf))
}

func readGrantClient(path string) (*controlv1.ChannelInitGrant, error) {
	var r io.Reader
	if path == "" {
		r = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var wrap struct {
		GrantClient *controlv1.ChannelInitGrant `json:"grant_client"`
	}
	if err := json.Unmarshal(b, &wrap); err == nil && wrap.GrantClient != nil {
		if wrap.GrantClient.Role != controlv1.Role_client {
			return nil, fmt.Errorf("expected role=client, got %v", wrap.GrantClient.Role)
		}
		return wrap.GrantClient, nil
	}
	var g controlv1.ChannelInitGrant
	if err := json.Unmarshal(b, &g); err != nil {
		return nil, err
	}
	if g.Role != controlv1.Role_client {
		return nil, fmt.Errorf("expected role=client, got %v", g.Role)
	}
	return &g, nil
}
