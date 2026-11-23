package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v7"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	var input struct {
		Artifact string
		Root     []byte
		Origin   string
	}
	if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
		return err
	}
	artifact, err := flowersec.ParseArtifact([]byte(input.Artifact))
	if err != nil {
		return err
	}
	spent := 0
	lease, err := flowersec.NewArtifactLease(artifact, func(context.Context) error { spent++; return nil })
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(input.Root)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	session, err := flowersec.Connect(ctx, lease, flowersec.ConnectorOptions{TrustRoots: roots, Origin: input.Origin})
	if err != nil {
		return err
	}
	defer session.Close()
	if spent != 1 {
		return fmt.Errorf("unexpected spend count %d", spent)
	}
	stream, err := session.OpenStream(ctx, "quic-echo", flowersec.EmptyStreamMetadata())
	if err != nil {
		return err
	}
	if _, err := stream.Write([]byte("hello")); err != nil {
		return err
	}
	if err := stream.CloseWrite(); err != nil {
		return err
	}
	reply, err := io.ReadAll(io.LimitReader(stream, 64))
	if err != nil || string(reply) != "world" {
		return fmt.Errorf("stream response failed: %v", err)
	}
	channel, err := session.UnreliableMessages()
	if err != nil {
		return err
	}
	status, err := channel.Send(ctx, []byte("request"), flowersec.UnreliableSendOptions{ExpiresAt: time.Now().Add(5 * time.Second)})
	if err != nil || status != flowersec.UnreliableAccepted {
		return fmt.Errorf("datagram send %s: %v", status, err)
	}
	answer, err := channel.Receive(ctx)
	if err != nil || string(answer) != "response" {
		return fmt.Errorf("datagram response failed: %v", err)
	}
	return nil
}
