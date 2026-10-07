package main

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

type directBridgeTestStream struct{ *net.TCPConn }

func (s directBridgeTestStream) Finish(ctx context.Context) error { return ctx.Err() }

func directBridgeTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	server, err := listener.AcceptTCP()
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close(); server.Close() })
	return client, server
}

// Cancellation must join both directions even after one FIN. The peer keeps
// its response direction open, so this catches a bridge that waits on EOF
// without retaining a cancellation path to the actual native connection.
func TestDirectClientBridgeJoinsCancellationAfterRequestFIN(t *testing.T) {
	application, ingress := directBridgeTCPPair(t)
	bridge, remote := directBridgeTCPPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- bridgeClientStream(ctx, directBridgeTestStream{bridge}, ingress) }()
	if _, err := application.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := application.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := remote.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(remote)
	if err != nil || string(payload) != "request" {
		t.Fatalf("request and original FIN were not forwarded: %q %v", payload, err)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancellation did not join both bridge tasks")
	}
}
func TestDirectClientBridgePreservesBidirectionalFIN(t *testing.T) {
	application, ingress := directBridgeTCPPair(t)
	bridge, remote := directBridgeTCPPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- bridgeClientStream(ctx, directBridgeTestStream{bridge}, ingress) }()
	if _, err := application.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := application.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := remote.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	request, err := io.ReadAll(remote)
	if err != nil || string(request) != "request" {
		t.Fatalf("upstream request: %q %v", request, err)
	}
	if _, err = remote.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	if err = remote.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err = application.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(application)
	if err != nil || string(response) != "response" {
		t.Fatalf("response after request FIN: %q %v", response, err)
	}
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("bridge did not finish both original directions")
	}
}
