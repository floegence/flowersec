//go:build linux

package linuxnetlab

import (
	"context"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

func TestPrivilegedGoSocketsTraverseNamespaces(t *testing.T) {
	if os.Getenv("FLOWERSEC_LINUX_NETLAB_INTEGRATION") != "1" {
		t.Skip("set FLOWERSEC_LINUX_NETLAB_INTEGRATION=1 on the audited privileged Linux runner")
	}
	config, err := ConfigForCell("go-sockets", os.Getpid()%9999+1, 1500, FrozenFirewall)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	lab, err := Open(ctx, ExecRunner{}, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		if err := lab.Close(cleanupCtx); err != nil {
			t.Error(err)
		}
	})

	var listener net.Listener
	if err := InNamespace(config.ServerNamespace, func() error {
		var listenErr error
		listener, listenErr = net.Listen("tcp4", net.JoinHostPort(config.ServerAddress.Addr().String(), "0"))
		return listenErr
	}); err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer connection.Close()
		request := make([]byte, 4)
		if _, err := io.ReadFull(connection, request); err != nil {
			serverDone <- err
			return
		}
		_, writeErr := connection.Write([]byte("pong"))
		serverDone <- writeErr
	}()
	if err := InNamespace(config.ClientNamespace, func() error {
		connection, dialErr := net.DialTimeout("tcp4", listener.Addr().String(), 5*time.Second)
		if dialErr != nil {
			return dialErr
		}
		defer connection.Close()
		if _, err := connection.Write([]byte("ping")); err != nil {
			return err
		}
		response := make([]byte, 4)
		_, err := io.ReadFull(connection, response)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}
