package main

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
)

// The capacity driver supplies a private socket independent of issuance stdin.
func startCapacityMetrics() (func() error, error) {
	fd, enabled := os.LookupEnv("FLOWERSEC_V5_ISSUER_METRICS_FD")
	if !enabled {
		return func() error { return nil }, nil
	}
	if fd != "3" {
		return nil, errors.New("expected inherited metrics socket on fd 3")
	}
	file := os.NewFile(3, "capacity metrics")
	conn, err := net.FileConn(file)
	_ = file.Close()
	if err != nil {
		return nil, errors.New("invalid inherited metrics socket")
	}
	done := make(chan error, 1)
	go func() {
		done <- serveMetrics(conn)
	}()
	return func() error {
		_ = conn.Close()
		err := <-done
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	}, nil
}

func serveMetrics(conn net.Conn) error {
	scan := bufio.NewScanner(conn)
	scan.Buffer(make([]byte, 64), 64)
	for scan.Scan() {
		if scan.Text() != "goroutines" {
			return errors.New("unknown capacity metric")
		}
		if _, err := fmt.Fprintln(conn, runtime.NumGoroutine()); err != nil {
			return err
		}
	}
	return scan.Err()
}
