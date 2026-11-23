//go:build flowersec_capacity

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strings"

	"github.com/floegence/flowersec/flowersec-go/v7/internal/tunnelv3"
)

func (runtime *runtimeServer) serveWithCapacityInventory(ctx context.Context) error {
	fd, enabled := os.LookupEnv("FLOWERSEC_CAPACITY_RELAY_INVENTORY_FD")
	if !enabled {
		return runtime.Serve(ctx)
	}
	if fd != "4" {
		return errors.New("invalid private relay observation descriptor")
	}
	stop, err := startCapacityRelayInventory(runtime.coordinator)
	if err != nil {
		return err
	}
	defer stop()
	return runtime.Serve(ctx)
}

func startCapacityRelayInventory(coordinator *tunnelv3.Coordinator) (func(), error) {
	file := os.NewFile(4, "relay inventory")
	conn, err := net.FileConn(file)
	_ = file.Close()
	if err != nil {
		return nil, err
	}
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		defer conn.Close()
		scan := bufio.NewScanner(conn)
		scan.Buffer(make([]byte, 128), 512)
		replies := json.NewEncoder(conn)
		var watched string
		var done <-chan struct{}
		for scan.Scan() {
			command, channel, ok := strings.Cut(scan.Text(), " ")
			if !ok || channel == "" || len(channel) > 128 {
				return
			}
			groups, active, pending, current, unique := coordinator.CapacityObservation(channel)
			if !unique {
				return
			}
			switch command {
			case "watch":
				if done != nil || current == nil {
					return
				}
				watched, done = channel, current
			case "retired":
				if done == nil || watched != channel {
					return
				}
			case "inspect":
			default:
				return
			}
			finished := false
			if watched == channel {
				select {
				case <-done:
					finished = true
				default:
				}
			}
			if err := replies.Encode(map[string]any{"channel": channel, "groups": groups, "active": active, "pending": pending, "present": current != nil, "finished": finished}); err != nil {
				return
			}
			if command == "retired" && finished && current == nil {
				watched, done = "", nil
			}
		}
	}()
	return func() { _ = conn.Close(); <-joined }, nil
}
