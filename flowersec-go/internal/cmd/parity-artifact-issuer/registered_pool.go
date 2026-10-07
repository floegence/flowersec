package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/interopharness"
)

// The inherited private pipe is fixed before issuance. It carries exactly one
// original capture and one original winner continuation, with no query/replay.
func exchangeOriginalOwner(ctx context.Context, reader *bufio.Reader, message any, replyType string) error {
	wire, err := json.Marshal(message)
	if err != nil {
		return err
	}
	defer clear(wire)
	if len(wire) == 0 || len(wire) > 1<<20 {
		return errors.New("original relay control exceeds its envelope")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	digest := sha256.Sum256(wire)
	line := make([]byte, len(wire)+1)
	defer clear(line)
	copy(line, wire)
	line[len(wire)] = '\n'
	n, err := os.Stdout.Write(line)
	if err != nil {
		return err
	}
	if n != len(line) {
		return io.ErrShortWrite
	}
	acknowledgement, err := readOriginalControl(ctx, reader, 1024)
	if err != nil {
		return err
	}
	defer clear(acknowledgement)
	var ack struct {
		Type   string `json:"type"`
		Digest []byte `json:"digest"`
	}
	decoder := json.NewDecoder(bytes.NewReader(acknowledgement))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&ack); err != nil {
		return err
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF || ack.Type != replyType || !bytes.Equal(ack.Digest, digest[:]) {
		return errors.New("original relay acknowledgement differs from its one-shot invocation")
	}
	return ctx.Err()
}

func runRegisteredPoolOriginalOwner(ctx context.Context, reporter *interopharness.Reporter, reader *bufio.Reader, input request) error {
	if input.Mode != "tunnel" || !input.Persist || !input.RelayOwnerHandoff || input.RelayAddresses != nil || input.EndpointAddresses != nil || !filepath.IsAbs(input.DeploymentPath) || len(input.DeploymentPath) > 4096 {
		return errors.New("registered pool requires its one independently installed original relay owner")
	}
	file, err := os.Open(input.DeploymentPath)
	if err != nil {
		return err
	}
	wire, readErr := io.ReadAll(io.LimitReader(file, 4194305))
	err = errors.Join(readErr, file.Close())
	defer clear(wire)
	if err != nil {
		return err
	}
	if len(wire) == 0 || len(wire) > 4194304 {
		return errors.New("registered pool deployment exceeds its bound")
	}
	var installed interopharness.RegisteredRelayDeployment
	// Reporter cleanup retires the borrowed original key material after the
	// control authority and source service have actually joined.
	reporter.Cleanup(installed.ReleaseOwnedPrivateMaterial)
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&installed); err != nil {
		return err
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF || installed.LiveControl != nil || installed.RemoteRelay != nil || input.Origin != installed.Origin {
		return errors.New("registered pool installation differs from the original request")
	}
	listeners := [2]bool{false, true}
	if input.EndpointListeners != nil {
		listeners = *input.EndpointListeners
	}
	winnerDone := make(chan error, 1)
	original := interopharness.RegisteredPoolOriginalOwner{
		Capture: func(call context.Context, relay *interopharness.PoolRelay) error {
			handoff, err := originalTunnelResponse(input, relay, true)
			if err != nil {
				return err
			}
			defer clearOriginalResponse(&handoff)
			return exchangeOriginalOwner(call, reader, handoff, "original-relay-captured")
		},
		MatchWinner: func(call context.Context, lease, projection []byte, guard func() error) (err error) {
			defer func() { winnerDone <- err }()
			if err = guard(); err != nil {
				return err
			}
			message := struct {
				Type       string `json:"type"`
				Lease      []byte `json:"lease"`
				Projection []byte `json:"projection"`
			}{
				"original-winner-continue", lease, projection,
			}
			if err = exchangeOriginalOwner(call, reader, message, "original-winner-matched"); err != nil {
				return err
			}
			return guard()
		},
	}
	_, err = interopharness.NewRegisteredPoolRelayForOriginalOwner(ctx, reporter, &installed,
		[2]string{input.Carrier, input.ServerCarrier}, listeners, func(endpoint, profile string) error {
			return json.NewEncoder(os.Stdout).Encode(map[string]any{
				"type": "relay-prepared", "runtime": "rust", "wire_revision": 4, "path": "tunnel",
				"source": "preauthorized_pool", "profile": profile, "carrier": input.Carrier,
				"server_carrier": input.ServerCarrier, "control_endpoint": endpoint,
			})
		}, original)
	if err != nil {
		return err
	}
	// The original continuation exclusively owns stdin until its single reply;
	// a shutdown reader must never race it for that reply.
	timer := time.NewTimer(30 * time.Minute)
	defer timer.Stop()
	select {
	case err = <-winnerDone:
		if err != nil {
			return err
		}
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return errors.New("original relay winner continuation expired")
	}
	return waitForShutdown(reader, 30*time.Minute)
}
