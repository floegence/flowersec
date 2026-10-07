// browser-batch-peer is the explicit original Go engineering profile caller.
// Its host plan is separate from the browser's acquired signed material. It
// performs no qualification, history recovery, source retry or SDK fallback.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/transporttest"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/transporttest/browserworkload"
)

type originalProfile struct {
	ID                     string                    `json:"id"`
	Cold                   transporttest.ColdPlan    `json:"cold"`
	RPC                    transporttest.RPCPlan     `json:"rpc"`
	Bulk                   transporttest.BulkPlan    `json:"bulk"`
	Network                transporttest.NetworkPlan `json:"network"`
	Fault                  transporttest.FaultPlan   `json:"fault"`
	CleanupDeadlineSeconds int                       `json:"cleanup_deadline_seconds"`
	CellWatchdogMinutes    int                       `json:"cell_watchdog_minutes"`
}

func (p originalProfile) capture() transporttest.ProfilePlan {
	return transporttest.ProfilePlan{ID: p.ID, Cold: p.Cold, RPC: p.RPC, Bulk: p.Bulk, Network: p.Network, Fault: p.Fault, CleanupDeadlineSeconds: p.CleanupDeadlineSeconds, CellWatchdogMinutes: p.CellWatchdogMinutes}
}

type originalPlan struct {
	SchemaVersion          int             `json:"schema_version"`
	Topology               string          `json:"topology"`
	RunNumber              int             `json:"run_number"`
	Profile                originalProfile `json:"profile"`
	ColdDiagnostic         bool            `json:"cold_diagnostic"`
	SourceRoot             string          `json:"source_root"`
	Node                   string          `json:"node"`
	ServerAddress          string          `json:"server_address"`
	ClientNamespace        string          `json:"client_namespace"`
	ServerNamespace        string          `json:"server_namespace"`
	OutputDirectory        string          `json:"output_directory"`
	NativeInstallationPath string          `json:"native_installation_path"`
}

func run() error {
	if os.Getenv("FLOWERSEC_BROWSER_BATCH_TEST_ONLY") != "1" {
		return errors.New("original browser batch peer is test-only")
	}
	wire, err := io.ReadAll(io.LimitReader(os.Stdin, 65537))
	if err != nil {
		return err
	}
	defer clear(wire)
	if len(wire) == 0 || len(wire) > 65536 {
		return errors.New("original browser batch plan exceeds its finite bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var plan originalPlan
	if err = decoder.Decode(&plan); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF || plan.SchemaVersion != 1 {
		return errors.New("invalid original browser batch plan")
	}
	if plan.Profile.CellWatchdogMinutes < 1 || plan.Profile.CellWatchdogMinutes > 14 {
		return errors.New("original browser batch requires a finite original lifetime")
	}
	signals, cancelSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancelSignals()
	ctx, cancel := context.WithTimeout(signals, time.Duration(plan.Profile.CellWatchdogMinutes)*time.Minute)
	defer cancel()
	result, err := browserworkload.Run(ctx, browserworkload.Config{Topology: plan.Topology, RunNumber: plan.RunNumber, Profile: plan.Profile.capture(), ColdDiagnostic: plan.ColdDiagnostic, SourceRoot: plan.SourceRoot, Node: plan.Node, ServerAddress: plan.ServerAddress, ClientNamespace: plan.ClientNamespace, ServerNamespace: plan.ServerNamespace, OutputDirectory: plan.OutputDirectory, NativeInstallationPath: plan.NativeInstallationPath})
	if err != nil {
		return err
	}
	defer clear(result)
	output := append(result, '\n')
	written, err := os.Stdout.Write(output)
	if err == nil && written != len(output) {
		err = io.ErrShortWrite
	}
	return err
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
