//go:build linux

package main

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease/linuxnetlab"
)

func TestRustReleaseWorkerProductionLoopback(t *testing.T) {
	if os.Getenv("FLOWERSEC_RUST_RELEASE_INTEGRATION") != "1" {
		t.Skip("set FLOWERSEC_RUST_RELEASE_INTEGRATION=1 on the audited privileged Linux runner")
	}
	config, err := linuxnetlab.ConfigForCell("rust-edge02-loopback", os.Getpid()%9999+1, 1500, linuxnetlab.FrozenFirewall)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	lab, err := linuxnetlab.Open(ctx, linuxnetlab.ExecRunner{}, config)
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

	plan := transportrelease.ProfilePlan{
		ID: "edge-v1",
		Cold: transportrelease.ColdPlan{
			Operations: 1, MaxInflight: 1, StartRatePerSecond: 10,
			OperationDeadlineSeconds: 10, PhaseDeadlineSeconds: 20,
		},
		RPC: transportrelease.RPCPlan{
			Operations: 2, Workers: 1, RequestBytes: 32, ResponseBytes: 32,
			OperationDeadlineSeconds: 10, PhaseDeadlineSeconds: 20,
		},
		Bulk: transportrelease.BulkPlan{
			WarmupBytesPerDirection: 1024, ScoreBytesPerDirection: 4096,
			PhaseDeadlineSeconds: 20,
		},
		CleanupDeadlineSeconds: 10,
		CellWatchdogMinutes:    1,
	}
	request := networkWorkerRequest{
		Mode: networkModeDirect, Kind: carrier.KindQUIC, Plan: plan,
		ClientNamespace: config.ClientNamespace, ServerNamespace: config.ServerNamespace,
		ServerAddress: config.ServerAddress.Addr().String(),
	}
	var result baselineCarrierResult
	if err := linuxnetlab.InNamespace(config.ClientNamespace, func() error {
		var runErr error
		result, runErr = runRustEndpointCarrier(ctx, request, nil)
		return runErr
	}); err != nil {
		t.Fatal(err)
	}
	if result.Carrier != string(carrier.KindQUIC) || len(result.Cold) != 1 || len(result.RPC) != 2 {
		t.Fatalf("production loopback result is incomplete: %+v", result)
	}
	if result.Bulk.BytesPerDirection != 4096 || len(result.Bulk.Directions) != 2 || result.RustRoles == nil {
		t.Fatalf("production loopback bulk evidence is incomplete: %+v", result)
	}
	if result.CleanupDuration <= 0 || result.Resource.FinishedAt.Before(result.Resource.StartedAt) {
		t.Fatalf("production loopback cleanup/resource evidence is invalid: %+v", result)
	}
}
