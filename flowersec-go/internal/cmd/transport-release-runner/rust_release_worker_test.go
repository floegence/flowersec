package main

import (
	"crypto/x509"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease"
)

func TestRustReleaseWorkerOwnsOnlyEdgeDirectRawQUIC(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		request networkWorkerRequest
		want    bool
	}{
		{name: "edge direct raw QUIC", request: networkWorkerRequest{Mode: networkModeDirect, Kind: carrier.KindQUIC, Plan: transportrelease.ProfilePlan{ID: "edge-v1"}}, want: true},
		{name: "clean direct raw QUIC", request: networkWorkerRequest{Mode: networkModeDirect, Kind: carrier.KindQUIC, Plan: transportrelease.ProfilePlan{ID: "clean-v1"}}},
		{name: "mobile direct raw QUIC", request: networkWorkerRequest{Mode: networkModeDirect, Kind: carrier.KindQUIC, Plan: transportrelease.ProfilePlan{ID: "mobile-v1"}}},
		{name: "edge direct WSS", request: networkWorkerRequest{Mode: networkModeDirect, Kind: carrier.KindWebSocket, Plan: transportrelease.ProfilePlan{ID: "edge-v1"}}},
		{name: "edge tunnel raw QUIC", request: networkWorkerRequest{Mode: networkModeTunnel, Kind: carrier.KindQUIC, Plan: transportrelease.ProfilePlan{ID: "edge-v1"}}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := useRustReleaseWorker(test.request); got != test.want {
				t.Fatalf("useRustReleaseWorker() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestRustPlanBindsMeasuredEdgeRecoveryBudgets(t *testing.T) {
	t.Parallel()
	plan, _, err := transportrelease.LoadReleasePlan("../../../../testdata/transport_v2/performance_manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	got := rustPlan(plan.Edge)
	if got.RequestOperationTimeoutMS != 24_000 || got.RequestPhaseTimeoutMS != 26_000 {
		t.Fatalf("edge RPC timeouts = %d/%dms, want 24000/26000ms", got.RequestOperationTimeoutMS, got.RequestPhaseTimeoutMS)
	}
	if got.BulkPhaseTimeoutMS != 57_000 {
		t.Fatalf("edge bulk timeout = %dms, want 57000ms", got.BulkPhaseTimeoutMS)
	}
	if got.CleanupTimeoutMS != 12_000 {
		t.Fatalf("edge cleanup timeout = %dms, want 12000ms", got.CleanupTimeoutMS)
	}
}

func TestRustReleaseCertificateUsesExactIPSANAndPKCS8(t *testing.T) {
	t.Parallel()
	address := netip.MustParseAddr("192.0.2.44")
	certificateDER, keyDER, err := newRustReleaseCertificate(address)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := certificate.VerifyHostname(address.String()); err != nil {
		t.Fatalf("verify IP SAN: %v", err)
	}
	if len(certificate.DNSNames) != 0 || len(certificate.IPAddresses) != 1 {
		t.Fatalf("certificate names = DNS %v IP %v", certificate.DNSNames, certificate.IPAddresses)
	}
	if _, err := x509.ParsePKCS8PrivateKey(keyDER); err != nil {
		t.Fatalf("parse PKCS#8 key: %v", err)
	}
}

func TestVerifiedRustReleaseRunnerRejectsRelativeAndSymlinkPaths(t *testing.T) {
	t.Setenv(rustReleaseRunnerEnvironment, "relative-runner")
	if _, err := verifiedRustReleaseRunner(); err == nil {
		t.Fatal("relative runner path was accepted")
	}
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runner := filepath.Join(directory, "runner")
	if err := os.WriteFile(runner, []byte("runner"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(rustReleaseRunnerEnvironment, runner)
	if got, err := verifiedRustReleaseRunner(); err != nil || got != runner {
		t.Fatalf("verified runner = %q, %v", got, err)
	}
	link := filepath.Join(directory, "runner-link")
	if err := os.Symlink(runner, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv(rustReleaseRunnerEnvironment, link)
	if _, err := verifiedRustReleaseRunner(); err == nil {
		t.Fatal("symlinked runner path was accepted")
	}
}

func TestMergeRustResourceSumsBothProductionProcesses(t *testing.T) {
	t.Parallel()
	client := rustResourceMeasurement{
		Start:  rustResourceSnapshot{AtUnixNS: 100, RSSBytes: 10, CPUNanoseconds: 20, AllocatedBytes: 30, OpenFDs: 2, RuntimeThreads: 3, Tasks: 4},
		Finish: rustResourceSnapshot{AtUnixNS: 300, RSSBytes: 40, CPUNanoseconds: 120, AllocatedBytes: 230, OpenFDs: 5, RuntimeThreads: 6, Tasks: 7},
	}
	server := rustResourceMeasurement{
		Start:  rustResourceSnapshot{AtUnixNS: 90, RSSBytes: 100, CPUNanoseconds: 200, AllocatedBytes: 300, OpenFDs: 20, RuntimeThreads: 30, Tasks: 40},
		Finish: rustResourceSnapshot{AtUnixNS: 310, RSSBytes: 400, CPUNanoseconds: 1200, AllocatedBytes: 2300, OpenFDs: 50, RuntimeThreads: 60, Tasks: 70},
	}
	measurement, err := mergeRustResource(client, server)
	if err != nil {
		t.Fatal(err)
	}
	if !measurement.StartedAt.Equal(time.Unix(0, 90).UTC()) || !measurement.FinishedAt.Equal(time.Unix(0, 310).UTC()) {
		t.Fatalf("measurement interval = %s..%s", measurement.StartedAt, measurement.FinishedAt)
	}
	if measurement.CPUNanoseconds != 1100 || measurement.AllocatedBytes != 2200 || measurement.Start.RSSBytes != 110 || measurement.Finish.RSSBytes != 440 {
		t.Fatalf("merged measurement = %+v", measurement)
	}
	if measurement.Finish.OpenFDs != 55 || measurement.Finish.Goroutines != 66 || measurement.Finish.Tasks != 77 {
		t.Fatalf("merged finish snapshot = %+v", measurement.Finish)
	}
}

func TestMergeRustBulkRequiresBothExactDirections(t *testing.T) {
	t.Parallel()
	makeDirection := func(phase, direction string, bytes int64, start int64) rustBulkPhaseDirection {
		return rustBulkPhaseDirection{
			Phase: phase, Direction: direction, Bytes: bytes, ScheduledAtUnixNS: start,
			StartedAtUnixNS: start, DurationNS: int64(time.Millisecond), PayloadSHA256: [32]byte{byte(bytes)},
		}
	}
	client := []rustBulkPhaseDirection{
		makeDirection("warmup", "client-to-server", 64, 100),
		makeDirection("score", "client-to-server", 128, 200),
	}
	server := []rustBulkPhaseDirection{
		makeDirection("warmup", "server-to-client", 64, 101),
		makeDirection("score", "server-to-client", 128, 201),
	}
	result, err := mergeRustBulk(client, server, 128)
	if err != nil {
		t.Fatal(err)
	}
	if result.BytesPerDirection != 128 || result.ActiveStreams != 2 || len(result.Directions) != 2 ||
		result.Directions[0].Direction != "client-to-server" || result.Directions[1].Direction != "server-to-client" {
		t.Fatalf("merged bulk = %+v", result)
	}
	if _, err := mergeRustBulk(client, server[:1], 128); err == nil {
		t.Fatal("incomplete server direction was accepted")
	}
}

func TestDecodeSingleJSONRejectsUnknownAndTrailingValues(t *testing.T) {
	t.Parallel()
	var result struct {
		Role string `json:"role"`
	}
	if err := decodeSingleJSON([]byte(`{"role":"client"}`), &result); err != nil || result.Role != "client" {
		t.Fatalf("decode exact JSON = %+v, %v", result, err)
	}
	if err := decodeSingleJSON([]byte(`{"role":"client","extra":true}`), &result); err == nil {
		t.Fatal("unknown field was accepted")
	}
	if err := decodeSingleJSON([]byte(`{"role":"client"} {"role":"server"}`), &result); err == nil {
		t.Fatal("trailing JSON value was accepted")
	}
	if _, err := json.Marshal(result); err != nil {
		t.Fatal(err)
	}
}
