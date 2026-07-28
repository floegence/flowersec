package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease/linuxnetlab"
)

const rustReleaseRunnerEnvironment = "FLOWERSEC_RUST_RELEASE_RUNNER"

type rustWorkloadPlan struct {
	ColdOperations              int   `json:"cold_operations"`
	ColdMaxInflight             int   `json:"cold_max_inflight"`
	ColdStartRatePerSecond      int   `json:"cold_start_rate_per_second"`
	ColdOperationTimeoutMS      int64 `json:"cold_operation_timeout_ms"`
	ColdPhaseTimeoutMS          int64 `json:"cold_phase_timeout_ms"`
	RequestOperations           int   `json:"request_operations"`
	RequestWorkers              int   `json:"request_workers"`
	RequestBytes                int   `json:"request_bytes"`
	RequestOperationTimeoutMS   int64 `json:"request_operation_timeout_ms"`
	RequestPhaseTimeoutMS       int64 `json:"request_phase_timeout_ms"`
	BulkWarmupBytesPerDirection int64 `json:"bulk_warmup_bytes_per_direction"`
	BulkScoreBytesPerDirection  int64 `json:"bulk_score_bytes_per_direction"`
	BulkPhaseTimeoutMS          int64 `json:"bulk_phase_timeout_ms"`
	CleanupTimeoutMS            int64 `json:"cleanup_timeout_ms"`
}

type rustServerConnection struct {
	ArtifactJSON string `json:"artifact_json"`
	BindAddress  string `json:"bind_address"`
}

type rustServerRequest struct {
	Role                   string                 `json:"role"`
	Connections            []rustServerConnection `json:"connections"`
	CertificateChainDERB64 []string               `json:"certificate_chain_der_b64"`
	PrivateKeyDERB64       string                 `json:"private_key_der_b64"`
	MaxInboundStreams      uint16                 `json:"max_inbound_streams"`
	AcceptTimeoutMS        int64                  `json:"accept_timeout_ms"`
	ReadyPath              string                 `json:"ready_path"`
	Plan                   rustWorkloadPlan       `json:"plan"`
}

type rustClientRequest struct {
	Role             string           `json:"role"`
	ArtifactsJSON    []string         `json:"artifacts_json"`
	TrustRootsDERB64 []string         `json:"trust_roots_der_b64"`
	ConnectTimeoutMS int64            `json:"connect_timeout_ms"`
	ControlDirectory string           `json:"control_directory,omitempty"`
	Plan             rustWorkloadPlan `json:"plan"`
}

type rustResourceSnapshot struct {
	AtUnixNS       int64  `json:"at_unix_ns"`
	RSSBytes       uint64 `json:"rss_bytes"`
	CPUNanoseconds uint64 `json:"cpu_nanoseconds"`
	AllocatedBytes uint64 `json:"allocated_bytes"`
	OpenFDs        int    `json:"open_fds"`
	RuntimeThreads int    `json:"runtime_threads"`
	Tasks          int    `json:"tasks"`
}

type rustResourceMeasurement struct {
	StartedAtUnixNS  int64                `json:"started_at_unix_ns"`
	FinishedAtUnixNS int64                `json:"finished_at_unix_ns"`
	CPUNanoseconds   uint64               `json:"cpu_nanoseconds"`
	AllocatedBytes   uint64               `json:"allocated_bytes"`
	Start            rustResourceSnapshot `json:"start"`
	Finish           rustResourceSnapshot `json:"finish"`
}

type rustPhaseMeasurement struct {
	Phase         string                  `json:"phase"`
	Resource      rustResourceMeasurement `json:"resource"`
	ActiveStreams int                     `json:"active_streams"`
}

type rustConnectOperation struct {
	Ordinal           int   `json:"ordinal"`
	ScheduledAtUnixNS int64 `json:"scheduled_at_unix_ns"`
	StartedAtUnixNS   int64 `json:"started_at_unix_ns"`
	DurationNS        int64 `json:"duration_ns"`
	CleanupDurationNS int64 `json:"cleanup_duration_ns"`
	CommitCount       int   `json:"commit_count"`
}

type rustOperation struct {
	Ordinal           int      `json:"ordinal"`
	ScheduledAtUnixNS int64    `json:"scheduled_at_unix_ns"`
	StartedAtUnixNS   int64    `json:"started_at_unix_ns"`
	DurationNS        int64    `json:"duration_ns"`
	InputBytes        int      `json:"input_bytes"`
	OutputBytes       int      `json:"output_bytes"`
	PayloadSHA256     [32]byte `json:"payload_sha256"`
}

type rustBulkPhaseDirection struct {
	Phase             string   `json:"phase"`
	Direction         string   `json:"direction"`
	ScheduledAtUnixNS int64    `json:"scheduled_at_unix_ns"`
	StartedAtUnixNS   int64    `json:"started_at_unix_ns"`
	DurationNS        int64    `json:"duration_ns"`
	Bytes             int64    `json:"bytes"`
	PayloadSHA256     [32]byte `json:"payload_sha256"`
}

type rustClientBulkResult struct {
	Outbound          []rustBulkPhaseDirection `json:"outbound"`
	BytesPerDirection int64                    `json:"bytes_per_direction"`
	ActiveStreams     int                      `json:"active_streams"`
}

type rustRoleResult struct {
	Role              string                   `json:"role"`
	Cold              []rustConnectOperation   `json:"cold"`
	RequestResponse   []rustOperation          `json:"request_response"`
	Bulk              rustClientBulkResult     `json:"bulk"`
	CleanupDurationNS int64                    `json:"cleanup_duration_ns"`
	Resource          rustResourceMeasurement  `json:"resource"`
	Phases            []rustPhaseMeasurement   `json:"phases"`
	OutboundBulk      []rustBulkPhaseDirection `json:"outbound_bulk"`
}

type rustRoleEvidence struct {
	Client rustRoleResult `json:"client"`
	Server rustRoleResult `json:"server"`
}

func runRustEndpointCarrier(ctx context.Context, request networkWorkerRequest, sampleKernel kernelEvidenceSampler) (baselineCarrierResult, error) {
	if request.Kind != carrier.KindQUIC || request.Mode != networkModeDirect {
		return baselineCarrierResult{}, errors.New("Rust release worker requires direct raw QUIC")
	}
	runner, err := verifiedRustReleaseRunner()
	if err != nil {
		return baselineCarrierResult{}, err
	}
	serverIP, err := netip.ParseAddr(request.ServerAddress)
	if err != nil {
		return baselineCarrierResult{}, fmt.Errorf("parse Rust server address: %w", err)
	}
	certificateDER, privateKeyDER, err := newRustReleaseCertificate(serverIP)
	if err != nil {
		return baselineCarrierResult{}, err
	}
	const maxInboundStreams uint16 = 128
	connections := make([]rustServerConnection, request.Plan.Cold.Operations+1)
	artifacts := make([]string, len(connections))
	for index := range connections {
		port := 43000 + index
		address := net.JoinHostPort(serverIP.String(), fmt.Sprint(port))
		artifact, err := transportrelease.NewRawQUICReleaseArtifactJSON("quic://"+address, maxInboundStreams)
		if err != nil {
			return baselineCarrierResult{}, err
		}
		artifacts[index] = string(artifact)
		connections[index] = rustServerConnection{ArtifactJSON: string(artifact), BindAddress: address}
	}
	workDirectory, err := os.MkdirTemp("", "flowersec-rust-release-")
	if err != nil {
		return baselineCarrierResult{}, err
	}
	defer os.RemoveAll(workDirectory)
	readyPath := filepath.Join(workDirectory, "server.ready")
	controlDirectory := ""
	if sampleKernel != nil {
		controlDirectory = filepath.Join(workDirectory, "phase-control")
		if err := os.Mkdir(controlDirectory, 0700); err != nil {
			return baselineCarrierResult{}, err
		}
	}
	plan := rustPlan(request.Plan)
	serverRequest := rustServerRequest{
		Role: "server", Connections: connections,
		CertificateChainDERB64: []string{base64.StdEncoding.EncodeToString(certificateDER)},
		PrivateKeyDERB64:       base64.StdEncoding.EncodeToString(privateKeyDER),
		MaxInboundStreams:      maxInboundStreams, AcceptTimeoutMS: int64(request.Plan.CellWatchdogMinutes) * 60_000,
		ReadyPath: readyPath, Plan: plan,
	}
	clientRequest := rustClientRequest{
		Role: "client", ArtifactsJSON: artifacts,
		TrustRootsDERB64: []string{base64.StdEncoding.EncodeToString(certificateDER)},
		ConnectTimeoutMS: int64(request.Plan.CellWatchdogMinutes) * 60_000,
		ControlDirectory: controlDirectory, Plan: plan,
	}
	serverJSON, err := json.Marshal(serverRequest)
	if err != nil {
		return baselineCarrierResult{}, err
	}
	clientJSON, err := json.Marshal(clientRequest)
	if err != nil {
		return baselineCarrierResult{}, err
	}

	processCtx, cancelProcesses := context.WithCancel(ctx)
	defer cancelProcesses()
	serverCommand := exec.CommandContext(processCtx, "/usr/bin/nsenter", "--net=/var/run/netns/"+request.ServerNamespace, "--", runner)
	serverCommand.Stdin = bytes.NewReader(serverJSON)
	var serverStdout, serverStderr bytes.Buffer
	serverCommand.Stdout, serverCommand.Stderr = &serverStdout, &serverStderr
	if err := serverCommand.Start(); err != nil {
		return baselineCarrierResult{}, fmt.Errorf("start Rust server: %w", err)
	}
	serverDone := make(chan error, 1)
	serverWatch := make(chan error, 1)
	go func() {
		err := serverCommand.Wait()
		serverWatch <- err
		serverDone <- err
	}()
	if err := waitForRustFile(processCtx, readyPath, serverWatch); err != nil {
		cancelProcesses()
		<-serverDone
		return baselineCarrierResult{}, fmt.Errorf("Rust server readiness: %w: %s", err, strings.TrimSpace(serverStderr.String()))
	}

	clientCommand := exec.CommandContext(processCtx, runner)
	clientCommand.Stdin = bytes.NewReader(clientJSON)
	var clientStdout, clientStderr bytes.Buffer
	clientCommand.Stdout, clientCommand.Stderr = &clientStdout, &clientStderr
	if err := clientCommand.Start(); err != nil {
		cancelProcesses()
		<-serverDone
		return baselineCarrierResult{}, fmt.Errorf("start Rust client: %w", err)
	}
	clientDone := make(chan error, 1)
	clientWatch := make(chan error, 1)
	go func() {
		err := clientCommand.Wait()
		clientWatch <- err
		clientDone <- err
	}()
	kernelSamples, monitorErr := monitorRustPhases(processCtx, controlDirectory, sampleKernel, clientWatch)
	if monitorErr != nil {
		cancelProcesses()
	}
	clientErr := <-clientDone
	serverErr := <-serverDone
	if monitorErr != nil || clientErr != nil || serverErr != nil {
		return baselineCarrierResult{}, fmt.Errorf("Rust workload failed: monitor=%v client=%v server=%v client_stderr=%s server_stderr=%s", monitorErr, clientErr, serverErr, strings.TrimSpace(clientStderr.String()), strings.TrimSpace(serverStderr.String()))
	}
	var clientResult, serverResult rustRoleResult
	if err := decodeSingleJSON(clientStdout.Bytes(), &clientResult); err != nil {
		return baselineCarrierResult{}, fmt.Errorf("decode Rust client: %w", err)
	}
	if err := decodeSingleJSON(serverStdout.Bytes(), &serverResult); err != nil {
		return baselineCarrierResult{}, fmt.Errorf("decode Rust server: %w", err)
	}
	if clientResult.Role != "client" || serverResult.Role != "server" {
		return baselineCarrierResult{}, errors.New("Rust workers returned the wrong roles")
	}
	return mergeRustRoleResults(request.Plan, clientResult, serverResult, kernelSamples)
}

func rustPlan(plan transportrelease.ProfilePlan) rustWorkloadPlan {
	return rustWorkloadPlan{
		ColdOperations: plan.Cold.Operations, ColdMaxInflight: plan.Cold.MaxInflight,
		ColdStartRatePerSecond: plan.Cold.StartRatePerSecond,
		ColdOperationTimeoutMS: int64(plan.Cold.OperationDeadlineSeconds) * 1000,
		ColdPhaseTimeoutMS:     int64(plan.Cold.PhaseDeadlineSeconds) * 1000,
		RequestOperations:      plan.RPC.Operations, RequestWorkers: plan.RPC.Workers, RequestBytes: plan.RPC.RequestBytes,
		RequestOperationTimeoutMS:   int64(plan.RPC.OperationDeadlineSeconds) * 1000,
		RequestPhaseTimeoutMS:       int64(plan.RPC.PhaseDeadlineSeconds) * 1000,
		BulkWarmupBytesPerDirection: plan.Bulk.WarmupBytesPerDirection,
		BulkScoreBytesPerDirection:  plan.Bulk.ScoreBytesPerDirection,
		BulkPhaseTimeoutMS:          int64(plan.Bulk.PhaseDeadlineSeconds) * 1000,
		CleanupTimeoutMS:            int64(plan.CleanupDeadlineSeconds) * 1000,
	}
}

func verifiedRustReleaseRunner() (string, error) {
	path := os.Getenv(rustReleaseRunnerEnvironment)
	if !filepath.IsAbs(path) {
		return "", errors.New("Rust release runner path must be absolute")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return "", errors.New("Rust release runner path must resolve without symlinks")
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return "", errors.New("Rust release runner is not an executable regular file")
	}
	return path, nil
}

func newRustReleaseCertificate(serverIP netip.Addr) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := cryptorand.Int(cryptorand.Reader, serialLimit)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "flowersec-release"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IPAddresses: []net.IP{net.IP(serverIP.AsSlice())},
	}
	certificate, err := x509.CreateCertificate(cryptorand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	privateKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return certificate, privateKey, nil
}

func waitForRustFile(ctx context.Context, path string, processDone <-chan error) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		info, err := os.Lstat(path)
		if err == nil {
			if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
				return errors.New("Rust control file is not regular")
			}
			return nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case err := <-processDone:
			return fmt.Errorf("Rust process exited before control file: %w", err)
		case <-ticker.C:
		}
	}
}

func monitorRustPhases(ctx context.Context, directory string, sample kernelEvidenceSampler, processDone <-chan error) ([]linuxnetlab.KernelFaultEvidence, error) {
	if sample == nil {
		return nil, nil
	}
	boundaries := []string{"cold-start", "cold-finish", "rpc-start", "rpc-finish", "bulk-start", "bulk-finish", "cleanup-start", "cleanup-finish"}
	result := make([]linuxnetlab.KernelFaultEvidence, 0, len(boundaries))
	for _, boundary := range boundaries {
		path := filepath.Join(directory, boundary)
		if err := waitForRustFile(ctx, path, processDone); err != nil {
			return nil, err
		}
		snapshot, err := sample(ctx)
		if err != nil {
			return nil, err
		}
		acknowledgement := path + ".ack"
		file, err := os.OpenFile(acknowledgement, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return nil, err
		}
		_, writeErr := file.WriteString("ack\n")
		closeErr := file.Close()
		if err := errors.Join(writeErr, closeErr); err != nil {
			return nil, err
		}
		result = append(result, snapshot)
	}
	return result, nil
}

func decodeSingleJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("Rust worker emitted trailing JSON")
		}
		return err
	}
	return nil
}

func mergeRustRoleResults(plan transportrelease.ProfilePlan, client, server rustRoleResult, kernel []linuxnetlab.KernelFaultEvidence) (baselineCarrierResult, error) {
	if len(client.Cold) != plan.Cold.Operations || len(client.RequestResponse) != plan.RPC.Operations || len(client.Phases) != 4 || len(server.Phases) != 4 ||
		len(client.Bulk.Outbound) != 2 || len(server.OutboundBulk) != 2 || client.Bulk.BytesPerDirection != plan.Bulk.ScoreBytesPerDirection || client.Bulk.ActiveStreams != 2 {
		return baselineCarrierResult{}, errors.New("Rust role results are incomplete")
	}
	cold := make([]transportrelease.ConnectOperation, len(client.Cold))
	for index, operation := range client.Cold {
		cold[index] = transportrelease.ConnectOperation{
			Ordinal: operation.Ordinal, ScheduledAt: unixNSTime(operation.ScheduledAtUnixNS), StartedAt: unixNSTime(operation.StartedAtUnixNS),
			Duration: time.Duration(operation.DurationNS), CleanupDuration: time.Duration(operation.CleanupDurationNS),
			StartedCandidate: "direct-raw-quic", WinnerCandidate: "direct-raw-quic",
			CommitCount: operation.CommitCount, CredentialWrites: operation.CommitCount,
		}
	}
	rpc := make([]transportrelease.Operation, len(client.RequestResponse))
	for index, operation := range client.RequestResponse {
		rpc[index] = transportrelease.Operation{
			Ordinal: operation.Ordinal, ScheduledAt: unixNSTime(operation.ScheduledAtUnixNS), StartedAt: unixNSTime(operation.StartedAtUnixNS),
			Duration: time.Duration(operation.DurationNS), InputBytes: operation.InputBytes, OutputBytes: operation.OutputBytes, PayloadSHA256: operation.PayloadSHA256,
		}
	}
	bulk, err := mergeRustBulk(client.Bulk.Outbound, server.OutboundBulk, plan.Bulk.ScoreBytesPerDirection)
	if err != nil {
		return baselineCarrierResult{}, err
	}
	resource, err := mergeRustResource(client.Resource, server.Resource)
	if err != nil {
		return baselineCarrierResult{}, err
	}
	phases := make([]baselinePhaseMeasurement, 4)
	for index, phase := range []string{"cold", "rpc", "bulk", "cleanup"} {
		if client.Phases[index].Phase != phase || server.Phases[index].Phase != phase {
			return baselineCarrierResult{}, errors.New("Rust phase order is invalid")
		}
		measurement, err := mergeRustResource(client.Phases[index].Resource, server.Phases[index].Resource)
		if err != nil {
			return baselineCarrierResult{}, err
		}
		active := 0
		if phase == "bulk" {
			active = 2
		}
		phases[index] = baselinePhaseMeasurement{Phase: phase, Resource: measurement, ActiveStreams: active}
		if len(kernel) == 8 {
			phases[index].KernelStart = &kernel[index*2]
			phases[index].KernelFinish = &kernel[index*2+1]
		}
	}
	return baselineCarrierResult{
		Carrier: string(carrier.KindQUIC), Cold: cold, RPC: rpc, Bulk: bulk,
		CleanupDuration: time.Duration(client.CleanupDurationNS), Resource: resource, Phases: phases,
		RustRoles: &rustRoleEvidence{Client: client, Server: server},
	}, nil
}

func mergeRustBulk(client, server []rustBulkPhaseDirection, scoreBytes int64) (transportrelease.BulkResult, error) {
	all := append(append([]rustBulkPhaseDirection(nil), client...), server...)
	byKey := make(map[string]rustBulkPhaseDirection, 4)
	for _, direction := range all {
		byKey[direction.Direction+"/"+direction.Phase] = direction
	}
	result := transportrelease.BulkResult{BytesPerDirection: scoreBytes, ActiveStreams: 2}
	for _, name := range []string{"client-to-server", "server-to-client"} {
		warmup, warmupOK := byKey[name+"/warmup"]
		score, scoreOK := byKey[name+"/score"]
		if !warmupOK || !scoreOK || warmup.Bytes <= 0 || score.Bytes != scoreBytes {
			return transportrelease.BulkResult{}, errors.New("Rust bulk direction evidence is incomplete")
		}
		converted := transportrelease.BulkDirection{Direction: name, Warmup: convertRustBulkDirection(warmup), Score: convertRustBulkDirection(score)}
		result.Directions = append(result.Directions, converted)
		if result.StartedAt.IsZero() || converted.Score.StartedAt.Before(result.StartedAt) {
			result.StartedAt = converted.Score.StartedAt
		}
		result.Duration = max(result.Duration, converted.Score.Duration)
	}
	return result, nil
}

func convertRustBulkDirection(value rustBulkPhaseDirection) transportrelease.BulkPhaseDirection {
	return transportrelease.BulkPhaseDirection{
		Direction: value.Direction, ScheduledAt: unixNSTime(value.ScheduledAtUnixNS), StartedAt: unixNSTime(value.StartedAtUnixNS),
		Duration: time.Duration(value.DurationNS), Bytes: value.Bytes, PayloadSHA256: value.PayloadSHA256,
	}
}

func mergeRustResource(client, server rustResourceMeasurement) (transportrelease.ResourceMeasurement, error) {
	start, err := mergeRustSnapshot(client.Start, server.Start, true)
	if err != nil {
		return transportrelease.ResourceMeasurement{}, err
	}
	finish, err := mergeRustSnapshot(client.Finish, server.Finish, false)
	if err != nil {
		return transportrelease.ResourceMeasurement{}, err
	}
	return transportrelease.CompleteResourceMeasurement(start, finish)
}

func mergeRustSnapshot(client, server rustResourceSnapshot, start bool) (transportrelease.ResourceSnapshot, error) {
	at := max(client.AtUnixNS, server.AtUnixNS)
	if start {
		at = min(client.AtUnixNS, server.AtUnixNS)
	}
	rss, ok := checkedAdd(client.RSSBytes, server.RSSBytes)
	if !ok {
		return transportrelease.ResourceSnapshot{}, errors.New("Rust RSS counter overflow")
	}
	cpu, ok := checkedAdd(client.CPUNanoseconds, server.CPUNanoseconds)
	if !ok {
		return transportrelease.ResourceSnapshot{}, errors.New("Rust CPU counter overflow")
	}
	allocated, ok := checkedAdd(client.AllocatedBytes, server.AllocatedBytes)
	if !ok {
		return transportrelease.ResourceSnapshot{}, errors.New("Rust allocation counter overflow")
	}
	return transportrelease.ResourceSnapshot{
		At: unixNSTime(at), RSSBytes: rss, CPUNanoseconds: cpu, AllocatedBytes: allocated,
		OpenFDs: client.OpenFDs + server.OpenFDs, Goroutines: client.RuntimeThreads + server.RuntimeThreads, Tasks: client.Tasks + server.Tasks,
	}, nil
}

func checkedAdd(left, right uint64) (uint64, bool) {
	result := left + right
	return result, result >= left
}

func unixNSTime(value int64) time.Time {
	return time.Unix(0, value).UTC()
}
