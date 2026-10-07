package browserworkload

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/interopharness"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/transporttest"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/transporttest/linuxnetlab"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/transporttest/tunnelworkload"
)

// Config is supplied by the original engineering profile caller. It is captured
// once before source startup; an HTTP acquisition never selects policy, native
// qualification, deadlines, output/history paths, concurrency or phase order.
// Existing original namespaces/packet-fault setup remains the caller's owner.
type Config struct {
	Topology               string
	RunNumber              int
	Profile                transporttest.ProfilePlan
	ColdDiagnostic         bool
	SourceRoot             string
	Node                   string
	ServerAddress          string
	ClientNamespace        string
	ServerNamespace        string
	OutputDirectory        string
	NativeInstallationPath string
}
type boundedOutput struct {
	bytes.Buffer
	maximum int
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	if len(p) > b.maximum-b.Len() {
		return 0, errors.New("browser process output exceeds its declared bound")
	}
	return b.Buffer.Write(p)
}

func validateConfig(c Config) error {
	if runtime.GOOS != "linux" || c.Topology != "browser_webtransport" && c.Topology != string(tunnelworkload.BrowserTunnelWTWSS) && c.Topology != string(tunnelworkload.BrowserTunnelWTQUIC) {
		return errors.New("original browser batch requires an explicit supported Linux forced topology")
	}
	if c.RunNumber < 1 || c.RunNumber > 1000000 || !filepath.IsAbs(c.SourceRoot) || !filepath.IsAbs(c.Node) || !filepath.IsAbs(c.OutputDirectory) || !filepath.IsAbs(c.NativeInstallationPath) || !validNamespace(c.ClientNamespace) || !validNamespace(c.ServerNamespace) || c.ClientNamespace == c.ServerNamespace {
		return errors.New("complete original browser run installation is required")
	}
	address, err := netip.ParseAddr(c.ServerAddress)
	if err != nil || !address.Is4() || address.IsUnspecified() || address.IsMulticast() {
		return errors.New("original browser run requires one explicit IPv4 listener")
	}
	p := c.Profile
	if p.ID == "" || len(p.ID) > 128 || p.Cold.Operations < 1 || p.Cold.Operations > 999 || p.Cold.MaxInflight < 1 || p.Cold.MaxInflight > 128 || p.Cold.MaxInflight > p.Cold.Operations || p.Cold.StartRatePerSecond < 1 || p.Cold.StartRatePerSecond > 1000000 || p.Cold.Retries != 0 || p.Cold.OperationDeadlineSeconds < 1 || p.Cold.OperationDeadlineSeconds > 90 || p.Cold.PhaseDeadlineSeconds < p.Cold.OperationDeadlineSeconds || p.Cold.PhaseDeadlineSeconds > 840 || p.CleanupDeadlineSeconds < 1 || p.CleanupDeadlineSeconds > 90 || p.CellWatchdogMinutes < 1 || p.CellWatchdogMinutes > 14 {
		return errors.New("original browser run requires its finite frozen cold profile without retries")
	}
	if p.RPC.Operations < 1 || p.RPC.Operations > 1000000 || p.RPC.Workers < 1 || p.RPC.Workers > 32 || p.RPC.Workers > p.RPC.Operations || p.RPC.Retries != 0 || p.RPC.RequestBytes < 2 || p.RPC.RequestBytes > 1<<20 || p.RPC.ResponseBytes != p.RPC.RequestBytes || p.RPC.OperationDeadlineSeconds < 1 || p.RPC.OperationDeadlineSeconds > 90 || p.RPC.PhaseDeadlineSeconds < p.RPC.OperationDeadlineSeconds || p.RPC.PhaseDeadlineSeconds > 840 || p.Bulk.WarmupBytesPerDirection < 1 || p.Bulk.WarmupBytesPerDirection > 1<<40 || p.Bulk.ScoreBytesPerDirection < 1 || p.Bulk.ScoreBytesPerDirection > 1<<40 || p.Bulk.PhaseDeadlineSeconds < 1 || p.Bulk.PhaseDeadlineSeconds > 840 {
		return errors.New("original browser run requires its finite frozen RPC/bulk profile")
	}
	phaseSeconds := p.Cold.PhaseDeadlineSeconds + p.Cold.OperationDeadlineSeconds + p.CleanupDeadlineSeconds
	if !c.ColdDiagnostic {
		phaseSeconds += p.RPC.PhaseDeadlineSeconds + p.Bulk.PhaseDeadlineSeconds + p.CleanupDeadlineSeconds
	}
	if phaseSeconds > p.CellWatchdogMinutes*60 {
		return errors.New("original browser phase bounds exceed the installed cell lifetime")
	}
	root, err := filepath.EvalSymlinks(c.SourceRoot)
	if err != nil {
		return errors.New("original browser source directory is unavailable")
	}
	output, err := filepath.EvalSymlinks(c.OutputDirectory)
	if err != nil {
		return errors.New("original browser output directory is unavailable")
	}
	native, err := filepath.EvalSymlinks(c.NativeInstallationPath)
	if err != nil {
		return errors.New("independent browser native installation is unavailable")
	}
	for _, forbidden := range []string{root, os.TempDir(), "/tmp", "/private/tmp"} {
		for _, path := range []string{output, native} {
			relative, err := filepath.Rel(forbidden, path)
			if err == nil && relative != ".." && !filepath.IsAbs(relative) && !strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
				return errors.New("browser history, output, and native installation must be outside the repository and system temporary roots")
			}
		}
	}
	return nil
}

func validNamespace(value string) bool {
	if len(value) < 1 || len(value) > 63 {
		return false
	}
	for index, character := range []byte(value) {
		alpha := character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9'
		if !alpha && (index == 0 || character != '_' && character != '-' && character != '.') {
			return false
		}
	}
	return true
}

type directArtifact struct {
	*transporttest.ProductDirectBrowserArtifact
}

func (a *directArtifact) Start(ctx context.Context) error { return ctx.Err() }

// Run performs the original forced batch acquisition/connection/application
// lifecycle. It installs independent host history before browser startup, feeds
// the existing TS runner exact acquisition bytes, and joins actual native and
// workload owners before returning. Failed runs never reissue or replay a batch.
func Run(ctx context.Context, c Config) (result json.RawMessage, err error) {
	if ctx == nil {
		return nil, errors.New("original browser run context is required")
	}
	if err = validateConfig(c); err != nil {
		return nil, err
	}
	installed, err := interopharness.ReadBrowserNativeInstallation(c.NativeInstallationPath)
	if err != nil {
		return nil, err
	}
	if installed.Carrier != "webtransport" {
		return nil, errors.New("original forced browser batch requires its independent WebTransport qualification")
	}
	if err = linuxnetlab.RequireCurrentNamespace(c.ClientNamespace); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(c.OutputDirectory)
	if err != nil || len(entries) != 0 {
		return nil, errors.New("original browser output directory must exist and be empty")
	}
	output := &boundedOutput{maximum: 1 << 20}
	diagnostic := &boundedOutput{maximum: 65536}
	defer func() {
		if err != nil {
			err = errors.Join(err, retainRunnerDiagnostic(c.OutputDirectory, output.Bytes(), diagnostic.Bytes()))
		}
		clear(output.Bytes())
		clear(diagnostic.Bytes())
	}()
	for _, relative := range []string{"flowersec-ts/scripts/browser-test-runner.mjs", "flowersec-ts/scripts/browser-runner-installation.mjs", "flowersec-ts/scripts/chromium-netns-launcher.sh", "flowersec-ts/dist/browser/index.js"} {
		info, statErr := os.Stat(filepath.Join(c.SourceRoot, relative))
		if statErr != nil || !info.Mode().IsRegular() {
			return nil, errors.New("original browser runner source is incomplete")
		}
	}
	phases := []batchPhase{{profile: c.Profile.ID, phase: "cold", count: c.Profile.Cold.Operations, plan: c.Profile}}
	maximum := c.Profile.Cold.Operations
	if !c.ColdDiagnostic {
		phases = append(phases, batchPhase{profile: c.Profile.ID, phase: "session", count: 1, plan: c.Profile})
		maximum++
	}
	manifest := filepath.Join(c.OutputDirectory, "browser-installation.json")
	history := filepath.Join(c.OutputDirectory, "browser-history")
	installation, err := interopharness.ProvisionBrowserRunnerInstallation(ctx, c.Node, c.SourceRoot, manifest, history, uint32(maximum))
	if err != nil {
		return nil, err
	}
	ownerContext, cancelOwner := context.WithCancelCause(ctx)
	defer cancelOwner(context.Canceled)
	var issue func(context.Context) (Artifact, error)
	var bindOrigin func(string) error
	var certificate func() (string, error)
	var closeOwner func(context.Context) error
	err = linuxnetlab.InNamespace(c.ServerNamespace, func() error {
		if c.Topology == "browser_webtransport" {
			owner, openErr := transporttest.OpenProductDirectBrowserBatchEndpointAt(ownerContext, c.ServerAddress, installed.OriginHost, c.Profile, maximum)
			if openErr != nil {
				return openErr
			}
			issue = func(call context.Context) (Artifact, error) {
				if err := call.Err(); err != nil {
					return nil, err
				}
				artifact, err := owner.IssueBrowserArtifact()
				if err != nil {
					return nil, err
				}
				return &directArtifact{artifact}, nil
			}
			bindOrigin = owner.BindOriginalBrowserRuntimeOrigin
			certificate = owner.CertificateHashBase64URL
			closeOwner = func(context.Context) error { return owner.Close() }
			return nil
		}
		owner, openErr := tunnelworkload.OpenBrowserBatchEndpointAt(ownerContext, tunnelworkload.BrowserTopology(c.Topology), c.ServerAddress, installed.OriginHost, c.Profile, maximum)
		if openErr != nil {
			return openErr
		}
		if setErr := owner.SetNetworkNamespaces(c.ServerNamespace, c.ClientNamespace); setErr != nil {
			return errors.Join(setErr, owner.Close(context.Background()))
		}
		issue = func(call context.Context) (Artifact, error) {
			if err := call.Err(); err != nil {
				return nil, err
			}
			return owner.IssueBrowserArtifact()
		}
		bindOrigin = owner.BindOriginalBrowserRuntimeOrigin
		certificate = owner.CertificateHashBase64URL
		closeOwner = owner.Close
		return nil
	})
	if err != nil {
		return nil, err
	}
	var source *Source
	defer func() {
		cancelOwner(context.Canceled)
		cleanup, cancel := context.WithTimeout(context.Background(), time.Duration(c.Profile.CleanupDeadlineSeconds)*time.Second)
		defer cancel()
		if source != nil {
			err = errors.Join(err, source.Close(cleanup))
		}
		err = errors.Join(err, closeOwner(cleanup))
	}()
	certificateHash, err := certificate()
	if err != nil {
		return nil, err
	}
	source, err = newSource(ownerContext, c.Topology, c.RunNumber, phases, c.Profile.Cold.MaxInflight, issue, bindOrigin, installation, installed)
	if err != nil {
		return nil, err
	}
	var listener net.Listener
	err = linuxnetlab.InNamespace(c.ServerNamespace, func() error {
		var listenErr error
		listener, listenErr = net.Listen("tcp4", net.JoinHostPort(c.ServerAddress, "0"))
		return listenErr
	})
	if err != nil {
		return nil, err
	}
	server := &http.Server{Handler: source, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: time.Duration(c.Profile.Cold.PhaseDeadlineSeconds) * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8192}
	served := make(chan error, 1)
	go func() {
		serveErr := server.Serve(listener)
		if !errors.Is(serveErr, http.ErrServerClosed) {
			source.fail(serveErr)
		}
		served <- serveErr
	}()
	defer func() {
		closeErr := server.Close()
		<-served
		if !errors.Is(closeErr, net.ErrClosed) {
			err = errors.Join(err, closeErr)
		}
	}()
	url := "http://" + net.JoinHostPort(c.ServerAddress, fmt.Sprint(listener.Addr().(*net.TCPAddr).Port)) + source.Path()
	plan := runnerPlan(c, url, manifest, history, certificateHash)
	planWire, err := json.Marshal(plan)
	if err != nil {
		return nil, err
	}
	defer clear(planWire)
	if len(planWire) > 65536 {
		return nil, errors.New("original browser process plan exceeds its bound")
	}
	planPath := filepath.Join(c.OutputDirectory, "browser-runner-plan.json")
	file, err := os.OpenFile(planPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, os.Remove(planPath)) }()
	n, writeErr := file.Write(planWire)
	if writeErr == nil && n != len(planWire) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	writeErr = errors.Join(writeErr, file.Close())
	if writeErr != nil {
		return nil, writeErr
	}
	operation, cancel := context.WithTimeout(source.ctx, time.Duration(c.Profile.CellWatchdogMinutes)*time.Minute)
	defer cancel()
	resultPath := filepath.Join(c.OutputDirectory, "browser-result.json")
	command := exec.CommandContext(operation, "/usr/bin/nsenter", "--net=/var/run/netns/"+c.ServerNamespace, "--", c.Node, filepath.Join(c.SourceRoot, "flowersec-ts", "scripts", "browser-test-runner.mjs"), "--plan", planPath, "--result", resultPath)
	command.Dir = c.SourceRoot
	configureRunnerCommand(command)
	defer func() { err = errors.Join(err, terminateRunnerGroup(command)) }()
	command.Stdout = output
	command.Stderr = diagnostic
	if err = command.Run(); err != nil {
		return nil, errors.Join(err, errors.New("original browser workload process failed"))
	}
	resultFile, err := os.Open(resultPath)
	if err != nil {
		return nil, err
	}
	resultWire, readErr := io.ReadAll(io.LimitReader(resultFile, (1<<20)+1))
	readErr = errors.Join(readErr, resultFile.Close())
	if readErr != nil {
		return nil, readErr
	}
	if len(resultWire) == 0 || len(resultWire) > 1<<20 {
		clear(resultWire)
		return nil, errors.New("original browser result exceeds its finite bound")
	}
	defer clear(resultWire)
	var observed struct {
		SchemaVersion int    `json:"schema_version"`
		Status        string `json:"status"`
		Topology      string `json:"topology"`
		ProfileID     string `json:"profile_id"`
		RunNumber     int    `json:"run_number"`
		SpendCount    int    `json:"spend_count"`
	}
	if err = json.Unmarshal(resultWire, &observed); err != nil || observed.SchemaVersion != 1 || observed.Status != "passed" || observed.Topology != c.Topology || observed.ProfileID != c.Profile.ID || observed.RunNumber != c.RunNumber || observed.SpendCount != maximum {
		return nil, errors.New("browser result differs from the original frozen run")
	}
	wait, cancelWait := context.WithTimeout(ctx, time.Duration(c.Profile.CleanupDeadlineSeconds)*time.Second)
	defer cancelWait()
	if err = source.waitOriginalRecords(wait); err != nil {
		return nil, err
	}
	if err = source.RequireComplete(); err != nil {
		return nil, err
	}
	return append(json.RawMessage(nil), resultWire...), nil
}
func (s *Source) waitOriginalRecords(ctx context.Context) error {
	s.mu.Lock()
	records := append([]*batchRecord(nil), s.records...)
	s.mu.Unlock()
	for _, record := range records {
		select {
		case <-record.done:
		case <-ctx.Done():
			return context.Cause(ctx)
		}
	}
	return nil
}
func runnerPlan(c Config, url, manifest, history, certificate string) map[string]any {
	p := c.Profile
	return map[string]any{"schema_version": 1, "browser": "chromium", "topology": c.Topology, "profile_id": p.ID, "run_number": c.RunNumber, "mode": "forced", "cold_diagnostic": c.ColdDiagnostic, "diagnostics_enabled": false, "policy": "require_quic_family", "artifact_source_url": url, "installation_manifest_path": manifest, "history_directory": history, "certificate_hash": certificate, "client_netns": c.ClientNamespace, "module_bind_address": c.ServerAddress, "module_advertise_host": c.ServerAddress, "output_directory": c.OutputDirectory, "cell_deadline_ms": p.CellWatchdogMinutes * 60000, "cleanup_deadline_ms": p.CleanupDeadlineSeconds * 1000,
		"cold": map[string]any{"operations": p.Cold.Operations, "max_inflight": p.Cold.MaxInflight, "start_rate_per_second": p.Cold.StartRatePerSecond, "operation_deadline_ms": p.Cold.OperationDeadlineSeconds * 1000, "phase_deadline_ms": p.Cold.PhaseDeadlineSeconds * 1000},
		"rpc":  map[string]any{"operations": p.RPC.Operations, "workers": p.RPC.Workers, "request_bytes": p.RPC.RequestBytes, "operation_deadline_ms": p.RPC.OperationDeadlineSeconds * 1000, "phase_deadline_ms": p.RPC.PhaseDeadlineSeconds * 1000},
		"bulk": map[string]any{"warmup_bytes_per_direction": p.Bulk.WarmupBytesPerDirection, "score_bytes_per_direction": p.Bulk.ScoreBytesPerDirection, "phase_deadline_ms": p.Bulk.PhaseDeadlineSeconds * 1000}}
}

// retainRunnerDiagnostic writes bounded actual process diagnostics in the
// caller-owned external artifact directory. It makes no result/evidence claim.
func retainRunnerDiagnostic(directory string, stdout, stderr []byte) error {
	if len(stdout) > 1<<20 || len(stderr) > 65536 {
		return errors.New("browser diagnostics exceed their original bound")
	}
	log := make([]byte, 0, len(stdout)+len(stderr)+128)
	log = append(log, []byte("Original browser batch did not complete.\nProcess stdout:\n")...)
	log = append(log, stdout...)
	log = append(log, []byte("\nProcess stderr:\n")...)
	log = append(log, stderr...)
	defer clear(log)
	name := "browser-runner-failure.log"
	if err := writeOwnedArtifact(filepath.Join(directory, name), log); err != nil {
		return err
	}
	digest := sha256.Sum256(log)
	checksum := []byte(fmt.Sprintf("%x  %s\n", digest, name))
	if err := writeOwnedArtifact(filepath.Join(directory, name+".sha256"), checksum); err != nil {
		return err
	}
	file, err := os.Open(filepath.Join(directory, name))
	if err != nil {
		return err
	}
	stored, readErr := io.ReadAll(io.LimitReader(file, int64(len(log)+1)))
	readErr = errors.Join(readErr, file.Close())
	defer clear(stored)
	if readErr != nil {
		return readErr
	}
	if sha256.Sum256(stored) != digest {
		return errors.New("original browser failure diagnostic readback differs")
	}
	parent, err := os.Open(directory)
	if err != nil {
		return err
	}
	return errors.Join(parent.Sync(), parent.Close())
}
func writeOwnedArtifact(path string, wire []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	n, err := file.Write(wire)
	if err == nil && n != len(wire) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = file.Sync()
	}
	return errors.Join(err, file.Close())
}
