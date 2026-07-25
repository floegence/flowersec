//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease/linuxnetlab"
)

type systemWorkerRequest struct {
	ID             string       `json:"id"`
	Profile        string       `json:"profile"`
	Carrier        carrier.Kind `json:"carrier"`
	CommonLossMode string       `json:"common_loss_mode"`
}

type systemWorkerResult struct {
	CompletedOperations int                         `json:"completed_operations"`
	TimedOut            bool                        `json:"timed_out"`
	TCPInfo             []weaknetTCPInfoObservation `json:"tcp_info,omitempty"`
	RebindBefore        string                      `json:"rebind_before,omitempty"`
	RebindAfter         string                      `json:"rebind_after,omitempty"`
	NativeStreamIDs     []int64                     `json:"native_stream_ids,omitempty"`
	EventTimes          map[string]int64            `json:"event_times,omitempty"`
}

var systemWorkerArguments = func() []string { return []string{systemWorkerArg} }

func runWeaknetSystemProbeProcess(ctx context.Context, definition releaseCaseDefinition, bpfObject, commonLossMode string) (result weaknetSystemProbe, resultErr error) {
	plan, err := planWeaknetSystemCase(definition)
	if err != nil {
		return result, err
	}
	if bpfObject == "" {
		return result, errors.New("weaknet system probe requires the frozen eBPF object")
	}
	config, err := systemNetworkConfig(definition, plan)
	if err != nil {
		return result, err
	}
	lab, err := linuxnetlab.Open(ctx, linuxnetlab.ExecRunner{}, config)
	if err != nil {
		return result, err
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		resultErr = errors.Join(resultErr, lab.Close(cleanupCtx))
		cancel()
	}()
	captureDirectory, err := os.MkdirTemp("", "flowersec-system-probe-")
	if err != nil {
		return result, err
	}
	defer os.RemoveAll(captureDirectory)
	capturePath := filepath.Join(captureDirectory, "traffic.pcap")
	capture, err := startPacketCapture(ctx, config.ClientNamespace, config.ClientInterface, capturePath)
	if err != nil {
		return result, err
	}
	captureStopped := false
	defer func() {
		if !captureStopped {
			resultErr = errors.Join(resultErr, capture.Stop())
		}
	}()
	var qlogCapture *nativeQLOGCapture
	qlogFinished := false
	if plan.Carrier == carrier.KindQUIC {
		qlogCapture, err = startNativeQLOGCapture()
		if err != nil {
			return result, err
		}
		defer func() {
			if !qlogFinished {
				_, _, finishErr := qlogCapture.finish(nil)
				resultErr = errors.Join(resultErr, finishErr)
			}
		}()
	}
	if err := lab.ApplyFaultProfile(ctx, systemFaultProfile(plan, bpfObject, commonLossMode)); err != nil {
		return result, err
	}
	worker, err := runSystemWorkerProcess(ctx, config, definition, commonLossMode)
	if err != nil {
		_ = capture.Stop()
		captureStopped = true
		var debugQLOG []byte
		if qlogCapture != nil {
			debugQLOG, _, _ = qlogCapture.finish(nil)
			qlogFinished = true
		}
		writeSystemProbeDebug(definition.ID, capturePath, debugQLOG)
		return result, err
	}
	result.CompletedOperations, result.TimedOut = worker.CompletedOperations, worker.TimedOut
	result.TCPInfo, result.RebindBefore, result.RebindAfter = worker.TCPInfo, worker.RebindBefore, worker.RebindAfter
	result.EventTimes = worker.EventTimes
	packetCtx, packetCancel := context.WithTimeout(ctx, 2*time.Second)
	packetErr := capture.WaitForPacket(packetCtx)
	packetCancel()
	if packetErr != nil {
		_ = capture.Stop()
		captureStopped = true
		writeSystemProbeDebug(definition.ID, capturePath, nil)
		return result, packetErr
	}
	if qlogCapture != nil {
		result.QLOG, result.ConnectionID, err = qlogCapture.finish(worker.NativeStreamIDs)
		qlogFinished = true
		if err != nil {
			return result, err
		}
	}
	stopErr := capture.Stop()
	captureStopped = true
	writeSystemProbeDebug(definition.ID, capturePath, result.QLOG)
	if stopErr != nil {
		return result, stopErr
	}
	result.PCAP, err = os.ReadFile(capturePath)
	if err != nil || !validClassicPCAP(result.PCAP) {
		return result, errors.Join(err, errors.New("system probe pcap is invalid"))
	}
	evidenceCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	result.Kernel, err = lab.FaultEvidence(evidenceCtx)
	cancel()
	if err != nil {
		return result, err
	}
	result.ClientAddress, result.ServerAddress = config.ClientAddress.String(), config.ServerAddress.String()
	return result, nil
}

func writeSystemProbeDebug(caseID, capturePath string, qlog []byte) {
	directory := os.Getenv("FLOWERSEC_SYSTEM_DEBUG_DIR")
	if directory == "" {
		return
	}
	_ = os.MkdirAll(directory, 0o700)
	if pcap, err := os.ReadFile(capturePath); err == nil {
		_ = os.WriteFile(filepath.Join(directory, strings.ToLower(caseID)+".pcap"), pcap, 0o600)
	}
	if len(qlog) != 0 {
		_ = os.WriteFile(filepath.Join(directory, strings.ToLower(caseID)+".sqlog"), qlog, 0o600)
	}
}

func systemNetworkConfig(definition releaseCaseDefinition, plan weaknetSystemPlan) (linuxnetlab.Config, error) {
	if plan.ConstrainedMTU != plan.InitialMTU {
		return linuxnetlab.ConfigForRoutedSystemCase(stringsLowerCaseID(definition.ID), 1, plan.InitialMTU, linuxnetlab.FrozenFirewall, plan.IPv6)
	}
	return linuxnetlab.ConfigForSystemCase(stringsLowerCaseID(definition.ID), 1, plan.InitialMTU, linuxnetlab.FrozenFirewall, plan.IPv6)
}

func systemFaultProfile(plan weaknetSystemPlan, bpfObject, commonLossMode string) linuxnetlab.FaultProfile {
	profile := linuxnetlab.FaultProfile{BPFObject: bpfObject, LossMode: linuxnetlab.LossNone, Jitter: []time.Duration{0}, LinkMTU: plan.InitialMTU}
	if !plan.CommonMatrix {
		return profile
	}
	profile = linuxnetlab.FaultProfile{BPFObject: bpfObject, BaseDelay: 20 * time.Millisecond,
		Jitter:   []time.Duration{-5 * time.Millisecond, -3 * time.Millisecond, -time.Millisecond, 0, time.Millisecond, 3 * time.Millisecond, 5 * time.Millisecond, 7 * time.Millisecond},
		LossMode: commonLossMode, EveryNth: 100, RateBitsPerSecond: 20_000_000, TokenBurstBytes: 64 << 10, QueueBytes: 1 << 20,
		LinkMTU: plan.InitialMTU, ReorderPercent: 1, DuplicatePercent: 1, ReorderDelay: 250 * time.Millisecond,
		OutageStart: time.Second, OutageDuration: 2 * time.Second}
	if commonLossMode == linuxnetlab.LossBurst {
		profile.EveryNth = 0
		profile.BlockSize, profile.BurstFirst, profile.BurstLast = 100, 1, 1
	}
	return profile
}

func runSystemWorkerProcess(ctx context.Context, config linuxnetlab.Config, definition releaseCaseDefinition, commonLossMode string) (systemWorkerResult, error) {
	executable, err := os.Executable()
	if err != nil {
		return systemWorkerResult{}, err
	}
	payload, err := json.Marshal(systemWorkerRequest{ID: definition.ID, Profile: definition.Profile, Carrier: definition.Carrier, CommonLossMode: commonLossMode})
	if err != nil {
		return systemWorkerResult{}, err
	}
	arguments := append([]string{"netns", "exec", config.ClientNamespace, executable}, systemWorkerArguments()...)
	command := exec.CommandContext(ctx, "ip", arguments...)
	command.Stdin = bytes.NewReader(payload)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		return systemWorkerResult{}, fmt.Errorf("weaknet system worker: %w: stdout=%s stderr=%s", err, strings.TrimSpace(stdout.String()), strings.TrimSpace(stderr.String()))
	}
	var result systemWorkerResult
	decoder := json.NewDecoder(&stdout)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return systemWorkerResult{}, fmt.Errorf("decode weaknet system worker: %w", err)
	}
	return result, nil
}

func runWeaknetSystemWorker(input io.Reader, output io.Writer) error {
	decoder := json.NewDecoder(io.LimitReader(input, 64<<10))
	decoder.DisallowUnknownFields()
	var request systemWorkerRequest
	if err := decoder.Decode(&request); err != nil {
		return err
	}
	definition := releaseCaseDefinition{ID: request.ID, Profile: request.Profile, Carrier: request.Carrier}
	plan, err := planWeaknetSystemCase(definition)
	if err != nil {
		return err
	}
	config, err := systemNetworkConfig(definition, plan)
	if err != nil {
		return err
	}
	if err := linuxnetlab.RequireCurrentNamespace(config.ClientNamespace); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	result, err := executeSystemWorkload(ctx, config, plan)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(result)
}

func executeSystemWorkload(ctx context.Context, config linuxnetlab.Config, plan weaknetSystemPlan) (result systemWorkerResult, resultErr error) {
	started := time.Now()
	stage := func(value string) { _, _ = fmt.Fprintln(os.Stderr, "weaknet-system-stage:", value) }
	if plan.RequireRebind {
		stage("rebind-start")
		streamID, before, after, events, err := runNamespacedNativeRebind(ctx, config, started)
		if err != nil {
			return result, err
		}
		result.CompletedOperations, result.RebindBefore, result.RebindAfter = 2, before, after
		result.NativeStreamIDs = []int64{streamID}
		result.EventTimes = events
		return result, nil
	}
	// Keep endpoint links at the frozen 1500-byte MTU while constraining only
	// the routed path before QUIC establishes. QUIC Initial packets still pass,
	// and quic-go must discover and retain the lower path MTU on the same socket.
	if plan.Carrier == carrier.KindQUIC && plan.ConstrainedMTU != plan.InitialMTU {
		stage("preconstrain-quic-path-mtu")
		if config.RouterNamespace == "" {
			return result, errors.New("PMTUD workload requires a routed network path")
		}
		if err := exec.CommandContext(ctx, "ip", "-n", config.RouterNamespace, "link", "set", "dev", config.RouterServerInterface, "mtu", fmt.Sprint(plan.ConstrainedMTU)).Run(); err != nil {
			return result, fmt.Errorf("preconstrain QUIC server path MTU: %w", err)
		}
	}
	var endpoint *transportrelease.ProductDirectEndpoint
	stage("endpoint-open")
	if err := linuxnetlab.InNamespace(config.ServerNamespace, func() error {
		var openErr error
		endpoint, openErr = transportrelease.OpenProductDirectEndpointAt(ctx, plan.Carrier, config.ServerAddress.Addr().String())
		return openErr
	}); err != nil {
		return result, fmt.Errorf("open %s endpoint in server namespace: %w", plan.Carrier, err)
	}
	defer func() { resultErr = errors.Join(resultErr, endpoint.Close()) }()
	stage("pair-connect")
	pair, err := endpoint.Connect(ctx)
	if err != nil {
		return result, fmt.Errorf("connect %s pair in client namespace: %w", plan.Carrier, err)
	}
	defer func() { resultErr = errors.Join(resultErr, pair.Close()) }()
	stage("initial-round-trip")
	if err := pair.RoundTrip(ctx, []byte("system-probe-before"), []byte("ok")); err != nil {
		return result, fmt.Errorf("initial %s round trip: %w", plan.Carrier, err)
	}
	result.CompletedOperations++
	result.EventTimes = map[string]int64{"initial_rpc_completed": time.Since(started).Nanoseconds()}
	if plan.RequireTCPInfo {
		observation, err := readWeaknetTCPInfo(ctx, config.ClientNamespace, config.ServerAddress.Addr(), time.Since(started).Nanoseconds())
		if err != nil {
			return result, err
		}
		if observation.SendMSSBytes <= 1280 {
			return result, fmt.Errorf("initial WSS MSS = %d, want larger than 1280", observation.SendMSSBytes)
		}
		result.TCPInfo = append(result.TCPInfo, observation)
	}
	var commonEndpoint *transportrelease.ProductDirectEndpoint
	var commonPair *transportrelease.ProductDirectPair
	if plan.CommonMatrix {
		if err := linuxnetlab.InNamespace(config.ServerNamespace, func() error {
			var openErr error
			commonEndpoint, openErr = transportrelease.OpenProductDirectEndpointAt(ctx, carrier.KindWebSocket, config.ServerAddress.Addr().String())
			return openErr
		}); err != nil {
			return result, err
		}
		defer func() { resultErr = errors.Join(resultErr, commonEndpoint.Close()) }()
		commonPair, err = commonEndpoint.Connect(ctx)
		if err != nil {
			return result, err
		}
		defer func() { resultErr = errors.Join(resultErr, commonPair.Close()) }()
		if err := commonPair.RoundTrip(ctx, []byte("common-tcp-before"), []byte("ok")); err != nil {
			return result, err
		}
		result.CompletedOperations++
		faultEvents := observeSystemFaultSchedule(ctx, started, time.Second, 2*time.Second)
		deadline := time.Now().Add(4 * time.Second)
		for time.Now().Before(deadline) {
			operationCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
			quicErr := pair.RoundTrip(operationCtx, make([]byte, 4096), []byte("quic"))
			wssErr := commonPair.RoundTrip(operationCtx, make([]byte, 4096), []byte("wss"))
			cancel()
			if quicErr == nil {
				result.CompletedOperations++
			}
			if wssErr == nil {
				result.CompletedOperations++
			}
			result.EventTimes["kernel_fault_matrix_last_operation"] = time.Since(started).Nanoseconds()
		}
		observed := <-faultEvents
		if observed.err != nil {
			return result, observed.err
		}
		result.EventTimes["outage_started"] = observed.started
		result.EventTimes["outage_ended"] = observed.ended
		result.EventTimes["kernel_fault_matrix_completed"] = time.Since(started).Nanoseconds()
		if err := validateCommonMatrixTimeline(result.EventTimes); err != nil {
			return result, err
		}
	}
	if plan.Carrier != carrier.KindQUIC && plan.ConstrainedMTU != plan.InitialMTU {
		stage("constrain-mtu")
		if config.RouterNamespace == "" {
			return result, errors.New("PMTUD workload requires a routed network path")
		}
		if err := exec.CommandContext(ctx, "ip", "-n", config.RouterNamespace, "link", "set", "dev", config.RouterServerInterface, "mtu", fmt.Sprint(plan.ConstrainedMTU)).Run(); err != nil {
			return result, fmt.Errorf("constrain server path MTU: %w", err)
		}
	}
	if plan.ExpectTimeout {
		match := []string{"ip", "protocol", "icmp"}
		if plan.IPv6 {
			match = []string{"ip6", "nexthdr", "ipv6-icmp"}
		}
		arguments := append([]string{"netns", "exec", config.ClientNamespace, "nft", "insert", "rule", "inet", "flowersec", "input"}, match...)
		arguments = append(arguments, "drop")
		if err := exec.CommandContext(ctx, "ip", arguments...).Run(); err != nil {
			return result, fmt.Errorf("install PTB drop rule: %w", err)
		}
	}
	afterDeadline := 5 * time.Second
	if plan.Carrier == carrier.KindQUIC && !plan.ExpectTimeout {
		afterDeadline = 20 * time.Second
	} else if plan.RequireTCPInfo && plan.ExpectTimeout && plan.IPv6 {
		afterDeadline = 12 * time.Second
	}
	afterCtx, cancel := context.WithTimeout(ctx, afterDeadline)
	stage("post-mtu-round-trip")
	afterErr := pair.RoundTrip(afterCtx, make([]byte, 1<<20), []byte("after-mtu"))
	cancel()
	stage("post-mtu-round-trip-finished")
	if plan.ExpectTimeout {
		if afterErr == nil {
			return result, errors.New("PMTUD timeout case completed instead of timing out")
		}
		result.TimedOut = true
	} else if afterErr != nil {
		return result, fmt.Errorf("post-MTU %s round trip: %w", plan.Carrier, afterErr)
	} else {
		result.CompletedOperations++
		result.EventTimes["post_mtu_operation_completed"] = time.Since(started).Nanoseconds()
	}
	if plan.RequireTCPInfo {
		observation, err := readWeaknetTCPInfo(ctx, config.ClientNamespace, config.ServerAddress.Addr(), time.Since(started).Nanoseconds())
		if err != nil {
			return result, err
		}
		before := result.TCPInfo[0]
		if observation.SocketCookie != before.SocketCookie || observation.LocalAddress != before.LocalAddress || observation.LocalPort != before.LocalPort ||
			observation.RemoteAddress != before.RemoteAddress || observation.RemotePort != before.RemotePort {
			return result, errors.New("WSS TCP_INFO samples do not identify one socket")
		}
		if plan.ExpectTimeout {
			if observation.SendMSSBytes <= 1280 || observation.RetransmittedBytes <= before.RetransmittedBytes {
				return result, fmt.Errorf("timeout TCP_INFO MSS/retrans = %d/%d, want oversized MSS and retransmission growth: %s", observation.SendMSSBytes, observation.RetransmittedBytes-before.RetransmittedBytes, observation.Raw)
			}
		} else if observation.SendMSSBytes > 1280 {
			return result, fmt.Errorf("recovered TCP_INFO MSS = %d, want at most 1280", observation.SendMSSBytes)
		}
		result.TCPInfo = append(result.TCPInfo, observation)
	}
	stage("workload-finished")
	result.EventTimes["workload_finished"] = time.Since(started).Nanoseconds()
	return result, nil
}

type observedSystemFaultSchedule struct {
	started int64
	ended   int64
	err     error
}

func observeSystemFaultSchedule(ctx context.Context, workloadStarted time.Time, outageStart, outageDuration time.Duration) <-chan observedSystemFaultSchedule {
	result := make(chan observedSystemFaultSchedule, 1)
	go func() {
		startTimer := time.NewTimer(outageStart)
		defer startTimer.Stop()
		select {
		case <-ctx.Done():
			result <- observedSystemFaultSchedule{err: context.Cause(ctx)}
			return
		case <-startTimer.C:
		}
		observed := observedSystemFaultSchedule{started: time.Since(workloadStarted).Nanoseconds()}
		endTimer := time.NewTimer(outageDuration)
		defer endTimer.Stop()
		select {
		case <-ctx.Done():
			observed.err = context.Cause(ctx)
		case <-endTimer.C:
			observed.ended = time.Since(workloadStarted).Nanoseconds()
		}
		result <- observed
	}()
	return result
}

func validateCommonMatrixTimeline(events map[string]int64) error {
	started := events["outage_started"]
	ended := events["outage_ended"]
	lastOperation := events["kernel_fault_matrix_last_operation"]
	completed := events["kernel_fault_matrix_completed"]
	if started <= 0 || ended <= started || lastOperation < ended || completed < lastOperation {
		return fmt.Errorf("common kernel fault timeline is not measured and monotonic: start=%d end=%d last_operation=%d completed=%d", started, ended, lastOperation, completed)
	}
	return nil
}
