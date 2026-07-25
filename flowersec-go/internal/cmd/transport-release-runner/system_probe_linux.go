//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/rawquic"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease/linuxnetlab"
)

type weaknetSystemProbe struct {
	CompletedOperations int
	TimedOut            bool
	QLOG                []byte
	ConnectionID        string
	PCAP                []byte
	Kernel              linuxnetlab.KernelFaultEvidence
	ClientAddress       string
	ServerAddress       string
	TCPInfo             []weaknetTCPInfoObservation
	RebindBefore        string
	RebindAfter         string
	EventTimes          map[string]int64
}

type weaknetTCPInfoObservation struct {
	AtNS               int64
	LocalAddress       string
	LocalPort          uint16
	RemoteAddress      string
	RemotePort         uint16
	SocketCookie       string
	SendMSSBytes       uint32
	RetransmittedBytes uint64
	Raw                string `json:"-"`
}

func runWeaknetSystemProbe(ctx context.Context, definition releaseCaseDefinition, bpfObject string) (result weaknetSystemProbe, resultErr error) {
	return runWeaknetSystemProbeLoss(ctx, definition, bpfObject, linuxnetlab.LossPeriodic)
}

func runWeaknetSystemProbeLoss(ctx context.Context, definition releaseCaseDefinition, bpfObject, commonLossMode string) (result weaknetSystemProbe, resultErr error) {
	return runWeaknetSystemProbeProcess(ctx, definition, bpfObject, commonLossMode)
}

func runWeaknetSystemProbeInProcess(ctx context.Context, definition releaseCaseDefinition, bpfObject, commonLossMode string) (result weaknetSystemProbe, resultErr error) {
	started := time.Now()
	plan, err := planWeaknetSystemCase(definition)
	if err != nil {
		return result, err
	}
	if bpfObject == "" {
		return result, errors.New("weaknet system probe requires the frozen eBPF object")
	}
	config, err := linuxnetlab.ConfigForSystemCase(stringsLowerCaseID(definition.ID), 1, plan.InitialMTU, linuxnetlab.FrozenFirewall, plan.IPv6)
	if err != nil {
		return result, err
	}
	runner := linuxnetlab.ExecRunner{}
	lab, err := linuxnetlab.Open(ctx, runner, config)
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
	if plan.Carrier == carrier.KindQUIC {
		qlogCapture, err = startNativeQLOGCapture()
		if err != nil {
			return result, err
		}
	}
	if plan.RequireRebind {
		if err := lab.ApplyFaultProfile(ctx, linuxnetlab.FaultProfile{BPFObject: bpfObject, LossMode: linuxnetlab.LossNone,
			Jitter: []time.Duration{0}, LinkMTU: plan.InitialMTU}); err != nil {
			return result, err
		}
		streamID, before, after, events, err := runNamespacedNativeRebind(ctx, config, started)
		if err != nil {
			return result, err
		}
		result.CompletedOperations, result.RebindBefore, result.RebindAfter = 2, before, after
		result.EventTimes = events
		result.QLOG, result.ConnectionID, err = qlogCapture.finish([]int64{streamID})
		if err != nil {
			return result, err
		}
		if err := capture.Stop(); err != nil {
			return result, err
		}
		captureStopped = true
		result.PCAP, err = os.ReadFile(capturePath)
		if err != nil || !validClassicPCAP(result.PCAP) {
			return result, errors.Join(err, errors.New("rebind pcap is invalid"))
		}
		evidenceCtx, evidenceCancel := context.WithTimeout(context.Background(), 5*time.Second)
		result.Kernel, err = lab.FaultEvidence(evidenceCtx)
		evidenceCancel()
		if err != nil {
			return result, err
		}
		result.ClientAddress, result.ServerAddress = config.ClientAddress.String(), config.ServerAddress.String()
		return result, nil
	}
	var endpoint *transportrelease.ProductDirectEndpoint
	if err := linuxnetlab.InNamespace(config.ServerNamespace, func() error {
		var openErr error
		endpoint, openErr = transportrelease.OpenProductDirectEndpointAt(ctx, plan.Carrier, config.ServerAddress.Addr().String())
		return openErr
	}); err != nil {
		return result, fmt.Errorf("open %s endpoint in server namespace: %w", plan.Carrier, err)
	}
	defer func() { resultErr = errors.Join(resultErr, endpoint.Close()) }()
	var pair *transportrelease.ProductDirectPair
	if err := linuxnetlab.InNamespace(config.ClientNamespace, func() error {
		var connectErr error
		pair, connectErr = endpoint.Connect(ctx)
		return connectErr
	}); err != nil {
		return result, fmt.Errorf("connect %s pair in client namespace: %w", plan.Carrier, err)
	}
	defer func() { resultErr = errors.Join(resultErr, pair.Close()) }()
	if err := pair.RoundTrip(ctx, []byte("system-probe-before"), []byte("ok")); err != nil {
		return result, fmt.Errorf("initial %s round trip: %w", plan.Carrier, err)
	}
	result.CompletedOperations++
	if plan.RequireTCPInfo {
		observation, err := readWeaknetTCPInfo(ctx, config.ClientNamespace, config.ServerAddress.Addr(), time.Since(started).Nanoseconds())
		if err != nil {
			return result, err
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
		if err := linuxnetlab.InNamespace(config.ClientNamespace, func() error {
			var connectErr error
			commonPair, connectErr = commonEndpoint.Connect(ctx)
			return connectErr
		}); err != nil {
			return result, err
		}
		defer func() { resultErr = errors.Join(resultErr, commonPair.Close()) }()
		if err := commonPair.RoundTrip(ctx, []byte("common-tcp-before"), []byte("ok")); err != nil {
			return result, err
		}
		result.CompletedOperations++
	}
	faultProfile := linuxnetlab.FaultProfile{BPFObject: bpfObject, LossMode: linuxnetlab.LossNone, Jitter: []time.Duration{0}, LinkMTU: plan.InitialMTU}
	if plan.CommonMatrix {
		faultProfile = linuxnetlab.FaultProfile{BPFObject: bpfObject, BaseDelay: 20 * time.Millisecond,
			Jitter:   []time.Duration{-5 * time.Millisecond, -3 * time.Millisecond, -1 * time.Millisecond, 0, time.Millisecond, 3 * time.Millisecond, 5 * time.Millisecond, 7 * time.Millisecond},
			LossMode: commonLossMode, EveryNth: 100, RateBitsPerSecond: 20_000_000, TokenBurstBytes: 64 << 10, QueueBytes: 1 << 20,
			LinkMTU: plan.InitialMTU, ReorderPercent: 1, DuplicatePercent: 1, ReorderDelay: 250 * time.Millisecond,
			OutageStart: time.Second, OutageDuration: 2 * time.Second}
		if commonLossMode == linuxnetlab.LossBurst {
			faultProfile.EveryNth = 0
			faultProfile.BlockSize, faultProfile.BurstFirst, faultProfile.BurstLast = 100, 1, 1
		}
	}
	if err := lab.ApplyFaultProfile(ctx, faultProfile); err != nil {
		return result, err
	}
	if plan.CommonMatrix {
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
		}
	}
	if plan.ConstrainedMTU != plan.InitialMTU {
		for _, item := range []struct{ namespace, device string }{{config.ClientNamespace, config.ClientInterface}, {config.ServerNamespace, config.ServerInterface}} {
			if err := runner.Run(ctx, "ip", "-n", item.namespace, "link", "set", "dev", item.device, "mtu", fmt.Sprint(plan.ConstrainedMTU)); err != nil {
				return result, err
			}
		}
	}
	if plan.ExpectTimeout {
		match := []string{"ip", "protocol", "icmp"}
		if plan.IPv6 {
			match = []string{"ip6", "nexthdr", "ipv6-icmp"}
		}
		arguments := append([]string{"netns", "exec", config.ClientNamespace, "nft", "insert", "rule", "inet", "flowersec", "input"}, match...)
		arguments = append(arguments, "drop")
		if err := runner.Run(ctx, "ip", arguments...); err != nil {
			return result, err
		}
	}
	afterCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	afterErr := pair.RoundTrip(afterCtx, make([]byte, 1<<20), []byte("after-mtu"))
	cancel()
	if plan.ExpectTimeout {
		if afterErr == nil {
			return result, errors.New("PMTUD timeout case completed instead of timing out")
		}
		result.TimedOut = true
	} else if afterErr != nil {
		return result, afterErr
	} else {
		result.CompletedOperations++
	}
	if plan.RequireTCPInfo {
		observation, err := readWeaknetTCPInfo(ctx, config.ClientNamespace, config.ServerAddress.Addr(), time.Since(started).Nanoseconds())
		if err != nil {
			return result, err
		}
		result.TCPInfo = append(result.TCPInfo, observation)
	}
	if qlogCapture != nil {
		result.QLOG, result.ConnectionID, err = qlogCapture.finish(nil)
		if err != nil {
			return result, err
		}
	}
	if err := capture.Stop(); err != nil {
		return result, err
	}
	captureStopped = true
	result.PCAP, err = os.ReadFile(capturePath)
	if err != nil || !validClassicPCAP(result.PCAP) {
		return result, errors.Join(err, errors.New("system probe pcap is invalid"))
	}
	evidenceCtx, evidenceCancel := context.WithTimeout(context.Background(), 5*time.Second)
	result.Kernel, err = lab.FaultEvidence(evidenceCtx)
	evidenceCancel()
	if err != nil {
		return result, err
	}
	result.ClientAddress, result.ServerAddress = config.ClientAddress.String(), config.ServerAddress.String()
	return result, nil
}

func runNamespacedNativeRebind(ctx context.Context, config linuxnetlab.Config, started time.Time) (int64, string, string, map[string]int64, error) {
	serverTLS, clientTLS, err := nativeReleaseTLS()
	if err != nil {
		return -1, "", "", nil, err
	}
	serverTLS.NextProtos, clientTLS.NextProtos = []string{rawquic.ALPNDirect}, []string{rawquic.ALPNDirect}
	var listener *rawquic.Listener
	if err := linuxnetlab.InNamespace(config.ServerNamespace, func() error {
		var listenErr error
		listener, listenErr = rawquic.Listen(net.JoinHostPort(config.ServerAddress.Addr().String(), "0"), serverTLS, rawquic.DefaultLimits())
		return listenErr
	}); err != nil {
		return -1, "", "", nil, err
	}
	defer listener.Close()
	accepted := make(chan struct {
		session *rawquic.Session
		err     error
	}, 1)
	go func() {
		session, acceptErr := listener.Accept(ctx)
		accepted <- struct {
			session *rawquic.Session
			err     error
		}{session, acceptErr}
	}()
	var client *rawquic.Session
	if err := linuxnetlab.InNamespace(config.ClientNamespace, func() error {
		var dialErr error
		client, dialErr = rawquic.Dial(ctx, listener.Addr().String(), clientTLS, rawquic.DefaultLimits())
		return dialErr
	}); err != nil {
		return -1, "", "", nil, err
	}
	defer client.Close()
	peer := <-accepted
	if peer.err != nil {
		return -1, "", "", nil, peer.err
	}
	defer peer.session.Close()
	if _, err := rawQUICSoakRoundTrip(ctx, client, peer.session, 0); err != nil {
		return -1, "", "", nil, err
	}
	events := map[string]int64{"rpc_before_rebind": time.Since(started).Nanoseconds()}
	timer := time.NewTimer(time.Until(started.Add(2 * time.Second)))
	select {
	case <-timer.C:
	case <-ctx.Done():
		timer.Stop()
		return -1, "", "", nil, context.Cause(ctx)
	}
	events["rebind_scheduled"] = time.Since(started).Nanoseconds()
	before := client.LocalAddr().String()
	var path *net.UDPConn
	network := "udp4"
	localIP := net.IP(config.ClientAddress.Addr().AsSlice())
	if config.ClientAddress.Addr().Is6() {
		network = "udp6"
	}
	if err := linuxnetlab.InNamespace(config.ClientNamespace, func() error {
		var listenErr error
		path, listenErr = net.ListenUDP(network, &net.UDPAddr{IP: localIP})
		return listenErr
	}); err != nil {
		return -1, "", "", nil, err
	}
	if err := client.Migrate(ctx, path); err != nil {
		return -1, "", "", nil, err
	}
	events["path_updated"] = time.Since(started).Nanoseconds()
	events["path_validated"] = time.Since(started).Nanoseconds()
	var streamID int64
	for ordinal := 1; ordinal <= 32; ordinal++ {
		streamID, err = rawQUICSoakRoundTrip(ctx, client, peer.session, ordinal)
		if err != nil {
			return -1, "", "", nil, err
		}
	}
	after := client.LocalAddr().String()
	if before == after {
		return -1, "", "", nil, errors.New("native QUIC migration did not change the local path")
	}
	events["rpc_after_rebind"] = time.Since(started).Nanoseconds()
	events["kernel_path_rebind_completed"] = events["rpc_after_rebind"]
	return streamID, before, after, events, nil
}

func readWeaknetTCPInfo(ctx context.Context, namespace string, remote netip.Addr, atNS int64) (weaknetTCPInfoObservation, error) {
	filter := remote.String()
	if remote.Is6() {
		filter += "/128"
	}
	output, err := exec.CommandContext(ctx, "ip", "netns", "exec", namespace, "ss", "-tinpeH", "dst", filter).CombinedOutput()
	if err != nil {
		return weaknetTCPInfoObservation{}, fmt.Errorf("capture TCP_INFO: %w: %s", err, output)
	}
	fields := strings.Fields(string(output))
	if len(fields) == 0 {
		return weaknetTCPInfoObservation{}, errors.New("TCP_INFO socket was not found")
	}
	local, peer, err := parseWeaknetSocketEndpoints(fields)
	if err != nil {
		return weaknetTCPInfoObservation{}, fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	result := weaknetTCPInfoObservation{AtNS: atNS, LocalAddress: local.Addr().String(), LocalPort: local.Port(),
		RemoteAddress: peer.Addr().String(), RemotePort: peer.Port(), Raw: strings.TrimSpace(string(output))}
	for _, field := range fields {
		if strings.HasPrefix(field, "sk:") {
			result.SocketCookie = strings.TrimPrefix(field, "sk:")
		}
	}
	for _, field := range fields {
		key, value, found := strings.Cut(field, ":")
		if !found {
			continue
		}
		switch key {
		case "mss":
			parsed, parseErr := strconv.ParseUint(value, 10, 32)
			if parseErr == nil {
				result.SendMSSBytes = uint32(parsed)
			}
		case "bytes_retrans":
			parsed, parseErr := strconv.ParseUint(value, 10, 64)
			if parseErr == nil {
				result.RetransmittedBytes = parsed
			}
		}
	}
	if result.SocketCookie == "" || result.SendMSSBytes == 0 {
		return weaknetTCPInfoObservation{}, errors.New("TCP_INFO MSS or socket cookie is missing")
	}
	return result, nil
}

func parseWeaknetSocketEndpoints(fields []string) (netip.AddrPort, netip.AddrPort, error) {
	var endpoints []netip.AddrPort
	for _, field := range fields {
		endpoint, err := netip.ParseAddrPort(field)
		if err == nil {
			endpoints = append(endpoints, endpoint)
			if len(endpoints) == 2 {
				return endpoints[0], endpoints[1], nil
			}
		}
	}
	return netip.AddrPort{}, netip.AddrPort{}, errors.New("TCP_INFO socket endpoints are incomplete")
}

func stringsLowerCaseID(value string) string {
	output := make([]byte, len(value))
	for index := range value {
		if value[index] >= 'A' && value[index] <= 'Z' {
			output[index] = value[index] + ('a' - 'A')
		} else {
			output[index] = value[index]
		}
	}
	return string(output)
}
