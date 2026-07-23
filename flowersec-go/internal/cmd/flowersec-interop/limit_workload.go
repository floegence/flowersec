package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/client"
	"github.com/floegence/flowersec/flowersec-go/v2/endpoint"
	endpointserve "github.com/floegence/flowersec/flowersec-go/v2/endpoint/serve"
	rpcv1 "github.com/floegence/flowersec/flowersec-go/v2/gen/flowersec/rpc/v1"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/interopprotocol"
	"github.com/floegence/flowersec/flowersec-go/v2/mux/yamux"
	"github.com/floegence/flowersec/flowersec-go/v2/proxy"
	"github.com/floegence/flowersec/flowersec-go/v2/rpc"
)

const limitBodyBytes = 1024

func (e *environment) startGoLimitPeer(
	ctx context.Context,
	value variant,
	workload interopprotocol.Workload,
	limitCase string,
) (*goPeer, error) {
	limits := serverLimitYamuxLimits(limitCase)
	return e.startGoPeerWithService(
		ctx,
		value,
		limits,
		func(serviceCtx context.Context, session endpoint.Session) error {
			return serveGoLimitSession(serviceCtx, session, e.upstream.URL, limitCase, workload)
		},
	)
}

func serverLimitYamuxLimits(limitCase string) endpoint.YamuxLimits {
	limits := yamux.DefaultLimits()
	switch limitCase {
	case "inbound_streams":
		limits.MaxInboundStreams = 1
	case "frame":
		limits.MaxFrameBytes = 1024
		limits.PreferredOutboundFrameBytes = 1024
	case "stream_receive":
		limits.MaxStreamReceiveBytes = yamux.DefaultMaxStreamReceiveBytes
	case "session_receive":
		limits.MaxSessionReceiveBytes = yamux.DefaultMaxStreamReceiveBytes
	}
	return endpoint.YamuxLimits(limits)
}

func serveGoLimitSession(
	ctx context.Context,
	session endpoint.Session,
	upstreamURL, limitCase string,
	workload interopprotocol.Workload,
) (returnErr error) {
	defer func() {
		closeErr := session.Close()
		if destructiveLimitCase(limitCase) && isEndpointCloseAfterTermination(closeErr) {
			closeErr = nil
		}
		returnErr = errors.Join(returnErr, closeErr)
	}()
	var completed atomic.Bool
	server, err := endpointserve.New(endpointserve.Options{
		RPC: endpointserve.RPCOptions{
			Server: rpc.ServerOptions{
				MaxConcurrentRequests:  workload.RPC.SaturationActive,
				MaxQueuedRequests:      workload.RPC.SaturationQueued,
				MaxQueuedNotifications: workload.RPC.SaturationQueued,
			},
			Register: func(router *rpc.Router, _ *rpc.Server) {
				router.Register(rpcTypeComplete, func(context.Context, json.RawMessage) (json.RawMessage, *rpcv1.RpcError) {
					completed.Store(true)
					return json.RawMessage(`{"ok":true}`), nil
				})
			},
		},
	})
	if err != nil {
		return err
	}
	server.Handle("hold", func(handlerCtx context.Context, _ io.ReadWriteCloser) {
		<-handlerCtx.Done()
	})
	proxyOptions := proxy.Options{Upstream: upstreamURL, UpstreamOrigin: upstreamURL}
	if limitCase == "proxy_body" {
		proxyOptions.MaxBodyBytes = limitBodyBytes
	}
	if err := proxy.Register(server, proxyOptions); err != nil {
		return err
	}
	serveErr := server.ServeSession(ctx, session)
	if completed.Load() || errors.Is(serveErr, context.Canceled) {
		return nil
	}
	if limitCase == "inbound_streams" || limitCase == "frame" || limitCase == "session_receive" {
		var endpointError *endpoint.Error
		if errors.As(serveErr, &endpointError) && endpointError.Code == endpoint.CodeResourceExhausted {
			return nil
		}
	}
	return serveErr
}

func (e *environment) runGoLimits(
	ctx context.Context,
	value variant,
	workload interopprotocol.Workload,
	diagnostics *[]interopprotocol.Diagnostic,
) (interopprotocol.Metrics, error) {
	count := max(0, workload.LimitChecks-1)
	metrics := interopprotocol.Metrics{}
	for index := 0; index < count; index++ {
		limitCase := interopprotocol.LimitCases[index]
		peer, err := e.startGoLimitPeer(ctx, value, workload, limitCase)
		if err != nil {
			return metrics, err
		}
		result, exerciseErr := exerciseGoLimit(ctx, peer.artifact, limitCase, value.Transport, peer.cancel, diagnostics)
		peerErr := peer.wait(ctx)
		metrics.Sessions += result.Sessions
		metrics.LimitChecks += result.LimitChecks
		metrics.ResourceRejections += result.ResourceRejections
		metrics.BackpressureChecks += result.BackpressureChecks
		if err := errors.Join(exerciseErr, peerErr); err != nil {
			return metrics, fmt.Errorf("limit check %s: %w", limitCase, err)
		}
	}
	return metrics, nil
}

func (e *environment) startGoLimitFleet(
	ctx context.Context,
	value variant,
	workload interopprotocol.Workload,
) ([]*goPeer, []interopprotocol.LimitArtifact, error) {
	count := max(0, workload.LimitChecks-1)
	peers := make([]*goPeer, 0, count)
	artifacts := make([]interopprotocol.LimitArtifact, 0, count)
	for index := 0; index < count; index++ {
		limitCase := interopprotocol.LimitCases[index]
		peer, err := e.startGoLimitPeer(ctx, value, workload, limitCase)
		if err != nil {
			closeGoPeers(peers)
			return nil, nil, err
		}
		peers = append(peers, peer)
		artifacts = append(artifacts, interopprotocol.LimitArtifact{
			Name: limitCase, DirectInfo: peer.artifact.DirectInfo, TunnelGrant: peer.artifact.TunnelGrant,
		})
	}
	return peers, artifacts, nil
}

func exerciseGoLimit(
	ctx context.Context,
	material interopprotocol.ClientArtifact,
	limitCase, transport string,
	complete func(),
	diagnostics *[]interopprotocol.Diagnostic,
) (interopprotocol.Metrics, error) {
	artifact, err := goConnectArtifact(material)
	if err != nil {
		return interopprotocol.Metrics{}, err
	}
	options := []client.ConnectOption{
		client.WithOrigin(interopOrigin),
		client.WithTransportSecurityPolicy(client.AllowPlaintextForLoopback),
		client.WithLivenessDisabled(),
	}
	if limitCase == "active_streams" {
		limits := yamux.DefaultLimits()
		limits.MaxActiveStreams = 2
		limits.MaxInboundStreams = 1
		options = append(options, client.WithYamuxLimits(limits))
	}
	connected, err := client.Connect(ctx, artifact, options...)
	if err != nil {
		return interopprotocol.Metrics{}, err
	}
	metrics := interopprotocol.Metrics{Sessions: 1, LimitChecks: 1}
	checkErr := runGoLimitAction(ctx, connected, limitCase, transport)
	if checkErr == nil {
		if err := recordDiagnostic(diagnostics, limitCase, transport); err != nil {
			checkErr = err
		}
	}
	if checkErr == nil {
		complete()
	}
	closeErr := connected.Close()
	if checkErr == nil && destructiveLimitCase(limitCase) && isGoCloseAfterTermination(closeErr) {
		closeErr = nil
	}
	if checkErr == nil {
		if limitCase == "stream_receive" {
			metrics.BackpressureChecks = 1
		} else {
			metrics.ResourceRejections = 1
		}
	}
	return metrics, errors.Join(checkErr, closeErr)
}

func destructiveLimitCase(limitCase string) bool {
	return limitCase == "inbound_streams" || limitCase == "frame" || limitCase == "session_receive"
}

func runGoLimitAction(ctx context.Context, connected client.Client, limitCase, transport string) error {
	switch limitCase {
	case "active_streams":
		held, err := connected.OpenStream(ctx, "hold")
		if err != nil {
			return err
		}
		_, err = connected.OpenStream(ctx, "hold")
		if !isGoResourceError(err) {
			return fmt.Errorf("active stream limit returned %v", err)
		}
		return completeActiveStreamLimit(
			func() error { return rpcControl(ctx, connected, rpcTypeComplete) },
			held.Reset,
		)
	case "inbound_streams", "frame":
		stream, err := connected.OpenStream(ctx, "hold")
		if err != nil {
			if isGoResourceError(err) {
				return nil
			}
			return err
		}
		if limitCase == "frame" {
			if _, err = stream.Write(bytes.Repeat([]byte("f"), 2048)); err != nil {
				return nil
			}
		}
		if failureErr := expectGoStreamFailure(ctx, stream); failureErr != nil {
			return failureErr
		}
		if limitCase == "inbound_streams" {
			return rpcControl(ctx, connected, rpcTypeComplete)
		}
		return nil
	case "stream_receive":
		stream, err := connected.OpenStream(ctx, "hold")
		if err != nil {
			return err
		}
		written := make(chan error, 1)
		go func() {
			_, writeErr := stream.Write(bytes.Repeat([]byte("b"), yamux.DefaultMaxStreamReceiveBytes+1))
			written <- writeErr
		}()
		select {
		case err := <-written:
			return fmt.Errorf("stream receive boundary did not apply backpressure: %v", err)
		case <-time.After(100 * time.Millisecond):
		}
		resetErr := stream.Reset()
		select {
		case writeErr := <-written:
			if writeErr == nil {
				return errors.Join(resetErr, errors.New("reset released the backpressured write without an error"))
			}
		case <-ctx.Done():
			return errors.Join(resetErr, ctx.Err())
		}
		return errors.Join(resetErr, rpcControl(ctx, connected, rpcTypeComplete))
	case "session_receive":
		first, err := connected.OpenStream(ctx, "hold")
		if err != nil {
			return err
		}
		second, err := connected.OpenStream(ctx, "hold")
		if err != nil {
			return err
		}
		writes := make(chan error, 2)
		for _, stream := range []io.Writer{first, second} {
			go func(writer io.Writer) {
				_, writeErr := writer.Write(bytes.Repeat([]byte("s"), yamux.DefaultMaxStreamReceiveBytes))
				writes <- writeErr
			}(stream)
		}
		completedWrites := 0
		failedWrites := 0
		for completedWrites < 2 {
			select {
			case writeErr := <-writes:
				completedWrites++
				if writeErr != nil {
					failedWrites++
				}
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		if failedWrites == 0 {
			return errors.New("session receive limit allowed both writes to complete")
		}
		return nil
	case "proxy_body":
		proxyClient, err := proxy.NewClient(proxy.ContractOptions{})
		if err != nil {
			return err
		}
		_, err = proxyClient.Do(ctx, connected, proxy.ClientHTTPRequest{
			Method: http.MethodPost, Path: "/http",
			Body: bytes.NewReader(bytes.Repeat([]byte("p"), limitBodyBytes+1)),
		})
		if err == nil {
			return errors.New("proxy body limit unexpectedly accepted the request")
		}
		var proxyError *proxy.ClientError
		if !errors.As(err, &proxyError) || proxyError.Code != "request_body_too_large" {
			return fmt.Errorf("proxy body limit returned %w", err)
		}
		return rpcControl(ctx, connected, rpcTypeComplete)
	default:
		return fmt.Errorf("unknown limit case %q for %s", limitCase, transport)
	}
}

func completeActiveStreamLimit(control, reset func() error) error {
	controlErr := control()
	resetErr := reset()
	return errors.Join(controlErr, resetErr)
}

func (e *environment) runGoLimitsAgainstHarness(
	ctx context.Context,
	repoRoot, language, cell, profile string,
	value variant,
	workload interopprotocol.Workload,
	diagnostics *[]interopprotocol.Diagnostic,
) (interopprotocol.Metrics, error) {
	metrics := interopprotocol.Metrics{}
	for index := 0; index < max(0, workload.LimitChecks-1); index++ {
		limitCase := interopprotocol.LimitCases[index]
		requestID := fmt.Sprintf("%s-limit-%s-%s-%s", cell, limitCase, value.Transport, value.Suite)
		command := interopprotocol.Command{
			V: interopprotocol.Version, Event: "serve", RequestID: requestID,
			Profile: profile, Transport: value.Transport, Suite: value.Suite,
			DeadlineMS: remainingMilliseconds(ctx), Origin: interopOrigin,
			UpstreamURL: e.upstream.URL, Workload: workload,
			ReconnectArtifacts: []interopprotocol.ClientArtifact{},
			LimitArtifacts:     []interopprotocol.LimitArtifact{}, LimitCase: limitCase,
		}
		var clientArtifact interopprotocol.ClientArtifact
		if value.Transport == "direct" {
			credential, _, err := e.directCredential(value.Suite)
			if err != nil {
				return metrics, err
			}
			command.DirectCredential = &credential
		} else {
			clientGrant, serverGrant, err := e.grants(value.Suite)
			if err != nil {
				return metrics, err
			}
			clientArtifact.TunnelGrant = clientGrant
			command.TunnelGrant = serverGrant
		}
		process, ready, err := startHarnessServer(ctx, repoRoot, language, command)
		if err != nil {
			return metrics, err
		}
		if value.Transport == "direct" {
			if ready.DirectInfo == nil {
				return metrics, errors.Join(errors.New("limit server harness omitted direct_info"), process.abort())
			}
			clientArtifact.DirectInfo = ready.DirectInfo
		}
		result, exerciseErr := exerciseGoLimit(ctx, clientArtifact, limitCase, value.Transport, func() {}, diagnostics)
		serverResult, stopErr := process.stop(requestID)
		if stopErr == nil && len(serverResult.Diagnostics) != 0 {
			stopErr = errors.New("limit server harness returned unexpected diagnostics")
		}
		metrics.Sessions += result.Sessions
		metrics.LimitChecks += result.LimitChecks
		metrics.ResourceRejections += result.ResourceRejections
		metrics.BackpressureChecks += result.BackpressureChecks
		if err := errors.Join(exerciseErr, stopErr); err != nil {
			return metrics, fmt.Errorf("limit server check %s: %w", limitCase, err)
		}
	}
	return metrics, nil
}

func expectGoStreamFailure(ctx context.Context, stream io.ReadWriteCloser) error {
	result := make(chan error, 1)
	go func() {
		var one [1]byte
		_, err := stream.Read(one[:])
		result <- err
	}()
	select {
	case err := <-result:
		if err == nil {
			return errors.New("limit stream unexpectedly remained readable")
		}
		return nil
	case <-time.After(time.Second):
		return errors.Join(errors.New("limit stream did not fail before the deadline"), stream.Close())
	case <-ctx.Done():
		return errors.Join(ctx.Err(), stream.Close())
	}
}

func isGoResourceError(err error) bool {
	var clientError *client.Error
	return errors.As(err, &clientError) && clientError.Code == client.CodeResourceExhausted
}

func isGoCloseAfterTermination(err error) bool {
	var clientError *client.Error
	return errors.As(err, &clientError) &&
		clientError.Stage == client.StageClose &&
		clientError.Code == client.CodeNotConnected
}

func isEndpointCloseAfterTermination(err error) bool {
	var endpointError *endpoint.Error
	return errors.As(err, &endpointError) &&
		endpointError.Stage == endpoint.StageClose &&
		endpointError.Code == endpoint.CodeNotConnected
}
