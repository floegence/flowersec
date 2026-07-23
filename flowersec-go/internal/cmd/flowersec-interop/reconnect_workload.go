package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/client"
	"github.com/floegence/flowersec/flowersec-go/v2/endpoint"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/interopprotocol"
	"github.com/floegence/flowersec/flowersec-go/v2/protocolio"
	"github.com/floegence/flowersec/flowersec-go/v2/reconnect"
	"github.com/gorilla/websocket"
)

type goPeer struct {
	artifact interopprotocol.ClientArtifact
	done     <-chan error
	cancel   context.CancelFunc
	close    func()
	started  atomic.Bool
}

type harnessPeer struct {
	process   *harnessProcess
	requestID string
	artifact  interopprotocol.ClientArtifact
}

func (e *environment) startGoPeer(ctx context.Context, value variant, workload interopprotocol.Workload) (*goPeer, error) {
	return e.startGoPeerWithService(
		ctx,
		value,
		serverYamuxLimits(workload),
		func(serviceCtx context.Context, session endpoint.Session) error {
			return e.serveReferenceSession(serviceCtx, session, workload)
		},
	)
}

func (e *environment) startGoPeerWithService(
	ctx context.Context,
	value variant,
	yamuxLimits endpoint.YamuxLimits,
	service func(context.Context, endpoint.Session) error,
) (*goPeer, error) {
	peerCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	peer := &goPeer{done: done, cancel: cancel, close: func() {}}
	switch value.Transport {
	case "direct":
		credential, info, err := e.directCredential(value.Suite)
		if err != nil {
			cancel()
			return nil, err
		}
		upgrader := websocket.Upgrader{CheckOrigin: func(request *http.Request) bool {
			return request.Header.Get("Origin") == interopOrigin
		}}
		directServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			peer.started.Store(true)
			connection, upgradeErr := upgrader.Upgrade(writer, request, nil)
			if upgradeErr != nil {
				done <- fmt.Errorf("upgrade reconnect WebSocket: %w", upgradeErr)
				return
			}
			defer connection.Close()
			session, acceptErr := endpoint.AcceptDirectWS(peerCtx, connection, endpoint.AcceptDirectOptions{
				ChannelID: credential.ChannelID, Suite: endpoint.Suite(credential.Suite),
				PSK: mustDecodePSK(credential.PSK), InitExpireAtUnixS: credential.InitExpiresAtUnix,
				ClockSkew: 30 * time.Second, YamuxLimits: yamuxLimits,
			})
			if acceptErr != nil {
				done <- acceptErr
				return
			}
			done <- service(peerCtx, session)
		}))
		info.WsUrl = "ws" + strings.TrimPrefix(directServer.URL, "http")
		peer.artifact = interopprotocol.ClientArtifact{DirectInfo: info}
		peer.close = directServer.Close
	case "tunnel":
		clientGrant, serverGrant, err := e.grants(value.Suite)
		if err != nil {
			cancel()
			return nil, err
		}
		peer.artifact = interopprotocol.ClientArtifact{TunnelGrant: clientGrant}
		peer.started.Store(true)
		go func() {
			session, connectErr := endpoint.ConnectTunnel(peerCtx, serverGrant,
				endpoint.WithOrigin(interopOrigin),
				endpoint.WithTransportSecurityPolicy(endpoint.AllowPlaintextForLoopback),
				endpoint.WithLivenessDisabled(),
				// Fleet peers are prestarted before the primary workload and can wait past the default timeout.
				endpoint.WithHandshakeTimeout(30*time.Second),
				endpoint.WithYamuxLimits(yamuxLimits),
			)
			if connectErr != nil {
				done <- connectErr
				return
			}
			done <- service(peerCtx, session)
		}()
	default:
		cancel()
		return nil, fmt.Errorf("unsupported reconnect transport %q", value.Transport)
	}
	return peer, nil
}

func (peer *goPeer) wait(ctx context.Context) error {
	if peer == nil {
		return nil
	}
	err := waitServer(peer.done, ctx)
	peer.cancel()
	peer.close()
	return err
}

func closeGoPeers(peers []*goPeer) {
	for _, peer := range peers {
		peer.cancel()
		peer.close()
	}
}

func abortGoPeerFleet(ctx context.Context, peers []*goPeer) error {
	var combined error
	for _, peer := range peers {
		peer.cancel()
		peer.close()
		if peer.started.Load() {
			joinedError(&combined, waitServer(peer.done, ctx))
		}
	}
	return combined
}

func (e *environment) startGoPeerFleet(ctx context.Context, value variant, workload interopprotocol.Workload) ([]*goPeer, []interopprotocol.ClientArtifact, error) {
	count := workload.ReconnectCycles + 1
	peers := make([]*goPeer, 0, count)
	artifacts := make([]interopprotocol.ClientArtifact, 0, count)
	for range count {
		peer, err := e.startGoPeer(ctx, value, workload)
		if err != nil {
			closeGoPeers(peers)
			return nil, nil, err
		}
		peers = append(peers, peer)
		artifacts = append(artifacts, peer.artifact)
	}
	return peers, artifacts, nil
}

func (e *environment) runGoReconnect(ctx context.Context, value variant, workload interopprotocol.Workload) (interopprotocol.Metrics, error) {
	peers, artifacts, err := e.startGoPeerFleet(ctx, value, workload)
	if err != nil {
		return interopprotocol.Metrics{}, err
	}
	metrics, exerciseErr := exerciseGoReconnect(ctx, artifacts, workload.ReconnectCycles)
	peerErr := waitGoPeerFleet(ctx, peers)
	return metrics, errors.Join(exerciseErr, peerErr)
}

func exerciseGoReconnect(ctx context.Context, materials []interopprotocol.ClientArtifact, cycles int) (metrics interopprotocol.Metrics, returnErr error) {
	artifacts := make([]*protocolio.ConnectArtifact, 0, len(materials))
	for index, material := range materials {
		artifact, err := goConnectArtifact(material)
		if err != nil {
			return interopprotocol.Metrics{}, fmt.Errorf("reconnect artifact %d: %w", index, err)
		}
		artifacts = append(artifacts, artifact)
	}
	var sourceMu sync.Mutex
	nextArtifact := 0
	source := reconnect.RefreshableSource(func(context.Context, reconnect.AcquireContext) (*protocolio.ConnectArtifact, error) {
		sourceMu.Lock()
		defer sourceMu.Unlock()
		if nextArtifact >= len(artifacts) {
			return nil, errors.New("reconnect artifact sequence exhausted")
		}
		artifact := artifacts[nextArtifact]
		nextArtifact++
		return artifact, nil
	})
	manager := reconnect.NewManager()
	defer func() {
		returnErr = errors.Join(returnErr, manager.Disconnect())
	}()
	settings := reconnect.DefaultSettings()
	settings.Enabled = true
	settings.MaxAttempts = 1
	settings.InitialDelay = 0
	settings.MaxDelay = 0
	settings.Factor = 1
	settings.JitterRatio = 0
	if err := manager.Connect(ctx, reconnect.Config{
		Source: source,
		ConnectOptions: []client.ConnectOption{
			client.WithOrigin(interopOrigin),
			client.WithTransportSecurityPolicy(client.AllowPlaintextForLoopback),
			client.WithLivenessDisabled(),
		},
		Reconnect: settings,
	}); err != nil {
		return interopprotocol.Metrics{}, err
	}
	metrics = interopprotocol.Metrics{Sessions: 1}
	for index := 0; index < cycles; index++ {
		previous := manager.State().Client
		if previous == nil {
			return metrics, errors.New("reconnect manager has no connected client")
		}
		if err := rpcControl(ctx, previous, rpcTypeDisconnect); err != nil {
			return metrics, fmt.Errorf("force reconnect %d: %w", index, err)
		}
		connected, err := waitForGoReconnect(ctx, manager, previous)
		if err != nil {
			return metrics, fmt.Errorf("wait for reconnect %d: %w", index, err)
		}
		if err := rpcEcho(ctx, connected, index, false); err != nil {
			return metrics, fmt.Errorf("post-reconnect RPC %d: %w", index, err)
		}
		metrics.Sessions++
		metrics.Reconnects++
	}
	finalClient := manager.State().Client
	if finalClient == nil {
		return metrics, errors.New("reconnect manager lost the final client")
	}
	if err := rpcControl(ctx, finalClient, rpcTypeComplete); err != nil {
		return metrics, fmt.Errorf("complete reconnect session: %w", err)
	}
	return metrics, nil
}

func waitForGoReconnect(ctx context.Context, manager *reconnect.Manager, previous client.Client) (client.Client, error) {
	states, unsubscribe := manager.Subscribe()
	defer unsubscribe()
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case state, ok := <-states:
			if !ok {
				return nil, errors.New("reconnect state stream closed")
			}
			if state.Status == reconnect.StatusError {
				return nil, state.Error
			}
			if state.Status == reconnect.StatusConnected && state.Client != nil && state.Client != previous {
				return state.Client, nil
			}
		}
	}
}

func goConnectArtifact(material interopprotocol.ClientArtifact) (*protocolio.ConnectArtifact, error) {
	switch {
	case material.DirectInfo != nil && material.TunnelGrant == nil:
		return &protocolio.ConnectArtifact{V: 1, Transport: protocolio.ConnectArtifactTransportDirect, DirectInfo: material.DirectInfo}, nil
	case material.TunnelGrant != nil && material.DirectInfo == nil:
		return &protocolio.ConnectArtifact{V: 1, Transport: protocolio.ConnectArtifactTransportTunnel, TunnelGrant: material.TunnelGrant}, nil
	default:
		return nil, errors.New("ambiguous reconnect artifact")
	}
}

func waitGoPeerFleet(ctx context.Context, peers []*goPeer) error {
	var combined error
	for _, peer := range peers {
		joinedError(&combined, peer.wait(ctx))
	}
	return combined
}

func (e *environment) runGoReconnectAgainstHarness(
	ctx context.Context,
	repoRoot, language, cell, profile string,
	value variant,
	workload interopprotocol.Workload,
) (interopprotocol.Metrics, error) {
	peers := make([]*harnessPeer, 0, workload.ReconnectCycles+1)
	for index := 0; index < workload.ReconnectCycles+1; index++ {
		requestID := fmt.Sprintf("%s-reconnect-%d-%s-%s", cell, index, value.Transport, value.Suite)
		command := interopprotocol.Command{
			V: interopprotocol.Version, Event: "serve", RequestID: requestID,
			Profile: profile, Transport: value.Transport, Suite: value.Suite,
			DeadlineMS: remainingMilliseconds(ctx), Origin: interopOrigin,
			UpstreamURL: e.upstream.URL, Workload: workload,
			ReconnectArtifacts: []interopprotocol.ClientArtifact{},
			LimitArtifacts:     []interopprotocol.LimitArtifact{},
		}
		var clientArtifact interopprotocol.ClientArtifact
		if value.Transport == "direct" {
			credential, _, err := e.directCredential(value.Suite)
			if err != nil {
				return interopprotocol.Metrics{}, errors.Join(err, abortHarnessPeers(peers))
			}
			command.DirectCredential = &credential
		} else {
			clientGrant, serverGrant, err := e.grants(value.Suite)
			if err != nil {
				return interopprotocol.Metrics{}, errors.Join(err, abortHarnessPeers(peers))
			}
			clientArtifact.TunnelGrant = clientGrant
			command.TunnelGrant = serverGrant
		}
		process, ready, err := startHarnessServer(ctx, repoRoot, language, command)
		if err != nil {
			return interopprotocol.Metrics{}, errors.Join(err, abortHarnessPeers(peers))
		}
		if value.Transport == "direct" {
			if ready.DirectInfo == nil {
				return interopprotocol.Metrics{}, errors.Join(
					errors.New("reconnect server harness omitted direct_info"),
					process.abort(),
					abortHarnessPeers(peers),
				)
			}
			clientArtifact.DirectInfo = ready.DirectInfo
		}
		peers = append(peers, &harnessPeer{process: process, requestID: requestID, artifact: clientArtifact})
	}
	artifacts := make([]interopprotocol.ClientArtifact, 0, len(peers))
	for _, peer := range peers {
		artifacts = append(artifacts, peer.artifact)
	}
	metrics, exerciseErr := exerciseGoReconnect(ctx, artifacts, workload.ReconnectCycles)
	stopErr := stopHarnessPeers(peers)
	return metrics, errors.Join(exerciseErr, stopErr)
}

func abortHarnessPeers(peers []*harnessPeer) error {
	var combined error
	for _, peer := range peers {
		joinedError(&combined, peer.process.abort())
	}
	return combined
}

func stopHarnessPeers(peers []*harnessPeer) error {
	var combined error
	for _, peer := range peers {
		result, err := peer.process.stop(peer.requestID)
		if err == nil && len(result.Diagnostics) != 0 {
			err = errors.New("reconnect server harness returned unexpected diagnostics")
		}
		joinedError(&combined, err)
	}
	return combined
}
