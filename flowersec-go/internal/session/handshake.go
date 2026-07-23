package session

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"io"
	"sync"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/protocolv2"
)

type handshakeMaterial struct {
	h3         [32]byte
	sessionPRK [32]byte
}

func performHandshake(ctx context.Context, carrierSession carrier.Session, config Config) (carrier.Stream, handshakeMaterial, error) {
	if config.Role == RoleClient {
		control, err := carrierSession.OpenStream(ctx)
		if err != nil {
			return nil, handshakeMaterial{}, err
		}
		stopWatch := watchStreamContext(ctx, control)
		material, err := performClientHandshake(control, config)
		stopWatch()
		return control, material, err
	}
	control, err := carrierSession.AcceptStream(ctx)
	if err != nil {
		return nil, handshakeMaterial{}, err
	}
	stopWatch := watchStreamContext(ctx, control)
	material, err := performServerHandshake(control, config)
	stopWatch()
	return control, material, err
}

func watchStreamContext(ctx context.Context, stream carrier.Stream) func() {
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		select {
		case <-ctx.Done():
			_ = stream.Reset()
		case <-done:
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() { close(done) })
		<-stopped
	}
}

func performClientHandshake(control carrier.Stream, config Config) (handshakeMaterial, error) {
	privateKey, publicKey, err := protocolv2.GenerateEphemeralKey(config.Suite, rand.Reader)
	if err != nil {
		return handshakeMaterial{}, err
	}
	var nonce [32]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return handshakeMaterial{}, err
	}
	fsc2 := protocolv2.MarshalControlPreface()
	initMessage := protocolv2.ClientInit{
		Profile: "flowersec/2", ChannelID: config.ChannelID,
		SessionContractHash: config.SessionContractHash, ClientRole: byte(protocolv2.RoleClient),
		Suite: config.Suite, ClientEphemeralPublic: publicKey, NonceC: nonce,
		SelectedFeatures: 0, MaxInboundStreams: config.MaxInboundStreams,
		ClientAdmissionBinding:   config.LocalAdmissionBinding,
		ClientEndpointInstanceID: config.LocalEndpointInstanceID,
	}
	initRaw, err := protocolv2.MarshalClientInit(initMessage)
	if err != nil {
		return handshakeMaterial{}, err
	}
	if err := writeAll(control, fsc2); err != nil {
		return handshakeMaterial{}, err
	}
	if err := writeAll(control, initRaw); err != nil {
		return handshakeMaterial{}, err
	}

	serverFrame, err := protocolv2.ReadHandshakeFrame(control)
	if err != nil {
		return handshakeMaterial{}, err
	}
	serverFinished, err := protocolv2.ParseServerFinished(serverFrame.Raw, config.Suite)
	if err != nil {
		return handshakeMaterial{}, err
	}
	if err := protocolv2.ValidateServerFinished(serverFinished, handshakeExpectations(config, false)); err != nil {
		return handshakeMaterial{}, err
	}
	sharedSecret, err := protocolv2.ComputeECDHSharedSecret(config.Suite, privateKey, serverFinished.Core.ServerEphemeralPublic)
	if err != nil {
		return handshakeMaterial{}, err
	}
	handshakePRK, err := protocolv2.DeriveHandshakePRK(config.PSK[:], sharedSecret)
	if err != nil {
		return handshakeMaterial{}, err
	}
	h0, err := protocolv2.ComputeHandshakeH0(fsc2, initRaw)
	if err != nil {
		return handshakeMaterial{}, err
	}
	serverCore, err := protocolv2.MarshalServerFinishedCore(serverFinished.Core, config.Suite)
	if err != nil {
		return handshakeMaterial{}, err
	}
	h1, err := protocolv2.ComputeHandshakeH1(h0, serverCore)
	if err != nil {
		return handshakeMaterial{}, err
	}
	if !protocolv2.VerifyServerConfirm(handshakePRK, h1, serverFinished.ServerConfirm) {
		return handshakeMaterial{}, protocolv2.ErrAuthentication
	}
	clientCore, err := protocolv2.MarshalClientFinishedCore(serverFinished.Core.HandshakeID)
	if err != nil {
		return handshakeMaterial{}, err
	}
	h2, err := protocolv2.ComputeHandshakeH2(h1, serverFrame.Raw, clientCore)
	if err != nil {
		return handshakeMaterial{}, err
	}
	_, clientConfirm, err := protocolv2.ComputeClientConfirm(handshakePRK, h2)
	if err != nil {
		return handshakeMaterial{}, err
	}
	clientRaw, err := protocolv2.MarshalClientFinished(protocolv2.ClientFinished{
		HandshakeID:   serverFinished.Core.HandshakeID,
		ClientConfirm: clientConfirm,
	})
	if err != nil {
		return handshakeMaterial{}, err
	}
	if err := writeAll(control, clientRaw); err != nil {
		return handshakeMaterial{}, err
	}
	h3, err := protocolv2.ComputeHandshakeH3(h2, clientRaw)
	if err != nil {
		return handshakeMaterial{}, err
	}
	return handshakeMaterial{h3: h3, sessionPRK: protocolv2.DeriveSessionPRK(h3, handshakePRK)}, nil
}

func performServerHandshake(control carrier.Stream, config Config) (handshakeMaterial, error) {
	fsc2 := make([]byte, protocolv2.ControlPrefaceSize)
	if _, err := io.ReadFull(control, fsc2); err != nil {
		return handshakeMaterial{}, err
	}
	if err := protocolv2.ParseControlPreface(fsc2); err != nil {
		return handshakeMaterial{}, err
	}
	clientFrame, err := protocolv2.ReadHandshakeFrame(control)
	if err != nil {
		return handshakeMaterial{}, err
	}
	clientInit, err := protocolv2.ParseClientInit(clientFrame.Raw)
	if err != nil {
		return handshakeMaterial{}, err
	}
	if err := protocolv2.ValidateClientInit(clientInit, handshakeExpectations(config, true)); err != nil {
		return handshakeMaterial{}, err
	}
	privateKey, publicKey, err := protocolv2.GenerateEphemeralKey(config.Suite, rand.Reader)
	if err != nil {
		return handshakeMaterial{}, err
	}
	sharedSecret, err := protocolv2.ComputeECDHSharedSecret(config.Suite, privateKey, clientInit.ClientEphemeralPublic)
	if err != nil {
		return handshakeMaterial{}, err
	}
	handshakePRK, err := protocolv2.DeriveHandshakePRK(config.PSK[:], sharedSecret)
	if err != nil {
		return handshakeMaterial{}, err
	}
	var nonce [32]byte
	handshakeID := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return handshakeMaterial{}, err
	}
	if _, err := io.ReadFull(rand.Reader, handshakeID); err != nil {
		return handshakeMaterial{}, err
	}
	server := protocolv2.ServerFinished{Core: protocolv2.ServerFinishedCore{
		Suite: config.Suite, HandshakeID: handshakeID,
		ServerEphemeralPublic: publicKey, NonceS: nonce,
		SessionContractHash: config.SessionContractHash,
		SelectedFeatures:    0, MaxInboundStreams: config.MaxInboundStreams,
		ServerAdmissionBinding:   config.LocalAdmissionBinding,
		ServerEndpointInstanceID: config.LocalEndpointInstanceID,
	}}
	h0, err := protocolv2.ComputeHandshakeH0(fsc2, clientFrame.Raw)
	if err != nil {
		return handshakeMaterial{}, err
	}
	serverCore, err := protocolv2.MarshalServerFinishedCore(server.Core, config.Suite)
	if err != nil {
		return handshakeMaterial{}, err
	}
	h1, err := protocolv2.ComputeHandshakeH1(h0, serverCore)
	if err != nil {
		return handshakeMaterial{}, err
	}
	_, server.ServerConfirm, err = protocolv2.ComputeServerConfirm(handshakePRK, h1)
	if err != nil {
		return handshakeMaterial{}, err
	}
	serverRaw, err := protocolv2.MarshalServerFinished(server, config.Suite)
	if err != nil {
		return handshakeMaterial{}, err
	}
	if err := writeAll(control, serverRaw); err != nil {
		return handshakeMaterial{}, err
	}

	clientFinishedFrame, err := protocolv2.ReadHandshakeFrame(control)
	if err != nil {
		return handshakeMaterial{}, err
	}
	clientFinished, err := protocolv2.ParseClientFinished(clientFinishedFrame.Raw)
	if err != nil {
		return handshakeMaterial{}, err
	}
	if len(clientFinished.HandshakeID) != len(handshakeID) || subtle.ConstantTimeCompare(clientFinished.HandshakeID, handshakeID) != 1 {
		return handshakeMaterial{}, fmt.Errorf("handshake ID mismatch")
	}
	clientCore, err := protocolv2.MarshalClientFinishedCore(clientFinished.HandshakeID)
	if err != nil {
		return handshakeMaterial{}, err
	}
	h2, err := protocolv2.ComputeHandshakeH2(h1, serverRaw, clientCore)
	if err != nil {
		return handshakeMaterial{}, err
	}
	if !protocolv2.VerifyClientConfirm(handshakePRK, h2, clientFinished.ClientConfirm) {
		return handshakeMaterial{}, protocolv2.ErrAuthentication
	}
	h3, err := protocolv2.ComputeHandshakeH3(h2, clientFinishedFrame.Raw)
	if err != nil {
		return handshakeMaterial{}, err
	}
	return handshakeMaterial{h3: h3, sessionPRK: protocolv2.DeriveSessionPRK(h3, handshakePRK)}, nil
}

func handshakeExpectations(config Config, peerIsClient bool) protocolv2.HandshakeExpectations {
	path := protocolv2.HandshakeDirect
	if config.Path == PathTunnel {
		path = protocolv2.HandshakeTunnel
	}
	expectation := protocolv2.HandshakeExpectations{
		Path: path, SessionContractHash: config.SessionContractHash,
		Suite: config.Suite, MaxInboundStreams: config.MaxInboundStreams,
		AdmissionBinding:           config.PeerAdmissionBinding,
		ExpectedEndpointInstanceID: config.ExpectedPeerEndpointInstanceID,
	}
	if peerIsClient {
		expectation.ChannelID = config.ChannelID
	}
	return expectation
}

func (s *engineSession) finishReadyBoundary() error {
	if s.config.Role == RoleServer {
		if err := s.sendControl(protocolv2.InnerSessionReady, nil); err != nil {
			return err
		}
		typ, _, err := s.readControl()
		if err != nil {
			return err
		}
		if typ != protocolv2.InnerSessionReadyACK {
			return ErrSessionProtocol
		}
		return nil
	}
	typ, _, err := s.readControl()
	if err != nil {
		return err
	}
	if typ != protocolv2.InnerSessionReady {
		return ErrSessionProtocol
	}
	return s.sendControl(protocolv2.InnerSessionReadyACK, nil)
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) != 0 {
		n, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(payload) {
			return io.ErrShortWrite
		}
		payload = payload[n:]
	}
	return nil
}
