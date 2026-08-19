package sessionv3

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"io"
	"sync"

	"github.com/floegence/flowersec/flowersec-go/v3/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/protocolv3"
)

type handshakeMaterial struct {
	h3               [32]byte
	sessionPRK       [32]byte
	selectedFeatures uint32
}

func performHandshake(ctx context.Context, carrierSession carrier.Session, config Config) (carrier.Stream, handshakeMaterial, error) {
	availableFeatures := carrierFeatures(carrierSession)
	if config.Role == RoleClient {
		control, err := carrierSession.OpenStream(ctx)
		if err != nil {
			return nil, handshakeMaterial{}, handshakeIOError("client", "open control", err)
		}
		stopWatch := watchStreamContext(ctx, control)
		material, err := performClientHandshake(control, config, availableFeatures)
		stopWatch()
		return control, material, err
	}
	control, err := carrierSession.AcceptStream(ctx)
	if err != nil {
		return nil, handshakeMaterial{}, handshakeIOError("server", "accept control", err)
	}
	stopWatch := watchStreamContext(ctx, control)
	material, err := performServerHandshake(control, config, availableFeatures)
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

func performClientHandshake(control carrier.Stream, config Config, availableFeatures uint32) (handshakeMaterial, error) {
	privateKey, publicKey, err := protocolv3.GenerateEphemeralKey(config.Suite, rand.Reader)
	if err != nil {
		return handshakeMaterial{}, err
	}
	var nonce [32]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return handshakeMaterial{}, err
	}
	controlPreface := protocolv3.MarshalControlPreface()
	initMessage := protocolv3.ClientInit{
		Profile: "flowersec/3", ChannelID: config.ChannelID,
		SessionContractHash: config.SessionContractHash, ClientRole: byte(protocolv3.RoleClient),
		Suite: config.Suite, ClientEphemeralPublic: publicKey, NonceC: nonce,
		SelectedFeatures: availableFeatures, MaxInboundStreams: config.MaxInboundStreams,
		ClientAdmissionBinding:   config.LocalAdmissionBinding,
		ClientEndpointInstanceID: config.LocalEndpointInstanceID,
	}
	initRaw, err := protocolv3.MarshalClientInit(initMessage)
	if err != nil {
		return handshakeMaterial{}, err
	}
	if err := writeAll(control, controlPreface); err != nil {
		return handshakeMaterial{}, handshakeIOError("client", "write control preface", err)
	}
	if err := writeAll(control, initRaw); err != nil {
		return handshakeMaterial{}, handshakeIOError("client", "write client init", err)
	}

	serverFrame, err := protocolv3.ReadHandshakeFrame(control)
	if err != nil {
		return handshakeMaterial{}, handshakeIOError("client", "read server finished", err)
	}
	serverFinished, err := protocolv3.ParseServerFinished(serverFrame.Raw, config.Suite)
	if err != nil {
		return handshakeMaterial{}, err
	}
	if err := protocolv3.ValidateServerFinished(serverFinished, handshakeExpectations(config, false, availableFeatures)); err != nil {
		return handshakeMaterial{}, err
	}
	sharedSecret, err := protocolv3.ComputeECDHSharedSecret(config.Suite, privateKey, serverFinished.Core.ServerEphemeralPublic)
	if err != nil {
		return handshakeMaterial{}, err
	}
	handshakePRK, err := protocolv3.DeriveHandshakePRK(config.PSK[:], sharedSecret)
	if err != nil {
		return handshakeMaterial{}, err
	}
	h0, err := protocolv3.ComputeHandshakeH0(controlPreface, initRaw)
	if err != nil {
		return handshakeMaterial{}, err
	}
	serverCore, err := protocolv3.MarshalServerFinishedCore(serverFinished.Core, config.Suite)
	if err != nil {
		return handshakeMaterial{}, err
	}
	h1, err := protocolv3.ComputeHandshakeH1(h0, serverCore)
	if err != nil {
		return handshakeMaterial{}, err
	}
	if !protocolv3.VerifyServerConfirm(handshakePRK, h1, serverFinished.ServerConfirm) {
		return handshakeMaterial{}, protocolv3.ErrAuthentication
	}
	clientCore, err := protocolv3.MarshalClientFinishedCore(serverFinished.Core.HandshakeID)
	if err != nil {
		return handshakeMaterial{}, err
	}
	h2, err := protocolv3.ComputeHandshakeH2(h1, serverFrame.Raw, clientCore)
	if err != nil {
		return handshakeMaterial{}, err
	}
	_, clientConfirm, err := protocolv3.ComputeClientConfirm(handshakePRK, h2)
	if err != nil {
		return handshakeMaterial{}, err
	}
	clientRaw, err := protocolv3.MarshalClientFinished(protocolv3.ClientFinished{
		HandshakeID:   serverFinished.Core.HandshakeID,
		ClientConfirm: clientConfirm,
	})
	if err != nil {
		return handshakeMaterial{}, err
	}
	if err := writeAll(control, clientRaw); err != nil {
		return handshakeMaterial{}, handshakeIOError("client", "write client finished", err)
	}
	h3, err := protocolv3.ComputeHandshakeH3(h2, clientRaw)
	if err != nil {
		return handshakeMaterial{}, err
	}
	return handshakeMaterial{h3: h3, sessionPRK: protocolv3.DeriveSessionPRK(h3, handshakePRK), selectedFeatures: serverFinished.Core.SelectedFeatures}, nil
}

func performServerHandshake(control carrier.Stream, config Config, availableFeatures uint32) (handshakeMaterial, error) {
	controlPreface := make([]byte, protocolv3.ControlPrefaceSize)
	if _, err := io.ReadFull(control, controlPreface); err != nil {
		return handshakeMaterial{}, handshakeIOError("server", "read control preface", err)
	}
	if err := protocolv3.ParseControlPreface(controlPreface); err != nil {
		return handshakeMaterial{}, err
	}
	clientFrame, err := protocolv3.ReadHandshakeFrame(control)
	if err != nil {
		return handshakeMaterial{}, handshakeIOError("server", "read client init", err)
	}
	clientInit, err := protocolv3.ParseClientInit(clientFrame.Raw)
	if err != nil {
		return handshakeMaterial{}, err
	}
	if err := protocolv3.ValidateClientInit(clientInit, handshakeExpectations(config, true, availableFeatures)); err != nil {
		return handshakeMaterial{}, err
	}
	privateKey, publicKey, err := protocolv3.GenerateEphemeralKey(config.Suite, rand.Reader)
	if err != nil {
		return handshakeMaterial{}, err
	}
	sharedSecret, err := protocolv3.ComputeECDHSharedSecret(config.Suite, privateKey, clientInit.ClientEphemeralPublic)
	if err != nil {
		return handshakeMaterial{}, err
	}
	handshakePRK, err := protocolv3.DeriveHandshakePRK(config.PSK[:], sharedSecret)
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
	server := protocolv3.ServerFinished{Core: protocolv3.ServerFinishedCore{
		Suite: config.Suite, HandshakeID: handshakeID,
		ServerEphemeralPublic: publicKey, NonceS: nonce,
		SessionContractHash: config.SessionContractHash,
		SelectedFeatures:    clientInit.SelectedFeatures & availableFeatures, MaxInboundStreams: config.MaxInboundStreams,
		ServerAdmissionBinding:   config.LocalAdmissionBinding,
		ServerEndpointInstanceID: config.LocalEndpointInstanceID,
	}}
	h0, err := protocolv3.ComputeHandshakeH0(controlPreface, clientFrame.Raw)
	if err != nil {
		return handshakeMaterial{}, err
	}
	serverCore, err := protocolv3.MarshalServerFinishedCore(server.Core, config.Suite)
	if err != nil {
		return handshakeMaterial{}, err
	}
	h1, err := protocolv3.ComputeHandshakeH1(h0, serverCore)
	if err != nil {
		return handshakeMaterial{}, err
	}
	_, server.ServerConfirm, err = protocolv3.ComputeServerConfirm(handshakePRK, h1)
	if err != nil {
		return handshakeMaterial{}, err
	}
	serverRaw, err := protocolv3.MarshalServerFinished(server, config.Suite)
	if err != nil {
		return handshakeMaterial{}, err
	}
	if err := writeAll(control, serverRaw); err != nil {
		return handshakeMaterial{}, handshakeIOError("server", "write server finished", err)
	}

	clientFinishedFrame, err := protocolv3.ReadHandshakeFrame(control)
	if err != nil {
		return handshakeMaterial{}, handshakeIOError("server", "read client finished", err)
	}
	clientFinished, err := protocolv3.ParseClientFinished(clientFinishedFrame.Raw)
	if err != nil {
		return handshakeMaterial{}, err
	}
	if len(clientFinished.HandshakeID) != len(handshakeID) || subtle.ConstantTimeCompare(clientFinished.HandshakeID, handshakeID) != 1 {
		return handshakeMaterial{}, fmt.Errorf("handshake ID mismatch")
	}
	clientCore, err := protocolv3.MarshalClientFinishedCore(clientFinished.HandshakeID)
	if err != nil {
		return handshakeMaterial{}, err
	}
	h2, err := protocolv3.ComputeHandshakeH2(h1, serverRaw, clientCore)
	if err != nil {
		return handshakeMaterial{}, err
	}
	if !protocolv3.VerifyClientConfirm(handshakePRK, h2, clientFinished.ClientConfirm) {
		return handshakeMaterial{}, protocolv3.ErrAuthentication
	}
	h3, err := protocolv3.ComputeHandshakeH3(h2, clientFinishedFrame.Raw)
	if err != nil {
		return handshakeMaterial{}, err
	}
	return handshakeMaterial{h3: h3, sessionPRK: protocolv3.DeriveSessionPRK(h3, handshakePRK), selectedFeatures: server.Core.SelectedFeatures}, nil
}

func handshakeIOError(role, operation string, err error) error {
	return fmt.Errorf("%s handshake %s: %w", role, operation, err)
}

func handshakeExpectations(config Config, peerIsClient bool, availableFeatures uint32) protocolv3.HandshakeExpectations {
	path := protocolv3.HandshakeDirect
	if config.Path == PathTunnel {
		path = protocolv3.HandshakeTunnel
	}
	expectation := protocolv3.HandshakeExpectations{
		Path: path, SessionContractHash: config.SessionContractHash,
		Suite: config.Suite, MaxInboundStreams: config.MaxInboundStreams,
		AdmissionBinding:           config.PeerAdmissionBinding,
		ExpectedEndpointInstanceID: config.ExpectedPeerEndpointInstanceID,
		AvailableFeatures:          availableFeatures,
	}
	if peerIsClient {
		expectation.ChannelID = config.ChannelID
	}
	return expectation
}

func carrierFeatures(carrierSession carrier.Session) uint32 {
	unreliable, ok := carrierSession.(carrier.UnreliableTransport)
	if ok && unreliable.UnreliableAvailable() {
		return protocolv3.FeatureUnreliableMessages
	}
	return 0
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
