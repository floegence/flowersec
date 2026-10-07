package controlv4

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

const registeredControlBodyLimit = 262144
const registeredControlDomain = "flowersec/original-tunnel-control/1\x00"

// RegisteredControlConfig is immutable installed application control input.
// The peer material does not select its TLS identity, authority or endpoint.
// HTTPS names the complete /flowersec/control/live endpoint and a separately
// resolved numeric address. The signer's actual lifetime belongs to Dependencies.
type RegisteredControlConfig struct {
	HTTPS            HTTPSBootstrapConfig
	Authority        string
	Tenant, Audience string
	Parent           [32]byte
	Candidate        uint64
	Incarnation      []byte
	Identity         protocolv4.MapSigner
	// Relay belongs to this same original endpoint and has separate prepaid
	// native/control backing. Nil preserves the local authority/relay path.
	Relay        *RegisteredEndpointRelay
	RuntimeBytes uint64
	// EndpointPath selects the registered control resource. Empty derives it from HTTPS.BaseURL.
	EndpointPath string
}

// RegisteredControlPayload is the application envelope shared by registered
// current peers. Original signed maps remain opaque canonical byte strings.
type RegisteredControlPayload struct {
	Kind           string                              `json:"kind"`
	Incarnation    string                              `json:"incarnation"`
	Parent         string                              `json:"parent"`
	Candidate      uint64                              `json:"candidate"`
	Recipient      string                              `json:"recipient,omitempty"`
	Attempt        string                              `json:"attempt,omitempty"`
	Activation     string                              `json:"activation,omitempty"`
	Grant          string                              `json:"grant,omitempty"`
	Continuation   string                              `json:"continuation,omitempty"`
	Authentication string                              `json:"authentication,omitempty"`
	Signature      string                              `json:"signature,omitempty"`
	Request        *RegisteredLiveAuthorizationRequest `json:"request,omitempty"`
}

type RegisteredControlReply struct {
	Incarnation  string `json:"incarnation"`
	Authority    string `json:"authority"`
	ClientGrant  string `json:"clientGrant,omitempty"`
	ServerGrant  string `json:"serverGrant,omitempty"`
	Delivered    bool   `json:"delivered,omitempty"`
	Matched      bool   `json:"matched,omitempty"`
	Prepared     bool   `json:"prepared,omitempty"`
	Registered   bool   `json:"registered,omitempty"`
	Reserved     bool   `json:"reserved,omitempty"`
	Attempt      string `json:"attempt,omitempty"`
	Activation   string `json:"activation,omitempty"`
	Grant        string `json:"grant,omitempty"`
	Continuation string `json:"continuation,omitempty"`
	Lease        string `json:"lease,omitempty"`
	Projection   string `json:"projection,omitempty"`
}

// RegisteredControlTransport owns one physical request at a time. Close fences
// publication and interrupts the actual socket. Cleanup joins its original
// TLS/caller observer before retiring backing, including a late callback return.
// It never retries, queues, pools, follows redirects, or dispatches detached work.
type RegisteredControlTransport struct {
	mu                                                                    sync.Mutex
	config                                                                RegisteredControlConfig
	endpointPath                                                          string
	provider                                                              *HTTPSBootstrapProvider
	reservation, dependencies                                             resourcev4.Reference
	response                                                              []byte
	decoder                                                               *protocolv4.Decoder
	liveUsed, liveBusy                                                    bool
	liveRegistered, liveMaterialTaken, liveAcknowledged, liveServerFailed bool
	liveAttempt                                                           [16]byte
	liveCancel                                                            context.CancelFunc
	cancel                                                                context.CancelFunc
	done                                                                  chan struct{}
	busy, closed, cleaned                                                 bool
}

func RegisteredControlTransportCharge(c RegisteredControlConfig) (resourcev4.Vector, error) {
	if c.Identity == nil || len(c.Identity.PublicKey()) != ed25519.PublicKeySize || c.Parent == ([32]byte{}) || c.Candidate >= 16 || len(c.Incarnation) != 16 && len(c.Incarnation) != 32 || c.Authority == "" || len(c.Authority) > 128 || c.RuntimeBytes == 0 || c.HTTPS.TLS == nil || len(c.HTTPS.TLS.Certificates) == 0 || c.HTTPS.TLS.GetClientCertificate != nil {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	if c.Relay != nil {
		role := protocolv4.ClientToServer
		if len(c.Incarnation) == 16 {
			role = protocolv4.ServerToClient
		}
		if !c.Relay.MatchesBinding(c.Parent, c.Candidate, role) || len(c.HTTPS.TLS.Certificates[0].Certificate) == 0 || !c.Relay.MatchesEndpointLeaf(c.HTTPS.TLS.Certificates[0].Certificate[0]) {
			return resourcev4.Vector{}, resourcev4.ErrOwner
		}
	}
	if _, err := HTTPSBootstrapCharge(c.HTTPS); err != nil {
		return resourcev4.Vector{}, err
	}
	endpoint, err := url.Parse(c.HTTPS.BaseURL)
	path := c.EndpointPath
	if path == "" && err == nil {
		path = endpoint.Path
	}
	if (path != "/flowersec/control/live" && path != "/flowersec/control/tunnel") || err != nil || endpoint.Path != path || endpoint.RawPath != "" || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	if path == "/flowersec/control/tunnel" && (len(c.Incarnation) != 32 || c.Relay != nil) {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	// The bound includes JSON/base64/signature copies, the complete response,
	// and decoder backing. TLS/native backing is admitted separately below.
	decoderBytes, err := protocolv4.DecoderBackingBytes(liveTunnelMaterialLimit(), 4)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(RegisteredControlTransport{})) + 4*registeredControlBodyLimit + c.RuntimeBytes + decoderBytes, resourcev4.Items: 1, resourcev4.WorkSlots: 1, resourcev4.Tasks: 1, resourcev4.Timers: 1}, nil
}

func NewRegisteredControlTransport(c RegisteredControlConfig, reservation, providerReservation, dependencies resourcev4.Reference) (*RegisteredControlTransport, error) {
	charge, err := RegisteredControlTransportCharge(c)
	if err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(providerReservation); err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(dependencies); err != nil {
		return nil, err
	}
	if c.Relay != nil {
		if err = c.Relay.CheckEnvironment(reservation); err != nil {
			return nil, err
		}
	}
	shared, err := dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		shared.Release()
		return nil, err
	}
	borrow, err := dependencies.Borrow()
	if err != nil {
		owned.Release()
		shared.Release()
		return nil, err
	}
	endpoint, _ := url.Parse(c.HTTPS.BaseURL)
	endpointPath := c.EndpointPath
	if endpointPath == "" {
		endpointPath = endpoint.Path
	}
	endpoint.Path = ""
	transportConfig := c.HTTPS
	transportConfig.BaseURL = endpoint.String()
	transportConfig.TLS = c.HTTPS.TLS.Clone()
	transportConfig.TLS.MinVersion, transportConfig.TLS.MaxVersion = tls.VersionTLS13, tls.VersionTLS13
	transportConfig.TLS.SessionTicketsDisabled = true
	transportConfig.TLS.ClientSessionCache = nil
	provider, err := NewHTTPSBootstrapProvider(transportConfig, providerReservation, borrow)
	borrow.Release()
	if err != nil {
		owned.Release()
		shared.Release()
		return nil, err
	}
	decoder, err := protocolv4.NewDecoder(liveTunnelMaterialLimit(), 4)
	if err != nil {
		provider.Close()
		_ = provider.Retire()
		owned.Release()
		shared.Release()
		return nil, err
	}
	c.Authority = strings.Clone(c.Authority)
	c.Tenant = strings.Clone(c.Tenant)
	c.Audience = strings.Clone(c.Audience)
	c.Incarnation = append([]byte(nil), c.Incarnation...)
	c.HTTPS = HTTPSBootstrapConfig{}
	return &RegisteredControlTransport{config: c, endpointPath: endpointPath, provider: provider, decoder: decoder, reservation: owned, dependencies: shared, response: make([]byte, registeredControlBodyLimit), done: make(chan struct{})}, nil
}

func (p *RegisteredControlTransport) Payload(kind string) RegisteredControlPayload {
	if p == nil {
		return RegisteredControlPayload{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return RegisteredControlPayload{Kind: kind, Incarnation: base64.StdEncoding.EncodeToString(p.config.Incarnation), Parent: base64.StdEncoding.EncodeToString(p.config.Parent[:]), Candidate: p.config.Candidate}
}

func (p *RegisteredControlTransport) Call(ctx context.Context, payload RegisteredControlPayload, guard func() error) (reply RegisteredControlReply, err error) {
	return p.call(ctx, payload, guard, "")
}

// CallTunnel sends one signed request to the registered pool tunnel endpoint.
// It shares the live transport state machine and retains its no-retry contract.
func (p *RegisteredControlTransport) CallTunnel(ctx context.Context, payload RegisteredControlPayload, guard func() error) (reply RegisteredControlReply, err error) {
	return p.call(ctx, payload, guard, "/flowersec/control/tunnel")
}

// PrepareRegisteredTunnel requests the one original pool issuance. The caller
// must verify the returned grants against its independently installed pool
// authority before admitting either Grant.
func (p *RegisteredControlTransport) PrepareRegisteredTunnel(ctx context.Context, candidate uint64, guard func() error) (reply RegisteredControlReply, err error) {
	payload := p.Payload("prepare")
	payload.Candidate = candidate
	return p.CallTunnel(ctx, payload, guard)
}

// AcknowledgeRegisteredTunnelPreparation confirms verified material installation
// using the exact server Grant digest and original continuation. It performs no
// native preparation, Allow delivery or admission and is a single no-retry call.
func (p *RegisteredControlTransport) AcknowledgeRegisteredTunnelPreparation(ctx context.Context, candidate uint64, grantDigest, continuation []byte, guard func() error) (reply RegisteredControlReply, err error) {
	payload := p.Payload("prepared_ack")
	payload.Candidate = candidate
	payload.Grant = base64.StdEncoding.EncodeToString(grantDigest)
	payload.Continuation = base64.StdEncoding.EncodeToString(continuation)
	return p.CallTunnel(ctx, payload, guard)
}

// ContinueRegisteredTunnelWinner consumes the acknowledged continuation once.
func (p *RegisteredControlTransport) ContinueRegisteredTunnelWinner(ctx context.Context, candidate uint64, continuation []byte, guard func() error) (reply RegisteredControlReply, err error) {
	payload := p.Payload("winner_continue")
	payload.Candidate = candidate
	payload.Continuation = base64.StdEncoding.EncodeToString(continuation)
	return p.CallTunnel(ctx, payload, guard)
}

func (p *RegisteredControlTransport) call(ctx context.Context, payload RegisteredControlPayload, guard func() error, requestedPath string) (reply RegisteredControlReply, err error) {
	if p == nil || ctx == nil || guard == nil {
		return reply, resourcev4.ErrConfiguration
	}
	if !p.mu.TryLock() {
		return reply, ErrBusy
	}
	if p.closed || p.busy {
		p.mu.Unlock()
		return reply, ErrBusy
	}
	if requestedPath != "" && requestedPath != p.endpointPath {
		p.mu.Unlock()
		return reply, resourcev4.ErrConfiguration
	}
	if payload.Incarnation != base64.StdEncoding.EncodeToString(p.config.Incarnation) || payload.Parent != base64.StdEncoding.EncodeToString(p.config.Parent[:]) || payload.Candidate != p.config.Candidate {
		p.mu.Unlock()
		return reply, ErrResponse
	}
	if err = p.reservation.Check(); err == nil {
		err = p.dependencies.Check()
	}
	if err != nil {
		p.mu.Unlock()
		return reply, err
	}
	call := newHTTPSCallContext(p.provider)
	p.busy, p.cancel = true, call.stopCall
	provider, signer, authority := p.provider, p.config.Identity, p.config.Authority
	p.mu.Unlock()
	var content, proof, body, message []byte
	returned := false
	defer func() {
		if recovered := recover(); recovered != nil || !returned {
			err = ErrControlTaskExit
			call.cancel(err)
		}
		call.finish()
		clear(content)
		clear(proof)
		clear(body)
		clear(message)
		p.mu.Lock()
		defer p.mu.Unlock()
		if err == nil {
			err = call.cause()
		}
		if err == nil {
			err = p.reservation.Check()
		}
		if err == nil {
			err = p.dependencies.Check()
		}
		if p.closed && err == nil {
			err = context.Canceled
		}
		if err != nil {
			reply = RegisteredControlReply{}
		}
		clear(p.response)
		call.stopCall()
		p.busy, p.cancel = false, nil
		p.cleanupLocked()
	}()
	check := func() error {
		if err := call.cause(); err != nil {
			return err
		}
		if err := p.reservation.Check(); err != nil {
			return err
		}
		if err := p.dependencies.Check(); err != nil {
			return err
		}
		return guard()
	}
	call.beforeWrite = check
	if err = call.start(ctx); err == nil {
		err = check()
	}
	if err == nil {
		content, err = json.Marshal(payload)
	}
	if err == nil {
		message = make([]byte, len(registeredControlDomain)+len(content))
		copy(message, registeredControlDomain)
		copy(message[len(registeredControlDomain):], content)
		proof, err = signer.Sign(message)
		if err == nil && (len(proof) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(signer.PublicKey()), message, proof)) {
			err = ErrResponse
		}
	}
	if err == nil {
		err = check()
	}
	if err == nil {
		body, err = json.Marshal(struct {
			Payload string `json:"payload"`
			Proof   string `json:"proof"`
		}{string(content), base64.StdEncoding.EncodeToString(proof)})
	}
	if err == nil && len(body) > registeredControlBodyLimit {
		err = ErrResponse
	}
	if err == nil {
		path := requestedPath
		if path == "" {
			p.mu.Lock()
			path = p.endpointPath
			p.mu.Unlock()
			if path == "" {
				path = "/flowersec/control/live"
			}
		}
		var size int
		size, _, err = provider.exchangeContent(call, http.MethodPost, path, nil, body, p.response, false, false, "application/json")
		if err == nil {
			decoder := json.NewDecoder(bytes.NewReader(p.response[:size:size]))
			decoder.DisallowUnknownFields()
			err = decoder.Decode(&reply)
			if err == nil {
				var trailing any
				if end := decoder.Decode(&trailing); end != io.EOF {
					err = ErrResponse
				}
			}
			if err == nil && (reply.Incarnation != payload.Incarnation || reply.Authority != authority) {
				err = ErrResponse
			}
		}
	}
	if err == nil {
		err = check()
	}
	returned = true
	return reply, err
}

func (p *RegisteredControlTransport) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	if p.cancel != nil {
		p.cancel()
	}
	if p.liveCancel != nil {
		p.liveCancel()
	}
	if p.provider != nil {
		p.provider.Close()
	}
	if p.config.Relay != nil {
		p.config.Relay.Close()
	}
	p.cleanupLocked()
}
func (p *RegisteredControlTransport) cleanupLocked() {
	if !p.closed || p.busy || p.liveBusy || p.cleaned {
		return
	}
	if p.provider != nil && p.provider.Retire() != nil {
		return
	}
	clear(p.response)
	clear(p.config.Incarnation)
	p.response = nil
	p.provider = nil
	p.decoder = nil
	p.config = RegisteredControlConfig{}
	p.reservation.Release()
	p.dependencies.Release()
	p.reservation, p.dependencies = resourcev4.Reference{}, resourcev4.Reference{}
	p.cleaned = true
	close(p.done)
}
func (p *RegisteredControlTransport) WaitCleanup(ctx context.Context) error {
	if p == nil || ctx == nil {
		return resourcev4.ErrConfiguration
	}
	select {
	case <-p.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func DecodeRegisteredControlBytes(value string, maximum, exact int) ([]byte, error) {
	if len(value) == 0 || len(value) > ((maximum+2)/3)*4 {
		return nil, ErrResponse
	}
	wire, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(wire) == 0 || len(wire) > maximum || exact > 0 && len(wire) != exact || base64.StdEncoding.EncodeToString(wire) != value {
		clear(wire)
		return nil, ErrResponse
	}
	return wire, nil
}
