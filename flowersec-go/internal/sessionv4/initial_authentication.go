package sessionv4

import (
	"crypto/sha256"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

type initialAdmission struct {
	context, binding, client, server [32]byte
	features                         uint64
}

// Authenticate runs the two actual Noise messages and both READY flights on
// this original carrier. It can start only after the original FSA handler has
// succeeded. The caller has already verified trust/freshness/revocation and
// consumed its durable original admission start guard; config is the retained
// credential/key projection from that invocation, never a query or receipt.
// reserve attaches all pre-admitted Session/profile backing before signing
// READY. It is bounded SDK work, not an application callback or a new quota
// attempt. No public Session is delivered here; the private engine and actual
// carrier are transferred exactly once to the caller's Session initializer.
func (x *InitialExchange) Authenticate(config cryptov4.HandshakeConfig, records cryptov4.Config, reserve func(*cryptov4.Engine) error) (*cryptov4.Engine, error) {
	defer clear(config.PSK[:])
	return x.authenticate(config, records, nil, func(f *cryptov4.FinishedHandshake, config cryptov4.Config) (*cryptov4.Engine, error) {
		return f.PrepareRecords(config)
	}, reserve)
}

func (x *InitialExchange) authenticate(config cryptov4.HandshakeConfig, records cryptov4.Config, plan *SessionCorePlan, prepare func(*cryptov4.FinishedHandshake, cryptov4.Config) (*cryptov4.Engine, error), reserve func(*cryptov4.Engine) error) (engine *cryptov4.Engine, err error) {
	defer clear(config.PSK[:])
	x.mu.Lock()
	if err = x.checkLocked(); err != nil {
		x.mu.Unlock()
		return nil, err
	}
	if x.corePlan != plan {
		x.mu.Unlock()
		return nil, cryptov4.ErrTransition
	}
	if x.authenticating || x.sending || x.receiving {
		x.mu.Unlock()
		return nil, cryptov4.ErrCapacity
	}
	client, server := config.LocalCertificateDigest, config.PeerCertificateDigest
	if x.config.Role == protocolv4.ServerToClient {
		client, server = server, client
	}
	if !x.session.Contract.Valid() || config.Session != x.session || x.phase != 4 || prepare == nil || reserve == nil || config.Role != x.config.Role || config.Profile != x.config.Profile || config.Deadline != x.config.Deadline ||
		sha256.Sum256(config.FSB) != x.fsbDigest || sha256.Sum256(config.FSA) != x.fsaDigest ||
		config.ContextDigest != x.admission.context || config.AdmissionBinding != x.admission.binding || config.Features != x.admission.features ||
		client != x.admission.client || server != x.admission.server {
		err = x.failLocked(ErrInitialPhase)
		x.mu.Unlock()
		return nil, err
	}
	if err = cryptov4.CheckRecordContract(records, config.Session.Contract); err != nil {
		err = x.failLocked(err)
		x.mu.Unlock()
		return nil, err
	}
	x.authenticating = true
	// Carry the original connection guard through every subsequent crypto gate.
	config.Authorization = x.config.Authorization
	x.mu.Unlock()
	defer func() {
		x.mu.Lock()
		if err != nil {
			x.failLocked(err)
		}
		h, f := x.handshake, x.finished
		x.handshake, x.finished = nil, nil
		x.mu.Unlock()
		if h != nil {
			h.Close()
		}
		if f != nil {
			f.Close()
		}
		if err != nil && engine != nil {
			engine.Close()
			engine = nil
		}
		x.mu.Lock()
		x.authenticating = false
		x.cleanupLocked()
		x.mu.Unlock()
	}()
	h, err := cryptov4.NewHandshake(config)
	if err != nil {
		return nil, err
	}
	x.mu.Lock()
	x.handshake = h
	err = x.checkLocked()
	x.mu.Unlock()
	if err != nil {
		return nil, err
	}
	writeNoise := func() error {
		_, err := x.sendFlight(protocolv4.FrameHandshake, func(dst []byte) (int, error) {
			wire, err := h.WriteMessage()
			defer clear(wire)
			if err != nil {
				return 0, err
			}
			if len(wire) > len(dst) {
				return 0, protocolv4.ErrPayloadTooLarge
			}
			return copy(dst, wire), nil
		}, nil, true)
		return err
	}
	readNoise := func() error { return x.receiveFlight(protocolv4.FrameHandshake, h.ReadMessage, true) }
	if config.Role == protocolv4.ClientToServer {
		if err = writeNoise(); err == nil {
			err = readNoise()
		}
	} else {
		if err = readNoise(); err == nil {
			err = writeNoise()
		}
	}
	if err != nil {
		return nil, err
	}
	f, err := h.Finish()
	if err != nil {
		return nil, err
	}
	x.mu.Lock()
	x.finished = f
	err = x.checkLocked()
	x.mu.Unlock()
	if err != nil {
		return nil, err
	}
	engine, err = prepare(f, records)
	if err != nil {
		return nil, err
	}
	if err = x.check(); err != nil {
		return engine, err
	}
	if err = reserve(engine); err != nil {
		return engine, err
	}
	if err = x.check(); err != nil {
		return engine, err
	}
	ready, err := f.Ready()
	if err != nil {
		return engine, err
	}
	defer clear(ready)
	// One reserved publisher allows both endpoints to send READY without
	// requiring the peer to choose a different local send/read order. Join its
	// real completion even on cancellation; no borrowed key/buffer exits early.
	sent := make(chan error, 1)
	ticket := make(chan error, 1)
	go func() {
		ticketed := false
		_, sendErr := x.sendFlight(protocolv4.FrameReady, func(dst []byte) (int, error) {
			if len(ready) > len(dst) {
				return 0, protocolv4.ErrPayloadTooLarge
			}
			return copy(dst, ready), nil
		}, func() error {
			err := f.MarkReadySubmitted()
			ticketed = true
			ticket <- err
			return err
		}, true)
		if !ticketed {
			ticket <- sendErr
		}
		sent <- sendErr
	}()
	err = <-ticket
	if err == nil {
		err = x.receiveFlight(protocolv4.FrameReady, f.VerifyReady, true)
	}
	if err != nil {
		x.Close(err)
		f.Close()
	}
	sendErr := <-sent
	if err == nil {
		err = sendErr
	}
	if err != nil {
		return engine, err
	}
	if err = x.check(); err != nil {
		return engine, err
	}
	started, err := f.StartRecords()
	if err != nil {
		return engine, err
	}
	if started != engine {
		return engine, ErrInitialPhase
	}
	x.mu.Lock()
	err = x.checkLocked()
	if err == nil && (!x.readySent || !x.readyReceived || x.sending || x.receiving) {
		err = ErrInitialPhase
	}
	if err == nil {
		x.transferred = true
		x.cancel(nil)
	}
	x.mu.Unlock()
	return engine, err
}
