package sessionv4

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

var (
	ErrInitialPhase      = errors.New("sessionv4: invalid initial flight")
	ErrAdmissionRejected = errors.New("sessionv4: admission rejected")
)

// InitialMessages preserves the provider's message boundary. ReadMessage must
// reject oversize messages without copying them into an unreserved allocation.
// WriteMessage submits exactly one binary message, never a sequence of chunks.
// Close seals this original carrier and cancels its actual I/O. Provider-owned
// buffers, background work and physical cleanup remain that provider's charge.
// Contexts retained beyond a call belong to that same provider lifecycle.
type InitialMessages interface {
	ReadMessage(context.Context, []byte) (int, error)
	WriteMessage(context.Context, []byte) error
	Close() error
}

type InitialLimits struct {
	MaxFrame, Nodes int
}

// InitialConfig is fixed by the original admitted local owner, not by a peer
// hello. Deadline is the original handshake age tightened by the Connect and
// Session caps. The admission window is checked independently by credential
// handlers at its specified gates; it is not extended or reused for READY.
type InitialConfig struct {
	Role                             protocolv4.Direction
	Profile, ActivationSourceProfile string
	Limits                           InitialLimits
	Deadline                         *timev4.Deadline
	Authorization                    protocolv4.AuthorizationGuard
	Reservation                      resourcev4.Reference
	original                         initialOriginalBinding
	accepted                         *acceptedAuthorization
}

// InitialExchange owns the original maintenance transport from NEGOTIATE
// through both READY flights. There is one build/write slot, one read/verify
// slot, one watchdog and no waiter queue. Only READY permits concurrent send
// and receive. A failed/cancelled owner is never reusable on another carrier.
type InitialExchange struct {
	mu                                  sync.Mutex
	config                              InitialConfig
	parent                              *initialParentContext
	ctx                                 context.Context
	cancel                              context.CancelCauseFunc
	stream                              io.ReadWriteCloser
	messages                            InitialMessages
	send, receive                       []byte
	clientHello, serverHello            []byte
	clientHelloBytes, serverHelloBytes  int
	sendDecoder, receiveDecoder         *protocolv4.Decoder
	phase                               uint8
	sending, receiving, authenticating  bool
	readySent, readyReceived            bool
	fsbDigest, fsaDigest                [32]byte
	admission                           initialAdmission
	session                             protocolv4.ArtifactSessionParameters
	hello                               *protocolv4.HelloBinding
	handshake                           *cryptov4.Handshake
	finished                            *cryptov4.FinishedHandshake
	corePlan                            *SessionCorePlan
	terminal                            error
	transferred, watcherExited, cleaned bool
	done                                chan struct{}
}

// InitialBackingBytes counts the two private envelope and decoder reservations.
// The owning admission also reserves two active work slots plus the one timer /
// watchdog and accounts for the actual provider and retained signed materials.
func InitialBackingBytes(limits InitialLimits) (uint64, error) {
	if limits.MaxFrame <= 0 || limits.MaxFrame > protocolv4.MaxPayloadLength {
		return 0, cryptov4.ErrConfiguration
	}
	decoder, err := protocolv4.DecoderBackingBytes(limits.MaxFrame, limits.Nodes)
	if err != nil {
		return 0, err
	}
	hello, err := protocolv4.SchemaByteLimit("ClientHello")
	if err != nil {
		return 0, err
	}
	server, err := protocolv4.SchemaByteLimit("ServerHello")
	if err != nil {
		return 0, err
	}
	extra := uint64(2*(protocolv4.EnvelopePrefixSize+limits.MaxFrame)+min(hello, limits.MaxFrame)+min(server, limits.MaxFrame)) + uint64(unsafe.Sizeof(InitialExchange{})) + uint64(unsafe.Sizeof(initialParentContext{}))
	if decoder > (^uint64(0)-extra)/2 {
		return 0, cryptov4.ErrConfiguration
	}
	return 2*decoder + extra, nil
}

// InitialCharge is the local minimum above provider/material reservations.
// Actual allocator, channel, goroutine and timer bookkeeping is added by the
// admitted runtime profile; it must not be inferred from peer capability bits.
func InitialCharge(limits InitialLimits) (resourcev4.Vector, error) {
	bytes, err := InitialBackingBytes(limits)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return resourcev4.Vector{resourcev4.SDKBytes: bytes, resourcev4.WorkSlots: 2, resourcev4.Tasks: 3, resourcev4.Timers: 1, resourcev4.Items: 1}, nil
}

// The caller transfers one already activated, independently verified carrier.
// Direct uses its original maintenance stream; tunnel has completed both
// required hop authentication/pairing gates. No preparation/spend happens here.
func NewInitialStream(ctx context.Context, config InitialConfig, stream io.ReadWriteCloser) (*InitialExchange, error) {
	if stream == nil {
		return nil, cryptov4.ErrConfiguration
	}
	return newInitialExchange(ctx, config, stream, nil)
}

func NewInitialMessages(ctx context.Context, config InitialConfig, messages InitialMessages) (*InitialExchange, error) {
	if messages == nil {
		return nil, cryptov4.ErrConfiguration
	}
	return newInitialExchange(ctx, config, nil, messages)
}

func newInitialExchange(ctx context.Context, config InitialConfig, stream io.ReadWriteCloser, messages InitialMessages) (*InitialExchange, error) {
	if ctx == nil || config.Role > protocolv4.ServerToClient || config.Deadline == nil || config.Authorization == nil || config.ActivationSourceProfile != "live_authority" && config.ActivationSourceProfile != "preauthorized_pool" {
		return nil, cryptov4.ErrConfiguration
	}
	if _, err := protocolv4.Profile(config.Profile); err != nil {
		return nil, err
	}
	charge, err := InitialCharge(config.Limits)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := config.Deadline.Check(); err != nil {
		return nil, err
	}
	if err := config.Authorization.Check(); err != nil {
		return nil, err
	}
	owned, err := config.Reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	send, err := protocolv4.NewDecoder(config.Limits.MaxFrame, config.Limits.Nodes)
	if err != nil {
		owned.Release()
		return nil, err
	}
	receive, err := protocolv4.NewDecoder(config.Limits.MaxFrame, config.Limits.Nodes)
	if err != nil {
		owned.Release()
		return nil, err
	}
	config.Reservation = owned
	clientCap, _ := protocolv4.SchemaByteLimit("ClientHello")
	serverCap, _ := protocolv4.SchemaByteLimit("ServerHello")
	x := &InitialExchange{config: config, stream: stream, messages: messages,
		send: make([]byte, protocolv4.EnvelopePrefixSize+config.Limits.MaxFrame), receive: make([]byte, protocolv4.EnvelopePrefixSize+config.Limits.MaxFrame), sendDecoder: send, receiveDecoder: receive, done: make(chan struct{}),
		clientHello: make([]byte, min(clientCap, config.Limits.MaxFrame)), serverHello: make([]byte, min(serverCap, config.Limits.MaxFrame))}
	x.parent = &initialParentContext{parent: ctx, done: make(chan struct{})}
	x.parent.deadline, x.parent.hasDeadline = ctx.Deadline()
	// Observation starts only after standard-library registration returns.
	x.ctx, x.cancel = context.WithCancelCause(x.parent)
	go x.watch()
	return x, nil
}

func (x *InitialExchange) failLocked(err error) error {
	if x.terminal == nil && !x.transferred {
		// Providers often return ctx.Err(). Preserve an already observed
		// original cause instead of replacing it with generic cancellation.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			x.parent.observe()
			if cause := context.Cause(x.ctx); cause != nil {
				err = cause
			}
		}
		if err == nil {
			err = cryptov4.ErrClosed
		}
		x.terminal = err
		x.config.Reservation.Seal()
		x.config.Authorization.Close(err)
		x.cancel(err)
	}
	return x.terminal
}

func (x *InitialExchange) checkLocked() error {
	if x.transferred {
		return cryptov4.ErrClosed
	}
	if x.terminal != nil {
		return x.terminal
	}
	x.parent.observe()
	if err := context.Cause(x.ctx); err != nil {
		return x.failLocked(err)
	}
	if err := x.config.Reservation.Check(); err != nil {
		return x.failLocked(err)
	}
	if err := x.config.Deadline.Check(); err != nil {
		return x.failLocked(err)
	}
	if err := x.config.Authorization.Check(); err != nil {
		return x.failLocked(err)
	}
	return nil
}

func (x *InitialExchange) check() error {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.checkLocked()
}

func (x *InitialExchange) cleanupLocked() {
	if x.cleaned || !x.watcherExited || x.sending || x.receiving || x.authenticating {
		return
	}
	clear(x.send)
	clear(x.receive)
	clear(x.clientHello)
	clear(x.serverHello)
	x.send, x.receive = nil, nil
	x.clientHello, x.serverHello = nil, nil
	x.hello = nil
	x.sendDecoder, x.receiveDecoder = nil, nil
	x.stream, x.messages = nil, nil
	x.parent = nil
	x.corePlan = nil
	x.ctx, x.cancel = nil, nil
	x.config.Reservation.Release()
	x.cleaned = true
	close(x.done)
}

func (x *InitialExchange) watch() {
	parentDone := x.parent.parent.Done() // Parent stays attached until this task exits.
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
		x.mu.Lock()
		transferred := x.transferred
		stream, messages := x.stream, x.messages
		handshake, finished := x.handshake, x.finished
		x.mu.Unlock()
		if !transferred {
			if handshake != nil {
				handshake.Close()
			}
			if finished != nil {
				finished.Close()
			}
			if stream != nil {
				_ = stream.Close()
			} else {
				_ = messages.Close()
			}
		} else {
			// This watchdog may have consumed the last trust notification just
			// before READY transferred ownership. Forward a recheck only after
			// its final receive so the Session watchdog cannot lose that event.
			x.config.Authorization.Notify()
		}
		x.mu.Lock()
		x.watcherExited = true
		x.cleanupLocked()
		x.mu.Unlock()
	}()
	for {
		x.mu.Lock()
		if x.transferred || x.checkLocked() != nil {
			x.mu.Unlock()
			return
		}
		x.mu.Unlock()
		remaining, err := x.config.Deadline.RemainingMS()
		if err != nil {
			x.Close(err)
			return
		}
		authorized, err := x.config.Authorization.RemainingMS()
		if err != nil {
			x.Close(err)
			return
		}
		remaining = min(remaining, authorized)
		if timer == nil {
			timer = time.NewTimer(idleTimerChunk(remaining))
		} else {
			timer.Reset(idleTimerChunk(remaining))
		}
		select {
		case <-parentDone:
			x.mu.Lock()
			_ = x.checkLocked()
			x.mu.Unlock()
			return
		case <-x.ctx.Done():
			x.Close(context.Cause(x.ctx))
			return
		case <-timer.C:
		case <-x.config.Authorization.Wake():
			timer.Stop()
		}
	}
}

func (x *InitialExchange) Close(cause error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.failLocked(cause)
}

func (x *InitialExchange) WaitCleanup(ctx context.Context) error {
	select {
	case <-x.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func initialFlight(phase uint8) (protocolv4.FrameType, protocolv4.Direction) {
	switch phase {
	case 0:
		return protocolv4.FrameNegotiate, protocolv4.ClientToServer
	case 1:
		return protocolv4.FrameNegotiate, protocolv4.ServerToClient
	case 2:
		return protocolv4.FrameAdmission, protocolv4.ClientToServer
	case 3:
		return protocolv4.FrameAdmissionResult, protocolv4.ServerToClient
	case 4:
		return protocolv4.FrameHandshake, protocolv4.ClientToServer
	case 5:
		return protocolv4.FrameHandshake, protocolv4.ServerToClient
	default:
		return protocolv4.FrameReady, 0
	}
}

func (x *InitialExchange) begin(frame protocolv4.FrameType, send, authentication bool) (protocolv4.InitialFrameSpec, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if err := x.checkLocked(); err != nil {
		return protocolv4.InitialFrameSpec{}, err
	}
	if x.authenticating != authentication || send && x.sending || !send && x.receiving || x.phase < 6 && (x.sending || x.receiving) {
		return protocolv4.InitialFrameSpec{}, cryptov4.ErrCapacity
	}
	sender := x.config.Role
	if !send {
		sender = 1 - sender
	}
	want, direction := initialFlight(x.phase)
	if x.phase >= 3 && x.config.accepted != nil {
		// Before a definite admitted continuation only a verified rejection
		// response may proceed; validate checks the actual canonical status.
		var err error
		if x.phase == 3 && send && frame == protocolv4.FrameAdmissionResult {
			err = x.config.accepted.checkResponse(false)
		} else {
			err = x.config.accepted.checkAdmitted()
		}
		if err != nil {
			return protocolv4.InitialFrameSpec{}, err
		}
	}
	if frame != want || !authentication && x.phase >= 4 || x.phase < 6 && sender != direction || x.phase == 6 && (send && x.readySent || !send && x.readyReceived) {
		return protocolv4.InitialFrameSpec{}, x.failLocked(ErrInitialPhase)
	}
	spec, err := protocolv4.InitialFrame(frame, sender, x.config.Profile)
	if err != nil {
		return spec, x.failLocked(err)
	}
	if send {
		x.sending = true
	} else {
		x.receiving = true
	}
	return spec, nil
}

func (x *InitialExchange) end(send, rejected bool, err *error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if send {
		x.sending = false
	} else {
		x.receiving = false
	}
	if *err == nil {
		*err = x.checkLocked()
	}
	if *err == nil {
		if x.phase < 6 {
			x.phase++
		} else if send {
			x.readySent = true
		} else {
			x.readyReceived = true
		}
		if rejected {
			*err = ErrAdmissionRejected
		}
	}
	if *err != nil {
		*err = x.failLocked(*err)
	}
	x.cleanupLocked()
}

func (x *InitialExchange) validate(decoder *protocolv4.Decoder, spec protocolv4.InitialFrameSpec, payload []byte) (bool, error) {
	if err := spec.CheckLength(len(payload)); err != nil {
		return false, err
	}
	if spec.Schema == "" {
		return false, nil
	}
	doc, err := decoder.DecodeMap(payload, spec.Schema, protocolv4.DecodeContext{Selectors: map[string]string{"crypto_profile_id": x.config.Profile, "activation_source_profile": x.config.ActivationSourceProfile}})
	if err != nil {
		return false, err
	}
	defer doc.Release()
	if err := x.config.original.checkFrame(doc, spec.Schema, x.config.Role); err != nil {
		return false, err
	}
	if spec.Schema == "ClientHello" || spec.Schema == "ServerHello" {
		profile, _ := doc.Root().Named(spec.Schema, "crypto_profile_id").Text()
		if profile != x.config.Profile {
			return false, ErrInitialPhase
		}
		if spec.Schema == "ClientHello" {
			x.clientHelloBytes = copy(x.clientHello, payload)
		} else {
			x.serverHelloBytes = copy(x.serverHello, payload)
		}
	}
	// These detached input facts cannot start Noise: only a successful original
	// verifier plus the completed phase enables Authenticate. No input alias or
	// mutable callback projection is retained here.
	if spec.Schema == "FSB4" {
		x.fsbDigest = sha256.Sum256(payload)
	}
	if spec.Schema == "FSA4" {
		x.fsaDigest = sha256.Sum256(payload)
		status, _ := doc.Root().Named("FSA4", "status").Uint()
		if x.config.accepted != nil {
			if err := x.config.accepted.checkResponse(status == 0); err != nil {
				return false, err
			}
			if err := x.hello.CheckAcceptedResponse(doc, x.config.accepted.admissionBinding); err != nil {
				return false, err
			}
			if err := x.config.accepted.matchResponseDocument(doc); err != nil {
				return false, err
			}
		}
		if status == 0 {
			get := func(name string) [32]byte {
				value, _ := doc.Root().Named("FSA4", name).ByteString()
				return [32]byte(value)
			}
			features, _ := doc.Root().Named("FSA4", "selected_features").Uint()
			x.admission = initialAdmission{context: get("transport_context_digest"), binding: get("admission_binding"), client: get("client_identity_digest"), server: get("server_identity_digest"), features: features}
		}
		return status == 1, nil
	}
	return false, nil
}

// CopyClientHello provides the original local/received ClientHello for the
// bounded ServerHello or client FSB handler. It never reads a mutable carrier
// configuration or repairs a peer's offer. dst is the handler's reservation.
func (x *InitialExchange) CopyClientHello(dst []byte) (int, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if err := x.checkLocked(); err != nil {
		return 0, err
	}
	if x.phase < 1 {
		return 0, ErrInitialPhase
	}
	if len(dst) < x.clientHelloBytes {
		return 0, io.ErrShortBuffer
	}
	return copy(dst, x.clientHello[:x.clientHelloBytes]), nil
}

// CopyHellos retains exact bytes for the original durable admission invocation.
// The returned copies have no dispatch or restoration rights of their own.
func (x *InitialExchange) CopyHellos(client, server []byte) (int, int, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if err := x.checkLocked(); err != nil {
		return 0, 0, err
	}
	if x.phase < 2 {
		return 0, 0, ErrInitialPhase
	}
	if len(client) < x.clientHelloBytes || len(server) < x.serverHelloBytes {
		return 0, 0, io.ErrShortBuffer
	}
	return copy(client, x.clientHello[:x.clientHelloBytes]), copy(server, x.serverHello[:x.serverHelloBytes]), nil
}

// InitialWriteResult reports only publication facts, never remote acceptance.
// Started includes a failed build/sign job; Submitted begins at the first real
// provider call. An error cannot convert either fact into retry permission.
type InitialWriteResult struct {
	Started, Submitted, Complete bool
	EnvelopeBytes                int
}

// Send calls a bounded SDK builder exactly once after claiming the phase. FSB
// signing, server nonce generation and admitted FSA signing belong inside that
// original call, after their independent authorization/admission guards.
func (x *InitialExchange) Send(frame protocolv4.FrameType, build func([]byte) (int, error)) (InitialWriteResult, error) {
	return x.sendFlight(frame, build, nil, false)
}

func (x *InitialExchange) sendFlight(frame protocolv4.FrameType, build func([]byte) (int, error), submitted func() error, authentication bool) (result InitialWriteResult, err error) {
	if build == nil {
		return result, cryptov4.ErrConfiguration
	}
	spec, err := x.begin(frame, true, authentication)
	if err != nil {
		return result, err
	}
	rejected := false
	defer func() { clear(x.send); x.end(true, rejected, &err) }()
	result.Started = true
	if err = x.check(); err != nil {
		return result, err
	}
	capacity := min(x.config.Limits.MaxFrame, spec.Maximum)
	n, err := build(x.send[protocolv4.EnvelopePrefixSize : protocolv4.EnvelopePrefixSize+capacity : protocolv4.EnvelopePrefixSize+capacity])
	if err != nil {
		return result, err
	}
	if n < 0 || n > capacity {
		return result, protocolv4.ErrPayloadTooLarge
	}
	data := x.send[:protocolv4.EnvelopePrefixSize+n]
	rejected, err = x.validate(x.sendDecoder, spec, data[protocolv4.EnvelopePrefixSize:])
	if err != nil {
		return result, err
	}
	binary.BigEndian.PutUint32(data[:4], uint32(n))
	data[4] = byte(frame)
	if err = x.check(); err != nil {
		return result, err
	}
	if submitted != nil {
		if err = submitted(); err != nil {
			return result, err
		}
	}
	if x.messages != nil {
		result.Submitted = true
		err = x.messages.WriteMessage(x.ctx, data)
		if err == nil {
			result.EnvelopeBytes, result.Complete = len(data), true
		}
		return result, err
	}
	for result.EnvelopeBytes < len(data) {
		if err = x.check(); err != nil {
			return result, err
		}
		result.Submitted = true
		n, writeErr := x.stream.Write(data[result.EnvelopeBytes:])
		if n < 0 || n > len(data)-result.EnvelopeBytes {
			return result, ErrRecordWriter
		}
		result.EnvelopeBytes += n
		result.Complete = result.EnvelopeBytes == len(data)
		if writeErr != nil {
			return result, writeErr
		}
		if n == 0 {
			return result, io.ErrNoProgress
		}
	}
	return result, nil
}

func (x *InitialExchange) readFull(dst []byte) error {
	for offset := 0; offset < len(dst); {
		if err := x.check(); err != nil {
			return err
		}
		n, err := x.stream.Read(dst[offset:])
		if n < 0 || n > len(dst)-offset {
			return ErrInitialPhase
		}
		offset += n
		if err != nil {
			if offset == len(dst) && errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

func (x *InitialExchange) prefix(frame protocolv4.FrameType, spec protocolv4.InitialFrameSpec, data []byte) (int, error) {
	if len(data) < protocolv4.EnvelopePrefixSize {
		return 0, protocolv4.ErrTruncated
	}
	if data[4] != byte(frame) {
		return 0, ErrInitialPhase
	}
	if data[5] != 0 || data[6] != 0 || data[7] != 0 {
		return 0, protocolv4.ErrInvalidFlags
	}
	n := uint64(binary.BigEndian.Uint32(data[:4]))
	if n > uint64(x.config.Limits.MaxFrame) || n > uint64(spec.Maximum) {
		return 0, protocolv4.ErrPayloadTooLarge
	}
	return int(n), spec.CheckLength(int(n))
}

// Receive rejects framing/shape/rules before the mandatory original credential
// or Noise verifier. The callback borrows the slot only until it returns and
// must authenticate FSA before returning its rejection as a trusted result.
func (x *InitialExchange) Receive(frame protocolv4.FrameType, verify func([]byte) error) error {
	return x.receiveFlight(frame, verify, false)
}

func (x *InitialExchange) receiveFlight(frame protocolv4.FrameType, verify func([]byte) error, authentication bool) (err error) {
	if verify == nil {
		return cryptov4.ErrConfiguration
	}
	spec, err := x.begin(frame, false, authentication)
	if err != nil {
		return err
	}
	rejected := false
	defer func() { clear(x.receive); x.end(false, rejected, &err) }()
	var n int
	if x.messages != nil {
		n, err = x.messages.ReadMessage(x.ctx, x.receive)
		if err != nil {
			return err
		}
		if n < protocolv4.EnvelopePrefixSize || n > len(x.receive) {
			return protocolv4.ErrTruncated
		}
		size, parseErr := x.prefix(frame, spec, x.receive[:n])
		if parseErr != nil {
			return parseErr
		}
		if size != n-protocolv4.EnvelopePrefixSize {
			return protocolv4.ErrTruncated
		}
	} else {
		if err = x.readFull(x.receive[:protocolv4.EnvelopePrefixSize]); err != nil {
			return err
		}
		size, parseErr := x.prefix(frame, spec, x.receive[:protocolv4.EnvelopePrefixSize])
		if parseErr != nil {
			return parseErr
		}
		n = protocolv4.EnvelopePrefixSize + size
		if err = x.readFull(x.receive[protocolv4.EnvelopePrefixSize:n]); err != nil {
			return err
		}
	}
	if err = x.check(); err != nil {
		return err
	}
	payload := x.receive[protocolv4.EnvelopePrefixSize:n:n]
	rejected, err = x.validate(x.receiveDecoder, spec, payload)
	if err != nil {
		return err
	}
	if err = x.check(); err != nil {
		return err
	}
	return verify(payload)
}
