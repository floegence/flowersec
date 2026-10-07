package webtransport

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrier"
	carrierlife "github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/internal/lifecycle"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	wt "github.com/quic-go/webtransport-go"
)

// ownedNativeSession has one actual CONNECT association and no map keyed by
// untrusted Session IDs. Prefix readers, accepted streams and H3 workers use
// finite positions from the original connection reservation.
type ownedNativeSession struct {
	conn        *quic.Conn
	options     OwnedOptions
	client      bool
	request     nativeConnectStream
	id          uint64
	ready       chan struct{}
	incoming    chan *quic.Stream
	readers     chan struct{}
	uniReaders  chan struct{}
	wg          sync.WaitGroup
	done        chan struct{}
	connectSeen atomic.Bool
	installed   atomic.Bool
}

type nativeConnectStream interface {
	io.ReadWriteCloser
	StreamID() quic.StreamID
	CancelRead(quic.StreamErrorCode)
	CancelWrite(quic.StreamErrorCode)
	SendDatagram([]byte) error
	ReceiveDatagram(context.Context) ([]byte, error)
	SetReadDeadline(time.Time) error
}

func newOwnedNativeSession(conn *quic.Conn, o OwnedOptions, client bool) *ownedNativeSession {
	return &ownedNativeSession{conn: conn, options: o, client: client,
		ready: make(chan struct{}), done: make(chan struct{}), incoming: make(chan *quic.Stream, o.StreamSlots),
		readers: make(chan struct{}, o.Limits.MaxInboundStreams), uniReaders: make(chan struct{}, MaxH3IncomingUniStreams)}
}

func (s *ownedNativeSession) start(uni func(*quic.ReceiveStream), request func(*quic.Stream)) {
	s.wg.Add(2)
	go s.acceptBidirectional(request)
	go s.acceptUnidirectional(uni)
	go func() { s.wg.Wait(); close(s.done) }()
}

func (s *ownedNativeSession) acquire(slots chan struct{}) bool {
	select {
	case slots <- struct{}{}:
		return true
	case <-s.conn.Context().Done():
		return false
	}
}

func (s *ownedNativeSession) acceptBidirectional(request func(*quic.Stream)) {
	defer s.wg.Done()
	for s.acquire(s.readers) {
		str, err := s.conn.AcceptStream(s.conn.Context())
		if err != nil {
			<-s.readers
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.readers }()
			_ = str.SetReadDeadline(time.Now().Add(s.options.Limits.HandshakeIdleTimeout))
			typ, err := quicvarint.Peek(str)
			if err != nil {
				rejectNativeStream(str)
				return
			}
			if typ != 0x41 {
				if s.client || request == nil || !s.connectSeen.CompareAndSwap(false, true) {
					_ = s.conn.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeRequestRejected), "dedicated connection")
					return
				}
				request(str)
				return
			}
			prefix, err := readNativeVarint(str)
			if err != nil || prefix != 0x41 {
				rejectNativeStream(str)
				return
			}
			id, err := readNativeVarint(str)
			if err != nil || id%4 != 0 {
				rejectNativeStream(str)
				return
			}
			// A reordered native association may await only this original
			// CONNECT, under its fixed reader deadline and admitted slot.
			timer := time.NewTimer(s.options.Limits.HandshakeIdleTimeout)
			defer timer.Stop()
			select {
			case <-s.ready:
			case <-timer.C:
				rejectNativeStream(str)
				return
			case <-s.conn.Context().Done():
				rejectNativeStream(str)
				return
			}
			if id != s.id {
				rejectNativeStream(str)
				return
			}
			_ = str.SetReadDeadline(time.Time{})
			select {
			case s.incoming <- str:
			case <-s.conn.Context().Done():
				rejectNativeStream(str)
			}
		}()
	}
}

func (s *ownedNativeSession) acceptUnidirectional(handle func(*quic.ReceiveStream)) {
	defer s.wg.Done()
	for s.acquire(s.uniReaders) {
		str, err := s.conn.AcceptUniStream(s.conn.Context())
		if err != nil {
			<-s.uniReaders
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.uniReaders }()
			_ = str.SetReadDeadline(time.Now().Add(s.options.Limits.HandshakeIdleTimeout))
			typ, err := quicvarint.Peek(str)
			if err != nil {
				str.CancelRead(wt.WTBufferedStreamRejectedErrorCode)
				return
			}
			if typ == 0x54 {
				_, first := readNativeVarint(str)
				_, second := readNativeVarint(str)
				// Flowersec application associations are bidirectional. Consume
				// only the native prefix and refuse the unidirectional body.
				if first != nil || second != nil {
					str.CancelRead(wt.WTBufferedStreamRejectedErrorCode)
					return
				}
				str.CancelRead(wt.WTSessionGoneErrorCode)
				return
			}
			_ = str.SetReadDeadline(time.Time{})
			handle(str)
		}()
	}
}

func readNativeVarint(r io.Reader) (uint64, error) {
	var encoded [8]byte
	if _, err := io.ReadFull(r, encoded[:1]); err != nil {
		return 0, err
	}
	n := 1 << (encoded[0] >> 6)
	if _, err := io.ReadFull(r, encoded[1:n]); err != nil {
		return 0, err
	}
	v, _, err := quicvarint.Parse(encoded[:n])
	if err != nil || quicvarint.Len(v) != n {
		return 0, ErrNativeTuple
	}
	return v, nil
}

func rejectNativeStream(s *quic.Stream) {
	s.CancelRead(wt.WTBufferedStreamRejectedErrorCode)
	s.CancelWrite(wt.WTBufferedStreamRejectedErrorCode)
}

func (s *ownedNativeSession) install(request nativeConnectStream) error {
	if request == nil || uint64(request.StreamID())%4 != 0 || !s.installed.CompareAndSwap(false, true) {
		return resourcev4.ErrOwner
	}
	s.request, s.id = request, uint64(request.StreamID())
	if err := request.SetReadDeadline(time.Time{}); err != nil {
		return err
	}
	s.wg.Add(1)
	go s.readCapsules()
	close(s.ready)
	return nil
}

// Only native lifecycle capsules are consumed here. They never carry Flowersec
// records and cannot replace its authenticated termination or liveness facts.
func (s *ownedNativeSession) readCapsules() {
	defer s.wg.Done()
	parser := http3.NewCapsuleParser(s.request)
	for {
		typ, r, err := parser.Next()
		if err != nil {
			_ = s.conn.CloseWithError(0, "")
			return
		}
		if typ == 0x2843 {
			if r.Remaining() < 4 || r.Remaining() > 1028 {
				_ = s.conn.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeFrameError), "")
				return
			}
			_ = r.Discard()
			_ = s.conn.CloseWithError(0, "")
			return
		}
		// These registered tuples cannot enable another data/stream credit
		// gate after preparation. Drain (0x78ae) is only a carrier hint.
		if uint64(typ) >= 0x190b4d3d && uint64(typ) <= 0x190b4d44 || r.Remaining() > 16384 {
			_ = s.conn.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeSettingsError), "")
			return
		}
		if err = r.Discard(); err != nil {
			_ = s.conn.CloseWithError(0, "")
			return
		}
	}
}

func (s *ownedNativeSession) OpenStream(ctx context.Context) (carrier.Stream, error) {
	str, err := s.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	prefix := quicvarint.Append(quicvarint.Append(make([]byte, 0, 16), 0x41), s.id)
	return &Stream{inner: &ownedWTStream{native: str, prefix: prefix}, lifecycle: carrierlife.NewStream(s.conn.Context())}, nil
}

func (s *ownedNativeSession) AcceptStream(ctx context.Context) (carrier.Stream, error) {
	select {
	case str := <-s.incoming:
		return &Stream{inner: &ownedWTStream{native: str}, lifecycle: carrierlife.NewStream(s.conn.Context())}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.conn.Context().Done():
		return nil, context.Cause(s.conn.Context())
	}
}

func (s *ownedNativeSession) SendDatagram(b []byte) error { return s.request.SendDatagram(b) }
func (s *ownedNativeSession) ReceiveUnreliable(ctx context.Context) ([]byte, error) {
	return s.request.ReceiveDatagram(ctx)
}
func (s *ownedNativeSession) Close() error { return s.conn.CloseWithError(0, "") }

type ownedWTStream struct {
	native *quic.Stream
	prefix []byte
}

func (s *ownedWTStream) Read(b []byte) (int, error) { return s.native.Read(b) }
func (s *ownedWTStream) Write(b []byte) (int, error) {
	if len(s.prefix) != 0 {
		n, err := s.native.Write(s.prefix)
		s.prefix = s.prefix[n:]
		if err != nil {
			return 0, err
		}
		if len(s.prefix) != 0 {
			return 0, io.ErrShortWrite
		}
	}
	return s.native.Write(b)
}
func (s *ownedWTStream) Context() context.Context { return s.native.Context() }
func (s *ownedWTStream) Close() error             { return s.native.Close() }
func (s *ownedWTStream) StreamID() quic.StreamID  { return s.native.StreamID() }
func nativeResetCode(code wt.StreamErrorCode) quic.StreamErrorCode {
	return 0x52e4a40fa8db + quic.StreamErrorCode(code) + quic.StreamErrorCode(code/0x1e)
}
func (s *ownedWTStream) CancelRead(code wt.StreamErrorCode) {
	s.native.CancelRead(nativeResetCode(code))
}
func (s *ownedWTStream) CancelWrite(code wt.StreamErrorCode) {
	s.native.CancelWrite(nativeResetCode(code))
}

func (p *OwnedConnection) connectNative(ctx context.Context, endpoint *url.URL, origin string) error {
	state := p.conn.ConnectionState()
	if state.TLS.Version != tls.VersionTLS13 || state.TLS.NegotiatedProtocol != "h3" || state.Used0RTT || state.TLS.DidResume ||
		!state.SupportsDatagrams.Remote || !state.SupportsStreamResetPartialDelivery.Remote {
		return ErrNativeTuple
	}
	var tuple *nativeTuple
	for i := range nativeProfiles.Tuples {
		if nativeProfiles.Tuples[i].ID == "go_native_h3" {
			tuple = &nativeProfiles.Tuples[i]
		}
	}
	if tuple == nil {
		return ErrNativeTuple
	}
	settings := make(map[uint64]uint64, len(tuple.RequiredPeerSettings))
	for k, v := range tuple.RequiredPeerSettings {
		settings[k] = v
	}
	h3 := (&http3.Transport{EnableDatagrams: true, DisableCompression: true, AdditionalSettings: settings, MaxResponseHeaderBytes: nativeProfiles.Listener.HeaderBytes}).NewRawClientConn(p.conn)
	s := newOwnedNativeSession(p.conn, p.options, true)
	p.session, p.nativeDone = s, false
	// The original preparation remains a live task until CONNECT installation
	// or failure; a racing socket close cannot finish Wait before this Add.
	s.wg.Add(1)
	defer s.wg.Done()
	s.start(h3.HandleUnidirectionalStream, nil)
	go func() { <-s.done; p.mu.Lock(); p.nativeDone = true; p.cleanupLocked(); p.mu.Unlock() }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.conn.Context().Done():
		return context.Cause(p.conn.Context())
	case <-h3.ReceivedSettings():
	}
	if !h3.Settings().EnableExtendedConnect || tuple.checkSettings(h3.Settings()) != nil {
		return ErrNativeTuple
	}
	request, err := h3.OpenRequestStream(ctx)
	if err != nil {
		return err
	}
	cancelDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(cancelDone)
		request.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		request.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
	})
	defer func() {
		if !stop() {
			<-cancelDone
		}
	}()
	header := make(http.Header)
	for k, v := range tuple.RequestHeaders {
		header.Set(k, v)
	}
	if origin != "" {
		header.Set("Origin", origin)
	}
	if err = request.SendRequestHeader((&http.Request{Method: http.MethodConnect, Host: endpoint.Host, URL: endpoint, Proto: tuple.Protocol, Header: header}).WithContext(ctx)); err != nil {
		return err
	}
	response, err := request.ReadResponse()
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return ErrNativeTuple
	}
	for _, forbidden := range []string{"WT-Protocol", "Capsule-Protocol"} {
		if count, _ := headerValue(response.Header, forbidden); count != 0 {
			return ErrNativeTuple
		}
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	return s.install(request)
}
