package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/admissionv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/protocolv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/session"
)

const (
	frameOpen  = 1
	frameData  = 2
	frameFIN   = 3
	frameReset = 4
	frameClose = 5
)

func main() {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	defer listener.Close()
	fmt.Println(listener.Addr().String())
	conn, err := listener.Accept()
	must(err)
	transport := newFramedSession(conn, false)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	admission, err := transport.AcceptStream(ctx)
	must(err)
	decoded, err := admissionv2.Serve(ctx, admission, nil, func(context.Context, *artifactv2.DecodedRequest) (artifactv2.AdmissionResponse, error) {
		return artifactv2.AdmissionResponse{Status: artifactv2.AdmissionSuccess}, nil
	})
	must(err)
	var psk [32]byte
	for i := range psk {
		psk[i] = byte(i + 1)
	}
	established, err := session.Establish(ctx, transport, session.Config{
		Role:                  session.RoleServer,
		Path:                  session.PathDirect,
		ChannelID:             decoded.Request.ChannelID,
		SessionContractHash:   decoded.Request.SessionContractHash,
		Suite:                 protocolv2.SuiteChaCha20Poly1305,
		PSK:                   psk,
		MaxInboundStreams:     64,
		LocalAdmissionBinding: decoded.LocalAdmissionBinding,
		PeerAdmissionBinding:  decoded.LocalAdmissionBinding,
	})
	must(err)
	incoming, err := established.AcceptStream(ctx)
	must(err)
	buffer := make([]byte, 64)
	n, err := incoming.Stream.Read(buffer)
	must(err)
	if string(buffer[:n]) != "hello-go" {
		must(fmt.Errorf("unexpected first payload %q", buffer[:n]))
	}
	_, err = incoming.Stream.Write([]byte("hello-ts"))
	must(err)
	must(established.Rekey(ctx))
	_, err = incoming.Stream.Write([]byte("go-rekey-ok"))
	must(err)
	n, err = incoming.Stream.Read(buffer)
	must(err)
	if string(buffer[:n]) != "ts-rekey-ok" {
		must(fmt.Errorf("unexpected rekey payload %q", buffer[:n]))
	}
	n, err = incoming.Stream.Read(buffer)
	if !errors.Is(err, io.EOF) || n != 0 {
		must(fmt.Errorf("expected EOF, got n=%d err=%v", n, err))
	}
	_, err = incoming.Stream.Write([]byte("done"))
	must(err)
	must(incoming.Stream.CloseWrite())
	time.Sleep(50 * time.Millisecond)
	must(established.Close())
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type framedSession struct {
	conn   net.Conn
	ctx    context.Context
	cancel context.CancelFunc
	client bool

	writeMu   sync.Mutex
	mu        sync.Mutex
	nextID    uint32
	streams   map[uint32]*framedStream
	acceptCh  chan *framedStream
	closeOnce sync.Once
}

func newFramedSession(conn net.Conn, client bool) *framedSession {
	ctx, cancel := context.WithCancel(context.Background())
	nextID := uint32(2)
	if client {
		nextID = 1
	}
	s := &framedSession{conn: conn, ctx: ctx, cancel: cancel, client: client, nextID: nextID, streams: make(map[uint32]*framedStream), acceptCh: make(chan *framedStream, 128)}
	go s.readLoop()
	return s
}

func (s *framedSession) Kind() carrier.Kind { return carrier.KindQUIC }

func (s *framedSession) Path() carrier.Path { return carrier.PathDirect }

func (s *framedSession) MaxIncomingStreams() uint16 { return 66 }

func (s *framedSession) OpenStream(ctx context.Context) (carrier.Stream, error) {
	s.mu.Lock()
	id := s.nextID
	s.nextID += 2
	stream := newFramedStream(s, id)
	s.streams[id] = stream
	s.mu.Unlock()
	if err := s.writeFrame(frameOpen, id, nil); err != nil {
		stream.peerReset(err)
		return nil, err
	}
	return stream, nil
}

func (s *framedSession) AcceptStream(ctx context.Context) (carrier.Stream, error) {
	select {
	case stream := <-s.acceptCh:
		return stream, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.ctx.Done():
		return nil, errors.New("framed carrier closed")
	}
}

func (s *framedSession) CloseWithError(carrier.ApplicationError) error { return s.Close() }

func (s *framedSession) CloseWithErrorContext(context.Context, carrier.ApplicationError) error {
	return s.Close()
}

func (s *framedSession) Close() error {
	s.closeOnce.Do(func() {
		_ = s.writeFrame(frameClose, 0, nil)
		s.cancel()
		_ = s.conn.Close()
		s.failAll(errors.New("framed carrier closed"))
	})
	return nil
}

func (s *framedSession) writeFrame(typ byte, id uint32, payload []byte) error {
	var header [9]byte
	header[0] = typ
	binary.BigEndian.PutUint32(header[1:5], id)
	binary.BigEndian.PutUint32(header[5:9], uint32(len(payload)))
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if _, err := s.conn.Write(header[:]); err != nil {
		return err
	}
	if len(payload) != 0 {
		_, err := s.conn.Write(payload)
		return err
	}
	return nil
}

func (s *framedSession) readLoop() {
	var header [9]byte
	for {
		if _, err := io.ReadFull(s.conn, header[:]); err != nil {
			s.failAll(err)
			return
		}
		typ := header[0]
		id := binary.BigEndian.Uint32(header[1:5])
		length := binary.BigEndian.Uint32(header[5:9])
		if length > 1<<20 {
			s.failAll(errors.New("oversized framed carrier payload"))
			return
		}
		payload := make([]byte, int(length))
		if _, err := io.ReadFull(s.conn, payload); err != nil {
			s.failAll(err)
			return
		}
		if typ == frameClose {
			s.failAll(errors.New("peer closed framed carrier"))
			return
		}
		s.mu.Lock()
		stream := s.streams[id]
		if typ == frameOpen {
			if stream != nil {
				s.mu.Unlock()
				s.failAll(errors.New("duplicate carrier stream"))
				return
			}
			stream = newFramedStream(s, id)
			s.streams[id] = stream
		}
		s.mu.Unlock()
		if stream == nil {
			s.failAll(errors.New("unknown carrier stream"))
			return
		}
		switch typ {
		case frameOpen:
			select {
			case s.acceptCh <- stream:
			case <-s.ctx.Done():
				return
			}
		case frameData:
			stream.push(payload)
		case frameFIN:
			stream.peerFIN()
		case frameReset:
			stream.peerReset(carrier.ErrStreamReset)
		default:
			s.failAll(errors.New("unknown carrier frame"))
			return
		}
	}
}

func (s *framedSession) failAll(err error) {
	s.cancel()
	s.mu.Lock()
	streams := make([]*framedStream, 0, len(s.streams))
	for _, stream := range s.streams {
		streams = append(streams, stream)
	}
	s.mu.Unlock()
	for _, stream := range streams {
		stream.peerReset(err)
	}
}

type framedStream struct {
	session   *framedSession
	id        uint32
	mu        sync.Mutex
	cond      *sync.Cond
	chunks    [][]byte
	offset    int
	eof       bool
	err       error
	localFIN  bool
	resetOnce sync.Once
}

func newFramedStream(session *framedSession, id uint32) *framedStream {
	stream := &framedStream{session: session, id: id}
	stream.cond = sync.NewCond(&stream.mu)
	return stream
}

func (s *framedStream) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.chunks) == 0 && !s.eof && s.err == nil {
		s.cond.Wait()
	}
	if s.err != nil {
		return 0, s.err
	}
	if len(s.chunks) == 0 && s.eof {
		return 0, io.EOF
	}
	chunk := s.chunks[0]
	n := copy(p, chunk[s.offset:])
	s.offset += n
	if s.offset == len(chunk) {
		s.chunks = s.chunks[1:]
		s.offset = 0
	}
	return n, nil
}

func (s *framedStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	closed := s.localFIN || s.err != nil
	s.mu.Unlock()
	if closed {
		return 0, errors.New("framed stream closed")
	}
	if err := s.session.writeFrame(frameData, s.id, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (s *framedStream) CloseWrite() error {
	s.mu.Lock()
	if s.localFIN {
		s.mu.Unlock()
		return nil
	}
	s.localFIN = true
	s.mu.Unlock()
	return s.session.writeFrame(frameFIN, s.id, nil)
}

func (s *framedStream) Reset() error {
	s.resetOnce.Do(func() {
		_ = s.session.writeFrame(frameReset, s.id, nil)
		s.peerReset(carrier.ErrStreamReset)
	})
	return nil
}

func (s *framedStream) Close() error             { return nil }
func (s *framedStream) Context() context.Context { return s.session.ctx }

func (s *framedStream) push(payload []byte) {
	s.mu.Lock()
	if s.err == nil && !s.eof {
		s.chunks = append(s.chunks, append([]byte(nil), payload...))
		s.cond.Broadcast()
	}
	s.mu.Unlock()
}

func (s *framedStream) peerFIN() {
	s.mu.Lock()
	s.eof = true
	s.cond.Broadcast()
	s.mu.Unlock()
}

func (s *framedStream) peerReset(err error) {
	s.mu.Lock()
	if s.err == nil {
		s.err = err
		s.chunks = nil
		s.cond.Broadcast()
	}
	s.mu.Unlock()
}

var _ carrier.Session = (*framedSession)(nil)
var _ carrier.Stream = (*framedStream)(nil)
